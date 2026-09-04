using Hch.Worker.IPC.Contracts;

namespace Hch.Worker.Linux.Tests;

public sealed class UnixDomainSocketControlTests : IDisposable
{
    private readonly string directory = Path.Combine(
        Path.GetTempPath(),
        "hch-linux-ipc-" + Guid.NewGuid().ToString("N"));

    [Fact]
    public async Task AuthenticatesPeerAndCarriesFramedContract()
    {
        string path = SocketPath();
        uint uid = LinuxPathSecurity.ReadMetadata(directory).OwnerUid;
        await using var server = UnixDomainSocketControlServer.Create(path, [uid]);

        ValueTask<AuthenticatedUnixConnection> accepting = server.AcceptAuthenticatedAsync();
        await using AuthenticatedUnixConnection client =
            await UnixDomainSocketControlClient.ConnectAuthenticatedAsync(path, uid);
        await using AuthenticatedUnixConnection accepted = await accepting;

        IpcRequest request = IpcRequest.Create(IpcCommand.GetSnapshot, EmptyPayload.Value);
        await IpcFraming.WriteAsync(client.Stream, request);
        IpcRequest received = await IpcFraming.ReadAsync<IpcRequest>(accepted.Stream);

        Assert.Equal(request.RequestId, received.RequestId);
        Assert.Equal(uid, accepted.Peer.UserId);
        Assert.True(accepted.Peer.ProcessId > 0);
    }

    [Fact]
    public async Task ClientRejectsSocketWithUnsafePermissions()
    {
        string path = SocketPath();
        uint uid = LinuxPathSecurity.ReadMetadata(directory).OwnerUid;
        await using var server = UnixDomainSocketControlServer.Create(path, [uid]);
        File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite
            | UnixFileMode.GroupRead | UnixFileMode.GroupWrite);

        UnauthorizedAccessException error = await Assert.ThrowsAsync<UnauthorizedAccessException>(
            async () => await UnixDomainSocketControlClient.ConnectAuthenticatedAsync(path, uid));
        Assert.Equal("linux-control-socket-permissions-invalid", error.Message);
    }

    [Fact]
    public void ServerRefusesExistingPathWithoutDeletingIt()
    {
        string path = SocketPath();
        File.WriteAllText(path, "not-a-socket");

        IOException error = Assert.Throws<IOException>(() =>
            UnixDomainSocketControlServer.Create(path));

        Assert.Equal("linux-control-socket-path-already-exists", error.Message);
        Assert.True(File.Exists(path));
    }

    private string SocketPath()
    {
        Directory.CreateDirectory(directory, UnixFileMode.UserRead
            | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        File.SetUnixFileMode(directory, UnixFileMode.UserRead
            | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        return Path.Combine(directory, "control.sock");
    }

    public void Dispose()
    {
        if (Directory.Exists(directory))
        {
            Directory.Delete(directory, recursive: true);
        }
    }
}
