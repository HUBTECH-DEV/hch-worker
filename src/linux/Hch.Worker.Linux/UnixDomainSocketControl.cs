using System.Net.Sockets;
using System.Runtime.InteropServices;

namespace Hch.Worker.Linux;

public readonly record struct UnixPeerCredentials(int ProcessId, uint UserId, uint GroupId);

public sealed class AuthenticatedUnixConnection : IAsyncDisposable, IDisposable
{
    private readonly Socket socket;

    internal AuthenticatedUnixConnection(Socket socket, UnixPeerCredentials peer)
    {
        this.socket = socket;
        Peer = peer;
        Stream = new NetworkStream(socket, ownsSocket: false);
    }

    public UnixPeerCredentials Peer { get; }

    public Stream Stream { get; }

    public void Dispose()
    {
        Stream.Dispose();
        socket.Dispose();
    }

    public async ValueTask DisposeAsync()
    {
        await Stream.DisposeAsync().ConfigureAwait(false);
        socket.Dispose();
    }
}

/// <summary>
/// Creates and authenticates local control connections. TCP fallback is
/// deliberately unsupported: failure to prove SO_PEERCRED always rejects.
/// </summary>
public sealed class UnixDomainSocketControlServer : IAsyncDisposable, IDisposable
{
    private readonly Socket listener;
    private readonly string socketPath;
    private readonly HashSet<uint> allowedPeerUids;
    private bool disposed;

    private UnixDomainSocketControlServer(
        Socket listener,
        string socketPath,
        HashSet<uint> allowedPeerUids)
    {
        this.listener = listener;
        this.socketPath = socketPath;
        this.allowedPeerUids = allowedPeerUids;
    }

    public string SocketPath => socketPath;

    public static UnixDomainSocketControlServer Create(
        string socketPath,
        IEnumerable<uint>? allowedPeerUids = null,
        int backlog = 16)
    {
        EnsureLinux();
        string path = ValidateSocketPath(socketPath);
        if (backlog is < 1 or > 128)
        {
            throw new ArgumentOutOfRangeException(nameof(backlog));
        }

        string directory = Path.GetDirectoryName(path)!;
        LinuxPathSecurity.EnsurePrivateDirectory(directory);
        if (PathExists(path))
        {
            throw new IOException("linux-control-socket-path-already-exists");
        }

        var allowed = (allowedPeerUids ?? [UnixNative.GetEffectiveUserId()]).ToHashSet();
        if (allowed.Count == 0)
        {
            throw new ArgumentException("linux-control-peer-uids-empty", nameof(allowedPeerUids));
        }

        var socket = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
        try
        {
            socket.Bind(new UnixDomainSocketEndPoint(path));
            File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite);
            RequireSecureSocket(path, UnixNative.GetEffectiveUserId());
            socket.Listen(backlog);
            return new UnixDomainSocketControlServer(socket, path, allowed);
        }
        catch
        {
            socket.Dispose();
            DeleteOwnedSocketIfPresent(path);
            throw;
        }
    }

    public async ValueTask<AuthenticatedUnixConnection> AcceptAuthenticatedAsync(
        CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(disposed, this);
        Socket accepted = await listener.AcceptAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            UnixPeerCredentials peer = UnixNative.GetPeerCredentials(accepted);
            if (peer.ProcessId < 1 || !allowedPeerUids.Contains(peer.UserId)
                || !Directory.Exists($"/proc/{peer.ProcessId}"))
            {
                throw new UnauthorizedAccessException("linux-control-peer-not-authorized");
            }

            return new AuthenticatedUnixConnection(accepted, peer);
        }
        catch
        {
            accepted.Dispose();
            throw;
        }
    }

    public void Dispose()
    {
        if (disposed)
        {
            return;
        }

        disposed = true;
        listener.Dispose();
        DeleteOwnedSocketIfPresent(socketPath);
    }

    public ValueTask DisposeAsync()
    {
        Dispose();
        return ValueTask.CompletedTask;
    }

    internal static string ValidateSocketPath(string socketPath)
    {
        string path = LinuxPathSecurity.RequireAbsoluteCanonicalPath(socketPath);
        // Linux sockaddr_un.sun_path is 108 bytes including the terminator.
        if (System.Text.Encoding.UTF8.GetByteCount(path) > 107
            || Path.GetFileName(path).Length == 0)
        {
            throw new ArgumentException("linux-control-socket-path-invalid", nameof(socketPath));
        }

        return path;
    }

    internal static void RequireSecureSocket(string path, uint expectedOwnerUid)
    {
        LinuxFileMetadata metadata = LinuxPathSecurity.ReadMetadata(path);
        if (!metadata.IsSocket || metadata.OwnerUid != expectedOwnerUid)
        {
            throw new UnauthorizedAccessException("linux-control-socket-owner-or-type-invalid");
        }

        UnixFileMode mode = File.GetUnixFileMode(path);
        UnixFileMode allowed = UnixFileMode.UserRead | UnixFileMode.UserWrite;
        if ((mode & ~allowed) != 0 || (mode & allowed) != allowed)
        {
            throw new UnauthorizedAccessException("linux-control-socket-permissions-invalid");
        }
    }

    private static bool PathExists(string path)
    {
        try
        {
            _ = LinuxPathSecurity.ReadMetadata(path);
            return true;
        }
        catch (IOException error) when (error.InnerException is System.ComponentModel.Win32Exception native
            && native.NativeErrorCode == 2)
        {
            return false;
        }
    }

    private static void DeleteOwnedSocketIfPresent(string path)
    {
        try
        {
            LinuxFileMetadata metadata = LinuxPathSecurity.ReadMetadata(path);
            if (metadata.IsSocket && metadata.OwnerUid == UnixNative.GetEffectiveUserId())
            {
                File.Delete(path);
            }
        }
        catch (IOException)
        {
        }
    }

    private static void EnsureLinux()
    {
        if (!OperatingSystem.IsLinux())
        {
            throw new PlatformNotSupportedException("linux-platform-required");
        }
    }
}

public static class UnixDomainSocketControlClient
{
    public static async ValueTask<AuthenticatedUnixConnection> ConnectAuthenticatedAsync(
        string socketPath,
        uint expectedServerUid,
        CancellationToken cancellationToken = default)
    {
        if (!OperatingSystem.IsLinux())
        {
            throw new PlatformNotSupportedException("linux-platform-required");
        }

        string path = UnixDomainSocketControlServer.ValidateSocketPath(socketPath);
        UnixDomainSocketControlServer.RequireSecureSocket(path, expectedServerUid);
        var socket = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
        try
        {
            await socket.ConnectAsync(new UnixDomainSocketEndPoint(path), cancellationToken)
                .ConfigureAwait(false);
            UnixPeerCredentials peer = UnixNative.GetPeerCredentials(socket);
            UnixDomainSocketControlServer.RequireSecureSocket(path, expectedServerUid);
            if (peer.ProcessId < 1 || peer.UserId != expectedServerUid)
            {
                throw new UnauthorizedAccessException("linux-control-server-not-authorized");
            }

            return new AuthenticatedUnixConnection(socket, peer);
        }
        catch
        {
            socket.Dispose();
            throw;
        }
    }
}

internal static class UnixNative
{
    private const int SolSocket = 1;
    private const int SoPeerCred = 17;

    public static uint GetEffectiveUserId() => Geteuid();

    public static UnixPeerCredentials GetPeerCredentials(Socket socket)
    {
        ArgumentNullException.ThrowIfNull(socket);
        var credentials = new UCred();
        uint length = checked((uint)Marshal.SizeOf<UCred>());
        int result = Getsockopt(
            socket.SafeHandle.DangerousGetHandle(),
            SolSocket,
            SoPeerCred,
            ref credentials,
            ref length);
        if (result != 0 || length != Marshal.SizeOf<UCred>()
            || credentials.ProcessId < 1 || credentials.UserId == uint.MaxValue)
        {
            throw new UnauthorizedAccessException(
                "linux-control-peer-credentials-unavailable",
                new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error()));
        }

        return new UnixPeerCredentials(
            credentials.ProcessId,
            credentials.UserId,
            credentials.GroupId);
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct UCred
    {
        public int ProcessId;
        public uint UserId;
        public uint GroupId;
    }

    [DllImport("libc", EntryPoint = "getsockopt", SetLastError = true)]
    private static extern int Getsockopt(
        nint socket,
        int level,
        int optionName,
        ref UCred optionValue,
        ref uint optionLength);

    [DllImport("libc", EntryPoint = "geteuid", SetLastError = false)]
    private static extern uint Geteuid();
}
