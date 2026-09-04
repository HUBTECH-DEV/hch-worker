using System.Runtime.InteropServices;
using Hch.Worker.Core;
using Hch.Worker.IPC.Contracts;
using Hch.Worker.Linux;
using Hch.Worker.Service;

namespace Hch.Worker.Linux.Tests;

public sealed class LinuxHostControlTests : IDisposable
{
    private readonly string root = Path.Combine(
        Path.GetTempPath(),
        "hch-linux-host-tests-" + Guid.NewGuid().ToString("N"));

    [Fact]
    public async Task ServesPauseOverAuthenticatedUnixSocket()
    {
        string socketPath = PrepareSocketPath();
        WorkerControlState control = new(lastNonZeroMaxConcurrentJobs: 1, claimBatchSize: 1);
        var controller = new WorkerOperationalController(control, new WorkerSchedulerHost());
        WorkerControlPipeServer server = CreateServer(socketPath, controller);
        using var stop = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        Task serverTask = server.RunAsync(stop.Token);
        await WaitForSocketAsync(socketPath, stop.Token);

        await using AuthenticatedUnixConnection connection =
            await UnixDomainSocketControlClient.ConnectAuthenticatedAsync(
                socketPath,
                GetEffectiveUserId(),
                stop.Token);
        IpcRequest request = IpcRequest.Create(IpcCommand.Pause, EmptyPayload.Value);
        await IpcFraming.WriteAsync(connection.Stream, request, stop.Token);
        IpcResponse response = await IpcFraming.ReadAsync<IpcResponse>(connection.Stream, stop.Token);

        Assert.True(response.Success);
        Assert.Null(response.ErrorCode);
        Assert.Equal(request.RequestId, response.RequestId);
        CommandAcceptedPayload accepted = IpcValidation.Payload<CommandAcceptedPayload>(response.Payload);
        Assert.Equal("Paused", accepted.State);
        Assert.Equal(WorkerOperationalState.Paused, control.Snapshot.State);

        stop.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () => await serverTask);
    }

    [Fact]
    public async Task StartRemainsFailClosedWhenCutoverCannotBeProved()
    {
        string socketPath = PrepareSocketPath();
        WorkerControlState control = new(lastNonZeroMaxConcurrentJobs: 1, claimBatchSize: 1);
        control.MarkReady("test-ready-paused");
        var controller = new WorkerOperationalController(
            control,
            new WorkerSchedulerHost(),
            ensureExclusiveClaiming: _ => throw new WorkerControlException(
                "linux-exclusive-claiming-unimplemented",
                "test cutover remains unavailable"));
        WorkerControlPipeServer server = CreateServer(socketPath, controller);
        using var stop = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        Task serverTask = server.RunAsync(stop.Token);
        await WaitForSocketAsync(socketPath, stop.Token);

        await using AuthenticatedUnixConnection connection =
            await UnixDomainSocketControlClient.ConnectAuthenticatedAsync(
                socketPath,
                GetEffectiveUserId(),
                stop.Token);
        IpcRequest request = IpcRequest.Create(IpcCommand.Start, EmptyPayload.Value);
        await IpcFraming.WriteAsync(connection.Stream, request, stop.Token);
        IpcResponse response = await IpcFraming.ReadAsync<IpcResponse>(connection.Stream, stop.Token);

        Assert.False(response.Success);
        Assert.Equal("linux-exclusive-claiming-unimplemented", response.ErrorCode);
        Assert.Equal(WorkerOperationalState.Paused, control.Snapshot.State);
        Assert.False(control.Snapshot.AcceptingClaims);
        Assert.Equal(0, control.Snapshot.MaxConcurrentJobs);

        stop.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () => await serverTask);
    }

    [Fact]
    public void AuthorizesWorkerUidAndRestrictsRootToMaintenance()
    {
        const uint workerUid = 1001;
        Assert.True(WorkerControlPipeServer.IsCommandAuthorized(workerUid, workerUid, IpcCommand.Start));
        Assert.True(WorkerControlPipeServer.IsCommandAuthorized(0, workerUid, IpcCommand.PrepareMaintenance));
        Assert.False(WorkerControlPipeServer.IsCommandAuthorized(0, workerUid, IpcCommand.Start));
        Assert.False(WorkerControlPipeServer.IsCommandAuthorized(1002, workerUid, IpcCommand.GetSnapshot));
    }

    public void Dispose()
    {
        if (Directory.Exists(root))
        {
            Directory.Delete(root, recursive: true);
        }
    }

    private WorkerControlPipeServer CreateServer(
        string socketPath,
        WorkerOperationalController controller)
    {
        string state = Path.Combine(root, "state");
        Directory.CreateDirectory(state, UnixFileMode.UserRead
            | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        var configuration = new WorkerConfiguration(
            1,
            "linux-test-node",
            "Linux test worker",
            "linux-test-key",
            null,
            null,
            null,
            null,
            new Uri("https://hubtech.online/"),
            new Uri("http://127.0.0.1:11434/"),
            1,
            1,
            64,
            64,
            state).Validate();
        return new WorkerControlPipeServer(
            configuration,
            controller,
            () => throw new InvalidOperationException("snapshot-not-used"),
            new SanitizedLogStore(state),
            enrollment: null,
            postEnrollmentActivation: null,
            socketPath: socketPath);
    }

    private string PrepareSocketPath()
    {
        string runtime = Path.Combine(root, "run");
        Directory.CreateDirectory(runtime, UnixFileMode.UserRead
            | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        return Path.Combine(runtime, "control.sock");
    }

    private static async Task WaitForSocketAsync(string path, CancellationToken cancellationToken)
    {
        while (!File.Exists(path))
        {
            await Task.Delay(TimeSpan.FromMilliseconds(10), cancellationToken);
        }
    }

    [DllImport("libc", EntryPoint = "geteuid", SetLastError = false)]
    private static extern uint GetEffectiveUserId();
}
