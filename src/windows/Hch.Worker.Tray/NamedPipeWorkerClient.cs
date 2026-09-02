using System.IO.Pipes;
using Hch.Worker.IPC.Contracts;
using Hch.Worker.Windows;

namespace Hch.Worker.Tray;

public sealed class NamedPipeWorkerClient
{
    private const string WorkerServiceName = "HchWorker";
    private readonly string _pipeName;
    private readonly TimeProvider _timeProvider;
    private readonly ILocalPipeServerAuthenticator _serverAuthenticator;

    public NamedPipeWorkerClient(string nodeId, TimeProvider? timeProvider = null)
        : this(
            nodeId,
            new WindowsServicePipeServerAuthenticator(WorkerServiceName),
            timeProvider)
    {
    }

    internal NamedPipeWorkerClient(
        string nodeId,
        ILocalPipeServerAuthenticator serverAuthenticator,
        TimeProvider? timeProvider = null)
    {
        _pipeName = IpcProtocol.PipeName(nodeId);
        _serverAuthenticator = serverAuthenticator
            ?? throw new ArgumentNullException(nameof(serverAuthenticator));
        _timeProvider = timeProvider ?? TimeProvider.System;
    }

    public Task<WorkerSnapshotPayload> GetSnapshotAsync(CancellationToken cancellationToken = default) =>
        SendAsync<EmptyPayload, WorkerSnapshotPayload>(
            IpcCommand.GetSnapshot,
            EmptyPayload.Value,
            cancellationToken);

    public Task<CommandAcceptedPayload> StartAsync(CancellationToken cancellationToken = default) =>
        SendAsync<EmptyPayload, CommandAcceptedPayload>(IpcCommand.Start, EmptyPayload.Value, cancellationToken);

    public Task<CommandAcceptedPayload> PauseAsync(CancellationToken cancellationToken = default) =>
        SendAsync<EmptyPayload, CommandAcceptedPayload>(IpcCommand.Pause, EmptyPayload.Value, cancellationToken);

    public Task<CommandAcceptedPayload> StopAsync(CancellationToken cancellationToken = default) =>
        SendAsync<EmptyPayload, CommandAcceptedPayload>(IpcCommand.Stop, EmptyPayload.Value, cancellationToken);

    public Task<CommandAcceptedPayload> SetMaxConcurrentJobsAsync(
        int value,
        CancellationToken cancellationToken = default) =>
        SendAsync<SetMaxConcurrentJobsPayload, CommandAcceptedPayload>(
            IpcCommand.SetMaxConcurrentJobs,
            new(value),
            cancellationToken);

    public Task<CommandAcceptedPayload> SetClaimBatchSizeAsync(
        int value,
        CancellationToken cancellationToken = default) =>
        SendAsync<SetClaimBatchSizePayload, CommandAcceptedPayload>(
            IpcCommand.SetClaimBatchSize,
            new(value),
            cancellationToken);

    public Task<OperationalEnrollmentContextPayload> BeginEnrollmentAsync(
        string preferredFlow,
        CancellationToken cancellationToken = default) =>
        SendAsync<BeginEnrollmentPayload, OperationalEnrollmentContextPayload>(
            IpcCommand.BeginEnrollment,
            new(preferredFlow),
            cancellationToken);

    public async Task<OperationalEnrollmentCompletedPayload> SubmitEnrollmentTokenAsync(
        ReadOnlyMemory<byte> enrollmentTokenUtf8,
        string ownerSshKeyId,
        string ownerSshKeyFingerprint,
        CancellationToken cancellationToken = default)
    {
        var payload = new EnrollmentTokenPayload(
            enrollmentTokenUtf8.ToArray(),
            ownerSshKeyId,
            ownerSshKeyFingerprint);
        try
        {
            return await SendAsync<EnrollmentTokenPayload, OperationalEnrollmentCompletedPayload>(
                IpcCommand.SubmitEnrollmentToken,
                payload,
                cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            payload.Clear();
        }
    }

    public Task<SanitizedLogsPayload> ReadSanitizedLogsAsync(
        DateTimeOffset? since = null,
        int maximumEntries = 2_000,
        CancellationToken cancellationToken = default) =>
        SendAsync<ExportLogsPayload, SanitizedLogsPayload>(
            IpcCommand.ExportSanitizedLogs,
            new(since, maximumEntries),
            cancellationToken);

    private async Task<TResponse> SendAsync<TPayload, TResponse>(
        IpcCommand command,
        TPayload payload,
        CancellationToken cancellationToken)
    {
        await using NamedPipeClientStream pipe = LocalNamedPipe.CreateClient(_pipeName);
        await pipe.ConnectAsync(TimeSpan.FromSeconds(5), cancellationToken).ConfigureAwait(false);
        // The connected handle is bound to one server instance. Authenticate
        // that process before serializing or transmitting any frame (especially
        // the one-time enrollment token).
        _serverAuthenticator.Authenticate(pipe);
        var request = IpcRequest.Create(command, payload, _timeProvider.GetUtcNow());
        await IpcFraming.WriteAsync(pipe, request, cancellationToken).ConfigureAwait(false);
        var response = await IpcFraming.ReadAsync<IpcResponse>(pipe, cancellationToken).ConfigureAwait(false);
        if (response.Version != IpcProtocol.Version || response.RequestId != request.RequestId)
        {
            throw new IpcContractException("ipc-response-correlation-invalid");
        }

        if (!response.Success)
        {
            throw new WorkerControlClientException(response.ErrorCode ?? "ipc-command-failed");
        }

        return IpcValidation.Payload<TResponse>(response.Payload);
    }
}

public sealed class WorkerControlClientException(string code) : Exception("The Worker refused the command.")
{
    public string Code { get; } = code;
}
