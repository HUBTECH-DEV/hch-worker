using System.IO.Pipes;
using Hch.Worker.IPC.Contracts;
using Hch.Worker.Windows;

namespace Hch.Worker.Tray;

public sealed class NamedPipeWorkerClient
{
    private const string WorkerServiceName = "HchWorker";
    private static readonly TimeSpan DefaultOperationTimeout = TimeSpan.FromSeconds(5);
    // The service permits a command to execute for two minutes and then has a
    // separate five-second response-write deadline. Keep the client beyond
    // both server deadlines so it never reports a timeout while Stop or the
    // enrollment activation can still complete normally on the service.
    private static readonly TimeSpan DefaultLongRunningOperationTimeout = TimeSpan.FromMinutes(2) +
        TimeSpan.FromSeconds(10);
    private readonly string _pipeName;
    private readonly TimeSpan _operationTimeout;
    private readonly TimeSpan _longRunningOperationTimeout;
    private readonly TimeProvider _timeProvider;
    private readonly ILocalPipeServerAuthenticator _serverAuthenticator;
    private readonly SemaphoreSlim _authenticationGate = new(1, 1);

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
        TimeProvider? timeProvider = null,
        TimeSpan? operationTimeout = null,
        TimeSpan? longRunningOperationTimeout = null)
    {
        _pipeName = IpcProtocol.PipeName(nodeId);
        _serverAuthenticator = serverAuthenticator
            ?? throw new ArgumentNullException(nameof(serverAuthenticator));
        _timeProvider = timeProvider ?? TimeProvider.System;
        _operationTimeout = operationTimeout ?? DefaultOperationTimeout;
        _longRunningOperationTimeout = longRunningOperationTimeout ?? DefaultLongRunningOperationTimeout;
        if (_operationTimeout <= TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(nameof(operationTimeout));
        }

        if (_longRunningOperationTimeout <= TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(nameof(longRunningOperationTimeout));
        }
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
        using var preflightDeadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        preflightDeadline.CancelAfter(_operationTimeout);
        CancellationToken preflightToken = preflightDeadline.Token;
        await using NamedPipeClientStream pipe = LocalNamedPipe.CreateClient(_pipeName);
        IpcRequest request;
        try
        {
            await pipe.ConnectAsync(preflightToken).ConfigureAwait(false);
            preflightToken.ThrowIfCancellationRequested();
            // Win32 trust verification is synchronous and has no cancellation
            // primitive. Run it outside the caller thread, cap the caller-visible
            // wait with the operation deadline, and keep one authentication in
            // flight until the native call actually returns. This prevents a stuck
            // trust provider from accumulating tasks or pipe handles. No request or
            // enrollment secret is created or transmitted before it succeeds.
            await AuthenticateAsync(pipe, preflightToken).ConfigureAwait(false);
            preflightToken.ThrowIfCancellationRequested();
            request = IpcRequest.Create(command, payload, _timeProvider.GetUtcNow());
            await IpcFraming.WriteAsync(pipe, request, preflightToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException error)
            when (preflightDeadline.IsCancellationRequested && !cancellationToken.IsCancellationRequested)
        {
            throw new TimeoutException("ipc-operation-timeout", error);
        }

        using var responseDeadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        responseDeadline.CancelAfter(ResponseTimeout(command));
        try
        {
            var response = await IpcFraming.ReadAsync<IpcResponse>(pipe, responseDeadline.Token)
                .ConfigureAwait(false);
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
        catch (OperationCanceledException error)
            when (responseDeadline.IsCancellationRequested && !cancellationToken.IsCancellationRequested)
        {
            throw new TimeoutException("ipc-operation-timeout", error);
        }
    }

    private TimeSpan ResponseTimeout(IpcCommand command) => command is
        IpcCommand.Stop or IpcCommand.SubmitEnrollmentToken
            ? _longRunningOperationTimeout
            : _operationTimeout;

    private async Task AuthenticateAsync(
        NamedPipeClientStream pipe,
        CancellationToken cancellationToken)
    {
        await _authenticationGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        Task authentication;
        try
        {
            authentication = Task.Run(() => _serverAuthenticator.Authenticate(pipe));
        }
        catch
        {
            _authenticationGate.Release();
            throw;
        }

        _ = authentication.ContinueWith(
            static (completed, state) =>
            {
                // Observe a late attestation failure after the caller deadline;
                // there is deliberately no retry until this task has terminated.
                _ = completed.Exception;
                ((SemaphoreSlim)state!).Release();
            },
            _authenticationGate,
            CancellationToken.None,
            TaskContinuationOptions.ExecuteSynchronously,
            TaskScheduler.Default);
        await authentication.WaitAsync(cancellationToken).ConfigureAwait(false);
    }
}

public sealed class WorkerControlClientException(string code) : Exception("The Worker refused the command.")
{
    public string Code { get; } = code;
}
