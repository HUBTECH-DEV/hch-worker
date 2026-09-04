using System.Runtime.InteropServices;
using Hch.Worker.Core;
using Hch.Worker.IPC.Contracts;
using Hch.Worker.Linux;

namespace Hch.Worker.Service;

public sealed class WorkerOperationalController
{
    private readonly WorkerControlState control;
    private readonly Func<ConcurrentJobScheduler?> scheduler;
    private readonly TimeProvider clock;
    private readonly Func<WorkerControlSnapshot, CancellationToken, Task>? persistConfiguration;
    private readonly Func<CancellationToken, Task>? ensureExclusiveClaiming;
    private readonly SemaphoreSlim commandGate = new(1, 1);
    private int maintenancePrepared;

    public WorkerOperationalController(
        WorkerControlState control,
        WorkerSchedulerHost schedulerHost,
        TimeProvider? timeProvider = null,
        Func<WorkerControlSnapshot, CancellationToken, Task>? persistConfiguration = null,
        Func<CancellationToken, Task>? ensureExclusiveClaiming = null)
    {
        ArgumentNullException.ThrowIfNull(schedulerHost);
        this.control = control ?? throw new ArgumentNullException(nameof(control));
        scheduler = () => schedulerHost.Current;
        clock = timeProvider ?? TimeProvider.System;
        this.persistConfiguration = persistConfiguration;
        this.ensureExclusiveClaiming = ensureExclusiveClaiming;
    }

    public WorkerControlSnapshot Snapshot => control.Snapshot;

    public async Task<WorkerControlSnapshot> StartAsync(CancellationToken cancellationToken = default)
    {
        await commandGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (Volatile.Read(ref maintenancePrepared) != 0)
            {
                throw new WorkerControlException(
                    "worker-maintenance-prepared",
                    "The Worker is prepared for installer maintenance.");
            }

            if (ensureExclusiveClaiming is not null)
            {
                await ensureExclusiveClaiming(cancellationToken).ConfigureAwait(false);
            }

            scheduler()?.ResumeAfterStop();
            return control.Start();
        }
        finally
        {
            commandGate.Release();
        }
    }

    public async Task<WorkerControlSnapshot> PauseAsync(CancellationToken cancellationToken = default)
    {
        await commandGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try { return control.Pause(); }
        finally { commandGate.Release(); }
    }

    public async Task<WorkerControlSnapshot> StopAsync(CancellationToken cancellationToken = default)
    {
        await commandGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            ConcurrentJobScheduler? currentScheduler = scheduler();
            if (currentScheduler is null)
            {
                control.BeginStop();
                return control.CompleteStop();
            }

            await currentScheduler.StopAsync(cancellationToken).ConfigureAwait(false);
            return control.Snapshot;
        }
        finally
        {
            commandGate.Release();
        }
    }

    public async Task<WorkerControlSnapshot> SetMaxConcurrentJobsAsync(
        int value,
        CancellationToken cancellationToken = default)
    {
        await commandGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (value > 0)
            {
                if (Volatile.Read(ref maintenancePrepared) != 0)
                {
                    throw new WorkerControlException(
                        "worker-maintenance-prepared",
                        "The Worker is prepared for installer maintenance.");
                }

                if (ensureExclusiveClaiming is not null)
                {
                    await ensureExclusiveClaiming(cancellationToken).ConfigureAwait(false);
                }

                scheduler()?.ResumeAfterStop();
            }

            WorkerControlSnapshot snapshot = control.SetMaxConcurrentJobs(value);
            if (persistConfiguration is not null)
            {
                await persistConfiguration(snapshot, cancellationToken).ConfigureAwait(false);
            }

            return snapshot;
        }
        finally
        {
            commandGate.Release();
        }
    }

    public async Task<WorkerControlSnapshot> SetClaimBatchSizeAsync(
        int value,
        CancellationToken cancellationToken = default)
    {
        await commandGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            WorkerControlSnapshot snapshot = control.SetClaimBatchSize(value);
            if (persistConfiguration is not null)
            {
                await persistConfiguration(snapshot, cancellationToken).ConfigureAwait(false);
            }

            return snapshot;
        }
        finally
        {
            commandGate.Release();
        }
    }

    public async Task<WorkerControlSnapshot> PrepareMaintenanceAsync(
        CancellationToken cancellationToken = default)
    {
        await commandGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            Interlocked.Exchange(ref maintenancePrepared, 1);
            WorkerControlSnapshot snapshot = control.Pause("installer-maintenance");
            if (snapshot.ActiveJobs != 0 || snapshot.ReservedJobs != 0)
            {
                throw new WorkerControlException(
                    "worker-maintenance-drain-required",
                    "Active or reserved jobs must drain before installer maintenance.");
            }

            return snapshot;
        }
        finally
        {
            commandGate.Release();
        }
    }

    public CommandAcceptedPayload Accepted(WorkerControlSnapshot snapshot) =>
        new(snapshot.State.ToString(), clock.GetUtcNow());
}

/// <summary>
/// Authenticated Linux control endpoint. The worker UID has owner-equivalent
/// access; UID 0 is restricted to PrepareMaintenance. No TCP fallback exists.
/// </summary>
public sealed class WorkerControlPipeServer
{
    public const string DefaultSocketPath = "/run/hch-worker/control.sock";
    private static readonly TimeSpan DefaultRequestReadTimeout = TimeSpan.FromSeconds(5);
    private static readonly TimeSpan DefaultCommandTimeout = TimeSpan.FromMinutes(2);
    private static readonly TimeSpan DefaultResponseWriteTimeout = TimeSpan.FromSeconds(5);

    private readonly WorkerOperationalController controller;
    private readonly Func<WorkerSnapshotPayload> snapshot;
    private readonly SanitizedLogStore logs;
    private readonly OperationalEnrollmentCoordinator? enrollment;
    private readonly PostEnrollmentRuntimeActivator? postEnrollmentActivation;
    private readonly TimeProvider clock;
    private readonly string socketPath;
    private readonly uint serviceUid;
    private readonly TimeSpan requestReadTimeout;
    private readonly TimeSpan commandTimeout;
    private readonly TimeSpan responseWriteTimeout;
    private readonly SemaphoreSlim commandExecutionGate = new(1, 1);

    public WorkerControlPipeServer(
        WorkerConfiguration configuration,
        WorkerOperationalController controller,
        Func<WorkerSnapshotPayload> snapshot,
        SanitizedLogStore logs,
        OperationalEnrollmentCoordinator? enrollment,
        PostEnrollmentRuntimeActivator? postEnrollmentActivation,
        TimeProvider? timeProvider = null,
        string? socketPath = null,
        TimeSpan? requestReadTimeout = null,
        TimeSpan? commandTimeout = null,
        TimeSpan? responseWriteTimeout = null)
    {
        ArgumentNullException.ThrowIfNull(configuration);
        this.controller = controller ?? throw new ArgumentNullException(nameof(controller));
        this.snapshot = snapshot ?? throw new ArgumentNullException(nameof(snapshot));
        this.logs = logs ?? throw new ArgumentNullException(nameof(logs));
        this.enrollment = enrollment;
        this.postEnrollmentActivation = postEnrollmentActivation;
        clock = timeProvider ?? TimeProvider.System;
        this.socketPath = socketPath
            ?? Environment.GetEnvironmentVariable("HCH_WORKER_CONTROL_SOCKET")
            ?? DefaultSocketPath;
        serviceUid = GetEffectiveUserId();
        this.requestReadTimeout = ValidateTimeout(
            requestReadTimeout ?? DefaultRequestReadTimeout,
            nameof(requestReadTimeout));
        this.commandTimeout = ValidateTimeout(commandTimeout ?? DefaultCommandTimeout, nameof(commandTimeout));
        this.responseWriteTimeout = ValidateTimeout(
            responseWriteTimeout ?? DefaultResponseWriteTimeout,
            nameof(responseWriteTimeout));
    }

    public async Task RunAsync(CancellationToken serviceStopping)
    {
        uint[] allowedUids = serviceUid == 0 ? [0] : [serviceUid, 0];
        await using var server = UnixDomainSocketControlServer.Create(socketPath, allowedUids);
        while (!serviceStopping.IsCancellationRequested)
        {
            try
            {
                await using AuthenticatedUnixConnection connection =
                    await server.AcceptAuthenticatedAsync(serviceStopping).ConfigureAwait(false);
                await ProcessOneAsync(connection, serviceStopping).ConfigureAwait(false);
            }
            catch (IOException) when (!serviceStopping.IsCancellationRequested)
            {
                // A peer disconnect is scoped to one accepted socket.
            }
            catch (UnauthorizedAccessException) when (!serviceStopping.IsCancellationRequested)
            {
                // An unauthenticated peer receives no protocol response.
            }
        }
    }

    internal async Task ProcessOneAsync(
        AuthenticatedUnixConnection connection,
        CancellationToken cancellationToken)
    {
        IpcRequest? request = null;
        IpcResponse response;
        try
        {
            using (var readDeadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken))
            {
                readDeadline.CancelAfter(requestReadTimeout);
                try
                {
                    request = await IpcFraming.ReadAsync<IpcRequest>(connection.Stream, readDeadline.Token)
                        .ConfigureAwait(false);
                }
                catch (OperationCanceledException error)
                    when (readDeadline.IsCancellationRequested && !cancellationToken.IsCancellationRequested)
                {
                    throw new IpcOperationTimeoutException("ipc-request-timeout", error);
                }
            }

            IpcValidation.Request(request, clock.GetUtcNow());
            if (!IsCommandAuthorized(connection.Peer.UserId, serviceUid, request.Command))
            {
                throw new UnauthorizedAccessException("ipc-command-owner-required");
            }

            response = await DispatchWithDeadlineAsync(request, cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception error)
        {
            string? requestId = request?.RequestId;
            if (!Guid.TryParseExact(requestId, "D", out _))
            {
                requestId = Guid.NewGuid().ToString("D");
            }

            response = IpcResponse.Error(requestId!, ErrorCode(error));
        }

        if (request is null)
        {
            return;
        }

        using var writeDeadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        writeDeadline.CancelAfter(responseWriteTimeout);
        try
        {
            await IpcFraming.WriteAsync(connection.Stream, response, writeDeadline.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (
            writeDeadline.IsCancellationRequested && !cancellationToken.IsCancellationRequested)
        {
        }
        catch (IOException)
        {
        }
    }

    internal static bool IsCommandAuthorized(uint peerUid, uint workerUid, IpcCommand command) =>
        peerUid == workerUid || peerUid == 0 && command == IpcCommand.PrepareMaintenance;

    internal async Task<IpcResponse> DispatchAsync(
        IpcRequest request,
        CancellationToken cancellationToken) => request.Command switch
    {
        IpcCommand.GetSnapshot => IpcResponse.Ok(request.RequestId, snapshot()),
        IpcCommand.Start => IpcResponse.Ok(
            request.RequestId,
            controller.Accepted(await controller.StartAsync(cancellationToken).ConfigureAwait(false))),
        IpcCommand.Pause => IpcResponse.Ok(
            request.RequestId,
            controller.Accepted(await controller.PauseAsync(cancellationToken).ConfigureAwait(false))),
        IpcCommand.Stop => IpcResponse.Ok(
            request.RequestId,
            controller.Accepted(await controller.StopAsync(cancellationToken).ConfigureAwait(false))),
        IpcCommand.SetMaxConcurrentJobs => IpcResponse.Ok(
            request.RequestId,
            controller.Accepted(await controller.SetMaxConcurrentJobsAsync(
                IpcValidation.Payload<SetMaxConcurrentJobsPayload>(request.Payload).Value,
                cancellationToken).ConfigureAwait(false))),
        IpcCommand.SetClaimBatchSize => IpcResponse.Ok(
            request.RequestId,
            controller.Accepted(await controller.SetClaimBatchSizeAsync(
                IpcValidation.Payload<SetClaimBatchSizePayload>(request.Payload).Value,
                cancellationToken).ConfigureAwait(false))),
        IpcCommand.PrepareMaintenance => await PrepareMaintenanceAsync(request, cancellationToken)
            .ConfigureAwait(false),
        IpcCommand.ExportSanitizedLogs => IpcResponse.Ok(
            request.RequestId,
            await ExportLogsAsync(request, cancellationToken).ConfigureAwait(false)),
        IpcCommand.BeginEnrollment => await BeginEnrollmentAsync(request, cancellationToken)
            .ConfigureAwait(false),
        IpcCommand.SubmitEnrollmentToken => await CompleteEnrollmentAsync(request, cancellationToken)
            .ConfigureAwait(false),
        _ => IpcResponse.Error(request.RequestId, "ipc-command-unsupported"),
    };

    private async Task<IpcResponse> DispatchWithDeadlineAsync(
        IpcRequest request,
        CancellationToken cancellationToken)
    {
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(commandTimeout);
        try
        {
            await commandExecutionGate.WaitAsync(deadline.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException error)
            when (deadline.IsCancellationRequested && !cancellationToken.IsCancellationRequested)
        {
            throw new IpcOperationTimeoutException("ipc-command-timeout", error);
        }

        Task<IpcResponse> dispatch;
        try
        {
            dispatch = DispatchAsync(request, deadline.Token);
        }
        catch
        {
            commandExecutionGate.Release();
            throw;
        }

        _ = dispatch.ContinueWith(
            static (completed, state) =>
            {
                _ = completed.Exception;
                ((SemaphoreSlim)state!).Release();
            },
            commandExecutionGate,
            CancellationToken.None,
            TaskContinuationOptions.ExecuteSynchronously,
            TaskScheduler.Default);
        try
        {
            return await dispatch.WaitAsync(deadline.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException error)
            when (deadline.IsCancellationRequested && !cancellationToken.IsCancellationRequested)
        {
            throw new IpcOperationTimeoutException("ipc-command-timeout", error);
        }
    }

    private async Task<IpcResponse> PrepareMaintenanceAsync(
        IpcRequest request,
        CancellationToken cancellationToken)
    {
        _ = IpcValidation.Payload<EmptyPayload>(request.Payload);
        _ = await controller.PrepareMaintenanceAsync(cancellationToken).ConfigureAwait(false);
        return IpcResponse.Ok(request.RequestId, snapshot());
    }

    private async Task<IpcResponse> BeginEnrollmentAsync(
        IpcRequest request,
        CancellationToken cancellationToken)
    {
        BeginEnrollmentPayload payload = IpcValidation.Payload<BeginEnrollmentPayload>(request.Payload);
        if (!string.Equals(
                payload.PreferredFlow,
                Hch.Worker.Protocol.OperationalEnrollmentContract.Protocol,
                StringComparison.Ordinal))
        {
            return IpcResponse.Error(request.RequestId, "ipc-enrollment-protocol-unsupported");
        }

        if (enrollment is null)
        {
            return IpcResponse.Error(request.RequestId, "ipc-enrollment-identity-unavailable");
        }

        WorkerControlSnapshot paused = await controller.PauseAsync(cancellationToken).ConfigureAwait(false);
        if (paused.ActiveJobs > 0 || paused.ReservedJobs > 0)
        {
            return IpcResponse.Error(request.RequestId, "ipc-enrollment-drain-pending");
        }

        OperationalEnrollmentContext context = enrollment.PublicContext();
        return IpcResponse.Ok(request.RequestId, new OperationalEnrollmentContextPayload(
            context.Protocol,
            context.NodeId,
            context.WorkerKeyId,
            context.WorkerPublicKeyPem,
            context.WorkerPublicKeyFingerprint,
            context.WorkerRuntimeVersion));
    }

    private async Task<IpcResponse> CompleteEnrollmentAsync(
        IpcRequest request,
        CancellationToken cancellationToken)
    {
        if (enrollment is null)
        {
            return IpcResponse.Error(request.RequestId, "ipc-enrollment-identity-unavailable");
        }

        EnrollmentTokenPayload payload = IpcValidation.Payload<EnrollmentTokenPayload>(request.Payload);
        try
        {
            WorkerControlSnapshot paused = await controller.PauseAsync(cancellationToken).ConfigureAwait(false);
            if (paused.ActiveJobs > 0 || paused.ReservedJobs > 0)
            {
                return IpcResponse.Error(request.RequestId, "ipc-enrollment-drain-pending");
            }

            OperationalEnrollmentReceipt receipt = await enrollment.CompleteAsync(
                payload.TokenUtf8 ?? [],
                payload.OwnerSshKeyId,
                payload.OwnerSshKeyFingerprint,
                cancellationToken).ConfigureAwait(false);
            payload.Clear();
            if (postEnrollmentActivation is null)
            {
                throw new WorkerServiceException(
                    "post-enrollment-activation-unavailable",
                    "The service cannot activate the enrolled runtime in this process.");
            }

            await postEnrollmentActivation.ActivatePausedAsync(cancellationToken).ConfigureAwait(false);
            if (!DateTimeOffset.TryParse(
                    receipt.EnrolledAt,
                    System.Globalization.CultureInfo.InvariantCulture,
                    System.Globalization.DateTimeStyles.AssumeUniversal |
                    System.Globalization.DateTimeStyles.AdjustToUniversal,
                    out DateTimeOffset enrolledAt))
            {
                throw new OperationalEnrollmentException(
                    "enrollment-receipt-timestamp-invalid",
                    retryable: false);
            }

            return IpcResponse.Ok(request.RequestId, new OperationalEnrollmentCompletedPayload(
                receipt.Protocol,
                receipt.NodeId,
                receipt.WorkerKeyId,
                receipt.WorkerPublicKeyFingerprint,
                receipt.OwnerUserId,
                receipt.OwnerEmail,
                receipt.OwnerSshKeyId,
                receipt.OwnerSshKeyFingerprint,
                receipt.Status,
                enrolledAt));
        }
        finally
        {
            payload.Clear();
        }
    }

    private async Task<SanitizedLogsPayload> ExportLogsAsync(
        IpcRequest request,
        CancellationToken cancellationToken)
    {
        ExportLogsPayload payload = IpcValidation.Payload<ExportLogsPayload>(request.Payload);
        IReadOnlyList<SanitizedLogEntry> entries = await logs
            .ReadAsync(payload.Since, payload.MaximumEntries, cancellationToken)
            .ConfigureAwait(false);
        return new SanitizedLogsPayload(entries.Select(static entry => new SanitizedLogEntryPayload(
            entry.Timestamp,
            entry.Level,
            entry.EventCode,
            entry.Message,
            entry.Fields)).ToArray());
    }

    private static string ErrorCode(Exception error) => error switch
    {
        WorkerControlException controlError => controlError.Code,
        OperationalEnrollmentException enrollmentError => enrollmentError.Code,
        OrchestratorRequestException orchestratorError => orchestratorError.Code,
        WorkerServiceException serviceError => serviceError.Code,
        Hch.Worker.Protocol.ProtocolValidationException protocolError => protocolError.Code,
        IpcContractException ipcError => ipcError.Code,
        UnauthorizedAccessException => "ipc-client-unauthorized",
        IpcOperationTimeoutException timeoutError => timeoutError.Code,
        OperationCanceledException => "ipc-command-cancelled",
        _ => "ipc-command-failed",
    };

    private static TimeSpan ValidateTimeout(TimeSpan value, string parameterName)
    {
        if (value <= TimeSpan.Zero || value > TimeSpan.FromMinutes(10))
        {
            throw new ArgumentOutOfRangeException(parameterName);
        }

        return value;
    }

    [DllImport("libc", EntryPoint = "geteuid", SetLastError = false)]
    private static extern uint GetEffectiveUserId();

    private sealed class IpcOperationTimeoutException(string code, Exception innerException)
        : TimeoutException(code, innerException)
    {
        public string Code { get; } = code;
    }
}
