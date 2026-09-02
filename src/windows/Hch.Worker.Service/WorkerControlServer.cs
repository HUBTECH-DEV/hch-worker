using System.IO.Pipes;
using System.Security.Principal;
using Hch.Worker.Core;
using Hch.Worker.IPC.Contracts;
using Hch.Worker.Windows;

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
        ConcurrentJobScheduler? scheduler,
        TimeProvider? timeProvider = null,
        Func<WorkerControlSnapshot, CancellationToken, Task>? persistConfiguration = null,
        Func<CancellationToken, Task>? ensureExclusiveClaiming = null)
        : this(control, () => scheduler, timeProvider, persistConfiguration, ensureExclusiveClaiming)
    {
    }

    public WorkerOperationalController(
        WorkerControlState control,
        WorkerSchedulerHost schedulerHost,
        TimeProvider? timeProvider = null,
        Func<WorkerControlSnapshot, CancellationToken, Task>? persistConfiguration = null,
        Func<CancellationToken, Task>? ensureExclusiveClaiming = null)
        : this(
            control,
            () => schedulerHost.Current,
            timeProvider,
            persistConfiguration,
            ensureExclusiveClaiming)
    {
        ArgumentNullException.ThrowIfNull(schedulerHost);
    }

    private WorkerOperationalController(
        WorkerControlState control,
        Func<ConcurrentJobScheduler?> scheduler,
        TimeProvider? timeProvider,
        Func<WorkerControlSnapshot, CancellationToken, Task>? persistConfiguration,
        Func<CancellationToken, Task>? ensureExclusiveClaiming)
    {
        this.control = control ?? throw new ArgumentNullException(nameof(control));
        this.scheduler = scheduler ?? throw new ArgumentNullException(nameof(scheduler));
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
        try
        {
            return control.Pause();
        }
        finally
        {
            commandGate.Release();
        }
    }

    public async Task<WorkerControlSnapshot> StopAsync(CancellationToken cancellationToken = default)
    {
        await commandGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var currentScheduler = scheduler();
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

public sealed class WorkerControlPipeServer(
    WorkerConfiguration configuration,
    WorkerOperationalController controller,
    Func<WorkerSnapshotPayload> snapshot,
    SanitizedLogStore logs,
    OperationalEnrollmentCoordinator? enrollment,
    PostEnrollmentRuntimeActivator? postEnrollmentActivation,
    TimeProvider? timeProvider = null)
{
    private readonly TimeProvider clock = timeProvider ?? TimeProvider.System;

    public async Task RunAsync(CancellationToken serviceStopping)
    {
        if (configuration.OwnerSid is null)
        {
            await Task.Delay(Timeout.InfiniteTimeSpan, clock, serviceStopping).ConfigureAwait(false);
            return;
        }

        var ownerSid = new SecurityIdentifier(configuration.OwnerSid);
        var serviceSid = WindowsServiceIdentity.ResolveServiceSid(Worker.ServiceName);
        var pipeName = IpcProtocol.PipeName(configuration.NodeId);
        while (!serviceStopping.IsCancellationRequested)
        {
            await using var pipe = LocalNamedPipe.CreateServer(pipeName, ownerSid, serviceSid);
            await pipe.WaitForConnectionAsync(serviceStopping).ConfigureAwait(false);
            await ProcessOneAsync(pipe, ownerSid, serviceStopping).ConfigureAwait(false);
        }
    }

    internal async Task ProcessOneAsync(
        NamedPipeServerStream pipe,
        SecurityIdentifier ownerSid,
        CancellationToken cancellationToken)
    {
        IpcRequest? request = null;
        IpcResponse response;
        try
        {
            NamedPipeClientAuthorization authorization =
                LocalNamedPipe.GetClientAuthorization(pipe, ownerSid);
            request = await IpcFraming.ReadAsync<IpcRequest>(pipe, cancellationToken).ConfigureAwait(false);
            IpcValidation.Request(request, clock.GetUtcNow());
            if (!IsCommandAuthorized(authorization, request.Command))
            {
                throw new UnauthorizedAccessException("ipc-command-owner-required");
            }

            response = await DispatchAsync(request, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception error)
        {
            var requestId = request?.RequestId;
            if (!Guid.TryParseExact(requestId, "D", out _))
            {
                requestId = Guid.NewGuid().ToString("D");
            }

            response = IpcResponse.Error(requestId!, ErrorCode(error));
        }

        await IpcFraming.WriteAsync(pipe, response, cancellationToken).ConfigureAwait(false);
    }

    internal static bool IsCommandAuthorized(
        NamedPipeClientAuthorization authorization,
        IpcCommand command) =>
        authorization.IsOwner
        || (authorization.IsLocalAdministrator && command == IpcCommand.PrepareMaintenance);

    internal async Task<IpcResponse> DispatchAsync(IpcRequest request, CancellationToken cancellationToken)
    {
        return request.Command switch
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
            IpcCommand.PrepareMaintenance => await PrepareMaintenanceAsync(
                request,
                cancellationToken).ConfigureAwait(false),
            IpcCommand.ExportSanitizedLogs => IpcResponse.Ok(
                request.RequestId,
                await ExportLogsAsync(request, cancellationToken).ConfigureAwait(false)),
            IpcCommand.BeginEnrollment => await BeginEnrollmentAsync(request, cancellationToken)
                .ConfigureAwait(false),
            IpcCommand.SubmitEnrollmentToken => await CompleteEnrollmentAsync(request, cancellationToken)
                .ConfigureAwait(false),
            _ => IpcResponse.Error(request.RequestId, "ipc-command-unsupported"),
        };
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
        var payload = IpcValidation.Payload<BeginEnrollmentPayload>(request.Payload);
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

        var payload = IpcValidation.Payload<EnrollmentTokenPayload>(request.Payload);
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
            // Enrollment tokens are no longer needed once the durable public
            // receipt exists. Clear them before bootstrap/artifact work begins.
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
                    out var enrolledAt))
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
        var payload = IpcValidation.Payload<ExportLogsPayload>(request.Payload);
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
        WorkerControlException control => control.Code,
        OperationalEnrollmentException enrollment => enrollment.Code,
        OrchestratorRequestException orchestrator => orchestrator.Code,
        WorkerServiceException service => service.Code,
        LegacyWorkerCutoverException cutover => cutover.Code,
        Hch.Worker.Protocol.ProtocolValidationException protocol => protocol.Code,
        IpcContractException ipc => ipc.Code,
        UnauthorizedAccessException => "ipc-client-unauthorized",
        OperationCanceledException => "ipc-command-cancelled",
        _ => "ipc-command-failed",
    };
}
