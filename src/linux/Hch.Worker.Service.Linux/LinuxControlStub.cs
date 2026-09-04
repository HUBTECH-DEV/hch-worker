using Hch.Worker.Core;

namespace Hch.Worker.Service;

/// <summary>
/// Headless operational controller retained for runtime composition. Linux IPC
/// is intentionally unavailable in this host and no external caller can invoke
/// these transitions until the authenticated Unix socket server is integrated.
/// </summary>
public sealed class WorkerOperationalController
{
    private readonly WorkerControlState control;
    private readonly Func<ConcurrentJobScheduler?> scheduler;
    private readonly Func<WorkerControlSnapshot, CancellationToken, Task>? persistConfiguration;
    private readonly Func<CancellationToken, Task>? ensureExclusiveClaiming;
    private readonly SemaphoreSlim gate = new(1, 1);

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
        this.persistConfiguration = persistConfiguration;
        this.ensureExclusiveClaiming = ensureExclusiveClaiming;
    }

    public WorkerControlSnapshot Snapshot => control.Snapshot;

    public async Task<WorkerControlSnapshot> StartAsync(CancellationToken cancellationToken = default)
    {
        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (ensureExclusiveClaiming is not null)
            {
                await ensureExclusiveClaiming(cancellationToken).ConfigureAwait(false);
            }

            scheduler()?.ResumeAfterStop();
            return control.Start();
        }
        finally
        {
            gate.Release();
        }
    }

    public async Task<WorkerControlSnapshot> PauseAsync(CancellationToken cancellationToken = default)
    {
        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try { return control.Pause(); }
        finally { gate.Release(); }
    }

    public async Task<WorkerControlSnapshot> SetMaxConcurrentJobsAsync(
        int value,
        CancellationToken cancellationToken = default)
    {
        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (value > 0 && ensureExclusiveClaiming is not null)
            {
                await ensureExclusiveClaiming(cancellationToken).ConfigureAwait(false);
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
            gate.Release();
        }
    }
}

/// <summary>
/// Explicit fail-closed placeholder. It keeps the service lifetime alive but
/// opens no pipe, socket, port or command surface.
/// </summary>
public sealed class WorkerControlPipeServer
{
    public WorkerControlPipeServer(
        WorkerConfiguration configuration,
        WorkerOperationalController controller,
        Func<Hch.Worker.IPC.Contracts.WorkerSnapshotPayload> snapshot,
        SanitizedLogStore logs,
        OperationalEnrollmentCoordinator? enrollment,
        PostEnrollmentRuntimeActivator? postEnrollmentActivation,
        TimeProvider? timeProvider = null)
    {
        ArgumentNullException.ThrowIfNull(configuration);
        ArgumentNullException.ThrowIfNull(controller);
        ArgumentNullException.ThrowIfNull(snapshot);
        ArgumentNullException.ThrowIfNull(logs);
        _ = enrollment;
        _ = postEnrollmentActivation;
        _ = timeProvider;
    }

    public Task RunAsync(CancellationToken serviceStopping) =>
        Task.Delay(Timeout.InfiniteTimeSpan, serviceStopping);
}
