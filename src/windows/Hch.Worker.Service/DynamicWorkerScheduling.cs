using Hch.Worker.Core;

namespace Hch.Worker.Service;

/// <summary>
/// Publishes the single scheduler owned by the service process. A scheduler may
/// appear after the service has already started (for example, after native
/// enrollment), while readers always observe either no scheduler or the fully
/// composed scheduler.
/// </summary>
public sealed class WorkerSchedulerHost : IAsyncDisposable
{
    private readonly object gate = new();
    private TaskCompletionSource<bool> changed = NewSignal();
    private ConcurrentJobScheduler? current;
    private bool disposed;

    public ConcurrentJobScheduler? Current
    {
        get
        {
            lock (gate)
            {
                return current;
            }
        }
    }

    public bool TryPublish(ConcurrentJobScheduler scheduler)
    {
        ArgumentNullException.ThrowIfNull(scheduler);
        lock (gate)
        {
            ObjectDisposedException.ThrowIf(disposed, this);
            if (current is not null)
            {
                return false;
            }

            current = scheduler;
            changed.TrySetResult(true);
            changed = NewSignal();
            return true;
        }
    }

    public async Task<ConcurrentJobScheduler> WaitForSchedulerAsync(
        CancellationToken cancellationToken)
    {
        while (true)
        {
            Task signal;
            lock (gate)
            {
                ObjectDisposedException.ThrowIf(disposed, this);
                if (current is not null)
                {
                    return current;
                }

                signal = changed.Task;
            }

            await signal.WaitAsync(cancellationToken).ConfigureAwait(false);
        }
    }

    public async ValueTask DisposeAsync()
    {
        ConcurrentJobScheduler? scheduler;
        lock (gate)
        {
            if (disposed)
            {
                return;
            }

            disposed = true;
            scheduler = current;
            current = null;
            changed.TrySetResult(true);
        }

        if (scheduler is not null)
        {
            await scheduler.DisposeAsync().ConfigureAwait(false);
        }
    }

    private static TaskCompletionSource<bool> NewSignal() => new(
        TaskCreationOptions.RunContinuationsAsynchronously);
}

/// <summary>
/// Serializes the post-enrollment transition. Composition happens while the
/// Worker is fail-closed; publishing the scheduler precedes the final Paused
/// readiness commit, so no observer can start claims without an executable
/// scheduler.
/// </summary>
public sealed class PostEnrollmentRuntimeActivator(
    WorkerControlState control,
    WorkerSchedulerHost schedulerHost,
    Func<CancellationToken, Task<ConcurrentJobScheduler>> composeScheduler)
{
    private readonly SemaphoreSlim activationGate = new(1, 1);

    public async Task<WorkerControlSnapshot> ActivatePausedAsync(
        CancellationToken cancellationToken = default)
    {
        await activationGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var paused = control.Pause("post-enrollment-drain");
            if (paused.ActiveJobs > 0 || paused.ReservedJobs > 0)
            {
                throw Error(
                    "post-enrollment-drain-pending",
                    "Active or reserved work must drain before bootstrap activation.");
            }

            if (schedulerHost.Current is not null)
            {
                if (paused.Ready)
                {
                    return paused;
                }

                throw Error(
                    "runtime-composition-not-ready",
                    "An existing runtime composition is not ready and cannot be replaced by enrollment.");
            }

            control.MarkNotReady("post-enrollment-bootstrap-pending");
            ConcurrentJobScheduler? candidate = null;
            var published = false;
            try
            {
                candidate = await composeScheduler(cancellationToken).ConfigureAwait(false);
                if (!schedulerHost.TryPublish(candidate))
                {
                    throw Error(
                        "runtime-composition-race",
                        "Another runtime composition was published concurrently.");
                }

                published = true;
                return control.MarkReady("post-enrollment-readiness-paused");
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                control.MarkNotReady("post-enrollment-bootstrap-cancelled");
                throw;
            }
            catch (Exception error)
            {
                control.MarkNotReady(ErrorCode(error));
                throw;
            }
            finally
            {
                if (candidate is not null && !published)
                {
                    await candidate.DisposeAsync().ConfigureAwait(false);
                }
            }
        }
        finally
        {
            activationGate.Release();
        }
    }

    private static string ErrorCode(Exception error) => error switch
    {
        WorkerServiceException service => service.Code,
        OrchestratorRequestException orchestrator => orchestrator.Code,
        _ => "post-enrollment-bootstrap-failed",
    };

    private static WorkerServiceException Error(string code, string message) => new(code, message);
}
