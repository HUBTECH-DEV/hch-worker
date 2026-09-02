using System.Collections.Concurrent;
using System.Threading.Channels;

namespace Hch.Worker.Core;

public sealed record WorkerJob(
    string AssignmentId,
    string LeaseToken,
    DateTimeOffset LeaseExpiresAt,
    string GenerationPlanHash,
    object Payload,
    int ItemIndex = 1,
    int BatchTotal = 1);

public sealed record JobExecutionResult(string AssignmentId, string Status, object? Draft = null);

public interface IWorkerJobSource
{
    Task<IReadOnlyList<WorkerJob>> ClaimAsync(int requestedCount, CancellationToken cancellationToken);
}

public interface IWorkerJobExecutor
{
    Task<JobExecutionResult> ExecuteAsync(WorkerJob job, CancellationToken cancellationToken);
}

public interface IWorkerJobReporter
{
    Task CompleteAsync(WorkerJob job, JobExecutionResult result, CancellationToken cancellationToken);

    Task FailAsync(WorkerJob job, string errorCode, CancellationToken cancellationToken);
}

public sealed class ConcurrentJobScheduler : IAsyncDisposable
{
    public const string OperatorStopErrorCode = "operator-stop-requested";
    public const string UnhandledExecutionErrorCode = "worker-unhandled-execution-error";

    private readonly WorkerControlState _control;
    private readonly IWorkerJobSource _source;
    private readonly IWorkerJobExecutor _executor;
    private readonly IWorkerJobReporter _reporter;
    private readonly ConcurrentDictionary<string, ActiveJob> _active = new(StringComparer.Ordinal);
    private readonly Channel<bool> _pulse = Channel.CreateBounded<bool>(new BoundedChannelOptions(1)
    {
        FullMode = BoundedChannelFullMode.DropWrite,
        SingleReader = true,
        SingleWriter = false,
    });
    private readonly object _stopSync = new();
    private CancellationTokenSource _operatorRun = new();
    private int _operatorStopReconciliationFailed;
    private bool _disposed;

    public ConcurrentJobScheduler(
        WorkerControlState control,
        IWorkerJobSource source,
        IWorkerJobExecutor executor,
        IWorkerJobReporter reporter)
    {
        _control = control;
        _source = source;
        _executor = executor;
        _reporter = reporter;
        _control.Changed += OnControlChanged;
    }

    public IReadOnlyCollection<string> ActiveAssignmentIds => _active.Keys.ToArray();

    public async Task RunAsync(CancellationToken serviceStopping)
    {
        ThrowIfDisposed();
        Signal();
        while (true)
        {
            serviceStopping.ThrowIfCancellationRequested();
            await FillAvailableSlotsAsync(serviceStopping).ConfigureAwait(false);
            await _pulse.Reader.ReadAsync(serviceStopping).ConfigureAwait(false);
        }
    }

    public void ResumeAfterStop()
    {
        lock (_stopSync)
        {
            ThrowIfDisposed();
            if (!_operatorRun.IsCancellationRequested)
            {
                return;
            }

            _operatorRun.Dispose();
            _operatorRun = new CancellationTokenSource();
        }

        Signal();
    }

    public async Task StopAsync(CancellationToken cancellationToken)
    {
        ThrowIfDisposed();
        Interlocked.Exchange(ref _operatorStopReconciliationFailed, 0);
        _control.BeginStop();
        CancellationTokenSource operatorRun;
        lock (_stopSync)
        {
            operatorRun = _operatorRun;
            if (!operatorRun.IsCancellationRequested)
            {
                operatorRun.Cancel();
            }
        }

        Signal();
        while (_active.Count > 0)
        {
            var tasks = _active.Values.Select(static active => active.Task).ToArray();
            await Task.WhenAll(tasks).WaitAsync(cancellationToken).ConfigureAwait(false);
        }

        if (Volatile.Read(ref _operatorStopReconciliationFailed) != 0)
        {
            throw new WorkerControlException(
                "operator-stop-reconciliation-pending",
                "At least one active assignment could not report the operator stop durably.");
        }

        _control.CompleteStop();
    }

    private async Task FillAvailableSlotsAsync(CancellationToken serviceStopping)
    {
        while (!serviceStopping.IsCancellationRequested)
        {
            var snapshot = _control.Snapshot;
            if (!snapshot.AcceptingClaims || snapshot.AvailableSlots < 1)
            {
                return;
            }

            int recommended = _control.CurrentRecommendedClaimCount();
            if (recommended < 1)
            {
                return;
            }

            var requested = Math.Min(recommended, snapshot.ClaimBatchSize);
            var reserved = 0;
            while (reserved < requested && _control.TryReserveClaimSlot())
            {
                reserved++;
            }

            if (reserved == 0)
            {
                return;
            }

            IReadOnlyList<WorkerJob> claimed;
            try
            {
                claimed = await _source.ClaimAsync(reserved, serviceStopping).ConfigureAwait(false);
                if (claimed.Count > reserved)
                {
                    _control.MarkNotReady("scheduler-claim-capacity-invalid");
                    throw new WorkerControlException(
                        "claim-capacity-exceeded",
                        "The orchestrator returned more assignments than reserved slots.");
                }

                if (claimed.Any(static job => job.BatchTotal is < 1 or > WorkerControlState.MaximumParallelism
                    || job.ItemIndex < 1 || job.ItemIndex > job.BatchTotal))
                {
                    _control.MarkNotReady("scheduler-claim-batch-invalid");
                    throw new WorkerControlException(
                        "claim-batch-metadata-invalid",
                        "The claimed assignment batch metadata is invalid.");
                }

                if (HasDuplicateAssignments(claimed)
                    || claimed.Any(job => _active.ContainsKey(job.AssignmentId)))
                {
                    _control.MarkNotReady("scheduler-claim-duplicate");
                    throw new WorkerControlException(
                        "assignment-duplicate",
                        "The claimed assignments are not unique and inactive.");
                }

                foreach (var job in claimed)
                {
                    _control.ActivateReservation();
                    reserved--;
                    StartJob(job, serviceStopping);
                }
            }
            finally
            {
                // Claim parsing, validation and activation are a single reservation
                // boundary. Every slot not converted into an active job is released,
                // including exceptions raised half-way through a returned batch.
                ReleaseReservations(reserved);
            }

            if (claimed.Count == 0)
            {
                return;
            }
        }
    }

    private void StartJob(WorkerJob job, CancellationToken serviceStopping)
    {
        if (_active.ContainsKey(job.AssignmentId))
        {
            _control.MarkNotReady("scheduler-start-duplicate");
            _control.FinishJob("scheduler-duplicate");
            throw new WorkerControlException("assignment-duplicate", "The assignment is already active.");
        }

        CancellationToken operatorToken;
        lock (_stopSync)
        {
            operatorToken = _operatorRun.Token;
        }

        var linked = CancellationTokenSource.CreateLinkedTokenSource(serviceStopping, operatorToken);
        var active = new ActiveJob(linked);
        if (!_active.TryAdd(job.AssignmentId, active))
        {
            linked.Cancel();
            linked.Dispose();
            _control.MarkNotReady("scheduler-start-duplicate");
            _control.FinishJob("scheduler-duplicate");
            throw new WorkerControlException("assignment-duplicate", "The assignment is already active.");
        }

        // Register the active slot before invoking user code. An executor or
        // reporter is allowed to complete synchronously; starting it first
        // could otherwise leave a completed assignment stranded in _active.
        active.Attach(ExecuteJobAsync(job, linked, operatorToken));
    }

    private async Task ExecuteJobAsync(
        WorkerJob job,
        CancellationTokenSource linked,
        CancellationToken operatorToken)
    {
        try
        {
            JobExecutionResult result;
            try
            {
                result = await _executor.ExecuteAsync(job, linked.Token).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (operatorToken.IsCancellationRequested)
            {
                if (!await TryReportFailureAsync(job, OperatorStopErrorCode).ConfigureAwait(false))
                {
                    Interlocked.Exchange(ref _operatorStopReconciliationFailed, 1);
                }
                return;
            }
            catch (OperationCanceledException) when (linked.IsCancellationRequested)
            {
                // SCM shutdown is distinct from operational Stop. The persisted journal
                // owns reconciliation at the next boot and no operator failure is forged.
                return;
            }
            catch (WorkerJobException error)
            {
                _ = await TryReportFailureAsync(job, error.Code).ConfigureAwait(false);
                return;
            }
            catch (Exception error) when (IsCatchable(error))
            {
                // Unknown executor failures are never allowed to silently free a slot
                // and continue claiming. Report a fixed, non-sensitive code and require
                // a fresh readiness decision before work can resume.
                _control.MarkNotReady("scheduler-unhandled-execution-error");
                _ = await TryReportFailureAsync(job, UnhandledExecutionErrorCode).ConfigureAwait(false);
                return;
            }

            try
            {
                await _reporter.CompleteAsync(job, result, CancellationToken.None).ConfigureAwait(false);
            }
            catch (WorkerJobException error)
            {
                // Reporter validation failed before an outcome could be sent.
                // This remains a normal, durably reportable assignment failure.
                _ = await TryReportFailureAsync(job, error.Code).ConfigureAwait(false);
            }
            catch (Exception error) when (IsCatchable(error))
            {
                // A completion may already have reached the orchestrator. Never convert
                // an unknown completion into Fail; the durable reporter journal owns
                // reconciliation and the Worker drains until it is resolved.
                _control.MarkNotReady("scheduler-complete-outcome-unknown");
            }
        }
        finally
        {
            // Publish the control-state release before removing the task from
            // the active index. StopAsync uses that index as its drain barrier;
            // removing first creates a race where CompleteStop can still see
            // ActiveJobs == 1 even though the index is already empty.
            try
            {
                _control.FinishJob();
            }
            finally
            {
                _active.TryRemove(job.AssignmentId, out _);
                linked.Dispose();
                Signal();
            }
        }
    }

    private async Task<bool> TryReportFailureAsync(WorkerJob job, string errorCode)
    {
        try
        {
            await _reporter.FailAsync(job, errorCode, CancellationToken.None).ConfigureAwait(false);
            return true;
        }
        catch (Exception error) when (IsCatchable(error))
        {
            _control.MarkNotReady("scheduler-fail-outcome-unknown");
            return false;
        }
    }

    private static bool HasDuplicateAssignments(IReadOnlyList<WorkerJob> jobs)
    {
        var assignmentIds = new HashSet<string>(StringComparer.Ordinal);
        return jobs.Any(job => !assignmentIds.Add(job.AssignmentId));
    }

    private static bool IsCatchable(Exception error) =>
        error is not (OutOfMemoryException or AccessViolationException);

    private void ReleaseReservations(int count)
    {
        for (var index = 0; index < count; index++)
        {
            _control.ReleaseReservation();
        }
    }

    private void OnControlChanged(object? sender, WorkerControlSnapshot snapshot)
    {
        // Reservation bookkeeping happens inside FillAvailableSlotsAsync. If it
        // emits a new wake-up for itself when the central queue is empty, the
        // scheduler spins and hammers /claim. Job completion has an explicit
        // Signal() in finally; operator/orchestrator changes still wake here.
        if (!snapshot.UpdatedBy.StartsWith("scheduler-", StringComparison.Ordinal))
        {
            Signal();
        }
    }

    private void Signal() => _pulse.Writer.TryWrite(true);

    private void ThrowIfDisposed()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
    }

    public async ValueTask DisposeAsync()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        _control.Changed -= OnControlChanged;
        _operatorRun.Cancel();
        await Task.WhenAll(_active.Values.Select(static value => value.Task)).ConfigureAwait(false);
        _operatorRun.Dispose();
    }

    private sealed class ActiveJob(CancellationTokenSource cancellation)
    {
        private readonly TaskCompletionSource _completion = new(
            TaskCreationOptions.RunContinuationsAsynchronously);
        private int _attached;

        public Task Task => _completion.Task;

        public CancellationTokenSource Cancellation { get; } = cancellation;

        public void Attach(Task execution)
        {
            if (Interlocked.Exchange(ref _attached, 1) != 0)
            {
                throw new InvalidOperationException("An active job execution was already attached.");
            }

            _ = ObserveAsync(execution);
        }

        private async Task ObserveAsync(Task execution)
        {
            try
            {
                await execution.ConfigureAwait(false);
                _completion.TrySetResult();
            }
            catch (OperationCanceledException error)
            {
                _completion.TrySetCanceled(error.CancellationToken);
            }
            catch (Exception error)
            {
                _completion.TrySetException(error);
            }
        }
    }
}

public sealed class WorkerJobException(string code, string message, Exception? innerException = null)
    : Exception(message, innerException)
{
    public string Code { get; } = ValidateCode(code);

    private static string ValidateCode(string value)
    {
        if (string.IsNullOrWhiteSpace(value) || value.Length > 200 ||
            !char.IsAsciiLetterOrDigit(value[0]) ||
            value.Any(static character => !(char.IsAsciiLetterOrDigit(character) || character is '.' or '_' or '-')))
        {
            throw new ArgumentException("The error code is not protocol-safe.", nameof(value));
        }

        return value.ToLowerInvariant();
    }
}
