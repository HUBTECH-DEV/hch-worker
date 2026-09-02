using System.Collections.Concurrent;
using Hch.Worker.Core;

namespace Hch.Worker.Tests;

public sealed class CoreSchedulerTests
{
    [Fact]
    public async Task CompletedSlotIsRefilledWhileOtherJobsContinue()
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var control = new WorkerControlState(lastNonZeroMaxConcurrentJobs: 4, claimBatchSize: 4);
        control.MarkReady();
        control.Start();
        control.SetGrantedCapacity(4);
        var source = new QueueSource(Enumerable.Range(1, 5).Select(Job).ToArray());
        var executor = new GateExecutor();
        var reporter = new RecordingReporter();
        await using var scheduler = new ConcurrentJobScheduler(control, source, executor, reporter);
        using var service = new CancellationTokenSource();
        var run = scheduler.RunAsync(service.Token);

        await executor.WaitForStartedAsync(4, timeout.Token);
        executor.Release("assignment-1");
        await executor.WaitForStartedAsync(5, timeout.Token);

        Assert.Contains("assignment-5", executor.Started);
        Assert.Equal(4, control.Snapshot.ActiveJobs);

        executor.ReleaseAll();
        await reporter.WaitForCompletedAsync(5, timeout.Token);
        service.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => run);
    }

    [Fact]
    public async Task PauseLeavesActiveJobRunningAndPreventsReplacement()
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var control = new WorkerControlState(lastNonZeroMaxConcurrentJobs: 1);
        control.MarkReady();
        control.Start();
        control.SetGrantedCapacity(1);
        var source = new QueueSource([Job(1), Job(2)]);
        var executor = new GateExecutor();
        var reporter = new RecordingReporter();
        await using var scheduler = new ConcurrentJobScheduler(control, source, executor, reporter);
        using var service = new CancellationTokenSource();
        var run = scheduler.RunAsync(service.Token);
        await executor.WaitForStartedAsync(1, timeout.Token);

        control.Pause();
        Assert.False(executor.WasCancelled("assignment-1"));
        executor.Release("assignment-1");
        await reporter.WaitForCompletedAsync(1, timeout.Token);
        await Task.Delay(100, timeout.Token);
        Assert.DoesNotContain("assignment-2", executor.Started);

        service.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => run);
    }

    [Fact]
    public async Task StopCancelsAndReportsOperatorStopBeforeCompleting()
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var control = new WorkerControlState(lastNonZeroMaxConcurrentJobs: 1);
        control.MarkReady();
        control.Start();
        control.SetGrantedCapacity(1);
        var source = new QueueSource([Job(1)]);
        var executor = new GateExecutor();
        var reporter = new RecordingReporter();
        await using var scheduler = new ConcurrentJobScheduler(control, source, executor, reporter);
        using var service = new CancellationTokenSource();
        var run = scheduler.RunAsync(service.Token);
        await executor.WaitForStartedAsync(1, timeout.Token);

        await scheduler.StopAsync(timeout.Token);

        Assert.Contains(("assignment-1", ConcurrentJobScheduler.OperatorStopErrorCode), reporter.Failures);
        Assert.Equal(WorkerOperationalState.Stopped, control.Snapshot.State);
        service.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => run);
    }

    [Fact]
    public async Task SynchronousCompletionNeverLeavesAStaleActiveSlot()
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var control = new WorkerControlState(lastNonZeroMaxConcurrentJobs: 1);
        control.MarkReady();
        control.Start();
        control.SetGrantedCapacity(1);
        var source = new QueueSource([Job(1)]);
        var reporter = new RecordingReporter();
        await using var scheduler = new ConcurrentJobScheduler(
            control,
            source,
            new ImmediateExecutor(),
            reporter);
        using var service = new CancellationTokenSource();
        var run = scheduler.RunAsync(service.Token);

        await reporter.WaitForCompletedAsync(1, timeout.Token);
        while (control.Snapshot.ActiveJobs != 0)
        {
            await Task.Delay(10, timeout.Token);
        }
        Assert.Empty(scheduler.ActiveAssignmentIds);
        Assert.Equal(0, control.Snapshot.ActiveJobs);

        service.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => run);
    }

    [Fact]
    public async Task UnexpectedExecutorFailureIsReportedAndBlocksReplacementClaims()
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var control = new WorkerControlState(lastNonZeroMaxConcurrentJobs: 1);
        control.MarkReady();
        control.Start();
        control.SetGrantedCapacity(1);
        var source = new QueueSource([Job(1), Job(2)]);
        var executor = new FirstCallThrowsExecutor();
        var reporter = new RecordingReporter();
        await using var scheduler = new ConcurrentJobScheduler(control, source, executor, reporter);
        using var service = new CancellationTokenSource();
        var run = scheduler.RunAsync(service.Token);

        await WaitUntilAsync(
            () => reporter.Failures.Count == 1 && control.Snapshot.ActiveJobs == 0,
            timeout.Token);

        Assert.Contains(
            ("assignment-1", ConcurrentJobScheduler.UnhandledExecutionErrorCode),
            reporter.Failures);
        Assert.Equal(WorkerOperationalState.NotReady, control.Snapshot.State);
        Assert.False(control.Snapshot.Ready);
        Assert.False(control.Snapshot.AcceptingClaims);
        Assert.Equal(["assignment-1"], executor.Started);

        service.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => run);
    }

    [Fact]
    public async Task UnknownCompletionIsNotConvertedIntoFailureAndStopsNewClaims()
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var control = new WorkerControlState(lastNonZeroMaxConcurrentJobs: 1);
        control.MarkReady();
        control.Start();
        control.SetGrantedCapacity(1);
        var source = new QueueSource([Job(1), Job(2)]);
        var executor = new CountingImmediateExecutor();
        var reporter = new CompletionThrowsReporter();
        await using var scheduler = new ConcurrentJobScheduler(control, source, executor, reporter);
        using var service = new CancellationTokenSource();
        var run = scheduler.RunAsync(service.Token);

        await WaitUntilAsync(
            () => reporter.CompletionAttempts == 1 && control.Snapshot.ActiveJobs == 0,
            timeout.Token);

        Assert.Equal(WorkerOperationalState.NotReady, control.Snapshot.State);
        Assert.Equal(["assignment-1"], executor.Started);
        Assert.Equal(0, reporter.FailureAttempts);

        service.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => run);
    }

    [Fact]
    public async Task DuplicateClaimBatchFailsClosedAndReleasesEveryReservation()
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var control = new WorkerControlState(lastNonZeroMaxConcurrentJobs: 2, claimBatchSize: 2);
        control.MarkReady();
        control.Start();
        control.SetGrantedCapacity(2);
        var duplicate = Job(1);
        var source = new QueueSource([duplicate, duplicate]);
        var executor = new CountingImmediateExecutor();
        await using var scheduler = new ConcurrentJobScheduler(
            control,
            source,
            executor,
            new RecordingReporter());

        var error = await Assert.ThrowsAsync<WorkerControlException>(
            () => scheduler.RunAsync(timeout.Token));

        Assert.Equal("assignment-duplicate", error.Code);
        Assert.Equal(WorkerOperationalState.NotReady, control.Snapshot.State);
        Assert.Equal(0, control.Snapshot.ReservedJobs);
        Assert.Equal(0, control.Snapshot.ActiveJobs);
        Assert.Empty(executor.Started);
    }

    [Fact]
    public async Task StopDoesNotCompleteWhenFailureOutcomeCannotBeReconciled()
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var control = new WorkerControlState(lastNonZeroMaxConcurrentJobs: 1);
        control.MarkReady();
        control.Start();
        control.SetGrantedCapacity(1);
        var executor = new GateExecutor();
        await using var scheduler = new ConcurrentJobScheduler(
            control,
            new QueueSource([Job(1)]),
            executor,
            new FailureThrowsReporter());
        using var service = new CancellationTokenSource();
        var run = scheduler.RunAsync(service.Token);
        await executor.WaitForStartedAsync(1, timeout.Token);

        var error = await Assert.ThrowsAsync<WorkerControlException>(
            () => scheduler.StopAsync(timeout.Token));

        Assert.Equal("operator-stop-reconciliation-pending", error.Code);
        Assert.NotEqual(WorkerOperationalState.Stopped, control.Snapshot.State);
        Assert.False(control.Snapshot.Ready);
        service.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => run);
    }

    private static WorkerJob Job(int number) => new(
        $"assignment-{number}",
        $"lease-{number}",
        DateTimeOffset.UtcNow.AddMinutes(3),
        new string('a', 64),
        new { Number = number });

    private sealed class QueueSource(IEnumerable<WorkerJob> jobs) : IWorkerJobSource
    {
        private readonly ConcurrentQueue<WorkerJob> _jobs = new(jobs);

        public Task<IReadOnlyList<WorkerJob>> ClaimAsync(int requestedCount, CancellationToken cancellationToken)
        {
            var claimed = new List<WorkerJob>();
            while (claimed.Count < requestedCount && _jobs.TryDequeue(out var job))
            {
                claimed.Add(job);
            }

            return Task.FromResult<IReadOnlyList<WorkerJob>>(claimed);
        }
    }

    private sealed class GateExecutor : IWorkerJobExecutor
    {
        private readonly ConcurrentDictionary<string, TaskCompletionSource> _gates = new(StringComparer.Ordinal);
        private readonly ConcurrentDictionary<string, bool> _cancelled = new(StringComparer.Ordinal);

        public IReadOnlyCollection<string> Started => _gates.Keys.ToArray();

        public async Task<JobExecutionResult> ExecuteAsync(WorkerJob job, CancellationToken cancellationToken)
        {
            var gate = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            if (!_gates.TryAdd(job.AssignmentId, gate))
            {
                throw new InvalidOperationException("Duplicate test assignment.");
            }

            try
            {
                await gate.Task.WaitAsync(cancellationToken);
                return new JobExecutionResult(job.AssignmentId, "pending-review", new { });
            }
            catch (OperationCanceledException)
            {
                _cancelled[job.AssignmentId] = true;
                throw;
            }
        }

        public void Release(string assignmentId) => _gates[assignmentId].TrySetResult();

        public void ReleaseAll()
        {
            foreach (var gate in _gates.Values)
            {
                gate.TrySetResult();
            }
        }

        public bool WasCancelled(string assignmentId) => _cancelled.ContainsKey(assignmentId);

        public async Task WaitForStartedAsync(int count, CancellationToken cancellationToken)
        {
            while (_gates.Count < count)
            {
                await Task.Delay(10, cancellationToken);
            }
        }
    }

    private sealed class ImmediateExecutor : IWorkerJobExecutor
    {
        public Task<JobExecutionResult> ExecuteAsync(WorkerJob job, CancellationToken cancellationToken) =>
            Task.FromResult(new JobExecutionResult(job.AssignmentId, "pending-review", new { }));
    }

    private sealed class FirstCallThrowsExecutor : IWorkerJobExecutor
    {
        public ConcurrentQueue<string> Started { get; } = new();

        public Task<JobExecutionResult> ExecuteAsync(WorkerJob job, CancellationToken cancellationToken)
        {
            Started.Enqueue(job.AssignmentId);
            throw new HttpRequestException("simulated local model transport failure");
        }
    }

    private sealed class CountingImmediateExecutor : IWorkerJobExecutor
    {
        public ConcurrentQueue<string> Started { get; } = new();

        public Task<JobExecutionResult> ExecuteAsync(WorkerJob job, CancellationToken cancellationToken)
        {
            Started.Enqueue(job.AssignmentId);
            return Task.FromResult(new JobExecutionResult(job.AssignmentId, "pending-review", new { }));
        }
    }

    private sealed class RecordingReporter : IWorkerJobReporter
    {
        private readonly ConcurrentDictionary<string, bool> _completed = new(StringComparer.Ordinal);
        public ConcurrentBag<(string AssignmentId, string Code)> Failures { get; } = [];

        public Task CompleteAsync(WorkerJob job, JobExecutionResult result, CancellationToken cancellationToken)
        {
            _completed[job.AssignmentId] = true;
            return Task.CompletedTask;
        }

        public Task FailAsync(WorkerJob job, string errorCode, CancellationToken cancellationToken)
        {
            Failures.Add((job.AssignmentId, errorCode));
            return Task.CompletedTask;
        }

        public async Task WaitForCompletedAsync(int count, CancellationToken cancellationToken)
        {
            while (_completed.Count < count)
            {
                await Task.Delay(10, cancellationToken);
            }
        }
    }

    private sealed class CompletionThrowsReporter : IWorkerJobReporter
    {
        private int completionAttempts;
        private int failureAttempts;

        public int CompletionAttempts => Volatile.Read(ref completionAttempts);
        public int FailureAttempts => Volatile.Read(ref failureAttempts);

        public Task CompleteAsync(WorkerJob job, JobExecutionResult result, CancellationToken cancellationToken)
        {
            Interlocked.Increment(ref completionAttempts);
            throw new IOException("simulated unknown completion outcome");
        }

        public Task FailAsync(WorkerJob job, string errorCode, CancellationToken cancellationToken)
        {
            Interlocked.Increment(ref failureAttempts);
            return Task.CompletedTask;
        }
    }

    private sealed class FailureThrowsReporter : IWorkerJobReporter
    {
        public Task CompleteAsync(WorkerJob job, JobExecutionResult result, CancellationToken cancellationToken) =>
            Task.CompletedTask;

        public Task FailAsync(WorkerJob job, string errorCode, CancellationToken cancellationToken) =>
            throw new IOException("simulated failure outcome outage");
    }

    private static async Task WaitUntilAsync(Func<bool> predicate, CancellationToken cancellationToken)
    {
        while (!predicate())
        {
            await Task.Delay(10, cancellationToken);
        }
    }
}
