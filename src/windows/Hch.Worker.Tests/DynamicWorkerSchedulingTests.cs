using Hch.Worker.Core;
using Hch.Worker.Service;

namespace Hch.Worker.Tests;

public sealed class DynamicWorkerSchedulingTests
{
    [Fact]
    public async Task PostEnrollmentActivationPublishesReadyPausedSchedulerAndStartEnablesClaims()
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var control = new WorkerControlState(lastNonZeroMaxConcurrentJobs: 2, claimBatchSize: 1);
        await using var host = new WorkerSchedulerHost();
        var source = new RecordingSource();
        var compositions = 0;
        var activator = new PostEnrollmentRuntimeActivator(
            control,
            host,
            _ =>
            {
                Interlocked.Increment(ref compositions);
                return Task.FromResult(new ConcurrentJobScheduler(
                    control,
                    source,
                    new UnusedExecutor(),
                    new UnusedReporter()));
            });

        var activated = await activator.ActivatePausedAsync(timeout.Token);
        var replay = await activator.ActivatePausedAsync(timeout.Token);

        Assert.Equal(1, compositions);
        Assert.True(activated.Ready);
        Assert.Equal(WorkerOperationalState.Paused, activated.State);
        Assert.False(activated.AcceptingClaims);
        Assert.Equal(0, activated.MaxConcurrentJobs);
        Assert.Equal(WorkerOperationalState.Paused, replay.State);

        var scheduler = await host.WaitForSchedulerAsync(timeout.Token);
        using var service = new CancellationTokenSource();
        var run = scheduler.RunAsync(service.Token);
        await Task.Delay(100, timeout.Token);
        Assert.Equal(0, source.ClaimCalls);

        var controller = new WorkerOperationalController(control, host);
        var running = await controller.StartAsync(timeout.Token);
        Assert.True(running.AcceptingClaims);
        Assert.Equal(2, running.MaxConcurrentJobs);
        control.ApplyHeartbeatDecision(
            grantedCapacity: 1,
            claimAllowed: true,
            recommendedClaimCount: 1,
            DateTimeOffset.UtcNow.AddMinutes(2),
            "claim-recommended",
            "test-heartbeat");
        await source.FirstClaim.Task.WaitAsync(timeout.Token);

        Assert.True(source.ClaimCalls >= 1);
        service.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => run);
    }

    [Fact]
    public async Task FailedPostEnrollmentBootstrapRemainsNotReadyWithoutPublishingScheduler()
    {
        var control = new WorkerControlState();
        await using var host = new WorkerSchedulerHost();
        var activator = new PostEnrollmentRuntimeActivator(
            control,
            host,
            _ => throw new WorkerServiceException(
                "bootstrap-attestation-rejected",
                "The test bootstrap was rejected."));

        var error = await Assert.ThrowsAsync<WorkerServiceException>(
            () => activator.ActivatePausedAsync());

        Assert.Equal("bootstrap-attestation-rejected", error.Code);
        Assert.Null(host.Current);
        Assert.False(control.Snapshot.Ready);
        Assert.False(control.Snapshot.AcceptingClaims);
        Assert.Equal(WorkerOperationalState.NotReady, control.Snapshot.State);
        var controller = new WorkerOperationalController(control, host);
        var start = await Assert.ThrowsAsync<WorkerControlException>(() => controller.StartAsync());
        Assert.Equal("worker-not-ready", start.Code);
    }

    private sealed class RecordingSource : IWorkerJobSource
    {
        private int claimCalls;

        public int ClaimCalls => Volatile.Read(ref claimCalls);

        public TaskCompletionSource FirstClaim { get; } = new(
            TaskCreationOptions.RunContinuationsAsynchronously);

        public Task<IReadOnlyList<WorkerJob>> ClaimAsync(
            int requestedCount,
            CancellationToken cancellationToken)
        {
            Interlocked.Increment(ref claimCalls);
            FirstClaim.TrySetResult();
            return Task.FromResult<IReadOnlyList<WorkerJob>>([]);
        }
    }

    private sealed class UnusedExecutor : IWorkerJobExecutor
    {
        public Task<JobExecutionResult> ExecuteAsync(WorkerJob job, CancellationToken cancellationToken) =>
            throw new InvalidOperationException("No test job should be returned by the source.");
    }

    private sealed class UnusedReporter : IWorkerJobReporter
    {
        public Task CompleteAsync(
            WorkerJob job,
            JobExecutionResult result,
            CancellationToken cancellationToken) =>
            throw new InvalidOperationException("No test job should complete.");

        public Task FailAsync(WorkerJob job, string errorCode, CancellationToken cancellationToken) =>
            throw new InvalidOperationException("No test job should fail.");
    }
}
