using Hch.Worker.Core;
using Hch.Worker.Ollama;
using Hch.Worker.Protocol;
using Hch.Worker.Service;
using Hch.Worker.Windows;
using Hch.Worker.IPC.Contracts;

namespace Hch.Worker.Tests;

public sealed class ServiceRuntimeTests
{
    [Fact]
    public async Task ReadinessAlwaysEntersPausedDrainAndOperatorControlsAreDistinct()
    {
        var control = new WorkerControlState(lastNonZeroMaxConcurrentJobs: 4, claimBatchSize: 3);

        var ready = control.MarkReady("test-readiness");
        Assert.Equal(WorkerOperationalState.Paused, ready.State);
        Assert.False(ready.AcceptingClaims);
        Assert.Equal(0, ready.MaxConcurrentJobs);
        Assert.Equal(0, ready.GrantedCapacity);

        var controller = new WorkerOperationalController(control, scheduler: null);
        var running = await controller.StartAsync();
        Assert.Equal(WorkerOperationalState.Running, running.State);
        Assert.Equal(4, running.MaxConcurrentJobs);
        Assert.True(running.AcceptingClaims);

        var paused = await controller.SetMaxConcurrentJobsAsync(0);
        Assert.Equal(WorkerOperationalState.Paused, paused.State);
        Assert.False(paused.AcceptingClaims);

        var stopped = await controller.StopAsync();
        Assert.Equal(WorkerOperationalState.Stopped, stopped.State);
        Assert.Equal(0, stopped.ActiveJobs);
    }

    [Fact]
    public void InstalledVersionComesFromServiceAssembly()
    {
        Assert.Equal("4.0.0", WorkerInstalledVersion.Current);
        Assert.Equal(TimeSpan.FromSeconds(60), WorkerServiceRuntime.NodeHeartbeatInterval);
        Assert.Equal(TimeSpan.FromSeconds(30), AssignmentRuntimeRegistry.HeartbeatInterval);
    }

    [Fact]
    public async Task ConfigurationControlValuesRoundTripAtomically()
    {
        string root = Path.Combine(Path.GetTempPath(), "hch-worker-config-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            string path = Path.Combine(root, "config.json");
            WorkerConfiguration value = WorkerConfigurationStore
                .CreatePausedDefault("node-configuration-test", "SHA256:" + new string('A', 43)) with
            {
                LastNonZeroMaxConcurrentJobs = 7,
                ClaimBatchSize = 5,
                StateRoot = Path.Combine(root, "state"),
            };

            await WorkerConfigurationStore.WriteAsync(value, path);
            WorkerConfiguration roundTrip = await WorkerConfigurationStore.ReadAsync(path);

            Assert.Equal(7, roundTrip.LastNonZeroMaxConcurrentJobs);
            Assert.Equal(5, roundTrip.ClaimBatchSize);
            Assert.Equal(value.NodeId, roundTrip.NodeId);
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task ParallelismAndClaimBatchChangesInvokeDurableConfigurationUpdate()
    {
        var control = new WorkerControlState(lastNonZeroMaxConcurrentJobs: 4, claimBatchSize: 2);
        // Runtime configuration can only enable positive concurrency after the
        // signed bootstrap/attestation gate has committed readiness.
        control.MarkReady("test-bootstrap-attested");
        var persisted = new List<(int LastNonZero, int Batch)>();
        var controller = new WorkerOperationalController(
            control,
            scheduler: null,
            persistConfiguration: (snapshot, _) =>
            {
                persisted.Add((snapshot.LastNonZeroMaxConcurrentJobs, snapshot.ClaimBatchSize));
                return Task.CompletedTask;
            });

        await controller.SetMaxConcurrentJobsAsync(6);
        await controller.SetMaxConcurrentJobsAsync(0);
        await controller.SetClaimBatchSizeAsync(9);

        Assert.Equal([(6, 2), (6, 2), (6, 9)], persisted);
        Assert.Equal(WorkerOperationalState.Paused, control.Snapshot.State);
    }

    [Fact]
    public async Task LegacyCutoverGuardBlocksEveryTransitionThatCanEnableClaims()
    {
        var control = new WorkerControlState(lastNonZeroMaxConcurrentJobs: 4, claimBatchSize: 2);
        control.MarkReady("test-bootstrap-attested");
        var controller = new WorkerOperationalController(
            control,
            scheduler: null,
            ensureExclusiveClaiming: _ => throw new Hch.Worker.Windows.LegacyWorkerCutoverException(
                "legacy-worker-cutover-not-exclusive"));

        Hch.Worker.Windows.LegacyWorkerCutoverException start =
            await Assert.ThrowsAsync<Hch.Worker.Windows.LegacyWorkerCutoverException>(
                () => controller.StartAsync());
        Hch.Worker.Windows.LegacyWorkerCutoverException parallelism =
            await Assert.ThrowsAsync<Hch.Worker.Windows.LegacyWorkerCutoverException>(
                () => controller.SetMaxConcurrentJobsAsync(2));

        Assert.Equal("legacy-worker-cutover-not-exclusive", start.Code);
        Assert.Equal("legacy-worker-cutover-not-exclusive", parallelism.Code);
        Assert.Equal(WorkerOperationalState.Paused, control.Snapshot.State);
        Assert.False(control.Snapshot.AcceptingClaims);

        await controller.SetMaxConcurrentJobsAsync(0);
        await controller.PauseAsync();
        await controller.StopAsync();
    }

    [Fact]
    public async Task InstallerMaintenanceLatchesPausedDrainAndRejectsFutureClaims()
    {
        var control = new WorkerControlState(lastNonZeroMaxConcurrentJobs: 3);
        control.MarkReady("test-bootstrap-attested");
        var controller = new WorkerOperationalController(control, scheduler: null);

        WorkerControlSnapshot prepared = await controller.PrepareMaintenanceAsync();

        Assert.Equal(WorkerOperationalState.Paused, prepared.State);
        Assert.False(prepared.AcceptingClaims);
        WorkerControlException start = await Assert.ThrowsAsync<WorkerControlException>(
            () => controller.StartAsync());
        WorkerControlException parallelism = await Assert.ThrowsAsync<WorkerControlException>(
            () => controller.SetMaxConcurrentJobsAsync(1));
        Assert.Equal("worker-maintenance-prepared", start.Code);
        Assert.Equal("worker-maintenance-prepared", parallelism.Code);
        await controller.SetMaxConcurrentJobsAsync(0);
        await controller.StopAsync();
    }

    [Fact]
    public async Task InstallerMaintenanceFailsClosedWhileAReservationStillExists()
    {
        var control = new WorkerControlState(lastNonZeroMaxConcurrentJobs: 1);
        control.MarkReady("test-bootstrap-attested");
        control.Start();
        control.SetGrantedCapacity(1);
        Assert.True(control.TryReserveSlot());
        var controller = new WorkerOperationalController(control, scheduler: null);

        WorkerControlException error = await Assert.ThrowsAsync<WorkerControlException>(
            () => controller.PrepareMaintenanceAsync());

        Assert.Equal("worker-maintenance-drain-required", error.Code);
        Assert.Equal(WorkerOperationalState.Paused, control.Snapshot.State);
        Assert.False(control.Snapshot.AcceptingClaims);
        WorkerControlException start = await Assert.ThrowsAsync<WorkerControlException>(
            () => controller.StartAsync());
        Assert.Equal("worker-maintenance-prepared", start.Code);
        control.ReleaseReservation();
        await controller.PrepareMaintenanceAsync();
    }

    [Fact]
    public void LegacyCutoverRequiresExactStoppedDisabledServiceEvidence()
    {
        const string serviceName = "HchEditorialWorker-node-000000000000";
        WindowsLegacyWorkerCutoverGuard.ValidateExclusive(
            new LegacyWorkerCutoverEvidence(true, serviceName, "Stopped", null, 4),
            serviceName);

        LegacyWorkerCutoverException running = Assert.Throws<LegacyWorkerCutoverException>(() =>
            WindowsLegacyWorkerCutoverGuard.ValidateExclusive(
                new LegacyWorkerCutoverEvidence(true, serviceName, "Running", 123, 4),
                serviceName));
        LegacyWorkerCutoverException automatic = Assert.Throws<LegacyWorkerCutoverException>(() =>
            WindowsLegacyWorkerCutoverGuard.ValidateExclusive(
                new LegacyWorkerCutoverEvidence(true, serviceName, "Stopped", null, 2),
                serviceName));
        LegacyWorkerCutoverException missing = Assert.Throws<LegacyWorkerCutoverException>(() =>
            WindowsLegacyWorkerCutoverGuard.ValidateExclusive(
                new LegacyWorkerCutoverEvidence(false, serviceName, "Missing", null, -1),
                serviceName));

        Assert.Equal("legacy-worker-cutover-not-exclusive", running.Code);
        Assert.Equal("legacy-worker-cutover-not-exclusive", automatic.Code);
        Assert.Equal("legacy-worker-cutover-not-exclusive", missing.Code);
    }

    [Fact]
    public async Task LegacyCutoverStillFindsARegisteredClaimerWhenItsRootWasRemoved()
    {
        string absentRoot = Path.Combine(
            Path.GetTempPath(),
            "hch-absent-legacy-" + Guid.NewGuid().ToString("N"));
        const string nodeId = "node-cutover-probe";
        string serviceName = Hch.Worker.Persistence.LegacyWindowsWorkerMigrator
            .CreateLegacyServiceName(nodeId);
        var guard = new WindowsLegacyWorkerCutoverGuard(
            nodeId,
            absentRoot,
            new FixedCutoverProbe(new LegacyWorkerCutoverEvidence(
                true,
                serviceName,
                "Running",
                42,
                2)));

        LegacyWorkerCutoverException error = await Assert.ThrowsAsync<LegacyWorkerCutoverException>(
            () => guard.EnsureExclusiveAsync());

        Assert.Equal("legacy-worker-cutover-not-exclusive", error.Code);
    }

    [Fact]
    public void LocalAdministratorIpcPrivilegeIsLimitedToMaintenancePreflight()
    {
        var administrator = new NamedPipeClientAuthorization(
            IsOwner: false,
            IsLocalAdministrator: true);
        var owner = new NamedPipeClientAuthorization(
            IsOwner: true,
            IsLocalAdministrator: false);

        Assert.True(WorkerControlPipeServer.IsCommandAuthorized(
            administrator,
            IpcCommand.PrepareMaintenance));
        Assert.False(WorkerControlPipeServer.IsCommandAuthorized(administrator, IpcCommand.Start));
        Assert.False(WorkerControlPipeServer.IsCommandAuthorized(
            administrator,
            IpcCommand.SubmitEnrollmentToken));
        Assert.True(WorkerControlPipeServer.IsCommandAuthorized(owner, IpcCommand.Start));
    }

    [Fact]
    public async Task ScmCancellationDoesNotForgeAnOperationalStopFailure()
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var control = new WorkerControlState();
        control.MarkReady();
        control.Start();
        control.SetGrantedCapacity(1);
        var executor = new CancellationExecutor();
        var reporter = new FailureRecorder();
        await using var scheduler = new ConcurrentJobScheduler(
            control,
            new SingleJobSource(),
            executor,
            reporter);
        using var scm = new CancellationTokenSource();
        var run = scheduler.RunAsync(scm.Token);
        await executor.Started.Task.WaitAsync(timeout.Token);

        scm.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => run);
        while (control.Snapshot.ActiveJobs != 0)
        {
            await Task.Delay(10, timeout.Token);
        }

        Assert.Empty(reporter.Failures);
        Assert.NotEqual(WorkerOperationalState.Stopped, control.Snapshot.State);
    }

    [Fact]
    public void DurableAppliedContractSurvivesDownloadManifestExpiryIndependently()
    {
        var profile = RuntimeProfile();
        var state = new AppliedManifestState
        {
            SchemaVersion = 1,
            ManifestSequence = profile.ManifestSequence,
            ManifestHash = profile.ManifestHash,
            ContentContractHash = new string('9', 64),
            PolicyHash = profile.PolicyHash,
            PromptConfigHash = profile.PromptConfigHash,
            Provider = profile.Provider,
            EngineAdapter = profile.EngineAdapter,
            EngineAdapterVersion = profile.EngineAdapterVersion,
            Model = profile.Model,
            ModelDigest = profile.ModelDigest[7..],
            Protocol = profile.Protocol,
            RuntimeProfileHash = profile.RuntimeProfileHash,
            RuntimeProfile = profile,
        };

        var contract = AppliedRuntimeContract.FromAppliedState(state);

        Assert.Equal(state.ContentContractHash, contract.ContentContractHash);
        Assert.Equal(state.RuntimeProfileHash, contract.RuntimeProfileHash);
        Assert.Null(typeof(AppliedManifestState).GetProperty("ExpiresAt"));
    }

    [Fact]
    public async Task DashboardProgressPreservesPercentAndRealClaimBatchPosition()
    {
        var registry = new AssignmentRuntimeRegistry();
        var single = registry.Begin(Assignment("assignment-single"), itemIndex: 1, batchTotal: 1);

        await single.ReportAsync(new OllamaProgress(
            "responding",
            Attempt: 1,
            Sequence: 4,
            ContentBytes: 256,
            DateTimeOffset.UtcNow,
            Percent: 42.5));

        var oneOfOne = Assert.Single(registry.Snapshot());
        Assert.Equal(42.5, oneOfOne.Percent);
        Assert.Equal(1, oneOfOne.ItemIndex);
        Assert.Equal(1, oneOfOne.BatchTotal);

        registry.Finish("assignment-single");
        _ = registry.Begin(Assignment("assignment-a"), itemIndex: 1, batchTotal: 2);
        _ = registry.Begin(Assignment("assignment-b"), itemIndex: 2, batchTotal: 2);
        var batch = registry.Snapshot();

        Assert.Collection(
            batch,
            first =>
            {
                Assert.Equal("assignment-a", first.AssignmentId);
                Assert.Equal(1, first.ItemIndex);
                Assert.Equal(2, first.BatchTotal);
            },
            second =>
            {
                Assert.Equal("assignment-b", second.AssignmentId);
                Assert.Equal(2, second.ItemIndex);
                Assert.Equal(2, second.BatchTotal);
            });

        registry.Finish("assignment-a");
        registry.Finish("assignment-b");
    }

    private static WorkerRuntimeProfile RuntimeProfile()
    {
        var core = new Dictionary<string, object?>(StringComparer.Ordinal)
        {
            ["contextWindow"] = 4096,
            ["engineAdapter"] = "ollama-chat",
            ["engineAdapterVersion"] = "1.0.0",
            ["manifestHash"] = new string('1', 64),
            ["manifestSequence"] = 8L,
            ["maxOutputTokens"] = 512,
            ["model"] = "model:test",
            ["modelDigest"] = "sha256:" + new string('2', 64),
            ["pipelineVersion"] = "editorial-v1",
            ["policyHash"] = new string('3', 64),
            ["policyId"] = "editorial-policy",
            ["policyVersion"] = "1.0.0",
            ["promptConfigHash"] = new string('4', 64),
            ["protocol"] = "ollama-chat-v1",
            ["provider"] = "ollama",
            ["temperature"] = 0.2,
        };
        return new WorkerRuntimeProfile
        {
            Provider = (string)core["provider"]!,
            EngineAdapter = (string)core["engineAdapter"]!,
            EngineAdapterVersion = (string)core["engineAdapterVersion"]!,
            Model = (string)core["model"]!,
            ModelDigest = (string)core["modelDigest"]!,
            Protocol = (string)core["protocol"]!,
            Temperature = (double)core["temperature"]!,
            ContextWindow = (int)core["contextWindow"]!,
            MaxOutputTokens = (int)core["maxOutputTokens"]!,
            PolicyId = (string)core["policyId"]!,
            PolicyVersion = (string)core["policyVersion"]!,
            PolicyHash = (string)core["policyHash"]!,
            PromptConfigHash = (string)core["promptConfigHash"]!,
            PipelineVersion = (string)core["pipelineVersion"]!,
            ManifestSequence = (long)core["manifestSequence"]!,
            ManifestHash = (string)core["manifestHash"]!,
            RuntimeProfileHash = HchDigest.Sha256Hex(JcsCanonicalizer.Serialize(core)),
        };
    }

    private static WorkerAssignment Assignment(string assignmentId) => new()
    {
        AssignmentId = assignmentId,
        LeaseToken = "lease-token-0123456789abcdef",
        LeaseExpiresAt = DateTimeOffset.UtcNow.AddMinutes(5).ToString("O"),
        Status = "processing",
        InputSnapshotHash = new string('a', 64),
        Entry = System.Text.Json.JsonSerializer.SerializeToElement(new { title = "test" }),
        GenerationPlanHash = new string('b', 64),
        GenerationPlan = new GenerationPlan
        {
            AlgorithmVersion = "hch-adaptive-work-v1",
            TierId = "minimum",
            TierRank = 0,
            MaxOutputTokens = 100,
            EditorialProfile = "EDITORIAL_MINIMUM",
            MinimumUnit = true,
            ProcessingWindowSeconds = 600,
            NearWindowSeconds = 60,
            FirstProgressGraceSeconds = 60,
            StallAfterSeconds = 60,
            FinalizationGraceSeconds = 60,
            PolicyHash = new string('c', 64),
        },
        RuntimeProfile = RuntimeProfile(),
    };

    private sealed class SingleJobSource : IWorkerJobSource
    {
        private int claimed;

        public Task<IReadOnlyList<WorkerJob>> ClaimAsync(int requestedCount, CancellationToken cancellationToken) =>
            Task.FromResult<IReadOnlyList<WorkerJob>>(Interlocked.Exchange(ref claimed, 1) == 0
                ? [new WorkerJob("assignment-1", "lease-1", DateTimeOffset.UtcNow.AddMinutes(5), new string('a', 64), new { })]
                : []);
    }

    private sealed class CancellationExecutor : IWorkerJobExecutor
    {
        public TaskCompletionSource Started { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);

        public async Task<JobExecutionResult> ExecuteAsync(WorkerJob job, CancellationToken cancellationToken)
        {
            Started.TrySetResult();
            await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken);
            throw new InvalidOperationException("unreachable");
        }
    }

    private sealed class FailureRecorder : IWorkerJobReporter
    {
        public List<string> Failures { get; } = [];

        public Task CompleteAsync(WorkerJob job, JobExecutionResult result, CancellationToken cancellationToken) =>
            Task.CompletedTask;

        public Task FailAsync(WorkerJob job, string errorCode, CancellationToken cancellationToken)
        {
            lock (Failures) { Failures.Add(errorCode); }
            return Task.CompletedTask;
        }
    }

    private sealed class FixedCutoverProbe(LegacyWorkerCutoverEvidence evidence)
        : ILegacyWorkerCutoverProbe
    {
        public LegacyWorkerCutoverEvidence Capture(string serviceName) => evidence;
    }
}
