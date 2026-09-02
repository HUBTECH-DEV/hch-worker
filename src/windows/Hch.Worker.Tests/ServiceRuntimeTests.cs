using System.IO.Pipes;
using Hch.Worker.Core;
using Hch.Worker.Ollama;
using Hch.Worker.Protocol;
using Hch.Worker.Security;
using Hch.Worker.Service;
using Hch.Worker.Windows;
using Hch.Worker.IPC.Contracts;
using System.Text.Json;

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
        control.ApplyHeartbeatDecision(
            grantedCapacity: 1,
            claimAllowed: true,
            recommendedClaimCount: 1,
            claimAuthorizationValidUntil: DateTimeOffset.UtcNow.AddMinutes(2),
            claimReason: "claim-recommended");
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
    public void NewerCompatibleTrustKeepsThePreviouslyAppliedReadyStateUsable()
    {
        var now = DateTimeOffset.Parse("2026-09-02T14:00:00Z");
        using var root = Ed25519Identity.Generate();
        var pins = new ManifestTrustPins(
            "hch-root-v1",
            root.Fingerprint,
            root.ExportSubjectPublicKeyInfo());
        WorkerConfiguration configuration = WorkerConfigurationStore.CreatePausedDefault(
            "node-compatible-trust",
            "worker-key:compatible-trust");
        AppliedManifestState applied = AppliedState();
        WorkerReadyStateRecord ready = ReadyState(applied, configuration, now);
        ManifestTrustStateRecord trust = TrustState(
            applied,
            pins,
            now,
            applied.ManifestSequence + 1,
            new string('5', 64));

        Assert.True(WorkerRuntimeFactory.ReadyStateIsUsable(
            ready,
            trust,
            applied,
            configuration,
            pins,
            now));
    }

    [Fact]
    public void NewerTrustCannotAuthorizeAChangedContentOrPolicyContract()
    {
        var now = DateTimeOffset.Parse("2026-09-02T14:00:00Z");
        using var root = Ed25519Identity.Generate();
        var pins = new ManifestTrustPins(
            "hch-root-v1",
            root.Fingerprint,
            root.ExportSubjectPublicKeyInfo());
        WorkerConfiguration configuration = WorkerConfigurationStore.CreatePausedDefault(
            "node-incompatible-trust",
            "worker-key:incompatible-trust");
        AppliedManifestState applied = AppliedState();
        WorkerReadyStateRecord ready = ReadyState(applied, configuration, now);

        ManifestTrustStateRecord changedContent = TrustState(
            applied,
            pins,
            now,
            applied.ManifestSequence + 1,
            new string('5', 64),
            contentContractHash: new string('6', 64));
        ManifestTrustStateRecord changedPolicy = TrustState(
            applied,
            pins,
            now,
            applied.ManifestSequence + 1,
            new string('5', 64),
            policyHash: new string('7', 64));

        Assert.False(WorkerRuntimeFactory.ReadyStateIsUsable(
            ready,
            changedContent,
            applied,
            configuration,
            pins,
            now));
        Assert.False(WorkerRuntimeFactory.ReadyStateIsUsable(
            ready,
            changedPolicy,
            applied,
            configuration,
            pins,
            now));
    }

    [Fact]
    public void EqualSequenceWithDifferentManifestHashFailsClosed()
    {
        var now = DateTimeOffset.Parse("2026-09-02T14:00:00Z");
        using var root = Ed25519Identity.Generate();
        var pins = new ManifestTrustPins(
            "hch-root-v1",
            root.Fingerprint,
            root.ExportSubjectPublicKeyInfo());
        WorkerConfiguration configuration = WorkerConfigurationStore.CreatePausedDefault(
            "node-equivocated-trust",
            "worker-key:equivocated-trust");
        AppliedManifestState applied = AppliedState();
        WorkerReadyStateRecord ready = ReadyState(applied, configuration, now);
        ManifestTrustStateRecord trust = TrustState(
            applied,
            pins,
            now,
            applied.ManifestSequence,
            new string('5', 64));

        Assert.False(WorkerRuntimeFactory.ReadyStateIsUsable(
            ready,
            trust,
            applied,
            configuration,
            pins,
            now));
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

    [Fact]
    public void DashboardMetricsUseObservedQueueOutcomesResourcesAndBoundedHistory()
    {
        var clock = new ManualTimeProvider(DateTimeOffset.Parse("2026-09-02T12:00:00Z"));
        var state = new WorkerRuntimeState(clock, new FixedServiceStateProvider("Running"));
        WorkerConfiguration configuration = WorkerConfigurationStore.CreatePausedDefault(
            "node-dashboard-metrics",
            "SHA256:" + new string('A', 43));
        var metadata = new WorkerRuntimeMetadata(
            availableVersion: "4.0.0",
            updateAvailable: false,
            updateCompatible: true,
            manifestStatus: "applied-contract-valid",
            manifestSequence: 1,
            contentContractHash: new string('a', 64),
            readyUntil: clock.GetUtcNow().AddHours(1),
            trustStatus: "verified",
            ollamaModel: "model:test");
        var control = new WorkerControlState(timeProvider: clock);
        control.MarkReady();
        state.RecordHeartbeat(clock.GetUtcNow(), TimeSpan.FromMilliseconds(25), claimableQueueDepth: 7);
        state.RecordTelemetry(new WindowsTelemetrySnapshot(
            clock.GetUtcNow(),
            Environment.ProcessId,
            12.5,
            32.5,
            512,
            1024,
            16_384,
            8_192,
            100,
            200,
            300,
            400,
            42,
            2_048,
            "GPU test",
            8_192,
            AuxiliaryProcessCount: 1));
        state.RecordCompleted(TimeSpan.FromSeconds(120));

        WorkerSnapshotPayload initial = state.Snapshot(configuration, metadata, control.Snapshot, []);
        Assert.Equal("Running", initial.ServiceState);
        Assert.Equal(7, initial.QueueDepth);
        Assert.Equal(120, initial.AverageDurationSeconds);
        Assert.Null(initial.ThroughputJobsPerHour);
        Assert.Equal("GPU test", initial.Resources.GpuName.Value);
        Assert.Equal(8_192, initial.Resources.VramTotalBytes.Value);
        Assert.Equal(1, initial.Resources.AuxiliaryProcessCount);

        clock.Advance(TimeSpan.FromMinutes(10));
        state.RecordHeartbeat(clock.GetUtcNow(), TimeSpan.FromMilliseconds(30), claimableQueueDepth: 4);
        state.RecordOperationalSample(control.Snapshot);
        WorkerSnapshotPayload later = state.Snapshot(configuration, metadata, control.Snapshot, []);

        Assert.Equal(4, later.QueueDepth);
        Assert.Equal(6, later.ThroughputJobsPerHour);
        OperationalHistoryPointPayload history = Assert.Single(later.OperationalHistory);
        Assert.Equal(4, history.QueueDepth);
        Assert.Equal(1, history.CompletedJobs);
        Assert.Equal(6, history.ThroughputJobsPerHour);

        for (int index = 0; index < WorkerRuntimeState.MaximumOperationalHistoryPoints + 10; index++)
        {
            clock.Advance(WorkerRuntimeState.OperationalHistoryInterval);
            state.RecordOperationalSample(control.Snapshot);
        }

        WorkerSnapshotPayload bounded = state.Snapshot(configuration, metadata, control.Snapshot, []);
        Assert.Equal(WorkerRuntimeState.MaximumOperationalHistoryPoints, bounded.OperationalHistory.Count);
        Assert.Null(bounded.QueueDepth);
    }

    [Theory]
    [InlineData("{\"claimable\":9,\"generating\":2,\"futureTotal\":11,\"claimableByTier\":{\"minimum\":9}}", 9)]
    [InlineData("{\"claimable\":null,\"generating\":0,\"futureTotal\":0,\"claimableByTier\":{\"minimum\":0}}", null)]
    [InlineData("{\"claimable\":-1,\"generating\":0,\"futureTotal\":0,\"claimableByTier\":{\"minimum\":0}}", null)]
    [InlineData("{\"claimable\":1,\"generating\":0,\"futureTotal\":0,\"claimableByTier\":{\"minimum\":1}}", null)]
    [InlineData("{\"claimable\":1,\"generating\":0,\"futureTotal\":1,\"claimableByTier\":{\"minimum\":2}}", null)]
    [InlineData("{\"claimable\":1,\"generating\":0,\"futureTotal\":1,\"claimableByTier\":{\"Minimum\":1}}", null)]
    [InlineData("{}", null)]
    public void QueueDepthComesOnlyFromAValidSignedHeartbeatWorkload(
        string json,
        int? expected)
    {
        JsonElement workload = JsonSerializer.Deserialize<JsonElement>(json);
        Assert.Equal(expected, WorkerServiceRuntime.ReadQueueDepth(workload));
    }

    [Fact]
    public void AssignmentDurationUsesTheObservedExecutionStart()
    {
        var clock = new ManualTimeProvider(DateTimeOffset.Parse("2026-09-02T12:00:00Z"));
        var registry = new AssignmentRuntimeRegistry(clock);
        _ = registry.Begin(Assignment("assignment-duration"));

        clock.Advance(TimeSpan.FromSeconds(75));

        Assert.Equal(TimeSpan.FromSeconds(75), registry.Elapsed("assignment-duration", clock.GetUtcNow()));
        registry.Finish("assignment-duration");
        Assert.Null(registry.Elapsed("assignment-duration", clock.GetUtcNow()));
    }

    [Fact]
    public async Task InvalidAssignmentHeartbeatAbortsOnlyItsAssignment()
    {
        var registry = new AssignmentRuntimeRegistry();
        AssignmentExecutionLease invalid = registry.Begin(Assignment("assignment-invalid-heartbeat"));
        AssignmentExecutionLease healthy = registry.Begin(Assignment("assignment-healthy-heartbeat"));
        var client = new SelectiveHeartbeatClient("assignment-invalid-heartbeat");

        await registry.RunHeartbeatPassAsync(client, CancellationToken.None);

        Assert.True(invalid.CancellationToken.IsCancellationRequested);
        Assert.Equal("assignment-heartbeat-response-invalid", invalid.AbortReason);
        Assert.False(healthy.CancellationToken.IsCancellationRequested);
        Assert.Equal(2, client.HeartbeatCalls);
        registry.Finish("assignment-invalid-heartbeat");
        registry.Finish("assignment-healthy-heartbeat");
    }

    [Fact]
    public async Task UnexpectedAssignmentHeartbeatFailureAbortsOnlyItsAssignment()
    {
        var registry = new AssignmentRuntimeRegistry();
        AssignmentExecutionLease invalid = registry.Begin(Assignment("assignment-unexpected-heartbeat"));
        AssignmentExecutionLease healthy = registry.Begin(Assignment("assignment-healthy-heartbeat"));
        var client = new SelectiveHeartbeatClient(
            "assignment-unexpected-heartbeat",
            unexpectedFailure: true);

        await registry.RunHeartbeatPassAsync(client, CancellationToken.None);

        Assert.True(invalid.CancellationToken.IsCancellationRequested);
        Assert.Equal("assignment-heartbeat-internal-error", invalid.AbortReason);
        Assert.False(healthy.CancellationToken.IsCancellationRequested);
        Assert.Equal(2, client.HeartbeatCalls);
        registry.Finish("assignment-unexpected-heartbeat");
        registry.Finish("assignment-healthy-heartbeat");
    }

    [Fact]
    public async Task FinishingAssignmentDuringInFlightHeartbeatDoesNotBreakThePass()
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var registry = new AssignmentRuntimeRegistry();
        _ = registry.Begin(Assignment("assignment-finishing-heartbeat"));
        AssignmentExecutionLease healthy = registry.Begin(Assignment("assignment-healthy-heartbeat"));
        var client = new FinishingHeartbeatClient("assignment-finishing-heartbeat");

        Task heartbeatPass = registry.RunHeartbeatPassAsync(client, timeout.Token);
        await client.FinishingHeartbeatEntered.Task.WaitAsync(timeout.Token);
        registry.Finish("assignment-finishing-heartbeat");
        client.ReleaseFinishingHeartbeat.TrySetResult();

        await heartbeatPass.WaitAsync(timeout.Token);

        Assert.False(healthy.CancellationToken.IsCancellationRequested);
        Assert.Equal(2, client.HeartbeatCalls);
        registry.Finish("assignment-healthy-heartbeat");
    }

    [Fact]
    public async Task ControlPipeContinuesServingAfterAClientNeverSendsAFrame()
    {
        string stateRoot = Path.Combine(
            Path.GetTempPath(),
            "hch-worker-pipe-tests",
            Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(stateRoot);
        var ownerSid = WindowsServiceIdentity.GetCurrentUserSid();
        WorkerConfiguration configuration = WorkerConfigurationStore.CreatePausedDefault(
            "node-pipe-timeout",
            "SHA256:" + new string('A', 43)) with
        {
            StateRoot = stateRoot,
            OwnerSid = ownerSid.Value,
        };
        var control = new WorkerControlState();
        var controller = new WorkerOperationalController(control, (ConcurrentJobScheduler?)null);
        var pipeServer = new WorkerControlPipeServer(
            configuration,
            controller,
            () => throw new InvalidOperationException("snapshot-unused"),
            new SanitizedLogStore(stateRoot),
            enrollment: null,
            postEnrollmentActivation: null,
            requestReadTimeout: TimeSpan.FromMilliseconds(150),
            commandTimeout: TimeSpan.FromSeconds(2),
            responseWriteTimeout: TimeSpan.FromSeconds(2));
        using var globalTimeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));

        try
        {
            string stalledName = $"hch-worker-stalled-{Guid.NewGuid():N}";
            await using (var stalledServer = new NamedPipeServerStream(
                stalledName,
                PipeDirection.InOut,
                1,
                PipeTransmissionMode.Byte,
                PipeOptions.Asynchronous))
            await using (NamedPipeClientStream stalledClient = LocalNamedPipe.CreateClient(stalledName))
            {
                Task connected = stalledServer.WaitForConnectionAsync(globalTimeout.Token);
                await stalledClient.ConnectAsync(globalTimeout.Token);
                await connected;

                await pipeServer.ProcessOneAsync(stalledServer, ownerSid, globalTimeout.Token)
                    .WaitAsync(globalTimeout.Token);
            }

            string healthyName = $"hch-worker-healthy-{Guid.NewGuid():N}";
            await using (var healthyServer = new NamedPipeServerStream(
                healthyName,
                PipeDirection.InOut,
                1,
                PipeTransmissionMode.Byte,
                PipeOptions.Asynchronous))
            await using (NamedPipeClientStream healthyClient = LocalNamedPipe.CreateClient(healthyName))
            {
                Task connected = healthyServer.WaitForConnectionAsync(globalTimeout.Token);
                await healthyClient.ConnectAsync(globalTimeout.Token);
                await connected;
                Task processing = pipeServer.ProcessOneAsync(
                    healthyServer,
                    ownerSid,
                    globalTimeout.Token);
                IpcRequest request = IpcRequest.Create(
                    IpcCommand.Pause,
                    EmptyPayload.Value,
                    DateTimeOffset.UtcNow);
                await IpcFraming.WriteAsync(healthyClient, request, globalTimeout.Token);
                IpcResponse response = await IpcFraming.ReadAsync<IpcResponse>(
                    healthyClient,
                    globalTimeout.Token);
                await processing.WaitAsync(globalTimeout.Token);

                Assert.True(response.Success);
                Assert.Equal(request.RequestId, response.RequestId);
            }
        }
        finally
        {
            Directory.Delete(stateRoot, recursive: true);
        }
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

    private static AppliedManifestState AppliedState()
    {
        WorkerRuntimeProfile profile = RuntimeProfile();
        return new AppliedManifestState
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
    }

    private static WorkerReadyStateRecord ReadyState(
        AppliedManifestState applied,
        WorkerConfiguration configuration,
        DateTimeOffset now) => new()
        {
            SchemaVersion = 1,
            Ready = true,
            NodeId = configuration.NodeId,
            KeyId = configuration.KeyId,
            ManifestSequence = applied.ManifestSequence,
            ManifestHash = applied.ManifestHash,
            ContentContractHash = applied.ContentContractHash,
            PolicyHash = applied.PolicyHash,
            Provider = applied.Provider,
            EngineAdapter = applied.EngineAdapter,
            EngineAdapterVersion = applied.EngineAdapterVersion,
            WorkerRuntimeVersion = WorkerInstalledVersion.Current,
            RuntimeProfileHash = applied.RuntimeProfileHash,
            CapacityPolicyHash = new string('a', 64),
            AdaptiveWorkPolicyHash = new string('b', 64),
            RequestedCapacity = 0,
            GrantedCapacity = 0,
            CapacityClass = "drain",
            CapacityReason = "drain-requested",
            CapacityGrantedUntil = now.AddMinutes(10).ToString("O"),
            BootstrapSessionId = Guid.NewGuid().ToString("D"),
            ReadyUntil = now.AddHours(1).ToString("O"),
            AttestedAt = now.ToString("O"),
            TrustVerifiedAt = now.ToString("O"),
        };

    private static ManifestTrustStateRecord TrustState(
        AppliedManifestState applied,
        ManifestTrustPins pins,
        DateTimeOffset now,
        long manifestSequence,
        string manifestHash,
        string? contentContractHash = null,
        string? policyHash = null) => new()
        {
            Schema = "hch.worker-trust-state/v1",
            SchemaVersion = 1,
            RootKeyId = pins.RootKeyId,
            RootFingerprint = pins.RootPublicKeyFingerprint,
            ReleaseKeyId = "release-v1",
            DelegationSequence = 1,
            DelegationHash = new string('c', 64),
            ManifestSequence = manifestSequence,
            ManifestHash = manifestHash,
            ContentContractHash = contentContractHash ?? applied.ContentContractHash,
            PolicyHash = policyHash ?? applied.PolicyHash,
            VerifiedAt = now.ToString("O"),
        };

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

    private sealed class SelectiveHeartbeatClient(
        string invalidAssignmentId,
        bool unexpectedFailure = false) : IOrchestratorClient
    {
        private int heartbeatCalls;

        public int HeartbeatCalls => Volatile.Read(ref heartbeatCalls);

        public Task<AssignmentHeartbeatResponse> HeartbeatAssignmentAsync(
            WorkerAssignment assignment,
            AssignmentProgress progress,
            CancellationToken cancellationToken)
        {
            Interlocked.Increment(ref heartbeatCalls);
            if (assignment.AssignmentId == invalidAssignmentId)
            {
                if (unexpectedFailure)
                {
                    throw new InvalidOperationException("simulated unexpected assignment heartbeat failure");
                }

                throw new ProtocolValidationException(
                    "orchestrator-heartbeat-assignment-mismatch",
                    "simulated invalid signed heartbeat response");
            }

            return Task.FromResult(SuccessfulHeartbeat(assignment));
        }

        public Task<ClaimResponse> ClaimAsync(
            int requestedCapacity,
            CancellationToken cancellationToken,
            string? requestId = null,
            bool acceptExpiredAssignmentsForRecovery = false) => throw new NotSupportedException();

        public Task<NodeHeartbeatResponse> HeartbeatNodeAsync(
            int requestedCapacity,
            CancellationToken cancellationToken) => throw new NotSupportedException();

        public Task<CompleteAssignmentResponse> CompleteAsync(
            WorkerAssignment assignment,
            object draft,
            string requestId,
            CancellationToken cancellationToken) => throw new NotSupportedException();

        public Task<FailAssignmentResponse> FailAsync(
            WorkerAssignment assignment,
            string errorCode,
            string requestId,
            CancellationToken cancellationToken) => throw new NotSupportedException();
    }

    private sealed class FinishingHeartbeatClient(string finishingAssignmentId) : IOrchestratorClient
    {
        private int heartbeatCalls;

        public TaskCompletionSource FinishingHeartbeatEntered { get; } =
            new(TaskCreationOptions.RunContinuationsAsynchronously);

        public TaskCompletionSource ReleaseFinishingHeartbeat { get; } =
            new(TaskCreationOptions.RunContinuationsAsynchronously);

        public int HeartbeatCalls => Volatile.Read(ref heartbeatCalls);

        public async Task<AssignmentHeartbeatResponse> HeartbeatAssignmentAsync(
            WorkerAssignment assignment,
            AssignmentProgress progress,
            CancellationToken cancellationToken)
        {
            Interlocked.Increment(ref heartbeatCalls);
            if (assignment.AssignmentId == finishingAssignmentId)
            {
                FinishingHeartbeatEntered.TrySetResult();
                await ReleaseFinishingHeartbeat.Task.WaitAsync(cancellationToken);
                throw new ProtocolValidationException(
                    "orchestrator-heartbeat-assignment-mismatch",
                    "simulated response arriving after assignment completion");
            }

            return SuccessfulHeartbeat(assignment);
        }

        public Task<ClaimResponse> ClaimAsync(
            int requestedCapacity,
            CancellationToken cancellationToken,
            string? requestId = null,
            bool acceptExpiredAssignmentsForRecovery = false) => throw new NotSupportedException();

        public Task<NodeHeartbeatResponse> HeartbeatNodeAsync(
            int requestedCapacity,
            CancellationToken cancellationToken) => throw new NotSupportedException();

        public Task<CompleteAssignmentResponse> CompleteAsync(
            WorkerAssignment assignment,
            object draft,
            string requestId,
            CancellationToken cancellationToken) => throw new NotSupportedException();

        public Task<FailAssignmentResponse> FailAsync(
            WorkerAssignment assignment,
            string errorCode,
            string requestId,
            CancellationToken cancellationToken) => throw new NotSupportedException();
    }

    private static AssignmentHeartbeatResponse SuccessfulHeartbeat(WorkerAssignment assignment) => new()
    {
        AssignmentId = assignment.AssignmentId,
        GenerationPlanHash = assignment.GenerationPlanHash,
        LeaseExpiresAt = DateTimeOffset.UtcNow.AddMinutes(10).ToString("O"),
        Liveness = new AssignmentLiveness
        {
            State = "starting",
            LastProgressAt = null,
            StaleAfterSeconds = assignment.GenerationPlan.FirstProgressGraceSeconds,
        },
        WorkSizing = new AssignmentWorkSizing
        {
            CurrentTier = assignment.GenerationPlan.TierId,
            CurrentRank = assignment.GenerationPlan.TierRank,
            Reason = "within-window",
        },
        ServerTime = DateTimeOffset.UtcNow.ToString("O"),
    };

    private sealed class FixedServiceStateProvider(string state) : IWindowsServiceStateProvider
    {
        public WindowsServiceStatus Collect(string serviceName, int expectedProcessId) =>
            new(state, true);
    }

    private sealed class ManualTimeProvider(DateTimeOffset current) : TimeProvider
    {
        private DateTimeOffset now = current;

        public override DateTimeOffset GetUtcNow() => now;

        public void Advance(TimeSpan duration) => now += duration;
    }
}
