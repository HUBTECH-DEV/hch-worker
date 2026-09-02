using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text.Json;
using Hch.Worker.Core;
using Hch.Worker.IPC.Contracts;
using Hch.Worker.Ollama;
using Hch.Worker.Persistence;
using Hch.Worker.Protocol;
using Hch.Worker.Security;
using Hch.Worker.Windows;
using Microsoft.Extensions.Logging;

namespace Hch.Worker.Service;

public sealed class WorkerRuntimeMetadata(
    string? availableVersion,
    bool updateAvailable,
    bool updateCompatible,
    string manifestStatus,
    long? manifestSequence,
    string? contentContractHash,
    DateTimeOffset? readyUntil,
    string trustStatus,
    string? ollamaModel)
{
    private readonly object metadataGate = new();
    private string? currentAvailableVersion = availableVersion;
    private bool currentUpdateAvailable = updateAvailable;
    private bool currentUpdateCompatible = updateCompatible;
    private string currentManifestStatus = manifestStatus;
    private long? currentManifestSequence = manifestSequence;
    private string? currentContentContractHash = contentContractHash;
    private DateTimeOffset? currentReadyUntil = readyUntil;
    private string currentTrustStatus = trustStatus;
    private string? currentOllamaModel = ollamaModel;

    public string? AvailableVersion { get { lock (metadataGate) return currentAvailableVersion; } }
    public bool UpdateAvailable { get { lock (metadataGate) return currentUpdateAvailable; } }
    public bool UpdateCompatible { get { lock (metadataGate) return currentUpdateCompatible; } }
    public string ManifestStatus { get { lock (metadataGate) return currentManifestStatus; } }
    public long? ManifestSequence { get { lock (metadataGate) return currentManifestSequence; } }
    public string? ContentContractHash { get { lock (metadataGate) return currentContentContractHash; } }
    public DateTimeOffset? ReadyUntil { get { lock (metadataGate) return currentReadyUntil; } }
    public string TrustStatus { get { lock (metadataGate) return currentTrustStatus; } }
    public string? OllamaModel { get { lock (metadataGate) return currentOllamaModel; } }

    public void RecordUpdate(WorkerUpdateAvailability update)
    {
        ArgumentNullException.ThrowIfNull(update);
        lock (metadataGate)
        {
            currentAvailableVersion = update.LatestAvailableWorkerVersion;
            currentUpdateAvailable = update.UpdateAvailable;
            currentUpdateCompatible = update.Compatible;
        }
    }

    public void RecordBootstrap(
        string? availableVersion,
        bool updateAvailable,
        bool updateCompatible,
        string manifestStatus,
        long? manifestSequence,
        string? contentContractHash,
        DateTimeOffset? readyUntil,
        string trustStatus,
        string? ollamaModel)
    {
        lock (metadataGate)
        {
            currentAvailableVersion = availableVersion;
            currentUpdateAvailable = updateAvailable;
            currentUpdateCompatible = updateCompatible;
            currentManifestStatus = manifestStatus;
            currentManifestSequence = manifestSequence;
            currentContentContractHash = contentContractHash;
            currentReadyUntil = readyUntil;
            currentTrustStatus = trustStatus;
            currentOllamaModel = ollamaModel;
        }
    }

    public void RecordNotReady(string manifestStatus = "not-attested")
    {
        lock (metadataGate)
        {
            currentManifestStatus = manifestStatus;
            currentReadyUntil = null;
            currentTrustStatus = "not-ready";
        }
    }
}

public sealed class WorkerRuntimeState
{
    public const int MaximumOperationalHistoryPoints = 120;
    public static readonly TimeSpan OperationalHistoryInterval = TimeSpan.FromMinutes(1);
    public static readonly TimeSpan QueueDepthFreshness = TimeSpan.FromMinutes(2);
    public static readonly TimeSpan ThroughputWindow = TimeSpan.FromHours(1);

    private readonly object gate = new();
    private readonly TimeProvider clock;
    private readonly DateTimeOffset startedAt;
    private readonly IWindowsServiceStateProvider serviceStateProvider;
    private readonly Queue<DateTimeOffset> completedOutcomeTimes = new();
    private readonly List<OperationalHistoryPointPayload> operationalHistory = [];
    private DateTimeOffset? lastHeartbeatAt;
    private long? orchestratorLatencyMilliseconds;
    private int? queueDepth;
    private DateTimeOffset? queueDepthObservedAt;
    private WindowsTelemetrySnapshot? telemetry;
    private long memorySampleTotal;
    private int memorySampleCount;
    private bool ollamaAvailable;
    private string? lastError;
    private long completed;
    private long failed;
    private long retries;
    private double completedDurationSecondsTotal;
    private long completedDurationCount;

    public WorkerRuntimeState(
        TimeProvider? timeProvider = null,
        IWindowsServiceStateProvider? serviceStateProvider = null)
    {
        clock = timeProvider ?? TimeProvider.System;
        startedAt = clock.GetUtcNow();
        this.serviceStateProvider = serviceStateProvider ?? WindowsServiceStateProvider.Instance;
    }

    public void RecordHeartbeat(DateTimeOffset observedAt, TimeSpan latency)
        => RecordHeartbeat(observedAt, latency, null);

    public void RecordHeartbeat(DateTimeOffset observedAt, TimeSpan latency, int? claimableQueueDepth)
    {
        lock (gate)
        {
            lastHeartbeatAt = observedAt;
            orchestratorLatencyMilliseconds = Math.Max(0, (long)latency.TotalMilliseconds);
            queueDepth = claimableQueueDepth is >= 0 ? claimableQueueDepth : null;
            queueDepthObservedAt = claimableQueueDepth is >= 0 ? clock.GetUtcNow() : null;
        }
    }

    public void RecordHeartbeatFailure()
    {
        lock (gate)
        {
            queueDepth = null;
            queueDepthObservedAt = null;
        }
    }

    public void RecordTelemetry(WindowsTelemetrySnapshot value)
    {
        lock (gate)
        {
            telemetry = value;
            if (value.ProcessWorkingSetBytes is long bytes)
            {
                memorySampleTotal = long.MaxValue - memorySampleTotal < bytes
                    ? long.MaxValue
                    : memorySampleTotal + bytes;
                memorySampleCount++;
                if (memorySampleCount > 10_000)
                {
                    memorySampleTotal /= 2;
                    memorySampleCount /= 2;
                }
            }
        }
    }

    public void RecordOllama(bool available)
    {
        lock (gate) { ollamaAvailable = available; }
    }

    public void RecordError(string code)
    {
        lock (gate) { lastError = SignedOrchestratorClient.SafeErrorCode(code); }
    }

    public void RecordCompleted()
        => RecordCompleted(duration: null);

    public void RecordCompleted(TimeSpan? duration)
    {
        lock (gate)
        {
            completed = Increment(completed);
            DateTimeOffset now = clock.GetUtcNow();
            completedOutcomeTimes.Enqueue(now);
            PruneCompletedOutcomes(now);
            if (duration is { } actualDuration
                && actualDuration >= TimeSpan.Zero
                && double.IsFinite(actualDuration.TotalSeconds))
            {
                completedDurationSecondsTotal = Math.Min(
                    double.MaxValue,
                    completedDurationSecondsTotal + actualDuration.TotalSeconds);
                completedDurationCount = Increment(completedDurationCount);
            }
        }
    }

    public void RecordFailed()
    {
        lock (gate) { failed = Increment(failed); }
    }

    public void RecordRetry()
    {
        lock (gate) { retries = Increment(retries); }
    }

    public void RecordOperationalSample(WorkerControlSnapshot control)
    {
        ArgumentNullException.ThrowIfNull(control);
        lock (gate)
        {
            DateTimeOffset now = clock.GetUtcNow();
            int? currentQueueDepth = CurrentQueueDepth(now);
            double? throughput = CurrentThroughput(now);
            double? averageDuration = AverageDuration();
            var point = new OperationalHistoryPointPayload(
                now,
                control.ActiveJobs,
                control.ReservedJobs,
                currentQueueDepth,
                completed,
                failed,
                retries,
                throughput,
                averageDuration);
            if (operationalHistory.Count > 0
                && now - operationalHistory[^1].ObservedAt < OperationalHistoryInterval)
            {
                operationalHistory[^1] = point;
            }
            else
            {
                operationalHistory.Add(point);
                if (operationalHistory.Count > MaximumOperationalHistoryPoints)
                {
                    operationalHistory.RemoveRange(
                        0,
                        operationalHistory.Count - MaximumOperationalHistoryPoints);
                }
            }
        }
    }

    public WorkerSnapshotPayload Snapshot(
        WorkerConfiguration configuration,
        WorkerRuntimeMetadata metadata,
        WorkerControlSnapshot control,
        IReadOnlyList<WorkerJobProgress> progress)
    {
        WindowsServiceStatus service = serviceStateProvider.Collect(
            Worker.ServiceName,
            Environment.ProcessId);
        lock (gate)
        {
            DateTimeOffset now = clock.GetUtcNow();
            var resources = Resources();
            var activeWork = progress.Select(item => new JobProgressPayload(
                item.AssignmentId,
                item.Phase,
                item.Attempt,
                item.Sequence,
                item.ContentBytes,
                item.Percent,
                item.ItemIndex,
                item.BatchTotal,
                item.ObservedAt)).ToArray();
            return new WorkerSnapshotPayload(
                configuration.NodeId,
                configuration.WorkerName,
                WorkerInstalledVersion.Current,
                metadata.AvailableVersion,
                service.State,
                control.State.ToString(),
                control.Ready,
                control.AcceptingClaims,
                control.MaxConcurrentJobs,
                control.LastNonZeroMaxConcurrentJobs,
                control.ClaimBatchSize,
                control.GrantedCapacity,
                control.ActiveJobs,
                control.ReservedJobs,
                control.AvailableSlots,
                lastHeartbeatAt,
                orchestratorLatencyMilliseconds,
                metadata.TrustStatus,
                metadata.ReadyUntil,
                metadata.ManifestStatus,
                metadata.ManifestSequence,
                metadata.ContentContractHash,
                metadata.UpdateAvailable,
                metadata.UpdateCompatible,
                metadata.OllamaModel,
                ollamaAvailable,
                CurrentQueueDepth(now),
                completed,
                failed,
                retries,
                AverageDuration(),
                CurrentThroughput(now),
                activeWork,
                operationalHistory.ToArray(),
                resources,
                lastError);
        }
    }

    private ResourceSnapshotPayload Resources()
    {
        var sample = telemetry;
        var unavailableLong = new MetricPayload<long>(false, default, "not-collected");
        return new ResourceSnapshotPayload(
            Metric(sample?.ProcessCpuPercent, "not-collected"),
            Metric(sample?.SystemCpuPercent, "not-collected"),
            Metric(sample?.ProcessWorkingSetBytes, "not-collected"),
            memorySampleCount == 0
                ? unavailableLong
                : new MetricPayload<long>(true, memorySampleTotal / memorySampleCount, null),
            Metric(sample?.ProcessPeakWorkingSetBytes, "not-collected"),
            sample?.GpuName is { Length: > 0 } gpuName
                ? new MetricPayload<string>(true, gpuName, null)
                : new MetricPayload<string>(false, null, "gpu-name-not-available"),
            Metric(sample?.GpuPercent, "gpu-not-available"),
            Metric(ToLong(sample?.VramUsedBytes), "gpu-not-available"),
            Metric(ToLong(sample?.VramTotalBytes), "vram-total-not-available"),
            Metric(ToLong(sample?.ProcessReadBytes), "not-collected"),
            Metric(ToLong(sample?.ProcessWriteBytes), "not-collected"),
            Metric(sample?.NetworkReceivedBytes, "not-collected"),
            Metric(sample?.NetworkSentBytes, "not-collected"),
            Math.Max(0, (long)(clock.GetUtcNow() - startedAt).TotalSeconds),
            sample?.AuxiliaryProcessCount ?? 0);
    }

    private int? CurrentQueueDepth(DateTimeOffset now) =>
        queueDepthObservedAt is { } observedAt
            && now >= observedAt
            && now - observedAt <= QueueDepthFreshness
            ? queueDepth
            : null;

    private double? AverageDuration() => completedDurationCount == 0
        ? null
        : completedDurationSecondsTotal / completedDurationCount;

    private double? CurrentThroughput(DateTimeOffset now)
    {
        PruneCompletedOutcomes(now);
        double elapsedHours = Math.Min(
            ThroughputWindow.TotalHours,
            Math.Max(0, (now - startedAt).TotalHours));
        return elapsedHours < TimeSpan.FromMinutes(1).TotalHours
            ? null
            : completedOutcomeTimes.Count / elapsedHours;
    }

    private void PruneCompletedOutcomes(DateTimeOffset now)
    {
        DateTimeOffset cutoff = now - ThroughputWindow;
        while (completedOutcomeTimes.TryPeek(out DateTimeOffset completedAt)
            && completedAt < cutoff)
        {
            _ = completedOutcomeTimes.Dequeue();
        }
    }

    private static MetricPayload<T> Metric<T>(T? value, string reason) where T : struct => value is T actual
        ? new MetricPayload<T>(true, actual, null)
        : new MetricPayload<T>(false, default, reason);

    private static long? ToLong(ulong? value) => value is null
        ? null
        : value > long.MaxValue ? long.MaxValue : (long)value.Value;

    private static long Increment(long value) => value == long.MaxValue ? value : value + 1;
}

public sealed class WorkerServiceRuntime : IAsyncDisposable
{
    public static readonly TimeSpan NodeHeartbeatInterval = TimeSpan.FromSeconds(60);
    public static readonly TimeSpan TelemetryInterval = TimeSpan.FromSeconds(5);
    private readonly WorkerConfiguration configuration;
    private readonly WorkerRuntimeMetadata metadata;
    private readonly WorkerControlState control;
    private readonly WorkerSchedulerHost schedulerHost;
    private readonly IOrchestratorClient? orchestrator;
    private readonly AssignmentRuntimeRegistry assignments;
    private readonly WorkerRuntimeState state;
    private readonly WindowsTelemetryCollector telemetry;
    private readonly OllamaChatClient? ollama;
    private readonly WorkerControlPipeServer pipe;
    private readonly SanitizedLogStore logs;
    private readonly TimeProvider clock;
    private readonly ILogger<WorkerServiceRuntime> logger;
    private readonly IDisposable[] ownedDisposables;
    private bool disposed;

    public WorkerServiceRuntime(
        WorkerConfiguration configuration,
        WorkerRuntimeMetadata metadata,
        WorkerControlState control,
        WorkerSchedulerHost schedulerHost,
        IOrchestratorClient? orchestrator,
        AssignmentRuntimeRegistry assignments,
        WorkerRuntimeState state,
        WindowsTelemetryCollector telemetry,
        OllamaChatClient? ollama,
        WorkerControlPipeServer pipe,
        SanitizedLogStore logs,
        ILogger<WorkerServiceRuntime> logger,
        TimeProvider? timeProvider = null,
        params IDisposable[] ownedDisposables)
    {
        this.configuration = configuration;
        this.metadata = metadata;
        this.control = control;
        this.schedulerHost = schedulerHost;
        this.orchestrator = orchestrator;
        this.assignments = assignments;
        this.state = state;
        this.telemetry = telemetry;
        this.ollama = ollama;
        this.pipe = pipe;
        this.logs = logs;
        this.logger = logger;
        clock = timeProvider ?? TimeProvider.System;
        this.ownedDisposables = ownedDisposables;
    }

    public WorkerControlSnapshot Control => control.Snapshot;

    public WorkerSnapshotPayload Snapshot() =>
        state.Snapshot(configuration, metadata, control.Snapshot, assignments.Snapshot());

    public async Task RunAsync(CancellationToken serviceStopping)
    {
        ObjectDisposedException.ThrowIf(disposed, this);
        using var stop = CancellationTokenSource.CreateLinkedTokenSource(serviceStopping);
        var tasks = new List<Task>
        {
            SupervisePipeAsync(stop.Token),
            RunTelemetryLoopAsync(stop.Token),
            SuperviseSchedulerHostAsync(stop.Token),
        };
        if (orchestrator is not null)
        {
            tasks.Add(RunNodeHeartbeatLoopAsync(stop.Token));
            tasks.Add(assignments.RunHeartbeatLoopAsync(orchestrator, stop.Token));
        }

        try
        {
            await Task.WhenAll(tasks).ConfigureAwait(false);
        }
        finally
        {
            stop.Cancel();
            try { await Task.WhenAll(tasks).ConfigureAwait(false); }
            catch (OperationCanceledException) when (stop.IsCancellationRequested) { }
        }
    }

    private async Task RunNodeHeartbeatLoopAsync(CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            var snapshot = control.Snapshot;
            var requested = snapshot.AcceptingClaims
                ? Math.Min(snapshot.MaxConcurrentJobs, Math.Min(
                    configuration.ManifestCapacityLimit,
                    configuration.LocalResourceLimit))
                : 0;
            try
            {
                var started = Stopwatch.GetTimestamp();
                var response = await orchestrator!.HeartbeatNodeAsync(requested, cancellationToken).ConfigureAwait(false);
                var latency = Stopwatch.GetElapsedTime(started);
                ValidatedNodeHeartbeatDirective directive =
                    OrchestratorContractValidator.ReadHeartbeatDirective(response);
                var grant = snapshot.AcceptingClaims
                    ? Math.Min(response.Capacity.GrantedCapacity, requested)
                    : 0;
                bool claimAllowed = snapshot.AcceptingClaims && directive.Claim.Allowed;
                DateTimeOffset heartbeatAt = ProtocolTime.ParseTimestamp(
                    response.HeartbeatAt,
                    "heartbeatAt");
                DateTimeOffset authorizationValidUntil = heartbeatAt.AddSeconds(
                    response.NextHeartbeatSeconds * 2d);
                control.ApplyHeartbeatDecision(
                    grant,
                    claimAllowed,
                    claimAllowed ? directive.Claim.RecommendedCount : 0,
                    authorizationValidUntil,
                    directive.Claim.Reason,
                    "orchestrator-node-heartbeat");
                state.RecordHeartbeat(
                    heartbeatAt,
                    latency,
                    SaturatingQueueDepth(directive.Workload.Claimable));
                metadata.RecordUpdate(response.Update);
                if (!response.Update.Compatible
                    && response.Update.ContentImpact.Equals("generated-content", StringComparison.Ordinal))
                {
                    control.MarkNotReady("worker-update-content-incompatible");
                }
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception error)
            {
                control.ClearClaimAuthorization();
                state.RecordHeartbeatFailure();
                await RecordErrorAsync("node-heartbeat-failed", error, cancellationToken).ConfigureAwait(false);
            }

            await Task.Delay(NodeHeartbeatInterval, clock, cancellationToken).ConfigureAwait(false);
        }
    }

    private async Task SuperviseSchedulerHostAsync(CancellationToken cancellationToken)
    {
        var scheduler = await schedulerHost.WaitForSchedulerAsync(cancellationToken).ConfigureAwait(false);
        while (!cancellationToken.IsCancellationRequested)
        {
            try
            {
                await scheduler.RunAsync(cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                throw;
            }
            catch (OrchestratorRequestException error) when (error.Retryable)
            {
                control.ClearClaimAuthorization(
                    "heartbeat-unavailable",
                    "scheduler-network-retry");
                state.RecordRetry();
                await RecordErrorAsync(error.Code, error, cancellationToken).ConfigureAwait(false);
                await Task.Delay(TimeSpan.FromSeconds(5), clock, cancellationToken).ConfigureAwait(false);
            }
            catch (Exception error)
            {
                control.MarkNotReady("scheduler-integrity-failure");
                await RecordErrorAsync("scheduler-integrity-failure", error, cancellationToken).ConfigureAwait(false);
                await Task.Delay(TimeSpan.FromSeconds(5), clock, cancellationToken).ConfigureAwait(false);
            }
        }
    }

    private async Task RunTelemetryLoopAsync(CancellationToken cancellationToken)
    {
        var ollamaCounter = 0;
        while (!cancellationToken.IsCancellationRequested)
        {
            try
            {
                state.RecordTelemetry(telemetry.Collect());
                if (ollama is not null && metadata.OllamaModel is not null && ollamaCounter++ % 12 == 0)
                {
                    var status = await ollama.GetModelStatusAsync(metadata.OllamaModel, cancellationToken)
                        .ConfigureAwait(false);
                    state.RecordOllama(status.Available);
                }
            }
            catch (Exception error) when (error is not OperationCanceledException)
            {
                await RecordErrorAsync("telemetry-collection-failed", error, cancellationToken).ConfigureAwait(false);
            }

            state.RecordOperationalSample(control.Snapshot);

            await Task.Delay(TelemetryInterval, clock, cancellationToken).ConfigureAwait(false);
        }
    }

    private async Task SupervisePipeAsync(CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            try
            {
                await pipe.RunAsync(cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception error)
            {
                await RecordErrorAsync("ipc-server-failed", error, cancellationToken).ConfigureAwait(false);
                await Task.Delay(TimeSpan.FromSeconds(2), clock, cancellationToken).ConfigureAwait(false);
            }
        }
    }

    private async Task RecordErrorAsync(string code, Exception error, CancellationToken cancellationToken)
    {
        state.RecordError(code);
        logger.LogWarning(
            "HCH Worker runtime event {Code} ({ExceptionType}).",
            code,
            error.GetType().Name);
        await logs.WriteAsync(
            "warning",
            code,
            "A sanitized Worker runtime event occurred.",
            cancellationToken: cancellationToken).ConfigureAwait(false);
    }

    internal static int? ReadQueueDepth(JsonElement workload)
    {
        try
        {
            return OrchestratorContractValidator.ReadClaimableWorkload(workload);
        }
        catch (WorkerServiceException)
        {
            return null;
        }
    }

    private static int SaturatingQueueDepth(long value) => value > int.MaxValue
        ? int.MaxValue
        : checked((int)value);

    public async ValueTask DisposeAsync()
    {
        if (disposed)
        {
            return;
        }

        disposed = true;
        await schedulerHost.DisposeAsync().ConfigureAwait(false);

        telemetry.Dispose();
        foreach (var disposable in ownedDisposables)
        {
            disposable.Dispose();
        }
    }
}

public sealed class WorkerRuntimeFactory(
    ILoggerFactory loggerFactory,
    TimeProvider timeProvider)
{
    public async Task<WorkerServiceRuntime> CreateAsync(CancellationToken cancellationToken)
    {
        var configurationPath = Environment.GetEnvironmentVariable("HCH_WORKER_CONFIG_PATH");
        var configuration = await WorkerConfigurationStore.ReadAsync(
            string.IsNullOrWhiteSpace(configurationPath) ? null : configurationPath,
            cancellationToken).ConfigureAwait(false);
        var files = new AtomicFileStore(configuration.StateRoot);
        var journals = new EditorialJournalStore(files);
        var recovery = new ProtectedEditorialRecoveryStore(
            files,
            new MachineSecretProtector(),
            configuration.NodeId,
            timeProvider);
        var pendingClaims = new PendingClaimStore(files);
        var logs = new SanitizedLogStore(configuration.StateRoot, timeProvider);
        var control = new WorkerControlState(
            configuration.LastNonZeroMaxConcurrentJobs,
            configuration.ClaimBatchSize,
            timeProvider);
        var assignments = new AssignmentRuntimeRegistry(timeProvider);
        var state = new WorkerRuntimeState(timeProvider);
        var runtimeLogger = loggerFactory.CreateLogger<WorkerServiceRuntime>();

        AppliedManifestState? appliedState = null;
        AppliedRuntimeContract? applied = null;
        AppliedManifestState? priorAppliedState = null;
        AppliedRuntimeContract? priorApplied = null;
        ManifestPayload? availableManifest = null;
        ManifestCompatibilityEvaluation? compatibility = null;
        WorkerReadyStateRecord? readyState = null;
        ManifestTrustStateRecord? trustState = null;
        try
        {
            appliedState = await files.ReadJsonAsync<AppliedManifestState>("applied-manifest.json", cancellationToken)
                .ConfigureAwait(false);
            if (appliedState is not null)
            {
                applied = AppliedRuntimeContract.FromAppliedState(appliedState);
            }
        }
        catch (Exception error) when (error is JsonException or ProtocolValidationException or WorkerServiceException)
        {
            await logs.WriteAsync("error", "applied-manifest-invalid", "The applied manifest is not usable.",
                cancellationToken: cancellationToken).ConfigureAwait(false);
        }

        try
        {
            priorAppliedState = await files.ReadJsonAsync<AppliedManifestState>(
                ManifestArtifactApplier.PreviousAppliedStatePath,
                cancellationToken).ConfigureAwait(false);
            if (priorAppliedState is not null)
            {
                priorApplied = AppliedRuntimeContract.FromAppliedState(priorAppliedState);
            }
        }
        catch (Exception error) when (error is JsonException or ProtocolValidationException or WorkerServiceException)
        {
            priorAppliedState = null;
            priorApplied = null;
            await logs.WriteAsync(
                "warning",
                "previous-applied-manifest-invalid",
                "The previous applied manifest cannot be used for ready-state recovery.",
                cancellationToken: cancellationToken).ConfigureAwait(false);
        }

        try
        {
            readyState = await files.ReadJsonAsync<WorkerReadyStateRecord>("ready.json", cancellationToken)
                .ConfigureAwait(false);
            trustState = await files.ReadJsonAsync<ManifestTrustStateRecord>("trust-state.json", cancellationToken)
                .ConfigureAwait(false);
        }
        catch (Exception error) when (error is JsonException or ProtocolValidationException or IOException)
        {
            readyState = null;
            trustState = null;
            await logs.WriteAsync("warning", "bootstrap-state-invalid", "The durable bootstrap state is not usable.",
                cancellationToken: cancellationToken).ConfigureAwait(false);
        }

        ManifestTrustPins? configuredPins = null;
        if (configuration.HasRootTrustPins)
        {
            try
            {
                configuredPins = await ManifestTrustPinsLoader.LoadAsync(configuration, cancellationToken)
                    .ConfigureAwait(false);
            }
            catch (WorkerServiceException)
            {
                // The regular bootstrap path records the actionable trust error.
                // No predecessor is selected without the configured root pins.
            }
        }

        AppliedManifestState? readyAppliedState = configuredPins is null
            ? null
            : SelectReadyAppliedState(
                appliedState,
                priorAppliedState,
                readyState,
                trustState,
                configuration,
                configuredPins,
                timeProvider.GetUtcNow());
        if (readyAppliedState is not null
            && ReferenceEquals(readyAppliedState, priorAppliedState)
            && priorApplied is not null)
        {
            appliedState = readyAppliedState;
            applied = priorApplied;
            await logs.WriteAsync(
                "warning",
                "attested-applied-state-recovered",
                "Startup selected the predecessor referenced by the durable ready commit after an interrupted compatible refresh.",
                cancellationToken: cancellationToken).ConfigureAwait(false);
        }

        var hasUnknownJournals = await HasUnreconciledJournalsAsync(files, journals, cancellationToken)
            .ConfigureAwait(false);
        Ed25519Identity? identity = null;
        try
        {
            identity = await new MachineWorkerIdentityStore(files, new MachineSecretProtector())
                .LoadAsync(configuration.NodeId, configuration.KeyId, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception error) when (error is CryptographicException or WorkerServiceException)
        {
            await logs.WriteAsync("error", "worker-identity-invalid", "The operational identity is unavailable.",
                cancellationToken: cancellationToken).ConfigureAwait(false);
        }

        HttpClient? orchestratorHttp = null;
        HttpClient? artifactHttp = null;
        HttpClient? ollamaHttp = null;
        WindowsOllamaEndpointGuard? ollamaGuard = null;
        IOrchestratorClient? orchestrator = null;
        OllamaChatClient? ollama = null;
        ConcurrentJobScheduler? scheduler = null;
        var schedulerHost = new WorkerSchedulerHost();
        var bootstrapReady = false;
        if (identity is not null)
        {
            orchestratorHttp = CreateOrchestratorHttpClient();
            artifactHttp = CreateArtifactHttpClient();
            ollamaGuard = new WindowsOllamaEndpointGuard(
                configuration.OllamaBaseUri,
                configuration.OwnerSid,
                Worker.ServiceName);
            ollamaHttp = CreateOllamaHttpClient(ollamaGuard);
            ollama = new OllamaChatClient(
                ollamaHttp,
                configuration.OllamaBaseUri,
                ollamaGuard,
                timeProvider);
            orchestrator = new SignedOrchestratorClient(
                orchestratorHttp,
                configuration.OrchestratorBaseUri,
                configuration.NodeId,
                configuration.KeyId,
                identity,
                timeProvider);
        }

        if (orchestrator is not null)
        {
            try
            {
                var recoverySource = new OrchestratorJobSource(
                    orchestrator,
                    control,
                    journals,
                    recovery,
                    pendingClaims,
                    applied,
                    timeProvider);
                var recoveredClaims = await recoverySource.RecoverPendingClaimAsync(cancellationToken)
                    .ConfigureAwait(false);
                var outcomeRecovery = await new EditorialOutcomeReconciler(
                    orchestrator,
                    journals,
                    recovery,
                    configuration.NodeId,
                    configuration.KeyId,
                    completed: state.RecordCompleted,
                    failed: state.RecordFailed,
                    timeProvider: timeProvider)
                    .ReconcileAsync(cancellationToken).ConfigureAwait(false);
                if (recoveredClaims > 0 || outcomeRecovery.Reconciled > 0)
                {
                    await logs.WriteAsync(
                        "information",
                        "startup-journal-reconciled",
                        "Durable claim and outcome evidence was reconciled before scheduling.",
                        cancellationToken: cancellationToken).ConfigureAwait(false);
                }

                if (outcomeRecovery.Pending > 0)
                {
                    await logs.WriteAsync(
                        "warning",
                        "startup-journal-reconciliation-deferred",
                        "Unfinished outcomes remain paused until exact reconciliation succeeds.",
                        cancellationToken: cancellationToken).ConfigureAwait(false);
                }
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception error) when (error is OrchestratorRequestException
                or WorkerServiceException
                or ProtocolValidationException
                or CryptographicException
                or JsonException
                or IOException)
            {
                await logs.WriteAsync(
                    "warning",
                    StartupErrorCode(error),
                    "Durable startup reconciliation was deferred; claims remain paused.",
                    cancellationToken: cancellationToken).ConfigureAwait(false);
            }

            hasUnknownJournals = await HasUnreconciledJournalsAsync(
                files,
                journals,
                cancellationToken).ConfigureAwait(false);
        }

        var previousAppliedState = appliedState;
        var previousApplied = applied;
        if (identity is not null && orchestratorHttp is not null
            && ollamaGuard is not null && configuration.HasRootTrustPins)
        {
            try
            {
                var pins = configuredPins
                    ?? await ManifestTrustPinsLoader.LoadAsync(configuration, cancellationToken)
                        .ConfigureAwait(false);
                var signedClient = (SignedOrchestratorClient)orchestrator!;
                var coordinator = new BootstrapAttestationCoordinator(
                    files,
                    new BootstrapAttestationClient(
                        orchestratorHttp,
                        configuration.OrchestratorBaseUri,
                        signedClient),
                    new ManifestArtifactApplier(
                        files,
                        new HttpManifestArtifactSource(
                            artifactHttp!,
                            configuration.OrchestratorBaseUri),
                        new HttpOllamaManifestProbe(
                            ollamaHttp!,
                            configuration.OllamaBaseUri,
                            ollamaGuard),
                        timeProvider),
                    pins,
                    identity,
                    timeProvider);
                _ = await coordinator.RunPausedAsync(
                    new BootstrapCoordinatorRequest(
                        configuration.NodeId,
                        configuration.KeyId,
                        RuntimeInformation.ProcessArchitecture.ToString(),
                        Environment.MachineName,
                        WorkerInstalledVersion.Current,
                        Guid.NewGuid().ToString("D"),
                        Guid.NewGuid().ToString("D"),
                        ActiveAssignments: hasUnknownJournals ? 1 : 0),
                    cancellationToken).ConfigureAwait(false);

                appliedState = await files.ReadJsonAsync<AppliedManifestState>(
                    "applied-manifest.json",
                    cancellationToken).ConfigureAwait(false)
                    ?? throw new WorkerServiceException(
                        "bootstrap-applied-state-missing",
                        "Bootstrap did not commit an applied manifest state.");
                applied = AppliedRuntimeContract.FromAppliedState(appliedState);
                readyState = await files.ReadJsonAsync<WorkerReadyStateRecord>(
                    "ready.json",
                    cancellationToken).ConfigureAwait(false);
                trustState = await files.ReadJsonAsync<ManifestTrustStateRecord>(
                    "trust-state.json",
                    cancellationToken).ConfigureAwait(false);
                bootstrapReady = ReadyStateIsUsable(
                    readyState,
                    trustState,
                    appliedState,
                    configuration,
                    pins,
                    timeProvider.GetUtcNow());
                if (!bootstrapReady)
                {
                    throw new WorkerServiceException(
                        "bootstrap-commit-invalid",
                        "Bootstrap did not produce a usable durable readiness commit.");
                }
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception error)
            {
                var code = StartupErrorCode(error);
                await logs.WriteAsync(
                    "warning",
                    code,
                    "The paused startup bootstrap did not complete.",
                    cancellationToken: cancellationToken).ConfigureAwait(false);

                WorkerReadyStateRecord? durableReady = null;
                ManifestTrustStateRecord? durableTrust = null;
                try
                {
                    durableReady = await files.ReadJsonAsync<WorkerReadyStateRecord>(
                        "ready.json",
                        cancellationToken).ConfigureAwait(false);
                    durableTrust = await files.ReadJsonAsync<ManifestTrustStateRecord>(
                        "trust-state.json",
                        cancellationToken).ConfigureAwait(false);
                }
                catch (Exception stateError) when (
                    stateError is JsonException or ProtocolValidationException or IOException)
                {
                    // A partial/invalidation record is deliberately not a ready commit.
                }

                ManifestTrustPins? fallbackPins = null;
                if (IsTransientBootstrapFailure(error))
                {
                    try
                    {
                        fallbackPins = await ManifestTrustPinsLoader.LoadAsync(configuration, cancellationToken)
                            .ConfigureAwait(false);
                    }
                    catch (WorkerServiceException)
                    {
                        fallbackPins = null;
                    }
                }

                if (previousAppliedState is not null
                    && previousApplied is not null
                    && fallbackPins is not null
                    && ReadyStateIsUsable(
                        durableReady,
                        durableTrust,
                        previousAppliedState,
                        configuration,
                        fallbackPins,
                        timeProvider.GetUtcNow()))
                {
                    appliedState = previousAppliedState;
                    applied = previousApplied;
                    readyState = durableReady;
                    trustState = durableTrust;
                    bootstrapReady = true;
                    await logs.WriteAsync(
                        "warning",
                        "compatible-bootstrap-refresh-deferred",
                        "A transient refresh failed; the still-valid attested content contract was preserved in Paused state.",
                        cancellationToken: cancellationToken).ConfigureAwait(false);
                }
                else
                {
                    bootstrapReady = false;
                    await WriteStartupNotReadyAsync(
                        files,
                        configuration,
                        code,
                        timeProvider,
                        cancellationToken).ConfigureAwait(false);
                }
            }
        }
        else if (!configuration.HasRootTrustPins)
        {
            await logs.WriteAsync(
                "warning",
                "root-trust-pins-missing",
                "The Worker remains paused until explicit orchestrator root trust is configured.",
                cancellationToken: cancellationToken).ConfigureAwait(false);
        }

        try
        {
            availableManifest = await files.ReadJsonAsync<ManifestPayload>("available-manifest.json", cancellationToken)
                .ConfigureAwait(false);
            if (availableManifest is not null)
            {
                compatibility = ManifestContractValidator.Evaluate(
                    availableManifest,
                    WorkerInstalledVersion.Current);
            }
        }
        catch (Exception error) when (error is JsonException or ProtocolValidationException or IOException)
        {
            availableManifest = null;
            compatibility = null;
            await logs.WriteAsync("warning", "available-manifest-invalid", "The available update manifest is not usable.",
                cancellationToken: cancellationToken).ConfigureAwait(false);
        }

        var schedulerEligible = orchestrator is not null
            && applied is not null
            && ollama is not null
            && bootstrapReady
            && !hasUnknownJournals;
        if (schedulerEligible && orchestrator is not null && applied is not null && ollama is not null)
        {
            var source = new OrchestratorJobSource(
                orchestrator,
                control,
                journals,
                recovery,
                pendingClaims,
                applied,
                timeProvider);
            var executor = new OllamaEditorialJobExecutor(
                ollama,
                journals,
                recovery,
                assignments,
                applied,
                timeProvider);
            JournaledJobReporter? reporter = null;
            reporter = new JournaledJobReporter(
                orchestrator,
                journals,
                recovery,
                assignments,
                configuration.NodeId,
                configuration.KeyId,
                unsafeOutcome: _ => control.MarkNotReady("journal-outcome-unknown"),
                completed: duration => state.RecordCompleted(duration),
                failed: state.RecordFailed,
                timeProvider: timeProvider);
            scheduler = new ConcurrentJobScheduler(control, source, executor, reporter);
            if (!schedulerHost.TryPublish(scheduler))
            {
                await scheduler.DisposeAsync().ConfigureAwait(false);
                throw new WorkerServiceException(
                    "runtime-composition-race",
                    "The startup scheduler was published more than once.");
            }
            control.MarkReady("startup-readiness-paused");
        }

        var metadata = CreateMetadata(
            appliedState,
            availableManifest,
            compatibility,
            applied,
            readyState,
            bootstrapReady);
        var controller = new WorkerOperationalController(
            control,
            schedulerHost,
            timeProvider,
            async (snapshot, persistCancellationToken) =>
            {
                WorkerConfiguration latest = await WorkerConfigurationStore.ReadAsync(
                    string.IsNullOrWhiteSpace(configurationPath) ? null : configurationPath,
                    persistCancellationToken).ConfigureAwait(false);
                await WorkerConfigurationStore.WriteAsync(
                    latest with
                    {
                        LastNonZeroMaxConcurrentJobs = snapshot.LastNonZeroMaxConcurrentJobs,
                        ClaimBatchSize = snapshot.ClaimBatchSize,
                    },
                    string.IsNullOrWhiteSpace(configurationPath) ? null : configurationPath,
                    persistCancellationToken).ConfigureAwait(false);
            },
            ensureExclusiveClaiming: new WindowsLegacyWorkerCutoverGuard(configuration.NodeId)
                .EnsureExclusiveAsync);
        OperationalEnrollmentCoordinator? enrollment = identity is not null && orchestratorHttp is not null
            ? new OperationalEnrollmentCoordinator(
                configuration,
                identity,
                files,
                orchestratorHttp,
                timeProvider)
            : null;
        PostEnrollmentRuntimeActivator? postEnrollmentActivation = null;
        if (enrollment is not null && identity is not null && orchestrator is not null
            && orchestratorHttp is not null && artifactHttp is not null
            && ollamaHttp is not null && ollamaGuard is not null && ollama is not null)
        {
            postEnrollmentActivation = new PostEnrollmentRuntimeActivator(
                control,
                schedulerHost,
                async activateCancellationToken =>
                {
                    try
                    {
                        return await ComposePostEnrollmentSchedulerAsync(
                            configuration,
                            files,
                            journals,
                            recovery,
                            pendingClaims,
                            logs,
                            control,
                            assignments,
                            state,
                            metadata,
                            identity,
                            orchestrator,
                            orchestratorHttp,
                            artifactHttp,
                            ollamaHttp,
                            ollamaGuard,
                            ollama,
                            activateCancellationToken).ConfigureAwait(false);
                    }
                    catch (OperationCanceledException) when (activateCancellationToken.IsCancellationRequested)
                    {
                        metadata.RecordNotReady();
                        throw;
                    }
                    catch (Exception error)
                    {
                        var code = StartupErrorCode(error);
                        metadata.RecordNotReady();
                        state.RecordError(code);
                        await WriteStartupNotReadyAsync(
                            files,
                            configuration,
                            code,
                            timeProvider,
                            activateCancellationToken).ConfigureAwait(false);
                        await logs.WriteAsync(
                            "warning",
                            code,
                            "Post-enrollment bootstrap activation did not complete.",
                            cancellationToken: activateCancellationToken).ConfigureAwait(false);
                        throw;
                    }
                });
        }

        WorkerServiceRuntime? runtime = null;
        var pipe = new WorkerControlPipeServer(
            configuration,
            controller,
            () => runtime?.Snapshot() ?? throw new InvalidOperationException("worker-runtime-not-bound"),
            logs,
            enrollment,
            postEnrollmentActivation,
            timeProvider);
        var owned = new List<IDisposable>();
        if (identity is not null) owned.Add(identity);
        if (orchestratorHttp is not null) owned.Add(orchestratorHttp);
        if (artifactHttp is not null) owned.Add(artifactHttp);
        if (ollamaHttp is not null) owned.Add(ollamaHttp);
        runtime = new WorkerServiceRuntime(
            configuration,
            metadata,
            control,
            schedulerHost,
            orchestrator,
            assignments,
            state,
            new WindowsTelemetryCollector(auxiliaryProcessProvider: ollamaGuard),
            ollama,
            pipe,
            logs,
            runtimeLogger,
            timeProvider,
            owned.ToArray());
        return runtime;
    }

    private async Task<ConcurrentJobScheduler> ComposePostEnrollmentSchedulerAsync(
        WorkerConfiguration configuration,
        AtomicFileStore files,
        EditorialJournalStore journals,
        ProtectedEditorialRecoveryStore recovery,
        PendingClaimStore pendingClaims,
        SanitizedLogStore logs,
        WorkerControlState control,
        AssignmentRuntimeRegistry assignments,
        WorkerRuntimeState state,
        WorkerRuntimeMetadata metadata,
        Ed25519Identity identity,
        IOrchestratorClient orchestrator,
        HttpClient orchestratorHttp,
        HttpClient artifactHttp,
        HttpClient ollamaHttp,
        IOllamaEndpointGuard ollamaGuard,
        OllamaChatClient ollama,
        CancellationToken cancellationToken)
    {
        var appliedState = await files.ReadJsonAsync<AppliedManifestState>(
            "applied-manifest.json",
            cancellationToken).ConfigureAwait(false);
        var applied = appliedState is null ? null : AppliedRuntimeContract.FromAppliedState(appliedState);

        var recoverySource = new OrchestratorJobSource(
            orchestrator,
            control,
            journals,
            recovery,
            pendingClaims,
            applied,
            timeProvider);
        var recoveredClaims = await recoverySource.RecoverPendingClaimAsync(cancellationToken)
            .ConfigureAwait(false);
        var outcomeRecovery = await new EditorialOutcomeReconciler(
            orchestrator,
            journals,
            recovery,
            configuration.NodeId,
            configuration.KeyId,
            completed: state.RecordCompleted,
            failed: state.RecordFailed,
            timeProvider: timeProvider)
            .ReconcileAsync(cancellationToken).ConfigureAwait(false);
        if (recoveredClaims > 0 || outcomeRecovery.Reconciled > 0)
        {
            await logs.WriteAsync(
                "information",
                "post-enrollment-journal-reconciled",
                "Durable claim and outcome evidence was reconciled before activation.",
                cancellationToken: cancellationToken).ConfigureAwait(false);
        }

        if (outcomeRecovery.Pending > 0
            || await HasUnreconciledJournalsAsync(files, journals, cancellationToken).ConfigureAwait(false))
        {
            throw new WorkerServiceException(
                "post-enrollment-journal-reconciliation-pending",
                "Unfinished durable outcomes prevent post-enrollment activation.");
        }

        var pins = await ManifestTrustPinsLoader.LoadAsync(configuration, cancellationToken)
            .ConfigureAwait(false);
        var signedClient = orchestrator as SignedOrchestratorClient
            ?? throw new WorkerServiceException(
                "orchestrator-client-invalid",
                "Post-enrollment activation requires the signed orchestrator transport.");
        var coordinator = new BootstrapAttestationCoordinator(
            files,
            new BootstrapAttestationClient(
                orchestratorHttp,
                configuration.OrchestratorBaseUri,
                signedClient),
            new ManifestArtifactApplier(
                files,
                new HttpManifestArtifactSource(artifactHttp, configuration.OrchestratorBaseUri),
                new HttpOllamaManifestProbe(
                    ollamaHttp,
                    configuration.OllamaBaseUri,
                    ollamaGuard),
                timeProvider),
            pins,
            identity,
            timeProvider);
        _ = await coordinator.RunPausedAsync(
            new BootstrapCoordinatorRequest(
                configuration.NodeId,
                configuration.KeyId,
                RuntimeInformation.ProcessArchitecture.ToString(),
                Environment.MachineName,
                WorkerInstalledVersion.Current,
                Guid.NewGuid().ToString("D"),
                Guid.NewGuid().ToString("D"),
                ActiveAssignments: 0),
            cancellationToken).ConfigureAwait(false);

        appliedState = await files.ReadJsonAsync<AppliedManifestState>(
            "applied-manifest.json",
            cancellationToken).ConfigureAwait(false)
            ?? throw new WorkerServiceException(
                "bootstrap-applied-state-missing",
                "Post-enrollment bootstrap did not commit an applied manifest state.");
        applied = AppliedRuntimeContract.FromAppliedState(appliedState);
        var ready = await files.ReadJsonAsync<WorkerReadyStateRecord>(
            "ready.json",
            cancellationToken).ConfigureAwait(false);
        var trust = await files.ReadJsonAsync<ManifestTrustStateRecord>(
            "trust-state.json",
            cancellationToken).ConfigureAwait(false);
        if (!ReadyStateIsUsable(
                ready,
                trust,
                appliedState,
                configuration,
                pins,
                timeProvider.GetUtcNow()))
        {
            throw new WorkerServiceException(
                "bootstrap-commit-invalid",
                "Post-enrollment bootstrap did not produce a usable readiness commit.");
        }

        var availableManifest = await files.ReadJsonAsync<ManifestPayload>(
            "available-manifest.json",
            cancellationToken).ConfigureAwait(false);
        var compatibility = availableManifest is null
            ? null
            : ManifestContractValidator.Evaluate(availableManifest, WorkerInstalledVersion.Current);
        var source = new OrchestratorJobSource(
            orchestrator,
            control,
            journals,
            recovery,
            pendingClaims,
            applied,
            timeProvider);
        var executor = new OllamaEditorialJobExecutor(
            ollama,
            journals,
            recovery,
            assignments,
            applied,
            timeProvider);
        var reporter = new JournaledJobReporter(
            orchestrator,
            journals,
            recovery,
            assignments,
            configuration.NodeId,
            configuration.KeyId,
            unsafeOutcome: _ => control.MarkNotReady("journal-outcome-unknown"),
            completed: duration => state.RecordCompleted(duration),
            failed: state.RecordFailed,
            timeProvider: timeProvider);
        var scheduler = new ConcurrentJobScheduler(control, source, executor, reporter);
        metadata.RecordBootstrap(
            availableManifest?.Runtime.WorkerVersion,
            compatibility?.UpdateAvailable ?? false,
            updateCompatible: compatibility?.MayClaim ?? true,
            "applied-contract-valid",
            appliedState.ManifestSequence,
            applied.ContentContractHash,
            ReadyUntil(ready),
            "verified",
            appliedState.Model);
        return scheduler;
    }

    private static WorkerRuntimeMetadata CreateMetadata(
        AppliedManifestState? appliedState,
        ManifestPayload? availableManifest,
        ManifestCompatibilityEvaluation? compatibility,
        AppliedRuntimeContract? applied,
        WorkerReadyStateRecord? readyState,
        bool bootstrapReady)
    {
        var availableVersion = availableManifest?.Runtime.WorkerVersion;
        return new WorkerRuntimeMetadata(
            availableVersion,
            compatibility?.UpdateAvailable ?? false,
            compatibility?.MayClaim ?? true,
            appliedState is null ? "unavailable" : bootstrapReady ? "applied-contract-valid" : "not-attested",
            appliedState?.ManifestSequence,
            applied?.ContentContractHash,
            ReadyUntil(readyState),
            bootstrapReady ? "verified" : "not-ready",
            appliedState?.Model);
    }

    internal static AppliedManifestState? SelectReadyAppliedState(
        AppliedManifestState? current,
        AppliedManifestState? prior,
        WorkerReadyStateRecord? ready,
        ManifestTrustStateRecord? trust,
        WorkerConfiguration configuration,
        ManifestTrustPins pins,
        DateTimeOffset now) => SelectReadyAppliedState(
            current,
            prior,
            ready,
            trust,
            configuration.NodeId,
            configuration.KeyId,
            WorkerInstalledVersion.Current,
            pins,
            now);

    internal static AppliedManifestState? SelectReadyAppliedState(
        AppliedManifestState? current,
        AppliedManifestState? prior,
        WorkerReadyStateRecord? ready,
        ManifestTrustStateRecord? trust,
        BootstrapCoordinatorRequest request,
        ManifestTrustPins pins,
        DateTimeOffset now) => SelectReadyAppliedState(
            current,
            prior,
            ready,
            trust,
            request.NodeId,
            request.WorkerKeyId,
            request.WorkerRuntimeVersion,
            pins,
            now);

    private static AppliedManifestState? SelectReadyAppliedState(
        AppliedManifestState? current,
        AppliedManifestState? prior,
        WorkerReadyStateRecord? ready,
        ManifestTrustStateRecord? trust,
        string nodeId,
        string keyId,
        string workerRuntimeVersion,
        ManifestTrustPins pins,
        DateTimeOffset now)
    {
        if (current is not null && ReadyStateIsUsable(
                ready,
                trust,
                current,
                nodeId,
                keyId,
                workerRuntimeVersion,
                pins,
                now))
        {
            return current;
        }

        return prior is not null && ReadyStateIsUsable(
            ready,
            trust,
            prior,
            nodeId,
            keyId,
            workerRuntimeVersion,
            pins,
            now)
            ? prior
            : null;
    }

    internal static bool ReadyStateIsUsable(
        WorkerReadyStateRecord? ready,
        ManifestTrustStateRecord? trust,
        AppliedManifestState applied,
        WorkerConfiguration configuration,
        ManifestTrustPins pins,
        DateTimeOffset now) => ReadyStateIsUsable(
            ready,
            trust,
            applied,
            configuration.NodeId,
            configuration.KeyId,
            WorkerInstalledVersion.Current,
            pins,
            now);

    internal static bool ReadyStateIsUsable(
        WorkerReadyStateRecord? ready,
        ManifestTrustStateRecord? trust,
        AppliedManifestState applied,
        string nodeId,
        string keyId,
        string workerRuntimeVersion,
        ManifestTrustPins pins,
        DateTimeOffset now)
    {
        if (ready is null || trust is null)
        {
            return false;
        }

        try
        {
            var readyUntil = ProtocolTime.ParseTimestamp(ready.ReadyUntil, "ready.readyUntil");
            var attestedAt = ProtocolTime.ParseTimestamp(ready.AttestedAt, "ready.attestedAt");
            var trustVerifiedAt = ProtocolTime.ParseTimestamp(
                ready.TrustVerifiedAt,
                "ready.trustVerifiedAt");
            var persistedTrustVerifiedAt = ProtocolTime.ParseTimestamp(
                trust.VerifiedAt,
                "trust.verifiedAt");
            return ready.SchemaVersion == 1
                && ready.Ready
                && ready.NodeId == nodeId
                && ready.KeyId == keyId
                && ready.WorkerRuntimeVersion == workerRuntimeVersion
                && ready.ManifestSequence == applied.ManifestSequence
                && ready.ManifestHash == applied.ManifestHash
                && ready.ContentContractHash == applied.ContentContractHash
                && ready.PolicyHash == applied.PolicyHash
                && ready.Provider == applied.Provider
                && ready.EngineAdapter == applied.EngineAdapter
                && ready.EngineAdapterVersion == applied.EngineAdapterVersion
                && ready.RuntimeProfileHash == applied.RuntimeProfileHash
                && HchDigest.IsLowerSha256(ready.CapacityPolicyHash)
                && HchDigest.IsLowerSha256(ready.AdaptiveWorkPolicyHash)
                && ready.RequestedCapacity == 0
                && ready.GrantedCapacity == 0
                && ready.CapacityReason.Contains("drain-requested", StringComparison.Ordinal)
                && Guid.TryParseExact(ready.BootstrapSessionId, "D", out var sessionId)
                && sessionId != Guid.Empty
                && readyUntil > now
                && attestedAt <= now.AddMinutes(5)
                && trustVerifiedAt <= now.AddMinutes(5)
                && trust.Schema == "hch.worker-trust-state/v1"
                && trust.SchemaVersion == 1
                && trust.RootKeyId == pins.RootKeyId
                && trust.RootFingerprint == pins.RootPublicKeyFingerprint
                && !string.IsNullOrWhiteSpace(trust.ReleaseKeyId)
                && trust.DelegationSequence >= 1
                && HchDigest.IsLowerSha256(trust.DelegationHash)
                && persistedTrustVerifiedAt <= now.AddMinutes(5)
                && TrustStateAuthorizesAppliedContract(trust, applied);
        }
        catch (ProtocolValidationException)
        {
            return false;
        }
    }

    private static bool TrustStateAuthorizesAppliedContract(
        ManifestTrustStateRecord trust,
        AppliedManifestState applied)
    {
        if (!HchDigest.IsLowerSha256(trust.ManifestHash)
            || !HchDigest.IsLowerSha256(trust.ContentContractHash)
            || !HchDigest.IsLowerSha256(trust.PolicyHash)
            || !HchDigest.IsLowerSha256(applied.ManifestHash)
            || !HchDigest.IsLowerSha256(applied.ContentContractHash)
            || !HchDigest.IsLowerSha256(applied.PolicyHash)
            || trust.ManifestSequence < applied.ManifestSequence
            || trust.ContentContractHash != applied.ContentContractHash
            || trust.PolicyHash != applied.PolicyHash)
        {
            return false;
        }

        // Persisting a newly signature-verified compatible manifest advances the
        // anti-rollback pin before bootstrap. If bootstrap then fails transiently,
        // the previous applied content contract remains safe to run. At the same
        // sequence, however, a different manifest hash is equivocation and must
        // fail closed.
        return trust.ManifestSequence > applied.ManifestSequence
            || trust.ManifestHash == applied.ManifestHash;
    }

    private static DateTimeOffset? ReadyUntil(WorkerReadyStateRecord? ready)
    {
        if (ready is null)
        {
            return null;
        }

        try
        {
            return ProtocolTime.ParseTimestamp(ready.ReadyUntil, "ready.readyUntil");
        }
        catch (ProtocolValidationException)
        {
            return null;
        }
    }

    internal static bool IsTransientBootstrapFailure(Exception error) => error switch
    {
        OrchestratorRequestException request => request.Retryable,
        WorkerServiceException service => service.Code is
            "network-request-failed" or "network-request-timeout",
        _ => false,
    };

    private static string StartupErrorCode(Exception error) => error switch
    {
        WorkerServiceException service => service.Code,
        OrchestratorRequestException request => request.Code,
        ProtocolValidationException protocol => protocol.Code,
        WorkerConfigurationException configuration => configuration.Code,
        CryptographicException => "bootstrap-cryptographic-failure",
        IOException => "bootstrap-state-io-failure",
        _ => "bootstrap-startup-failed",
    };

    private static Task WriteStartupNotReadyAsync(
        AtomicFileStore files,
        WorkerConfiguration configuration,
        string reason,
        TimeProvider timeProvider,
        CancellationToken cancellationToken) => files.WriteJsonAsync(
            "ready.json",
            new
            {
                schemaVersion = 1,
                ready = false,
                nodeId = configuration.NodeId,
                keyId = configuration.KeyId,
                invalidatedAt = timeProvider.GetUtcNow().ToString("O"),
                reason = SignedOrchestratorClient.SafeErrorCode(reason),
            },
            cancellationToken);

    private static async Task<bool> HasUnreconciledJournalsAsync(
        AtomicFileStore files,
        EditorialJournalStore journals,
        CancellationToken cancellationToken)
    {
        var directory = files.Resolve(Path.Combine("journals", "assignments"));
        if (File.Exists(files.Resolve(PendingClaimStore.RelativePath)))
        {
            return true;
        }

        if (!Directory.Exists(directory))
        {
            return false;
        }

        foreach (var path in Directory.EnumerateFiles(directory, "*.json", SearchOption.TopDirectoryOnly))
        {
            var assignmentId = Path.GetFileNameWithoutExtension(path);
            var journal = await journals.ReadAsync(assignmentId, cancellationToken).ConfigureAwait(false);
            if (journal is null || journal.RequiresReconciliation || journal.IsActive)
            {
                return true;
            }
        }

        return false;
    }

    private static HttpClient CreateOrchestratorHttpClient() => new(new SocketsHttpHandler
    {
        AllowAutoRedirect = false,
        AutomaticDecompression = System.Net.DecompressionMethods.None,
        UseCookies = false,
        PooledConnectionLifetime = TimeSpan.FromMinutes(5),
    })
    {
        Timeout = TimeSpan.FromSeconds(10),
    };

    private static HttpClient CreateArtifactHttpClient() => new(new SocketsHttpHandler
    {
        AllowAutoRedirect = false,
        AutomaticDecompression = System.Net.DecompressionMethods.None,
        UseCookies = false,
        PooledConnectionLifetime = TimeSpan.FromMinutes(5),
    })
    {
        Timeout = TimeSpan.FromMinutes(5),
    };

    private static HttpClient CreateOllamaHttpClient(
        WindowsOllamaEndpointGuard endpointGuard) => new(new SocketsHttpHandler
        {
            AllowAutoRedirect = false,
            AutomaticDecompression = System.Net.DecompressionMethods.None,
            UseCookies = false,
            UseProxy = false,
            PooledConnectionLifetime = TimeSpan.FromMinutes(5),
            ConnectCallback = (context, cancellationToken) =>
                endpointGuard.ConnectAuthenticatedAsync(context.DnsEndPoint, cancellationToken),
        })
        {
            Timeout = Timeout.InfiniteTimeSpan,
        };
}
