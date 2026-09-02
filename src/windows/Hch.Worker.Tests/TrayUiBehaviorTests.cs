using Hch.Worker.IPC.Contracts;
using Hch.Worker.Tray;
using System.Globalization;

namespace Hch.Worker.Tests;

public sealed class TrayUiBehaviorTests
{
    [Fact]
    public void LogFilter_SearchesSanitizedFieldsAndLevelAndSortsNewestFirst()
    {
        DateTimeOffset now = new(2026, 9, 2, 12, 0, 0, TimeSpan.Zero);
        SanitizedLogEntryPayload[] entries =
        [
            new(now.AddMinutes(-2), "Information", "worker-ready", "Ready.", new Dictionary<string, string>()),
            new(now, "Warning", "ollama-latency", "Inference slower than expected.", new Dictionary<string, string> { ["model"] = "qwen3" }),
            new(now.AddMinutes(-1), "Warning", "network-retry", "Retry scheduled.", new Dictionary<string, string>()),
        ];

        IReadOnlyList<SanitizedLogEntryPayload> result = TrayUiLogFilter.Apply(entries, "qwen3 latency", "warning");

        SanitizedLogEntryPayload item = Assert.Single(result);
        Assert.Equal("ollama-latency", item.EventCode);

        IReadOnlyList<SanitizedLogEntryPayload> warnings = TrayUiLogFilter.Apply(entries, null, "WARNING");
        Assert.Equal(new[] { "ollama-latency", "network-retry" }, warnings.Select(entry => entry.EventCode));
    }

    [Fact]
    public void OnboardingCompletion_FailsClosedUnlessEveryRequiredStateIsValid()
    {
        DateTimeOffset now = new(2026, 9, 2, 12, 0, 0, TimeSpan.Zero);
        WorkerSnapshotPayload valid = Snapshot(now);

        Assert.True(OnboardingCompletionPolicy.Evaluate(valid, enrollmentCompletedThisSession: true, now).CanComplete);
        Assert.True(OnboardingCompletionPolicy.Evaluate(valid with { TrustStatus = "verified", ManifestStatus = "applied-contract-valid" }, true, now).CanComplete);
        Assert.False(OnboardingCompletionPolicy.Evaluate(valid, enrollmentCompletedThisSession: false, now).CanComplete);
        Assert.False(OnboardingCompletionPolicy.Evaluate(valid with { TrustStatus = "pending" }, true, now).CanComplete);
        Assert.False(OnboardingCompletionPolicy.Evaluate(valid with { ManifestStatus = "not-attested" }, true, now).CanComplete);
        Assert.False(OnboardingCompletionPolicy.Evaluate(valid with { Ready = false }, true, now).CanComplete);
        Assert.False(OnboardingCompletionPolicy.Evaluate(valid with { ReadyUntil = null }, true, now).CanComplete);
        Assert.False(OnboardingCompletionPolicy.Evaluate(valid with { ReadyUntil = now }, true, now).CanComplete);
        Assert.False(OnboardingCompletionPolicy.Evaluate(valid with { OperationalState = "Running", AcceptingClaims = true }, true, now).CanComplete);
    }

    [Fact]
    public void JobProgress_ReportsItemPercentAndCompletesSingleItemBatchBar()
    {
        var payload = new JobProgressPayload(
            "assignment-1",
            "generating",
            1,
            4,
            2048,
            42.4,
            1,
            1,
            DateTimeOffset.UtcNow);

        var view = new JobProgressView(payload);

        Assert.Equal(42.4, view.ItemPercent);
        Assert.Equal("42%", view.ItemPercentText);
        Assert.Equal(100, view.BatchPercent);
        Assert.Equal("1/1", view.BatchText);
        Assert.Equal($"{2d.ToString("F1", CultureInfo.CurrentCulture)} KiB", view.ContentBytesText);
    }

    [Theory]
    [InlineData(0, "0.0 s")]
    [InlineData(9.5, "9.5 s")]
    [InlineData(65, "1:05")]
    [InlineData(3661, "1:01:01")]
    public void DurationFormatting_IsCompactAndUnambiguous(double seconds, string expected)
    {
        string localizedExpected = expected.Replace(
            ".",
            CultureInfo.CurrentCulture.NumberFormat.NumberDecimalSeparator,
            StringComparison.Ordinal);
        Assert.Equal(localizedExpected, WorkerOptionsViewModel.FormatDuration(seconds));
    }

    private static WorkerSnapshotPayload Snapshot(DateTimeOffset now) => new(
        NodeId: "node-1",
        WorkerName: "HCH Worker",
        InstalledVersion: "4.0.0",
        AvailableVersion: null,
        ServiceState: "Running",
        OperationalState: "Paused",
        Ready: true,
        AcceptingClaims: false,
        MaxConcurrentJobs: 0,
        LastNonZeroMaxConcurrentJobs: 1,
        ClaimBatchSize: 1,
        GrantedCapacity: 0,
        ActiveJobs: 0,
        ReservedJobs: 0,
        AvailableSlots: 0,
        LastHeartbeatAt: now,
        OrchestratorLatencyMilliseconds: 25,
        TrustStatus: "trusted",
        ReadyUntil: now.AddMinutes(15),
        ManifestStatus: "valid",
        ManifestSequence: 1,
        ContentContractHash: "sha256:test",
        UpdateAvailable: false,
        UpdateCompatible: true,
        OllamaModel: "qwen3",
        OllamaAvailable: true,
        QueueDepth: null,
        CompletedJobs: 0,
        FailedJobs: 0,
        RetryJobs: 0,
        AverageDurationSeconds: null,
        ThroughputJobsPerHour: null,
        ActiveWork: [],
        OperationalHistory: [],
        Resources: Resources(),
        LastSanitizedErrorCode: null);

    private static ResourceSnapshotPayload Resources() => new(
        Unavailable<double>(),
        Unavailable<double>(),
        Unavailable<long>(),
        Unavailable<long>(),
        Unavailable<long>(),
        Unavailable<string>(),
        Unavailable<double>(),
        Unavailable<long>(),
        Unavailable<long>(),
        Unavailable<long>(),
        Unavailable<long>(),
        Unavailable<long>(),
        Unavailable<long>(),
        UptimeSeconds: 0,
        AuxiliaryProcessCount: 0);

    private static MetricPayload<T> Unavailable<T>() => new(false, default, "not-collected");
}
