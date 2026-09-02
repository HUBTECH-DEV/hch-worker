namespace Hch.Worker.Core;

public sealed record OptionalMetric<T>(bool Available, T? Value, string? UnavailableReason = null)
{
    public static OptionalMetric<T> FromValue(T value) => new(true, value);

    public static OptionalMetric<T> Unavailable(string reason) => new(false, default, reason);
}

public sealed record WorkerResourceSnapshot(
    DateTimeOffset ObservedAt,
    OptionalMetric<double> WorkerCpuPercent,
    OptionalMetric<double> SystemCpuPercent,
    OptionalMetric<long> WorkingSetBytes,
    OptionalMetric<long> AverageWorkingSetBytes,
    OptionalMetric<long> PeakWorkingSetBytes,
    OptionalMetric<string> GpuName,
    OptionalMetric<double> GpuPercent,
    OptionalMetric<long> VramUsedBytes,
    OptionalMetric<long> VramTotalBytes,
    OptionalMetric<long> DiskReadBytes,
    OptionalMetric<long> DiskWrittenBytes,
    OptionalMetric<long> NetworkReceivedBytes,
    OptionalMetric<long> NetworkSentBytes,
    TimeSpan Uptime,
    int AuxiliaryProcessCount);

public sealed record WorkerJobProgress(
    string AssignmentId,
    string Phase,
    int Attempt,
    long Sequence,
    long ContentBytes,
    double? Percent,
    int ItemIndex,
    int BatchTotal,
    DateTimeOffset ObservedAt);

public sealed record WorkerDashboardSnapshot(
    string WorkerName,
    string NodeId,
    string InstalledVersion,
    string? AvailableVersion,
    string WindowsServiceState,
    WorkerControlSnapshot Control,
    WorkerResourceSnapshot Resources,
    IReadOnlyList<WorkerJobProgress> ActiveWork,
    DateTimeOffset? LastHeartbeatAt,
    TimeSpan? OrchestratorLatency,
    string TrustStatus,
    DateTimeOffset? ReadyUntil,
    string? OllamaModel,
    bool OllamaAvailable,
    long CompletedJobs,
    long FailedJobs,
    long RetryJobs,
    double? AverageDurationSeconds,
    string? LastSanitizedErrorCode);
