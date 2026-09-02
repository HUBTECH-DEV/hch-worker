using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Hch.Worker.IPC.Contracts;

public static class IpcProtocol
{
    public const int Version = 2;
    public const int MaximumFrameBytes = 1024 * 1024;
    public const string PipePrefix = "Hch.Worker.Control.v2";

    public static string PipeName(string nodeId)
    {
        if (string.IsNullOrWhiteSpace(nodeId) || nodeId.Length > 128 ||
            nodeId.Any(static value => !(char.IsAsciiLetterOrDigit(value) || value is '.' or '_' or '-')))
        {
            throw new ArgumentException("The node ID is not safe for a Named Pipe name.", nameof(nodeId));
        }

        return $"{PipePrefix}.{nodeId}";
    }
}

[JsonConverter(typeof(JsonStringEnumConverter<IpcCommand>))]
public enum IpcCommand
{
    GetSnapshot,
    Start,
    Pause,
    Stop,
    SetMaxConcurrentJobs,
    SetClaimBatchSize,
    PrepareMaintenance,
    BeginEnrollment,
    SubmitEnrollmentToken,
    ExportSanitizedLogs,
}

public sealed record IpcRequest(
    int Version,
    string RequestId,
    DateTimeOffset CreatedAt,
    IpcCommand Command,
    JsonElement Payload)
{
    public static IpcRequest Create<T>(IpcCommand command, T payload, DateTimeOffset? createdAt = null) => new(
        IpcProtocol.Version,
        Guid.NewGuid().ToString("D"),
        createdAt ?? DateTimeOffset.UtcNow,
        command,
        JsonSerializer.SerializeToElement(payload, IpcJson.Options));
}

public sealed record IpcResponse(
    int Version,
    string RequestId,
    bool Success,
    string? ErrorCode,
    JsonElement Payload)
{
    public static IpcResponse Ok<T>(string requestId, T payload) => new(
        IpcProtocol.Version,
        requestId,
        Success: true,
        ErrorCode: null,
        JsonSerializer.SerializeToElement(payload, IpcJson.Options));

    public static IpcResponse Error(string requestId, string errorCode) => new(
        IpcProtocol.Version,
        requestId,
        Success: false,
        ErrorCode: IpcValidation.ErrorCode(errorCode),
        JsonSerializer.SerializeToElement(EmptyPayload.Value, IpcJson.Options));
}

public sealed record EmptyPayload
{
    public static EmptyPayload Value { get; } = new();
}

public sealed record SetMaxConcurrentJobsPayload(int Value);

public sealed record SetClaimBatchSizePayload(int Value);

public sealed record EnrollmentTokenPayload(
    byte[] TokenUtf8,
    string OwnerSshKeyId,
    string OwnerSshKeyFingerprint)
{
    public void Clear()
    {
        if (TokenUtf8 is not null)
        {
            CryptographicOperations.ZeroMemory(TokenUtf8);
        }
    }
}

public sealed record BeginEnrollmentPayload(string PreferredFlow);

public sealed record EnrollmentStartPayload(
    string Flow,
    Uri AuthorizationUri,
    string CorrelationId,
    DateTimeOffset ExpiresAt);

public sealed record OperationalEnrollmentContextPayload(
    string Protocol,
    string NodeId,
    string WorkerKeyId,
    string WorkerPublicKeyPem,
    string WorkerPublicKeyFingerprint,
    string WorkerRuntimeVersion);

public sealed record OperationalEnrollmentCompletedPayload(
    string Protocol,
    string NodeId,
    string WorkerKeyId,
    string WorkerPublicKeyFingerprint,
    string OwnerUserId,
    string OwnerEmail,
    string OwnerSshKeyId,
    string OwnerSshKeyFingerprint,
    string Status,
    DateTimeOffset EnrolledAt);

public sealed record ExportLogsPayload(DateTimeOffset? Since, int MaximumEntries = 2_000);

public sealed record SanitizedLogEntryPayload(
    DateTimeOffset Timestamp,
    string Level,
    string EventCode,
    string Message,
    IReadOnlyDictionary<string, string> Fields);

public sealed record SanitizedLogsPayload(IReadOnlyList<SanitizedLogEntryPayload> Entries);

public sealed record CommandAcceptedPayload(string State, DateTimeOffset AcceptedAt);

public sealed record WorkerSnapshotPayload(
    string NodeId,
    string WorkerName,
    string InstalledVersion,
    string? AvailableVersion,
    string ServiceState,
    string OperationalState,
    bool Ready,
    bool AcceptingClaims,
    int MaxConcurrentJobs,
    int LastNonZeroMaxConcurrentJobs,
    int ClaimBatchSize,
    int GrantedCapacity,
    int ActiveJobs,
    int ReservedJobs,
    int AvailableSlots,
    DateTimeOffset? LastHeartbeatAt,
    long? OrchestratorLatencyMilliseconds,
    string TrustStatus,
    DateTimeOffset? ReadyUntil,
    string ManifestStatus,
    long? ManifestSequence,
    string? ContentContractHash,
    bool UpdateAvailable,
    bool UpdateCompatible,
    string? OllamaModel,
    bool OllamaAvailable,
    int? QueueDepth,
    long CompletedJobs,
    long FailedJobs,
    long RetryJobs,
    double? AverageDurationSeconds,
    double? ThroughputJobsPerHour,
    IReadOnlyList<JobProgressPayload> ActiveWork,
    IReadOnlyList<OperationalHistoryPointPayload> OperationalHistory,
    ResourceSnapshotPayload Resources,
    string? LastSanitizedErrorCode);

/// <summary>
/// Bounded, aggregate-only operational history. Assignment identifiers,
/// content, lease material and credentials are deliberately excluded.
/// </summary>
public sealed record OperationalHistoryPointPayload(
    DateTimeOffset ObservedAt,
    int ActiveJobs,
    int ReservedJobs,
    int? QueueDepth,
    long CompletedJobs,
    long FailedJobs,
    long RetryJobs,
    double? ThroughputJobsPerHour,
    double? AverageDurationSeconds);

public sealed record JobProgressPayload(
    string AssignmentId,
    string Phase,
    int Attempt,
    long Sequence,
    long ContentBytes,
    double? Percent,
    int ItemIndex,
    int BatchTotal,
    DateTimeOffset ObservedAt);

public sealed record ResourceSnapshotPayload(
    MetricPayload<double> WorkerCpuPercent,
    MetricPayload<double> SystemCpuPercent,
    MetricPayload<long> WorkingSetBytes,
    MetricPayload<long> AverageWorkingSetBytes,
    MetricPayload<long> PeakWorkingSetBytes,
    MetricPayload<string> GpuName,
    MetricPayload<double> GpuPercent,
    MetricPayload<long> VramUsedBytes,
    MetricPayload<long> VramTotalBytes,
    MetricPayload<long> DiskReadBytes,
    MetricPayload<long> DiskWrittenBytes,
    MetricPayload<long> NetworkReceivedBytes,
    MetricPayload<long> NetworkSentBytes,
    long UptimeSeconds,
    int AuxiliaryProcessCount);

public sealed record MetricPayload<T>(bool Available, T? Value, string? UnavailableReason);

public static class IpcJson
{
    public static JsonSerializerOptions Options { get; } = CreateOptions();

    private static JsonSerializerOptions CreateOptions() => new(JsonSerializerDefaults.Web)
    {
        AllowTrailingCommas = false,
        MaxDepth = 32,
        NumberHandling = JsonNumberHandling.Strict,
        PropertyNameCaseInsensitive = false,
        ReadCommentHandling = JsonCommentHandling.Disallow,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
        WriteIndented = false,
    };
}

public static class IpcValidation
{
    public static IpcRequest Request(IpcRequest value, DateTimeOffset now)
    {
        if (value.Version != IpcProtocol.Version)
        {
            throw new IpcContractException("ipc-version-unsupported");
        }

        if (!Guid.TryParseExact(value.RequestId, "D", out _))
        {
            throw new IpcContractException("ipc-request-id-invalid");
        }

        if (value.CreatedAt > now.AddSeconds(30) || value.CreatedAt < now.AddMinutes(-5))
        {
            throw new IpcContractException("ipc-request-expired");
        }

        if (!Enum.IsDefined(value.Command) || value.Payload.ValueKind != JsonValueKind.Object)
        {
            throw new IpcContractException("ipc-command-invalid");
        }

        return value;
    }

    public static string ErrorCode(string value)
    {
        if (string.IsNullOrWhiteSpace(value) || value.Length > 120 ||
            !char.IsAsciiLetterOrDigit(value[0]) ||
            value.Any(static character => !(char.IsAsciiLetterOrDigit(character) || character is '.' or '_' or '-')))
        {
            throw new ArgumentException("The IPC error code is invalid.", nameof(value));
        }

        return value.ToLowerInvariant();
    }

    public static T Payload<T>(JsonElement payload)
    {
        try
        {
            return payload.Deserialize<T>(IpcJson.Options)
                ?? throw new IpcContractException("ipc-payload-invalid");
        }
        catch (JsonException error)
        {
            throw new IpcContractException("ipc-payload-invalid", error);
        }
    }
}

public sealed class IpcContractException(string code, Exception? innerException = null)
    : Exception("The IPC message is invalid.", innerException)
{
    public string Code { get; } = IpcValidation.ErrorCode(code);
}
