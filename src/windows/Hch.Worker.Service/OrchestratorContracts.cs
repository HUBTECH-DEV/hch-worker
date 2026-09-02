using System.Text.Json;
using System.Text.Json.Serialization;
using Hch.Worker.Protocol;

namespace Hch.Worker.Service;

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed class ChallengeRequest
{
    [JsonRequired]
    public required string KeyId { get; init; }

    [JsonRequired]
    public required string NodeId { get; init; }

    [JsonRequired]
    public required string Purpose { get; init; }
}

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed class ChallengeResponse
{
    [JsonRequired]
    public required string NodeId { get; init; }

    [JsonRequired]
    public required string KeyId { get; init; }

    [JsonRequired]
    public required string Purpose { get; init; }

    [JsonRequired]
    public required string Nonce { get; init; }

    [JsonRequired]
    public required string ExpiresAt { get; init; }

    [JsonRequired]
    public required string SignatureProfile { get; init; }
}

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed class CapacityDecision
{
    [JsonRequired]
    public required int RequestedCapacity { get; init; }

    [JsonRequired]
    public required int GrantedCapacity { get; init; }

    [JsonRequired]
    public required int AvailableSlots { get; init; }

    [JsonRequired]
    public required int ActiveAssignments { get; init; }

    [JsonRequired]
    public required string Reason { get; init; }

    [JsonRequired]
    public required string? GrantedUntil { get; init; }
}

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed class ClaimRequest
{
    [JsonRequired]
    public required string NodeId { get; init; }

    [JsonRequired]
    public required string WorkerKeyId { get; init; }

    [JsonRequired]
    public required int RequestedCapacity { get; init; }
}

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed class ClaimResponse
{
    [JsonRequired]
    public required string RequestId { get; init; }

    [JsonRequired]
    public required string NodeId { get; init; }

    [JsonRequired]
    public required IReadOnlyList<WorkerAssignment> Assignments { get; init; }

    [JsonRequired]
    public required CapacityDecision Capacity { get; init; }

    [JsonRequired]
    public required bool Replayed { get; init; }

    [JsonRequired]
    public required string ServerTime { get; init; }
}

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed class NodeHeartbeatRequest
{
    [JsonRequired]
    public required string NodeId { get; init; }

    [JsonRequired]
    public required string WorkerKeyId { get; init; }

    [JsonRequired]
    public required int RequestedCapacity { get; init; }
}

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed class NodeHeartbeatCapacity
{
    [JsonRequired]
    public required int ConfiguredCapacity { get; init; }

    [JsonRequired]
    public required int RequestedCapacity { get; init; }

    [JsonRequired]
    public required int GrantedCapacity { get; init; }

    [JsonRequired]
    public required int ActiveAssignments { get; init; }

    [JsonRequired]
    public required int AvailableSlots { get; init; }

    [JsonRequired]
    public required string CapacityClass { get; init; }

    [JsonRequired]
    public required string Reason { get; init; }

    [JsonRequired]
    public required string? GrantedUntil { get; init; }
}

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed class WorkerUpdateAvailability
{
    [JsonRequired]
    public required string InstalledWorkerVersion { get; init; }

    [JsonRequired]
    public required string LatestAvailableWorkerVersion { get; init; }

    [JsonRequired]
    public required bool UpdateAvailable { get; init; }

    [JsonRequired]
    public required string UpdateMode { get; init; }

    [JsonRequired]
    public required bool Compatible { get; init; }

    [JsonRequired]
    public required string ContentImpact { get; init; }
}

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed class NodeHeartbeatResponse
{
    [JsonRequired]
    public required string RequestId { get; init; }

    [JsonRequired]
    public required string NodeId { get; init; }

    [JsonRequired]
    public required string HeartbeatAt { get; init; }

    [JsonRequired]
    public required int NextHeartbeatSeconds { get; init; }

    [JsonRequired]
    public required NodeHeartbeatCapacity Capacity { get; init; }

    [JsonRequired]
    public required JsonElement Workload { get; init; }

    [JsonRequired]
    public required JsonElement WorkSizing { get; init; }

    [JsonRequired]
    public required JsonElement Claim { get; init; }

    [JsonRequired]
    public required WorkerUpdateAvailability Update { get; init; }

    [JsonRequired]
    public required string ServerTime { get; init; }
}

internal sealed record ValidatedNodeHeartbeatWorkload(
    long Claimable,
    long Generating,
    long FutureTotal,
    IReadOnlyDictionary<string, long> ClaimableByTier);

internal sealed record ValidatedNodeHeartbeatWorkSizing(
    string AlgorithmVersion,
    string CurrentTier,
    int CurrentRank,
    int MaxOutputTokens,
    string EditorialProfile,
    bool MinimumUnit,
    string Reason,
    DateTimeOffset UpdatedAt,
    int ProcessingWindowSeconds,
    int NearWindowSeconds,
    int FirstProgressGraceSeconds,
    int StallAfterSeconds,
    int FinalizationGraceSeconds);

internal sealed record ValidatedNodeHeartbeatClaim(
    bool Allowed,
    int RecommendedCount,
    string Reason);

internal sealed record ValidatedNodeHeartbeatDirective(
    ValidatedNodeHeartbeatWorkload Workload,
    ValidatedNodeHeartbeatWorkSizing WorkSizing,
    ValidatedNodeHeartbeatClaim Claim);

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed class CompleteAssignmentRequest
{
    [JsonRequired]
    public required string AssignmentId { get; init; }

    [JsonRequired]
    public required string NodeId { get; init; }

    [JsonRequired]
    public required string WorkerKeyId { get; init; }

    [JsonRequired]
    public required string LeaseToken { get; init; }

    [JsonRequired]
    public required string GenerationPlanHash { get; init; }

    [JsonRequired]
    public required long ManifestSequence { get; init; }

    [JsonRequired]
    public required string ManifestHash { get; init; }

    [JsonRequired]
    public required string PolicyHash { get; init; }

    [JsonRequired]
    public required string RuntimeProfileHash { get; init; }

    [JsonRequired]
    public required string InputSnapshotHash { get; init; }

    [JsonRequired]
    public required object Draft { get; init; }
}

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed class CompleteAssignmentResponse
{
    [JsonRequired]
    public required string AssignmentId { get; init; }

    [JsonRequired]
    public required string GenerationPlanHash { get; init; }

    [JsonRequired]
    public required bool CommitAccepted { get; init; }

    [JsonRequired]
    public required string Status { get; init; }

    [JsonRequired]
    public required bool AutomaticApproval { get; init; }

    [JsonRequired]
    public required bool AutomaticPublication { get; init; }

    [JsonRequired]
    public required bool Replayed { get; init; }

    [JsonRequired]
    public required string ServerTime { get; init; }
}

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed class FailAssignmentRequest
{
    [JsonRequired]
    public required string AssignmentId { get; init; }

    [JsonRequired]
    public required string NodeId { get; init; }

    [JsonRequired]
    public required string WorkerKeyId { get; init; }

    [JsonRequired]
    public required string LeaseToken { get; init; }

    [JsonRequired]
    public required string GenerationPlanHash { get; init; }

    [JsonRequired]
    public required string ErrorCode { get; init; }
}

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed class FailAssignmentResponse
{
    [JsonRequired]
    public required string AssignmentId { get; init; }

    [JsonRequired]
    public required string GenerationPlanHash { get; init; }

    [JsonRequired]
    public required string Status { get; init; }

    [JsonRequired]
    public required bool Replayed { get; init; }

    [JsonRequired]
    public required string ServerTime { get; init; }
}

public static class OrchestratorContractValidator
{
    public static void Validate(ChallengeResponse value, string nodeId, string keyId, string purpose, DateTimeOffset now)
    {
        if (value.NodeId != nodeId || value.KeyId != keyId || value.Purpose != purpose
            || value.SignatureProfile != HchHttpMessageSignatures.SignatureTag
            || value.Nonce.Length is < 16 or > 512 || value.Nonce.Any(char.IsControl))
        {
            throw Invalid("challenge-response-invalid");
        }

        if (ProtocolTime.ParseTimestamp(value.ExpiresAt, "expiresAt") <= now)
        {
            throw Invalid("challenge-expired");
        }
    }

    public static void Validate(
        ClaimResponse value,
        string requestId,
        string nodeId,
        int requested,
        DateTimeOffset now,
        bool acceptExpiredAssignmentsForRecovery = false)
    {
        if (value.RequestId != requestId || value.NodeId != nodeId || value.Assignments.Count > requested)
        {
            throw Invalid("claim-response-invalid");
        }

        Validate(value.Capacity, requested);
        var serverTime = ProtocolTime.ParseTimestamp(value.ServerTime, "serverTime");
        var assignmentIds = new HashSet<string>(StringComparer.Ordinal);
        if (value.Assignments.Any(assignment => !assignmentIds.Add(assignment.AssignmentId)))
        {
            throw Invalid("claim-assignment-duplicate");
        }

        foreach (var assignment in value.Assignments)
        {
            AssignmentContractValidator.Validate(
                assignment,
                acceptExpiredAssignmentsForRecovery ? serverTime : now);
        }
    }

    public static void Validate(CapacityDecision value, int requested)
    {
        if (value.RequestedCapacity != requested || value.GrantedCapacity is < 0 or > 64
            || value.AvailableSlots < 0 || value.ActiveAssignments < 0
            || value.AvailableSlots > value.GrantedCapacity
            || value.GrantedCapacity > requested || string.IsNullOrWhiteSpace(value.Reason)
            || value.Reason.Length > 160)
        {
            throw Invalid("capacity-response-invalid");
        }

        if (value.GrantedUntil is not null)
        {
            _ = ProtocolTime.ParseTimestamp(value.GrantedUntil, "grantedUntil");
        }
    }

    public static void Validate(NodeHeartbeatResponse value, string requestId, string nodeId, int requested)
    {
        if (value.RequestId != requestId || value.NodeId != nodeId
            || value.NextHeartbeatSeconds != ProtocolTime.NodeHeartbeatIntervalSeconds
            || value.Capacity.ConfiguredCapacity is < 0 or > 64
            || value.Capacity.RequestedCapacity != requested
            || value.Capacity.GrantedCapacity is < 0 or > 32
            || value.Capacity.GrantedCapacity > requested
            || value.Capacity.GrantedCapacity > value.Capacity.ConfiguredCapacity
            || value.Capacity.AvailableSlots is < 0 or > 32
            || value.Capacity.AvailableSlots > value.Capacity.GrantedCapacity
            || value.Capacity.ActiveAssignments < 0
            || value.Capacity.CapacityClass is not ("constrained" or "standard" or "accelerated")
            || !IsBoundedText(value.Capacity.Reason, 160)
            || value.Workload.ValueKind != JsonValueKind.Object
            || value.WorkSizing.ValueKind != JsonValueKind.Object
            || value.Claim.ValueKind != JsonValueKind.Object
            || !UpdateIsValid(value.Update))
        {
            throw Invalid("node-heartbeat-response-invalid");
        }

        _ = ReadHeartbeatDirective(value);

        _ = ProtocolTime.ParseTimestamp(value.HeartbeatAt, "heartbeatAt");
        _ = ProtocolTime.ParseTimestamp(value.ServerTime, "serverTime");
        if (value.Capacity.GrantedUntil is not null)
        {
            _ = ProtocolTime.ParseTimestamp(value.Capacity.GrantedUntil, "grantedUntil");
        }
    }

    internal static ValidatedNodeHeartbeatDirective ReadHeartbeatDirective(NodeHeartbeatResponse value)
    {
        ArgumentNullException.ThrowIfNull(value);
        ValidatedNodeHeartbeatWorkload workload = ReadWorkload(value.Workload);
        ValidatedNodeHeartbeatWorkSizing workSizing = ReadWorkSizing(value.WorkSizing);
        ValidatedNodeHeartbeatClaim claim = ReadClaim(value.Claim);
        if (claim.Allowed != (claim.RecommendedCount > 0)
            || claim.RecommendedCount > value.Capacity.GrantedCapacity
            || claim.RecommendedCount > value.Capacity.AvailableSlots
            || claim.RecommendedCount > workload.Claimable
            || ((claim.Reason == "claim-recommended") != (claim.RecommendedCount > 0)))
        {
            throw Invalid("node-heartbeat-response-invalid");
        }

        return new(workload, workSizing, claim);
    }

    internal static int ReadClaimableWorkload(JsonElement workload)
    {
        long claimable = ReadWorkload(workload).Claimable;
        return claimable > int.MaxValue ? int.MaxValue : checked((int)claimable);
    }

    private static ValidatedNodeHeartbeatWorkload ReadWorkload(JsonElement workload)
    {
        RequireExactProperties(
            workload,
            ["claimable", "generating", "futureTotal", "claimableByTier"]);
        long claimable = ReadSafeCounter(workload.GetProperty("claimable"));
        long generating = ReadSafeCounter(workload.GetProperty("generating"));
        long futureTotal = ReadSafeCounter(workload.GetProperty("futureTotal"));
        if (futureTotal < claimable || futureTotal < generating)
        {
            throw Invalid("node-heartbeat-response-invalid");
        }

        JsonElement byTier = workload.GetProperty("claimableByTier");
        if (byTier.ValueKind != JsonValueKind.Object)
        {
            throw Invalid("node-heartbeat-response-invalid");
        }

        var tiers = new Dictionary<string, long>(StringComparer.Ordinal);
        foreach (JsonProperty tier in byTier.EnumerateObject())
        {
            long count = ReadSafeCounter(tier.Value);
            if (tiers.Count >= 8 || !IsTierIdentifier(tier.Name)
                || !tiers.TryAdd(tier.Name, count) || count > claimable)
            {
                throw Invalid("node-heartbeat-response-invalid");
            }
        }

        if (tiers.Count == 0)
        {
            throw Invalid("node-heartbeat-response-invalid");
        }

        return new(claimable, generating, futureTotal, tiers);
    }

    private static ValidatedNodeHeartbeatWorkSizing ReadWorkSizing(JsonElement value)
    {
        RequireExactProperties(value,
        [
            "algorithmVersion", "currentTier", "currentRank", "maxOutputTokens",
            "editorialProfile", "minimumUnit", "reason", "updatedAt",
            "processingWindowSeconds", "nearWindowSeconds", "firstProgressGraceSeconds",
            "stallAfterSeconds", "finalizationGraceSeconds",
        ]);
        string algorithmVersion = ReadIdentifier(value.GetProperty("algorithmVersion"), 64);
        string currentTier = ReadIdentifier(value.GetProperty("currentTier"), 32);
        int currentRank = ReadBoundedInt32(value.GetProperty("currentRank"), 0, 15);
        int maxOutputTokens = ReadBoundedInt32(value.GetProperty("maxOutputTokens"), 1, 4_096);
        string editorialProfile = ReadIdentifier(value.GetProperty("editorialProfile"), 64);
        JsonElement minimumUnitValue = value.GetProperty("minimumUnit");
        if (algorithmVersion != "hch-adaptive-work-v1"
            || !IsTierIdentifier(currentTier)
            || minimumUnitValue.ValueKind is not (JsonValueKind.True or JsonValueKind.False))
        {
            throw Invalid("node-heartbeat-response-invalid");
        }

        bool minimumUnit = minimumUnitValue.GetBoolean();
        string reason = ReadIdentifier(value.GetProperty("reason"), 64);
        if (minimumUnit != (currentRank == 0)
            || reason is not ("attestation-reset" or "minimum-unit-window-ignored"
                or "within-window" or "near-window-downshift" or "already-downshifted"))
        {
            throw Invalid("node-heartbeat-response-invalid");
        }

        DateTimeOffset updatedAt;
        try
        {
            updatedAt = ProtocolTime.ParseTimestamp(
                ReadString(value.GetProperty("updatedAt")),
                "workSizing.updatedAt");
        }
        catch (ProtocolValidationException)
        {
            throw Invalid("node-heartbeat-response-invalid");
        }
        int processingWindowSeconds = ReadBoundedInt32(
            value.GetProperty("processingWindowSeconds"), 60, 86_400);
        int nearWindowSeconds = ReadBoundedInt32(
            value.GetProperty("nearWindowSeconds"), 1, processingWindowSeconds);
        int firstProgressGraceSeconds = ReadBoundedInt32(
            value.GetProperty("firstProgressGraceSeconds"), 30, processingWindowSeconds);
        int stallAfterSeconds = ReadBoundedInt32(
            value.GetProperty("stallAfterSeconds"), 30, processingWindowSeconds);
        int finalizationGraceSeconds = ReadBoundedInt32(
            value.GetProperty("finalizationGraceSeconds"), 30, processingWindowSeconds);
        return new(
            algorithmVersion,
            currentTier,
            currentRank,
            maxOutputTokens,
            editorialProfile,
            minimumUnit,
            reason,
            updatedAt,
            processingWindowSeconds,
            nearWindowSeconds,
            firstProgressGraceSeconds,
            stallAfterSeconds,
            finalizationGraceSeconds);
    }

    private static ValidatedNodeHeartbeatClaim ReadClaim(JsonElement value)
    {
        RequireExactProperties(value, ["allowed", "recommendedCount", "reason"]);
        JsonElement allowedValue = value.GetProperty("allowed");
        if (allowedValue.ValueKind is not (JsonValueKind.True or JsonValueKind.False))
        {
            throw Invalid("node-heartbeat-response-invalid");
        }

        string reason = ReadIdentifier(value.GetProperty("reason"), 160);
        if (reason is not ("fleet-claims-disabled" or "capacity-zero"
            or "no-claimable-work" or "claim-recommended"))
        {
            throw Invalid("node-heartbeat-response-invalid");
        }

        return new(
            allowedValue.GetBoolean(),
            ReadBoundedInt32(value.GetProperty("recommendedCount"), 0, 32),
            reason);
    }

    private static void RequireExactProperties(JsonElement value, IReadOnlyList<string> expected)
    {
        if (value.ValueKind != JsonValueKind.Object)
        {
            throw Invalid("node-heartbeat-response-invalid");
        }

        var expectedNames = new HashSet<string>(expected, StringComparer.Ordinal);
        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (JsonProperty property in value.EnumerateObject())
        {
            if (!expectedNames.Contains(property.Name) || !seen.Add(property.Name))
            {
                throw Invalid("node-heartbeat-response-invalid");
            }
        }

        if (seen.Count != expected.Count)
        {
            throw Invalid("node-heartbeat-response-invalid");
        }
    }

    private static long ReadSafeCounter(JsonElement value)
    {
        const long maximumSafeInteger = 9_007_199_254_740_991;
        if (value.ValueKind != JsonValueKind.Number
            || !value.TryGetInt64(out long result)
            || result is < 0 or > maximumSafeInteger)
        {
            throw Invalid("node-heartbeat-response-invalid");
        }

        return result;
    }

    private static int ReadBoundedInt32(JsonElement value, int minimum, int maximum)
    {
        if (value.ValueKind != JsonValueKind.Number
            || !value.TryGetInt32(out int result)
            || result < minimum || result > maximum)
        {
            throw Invalid("node-heartbeat-response-invalid");
        }

        return result;
    }

    private static string ReadIdentifier(JsonElement value, int maximum)
    {
        string result = ReadString(value);
        if (result.Length is < 1 || result.Length > maximum
            || result.Any(static character => character is <= ' ' or '\x7f'))
        {
            throw Invalid("node-heartbeat-response-invalid");
        }

        return result;
    }

    private static string ReadString(JsonElement value)
    {
        if (value.ValueKind != JsonValueKind.String || value.GetString() is not { } result)
        {
            throw Invalid("node-heartbeat-response-invalid");
        }

        return result;
    }

    private static bool IsBoundedText(string value, int maximum)
    {
        if (string.IsNullOrWhiteSpace(value) || value.Length > maximum)
        {
            return false;
        }

        return !value.Any(static character => character is '\0'
            or (>= '\x01' and <= '\x08')
            or '\x0b' or '\x0c'
            or (>= '\x0e' and <= '\x1f')
            or '\x7f');
    }

    private static bool IsTierIdentifier(string value)
    {
        if (value.Length is < 1 or > 32 || value[0] is < 'a' or > 'z')
        {
            return false;
        }

        for (int index = 1; index < value.Length; index++)
        {
            char character = value[index];
            if (character is not (>= 'a' and <= 'z')
                && character is not (>= '0' and <= '9')
                && character != '-')
            {
                return false;
            }
        }

        return true;
    }

    private static bool UpdateIsValid(WorkerUpdateAvailability value)
    {
        if (value is null
            || !value.InstalledWorkerVersion.Equals(WorkerInstalledVersion.Current, StringComparison.Ordinal)
            || !SemanticVersion.TryParse(value.InstalledWorkerVersion, out var installed)
            || !SemanticVersion.TryParse(value.LatestAvailableWorkerVersion, out var latest)
            || installed.Prerelease is not null || installed.Build is not null
            || latest.Prerelease is not null || latest.Build is not null
            || value.UpdateAvailable != (installed.CompareTo(latest) < 0)
            || value.UpdateMode is not ("mandatory" or "advisory")
            || value.ContentImpact is not ("none" or "generated-content"))
        {
            return false;
        }

        return value.Compatible
            ? value.ContentImpact == "none" && value.UpdateMode == "advisory"
            : value.ContentImpact == "generated-content" && value.UpdateMode == "mandatory";
    }

    public static void Validate(CompleteAssignmentResponse value, WorkerAssignment assignment)
    {
        if (value.AssignmentId != assignment.AssignmentId
            || value.GenerationPlanHash != assignment.GenerationPlanHash
            || !value.CommitAccepted || value.Status != "pending-review"
            || value.AutomaticApproval || value.AutomaticPublication)
        {
            throw Invalid("complete-response-invalid");
        }

        _ = ProtocolTime.ParseTimestamp(value.ServerTime, "serverTime");
    }

    public static void Validate(FailAssignmentResponse value, WorkerAssignment assignment)
    {
        if (value.AssignmentId != assignment.AssignmentId
            || value.GenerationPlanHash != assignment.GenerationPlanHash
            || value.Status != "failed-attempt")
        {
            throw Invalid("fail-response-invalid");
        }

        _ = ProtocolTime.ParseTimestamp(value.ServerTime, "serverTime");
    }

    private static WorkerServiceException Invalid(string code) =>
        new(code, "The orchestrator returned an invalid or uncorrelated response.");
}
