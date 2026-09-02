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
            || value.Capacity.GrantedCapacity is < 0 or > 64
            || value.Capacity.GrantedCapacity > requested
            || value.Capacity.GrantedCapacity > value.Capacity.ConfiguredCapacity
            || value.Capacity.AvailableSlots is < 0 or > 64
            || value.Capacity.AvailableSlots > value.Capacity.GrantedCapacity
            || value.Capacity.ActiveAssignments < 0
            || string.IsNullOrWhiteSpace(value.Capacity.CapacityClass)
            || string.IsNullOrWhiteSpace(value.Capacity.Reason)
            || value.Workload.ValueKind != JsonValueKind.Object
            || value.WorkSizing.ValueKind != JsonValueKind.Object
            || value.Claim.ValueKind != JsonValueKind.Object
            || !UpdateIsValid(value.Update))
        {
            throw Invalid("node-heartbeat-response-invalid");
        }

        _ = ProtocolTime.ParseTimestamp(value.HeartbeatAt, "heartbeatAt");
        _ = ProtocolTime.ParseTimestamp(value.ServerTime, "serverTime");
        if (value.Capacity.GrantedUntil is not null)
        {
            _ = ProtocolTime.ParseTimestamp(value.Capacity.GrantedUntil, "grantedUntil");
        }
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

        return value.Compatible || value.UpdateMode == "mandatory";
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
