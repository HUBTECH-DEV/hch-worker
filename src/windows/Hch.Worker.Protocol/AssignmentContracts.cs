using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;

namespace Hch.Worker.Protocol;

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed class WorkerAssignment
{
    [JsonRequired]
    public required string AssignmentId { get; init; }

    [JsonRequired]
    public required string LeaseToken { get; init; }

    [JsonRequired]
    public required string LeaseExpiresAt { get; init; }

    [JsonRequired]
    public required string Status { get; init; }

    [JsonRequired]
    public required string InputSnapshotHash { get; init; }

    [JsonRequired]
    public required JsonElement Entry { get; init; }

    [JsonRequired]
    public required WorkerRuntimeProfile RuntimeProfile { get; init; }

    [JsonRequired]
    public required GenerationPlan GenerationPlan { get; init; }

    [JsonRequired]
    public required string GenerationPlanHash { get; init; }
}

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed class GenerationPlan
{
    [JsonRequired]
    public required string AlgorithmVersion { get; init; }

    [JsonRequired]
    public required string TierId { get; init; }

    [JsonRequired]
    public required int TierRank { get; init; }

    [JsonRequired]
    public required int MaxOutputTokens { get; init; }

    [JsonRequired]
    public required string EditorialProfile { get; init; }

    [JsonRequired]
    public required bool MinimumUnit { get; init; }

    [JsonRequired]
    public required int ProcessingWindowSeconds { get; init; }

    [JsonRequired]
    public required int NearWindowSeconds { get; init; }

    [JsonRequired]
    public required int FirstProgressGraceSeconds { get; init; }

    [JsonRequired]
    public required int StallAfterSeconds { get; init; }

    [JsonRequired]
    public required int FinalizationGraceSeconds { get; init; }

    [JsonRequired]
    public required string PolicyHash { get; init; }
}

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed class WorkerRuntimeProfile
{
    [JsonRequired]
    public required string Provider { get; init; }

    [JsonRequired]
    public required string EngineAdapter { get; init; }

    [JsonRequired]
    public required string EngineAdapterVersion { get; init; }

    [JsonRequired]
    public required string Model { get; init; }

    [JsonRequired]
    public required string ModelDigest { get; init; }

    [JsonRequired]
    public required string Protocol { get; init; }

    [JsonRequired]
    public required double Temperature { get; init; }

    [JsonRequired]
    public required int ContextWindow { get; init; }

    [JsonRequired]
    public required int MaxOutputTokens { get; init; }

    [JsonRequired]
    public required string PolicyId { get; init; }

    [JsonRequired]
    public required string PolicyVersion { get; init; }

    [JsonRequired]
    public required string PolicyHash { get; init; }

    [JsonRequired]
    public required string PromptConfigHash { get; init; }

    [JsonRequired]
    public required string PipelineVersion { get; init; }

    [JsonRequired]
    public required long ManifestSequence { get; init; }

    [JsonRequired]
    public required string ManifestHash { get; init; }

    [JsonRequired]
    public required string RuntimeProfileHash { get; init; }
}

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed class AssignmentProgress
{
    [JsonRequired]
    public required string Phase { get; init; }

    [JsonRequired]
    public required int Attempt { get; init; }

    [JsonRequired]
    public required long Sequence { get; init; }

    [JsonRequired]
    public required long ContentBytes { get; init; }
}

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed class AssignmentProgressSnapshot
{
    [JsonRequired]
    public required string AssignmentId { get; init; }

    [JsonRequired]
    public required string GenerationPlanHash { get; init; }

    [JsonRequired]
    public required string Phase { get; init; }

    [JsonRequired]
    public required int Attempt { get; init; }

    [JsonRequired]
    public required long Sequence { get; init; }

    [JsonRequired]
    public required long ContentBytes { get; init; }

    [JsonRequired]
    public required string UpdatedAt { get; init; }
}

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed class AssignmentHeartbeatRequest
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
    public required AssignmentProgress Progress { get; init; }
}

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed class AssignmentHeartbeatResponse
{
    [JsonRequired]
    public required string AssignmentId { get; init; }

    [JsonRequired]
    public required string GenerationPlanHash { get; init; }

    [JsonRequired]
    public required string LeaseExpiresAt { get; init; }

    [JsonRequired]
    public required AssignmentLiveness Liveness { get; init; }

    [JsonRequired]
    public required AssignmentWorkSizing WorkSizing { get; init; }

    [JsonRequired]
    public required string ServerTime { get; init; }
}

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed class AssignmentLiveness
{
    [JsonRequired]
    public required string State { get; init; }

    [JsonRequired]
    public required string? LastProgressAt { get; init; }

    [JsonRequired]
    public required int StaleAfterSeconds { get; init; }
}

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed class AssignmentWorkSizing
{
    [JsonRequired]
    public required string CurrentTier { get; init; }

    [JsonRequired]
    public required int CurrentRank { get; init; }

    [JsonRequired]
    public required string Reason { get; init; }
}

/// <summary>Strict assignment, progress, lease and stall-timer validation.</summary>
public static partial class AssignmentContractValidator
{
    public const int MaximumProgressAttempts = 8;
    public const long MaximumProgressCounter = 4_000_000;

    private static readonly HashSet<string> EditorialProfiles =
    [
        "EDITORIAL_LONG_FORM",
        "EDITORIAL_COMPACT",
        "EDITORIAL_MINIMUM",
        "CATALOG_SUMMARY",
        "EVENT_LISTING",
    ];

    private static readonly HashSet<string> WorkSizingReasons =
    [
        "minimum-unit-window-ignored",
        "within-window",
        "near-window-downshift",
        "already-downshifted",
    ];

    public static void Validate(WorkerAssignment assignment, DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(assignment);
        ValidateAssignmentId(assignment.AssignmentId);
        if (assignment.LeaseToken.Length < 16 || assignment.LeaseToken.Length > 4096
            || assignment.LeaseToken.Any(char.IsControl))
        {
            throw Invalid("assignment-lease-token-invalid", "The assignment lease token is invalid.");
        }

        var leaseExpiresAt = ProtocolTime.ParseTimestamp(assignment.LeaseExpiresAt, "leaseExpiresAt");
        if (leaseExpiresAt <= now)
        {
            throw Invalid("assignment-integrity-lease-expired", "The assignment lease has expired.");
        }

        if (!assignment.Status.Equals("processing", StringComparison.Ordinal))
        {
            throw Invalid("assignment-status-invalid", "The claimed assignment must have processing status.");
        }

        RequireHash(assignment.InputSnapshotHash, "inputSnapshotHash");
        RequireHash(assignment.GenerationPlanHash, "generationPlanHash");
        if (assignment.Entry.ValueKind != JsonValueKind.Object)
        {
            throw Invalid("assignment-entry-invalid", "entry must be a JSON object.");
        }

        var calculatedInputHash = HchDigest.Sha256Hex(JcsCanonicalizer.Canonicalize(assignment.Entry));
        if (!calculatedInputHash.Equals(assignment.InputSnapshotHash, StringComparison.Ordinal))
        {
            throw Invalid("assignment-input-snapshot-hash-mismatch", "inputSnapshotHash does not match entry.");
        }

        Validate(assignment.GenerationPlan);
        Validate(assignment.RuntimeProfile);

        var calculatedPlanHash = HchDigest.Sha256Hex(JcsCanonicalizer.Serialize(assignment.GenerationPlan));
        if (!calculatedPlanHash.Equals(assignment.GenerationPlanHash, StringComparison.Ordinal))
        {
            throw Invalid("assignment-generation-plan-hash-mismatch", "generationPlanHash does not match generationPlan.");
        }
    }

    public static void Validate(GenerationPlan plan)
    {
        ArgumentNullException.ThrowIfNull(plan);
        if (!plan.AlgorithmVersion.Equals("hch-adaptive-work-v1", StringComparison.Ordinal)
            || !TierPattern().IsMatch(plan.TierId)
            || plan.TierRank is < 0 or > 15
            || plan.MaxOutputTokens is < 1 or > 32_768
            || !EditorialProfiles.Contains(plan.EditorialProfile))
        {
            throw Invalid("assignment-generation-plan-invalid", "The generation plan is invalid.");
        }

        ValidateTimer(plan.ProcessingWindowSeconds, 60, 86_400, "processingWindowSeconds");
        ValidateTimer(plan.NearWindowSeconds, 1, 86_400, "nearWindowSeconds");
        ValidateTimer(plan.FirstProgressGraceSeconds, 30, 86_400, "firstProgressGraceSeconds");
        ValidateTimer(plan.StallAfterSeconds, 30, 86_400, "stallAfterSeconds");
        ValidateTimer(plan.FinalizationGraceSeconds, 30, 86_400, "finalizationGraceSeconds");
        if (plan.NearWindowSeconds > plan.ProcessingWindowSeconds)
        {
            throw Invalid("assignment-generation-plan-timer-invalid", "nearWindowSeconds cannot exceed the processing window.");
        }

        RequireHash(plan.PolicyHash, "policyHash");
    }

    public static void Validate(WorkerRuntimeProfile profile)
    {
        ArgumentNullException.ThrowIfNull(profile);
        RequireIdentifier(profile.Provider, "provider", 160);
        RequireIdentifier(profile.EngineAdapter, "engineAdapter", 160);
        RequireIdentifier(profile.EngineAdapterVersion, "engineAdapterVersion", 160);
        RequireIdentifier(profile.Model, "model", 256);
        RequireIdentifier(profile.Protocol, "protocol", 160);
        RequireIdentifier(profile.PolicyId, "policyId", 160);
        RequireIdentifier(profile.PolicyVersion, "policyVersion", 160);
        RequireIdentifier(profile.PipelineVersion, "pipelineVersion", 160);
        if (!double.IsFinite(profile.Temperature)
            || profile.ContextWindow < 1
            || profile.MaxOutputTokens < 1
            || profile.ManifestSequence < 1)
        {
            throw Invalid("assignment-runtime-profile-invalid", "The assignment runtime profile is invalid.");
        }

        RequireHash(StripSha256Prefix(profile.ModelDigest), "modelDigest");
        RequireHash(profile.PolicyHash, "policyHash");
        RequireHash(profile.PromptConfigHash, "promptConfigHash");
        RequireHash(profile.ManifestHash, "manifestHash");
        RequireHash(profile.RuntimeProfileHash, "runtimeProfileHash");

        var projection = new Dictionary<string, object?>(StringComparer.Ordinal)
        {
            ["contextWindow"] = profile.ContextWindow,
            ["engineAdapter"] = profile.EngineAdapter,
            ["engineAdapterVersion"] = profile.EngineAdapterVersion,
            ["manifestHash"] = profile.ManifestHash,
            ["manifestSequence"] = profile.ManifestSequence,
            ["maxOutputTokens"] = profile.MaxOutputTokens,
            ["model"] = profile.Model,
            ["modelDigest"] = profile.ModelDigest,
            ["pipelineVersion"] = profile.PipelineVersion,
            ["policyHash"] = profile.PolicyHash,
            ["policyId"] = profile.PolicyId,
            ["policyVersion"] = profile.PolicyVersion,
            ["promptConfigHash"] = profile.PromptConfigHash,
            ["protocol"] = profile.Protocol,
            ["provider"] = profile.Provider,
            ["temperature"] = profile.Temperature,
        };
        var calculatedHash = HchDigest.Sha256Hex(JcsCanonicalizer.Serialize(projection));
        if (!calculatedHash.Equals(profile.RuntimeProfileHash, StringComparison.Ordinal))
        {
            throw Invalid("assignment-runtime-profile-hash-mismatch", "runtimeProfileHash does not match runtimeProfile.");
        }
    }

    public static void Validate(AssignmentProgress progress)
    {
        ArgumentNullException.ThrowIfNull(progress);
        if (progress.Phase is not ("starting" or "responding" or "finalizing")
            || progress.Attempt is < 1 or > MaximumProgressAttempts
            || progress.Sequence is < 0 or > MaximumProgressCounter
            || progress.ContentBytes is < 0 or > MaximumProgressCounter)
        {
            throw Invalid("assignment-progress-value-invalid", "Assignment progress is outside the protocol limits.");
        }

        if (progress.Phase.Equals("starting", StringComparison.Ordinal)
            && progress.Attempt == 1
            && (progress.Sequence != 0 || progress.ContentBytes != 0))
        {
            throw Invalid("assignment-progress-starting-invalid", "Initial starting progress must have zero counters.");
        }

        if (progress.Phase is "responding" or "finalizing"
            && (progress.Sequence < 1 || progress.ContentBytes < 1))
        {
            throw Invalid("assignment-progress-response-empty", "Responding/finalizing progress must report material output.");
        }
    }

    public static void Validate(AssignmentProgressSnapshot progress, DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(progress);
        ValidateAssignmentId(progress.AssignmentId);
        RequireHash(progress.GenerationPlanHash, "generationPlanHash");
        Validate(new AssignmentProgress
        {
            Phase = progress.Phase,
            Attempt = progress.Attempt,
            Sequence = progress.Sequence,
            ContentBytes = progress.ContentBytes,
        });
        if (ProtocolTime.ParseTimestamp(progress.UpdatedAt, "updatedAt") > now.AddMinutes(5))
        {
            throw Invalid("assignment-progress-timestamp-invalid", "Progress cannot be more than five minutes in the future.");
        }
    }

    public static void Validate(AssignmentHeartbeatRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        ValidateAssignmentId(request.AssignmentId);
        RequireIdentifier(request.NodeId, "nodeId", 128);
        if (!WorkerKeyFingerprintPattern().IsMatch(request.WorkerKeyId))
        {
            throw Invalid("worker-key-id-invalid", "workerKeyId must be an Ed25519 SPKI fingerprint.");
        }

        if (request.LeaseToken.Length < 16 || request.LeaseToken.Length > 4096
            || request.LeaseToken.Any(char.IsControl))
        {
            throw Invalid("assignment-lease-token-invalid", "The assignment lease token is invalid.");
        }

        RequireHash(request.GenerationPlanHash, "generationPlanHash");
        Validate(request.Progress);
    }

    public static void Validate(
        AssignmentHeartbeatResponse response,
        WorkerAssignment assignment)
    {
        ArgumentNullException.ThrowIfNull(response);
        ArgumentNullException.ThrowIfNull(assignment);
        if (!response.AssignmentId.Equals(assignment.AssignmentId, StringComparison.Ordinal)
            || !response.GenerationPlanHash.Equals(assignment.GenerationPlanHash, StringComparison.Ordinal))
        {
            throw Invalid("orchestrator-heartbeat-assignment-mismatch", "The heartbeat response targets another assignment or plan.");
        }

        var serverTime = ProtocolTime.ParseTimestamp(response.ServerTime, "serverTime");
        var leaseExpiresAt = ProtocolTime.ParseTimestamp(response.LeaseExpiresAt, "leaseExpiresAt");
        if (leaseExpiresAt <= serverTime)
        {
            throw Invalid("orchestrator-heartbeat-lease-invalid", "The renewed lease does not extend beyond serverTime.");
        }

        if (response.Liveness.State is not ("starting" or "responding" or "finalizing"))
        {
            throw Invalid("orchestrator-heartbeat-liveness-state-invalid", "The orchestrator returned an invalid liveness state.");
        }

        DateTimeOffset? lastProgressAt = response.Liveness.LastProgressAt is null
            ? null
            : ProtocolTime.ParseTimestamp(response.Liveness.LastProgressAt, "lastProgressAt");
        if (lastProgressAt > serverTime)
        {
            throw Invalid("orchestrator-heartbeat-last-progress-invalid", "lastProgressAt cannot be after serverTime.");
        }

        var expectedGrace = response.Liveness.State.Equals("finalizing", StringComparison.Ordinal)
            ? assignment.GenerationPlan.FinalizationGraceSeconds
            : lastProgressAt is not null
                ? assignment.GenerationPlan.StallAfterSeconds
                : assignment.GenerationPlan.FirstProgressGraceSeconds;
        if (response.Liveness.StaleAfterSeconds != expectedGrace)
        {
            throw Invalid("orchestrator-heartbeat-liveness-grace-invalid", "The liveness grace does not match the signed plan.");
        }

        if (!TierPattern().IsMatch(response.WorkSizing.CurrentTier)
            || response.WorkSizing.CurrentRank is < 0 or > 15
            || response.WorkSizing.CurrentRank > assignment.GenerationPlan.TierRank
            || !WorkSizingReasons.Contains(response.WorkSizing.Reason))
        {
            throw Invalid("orchestrator-heartbeat-work-sizing-invalid", "The heartbeat work-sizing decision is invalid.");
        }
    }

    private static void ValidateAssignmentId(string assignmentId)
    {
        if (!Guid.TryParseExact(assignmentId, "D", out var parsed) || parsed == Guid.Empty)
        {
            throw Invalid("assignment-id-invalid", "assignmentId must be a non-empty canonical UUID.");
        }
    }

    private static void ValidateTimer(int value, int minimum, int maximum, string name)
    {
        if (value < minimum || value > maximum)
        {
            throw Invalid("assignment-generation-plan-timer-invalid", $"{name} is outside the allowed range.");
        }
    }

    private static void RequireHash(string value, string name)
    {
        if (!HchDigest.IsLowerSha256(value))
        {
            throw Invalid("assignment-hash-invalid", $"{name} must be lowercase SHA-256.");
        }
    }

    private static void RequireIdentifier(string value, string name, int maximum)
    {
        if (string.IsNullOrWhiteSpace(value) || value.Length > maximum
            || value.Any(character => char.IsWhiteSpace(character) || char.IsControl(character)))
        {
            throw Invalid("assignment-identifier-invalid", $"{name} is invalid.");
        }
    }

    private static string StripSha256Prefix(string value) =>
        value.StartsWith("sha256:", StringComparison.Ordinal) ? value[7..] : value;

    private static ProtocolValidationException Invalid(string code, string message) => new(code, message);

    [GeneratedRegex("^[a-z][a-z0-9-]{0,31}$", RegexOptions.CultureInvariant)]
    private static partial Regex TierPattern();

    [GeneratedRegex("^SHA256:[A-Za-z0-9_-]{43}$", RegexOptions.CultureInvariant)]
    private static partial Regex WorkerKeyFingerprintPattern();
}
