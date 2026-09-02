using System.Text.Json;
using System.Text.Json.Serialization;

namespace Hch.Worker.Protocol;

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed class BootstrapRequestContract
{
    [JsonRequired]
    public required string NodeId { get; init; }

    [JsonRequired]
    public required string WorkerKeyId { get; init; }

    [JsonRequired]
    public required string Platform { get; init; }

    [JsonRequired]
    public required string Architecture { get; init; }

    [JsonRequired]
    public required string Hostname { get; init; }

    [JsonRequired]
    public required int RequestedCapacity { get; init; }
}

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed class BootstrapResponseContract
{
    [JsonRequired]
    public required string BootstrapSessionId { get; init; }

    [JsonRequired]
    public required string State { get; init; }

    [JsonRequired]
    public required string ExpiresAt { get; init; }

    [JsonRequired]
    public required string Challenge { get; init; }

    [JsonRequired]
    public required long ManifestSequence { get; init; }

    [JsonRequired]
    public required string ManifestHash { get; init; }

    [JsonRequired]
    public required ManifestDelivery Manifest { get; init; }

    [JsonRequired]
    public required int RequestedCapacity { get; init; }

    [JsonRequired]
    public required JsonElement CapacityPolicy { get; init; }

    [JsonRequired]
    public required JsonElement AdaptiveWorkPolicy { get; init; }

    [JsonRequired]
    public required string AttestationUrl { get; init; }

    [JsonRequired]
    public required bool WorkEnabled { get; init; }
}

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed class AttestationChecksContract
{
    [JsonRequired]
    public required bool ConfigurationApplied { get; init; }

    [JsonRequired]
    public required bool ArtifactsVerified { get; init; }

    [JsonRequired]
    public required bool ModelAvailable { get; init; }

    [JsonRequired]
    public required bool GeneratorReachable { get; init; }

    [JsonRequired]
    public required bool SelfTestPassed { get; init; }
}

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed class UpdateReceiptContract
{
    [JsonRequired]
    public required string? PreviousManifestHash { get; init; }

    [JsonRequired]
    public required string TargetManifestHash { get; init; }

    [JsonRequired]
    public required IReadOnlyDictionary<string, string> ArtifactHashes { get; init; }

    [JsonRequired]
    public required string Result { get; init; }

    [JsonRequired]
    public required bool RollbackPerformed { get; init; }

    [JsonRequired]
    public required string AppliedAt { get; init; }

    [JsonRequired]
    public required string ReceiptHash { get; init; }

    [JsonRequired]
    public required string LocalAuditHash { get; init; }
}

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed class AttestationRequestContract
{
    [JsonRequired]
    public required string NodeId { get; init; }

    [JsonRequired]
    public required string WorkerKeyId { get; init; }

    [JsonRequired]
    public required long ManifestSequence { get; init; }

    [JsonRequired]
    public required string ManifestHash { get; init; }

    [JsonRequired]
    public required string ContentContractHash { get; init; }

    [JsonRequired]
    public required string Challenge { get; init; }

    [JsonRequired]
    public required string WorkerRuntimeVersion { get; init; }

    [JsonRequired]
    public required string PolicyHash { get; init; }

    [JsonRequired]
    public required string AdaptiveWorkPolicyHash { get; init; }

    [JsonRequired]
    public required string RootKeyId { get; init; }

    [JsonRequired]
    public required string ReleaseKeyId { get; init; }

    [JsonRequired]
    public required string TrustVerifiedAt { get; init; }

    [JsonRequired]
    public required string PromptConfigHash { get; init; }

    [JsonRequired]
    public required string PipelineVersion { get; init; }

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
    public required AttestationChecksContract Checks { get; init; }

    [JsonRequired]
    public required UpdateReceiptContract UpdateReceipt { get; init; }
}

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed class AttestedCapacityGrantContract
{
    [JsonRequired]
    public required int RequestedCapacity { get; init; }

    [JsonRequired]
    public required int GrantedCapacity { get; init; }

    [JsonRequired]
    public required string CapacityClass { get; init; }

    [JsonRequired]
    public required string Reason { get; init; }

    [JsonRequired]
    public required string GrantedUntil { get; init; }
}

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed class AttestationResponseContract
{
    [JsonRequired]
    public required string NodeId { get; init; }

    [JsonRequired]
    public required string WorkerKeyId { get; init; }

    [JsonRequired]
    public required bool Compatible { get; init; }

    [JsonRequired]
    public required string State { get; init; }

    [JsonRequired]
    public required long ManifestSequence { get; init; }

    [JsonRequired]
    public required string ManifestHash { get; init; }

    [JsonRequired]
    public required string ContentContractHash { get; init; }

    [JsonRequired]
    public required string? ReadyUntil { get; init; }

    [JsonRequired]
    public required AttestedCapacityGrantContract Capacity { get; init; }

    [JsonRequired]
    public required JsonElement Update { get; init; }

    [JsonRequired]
    public required string ServerTime { get; init; }
}
