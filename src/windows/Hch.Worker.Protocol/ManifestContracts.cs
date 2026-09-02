using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;

namespace Hch.Worker.Protocol;

/// <summary>Signed HCH manifest payload schema 2.0.</summary>
public sealed class ManifestPayload
{
    [JsonRequired]
    public required string SchemaVersion { get; init; }

    [JsonRequired]
    public required string BootstrapVersion { get; init; }

    [JsonRequired]
    public required long Sequence { get; init; }

    [JsonRequired]
    public required string ReleaseId { get; init; }

    [JsonRequired]
    public required string IssuedAt { get; init; }

    [JsonRequired]
    public required string ExpiresAt { get; init; }

    [JsonRequired]
    public required long MinimumAcceptedSequence { get; init; }

    public string? PreviousManifestHash { get; init; }

    [JsonRequired]
    public required WorkerRuntimeManifest Runtime { get; init; }

    public ManifestCompatibility? Compatibility { get; init; }

    [JsonRequired]
    public required EngineManifest Engine { get; init; }

    [JsonRequired]
    public required JsonElement Generation { get; init; }

    [JsonRequired]
    public required JsonElement CapacityPolicy { get; init; }

    public JsonElement? AdaptiveWorkPolicy { get; init; }

    [JsonRequired]
    public required EditorialManifest Editorial { get; init; }

    [JsonRequired]
    public required JsonElement Actions { get; init; }

    [JsonRequired]
    public required JsonElement RootActionCapabilities { get; init; }

    [JsonRequired]
    public required JsonElement Artifacts { get; init; }

    [JsonRequired]
    public required JsonElement Endpoints { get; init; }

    [JsonRequired]
    public required JsonElement Security { get; init; }

    [JsonRequired]
    public required JsonElement Safety { get; init; }

    [JsonRequired]
    public required string HashAlgorithm { get; init; }

    [JsonRequired]
    public required string Hash { get; init; }

    [JsonExtensionData]
    public IDictionary<string, JsonElement>? AdditionalProperties { get; init; }
}

public sealed class WorkerRuntimeManifest
{
    [JsonRequired]
    public required string WorkerVersion { get; init; }

    public IReadOnlyList<string>? SupportedPlatforms { get; init; }

    [JsonExtensionData]
    public IDictionary<string, JsonElement>? AdditionalProperties { get; init; }
}

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed class ManifestCompatibility
{
    [JsonRequired]
    public required string Classification { get; init; }

    [JsonRequired]
    public required string ContentContractHash { get; init; }

    [JsonRequired]
    public required string? PreviousContentContractHash { get; init; }

    [JsonRequired]
    public required string MinimumWorkerVersion { get; init; }

    [JsonRequired]
    public required string TestedThroughWorkerVersion { get; init; }

    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public IReadOnlyList<string>? AcceptedWorkerVersions { get; init; }

    [JsonRequired]
    public required string ContentImpact { get; init; }
}

public sealed class EngineManifest
{
    [JsonRequired]
    public required string Provider { get; init; }

    [JsonRequired]
    public required string Adapter { get; init; }

    [JsonRequired]
    public required string AdapterVersion { get; init; }

    [JsonRequired]
    public required string Model { get; init; }

    [JsonRequired]
    public required string ModelDigest { get; init; }

    [JsonRequired]
    public required string Protocol { get; init; }

    [JsonExtensionData]
    public IDictionary<string, JsonElement>? AdditionalProperties { get; init; }
}

public sealed class EditorialManifest
{
    [JsonRequired]
    public required string PipelineVersion { get; init; }

    [JsonRequired]
    public required string PolicyHash { get; init; }

    [JsonRequired]
    public required string PromptConfigHash { get; init; }

    [JsonExtensionData]
    public IDictionary<string, JsonElement>? AdditionalProperties { get; init; }
}

public enum ManifestRuntimeDisposition
{
    Continue,
    UpdateAvailableContinue,
    WorkerVersionUntestedContinue,
    MinimumWorkerVersionNotMet,
    WorkerVersionNotAccepted,
    GeneratedContentIncompatible,
}

public sealed record ManifestCompatibilityEvaluation(
    ManifestRuntimeDisposition Disposition,
    bool MayClaim,
    bool UpdateAvailable,
    string Reason);

/// <summary>Validates manifest invariants and the signed content projection.</summary>
public static class ManifestContractValidator
{
    private static readonly HashSet<string> BootstrapVersions =
        ["2.0.0", "2.1.0", "2.2.0", "2.3.0", "3.0.0"];

    public static void Validate(ManifestPayload manifest)
    {
        ArgumentNullException.ThrowIfNull(manifest);
        if (!manifest.SchemaVersion.Equals("2.0", StringComparison.Ordinal)
            || !BootstrapVersions.Contains(manifest.BootstrapVersion))
        {
            throw Invalid("manifest-version-invalid", "The manifest schema/bootstrap version is unsupported.");
        }

        if (manifest.Sequence < 1 || manifest.MinimumAcceptedSequence < 1
            || manifest.MinimumAcceptedSequence > manifest.Sequence)
        {
            throw Invalid("manifest-sequence-invalid", "The manifest sequence bounds are invalid.");
        }

        RequireIdentifier(manifest.ReleaseId, "releaseId", 160);
        var issuedAt = ProtocolTime.ParseTimestamp(manifest.IssuedAt, "issuedAt");
        var expiresAt = ProtocolTime.ParseTimestamp(manifest.ExpiresAt, "expiresAt");
        if (expiresAt <= issuedAt)
        {
            throw Invalid("manifest-window-invalid", "expiresAt must be after issuedAt.");
        }

        if (manifest.PreviousManifestHash is not null && !HchDigest.IsLowerSha256(manifest.PreviousManifestHash))
        {
            throw Invalid("manifest-previous-hash-invalid", "previousManifestHash must be lowercase SHA-256.");
        }

        if (!manifest.HashAlgorithm.Equals("sha256", StringComparison.Ordinal)
            || !HchDigest.IsLowerSha256(manifest.Hash))
        {
            throw Invalid("manifest-hash-invalid", "The manifest hash declaration is invalid.");
        }

        _ = SemanticVersion.Parse(manifest.Runtime.WorkerVersion);
        if (manifest.Runtime.SupportedPlatforms?.Any(platform =>
                platform is not ("linux" or "macos" or "windows")) == true)
        {
            throw Invalid("manifest-platform-invalid", "The manifest contains an unsupported platform.");
        }

        RequireIdentifier(manifest.Engine.Provider, "engine.provider", 160);
        RequireIdentifier(manifest.Engine.Adapter, "engine.adapter", 160);
        RequireIdentifier(manifest.Engine.AdapterVersion, "engine.adapterVersion", 160);
        RequireIdentifier(manifest.Engine.Model, "engine.model", 256);
        RequireIdentifier(manifest.Engine.Protocol, "engine.protocol", 160);
        if (!HchDigest.IsLowerSha256(StripSha256Prefix(manifest.Engine.ModelDigest)))
        {
            throw Invalid("manifest-model-digest-invalid", "engine.modelDigest must be SHA-256.");
        }

        if (!HchDigest.IsLowerSha256(manifest.Editorial.PolicyHash)
            || !HchDigest.IsLowerSha256(manifest.Editorial.PromptConfigHash))
        {
            throw Invalid("manifest-editorial-hash-invalid", "Editorial hashes must be lowercase SHA-256.");
        }

        RequireJsonKind(manifest.Generation, JsonValueKind.Object, "generation");
        RequireJsonKind(manifest.CapacityPolicy, JsonValueKind.Object, "capacityPolicy");
        RequireJsonKind(manifest.Artifacts, JsonValueKind.Array, "artifacts");
        RequireJsonKind(manifest.Actions, JsonValueKind.Array, "actions");
        RequireJsonKind(manifest.RootActionCapabilities, JsonValueKind.Array, "rootActionCapabilities");
        RequireJsonKind(manifest.Endpoints, JsonValueKind.Object, "endpoints");
        RequireJsonKind(manifest.Security, JsonValueKind.Object, "security");
        RequireJsonKind(manifest.Safety, JsonValueKind.Object, "safety");
        if (manifest.AdaptiveWorkPolicy is { } policy)
        {
            RequireJsonKind(policy, JsonValueKind.Object, "adaptiveWorkPolicy");
        }

        if (manifest.BootstrapVersion.Equals("2.3.0", StringComparison.Ordinal)
            && manifest.Compatibility is null)
        {
            throw Invalid(
                "manifest-compatibility-missing",
                "Manifest bootstrap 2.3.0 requires a content compatibility declaration.");
        }

        if (manifest.Compatibility is not null)
        {
            ValidateCompatibility(manifest.Compatibility);
            var calculated = ManifestContentContract.ComputeHash(manifest);
            if (!calculated.Equals(manifest.Compatibility.ContentContractHash, StringComparison.Ordinal))
            {
                throw Invalid(
                    "manifest-content-contract-hash-mismatch",
                    "The declared content contract hash does not match the signed manifest.");
            }
        }
    }

    public static ManifestCompatibilityEvaluation Evaluate(
        ManifestPayload manifest,
        string installedWorkerVersion)
    {
        Validate(manifest);
        var installed = SemanticVersion.Parse(installedWorkerVersion);
        var available = SemanticVersion.Parse(manifest.Runtime.WorkerVersion);
        var updateAvailable = installed.CompareTo(available) < 0;
        var compatibility = manifest.Compatibility;
        if (compatibility is null)
        {
            return new ManifestCompatibilityEvaluation(
                updateAvailable ? ManifestRuntimeDisposition.UpdateAvailableContinue : ManifestRuntimeDisposition.Continue,
                MayClaim: true,
                updateAvailable,
                updateAvailable ? "new-version-available" : "compatible-legacy-manifest");
        }

        var minimum = SemanticVersion.Parse(compatibility.MinimumWorkerVersion);
        var testedThrough = SemanticVersion.Parse(compatibility.TestedThroughWorkerVersion);
        if (compatibility.AcceptedWorkerVersions is { Count: > 0 } accepted
            && !accepted.Contains(installedWorkerVersion, StringComparer.Ordinal))
        {
            return new ManifestCompatibilityEvaluation(
                ManifestRuntimeDisposition.WorkerVersionNotAccepted,
                MayClaim: false,
                updateAvailable,
                "worker-version-not-accepted");
        }

        if (installed.CompareTo(minimum) < 0)
        {
            return new ManifestCompatibilityEvaluation(
                ManifestRuntimeDisposition.MinimumWorkerVersionNotMet,
                MayClaim: false,
                updateAvailable,
                "minimum-worker-version-not-met");
        }

        if (compatibility.Classification.Equals("content-incompatible", StringComparison.Ordinal))
        {
            return new ManifestCompatibilityEvaluation(
                ManifestRuntimeDisposition.GeneratedContentIncompatible,
                MayClaim: false,
                updateAvailable,
                "generated-content-contract-incompatible");
        }

        if (installed.CompareTo(testedThrough) > 0)
        {
            return new ManifestCompatibilityEvaluation(
                ManifestRuntimeDisposition.WorkerVersionUntestedContinue,
                MayClaim: true,
                updateAvailable,
                "worker-version-newer-than-tested-range");
        }

        return new ManifestCompatibilityEvaluation(
            updateAvailable ? ManifestRuntimeDisposition.UpdateAvailableContinue : ManifestRuntimeDisposition.Continue,
            MayClaim: true,
            updateAvailable,
            updateAvailable ? "new-version-available" : "compatible");
    }

    private static void ValidateCompatibility(ManifestCompatibility compatibility)
    {
        if (compatibility.Classification is not ("initial" or "compatible" or "content-incompatible")
            || compatibility.ContentImpact is not ("none" or "generated-content")
            || !HchDigest.IsLowerSha256(compatibility.ContentContractHash)
            || (compatibility.PreviousContentContractHash is not null
                && !HchDigest.IsLowerSha256(compatibility.PreviousContentContractHash)))
        {
            throw Invalid("manifest-compatibility-invalid", "The manifest compatibility declaration is invalid.");
        }

        var minimum = SemanticVersion.Parse(compatibility.MinimumWorkerVersion);
        var tested = SemanticVersion.Parse(compatibility.TestedThroughWorkerVersion);
        if (compatibility.AcceptedWorkerVersions is { } accepted)
        {
            if (accepted.Count > 64
                || accepted.Distinct(StringComparer.Ordinal).Count() != accepted.Count)
            {
                throw Invalid(
                    "manifest-compatibility-invalid",
                    "The accepted worker version list is duplicated or exceeds its bound.");
            }

            foreach (var version in accepted)
            {
                _ = SemanticVersion.Parse(version);
            }
        }

        if (minimum.CompareTo(tested) > 0)
        {
            throw Invalid("manifest-compatibility-invalid", "The compatibility version range is inverted.");
        }

        var relationshipIsValid = compatibility.Classification switch
        {
            "initial" => compatibility.PreviousContentContractHash is null
                && compatibility.ContentImpact.Equals("none", StringComparison.Ordinal),
            "compatible" => compatibility.PreviousContentContractHash is not null
                && compatibility.PreviousContentContractHash.Equals(compatibility.ContentContractHash, StringComparison.Ordinal)
                && compatibility.ContentImpact.Equals("none", StringComparison.Ordinal),
            "content-incompatible" => compatibility.PreviousContentContractHash is not null
                && !compatibility.PreviousContentContractHash.Equals(compatibility.ContentContractHash, StringComparison.Ordinal)
                && compatibility.ContentImpact.Equals("generated-content", StringComparison.Ordinal),
            _ => false,
        };
        if (!relationshipIsValid)
        {
            throw Invalid("manifest-compatibility-invalid", "The compatibility classification contradicts its hashes or impact.");
        }
    }

    private static string StripSha256Prefix(string value) =>
        value.StartsWith("sha256:", StringComparison.Ordinal) ? value[7..] : value;

    private static void RequireJsonKind(JsonElement value, JsonValueKind expected, string name)
    {
        if (value.ValueKind != expected)
        {
            throw Invalid("manifest-field-invalid", $"{name} must be a JSON {expected}.");
        }
    }

    private static void RequireIdentifier(string value, string name, int maximum)
    {
        if (string.IsNullOrWhiteSpace(value) || value.Length > maximum
            || value.Any(character => char.IsWhiteSpace(character) || char.IsControl(character)))
        {
            throw Invalid("manifest-identifier-invalid", $"{name} is invalid.");
        }
    }

    private static ProtocolValidationException Invalid(string code, string message) => new(code, message);
}

/// <summary>The exact generated-content projection shared with the orchestrator.</summary>
public static class ManifestContentContract
{
    public static string ComputeCanonicalJson(ManifestPayload manifest)
    {
        ArgumentNullException.ThrowIfNull(manifest);
        var projection = new JsonObject
        {
            ["adaptiveWorkPolicy"] = Clone(manifest.AdaptiveWorkPolicy),
            ["artifacts"] = Clone(manifest.Artifacts),
            ["editorial"] = new JsonObject
            {
                ["pipelineVersion"] = manifest.Editorial.PipelineVersion,
                ["policyHash"] = manifest.Editorial.PolicyHash,
                ["promptConfigHash"] = manifest.Editorial.PromptConfigHash,
            },
            ["engine"] = new JsonObject
            {
                ["adapter"] = manifest.Engine.Adapter,
                ["adapterVersion"] = manifest.Engine.AdapterVersion,
                ["model"] = manifest.Engine.Model,
                ["modelDigest"] = manifest.Engine.ModelDigest,
                ["protocol"] = manifest.Engine.Protocol,
                ["provider"] = manifest.Engine.Provider,
            },
            ["generation"] = Clone(manifest.Generation),
        };
        return JcsCanonicalizer.Canonicalize(projection.ToJsonString(ProtocolJson.SerializerOptions));
    }

    public static string ComputeHash(ManifestPayload manifest) =>
        HchDigest.Sha256Hex(ComputeCanonicalJson(manifest));

    private static JsonNode? Clone(JsonElement? element)
    {
        if (element is null || element.Value.ValueKind is JsonValueKind.Null or JsonValueKind.Undefined)
        {
            return null;
        }

        return JsonNode.Parse(element.Value.GetRawText());
    }
}
