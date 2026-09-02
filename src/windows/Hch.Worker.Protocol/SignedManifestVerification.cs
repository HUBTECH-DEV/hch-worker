using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;

namespace Hch.Worker.Protocol;

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed class JcsSignatureEnvelope
{
    [JsonRequired]
    [JsonPropertyName("protected")]
    public required string Protected { get; init; }

    [JsonRequired]
    public required string Payload { get; init; }

    [JsonRequired]
    public required string Signature { get; init; }
}

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed class ManifestDelivery
{
    [JsonRequired]
    public required JcsSignatureEnvelope Manifest { get; init; }

    [JsonRequired]
    public required JcsSignatureEnvelope Delegation { get; init; }

    [JsonRequired]
    public required string RootKeyId { get; init; }

    [JsonRequired]
    public required string RootPublicKeyFingerprint { get; init; }
}

/// <summary>Explicit, locally provisioned trust pins. This type never performs TOFU.</summary>
public sealed class ManifestTrustPins
{
    private readonly byte[] rootSubjectPublicKeyInfo;

    public ManifestTrustPins(
        string rootKeyId,
        string rootPublicKeyFingerprint,
        ReadOnlySpan<byte> rootSubjectPublicKeyInfo)
    {
        RootKeyId = RequiredIdentifier(rootKeyId, nameof(rootKeyId), 256);
        this.rootSubjectPublicKeyInfo = Ed25519KeyEncoding.NormalizeSubjectPublicKeyInfo(
            rootSubjectPublicKeyInfo);
        RootPublicKeyFingerprint = RequiredIdentifier(
            rootPublicKeyFingerprint,
            nameof(rootPublicKeyFingerprint),
            256);
        var calculated = Ed25519KeyEncoding.Fingerprint(this.rootSubjectPublicKeyInfo);
        if (!FixedTimeTextEquals(calculated, RootPublicKeyFingerprint))
        {
            throw new ProtocolValidationException(
                "root-key-pin-mismatch",
                "The configured root fingerprint does not match the configured root key.");
        }
    }

    public string RootKeyId { get; }

    public string RootPublicKeyFingerprint { get; }

    public byte[] ExportRootSubjectPublicKeyInfo() => rootSubjectPublicKeyInfo.ToArray();

    private static string RequiredIdentifier(string value, string name, int maximum)
    {
        ArgumentNullException.ThrowIfNull(value);
        if (value.Length is < 1 || value.Length > maximum
            || value.Any(character => character <= ' ' || character == '\x7f' || char.IsSurrogate(character)))
        {
            throw new ProtocolValidationException("trust-pin-invalid", $"{name} is invalid.");
        }

        return value;
    }

    internal static bool FixedTimeTextEquals(string left, string right)
    {
        byte[] leftBytes = Encoding.UTF8.GetBytes(left);
        byte[] rightBytes = Encoding.UTF8.GetBytes(right);
        try
        {
            return leftBytes.Length == rightBytes.Length
                && CryptographicOperations.FixedTimeEquals(leftBytes, rightBytes);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(leftBytes);
            CryptographicOperations.ZeroMemory(rightBytes);
        }
    }
}

public sealed record AppliedManifestAnchor(
    int SchemaVersion,
    long ManifestSequence,
    string ManifestHash,
    string? ContentContractHash);

public sealed record DelegationTrustAnchor(
    int SchemaVersion,
    string RootKeyId,
    string RootFingerprint,
    long DelegationSequence,
    string DelegationHash);

public sealed record ManifestArtifactContract(
    string Name,
    string MediaType,
    long Bytes,
    string Sha256,
    string Url,
    string AuthorizationClass);

public sealed record ManifestActionContract(string Type, string AuthorizationClass);

public sealed record VerifiedManifestDelivery(
    ManifestPayload Manifest,
    JsonElement SignedPayload,
    IReadOnlyList<ManifestArtifactContract> Artifacts,
    IReadOnlyList<ManifestActionContract> Actions,
    string RootKeyId,
    string RootFingerprint,
    string ReleaseKeyId,
    string ReleaseFingerprint,
    long DelegationSequence,
    string DelegationHash,
    string ContentContractHash,
    bool ExpiredFallback)
{
    public DelegationTrustAnchor CreateTrustAnchor() => new(
        1,
        RootKeyId,
        RootFingerprint,
        DelegationSequence,
        DelegationHash);
}

/// <summary>
/// Verifies root -&gt; release -&gt; manifest envelopes over canonical RFC 8785
/// bytes and enforces the same anti-rollback rules as the portable worker.
/// </summary>
public static partial class SignedManifestVerifier
{
    public const string ManifestSignatureType = "hch-editorial-manifest/v2";
    public const string DelegationSignatureType = "hch-editorial-release-key-delegation/v1";
    private const string EnvelopeType = "application/hch+jws+jcs";
    private const int DelegationMaximumLifetimeSeconds = 366 * 24 * 60 * 60;

    private static readonly HashSet<string> AllowedActions =
    [
        "verify-artifact",
        "configure-engine",
        "pull-model-by-digest",
        "apply-editorial-policy",
        "self-test",
    ];

    private static readonly HashSet<string> AllowedArtifactFields =
    [
        "name", "mediaType", "bytes", "sha256", "url", "authorizationClass",
    ];

    private static readonly HashSet<string> AllowedActionFields = ["type", "authorizationClass"];

    public static async Task<VerifiedManifestDelivery> VerifyAsync(
        ManifestDelivery delivery,
        ManifestTrustPins pins,
        IEd25519SignatureProvider verifier,
        AppliedManifestAnchor? appliedState = null,
        DelegationTrustAnchor? trustState = null,
        DateTimeOffset? now = null,
        string platform = "windows",
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(delivery);
        ArgumentNullException.ThrowIfNull(pins);
        ArgumentNullException.ThrowIfNull(verifier);
        var comparisonTime = now ?? DateTimeOffset.UtcNow;

        if (!ManifestTrustPins.FixedTimeTextEquals(delivery.RootKeyId, pins.RootKeyId)
            || !ManifestTrustPins.FixedTimeTextEquals(
                delivery.RootPublicKeyFingerprint,
                pins.RootPublicKeyFingerprint))
        {
            throw Invalid(
                "root-key-pin-mismatch",
                "The delivered root identity does not match the explicit local pins.");
        }

        VerifiedCryptographicChain chain;
        var expiredFallback = false;
        try
        {
            chain = await VerifyChainAsync(
                delivery,
                pins,
                verifier,
                comparisonTime,
                allowExpired: false,
                cancellationToken).ConfigureAwait(false);
        }
        catch (ProtocolValidationException error) when (
            error.Code is "manifest-expired" or "delegation-expired")
        {
            if (appliedState is null)
            {
                throw;
            }

            chain = await VerifyChainAsync(
                delivery,
                pins,
                verifier,
                comparisonTime,
                allowExpired: true,
                cancellationToken).ConfigureAwait(false);
            expiredFallback = true;
        }

        ParsedManifest parsed;
        try
        {
            parsed = ParseAndValidateManifest(
                chain.ManifestPayload,
                comparisonTime,
                platform,
                allowExpired: expiredFallback);
        }
        catch (ProtocolValidationException)
        {
            throw;
        }
        catch (Exception error) when (
            error is InvalidOperationException or JsonException or OverflowException or FormatException)
        {
            throw Invalid(
                "manifest-shape-invalid",
                "The signed manifest contains an invalid value shape.",
                error);
        }
        if (expiredFallback
            && (appliedState is null
                || parsed.Manifest.Hash != appliedState.ManifestHash
                || parsed.Manifest.Sequence != appliedState.ManifestSequence))
        {
            throw Invalid(
                "manifest-expired-update-refused",
                "An expired signature chain may only renew the identical applied manifest.");
        }

        var delegationHash = HchDigest.Sha256Hex(
            JcsCanonicalizer.Serialize(delivery.Delegation));
        ValidateDelegationAntiRollback(
            chain.Delegation.Sequence,
            delegationHash,
            trustState,
            pins);
        ValidateManifestAntiRollback(parsed.Manifest, appliedState);

        return new VerifiedManifestDelivery(
            parsed.Manifest,
            chain.ManifestPayload.Clone(),
            parsed.Artifacts,
            parsed.Actions,
            pins.RootKeyId,
            pins.RootPublicKeyFingerprint,
            chain.ReleaseKeyId,
            chain.Delegation.Fingerprint,
            chain.Delegation.Sequence,
            delegationHash,
            parsed.ContentContractHash,
            expiredFallback);
    }

    private static async Task<VerifiedCryptographicChain> VerifyChainAsync(
        ManifestDelivery delivery,
        ManifestTrustPins pins,
        IEd25519SignatureProvider verifier,
        DateTimeOffset now,
        bool allowExpired,
        CancellationToken cancellationToken)
    {
        var rootSpki = pins.ExportRootSubjectPublicKeyInfo();
        try
        {
            var delegationEnvelope = DecodeEnvelope(delivery.Delegation);
            var delegationHeader = ValidateProtectedHeader(
                delegationEnvelope.ProtectedHeader,
                expectedRole: "root",
                expectedType: DelegationSignatureType,
                expectedKeyId: pins.RootKeyId,
                now,
                DelegationMaximumLifetimeSeconds,
                allowExpired,
                "delegation-expired");
            await VerifyEnvelopeSignatureAsync(
                delegationEnvelope,
                rootSpki,
                verifier,
                cancellationToken).ConfigureAwait(false);
            var delegation = ParseDelegation(delegationEnvelope.Payload, now, allowExpired);

            var releaseSpki = Ed25519KeyEncoding.CreateSubjectPublicKeyInfo(
                HchDigest.Base64UrlDecode(delegation.PublicKeyX, "delegation.publicKey.x"));
            var releaseFingerprint = Ed25519KeyEncoding.Fingerprint(releaseSpki);
            if (!ManifestTrustPins.FixedTimeTextEquals(releaseFingerprint, delegation.Fingerprint))
            {
                throw Invalid(
                    "release-key-fingerprint-mismatch",
                    "The delegated release-key fingerprint does not match its public key.");
            }

            var manifestEnvelope = DecodeEnvelope(delivery.Manifest);
            var manifestHeader = ValidateProtectedHeader(
                manifestEnvelope.ProtectedHeader,
                expectedRole: "release",
                expectedType: ManifestSignatureType,
                expectedKeyId: delegation.ReleaseKeyId,
                now,
                ProtocolTime.ManifestSignatureMaximumLifetimeSeconds,
                allowExpired,
                "manifest-expired");
            await VerifyEnvelopeSignatureAsync(
                manifestEnvelope,
                releaseSpki,
                verifier,
                cancellationToken).ConfigureAwait(false);
            if (manifestHeader.IssuedAt < delegation.NotBefore
                || manifestHeader.IssuedAt > delegation.Expires
                || manifestHeader.Expires > delegation.Expires)
            {
                throw Invalid(
                    "manifest-outside-delegation-window",
                    "The manifest validity interval is outside the release-key delegation.");
            }

            if (!delegation.Permissions.Contains("sign-editorial-manifest", StringComparer.Ordinal))
            {
                throw Invalid(
                    "delegation-permission-denied",
                    "The release key is not authorized to sign editorial manifests.");
            }

            return new VerifiedCryptographicChain(
                delegation,
                manifestEnvelope.Payload,
                delegation.ReleaseKeyId,
                delegationHeader,
                manifestHeader);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(rootSpki);
        }
    }

    private static DecodedEnvelope DecodeEnvelope(JcsSignatureEnvelope envelope)
    {
        ArgumentNullException.ThrowIfNull(envelope);
        byte[] protectedBytes = HchDigest.Base64UrlDecode(envelope.Protected, "protected");
        byte[] payloadBytes = HchDigest.Base64UrlDecode(envelope.Payload, "payload");
        byte[] signature = HchDigest.Base64UrlDecode(envelope.Signature, "signature");
        if (signature.Length != Ed25519KeyEncoding.SignatureLength)
        {
            throw Invalid("manifest-signature-length-invalid", "An Ed25519 signature must contain 64 bytes.");
        }

        EnsureCanonical(protectedBytes, "protected");
        EnsureCanonical(payloadBytes, "payload");
        try
        {
            using var protectedDocument = JsonDocument.Parse(protectedBytes);
            using var payloadDocument = JsonDocument.Parse(payloadBytes);
            return new DecodedEnvelope(
                envelope.Protected,
                envelope.Payload,
                protectedDocument.RootElement.Clone(),
                payloadDocument.RootElement.Clone(),
                signature);
        }
        catch (JsonException error)
        {
            throw Invalid("manifest-envelope-invalid", "The signed envelope contains invalid JSON.", error);
        }
    }

    private static void EnsureCanonical(byte[] bytes, string name)
    {
        var canonical = JcsCanonicalizer.CanonicalizeToUtf8(bytes);
        if (!bytes.AsSpan().SequenceEqual(canonical))
        {
            throw Invalid(
                "manifest-envelope-noncanonical",
                $"The {name} member is not canonical RFC 8785 JSON.");
        }
    }

    private static async Task VerifyEnvelopeSignatureAsync(
        DecodedEnvelope envelope,
        ReadOnlyMemory<byte> publicKeySpki,
        IEd25519SignatureProvider verifier,
        CancellationToken cancellationToken)
    {
        var signingInput = Encoding.ASCII.GetBytes($"{envelope.ProtectedValue}.{envelope.PayloadValue}");
        var verified = await verifier.VerifyAsync(
            publicKeySpki,
            signingInput,
            envelope.Signature,
            cancellationToken).ConfigureAwait(false);
        if (!verified)
        {
            throw Invalid("manifest-invalid-signature", "The signed envelope signature is invalid.");
        }
    }

    private static ProtectedHeader ValidateProtectedHeader(
        JsonElement value,
        string expectedRole,
        string expectedType,
        string expectedKeyId,
        DateTimeOffset now,
        int maximumLifetimeSeconds,
        bool allowExpired,
        string expiryCode)
    {
        RequireObject(value, "protected");
        if (RequiredString(value, "alg") != "EdDSA"
            || RequiredString(value, "c14n") != "RFC8785"
            || RequiredString(value, "cty") != "application/json"
            || RequiredString(value, "typ") != EnvelopeType
            || RequiredString(value, "hch") != expectedType
            || RequiredString(value, "role") != expectedRole)
        {
            throw Invalid("manifest-protected-header-invalid", "The protected envelope profile is invalid.");
        }

        var keyId = RequiredIdentifier(value, "kid", 256);
        if (!ManifestTrustPins.FixedTimeTextEquals(keyId, expectedKeyId))
        {
            throw Invalid("manifest-key-id-mismatch", "The signing key id is not the expected delegated key.");
        }

        var issuedAt = RequiredSafeInteger(value, "iat", minimum: 0);
        var expires = RequiredSafeInteger(value, "exp", minimum: 0);
        if (expires <= issuedAt || expires - issuedAt > maximumLifetimeSeconds)
        {
            throw Invalid("manifest-signature-window-invalid", "The signature validity interval is invalid.");
        }

        var nowSeconds = now.ToUnixTimeSeconds();
        if (issuedAt > nowSeconds + ProtocolTime.DefaultClockSkewSeconds)
        {
            throw Invalid("manifest-not-yet-valid", "The signature creation time is in the future.");
        }

        if (!allowExpired && expires < nowSeconds - ProtocolTime.DefaultClockSkewSeconds)
        {
            throw Invalid(expiryCode, "The signed envelope has expired.");
        }

        return new ProtectedHeader(keyId, issuedAt, expires);
    }

    private static ReleaseDelegation ParseDelegation(
        JsonElement value,
        DateTimeOffset now,
        bool allowExpired)
    {
        RequireObject(value, "delegation");
        if (RequiredString(value, "type") != DelegationSignatureType
            || RequiredSafeInteger(value, "version", 1) != 1)
        {
            throw Invalid("delegation-payload-invalid", "The release-key delegation payload is unsupported.");
        }

        var expires = RequiredSafeInteger(value, "expires", 0);
        var notBefore = RequiredSafeInteger(value, "notBefore", 0);
        var sequence = RequiredSafeInteger(value, "sequence", 1);
        var releaseKeyId = RequiredIdentifier(value, "releaseKeyId", 256);
        var fingerprint = RequiredIdentifier(value, "fingerprint", 256);
        var publicKey = RequiredProperty(value, "publicKey");
        RequireObject(publicKey, "delegation.publicKey");
        if (RequiredString(publicKey, "kty") != "OKP"
            || RequiredString(publicKey, "crv") != "Ed25519")
        {
            throw Invalid("delegation-public-key-invalid", "Only an Ed25519 OKP public JWK is accepted.");
        }

        var publicKeyX = RequiredString(publicKey, "x");
        if (HchDigest.Base64UrlDecode(publicKeyX, "delegation.publicKey.x").Length
            != Ed25519KeyEncoding.RawPublicKeyLength)
        {
            throw Invalid("delegation-public-key-invalid", "The delegated Ed25519 public key is invalid.");
        }

        var permissionsValue = RequiredProperty(value, "permissions");
        if (permissionsValue.ValueKind != JsonValueKind.Array)
        {
            throw Invalid("delegation-permissions-invalid", "Delegation permissions must be an array.");
        }

        var permissions = permissionsValue.EnumerateArray()
            .Select((item, index) => RequiredIdentifierValue(item, $"permissions[{index}]", 128))
            .ToArray();
        var nowSeconds = now.ToUnixTimeSeconds();
        if (notBefore > nowSeconds + ProtocolTime.DefaultClockSkewSeconds)
        {
            throw Invalid("delegation-not-yet-valid", "The release-key delegation is not active yet.");
        }

        if (!allowExpired && expires < nowSeconds - ProtocolTime.DefaultClockSkewSeconds)
        {
            throw Invalid("delegation-expired", "The release-key delegation has expired.");
        }

        return new ReleaseDelegation(
            releaseKeyId,
            fingerprint,
            publicKeyX,
            permissions,
            notBefore,
            expires,
            sequence);
    }

    private static ParsedManifest ParseAndValidateManifest(
        JsonElement root,
        DateTimeOffset now,
        string platform,
        bool allowExpired)
    {
        RequireObject(root, "manifest");
        if (RequiredString(root, "schemaVersion") != "2.0"
            || RequiredString(root, "protocolVersion") != "2.0")
        {
            throw Invalid("manifest-version-unsupported", "Only manifest protocol 2.0 is supported.");
        }

        var bootstrapVersion = RequiredString(root, "bootstrapVersion");
        if (bootstrapVersion is not ("2.0.0" or "2.1.0" or "2.2.0" or "2.3.0" or "3.0.0"))
        {
            throw Invalid("manifest-version-unsupported", "The bootstrap contract is unsupported.");
        }

        var sequence = RequiredSafeInteger(root, "sequence", 1);
        var minimumAcceptedSequence = RequiredSafeInteger(root, "minimumAcceptedSequence", 1);
        if (sequence < minimumAcceptedSequence)
        {
            throw Invalid("manifest-minimum-sequence-invalid", "The manifest is below its minimum accepted sequence.");
        }

        var issuedAtText = RequiredString(root, "issuedAt");
        var expiresAtText = RequiredString(root, "expiresAt");
        var issuedAt = ProtocolTime.ParseTimestamp(issuedAtText, "manifest.issuedAt");
        var expiresAt = ProtocolTime.ParseTimestamp(expiresAtText, "manifest.expiresAt");
        if (issuedAt > now.AddMinutes(5) || expiresAt <= issuedAt || (!allowExpired && expiresAt <= now))
        {
            throw Invalid("manifest-expired", "The manifest payload validity interval is invalid.");
        }

        var runtime = RequiredProperty(root, "runtime");
        RequireObject(runtime, "manifest.runtime");
        var workerVersion = RequiredString(runtime, "workerVersion");
        _ = SemanticVersion.Parse(workerVersion);
        var supportedPlatforms = RequiredProperty(runtime, "supportedPlatforms");
        if (supportedPlatforms.ValueKind != JsonValueKind.Array)
        {
            throw Invalid("manifest-platform-incompatible", $"The manifest does not support {platform}.");
        }

        var platformValues = supportedPlatforms.EnumerateArray()
            .Select((item, index) => RequiredIdentifierValue(
                item,
                $"runtime.supportedPlatforms[{index}]",
                32))
            .ToArray();
        if (!platformValues.Contains(platform, StringComparer.Ordinal))
        {
            throw Invalid("manifest-platform-incompatible", $"The manifest does not support {platform}.");
        }

        var engine = RequiredProperty(root, "engine");
        RequireObject(engine, "manifest.engine");
        var provider = PortableIdentifier(engine, "provider");
        var adapter = PortableIdentifier(engine, "adapter");
        var adapterVersion = PortableIdentifier(engine, "adapterVersion");
        var model = RequiredString(engine, "model");
        if (model.Length == 0 || RequiredString(engine, "healthPath") != "/api/tags")
        {
            throw Invalid("manifest-engine-invalid", "The manifest engine contract is invalid.");
        }

        var modelDigest = NormalizeDigest(RequiredString(engine, "modelDigest"));
        if (!HchDigest.IsLowerSha256(modelDigest))
        {
            throw Invalid("manifest-engine-invalid", "The manifest model digest is invalid.");
        }

        var protocol = RequiredString(engine, "protocol");
        if (protocol.Length == 0)
        {
            throw Invalid("manifest-engine-invalid", "The engine protocol is invalid.");
        }

        ValidateGeneration(RequiredProperty(root, "generation"));
        ManifestPolicyValidator.ValidateCapacityPolicy(RequiredProperty(root, "capacityPolicy"));
        var adaptivePolicy = RequiredProperty(root, "adaptiveWorkPolicy");
        ManifestPolicyValidator.ValidateAdaptiveWorkPolicy(adaptivePolicy);

        var editorial = RequiredProperty(root, "editorial");
        RequireObject(editorial, "manifest.editorial");
        foreach (var field in new[] { "policyId", "policyVersion", "policyHash", "promptConfigHash", "pipelineVersion" })
        {
            if (RequiredString(editorial, field).Length == 0)
            {
                throw Invalid("manifest-editorial-invalid", $"The editorial {field} is invalid.");
            }
        }

        var policyHash = RequiredString(editorial, "policyHash");
        var promptConfigHash = RequiredString(editorial, "promptConfigHash");
        if (!HchDigest.IsLowerSha256(policyHash) || !HchDigest.IsLowerSha256(promptConfigHash))
        {
            throw Invalid("manifest-editorial-invalid", "Editorial hashes must be lowercase SHA-256.");
        }

        var actions = ParseActions(RequiredProperty(root, "actions"));
        var artifacts = ParseArtifacts(RequiredProperty(root, "artifacts"));
        if (artifacts.Select(artifact => artifact.Name).Distinct(StringComparer.Ordinal).Count() != artifacts.Count)
        {
            throw Invalid("manifest-artifact-duplicate", "Manifest artifact names must be unique.");
        }

        ValidateSafety(root);
        var hash = RequiredString(root, "hash");
        if (RequiredString(root, "hashAlgorithm") != "sha256" || !HchDigest.IsLowerSha256(hash))
        {
            throw Invalid("manifest-hash-invalid", "The manifest hash declaration is invalid.");
        }

        string? previousHash = OptionalNullableString(root, "previousManifestHash");
        if (previousHash is not null && !HchDigest.IsLowerSha256(previousHash))
        {
            throw Invalid("manifest-chain-invalid", "previousManifestHash is invalid.");
        }

        var hashless = JsonNode.Parse(root.GetRawText())?.AsObject()
            ?? throw Invalid("manifest-shape-invalid", "The manifest must be an object.");
        _ = hashless.Remove("hash");
        var calculatedHash = HchDigest.Sha256Hex(JcsCanonicalizer.Serialize(hashless));
        if (!ManifestTrustPins.FixedTimeTextEquals(calculatedHash, hash))
        {
            throw Invalid("manifest-hash-mismatch", "The canonical manifest hash does not match its payload.");
        }

        var compatibility = ParseCompatibility(root, bootstrapVersion);
        var contentContractHash = ComputeContentContractHash(root);
        if (compatibility is not null
            && !ManifestTrustPins.FixedTimeTextEquals(
                compatibility.ContentContractHash,
                contentContractHash))
        {
            throw Invalid(
                "manifest-content-contract-hash-mismatch",
                "The declared content contract hash does not match the signed manifest.");
        }

        var mapped = MapManifest(
            root,
            bootstrapVersion,
            sequence,
            minimumAcceptedSequence,
            issuedAtText,
            expiresAtText,
            previousHash,
            hash,
            workerVersion,
            runtime,
            engine,
            provider,
            adapter,
            adapterVersion,
            model,
            modelDigest,
            protocol,
            editorial,
            policyHash,
            promptConfigHash,
            compatibility);
        ManifestContractValidator.Validate(mapped);
        return new ParsedManifest(mapped, artifacts, actions, contentContractHash);
    }

    private static ManifestPayload MapManifest(
        JsonElement root,
        string bootstrapVersion,
        long sequence,
        long minimumAcceptedSequence,
        string issuedAt,
        string expiresAt,
        string? previousHash,
        string hash,
        string workerVersion,
        JsonElement runtime,
        JsonElement engine,
        string provider,
        string adapter,
        string adapterVersion,
        string model,
        string modelDigest,
        string protocol,
        JsonElement editorial,
        string policyHash,
        string promptConfigHash,
        ManifestCompatibility? compatibility)
    {
        var rootKnown = new HashSet<string>(StringComparer.Ordinal)
        {
            "schemaVersion", "bootstrapVersion", "sequence", "releaseId", "issuedAt", "expiresAt",
            "minimumAcceptedSequence", "previousManifestHash", "runtime", "compatibility", "engine",
            "generation", "capacityPolicy", "adaptiveWorkPolicy", "editorial", "actions",
            "rootActionCapabilities", "artifacts", "endpoints", "security", "safety", "hashAlgorithm", "hash",
        };
        return new ManifestPayload
        {
            SchemaVersion = "2.0",
            BootstrapVersion = bootstrapVersion,
            Sequence = sequence,
            ReleaseId = RequiredString(root, "releaseId"),
            IssuedAt = issuedAt,
            ExpiresAt = expiresAt,
            MinimumAcceptedSequence = minimumAcceptedSequence,
            PreviousManifestHash = previousHash,
            Runtime = new WorkerRuntimeManifest
            {
                WorkerVersion = workerVersion,
                SupportedPlatforms = RequiredProperty(runtime, "supportedPlatforms")
                    .EnumerateArray()
                    .Select((item, index) => RequiredIdentifierValue(
                        item,
                        $"runtime.supportedPlatforms[{index}]",
                        32))
                    .ToArray(),
                AdditionalProperties = ExtensionProperties(runtime, ["workerVersion", "supportedPlatforms"]),
            },
            Compatibility = compatibility,
            Engine = new EngineManifest
            {
                Provider = provider,
                Adapter = adapter,
                AdapterVersion = adapterVersion,
                Model = model,
                ModelDigest = modelDigest,
                Protocol = protocol,
                AdditionalProperties = ExtensionProperties(
                    engine,
                    ["provider", "adapter", "adapterVersion", "model", "modelDigest", "protocol"]),
            },
            Generation = RequiredProperty(root, "generation").Clone(),
            CapacityPolicy = RequiredProperty(root, "capacityPolicy").Clone(),
            AdaptiveWorkPolicy = RequiredProperty(root, "adaptiveWorkPolicy").Clone(),
            Editorial = new EditorialManifest
            {
                PipelineVersion = RequiredString(editorial, "pipelineVersion"),
                PolicyHash = policyHash,
                PromptConfigHash = promptConfigHash,
                AdditionalProperties = ExtensionProperties(
                    editorial,
                    ["pipelineVersion", "policyHash", "promptConfigHash"]),
            },
            Actions = RequiredProperty(root, "actions").Clone(),
            RootActionCapabilities = RequiredProperty(root, "rootActionCapabilities").Clone(),
            Artifacts = RequiredProperty(root, "artifacts").Clone(),
            Endpoints = RequiredProperty(root, "endpoints").Clone(),
            Security = RequiredProperty(root, "security").Clone(),
            Safety = RequiredProperty(root, "safety").Clone(),
            HashAlgorithm = "sha256",
            Hash = hash,
            AdditionalProperties = ExtensionProperties(root, rootKnown),
        };
    }

    private static IDictionary<string, JsonElement>? ExtensionProperties(
        JsonElement value,
        IEnumerable<string> known)
    {
        var knownSet = known.ToHashSet(StringComparer.Ordinal);
        var extension = value.EnumerateObject()
            .Where(property => !knownSet.Contains(property.Name))
            .ToDictionary(property => property.Name, property => property.Value.Clone(), StringComparer.Ordinal);
        return extension.Count == 0 ? null : extension;
    }

    private static ManifestCompatibility? ParseCompatibility(JsonElement root, string bootstrapVersion)
    {
        if (!root.TryGetProperty("compatibility", out var value))
        {
            if (bootstrapVersion == "2.3.0")
            {
                throw Invalid("manifest-compatibility-missing", "Manifest bootstrap 2.3.0 requires compatibility.");
            }

            return null;
        }

        RequireObject(value, "manifest.compatibility");
        var compatibility = new ManifestCompatibility
        {
            Classification = RequiredString(value, "classification"),
            ContentContractHash = RequiredString(value, "contentContractHash"),
            PreviousContentContractHash = OptionalNullableString(value, "previousContentContractHash"),
            MinimumWorkerVersion = RequiredString(value, "minimumWorkerVersion"),
            TestedThroughWorkerVersion = RequiredString(value, "testedThroughWorkerVersion"),
            AcceptedWorkerVersions = OptionalStringArray(value, "acceptedWorkerVersions", 64),
            ContentImpact = RequiredString(value, "contentImpact"),
        };
        ValidateCompatibilityRelationship(compatibility);
        return compatibility;
    }

    private static void ValidateCompatibilityRelationship(ManifestCompatibility value)
    {
        if (value.Classification is not ("initial" or "compatible" or "content-incompatible")
            || value.ContentImpact is not ("none" or "generated-content")
            || !HchDigest.IsLowerSha256(value.ContentContractHash)
            || (value.PreviousContentContractHash is not null
                && !HchDigest.IsLowerSha256(value.PreviousContentContractHash)))
        {
            throw Invalid("manifest-compatibility-invalid", "The compatibility declaration is invalid.");
        }

        var minimum = SemanticVersion.Parse(value.MinimumWorkerVersion);
        var tested = SemanticVersion.Parse(value.TestedThroughWorkerVersion);
        var valid = minimum.CompareTo(tested) <= 0 && value.Classification switch
        {
            "initial" => value.PreviousContentContractHash is null && value.ContentImpact == "none",
            "compatible" => value.PreviousContentContractHash == value.ContentContractHash
                && value.ContentImpact == "none",
            "content-incompatible" => value.PreviousContentContractHash is not null
                && value.PreviousContentContractHash != value.ContentContractHash
                && value.ContentImpact == "generated-content",
            _ => false,
        };
        if (!valid)
        {
            throw Invalid("manifest-compatibility-invalid", "The compatibility declaration contradicts itself.");
        }
    }

    private static string ComputeContentContractHash(JsonElement root)
    {
        var editorial = RequiredProperty(root, "editorial");
        var engine = RequiredProperty(root, "engine");
        var projection = new JsonObject
        {
            ["adaptiveWorkPolicy"] = JsonNode.Parse(RequiredProperty(root, "adaptiveWorkPolicy").GetRawText()),
            ["artifacts"] = JsonNode.Parse(RequiredProperty(root, "artifacts").GetRawText()),
            ["editorial"] = new JsonObject
            {
                ["pipelineVersion"] = RequiredString(editorial, "pipelineVersion"),
                ["policyHash"] = RequiredString(editorial, "policyHash"),
                ["promptConfigHash"] = RequiredString(editorial, "promptConfigHash"),
            },
            ["engine"] = new JsonObject
            {
                ["adapter"] = RequiredString(engine, "adapter"),
                ["adapterVersion"] = RequiredString(engine, "adapterVersion"),
                ["model"] = RequiredString(engine, "model"),
                ["modelDigest"] = RequiredString(engine, "modelDigest"),
                ["protocol"] = RequiredString(engine, "protocol"),
                ["provider"] = RequiredString(engine, "provider"),
            },
            ["generation"] = JsonNode.Parse(RequiredProperty(root, "generation").GetRawText()),
        };
        return HchDigest.Sha256Hex(JcsCanonicalizer.Serialize(projection));
    }

    private static IReadOnlyList<ManifestActionContract> ParseActions(JsonElement value)
    {
        if (value.ValueKind != JsonValueKind.Array)
        {
            throw Invalid("manifest-plan-invalid", "Manifest actions must be an array.");
        }

        var result = new List<ManifestActionContract>();
        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var action in value.EnumerateArray())
        {
            RequireObject(action, "manifest action");
            RequireExactFields(action, AllowedActionFields, "manifest-action-fields-refused");
            var type = RequiredString(action, "type");
            var authorizationClass = RequiredString(action, "authorizationClass");
            if (authorizationClass == "root-required")
            {
                throw Invalid("root-action-refused", "Root-required actions are not accepted by this worker.");
            }

            if (authorizationClass != "release" || !AllowedActions.Contains(type))
            {
                throw Invalid("manifest-action-refused", "The manifest action is not allowlisted.");
            }

            if (!seen.Add(type))
            {
                throw Invalid("manifest-action-duplicate", "Manifest actions must not be duplicated.");
            }

            result.Add(new ManifestActionContract(type, authorizationClass));
        }

        return result;
    }

    private static IReadOnlyList<ManifestArtifactContract> ParseArtifacts(JsonElement value)
    {
        if (value.ValueKind != JsonValueKind.Array)
        {
            throw Invalid("manifest-plan-invalid", "Manifest artifacts must be an array.");
        }

        var result = new List<ManifestArtifactContract>();
        foreach (var artifact in value.EnumerateArray())
        {
            RequireObject(artifact, "manifest artifact");
            RequireExactFields(artifact, AllowedArtifactFields, "manifest-artifact-fields-refused");
            var name = RequiredString(artifact, "name");
            if (!ArtifactNamePattern().IsMatch(name))
            {
                throw Invalid("manifest-artifact-name-invalid", "The artifact name is unsafe.");
            }

            var authorizationClass = RequiredString(artifact, "authorizationClass");
            if (authorizationClass == "root-required")
            {
                throw Invalid("root-artifact-refused", "Root-required artifacts are not accepted.");
            }

            var mediaType = RequiredString(artifact, "mediaType");
            var bytes = RequiredSafeInteger(artifact, "bytes", 1);
            var sha256 = RequiredString(artifact, "sha256").ToLowerInvariant();
            var url = RequiredString(artifact, "url");
            if (authorizationClass != "release" || mediaType.Length == 0
                || !HchDigest.IsLowerSha256(sha256) || url.Length == 0)
            {
                throw Invalid("manifest-artifact-invalid", "The artifact declaration is invalid.");
            }

            result.Add(new ManifestArtifactContract(
                name,
                mediaType,
                bytes,
                sha256,
                url,
                authorizationClass));
        }

        return result;
    }

    private static void ValidateGeneration(JsonElement generation)
    {
        RequireObject(generation, "manifest.generation");
        var temperature = RequiredDouble(generation, "temperature");
        var contextWindow = RequiredSafeInteger(generation, "contextWindow", 1);
        var maxOutputTokens = RequiredSafeInteger(generation, "maxOutputTokens", 1);
        if (!double.IsFinite(temperature) || temperature < 0
            || contextWindow < 1 || maxOutputTokens < 1)
        {
            throw Invalid("manifest-generation-invalid", "The generation parameters are invalid.");
        }
    }

    private static void ValidateSafety(JsonElement root)
    {
        var security = RequiredProperty(root, "security");
        var safety = RequiredProperty(root, "safety");
        RequireObject(security, "manifest.security");
        RequireObject(safety, "manifest.safety");
        if (RequiredBoolean(security, "authorizationByIp")
            || RequiredBoolean(security, "arbitraryRemoteCommands")
            || RequiredBoolean(safety, "credentialsInManifest")
            || RequiredBoolean(safety, "automaticApproval")
            || RequiredBoolean(safety, "automaticPublication"))
        {
            throw Invalid("manifest-safety-invalid", "The manifest safety guarantees are unacceptable.");
        }
    }

    private static void ValidateDelegationAntiRollback(
        long candidateSequence,
        string candidateHash,
        DelegationTrustAnchor? trustState,
        ManifestTrustPins pins)
    {
        if (trustState is null)
        {
            return;
        }

        if (trustState.SchemaVersion != 1
            || trustState.RootKeyId != pins.RootKeyId
            || trustState.RootFingerprint != pins.RootPublicKeyFingerprint
            || trustState.DelegationSequence < 1
            || !HchDigest.IsLowerSha256(trustState.DelegationHash))
        {
            throw Invalid("delegation-state-invalid", "The persisted delegation trust anchor is invalid.");
        }

        if (candidateSequence < trustState.DelegationSequence)
        {
            throw Invalid("delegation-rollback-refused", "The release delegation would roll back.");
        }

        if (candidateSequence == trustState.DelegationSequence
            && !ManifestTrustPins.FixedTimeTextEquals(candidateHash, trustState.DelegationHash))
        {
            throw Invalid("delegation-equivocation-refused", "A delegation sequence carries another hash.");
        }
    }

    private static void ValidateManifestAntiRollback(
        ManifestPayload manifest,
        AppliedManifestAnchor? appliedState)
    {
        if (appliedState is null)
        {
            return;
        }

        if (appliedState.SchemaVersion != 1 || appliedState.ManifestSequence < 1
            || !HchDigest.IsLowerSha256(appliedState.ManifestHash))
        {
            throw Invalid("applied-state-invalid", "The applied manifest anchor is invalid.");
        }

        if (manifest.Sequence < appliedState.ManifestSequence)
        {
            throw Invalid("manifest-rollback-refused", "The manifest sequence would roll back.");
        }

        if (manifest.Sequence == appliedState.ManifestSequence && manifest.Hash != appliedState.ManifestHash)
        {
            throw Invalid("manifest-equivocation-refused", "The same manifest sequence carries another hash.");
        }

        if (manifest.Sequence > appliedState.ManifestSequence
            && manifest.PreviousManifestHash != appliedState.ManifestHash)
        {
            throw Invalid("manifest-chain-break", "The manifest does not extend the applied hash chain.");
        }
    }

    private static string PortableIdentifier(JsonElement value, string name)
    {
        var result = RequiredString(value, name);
        if (!PortableIdentifierPattern().IsMatch(result))
        {
            throw Invalid("manifest-engine-invalid", $"The engine {name} is invalid.");
        }

        return result;
    }

    private static string NormalizeDigest(string value) =>
        value.StartsWith("sha256:", StringComparison.OrdinalIgnoreCase)
            ? value[7..].ToLowerInvariant()
            : value.ToLowerInvariant();

    private static void RequireExactFields(JsonElement value, HashSet<string> fields, string code)
    {
        foreach (var property in value.EnumerateObject())
        {
            if (!fields.Contains(property.Name))
            {
                throw Invalid(code, "The object contains an unsupported field.");
            }
        }

        if (fields.Any(field => !value.TryGetProperty(field, out _)))
        {
            throw Invalid(code, "The object is missing a required field.");
        }
    }

    private static JsonElement RequiredProperty(JsonElement value, string name)
    {
        if (!value.TryGetProperty(name, out var property))
        {
            throw Invalid("manifest-field-missing", $"The required {name} field is missing.");
        }

        return property;
    }

    private static string RequiredString(JsonElement value, string name)
    {
        var property = RequiredProperty(value, name);
        if (property.ValueKind != JsonValueKind.String || property.GetString() is not { } result)
        {
            throw Invalid("manifest-field-invalid", $"{name} must be a string.");
        }

        return result;
    }

    private static string RequiredIdentifier(JsonElement value, string name, int maximum) =>
        RequiredIdentifierValue(RequiredProperty(value, name), name, maximum);

    private static string RequiredIdentifierValue(JsonElement value, string name, int maximum)
    {
        if (value.ValueKind != JsonValueKind.String || value.GetString() is not { } result
            || result.Length is < 1 || result.Length > maximum
            || result.Any(character => character <= ' ' || character == '\x7f' || char.IsSurrogate(character)))
        {
            throw Invalid("manifest-identifier-invalid", $"{name} is invalid.");
        }

        return result;
    }

    private static long RequiredSafeInteger(JsonElement value, string name, long minimum)
    {
        var property = RequiredProperty(value, name);
        if (property.ValueKind != JsonValueKind.Number || !property.TryGetInt64(out var result)
            || result < minimum || result > ProtocolTime.JavaScriptMaximumSafeInteger)
        {
            throw Invalid("manifest-number-invalid", $"{name} must be a safe integer.");
        }

        return result;
    }

    private static double RequiredDouble(JsonElement value, string name)
    {
        var property = RequiredProperty(value, name);
        if (property.ValueKind != JsonValueKind.Number || !property.TryGetDouble(out var result))
        {
            throw Invalid("manifest-number-invalid", $"{name} must be a number.");
        }

        return result;
    }

    private static bool RequiredBoolean(JsonElement value, string name)
    {
        var property = RequiredProperty(value, name);
        if (property.ValueKind is not (JsonValueKind.True or JsonValueKind.False))
        {
            throw Invalid("manifest-field-invalid", $"{name} must be a boolean.");
        }

        return property.GetBoolean();
    }

    private static string? OptionalNullableString(JsonElement value, string name)
    {
        var property = RequiredProperty(value, name);
        return property.ValueKind switch
        {
            JsonValueKind.Null => null,
            JsonValueKind.String => property.GetString(),
            _ => throw Invalid("manifest-field-invalid", $"{name} must be a string or null."),
        };
    }

    private static IReadOnlyList<string>? OptionalStringArray(
        JsonElement value,
        string name,
        int maximumCount)
    {
        if (!value.TryGetProperty(name, out var property))
        {
            return null;
        }

        if (property.ValueKind != JsonValueKind.Array || property.GetArrayLength() > maximumCount)
        {
            throw Invalid("manifest-field-invalid", $"{name} must be a bounded string array.");
        }

        var result = new List<string>(property.GetArrayLength());
        foreach (var item in property.EnumerateArray())
        {
            if (item.ValueKind != JsonValueKind.String || item.GetString() is not { } text)
            {
                throw Invalid("manifest-field-invalid", $"{name} must contain only strings.");
            }

            result.Add(text);
        }

        return result;
    }

    private static void RequireObject(JsonElement value, string name)
    {
        if (value.ValueKind != JsonValueKind.Object)
        {
            throw Invalid("manifest-shape-invalid", $"{name} must be an object.");
        }
    }

    private static ProtocolValidationException Invalid(string code, string message, Exception? cause = null)
    {
        var exception = new ProtocolValidationException(code, message);
        if (cause is not null)
        {
            exception.Data["cause"] = cause.GetType().FullName;
        }

        return exception;
    }

    [GeneratedRegex("^[a-z0-9][a-z0-9-]{0,79}$", RegexOptions.CultureInvariant)]
    private static partial Regex ArtifactNamePattern();

    [GeneratedRegex("^[A-Za-z0-9][A-Za-z0-9._:+/-]{0,159}$", RegexOptions.CultureInvariant)]
    private static partial Regex PortableIdentifierPattern();

    private sealed record DecodedEnvelope(
        string ProtectedValue,
        string PayloadValue,
        JsonElement ProtectedHeader,
        JsonElement Payload,
        byte[] Signature);

    private sealed record ProtectedHeader(string KeyId, long IssuedAt, long Expires);

    private sealed record ReleaseDelegation(
        string ReleaseKeyId,
        string Fingerprint,
        string PublicKeyX,
        IReadOnlyList<string> Permissions,
        long NotBefore,
        long Expires,
        long Sequence);

    private sealed record VerifiedCryptographicChain(
        ReleaseDelegation Delegation,
        JsonElement ManifestPayload,
        string ReleaseKeyId,
        ProtectedHeader DelegationHeader,
        ProtectedHeader ManifestHeader);

    private sealed record ParsedManifest(
        ManifestPayload Manifest,
        IReadOnlyList<ManifestArtifactContract> Artifacts,
        IReadOnlyList<ManifestActionContract> Actions,
        string ContentContractHash);
}

/// <summary>Strict validation of signed capacity and liveness policy objects.</summary>
public static partial class ManifestPolicyValidator
{
    private static readonly HashSet<string> CapacityFields =
    [
        "algorithmVersion", "absoluteRequestedMaximum", "defaultNodeCeiling",
        "globalAssignmentCeiling", "grantTtlSeconds", "telemetryMayOnlyReduce",
        "classCeilings", "platformClasses", "nodeClasses", "nodeCeilings", "pressure",
    ];

    private static readonly HashSet<string> AdaptiveFields =
    [
        "algorithmVersion", "windowMode", "minimumTierIgnoresWindow", "livenessBasis",
        "processingWindowSeconds", "nearWindowRatio", "firstProgressGraceSeconds",
        "stallAfterSeconds", "finalizationGraceSeconds", "tiers",
    ];

    private static readonly HashSet<string> TierFields =
        ["id", "rank", "maxOutputTokens", "editorialProfile", "minimumUnit"];

    public static void ValidateCapacityPolicy(JsonElement value)
    {
        ExactObject(value, CapacityFields, "capacity-policy-invalid");
        if (String(value, "algorithmVersion") != "hch-adaptive-capacity-v1"
            || Integer(value, "absoluteRequestedMaximum", 64, 64) != 64
            || !Boolean(value, "telemetryMayOnlyReduce"))
        {
            throw Invalid("capacity-policy-unsupported", "The capacity policy guarantees are unsupported.");
        }

        _ = Integer(value, "defaultNodeCeiling", 0, 64);
        _ = Integer(value, "globalAssignmentCeiling", 1, 4096);
        _ = Integer(value, "grantTtlSeconds", 1, 3600);
        var classes = Property(value, "classCeilings");
        ExactObject(classes, ["constrained", "standard", "accelerated"], "capacity-policy-invalid");
        var constrained = Integer(classes, "constrained", 0, 64);
        var standard = Integer(classes, "standard", 0, 64);
        var accelerated = Integer(classes, "accelerated", 0, 64);
        if (constrained > standard || standard > accelerated)
        {
            throw Invalid("capacity-policy-invalid", "Capacity class ceilings must be monotonic.");
        }

        ValidateClassMap(Property(value, "platformClasses"), ["linux", "macos", "windows"]);
        ValidateClassMap(Property(value, "nodeClasses"), []);
        ValidateNodeCeilings(Property(value, "nodeCeilings"));
        var pressure = Property(value, "pressure");
        ExactObject(
            pressure,
            ["softLimitPercent", "hardLimitPercent", "softReductionFactor"],
            "capacity-policy-invalid");
        var soft = Number(pressure, "softLimitPercent", 0, 100);
        var hard = Number(pressure, "hardLimitPercent", 0, 100);
        var factor = Number(pressure, "softReductionFactor", 0, 1);
        if (soft >= hard || factor is < 0 or > 1)
        {
            throw Invalid("capacity-policy-invalid", "The capacity pressure policy is invalid.");
        }
    }

    public static void ValidateAdaptiveWorkPolicy(JsonElement value)
    {
        ExactObject(value, AdaptiveFields, "adaptive-work-policy-invalid");
        if (String(value, "algorithmVersion") != "hch-adaptive-work-v1"
            || String(value, "windowMode") != "advisory"
            || !Boolean(value, "minimumTierIgnoresWindow")
            || String(value, "livenessBasis") != "progress")
        {
            throw Invalid("adaptive-work-policy-unsupported", "The adaptive work policy is unsupported.");
        }

        var window = Integer(value, "processingWindowSeconds", 60, 86_400);
        _ = Number(value, "nearWindowRatio", 0.5, 0.95);
        _ = Integer(value, "firstProgressGraceSeconds", 30, window);
        _ = Integer(value, "stallAfterSeconds", 30, window);
        _ = Integer(value, "finalizationGraceSeconds", 30, window);
        var tiers = Property(value, "tiers");
        if (tiers.ValueKind != JsonValueKind.Array || tiers.GetArrayLength() is < 2 or > 8)
        {
            throw Invalid("adaptive-work-policy-invalid", "The policy must define between two and eight tiers.");
        }

        var identifiers = new HashSet<string>(StringComparer.Ordinal);
        var previousTokens = 0;
        var index = 0;
        foreach (var tier in tiers.EnumerateArray())
        {
            ExactObject(tier, TierFields, "adaptive-work-policy-invalid");
            var id = Identifier(tier, "id");
            if (!identifiers.Add(id) || Integer(tier, "rank", 0, tiers.GetArrayLength() - 1) != index)
            {
                throw Invalid("adaptive-work-policy-invalid", "Tier identifiers/ranks are invalid.");
            }

            var tokens = Integer(tier, "maxOutputTokens", 1, 4096);
            if (index > 0 && tokens <= previousTokens)
            {
                throw Invalid("adaptive-work-policy-invalid", "Tier token ceilings must increase.");
            }

            _ = Identifier(tier, "editorialProfile");
            if (Boolean(tier, "minimumUnit") != (index == 0))
            {
                throw Invalid("adaptive-work-policy-invalid", "Only rank zero may be the minimum unit.");
            }

            previousTokens = tokens;
            index++;
        }
    }

    public static string CapacityPolicyHash(JsonElement value)
    {
        ValidateCapacityPolicy(value);
        return HchDigest.Sha256Hex(JcsCanonicalizer.Canonicalize(value.GetRawText()));
    }

    public static string AdaptiveWorkPolicyHash(JsonElement value)
    {
        ValidateAdaptiveWorkPolicy(value);
        return HchDigest.Sha256Hex(JcsCanonicalizer.Canonicalize(value.GetRawText()));
    }

    private static void ValidateClassMap(JsonElement value, IReadOnlyList<string> required)
    {
        if (value.ValueKind != JsonValueKind.Object)
        {
            throw Invalid("capacity-policy-invalid", "A capacity class map must be an object.");
        }

        var properties = value.EnumerateObject().ToArray();
        if (required.Any(name => properties.All(property => property.Name != name)))
        {
            throw Invalid("capacity-policy-invalid", "A required platform capacity class is missing.");
        }

        foreach (var property in properties)
        {
            if (!IdentifierPattern().IsMatch(property.Name)
                || property.Value.ValueKind != JsonValueKind.String
                || property.Value.GetString() is not ("constrained" or "standard" or "accelerated"))
            {
                throw Invalid("capacity-policy-invalid", "A capacity class mapping is invalid.");
            }
        }
    }

    private static void ValidateNodeCeilings(JsonElement value)
    {
        if (value.ValueKind != JsonValueKind.Object)
        {
            throw Invalid("capacity-policy-invalid", "Node ceilings must be an object.");
        }

        foreach (var property in value.EnumerateObject())
        {
            if (!NodeIdentifierPattern().IsMatch(property.Name)
                || property.Value.ValueKind != JsonValueKind.Number
                || !property.Value.TryGetInt32(out var ceiling)
                || ceiling is < 0 or > 64)
            {
                throw Invalid("capacity-policy-invalid", "A node capacity ceiling is invalid.");
            }
        }
    }

    private static void ExactObject(JsonElement value, IEnumerable<string> fields, string code)
    {
        if (value.ValueKind != JsonValueKind.Object)
        {
            throw Invalid(code, "The policy member must be an object.");
        }

        var expected = fields.ToHashSet(StringComparer.Ordinal);
        var actual = value.EnumerateObject().Select(property => property.Name).ToHashSet(StringComparer.Ordinal);
        if (!expected.SetEquals(actual))
        {
            throw Invalid(code, "The policy contains missing or unsupported fields.");
        }
    }

    private static JsonElement Property(JsonElement value, string name)
    {
        if (!value.TryGetProperty(name, out var property))
        {
            throw Invalid("policy-field-missing", $"The policy field {name} is missing.");
        }

        return property;
    }

    private static string String(JsonElement value, string name)
    {
        var property = Property(value, name);
        if (property.ValueKind != JsonValueKind.String || property.GetString() is not { } result)
        {
            throw Invalid("policy-field-invalid", $"The policy field {name} must be a string.");
        }

        return result;
    }

    private static string Identifier(JsonElement value, string name)
    {
        var result = String(value, name);
        if (!TierIdentifierPattern().IsMatch(result))
        {
            throw Invalid("policy-field-invalid", $"The policy identifier {name} is invalid.");
        }

        return result;
    }

    private static int Integer(JsonElement value, string name, int minimum, int maximum)
    {
        var property = Property(value, name);
        if (property.ValueKind != JsonValueKind.Number || !property.TryGetInt32(out var result)
            || result < minimum || result > maximum)
        {
            throw Invalid("policy-field-invalid", $"The policy field {name} is outside its range.");
        }

        return result;
    }

    private static double Number(JsonElement value, string name, double minimum, double maximum)
    {
        var property = Property(value, name);
        if (property.ValueKind != JsonValueKind.Number || !property.TryGetDouble(out var result)
            || !double.IsFinite(result) || result < minimum || result > maximum)
        {
            throw Invalid("policy-field-invalid", $"The policy field {name} is outside its range.");
        }

        return result;
    }

    private static bool Boolean(JsonElement value, string name)
    {
        var property = Property(value, name);
        if (property.ValueKind is not (JsonValueKind.True or JsonValueKind.False))
        {
            throw Invalid("policy-field-invalid", $"The policy field {name} must be boolean.");
        }

        return property.GetBoolean();
    }

    private static ProtocolValidationException Invalid(string code, string message) => new(code, message);

    [GeneratedRegex("^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$", RegexOptions.CultureInvariant)]
    private static partial Regex IdentifierPattern();

    [GeneratedRegex("^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,127}$", RegexOptions.CultureInvariant)]
    private static partial Regex NodeIdentifierPattern();

    [GeneratedRegex("^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$", RegexOptions.CultureInvariant)]
    private static partial Regex TierIdentifierPattern();
}
