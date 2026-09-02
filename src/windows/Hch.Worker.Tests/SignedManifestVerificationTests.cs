using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Hch.Worker.Protocol;
using Hch.Worker.Security;

namespace Hch.Worker.Tests;

public sealed class SignedManifestVerificationTests
{
    private static readonly DateTimeOffset Now = new(2026, 9, 1, 16, 0, 0, TimeSpan.Zero);

    [Fact]
    public async Task VerifiesPinnedRootDelegationManifestAndContentContract()
    {
        using var root = Ed25519Identity.Generate();
        using var release = Ed25519Identity.Generate();
        var fixture = await CreateDeliveryAsync(root, release, Now);

        var verified = await SignedManifestVerifier.VerifyAsync(
            fixture.Delivery,
            fixture.Pins,
            root,
            now: Now);

        Assert.Equal(1, verified.Manifest.Sequence);
        Assert.Equal(fixture.ManifestHash, verified.Manifest.Hash);
        Assert.Equal(fixture.ContentContractHash, verified.ContentContractHash);
        Assert.Equal("release-v1", verified.ReleaseKeyId);
        Assert.Equal(1, verified.DelegationSequence);
        Assert.False(verified.ExpiredFallback);
        Assert.Equal(4, verified.Artifacts.Count);
        Assert.Equal(["3.1.0", "4.0.0"], verified.Manifest.Compatibility?.AcceptedWorkerVersions);
    }

    [Fact]
    public async Task RefusesDeliveredRootIdentityThatDoesNotMatchExplicitPins()
    {
        using var root = Ed25519Identity.Generate();
        using var release = Ed25519Identity.Generate();
        var fixture = await CreateDeliveryAsync(root, release, Now);
        var tampered = new ManifestDelivery
        {
            Manifest = fixture.Delivery.Manifest,
            Delegation = fixture.Delivery.Delegation,
            RootKeyId = fixture.Delivery.RootKeyId,
            RootPublicKeyFingerprint = "SHA256:" + new string('A', 43),
        };

        var error = await Assert.ThrowsAsync<ProtocolValidationException>(() =>
            SignedManifestVerifier.VerifyAsync(tampered, fixture.Pins, root, now: Now));

        Assert.Equal("root-key-pin-mismatch", error.Code);
    }

    [Fact]
    public async Task ExpiredChainIsAcceptedOnlyForIdenticalAppliedManifest()
    {
        using var root = Ed25519Identity.Generate();
        using var release = Ed25519Identity.Generate();
        var signedAt = Now.AddDays(-2);
        var fixture = await CreateDeliveryAsync(
            root,
            release,
            signedAt,
            envelopeExpires: Now.AddDays(-1),
            manifestExpires: Now.AddDays(-1));
        var applied = new AppliedManifestAnchor(1, 1, fixture.ManifestHash, fixture.ContentContractHash);

        var verified = await SignedManifestVerifier.VerifyAsync(
            fixture.Delivery,
            fixture.Pins,
            root,
            applied,
            now: Now);
        Assert.True(verified.ExpiredFallback);

        var wrongApplied = applied with { ManifestHash = new string('f', 64) };
        var error = await Assert.ThrowsAsync<ProtocolValidationException>(() =>
            SignedManifestVerifier.VerifyAsync(
                fixture.Delivery,
                fixture.Pins,
                root,
                wrongApplied,
                now: Now));
        Assert.Equal("manifest-expired-update-refused", error.Code);
    }

    [Fact]
    public async Task RefusesDelegationRollbackAndSameSequenceEquivocation()
    {
        using var root = Ed25519Identity.Generate();
        using var release = Ed25519Identity.Generate();
        var fixture = await CreateDeliveryAsync(root, release, Now);
        var newer = new DelegationTrustAnchor(
            1,
            fixture.Pins.RootKeyId,
            fixture.Pins.RootPublicKeyFingerprint,
            2,
            new string('a', 64));

        var rollback = await Assert.ThrowsAsync<ProtocolValidationException>(() =>
            SignedManifestVerifier.VerifyAsync(
                fixture.Delivery,
                fixture.Pins,
                root,
                trustState: newer,
                now: Now));
        Assert.Equal("delegation-rollback-refused", rollback.Code);

        var equivocation = newer with { DelegationSequence = 1 };
        var equivocationError = await Assert.ThrowsAsync<ProtocolValidationException>(() =>
            SignedManifestVerifier.VerifyAsync(
                fixture.Delivery,
                fixture.Pins,
                root,
                trustState: equivocation,
                now: Now));
        Assert.Equal("delegation-equivocation-refused", equivocationError.Code);
    }

    [Fact]
    public async Task RefusesSignedButUntruthfulContentCompatibilityDeclaration()
    {
        using var root = Ed25519Identity.Generate();
        using var release = Ed25519Identity.Generate();
        var fixture = await CreateDeliveryAsync(
            root,
            release,
            Now,
            declaredContentHash: new string('b', 64));

        var error = await Assert.ThrowsAsync<ProtocolValidationException>(() =>
            SignedManifestVerifier.VerifyAsync(fixture.Delivery, fixture.Pins, root, now: Now));

        Assert.Equal("manifest-content-contract-hash-mismatch", error.Code);
    }

    private static async Task<ManifestFixture> CreateDeliveryAsync(
        Ed25519Identity root,
        Ed25519Identity release,
        DateTimeOffset issuedAt,
        DateTimeOffset? envelopeExpires = null,
        DateTimeOffset? manifestExpires = null,
        string? declaredContentHash = null)
    {
        var expires = envelopeExpires ?? issuedAt.AddDays(7);
        var manifest = CreateManifest(
            issuedAt,
            manifestExpires ?? expires,
            declaredContentHash,
            out var contentHash);
        var manifestHash = ComputeAndSetHash(manifest);
        var releaseSpki = release.ExportSubjectPublicKeyInfo();
        var delegationPayload = new JsonObject
        {
            ["expires"] = expires.ToUnixTimeSeconds(),
            ["fingerprint"] = release.Fingerprint,
            ["notBefore"] = issuedAt.ToUnixTimeSeconds(),
            ["permissions"] = new JsonArray("sign-editorial-manifest"),
            ["publicKey"] = new JsonObject
            {
                ["crv"] = "Ed25519",
                ["kty"] = "OKP",
                ["x"] = Base64Url(Ed25519KeyEncoding.GetRawPublicKey(releaseSpki)),
            },
            ["releaseKeyId"] = "release-v1",
            ["sequence"] = 1,
            ["type"] = SignedManifestVerifier.DelegationSignatureType,
            ["version"] = 1,
        };
        var delegationHeader = new JsonObject
        {
            ["alg"] = "EdDSA",
            ["c14n"] = "RFC8785",
            ["cty"] = "application/json",
            ["exp"] = expires.ToUnixTimeSeconds(),
            ["hch"] = SignedManifestVerifier.DelegationSignatureType,
            ["iat"] = issuedAt.ToUnixTimeSeconds(),
            ["kid"] = "hch-root-v1",
            ["role"] = "root",
            ["typ"] = "application/hch+jws+jcs",
        };
        var manifestHeader = new JsonObject
        {
            ["alg"] = "EdDSA",
            ["c14n"] = "RFC8785",
            ["cty"] = "application/json",
            ["exp"] = expires.ToUnixTimeSeconds(),
            ["hch"] = SignedManifestVerifier.ManifestSignatureType,
            ["iat"] = issuedAt.ToUnixTimeSeconds(),
            ["kid"] = "release-v1",
            ["role"] = "release",
            ["typ"] = "application/hch+jws+jcs",
        };
        var delivery = new ManifestDelivery
        {
            Delegation = await SignEnvelopeAsync(delegationHeader, delegationPayload, root),
            Manifest = await SignEnvelopeAsync(manifestHeader, manifest, release),
            RootKeyId = "hch-root-v1",
            RootPublicKeyFingerprint = root.Fingerprint,
        };
        var pins = new ManifestTrustPins(
            "hch-root-v1",
            root.Fingerprint,
            root.ExportSubjectPublicKeyInfo());
        return new ManifestFixture(delivery, pins, manifestHash, contentHash);
    }

    private static JsonObject CreateManifest(
        DateTimeOffset issuedAt,
        DateTimeOffset expiresAt,
        string? declaredContentHash,
        out string contentHash)
    {
        var artifacts = new JsonArray(
            Artifact("policy", "application/json", 11, '1'),
            Artifact("prompt", "text/markdown", 12, '2'),
            Artifact("editorial-content-schema", "application/schema+json", 13, '3'),
            Artifact("editorial-source-schema", "application/schema+json", 14, '4'));
        var adaptive = new JsonObject
        {
            ["algorithmVersion"] = "hch-adaptive-work-v1",
            ["windowMode"] = "advisory",
            ["minimumTierIgnoresWindow"] = true,
            ["livenessBasis"] = "progress",
            ["processingWindowSeconds"] = 2700,
            ["nearWindowRatio"] = 0.8,
            ["firstProgressGraceSeconds"] = 900,
            ["stallAfterSeconds"] = 600,
            ["finalizationGraceSeconds"] = 180,
            ["tiers"] = new JsonArray(
                Tier("minimum", 0, 768, "EDITORIAL_MINIMUM", true),
                Tier("full", 1, 2400, "EDITORIAL_LONG_FORM", false)),
        };
        var engine = new JsonObject
        {
            ["provider"] = "ollama",
            ["adapter"] = "ollama-chat",
            ["adapterVersion"] = "1.0.0",
            ["model"] = "qwen3:8b",
            ["modelDigest"] = new string('5', 64),
            ["protocol"] = "ollama-chat-v1",
            ["healthPath"] = "/api/tags",
        };
        var editorial = new JsonObject
        {
            ["policyId"] = "hch-editorial",
            ["policyVersion"] = "1.0.0",
            ["policyHash"] = new string('6', 64),
            ["promptConfigHash"] = new string('7', 64),
            ["pipelineVersion"] = "1.0.0",
        };
        var generation = new JsonObject
        {
            ["temperature"] = 0.2,
            ["contextWindow"] = 8192,
            ["maxOutputTokens"] = 2400,
        };
        var contract = new JsonObject
        {
            ["adaptiveWorkPolicy"] = adaptive.DeepClone(),
            ["artifacts"] = artifacts.DeepClone(),
            ["editorial"] = new JsonObject
            {
                ["pipelineVersion"] = editorial["pipelineVersion"]!.DeepClone(),
                ["policyHash"] = editorial["policyHash"]!.DeepClone(),
                ["promptConfigHash"] = editorial["promptConfigHash"]!.DeepClone(),
            },
            ["engine"] = new JsonObject
            {
                ["adapter"] = engine["adapter"]!.DeepClone(),
                ["adapterVersion"] = engine["adapterVersion"]!.DeepClone(),
                ["model"] = engine["model"]!.DeepClone(),
                ["modelDigest"] = engine["modelDigest"]!.DeepClone(),
                ["protocol"] = engine["protocol"]!.DeepClone(),
                ["provider"] = engine["provider"]!.DeepClone(),
            },
            ["generation"] = generation.DeepClone(),
        };
        contentHash = HchDigest.Sha256Hex(JcsCanonicalizer.Serialize(contract));
        return new JsonObject
        {
            ["schemaVersion"] = "2.0",
            ["protocolVersion"] = "2.0",
            ["bootstrapVersion"] = "2.3.0",
            ["hashAlgorithm"] = "sha256",
            ["sequence"] = 1,
            ["releaseId"] = "hch-editorial-test.1",
            ["issuedAt"] = issuedAt.ToString("O"),
            ["expiresAt"] = expiresAt.ToString("O"),
            ["previousManifestHash"] = null,
            ["minimumAcceptedSequence"] = 1,
            ["updateMode"] = "mandatory",
            ["compatibility"] = new JsonObject
            {
                ["classification"] = "initial",
                ["contentContractHash"] = declaredContentHash ?? contentHash,
                ["previousContentContractHash"] = null,
                ["minimumWorkerVersion"] = "3.1.0",
                ["testedThroughWorkerVersion"] = "4.0.0",
                ["acceptedWorkerVersions"] = new JsonArray("3.1.0", "4.0.0"),
                ["contentImpact"] = "none",
            },
            ["configurationHash"] = new string('8', 64),
            ["runtime"] = new JsonObject
            {
                ["workerVersion"] = "3.1.0",
                ["latestAvailableWorkerVersion"] = "4.0.0",
                ["supportedPlatforms"] = new JsonArray("linux", "macos", "windows"),
                ["executableUpdatesRequireRoot"] = true,
            },
            ["engine"] = engine,
            ["generation"] = generation,
            ["capacityPolicy"] = CapacityPolicy(),
            ["adaptiveWorkPolicy"] = adaptive,
            ["editorial"] = editorial,
            ["actions"] = new JsonArray(
                Action("verify-artifact"),
                Action("configure-engine"),
                Action("pull-model-by-digest"),
                Action("apply-editorial-policy"),
                Action("self-test")),
            ["rootActionCapabilities"] = new JsonArray(),
            ["artifacts"] = artifacts,
            ["endpoints"] = new JsonObject(),
            ["security"] = new JsonObject
            {
                ["authorizationByIp"] = false,
                ["arbitraryRemoteCommands"] = false,
            },
            ["safety"] = new JsonObject
            {
                ["credentialsInManifest"] = false,
                ["automaticApproval"] = false,
                ["automaticPublication"] = false,
            },
        };
    }

    private static JsonObject CapacityPolicy() => new()
    {
        ["algorithmVersion"] = "hch-adaptive-capacity-v1",
        ["absoluteRequestedMaximum"] = 64,
        ["defaultNodeCeiling"] = 2,
        ["globalAssignmentCeiling"] = 64,
        ["grantTtlSeconds"] = 300,
        ["telemetryMayOnlyReduce"] = true,
        ["classCeilings"] = new JsonObject
        {
            ["constrained"] = 1,
            ["standard"] = 2,
            ["accelerated"] = 4,
        },
        ["platformClasses"] = new JsonObject
        {
            ["linux"] = "standard",
            ["macos"] = "standard",
            ["windows"] = "standard",
        },
        ["nodeClasses"] = new JsonObject(),
        ["nodeCeilings"] = new JsonObject(),
        ["pressure"] = new JsonObject
        {
            ["softLimitPercent"] = 75,
            ["hardLimitPercent"] = 90,
            ["softReductionFactor"] = 0.5,
        },
    };

    private static JsonObject Artifact(string name, string mediaType, int bytes, char digest) => new()
    {
        ["name"] = name,
        ["mediaType"] = mediaType,
        ["bytes"] = bytes,
        ["sha256"] = new string(digest, 64),
        ["url"] = $"/api/editorial/orchestrator/artifacts/{name}",
        ["authorizationClass"] = "release",
    };

    private static JsonObject Action(string type) => new()
    {
        ["type"] = type,
        ["authorizationClass"] = "release",
    };

    private static JsonObject Tier(string id, int rank, int tokens, string profile, bool minimum) => new()
    {
        ["id"] = id,
        ["rank"] = rank,
        ["maxOutputTokens"] = tokens,
        ["editorialProfile"] = profile,
        ["minimumUnit"] = minimum,
    };

    private static string ComputeAndSetHash(JsonObject manifest)
    {
        var hashless = manifest.DeepClone().AsObject();
        var hash = HchDigest.Sha256Hex(JcsCanonicalizer.Serialize(hashless));
        manifest["hash"] = hash;
        return hash;
    }

    private static async Task<JcsSignatureEnvelope> SignEnvelopeAsync(
        JsonObject header,
        JsonObject payload,
        Ed25519Identity identity)
    {
        var protectedValue = Base64Url(Encoding.UTF8.GetBytes(JcsCanonicalizer.Serialize(header)));
        var payloadValue = Base64Url(Encoding.UTF8.GetBytes(JcsCanonicalizer.Serialize(payload)));
        var input = Encoding.ASCII.GetBytes($"{protectedValue}.{payloadValue}");
        var signature = await identity.SignAsync(input);
        return new JcsSignatureEnvelope
        {
            Protected = protectedValue,
            Payload = payloadValue,
            Signature = Base64Url(signature),
        };
    }

    private static string Base64Url(ReadOnlySpan<byte> value) =>
        Convert.ToBase64String(value).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    private sealed record ManifestFixture(
        ManifestDelivery Delivery,
        ManifestTrustPins Pins,
        string ManifestHash,
        string ContentContractHash);
}
