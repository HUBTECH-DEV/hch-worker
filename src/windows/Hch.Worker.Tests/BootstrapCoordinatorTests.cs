using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Hch.Worker.Persistence;
using Hch.Worker.Protocol;
using Hch.Worker.Security;
using Hch.Worker.Service;

namespace Hch.Worker.Tests;

public sealed class BootstrapCoordinatorTests
{
    private static readonly DateTimeOffset Now = new(2026, 9, 1, 16, 30, 0, TimeSpan.Zero);

    [Fact]
    public async Task CompletesPinnedBootstrapAndAttestationWithoutStartingWork()
    {
        var rootPath = NewRoot();
        using var rootIdentity = Ed25519Identity.Generate();
        using var releaseIdentity = Ed25519Identity.Generate();
        try
        {
            var fixture = ManifestApplicationTests.CreateVerifiedManifest();
            var signed = await SignDeliveryAsync(fixture.Verified.Manifest, rootIdentity, releaseIdentity);
            var client = new FakeBootstrapClient(signed.Delivery, signed.ManifestHash, signed.ContentContractHash);
            var files = new AtomicFileStore(rootPath);
            var applier = new ManifestArtifactApplier(
                files,
                new ManifestApplicationTests.FakeArtifactSource(fixture.Content),
                new ManifestApplicationTests.FakeOllamaProbe(),
                new ManifestApplicationTests.FixedTimeProvider(Now));
            var coordinator = new BootstrapAttestationCoordinator(
                files,
                client,
                applier,
                signed.Pins,
                rootIdentity,
                new ManifestApplicationTests.FixedTimeProvider(Now));

            var result = await coordinator.RunPausedAsync(
                Request(activeAssignments: 0),
                CancellationToken.None);

            Assert.Equal("draining", result.State);
            Assert.False(result.WorkStarted);
            Assert.Equal(signed.ManifestHash, result.ManifestHash);
            Assert.Equal(signed.ContentContractHash, result.ContentContractHash);
            Assert.Equal(1, client.BootstrapCalls);
            Assert.Equal(1, client.AttestationCalls);
            var ready = await files.ReadJsonAsync<WorkerReadyStateRecord>("ready.json");
            Assert.NotNull(ready);
            Assert.True(ready.Ready);
            Assert.Equal(0, ready.RequestedCapacity);
            Assert.Equal(0, ready.GrantedCapacity);
            Assert.Equal("drain-requested", ready.CapacityReason);
            var appliedText = await File.ReadAllTextAsync(files.Resolve("applied-manifest.json"));
            Assert.DoesNotContain("expiresAt", appliedText, StringComparison.Ordinal);
        }
        finally
        {
            Directory.Delete(rootPath, recursive: true);
        }
    }

    [Fact]
    public async Task ContentChangingManifestWithActiveWorkEntersDrainBeforeBootstrapOrApply()
    {
        var rootPath = NewRoot();
        using var rootIdentity = Ed25519Identity.Generate();
        using var releaseIdentity = Ed25519Identity.Generate();
        try
        {
            var fixture = ManifestApplicationTests.CreateVerifiedManifest();
            var signed = await SignDeliveryAsync(fixture.Verified.Manifest, rootIdentity, releaseIdentity);
            var client = new FakeBootstrapClient(signed.Delivery, signed.ManifestHash, signed.ContentContractHash);
            var files = new AtomicFileStore(rootPath);
            var coordinator = new BootstrapAttestationCoordinator(
                files,
                client,
                new ManifestArtifactApplier(
                    files,
                    new ManifestApplicationTests.FakeArtifactSource(fixture.Content, failIfCalled: true),
                    new ManifestApplicationTests.FakeOllamaProbe()),
                signed.Pins,
                rootIdentity,
                new ManifestApplicationTests.FixedTimeProvider(Now));

            var error = await Assert.ThrowsAsync<WorkerServiceException>(() => coordinator.RunPausedAsync(
                Request(activeAssignments: 1),
                CancellationToken.None));

            Assert.Equal("manifest-content-update-draining", error.Code);
            Assert.Equal(0, client.BootstrapCalls);
            Assert.Equal(0, client.AttestationCalls);
            using var ready = JsonDocument.Parse(await File.ReadAllBytesAsync(files.Resolve("ready.json")));
            Assert.False(ready.RootElement.GetProperty("ready").GetBoolean());
            Assert.Equal(
                "manifest-content-update-required",
                ready.RootElement.GetProperty("reason").GetString());
            Assert.False(File.Exists(files.Resolve("applied-manifest.json")));
        }
        finally
        {
            Directory.Delete(rootPath, recursive: true);
        }
    }

    [Fact]
    public async Task ContentChangingBootstrapRevokesOldReadyCommitBeforeAttestationCanFail()
    {
        var rootPath = NewRoot();
        using var rootIdentity = Ed25519Identity.Generate();
        using var releaseIdentity = Ed25519Identity.Generate();
        try
        {
            var fixture = ManifestApplicationTests.CreateVerifiedManifest();
            var signed = await SignDeliveryAsync(fixture.Verified.Manifest, rootIdentity, releaseIdentity);
            var client = new FakeBootstrapClient(
                signed.Delivery,
                signed.ManifestHash,
                signed.ContentContractHash,
                failAttestation: true);
            var files = new AtomicFileStore(rootPath);
            await files.WriteJsonAsync("ready.json", new
            {
                schemaVersion = 1,
                ready = true,
                marker = "must-not-survive",
            });
            var coordinator = new BootstrapAttestationCoordinator(
                files,
                client,
                new ManifestArtifactApplier(
                    files,
                    new ManifestApplicationTests.FakeArtifactSource(fixture.Content),
                    new ManifestApplicationTests.FakeOllamaProbe(),
                    new ManifestApplicationTests.FixedTimeProvider(Now)),
                signed.Pins,
                rootIdentity,
                new ManifestApplicationTests.FixedTimeProvider(Now));

            var error = await Assert.ThrowsAsync<OrchestratorRequestException>(
                () => coordinator.RunPausedAsync(Request(activeAssignments: 0), CancellationToken.None));

            Assert.Equal("network-request-failed", error.Code);
            using var ready = JsonDocument.Parse(await File.ReadAllBytesAsync(files.Resolve("ready.json")));
            Assert.False(ready.RootElement.GetProperty("ready").GetBoolean());
            Assert.Equal(
                "manifest-content-update-required",
                ready.RootElement.GetProperty("reason").GetString());
            Assert.False(ready.RootElement.TryGetProperty("marker", out _));
            Assert.True(File.Exists(files.Resolve("applied-manifest.json")));
        }
        finally
        {
            Directory.Delete(rootPath, recursive: true);
        }
    }

    private static BootstrapCoordinatorRequest Request(int activeAssignments) => new(
        "windows-test",
        "worker-key:test",
        "X64",
        "WINDOWS-TEST",
        "4.0.0",
        Guid.NewGuid().ToString("D"),
        Guid.NewGuid().ToString("D"),
        activeAssignments);

    private static async Task<SignedFixture> SignDeliveryAsync(
        ManifestPayload manifest,
        Ed25519Identity root,
        Ed25519Identity release)
    {
        var raw = JsonNode.Parse(JsonSerializer.Serialize(manifest, ProtocolJson.SerializerOptions))!.AsObject();
        _ = raw.Remove("hash");
        var manifestHash = HchDigest.Sha256Hex(JcsCanonicalizer.Serialize(raw));
        raw["hash"] = manifestHash;
        var contentHash = ManifestContentContract.ComputeHash(manifest);
        var expires = Now.AddDays(7);
        var delegationPayload = new JsonObject
        {
            ["expires"] = expires.ToUnixTimeSeconds(),
            ["fingerprint"] = release.Fingerprint,
            ["notBefore"] = Now.ToUnixTimeSeconds(),
            ["permissions"] = new JsonArray("sign-editorial-manifest"),
            ["publicKey"] = new JsonObject
            {
                ["crv"] = "Ed25519",
                ["kty"] = "OKP",
                ["x"] = Base64Url(Ed25519KeyEncoding.GetRawPublicKey(release.ExportSubjectPublicKeyInfo())),
            },
            ["releaseKeyId"] = "release-v1",
            ["sequence"] = 1,
            ["type"] = SignedManifestVerifier.DelegationSignatureType,
            ["version"] = 1,
        };
        var delegationHeader = Header(
            SignedManifestVerifier.DelegationSignatureType,
            "hch-root-v1",
            "root",
            expires);
        var manifestHeader = Header(
            SignedManifestVerifier.ManifestSignatureType,
            "release-v1",
            "release",
            expires);
        var delivery = new ManifestDelivery
        {
            Manifest = await SignEnvelopeAsync(manifestHeader, raw, release),
            Delegation = await SignEnvelopeAsync(delegationHeader, delegationPayload, root),
            RootKeyId = "hch-root-v1",
            RootPublicKeyFingerprint = root.Fingerprint,
        };
        return new SignedFixture(
            delivery,
            new ManifestTrustPins(
                "hch-root-v1",
                root.Fingerprint,
                root.ExportSubjectPublicKeyInfo()),
            manifestHash,
            contentHash);
    }

    private static JsonObject Header(string type, string keyId, string role, DateTimeOffset expires) => new()
    {
        ["alg"] = "EdDSA",
        ["c14n"] = "RFC8785",
        ["cty"] = "application/json",
        ["exp"] = expires.ToUnixTimeSeconds(),
        ["hch"] = type,
        ["iat"] = Now.ToUnixTimeSeconds(),
        ["kid"] = keyId,
        ["role"] = role,
        ["typ"] = "application/hch+jws+jcs",
    };

    private static async Task<JcsSignatureEnvelope> SignEnvelopeAsync(
        JsonObject header,
        JsonObject payload,
        Ed25519Identity identity)
    {
        var protectedValue = Base64Url(Encoding.UTF8.GetBytes(JcsCanonicalizer.Serialize(header)));
        var payloadValue = Base64Url(Encoding.UTF8.GetBytes(JcsCanonicalizer.Serialize(payload)));
        var signature = await identity.SignAsync(
            Encoding.ASCII.GetBytes($"{protectedValue}.{payloadValue}"));
        return new JcsSignatureEnvelope
        {
            Protected = protectedValue,
            Payload = payloadValue,
            Signature = Base64Url(signature),
        };
    }

    private static string Base64Url(ReadOnlySpan<byte> value) =>
        Convert.ToBase64String(value).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    private static string NewRoot()
    {
        var path = Path.Combine(Path.GetTempPath(), $"hch-bootstrap-{Guid.NewGuid():N}");
        Directory.CreateDirectory(path);
        return path;
    }

    private sealed class FakeBootstrapClient(
        ManifestDelivery delivery,
        string manifestHash,
        string contentContractHash,
        bool failAttestation = false) : IWorkerBootstrapClient
    {
        private readonly string sessionId = Guid.NewGuid().ToString("D");
        private ManifestPayload? parsedManifest;

        public int BootstrapCalls { get; private set; }

        public int AttestationCalls { get; private set; }

        public Task<ManifestDelivery> FetchManifestAsync(CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return Task.FromResult(delivery);
        }

        public Task<BootstrapResponseContract> BootstrapAsync(
            BootstrapRequestContract request,
            string requestId,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            BootstrapCalls++;
            Assert.Equal(0, request.RequestedCapacity);
            Assert.Equal("windows", request.Platform);
            Assert.True(Guid.TryParseExact(requestId, "D", out _));
            parsedManifest ??= ParseManifestEcho();
            return Task.FromResult(new BootstrapResponseContract
            {
                BootstrapSessionId = sessionId,
                State = "awaiting-attestation",
                ExpiresAt = Now.AddMinutes(15).ToString("O"),
                Challenge = "bootstrap-challenge-00000001",
                ManifestSequence = 1,
                ManifestHash = manifestHash,
                Manifest = delivery,
                RequestedCapacity = 0,
                CapacityPolicy = parsedManifest.CapacityPolicy,
                AdaptiveWorkPolicy = parsedManifest.AdaptiveWorkPolicy!.Value,
                AttestationUrl = $"/api/editorial/orchestrator/bootstrap/{sessionId}/attest",
                WorkEnabled = false,
            });
        }

        public Task<AttestationResponseContract> AttestAsync(
            string bootstrapSessionId,
            AttestationRequestContract request,
            string requestId,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            AttestationCalls++;
            Assert.Equal(sessionId, bootstrapSessionId);
            Assert.Equal(manifestHash, request.ManifestHash);
            Assert.Equal(contentContractHash, request.ContentContractHash);
            Assert.Equal("hch-root-v1", request.RootKeyId);
            Assert.Equal("release-v1", request.ReleaseKeyId);
            Assert.Equal("applied", request.UpdateReceipt.Result);
            Assert.True(Guid.TryParseExact(requestId, "D", out _));
            if (failAttestation)
            {
                return Task.FromException<AttestationResponseContract>(
                    new OrchestratorRequestException(
                        "network-request-failed",
                        null,
                        retryable: true,
                        outcomeUnknown: true));
            }

            return Task.FromResult(new AttestationResponseContract
            {
                NodeId = request.NodeId,
                WorkerKeyId = request.WorkerKeyId,
                Compatible = true,
                State = "draining",
                ManifestSequence = request.ManifestSequence,
                ManifestHash = request.ManifestHash,
                ContentContractHash = request.ContentContractHash,
                ReadyUntil = Now.AddHours(1).ToString("O"),
                Capacity = new AttestedCapacityGrantContract
                {
                    RequestedCapacity = 0,
                    GrantedCapacity = 0,
                    CapacityClass = "standard",
                    Reason = "drain-requested",
                    GrantedUntil = Now.AddMinutes(5).ToString("O"),
                },
                Update = JsonSerializer.SerializeToElement(new
                {
                    available = false,
                    latestVersion = "4.0.0",
                }, ProtocolJson.SerializerOptions),
                ServerTime = Now.ToString("O"),
            });
        }

        private ManifestPayload ParseManifestEcho()
        {
            // This helper is only used after the coordinator has verified the
            // delivery. Decode the canonical payload to expose policy echoes.
            var bytes = DecodeBase64Url(delivery.Manifest.Payload);
            using var document = JsonDocument.Parse(bytes);
            var payload = document.RootElement;
            return new ManifestPayload
            {
                SchemaVersion = payload.GetProperty("schemaVersion").GetString()!,
                BootstrapVersion = payload.GetProperty("bootstrapVersion").GetString()!,
                Sequence = payload.GetProperty("sequence").GetInt64(),
                ReleaseId = payload.GetProperty("releaseId").GetString()!,
                IssuedAt = payload.GetProperty("issuedAt").GetString()!,
                ExpiresAt = payload.GetProperty("expiresAt").GetString()!,
                MinimumAcceptedSequence = payload.GetProperty("minimumAcceptedSequence").GetInt64(),
                PreviousManifestHash = null,
                Runtime = new WorkerRuntimeManifest { WorkerVersion = "3.1.0" },
                Engine = new EngineManifest
                {
                    Provider = "ollama",
                    Adapter = "ollama-chat",
                    AdapterVersion = "1.0.0",
                    Model = "qwen3:8b",
                    ModelDigest = new string('5', 64),
                    Protocol = "ollama-chat-v1",
                },
                Generation = payload.GetProperty("generation").Clone(),
                CapacityPolicy = payload.GetProperty("capacityPolicy").Clone(),
                AdaptiveWorkPolicy = payload.GetProperty("adaptiveWorkPolicy").Clone(),
                Editorial = new EditorialManifest
                {
                    PipelineVersion = "1.0.0",
                    PolicyHash = new string('6', 64),
                    PromptConfigHash = new string('7', 64),
                },
                Actions = payload.GetProperty("actions").Clone(),
                RootActionCapabilities = payload.GetProperty("rootActionCapabilities").Clone(),
                Artifacts = payload.GetProperty("artifacts").Clone(),
                Endpoints = payload.GetProperty("endpoints").Clone(),
                Security = payload.GetProperty("security").Clone(),
                Safety = payload.GetProperty("safety").Clone(),
                HashAlgorithm = "sha256",
                Hash = manifestHash,
            };
        }

        private static byte[] DecodeBase64Url(string value)
        {
            var padded = value.Replace('-', '+').Replace('_', '/');
            padded += new string('=', (4 - padded.Length % 4) % 4);
            return Convert.FromBase64String(padded);
        }
    }

    private sealed record SignedFixture(
        ManifestDelivery Delivery,
        ManifestTrustPins Pins,
        string ManifestHash,
        string ContentContractHash);
}
