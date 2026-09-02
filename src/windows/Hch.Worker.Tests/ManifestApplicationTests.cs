using System.Text;
using System.Text.Json;
using Hch.Worker.Persistence;
using Hch.Worker.Protocol;
using Hch.Worker.Service;

namespace Hch.Worker.Tests;

public sealed class ManifestApplicationTests
{
    [Fact]
    public async Task AppliesVerifiedArtifactsAndPersistsExpiryIndependentStateAndReceipt()
    {
        var root = NewRoot();
        try
        {
            var fixture = CreateVerifiedManifest();
            var source = new FakeArtifactSource(fixture.Content);
            var probe = new FakeOllamaProbe();
            var applier = new ManifestArtifactApplier(
                new AtomicFileStore(root),
                source,
                probe,
                new FixedTimeProvider(new DateTimeOffset(2026, 9, 1, 16, 30, 0, TimeSpan.Zero)));

            var result = await applier.ApplyAsync(
                fixture.Verified,
                null,
                new ManifestApplyContext("windows-test", "worker-key:test", "4.0.0"),
                CancellationToken.None);

            Assert.False(result.MetadataOnly);
            Assert.Equal("applied", result.UpdateReceipt.Result);
            Assert.All(result.UpdateReceipt.ArtifactHashes, pair =>
                Assert.Equal(HchDigest.Sha256Hex(fixture.Content[pair.Key]), pair.Value));
            Assert.True(File.Exists(Path.Combine(root, "applied-manifest.json")));
            Assert.True(File.Exists(Path.Combine(root, "receipts", $"{fixture.Verified.Manifest.Hash}.json")));
            var appliedJson = await File.ReadAllTextAsync(Path.Combine(root, "applied-manifest.json"));
            Assert.DoesNotContain("expiresAt", appliedJson, StringComparison.Ordinal);
            Assert.DoesNotContain("signature", appliedJson, StringComparison.OrdinalIgnoreCase);
            Assert.False(File.Exists(Path.Combine(root, "ready.json")));
            Assert.Equal(4, source.DownloadCount);
            Assert.Equal(1, probe.ProbeCount);
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task RestoresEveryPublishedTargetWhenPostWriteModelSelfTestFails()
    {
        var root = NewRoot();
        try
        {
            var fixture = CreateVerifiedManifest();
            var store = new AtomicFileStore(root);
            byte[] previousPolicy = Encoding.UTF8.GetBytes("previous-policy");
            await store.WriteBytesAsync("runtime/editorial/policy.json", previousPolicy);
            var applier = new ManifestArtifactApplier(
                store,
                new FakeArtifactSource(fixture.Content),
                new FakeOllamaProbe(fail: true));

            var error = await Assert.ThrowsAsync<WorkerServiceException>(() => applier.ApplyAsync(
                fixture.Verified,
                null,
                new ManifestApplyContext("windows-test", "worker-key:test", "4.0.0"),
                CancellationToken.None));

            Assert.Equal("model-digest-unavailable", error.Code);
            Assert.Equal(
                previousPolicy,
                await File.ReadAllBytesAsync(Path.Combine(root, "runtime", "editorial", "policy.json")));
            Assert.False(File.Exists(Path.Combine(root, "applied-manifest.json")));
            Assert.False(File.Exists(Path.Combine(root, "receipts", $"{fixture.Verified.Manifest.Hash}.json")));
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task IdenticalAppliedContentIsReverifiedWithoutDownloadingArtifactsAgain()
    {
        var root = NewRoot();
        try
        {
            var fixture = CreateVerifiedManifest();
            var store = new AtomicFileStore(root);
            var firstSource = new FakeArtifactSource(fixture.Content);
            var first = new ManifestArtifactApplier(store, firstSource, new FakeOllamaProbe());
            var initial = await first.ApplyAsync(
                fixture.Verified,
                null,
                new ManifestApplyContext("windows-test", "worker-key:test", "4.0.0"),
                CancellationToken.None);
            var noDownload = new FakeArtifactSource(fixture.Content, failIfCalled: true);
            var refresh = new ManifestArtifactApplier(store, noDownload, new FakeOllamaProbe());

            var result = await refresh.ApplyAsync(
                fixture.Verified,
                initial.AppliedState,
                new ManifestApplyContext("windows-test", "worker-key:test", "4.0.0"),
                CancellationToken.None);

            Assert.True(result.MetadataOnly);
            Assert.Equal("no-change", result.UpdateReceipt.Result);
            Assert.Equal(0, noDownload.DownloadCount);
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    internal static ApplicationFixture CreateVerifiedManifest()
    {
        var content = new Dictionary<string, byte[]>(StringComparer.Ordinal)
        {
            ["policy"] = Encoding.UTF8.GetBytes("{\"ok\":true}"),
            ["prompt"] = Encoding.UTF8.GetBytes("# prompt\n"),
            ["editorial-content-schema"] = Encoding.UTF8.GetBytes("{\"type\":\"object\"}"),
            ["editorial-source-schema"] = Encoding.UTF8.GetBytes("{\"type\":\"object\",\"title\":\"source\"}"),
        };
        var artifacts = content.Select(pair => new
        {
            name = pair.Key,
            mediaType = pair.Key == "prompt" ? "text/markdown" : "application/json",
            bytes = pair.Value.LongLength,
            sha256 = HchDigest.Sha256Hex(pair.Value),
            url = $"/api/editorial/orchestrator/artifacts/{pair.Key}",
            authorizationClass = "release",
        }).ToArray();
        var manifestArtifacts = artifacts.Select(artifact => new ManifestArtifactContract(
            artifact.name,
            artifact.mediaType,
            artifact.bytes,
            artifact.sha256,
            artifact.url,
            artifact.authorizationClass)).ToArray();
        var prelim = BuildManifest(artifacts, compatibility: null);
        var contentHash = ManifestContentContract.ComputeHash(prelim);
        var compatibility = new ManifestCompatibility
        {
            Classification = "initial",
            ContentContractHash = contentHash,
            PreviousContentContractHash = null,
            MinimumWorkerVersion = "3.1.0",
            TestedThroughWorkerVersion = "4.0.0",
            ContentImpact = "none",
        };
        var manifest = BuildManifest(artifacts, compatibility);
        var verified = new VerifiedManifestDelivery(
            manifest,
            JsonSerializer.SerializeToElement(manifest, ProtocolJson.SerializerOptions),
            manifestArtifacts,
            new[]
            {
                new ManifestActionContract("verify-artifact", "release"),
                new ManifestActionContract("configure-engine", "release"),
                new ManifestActionContract("pull-model-by-digest", "release"),
                new ManifestActionContract("apply-editorial-policy", "release"),
                new ManifestActionContract("self-test", "release"),
            },
            "hch-root-v1",
            "SHA256:test-root",
            "release-v1",
            "SHA256:test-release",
            1,
            new string('b', 64),
            contentHash,
            ExpiredFallback: false);
        return new ApplicationFixture(verified, content);
    }

    private static ManifestPayload BuildManifest(object artifacts, ManifestCompatibility? compatibility)
    {
        var generation = Element(new { temperature = 0.2, contextWindow = 8192, maxOutputTokens = 2400 });
        var capacity = Element(new
        {
            algorithmVersion = "hch-adaptive-capacity-v1",
            absoluteRequestedMaximum = 64,
            defaultNodeCeiling = 2,
            globalAssignmentCeiling = 64,
            grantTtlSeconds = 300,
            telemetryMayOnlyReduce = true,
            classCeilings = new { constrained = 1, standard = 2, accelerated = 4 },
            platformClasses = new { linux = "standard", macos = "standard", windows = "standard" },
            nodeClasses = new { },
            nodeCeilings = new { },
            pressure = new { softLimitPercent = 75, hardLimitPercent = 90, softReductionFactor = 0.5 },
        });
        var adaptive = Element(new
        {
            algorithmVersion = "hch-adaptive-work-v1",
            windowMode = "advisory",
            minimumTierIgnoresWindow = true,
            livenessBasis = "progress",
            processingWindowSeconds = 2700,
            nearWindowRatio = 0.8,
            firstProgressGraceSeconds = 900,
            stallAfterSeconds = 600,
            finalizationGraceSeconds = 180,
            tiers = new object[]
            {
                new { id = "minimum", rank = 0, maxOutputTokens = 768, editorialProfile = "EDITORIAL_MINIMUM", minimumUnit = true },
                new { id = "full", rank = 1, maxOutputTokens = 2400, editorialProfile = "EDITORIAL_LONG_FORM", minimumUnit = false },
            },
        });
        return new ManifestPayload
        {
            SchemaVersion = "2.0",
            BootstrapVersion = "2.3.0",
            Sequence = 1,
            ReleaseId = "hch-editorial-test.1",
            IssuedAt = "2026-09-01T16:00:00.0000000+00:00",
            ExpiresAt = "2026-10-01T16:00:00.0000000+00:00",
            MinimumAcceptedSequence = 1,
            PreviousManifestHash = null,
            Runtime = new WorkerRuntimeManifest
            {
                WorkerVersion = "3.1.0",
                SupportedPlatforms = ["linux", "macos", "windows"],
            },
            Compatibility = compatibility,
            Engine = new EngineManifest
            {
                Provider = "ollama",
                Adapter = "ollama-chat",
                AdapterVersion = "1.0.0",
                Model = "qwen3:8b",
                ModelDigest = new string('5', 64),
                Protocol = "ollama-chat-v1",
                AdditionalProperties = new Dictionary<string, JsonElement>
                {
                    ["healthPath"] = Element("/api/tags"),
                },
            },
            Generation = generation,
            CapacityPolicy = capacity,
            AdaptiveWorkPolicy = adaptive,
            Editorial = new EditorialManifest
            {
                PipelineVersion = "1.0.0",
                PolicyHash = new string('6', 64),
                PromptConfigHash = new string('7', 64),
                AdditionalProperties = new Dictionary<string, JsonElement>
                {
                    ["policyId"] = Element("hch-editorial"),
                    ["policyVersion"] = Element("1.0.0"),
                },
            },
            Actions = Element(new[]
            {
                new { type = "verify-artifact", authorizationClass = "release" },
                new { type = "configure-engine", authorizationClass = "release" },
                new { type = "pull-model-by-digest", authorizationClass = "release" },
                new { type = "apply-editorial-policy", authorizationClass = "release" },
                new { type = "self-test", authorizationClass = "release" },
            }),
            RootActionCapabilities = Element(Array.Empty<object>()),
            Artifacts = Element(artifacts),
            Endpoints = Element(new { }),
            Security = Element(new { authorizationByIp = false, arbitraryRemoteCommands = false }),
            Safety = Element(new
            {
                credentialsInManifest = false,
                automaticApproval = false,
                automaticPublication = false,
            }),
            HashAlgorithm = "sha256",
            Hash = new string('a', 64),
            AdditionalProperties = new Dictionary<string, JsonElement>
            {
                ["protocolVersion"] = Element("2.0"),
            },
        };
    }

    private static JsonElement Element<T>(T value) =>
        JsonSerializer.SerializeToElement(value, ProtocolJson.SerializerOptions);

    private static string NewRoot()
    {
        var path = Path.Combine(Path.GetTempPath(), $"hch-apply-{Guid.NewGuid():N}");
        Directory.CreateDirectory(path);
        return path;
    }

    internal sealed class FakeArtifactSource(
        IReadOnlyDictionary<string, byte[]> content,
        bool failIfCalled = false) : IManifestArtifactSource
    {
        public int DownloadCount { get; private set; }

        public Task<ManifestArtifactDownload> DownloadAsync(
            ManifestArtifactContract artifact,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            DownloadCount++;
            if (failIfCalled)
            {
                throw new InvalidOperationException("artifact-download-not-expected");
            }

            var mediaType = artifact.Name == "prompt" ? "text/markdown; charset=utf-8" : "application/json";
            return Task.FromResult(new ManifestArtifactDownload(content[artifact.Name].ToArray(), mediaType));
        }
    }

    internal sealed class FakeOllamaProbe(bool fail = false) : IOllamaManifestProbe
    {
        public int ProbeCount { get; private set; }

        public Task<OllamaManifestProbeResult> VerifyExactModelAsync(
            string model,
            string modelDigest,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ProbeCount++;
            if (fail)
            {
                throw new WorkerServiceException(
                    "model-digest-unavailable",
                    "The exact model is unavailable.");
            }

            Assert.Equal("qwen3:8b", model);
            Assert.Equal(new string('5', 64), modelDigest);
            return Task.FromResult(new OllamaManifestProbeResult("0.11.8"));
        }
    }

    internal sealed class FixedTimeProvider(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => now;
    }

    internal sealed record ApplicationFixture(
        VerifiedManifestDelivery Verified,
        IReadOnlyDictionary<string, byte[]> Content);
}
