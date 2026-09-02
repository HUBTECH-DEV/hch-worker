using System.Text.Json;
using Hch.Worker.Protocol;

namespace Hch.Worker.Tests;

public sealed class ProtocolContractsTests
{
    private const string ContentContractHash = "49f1c6f9954abc475772e92d3729d511c4906f747be4eac6414d5816bccdef71";
    private const string PlanHash = "df4e796abf58fd16b43c8c9d503cdc39c62cfe36fdff2c3a7c4670a547dd460a";
    private const string ProfileHash = "f94f451c51c302da3a38cbe3586c6636534ed082ffa928b0c248c3d9356a414c";

    [Fact]
    public void MatchesTheRepositoryManifestContentProjectionGoldenHash()
    {
        var manifest = CreateManifest();

        Assert.Equal(ContentContractHash, ManifestContentContract.ComputeHash(manifest));
        ManifestContractValidator.Validate(manifest);
    }

    [Fact]
    public void CompatibleVersionOnlyAnnouncesUpdateAndDoesNotStopClaims()
    {
        var manifest = CreateManifest(workerVersion: "4.0.0", testedThrough: "4.0.0");

        var evaluation = ManifestContractValidator.Evaluate(manifest, "3.1.0");

        Assert.Equal(ManifestRuntimeDisposition.UpdateAvailableContinue, evaluation.Disposition);
        Assert.True(evaluation.MayClaim);
        Assert.True(evaluation.UpdateAvailable);
    }

    [Fact]
    public void OnlyExplicitGeneratedContentIncompatibilityBlocksCompatibleRange()
    {
        var manifest = CreateManifest(
            workerVersion: "4.0.0",
            classification: "content-incompatible",
            previousHash: new string('a', 64),
            contentImpact: "generated-content",
            testedThrough: "4.0.0");

        var evaluation = ManifestContractValidator.Evaluate(manifest, "4.0.0");

        Assert.Equal(ManifestRuntimeDisposition.GeneratedContentIncompatible, evaluation.Disposition);
        Assert.False(evaluation.MayClaim);
    }

    [Fact]
    public void ExplicitAcceptedWorkerVersionsAreAuthoritative()
    {
        var manifest = CreateManifest(
            workerVersion: "4.0.0",
            testedThrough: "4.0.0",
            acceptedWorkerVersions: ["4.0.0"]);

        var evaluation = ManifestContractValidator.Evaluate(manifest, "3.1.0");

        Assert.Equal(ManifestRuntimeDisposition.WorkerVersionNotAccepted, evaluation.Disposition);
        Assert.False(evaluation.MayClaim);
        Assert.True(evaluation.UpdateAvailable);
        Assert.Equal("worker-version-not-accepted", evaluation.Reason);
    }

    [Fact]
    public void RejectsMissingOrUntruthfulBootstrapCompatibility()
    {
        var missing = CreateManifest(compatibility: false);
        Assert.Equal(
            "manifest-compatibility-missing",
            Assert.Throws<ProtocolValidationException>(() => ManifestContractValidator.Validate(missing)).Code);

        var untruthful = CreateManifest(declaredHash: new string('f', 64), previousHash: new string('f', 64));
        Assert.Equal(
            "manifest-content-contract-hash-mismatch",
            Assert.Throws<ProtocolValidationException>(() => ManifestContractValidator.Validate(untruthful)).Code);
    }

    [Fact]
    public void StrictDeserializerRejectsDuplicateAndUnknownAssignmentFields()
    {
        const string duplicate = "{\"phase\":\"starting\",\"attempt\":1,\"attempt\":2,\"sequence\":0,\"contentBytes\":0}";
        Assert.Equal(
            "jcs-duplicate-property",
            Assert.Throws<ProtocolValidationException>(() => ProtocolJson.Deserialize<AssignmentProgress>(duplicate)).Code);

        const string unknown = "{\"phase\":\"starting\",\"attempt\":1,\"sequence\":0,\"contentBytes\":0,\"leaseToken\":\"secret\"}";
        Assert.Equal(
            "protocol-json-contract-invalid",
            Assert.Throws<ProtocolValidationException>(() => ProtocolJson.Deserialize<AssignmentProgress>(unknown)).Code);
    }

    [Fact]
    public void ValidatesAssignmentGoldenHashesAndLease()
    {
        var assignment = CreateAssignment();

        AssignmentContractValidator.Validate(
            assignment,
            DateTimeOffset.Parse("2029-12-31T23:59:00Z", System.Globalization.CultureInfo.InvariantCulture));
    }

    [Fact]
    public void ProgressAndHeartbeatUseSignedPlanTimers()
    {
        var assignment = CreateAssignment();
        var progress = new AssignmentProgress
        {
            Phase = "responding",
            Attempt = 1,
            Sequence = 9,
            ContentBytes = 2048,
        };
        AssignmentContractValidator.Validate(progress);

        var heartbeat = new AssignmentHeartbeatResponse
        {
            AssignmentId = assignment.AssignmentId,
            GenerationPlanHash = assignment.GenerationPlanHash,
            ServerTime = "2030-01-01T00:01:00.000Z",
            LeaseExpiresAt = "2030-01-01T00:06:00.000Z",
            Liveness = new AssignmentLiveness
            {
                State = "responding",
                LastProgressAt = "2030-01-01T00:00:55.000Z",
                StaleAfterSeconds = assignment.GenerationPlan.StallAfterSeconds,
            },
            WorkSizing = new AssignmentWorkSizing
            {
                CurrentTier = "compact",
                CurrentRank = 1,
                Reason = "near-window-downshift",
            },
        };
        AssignmentContractValidator.Validate(heartbeat, assignment);

        heartbeat = new AssignmentHeartbeatResponse
        {
            AssignmentId = heartbeat.AssignmentId,
            GenerationPlanHash = heartbeat.GenerationPlanHash,
            ServerTime = heartbeat.ServerTime,
            LeaseExpiresAt = heartbeat.LeaseExpiresAt,
            Liveness = new AssignmentLiveness
            {
                State = "responding",
                LastProgressAt = heartbeat.Liveness.LastProgressAt,
                StaleAfterSeconds = assignment.GenerationPlan.StallAfterSeconds + 1,
            },
            WorkSizing = heartbeat.WorkSizing,
        };
        Assert.Equal(
            "orchestrator-heartbeat-liveness-grace-invalid",
            Assert.Throws<ProtocolValidationException>(() =>
                AssignmentContractValidator.Validate(heartbeat, assignment)).Code);
    }

    [Theory]
    [InlineData("starting", 1, 1, 0, "assignment-progress-starting-invalid")]
    [InlineData("responding", 1, 0, 0, "assignment-progress-response-empty")]
    [InlineData("responding", 9, 1, 1, "assignment-progress-value-invalid")]
    public void RejectsInvalidProgress(string phase, int attempt, long sequence, long bytes, string code)
    {
        var progress = new AssignmentProgress
        {
            Phase = phase,
            Attempt = attempt,
            Sequence = sequence,
            ContentBytes = bytes,
        };

        Assert.Equal(
            code,
            Assert.Throws<ProtocolValidationException>(() => AssignmentContractValidator.Validate(progress)).Code);
    }

    [Theory]
    [InlineData("2030-01-01", false)]
    [InlineData("01/09/2030 12:00:00", false)]
    [InlineData("2030-01-01T00:00:00Z", true)]
    [InlineData("2030-01-01T00:00:00.1234567-03:00", true)]
    public void ParsesOnlyExplicitCultureInvariantProtocolTimestamps(string value, bool valid)
    {
        if (valid)
        {
            _ = ProtocolTime.ParseTimestamp(value);
        }
        else
        {
            Assert.Throws<ProtocolValidationException>(() => ProtocolTime.ParseTimestamp(value));
        }
    }

    private static ManifestPayload CreateManifest(
        string workerVersion = "3.1.0",
        bool compatibility = true,
        string classification = "compatible",
        string? declaredHash = null,
        string? previousHash = null,
        string contentImpact = "none",
        string testedThrough = "3.1.0",
        IReadOnlyList<string>? acceptedWorkerVersions = null)
    {
        declaredHash ??= ContentContractHash;
        previousHash = classification.Equals("initial", StringComparison.Ordinal) ? null : previousHash ?? declaredHash;
        return new ManifestPayload
        {
            SchemaVersion = "2.0",
            BootstrapVersion = "2.3.0",
            Sequence = 7,
            ReleaseId = "hch-editorial-2030-01",
            IssuedAt = "2030-01-01T00:00:00.000Z",
            ExpiresAt = "2030-02-01T00:00:00.000Z",
            MinimumAcceptedSequence = 1,
            PreviousManifestHash = null,
            Runtime = new WorkerRuntimeManifest
            {
                WorkerVersion = workerVersion,
                SupportedPlatforms = ["linux", "macos", "windows"],
            },
            Compatibility = compatibility ? new ManifestCompatibility
            {
                Classification = classification,
                ContentContractHash = declaredHash,
                PreviousContentContractHash = previousHash,
                MinimumWorkerVersion = "2.2.0",
                TestedThroughWorkerVersion = testedThrough,
                AcceptedWorkerVersions = acceptedWorkerVersions,
                ContentImpact = contentImpact,
            } : null,
            Engine = new EngineManifest
            {
                Provider = "vps-local",
                Adapter = "ollama-chat",
                AdapterVersion = "1.0.0",
                Model = "qwen2.5:1.5b-instruct",
                ModelDigest = new string('b', 64),
                Protocol = "ollama-chat",
            },
            Generation = Element("{\"temperature\":0.2,\"contextWindow\":8192,\"maxOutputTokens\":2400}"),
            CapacityPolicy = Element("{\"defaultNodeCeiling\":16}"),
            AdaptiveWorkPolicy = Element("{\"algorithmVersion\":\"hch-adaptive-work-v1\",\"processingWindowSeconds\":2700}"),
            Editorial = new EditorialManifest
            {
                PipelineVersion = "editorial-v1",
                PolicyHash = new string('c', 64),
                PromptConfigHash = new string('d', 64),
            },
            Actions = Element("[]"),
            RootActionCapabilities = Element("[]"),
            Artifacts = Element($"[{{\"name\":\"editorial-policy.json\",\"sha256\":\"{new string('e', 64)}\"}}]"),
            Endpoints = Element("{}"),
            Security = Element("{}"),
            Safety = Element("{}"),
            HashAlgorithm = "sha256",
            Hash = new string('f', 64),
        };
    }

    private static WorkerAssignment CreateAssignment()
    {
        var plan = new GenerationPlan
        {
            AlgorithmVersion = "hch-adaptive-work-v1",
            TierId = "full",
            TierRank = 2,
            MaxOutputTokens = 2400,
            EditorialProfile = "EDITORIAL_LONG_FORM",
            MinimumUnit = false,
            ProcessingWindowSeconds = 2700,
            NearWindowSeconds = 2160,
            FirstProgressGraceSeconds = 900,
            StallAfterSeconds = 600,
            FinalizationGraceSeconds = 180,
            PolicyHash = new string('c', 64),
        };
        var profile = new WorkerRuntimeProfile
        {
            Provider = "vps-local",
            EngineAdapter = "ollama-chat",
            EngineAdapterVersion = "1.0.0",
            Model = "qwen2.5:1.5b-instruct",
            ModelDigest = new string('b', 64),
            Protocol = "ollama-chat",
            Temperature = 0.2,
            ContextWindow = 8192,
            MaxOutputTokens = 2400,
            PolicyId = "editorial-policy",
            PolicyVersion = "1.0.0",
            PolicyHash = new string('c', 64),
            PromptConfigHash = new string('d', 64),
            PipelineVersion = "editorial-v1",
            ManifestSequence = 7,
            ManifestHash = new string('a', 64),
            RuntimeProfileHash = ProfileHash,
        };
        return new WorkerAssignment
        {
            AssignmentId = "01234567-89ab-cdef-0123-456789abcdef",
            LeaseToken = "lease-token-redacted-value",
            LeaseExpiresAt = "2030-01-01T00:05:00.000Z",
            Status = "processing",
            InputSnapshotHash = "7920348c51b62652150c69c2bf5f7eda84993d434e57ba8c84be35b4eaa330f1",
            Entry = Element("{\"entryId\":\"entry-1\"}"),
            RuntimeProfile = profile,
            GenerationPlan = plan,
            GenerationPlanHash = PlanHash,
        };
    }

    private static JsonElement Element(string json) => JsonDocument.Parse(json).RootElement.Clone();
}
