using System.Net;
using System.Text;
using Hch.Worker.Protocol;
using Hch.Worker.Security;
using Hch.Worker.Service;

namespace Hch.Worker.Tests;

public sealed class ServiceTransportTests
{
    private static readonly DateTimeOffset Now = new(2026, 9, 1, 12, 0, 0, TimeSpan.Zero);

    [Fact]
    public async Task ClaimUsesSignedChallengeExactJcsAndCorrelatedRequestId()
    {
        using var identity = Ed25519Identity.Generate();
        var operationId = Guid.NewGuid().ToString("D");
        var challengeId = Guid.NewGuid().ToString("D");
        var handler = new RecordingHandler(async request =>
        {
            var body = await request.Content!.ReadAsByteArrayAsync();
            if (request.RequestUri!.AbsolutePath.EndsWith("/challenge", StringComparison.Ordinal))
            {
                return Json(new ChallengeResponse
                {
                    NodeId = "node-1",
                    KeyId = identity.Fingerprint,
                    Purpose = "claim",
                    Nonce = "server-0123456789abcdef0123456789abcdef",
                    ExpiresAt = Now.AddMinutes(5).ToString("O"),
                    SignatureProfile = HchHttpMessageSignatures.SignatureTag,
                });
            }

            Assert.Equal(
                "{\"nodeId\":\"node-1\",\"requestedCapacity\":1,\"workerKeyId\":\"" +
                identity.Fingerprint + "\"}",
                Encoding.UTF8.GetString(body));
            return Json(new ClaimResponse
            {
                RequestId = operationId,
                NodeId = "node-1",
                Assignments = [],
                Capacity = new CapacityDecision
                {
                    RequestedCapacity = 1,
                    GrantedCapacity = 1,
                    AvailableSlots = 1,
                    ActiveAssignments = 0,
                    Reason = "requested-capacity-granted",
                    GrantedUntil = Now.AddMinutes(2).ToString("O"),
                },
                Replayed = false,
                ServerTime = Now.ToString("O"),
            });
        });
        using var http = new HttpClient(handler);
        var client = new SignedOrchestratorClient(
            http,
            new Uri("https://hubtech.online/"),
            "node-1",
            identity.Fingerprint,
            identity,
            new FixedTimeProvider(Now),
            new FixedIdentifiers([operationId, challengeId]));

        var response = await client.ClaimAsync(1, CancellationToken.None);

        Assert.Equal(operationId, response.RequestId);
        Assert.Equal(2, handler.Requests.Count);
        var challenge = handler.Requests[0];
        Assert.Equal(
            $"{{\"keyId\":\"{identity.Fingerprint}\",\"nodeId\":\"node-1\",\"purpose\":\"claim\"}}",
            Encoding.UTF8.GetString(challenge.Body));
        Assert.Equal(challengeId, challenge.Headers["X-HCH-Request-Id"]);
        Assert.StartsWith("client-", challenge.Headers["X-HCH-Nonce"], StringComparison.Ordinal);
        Assert.True(HchDigest.MatchesContentDigest(challenge.Headers["Content-Digest"], challenge.Body));
        Assert.Contains("tag=\"hch-editorial-worker-request/v1\"", challenge.Headers["Signature-Input"]);
        Assert.Equal(operationId, handler.Requests[1].Headers["X-HCH-Request-Id"]);
        Assert.Equal("server-0123456789abcdef0123456789abcdef", handler.Requests[1].Headers["X-HCH-Nonce"]);
    }

    [Fact]
    public async Task CompletionRetryKeepsOneIdempotencyRequestId()
    {
        using var identity = Ed25519Identity.Generate();
        var operationId = Guid.NewGuid().ToString("D");
        var challengeIds = new[] { Guid.NewGuid().ToString("D"), Guid.NewGuid().ToString("D") };
        var completions = 0;
        var handler = new RecordingHandler(request =>
        {
            if (request.RequestUri!.AbsolutePath.EndsWith("/challenge", StringComparison.Ordinal))
            {
                return Task.FromResult(Json(new ChallengeResponse
                {
                    NodeId = "node-1",
                    KeyId = identity.Fingerprint,
                    Purpose = "complete",
                    Nonce = "server-0123456789abcdef0123456789abcdef",
                    ExpiresAt = Now.AddMinutes(5).ToString("O"),
                    SignatureProfile = HchHttpMessageSignatures.SignatureTag,
                }));
            }

            completions++;
            if (completions == 1)
            {
                return Task.FromResult(Json(new { code = "temporary-control-plane-error" }, HttpStatusCode.ServiceUnavailable));
            }

            var assignment = Assignment();
            return Task.FromResult(Json(new CompleteAssignmentResponse
            {
                AssignmentId = assignment.AssignmentId,
                GenerationPlanHash = assignment.GenerationPlanHash,
                CommitAccepted = true,
                Status = "pending-review",
                AutomaticApproval = false,
                AutomaticPublication = false,
                Replayed = true,
                ServerTime = Now.ToString("O"),
            }));
        });
        using var http = new HttpClient(handler);
        var client = new SignedOrchestratorClient(
            http,
            new Uri("https://hubtech.online/"),
            "node-1",
            identity.Fingerprint,
            identity,
            new FixedTimeProvider(Now),
            new FixedIdentifiers(challengeIds),
            requestRetries: 1);

        var assignmentValue = Assignment();
        var result = await client.CompleteAsync(
            assignmentValue,
            new { reviewStatus = "pending-editorial-review" },
            operationId,
            CancellationToken.None);

        Assert.True(result.Replayed);
        var operationRequests = handler.Requests
            .Where(request => request.Path.EndsWith("/complete", StringComparison.Ordinal))
            .ToArray();
        Assert.Equal(2, operationRequests.Length);
        Assert.All(operationRequests, request => Assert.Equal(operationId, request.Headers["X-HCH-Request-Id"]));
        Assert.Equal(operationRequests[0].Body, operationRequests[1].Body);
    }

    [Fact]
    public async Task NodeHeartbeatConsumesThePublishedUpdateContractWithoutBlockingCompatibleVersions()
    {
        using var identity = Ed25519Identity.Generate();
        string operationId = Guid.NewGuid().ToString("D");
        string challengeId = Guid.NewGuid().ToString("D");
        var handler = new RecordingHandler(request => Task.FromResult(
            request.RequestUri!.AbsolutePath.EndsWith("/challenge", StringComparison.Ordinal)
                ? Json(new ChallengeResponse
                {
                    NodeId = "node-1",
                    KeyId = identity.Fingerprint,
                    Purpose = "node-heartbeat",
                    Nonce = "server-0123456789abcdef0123456789abcdef",
                    ExpiresAt = Now.AddMinutes(5).ToString("O"),
                    SignatureProfile = HchHttpMessageSignatures.SignatureTag,
                })
                : Json(new NodeHeartbeatResponse
                {
                    RequestId = operationId,
                    NodeId = "node-1",
                    HeartbeatAt = Now.ToString("O"),
                    NextHeartbeatSeconds = 60,
                    Capacity = new NodeHeartbeatCapacity
                    {
                        ConfiguredCapacity = 4,
                        RequestedCapacity = 4,
                        GrantedCapacity = 4,
                        ActiveAssignments = 0,
                        AvailableSlots = 4,
                        CapacityClass = "standard",
                        Reason = "requested-capacity-granted",
                        GrantedUntil = Now.AddMinutes(2).ToString("O"),
                    },
                    Workload = HeartbeatWorkload(),
                    WorkSizing = HeartbeatWorkSizing(),
                    Claim = HeartbeatClaim(),
                    Update = new WorkerUpdateAvailability
                    {
                        InstalledWorkerVersion = "4.0.0",
                        LatestAvailableWorkerVersion = "4.0.0",
                        UpdateAvailable = false,
                        UpdateMode = "advisory",
                        Compatible = true,
                        ContentImpact = "none",
                    },
                    ServerTime = Now.ToString("O"),
                })));
        using var http = new HttpClient(handler);
        var client = new SignedOrchestratorClient(
            http,
            new Uri("https://hubtech.online/"),
            "node-1",
            identity.Fingerprint,
            identity,
            new FixedTimeProvider(Now),
            new FixedIdentifiers([operationId, challengeId]));

        NodeHeartbeatResponse response = await client.HeartbeatNodeAsync(4, CancellationToken.None);

        Assert.True(response.Update.Compatible);
        Assert.False(response.Update.UpdateAvailable);
        Assert.Equal("none", response.Update.ContentImpact);
    }

    [Theory]
    [InlineData(true, "generated-content", "advisory")]
    [InlineData(true, "none", "mandatory")]
    [InlineData(false, "none", "mandatory")]
    [InlineData(false, "generated-content", "advisory")]
    public void NodeHeartbeatRejectsContradictoryUpdateCompatibility(
        bool compatible,
        string contentImpact,
        string updateMode)
    {
        string requestId = Guid.NewGuid().ToString("D");
        var response = new NodeHeartbeatResponse
        {
            RequestId = requestId,
            NodeId = "node-1",
            HeartbeatAt = Now.ToString("O"),
            NextHeartbeatSeconds = 60,
            Capacity = new NodeHeartbeatCapacity
            {
                ConfiguredCapacity = 1,
                RequestedCapacity = 1,
                GrantedCapacity = 1,
                ActiveAssignments = 0,
                AvailableSlots = 1,
                CapacityClass = "standard",
                Reason = "requested-capacity-granted",
                GrantedUntil = Now.AddMinutes(2).ToString("O"),
            },
            Workload = HeartbeatWorkload(),
            WorkSizing = HeartbeatWorkSizing(),
            Claim = HeartbeatClaim(),
            Update = new WorkerUpdateAvailability
            {
                InstalledWorkerVersion = "4.0.0",
                LatestAvailableWorkerVersion = "4.0.1",
                UpdateAvailable = true,
                UpdateMode = updateMode,
                Compatible = compatible,
                ContentImpact = contentImpact,
            },
            ServerTime = Now.ToString("O"),
        };

        WorkerServiceException error = Assert.Throws<WorkerServiceException>(() =>
            OrchestratorContractValidator.Validate(response, requestId, "node-1", 1));

        Assert.Equal("node-heartbeat-response-invalid", error.Code);
    }

    [Theory]
    [InlineData("{\"allowed\":false,\"recommendedCount\":1,\"reason\":\"claim-recommended\"}")]
    [InlineData("{\"allowed\":true,\"recommendedCount\":2,\"reason\":\"claim-recommended\"}")]
    [InlineData("{\"allowed\":true,\"recommendedCount\":1,\"reason\":\"capacity-zero\"}")]
    [InlineData("{\"allowed\":true,\"recommendedCount\":1,\"reason\":\"claim-recommended\",\"extra\":true}")]
    public void NodeHeartbeatRejectsInvalidClaimDirective(string claimJson)
    {
        string requestId = Guid.NewGuid().ToString("D");
        NodeHeartbeatResponse response = HeartbeatResponse(
            requestId,
            claim: System.Text.Json.JsonSerializer.Deserialize<System.Text.Json.JsonElement>(claimJson));

        WorkerServiceException error = Assert.Throws<WorkerServiceException>(() =>
            OrchestratorContractValidator.Validate(response, requestId, "node-1", 1));

        Assert.Equal("node-heartbeat-response-invalid", error.Code);
    }

    [Fact]
    public void NodeHeartbeatRejectsIncompleteWorkSizing()
    {
        string requestId = Guid.NewGuid().ToString("D");
        NodeHeartbeatResponse response = HeartbeatResponse(
            requestId,
            workSizing: System.Text.Json.JsonSerializer.SerializeToElement(new
            {
                algorithmVersion = "hch-adaptive-work-v1",
            }));

        WorkerServiceException error = Assert.Throws<WorkerServiceException>(() =>
            OrchestratorContractValidator.Validate(response, requestId, "node-1", 1));

        Assert.Equal("node-heartbeat-response-invalid", error.Code);
    }

    [Fact]
    public void ClaimContractRejectsDuplicateAssignmentIdsBeforeScheduling()
    {
        string requestId = Guid.NewGuid().ToString("D");
        var assignment = Assignment();
        var response = new ClaimResponse
        {
            RequestId = requestId,
            NodeId = "node-1",
            Assignments = [assignment, assignment],
            Capacity = new CapacityDecision
            {
                RequestedCapacity = 2,
                GrantedCapacity = 2,
                AvailableSlots = 0,
                ActiveAssignments = 2,
                Reason = "requested-capacity-granted",
                GrantedUntil = Now.AddMinutes(2).ToString("O"),
            },
            Replayed = false,
            ServerTime = Now.ToString("O"),
        };

        var error = Assert.Throws<WorkerServiceException>(() =>
            OrchestratorContractValidator.Validate(response, requestId, "node-1", 2, Now));

        Assert.Equal("claim-assignment-duplicate", error.Code);
    }

    private static WorkerAssignment Assignment() => new()
    {
        AssignmentId = "11111111-2222-4333-8444-555555555555",
        LeaseToken = "lease-token-0123456789abcdef",
        LeaseExpiresAt = Now.AddMinutes(10).ToString("O"),
        Status = "processing",
        InputSnapshotHash = new string('a', 64),
        Entry = System.Text.Json.JsonSerializer.SerializeToElement(new { title = "input" }),
        GenerationPlanHash = new string('b', 64),
        GenerationPlan = new GenerationPlan
        {
            AlgorithmVersion = "hch-adaptive-work-v1",
            TierId = "minimum",
            TierRank = 0,
            MaxOutputTokens = 100,
            EditorialProfile = "EDITORIAL_MINIMUM",
            MinimumUnit = true,
            ProcessingWindowSeconds = 600,
            NearWindowSeconds = 60,
            FirstProgressGraceSeconds = 60,
            StallAfterSeconds = 60,
            FinalizationGraceSeconds = 60,
            PolicyHash = new string('c', 64),
        },
        RuntimeProfile = new WorkerRuntimeProfile
        {
            Provider = "ollama",
            EngineAdapter = "ollama-chat",
            EngineAdapterVersion = "1.0.0",
            Model = "model:test",
            ModelDigest = "sha256:" + new string('d', 64),
            Protocol = "ollama-chat-v1",
            Temperature = 0.2,
            ContextWindow = 4096,
            MaxOutputTokens = 100,
            PolicyId = "policy",
            PolicyVersion = "1.0.0",
            PolicyHash = new string('c', 64),
            PromptConfigHash = new string('e', 64),
            PipelineVersion = "editorial-v1",
            ManifestSequence = 1,
            ManifestHash = new string('f', 64),
            RuntimeProfileHash = new string('0', 64),
        },
    };

    private static NodeHeartbeatResponse HeartbeatResponse(
        string requestId,
        System.Text.Json.JsonElement? claim = null,
        System.Text.Json.JsonElement? workSizing = null) => new()
        {
            RequestId = requestId,
            NodeId = "node-1",
            HeartbeatAt = Now.ToString("O"),
            NextHeartbeatSeconds = 60,
            Capacity = new NodeHeartbeatCapacity
            {
                ConfiguredCapacity = 1,
                RequestedCapacity = 1,
                GrantedCapacity = 1,
                ActiveAssignments = 0,
                AvailableSlots = 1,
                CapacityClass = "standard",
                Reason = "requested-capacity-granted",
                GrantedUntil = Now.AddMinutes(2).ToString("O"),
            },
            Workload = HeartbeatWorkload(),
            WorkSizing = workSizing ?? HeartbeatWorkSizing(),
            Claim = claim ?? HeartbeatClaim(),
            Update = new WorkerUpdateAvailability
            {
                InstalledWorkerVersion = "4.0.0",
                LatestAvailableWorkerVersion = "4.0.0",
                UpdateAvailable = false,
                UpdateMode = "advisory",
                Compatible = true,
                ContentImpact = "none",
            },
            ServerTime = Now.ToString("O"),
        };

    private static System.Text.Json.JsonElement HeartbeatWorkload() =>
        System.Text.Json.JsonSerializer.SerializeToElement(new
        {
            claimable = 1,
            generating = 0,
            futureTotal = 1,
            claimableByTier = new { minimum = 1 },
        });

    private static System.Text.Json.JsonElement HeartbeatWorkSizing() =>
        System.Text.Json.JsonSerializer.SerializeToElement(new
        {
            algorithmVersion = "hch-adaptive-work-v1",
            currentTier = "minimum",
            currentRank = 0,
            maxOutputTokens = 512,
            editorialProfile = "EDITORIAL_MINIMUM",
            minimumUnit = true,
            reason = "within-window",
            updatedAt = Now.ToString("O"),
            processingWindowSeconds = 600,
            nearWindowSeconds = 480,
            firstProgressGraceSeconds = 60,
            stallAfterSeconds = 60,
            finalizationGraceSeconds = 60,
        });

    private static System.Text.Json.JsonElement HeartbeatClaim() =>
        System.Text.Json.JsonSerializer.SerializeToElement(new
        {
            allowed = true,
            recommendedCount = 1,
            reason = "claim-recommended",
        });

    private static HttpResponseMessage Json<T>(T value, HttpStatusCode status = HttpStatusCode.OK) => new(status)
    {
        Content = new ByteArrayContent(ProtocolJson.SerializeCanonicalToUtf8(value))
        {
            Headers = { ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("application/json") },
        },
    };

    private sealed class FixedTimeProvider(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => now;
    }

    private sealed class FixedIdentifiers(IEnumerable<string> requestIds) : IRequestIdentifierSource
    {
        private readonly Queue<string> ids = new(requestIds);

        public string NewRequestId() => ids.Dequeue();

        public string NewClientNonce() => "client-01234567-89ab-cdef-0123-456789abcdef-01234567-89ab-cdef-0123-456789abcdef";
    }

    private sealed class RecordingHandler(Func<HttpRequestMessage, Task<HttpResponseMessage>> handler) : HttpMessageHandler
    {
        public List<RecordedRequest> Requests { get; } = [];

        protected override async Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            var body = await request.Content!.ReadAsByteArrayAsync(cancellationToken);
            var headers = request.Headers.Concat(request.Content.Headers)
                .ToDictionary(pair => pair.Key, pair => string.Join(", ", pair.Value), StringComparer.OrdinalIgnoreCase);
            Requests.Add(new RecordedRequest(request.RequestUri!.AbsolutePath, body, headers));
            return await handler(request);
        }
    }

    private sealed record RecordedRequest(
        string Path,
        byte[] Body,
        IReadOnlyDictionary<string, string> Headers);
}
