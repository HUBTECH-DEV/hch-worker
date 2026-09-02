using System.Text.Json;
using Hch.Worker.Core;
using Hch.Worker.Persistence;
using Hch.Worker.Protocol;
using Hch.Worker.Service;

namespace Hch.Worker.Tests;

public sealed class ServiceRecoveryTests
{
    [Fact]
    public async Task GeneratedDraftIsCompletedAfterRestartWithoutRegeneration()
    {
        var root = TemporaryRoot();
        try
        {
            var now = DateTimeOffset.UtcNow;
            var assignment = Assignment(now);
            var files = new AtomicFileStore(root);
            var journals = new EditorialJournalStore(files);
            var recovery = Recovery(files);
            var draft = JsonSerializer.SerializeToElement(new
            {
                schemaVersion = "1.1",
                contentId = "draft-1",
                title = "Conteúdo recuperado",
            });
            await recovery.EnsureClaimAsync(assignment);
            await recovery.SaveDraftAsync(assignment, draft);
            var requestId = Guid.NewGuid().ToString("D");
            await journals.WriteAsync(Journal(assignment, EditorialJournalPhase.Generating, requestId, now));
            var client = new RecoveryClient();
            var reconciler = new EditorialOutcomeReconciler(
                client,
                journals,
                recovery,
                "node-1",
                "key-1");

            var result = await reconciler.ReconcileAsync();

            Assert.Equal(1, result.Scanned);
            Assert.Equal(1, result.Reconciled);
            Assert.Equal(0, result.Pending);
            Assert.Equal(1, client.CompleteCalls);
            Assert.Equal(requestId, client.RequestIds.Single());
            Assert.Equal(EditorialJournalPhase.Completed,
                (await journals.ReadAsync(assignment.AssignmentId))!.Phase);
            Assert.Null(await recovery.ReadAsync(assignment.AssignmentId));
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task UnknownFailureReplaysTheSameRequestUntilCentrallyAccepted()
    {
        var root = TemporaryRoot();
        try
        {
            var now = DateTimeOffset.UtcNow;
            var assignment = Assignment(now);
            var files = new AtomicFileStore(root);
            var journals = new EditorialJournalStore(files);
            var recovery = Recovery(files);
            await recovery.EnsureClaimAsync(assignment);
            var requestId = Guid.NewGuid().ToString("D");
            await journals.WriteAsync(Journal(assignment, EditorialJournalPhase.Generating, requestId, now));
            var client = new RecoveryClient(failFirstFailure: true);
            var reconciler = new EditorialOutcomeReconciler(
                client,
                journals,
                recovery,
                "node-1",
                "key-1");

            var first = await reconciler.ReconcileAsync();
            Assert.Equal(1, first.Pending);
            Assert.Equal(EditorialJournalPhase.FailUnknown,
                (await journals.ReadAsync(assignment.AssignmentId))!.Phase);

            var second = await reconciler.ReconcileAsync();
            Assert.Equal(1, second.Reconciled);
            Assert.Equal(0, second.Pending);
            Assert.Equal(2, client.FailCalls);
            Assert.Equal([requestId, requestId], client.RequestIds);
            Assert.Equal([EditorialOutcomeReconciler.RestartFailureCode,
                EditorialOutcomeReconciler.RestartFailureCode], client.FailureCodes);

            var third = await reconciler.ReconcileAsync();
            Assert.Equal(0, third.Reconciled);
            Assert.Equal(2, client.FailCalls);
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task PendingClaimReusesItsDurableRequestIdAfterNetworkFailure()
    {
        var root = TemporaryRoot();
        try
        {
            var now = DateTimeOffset.UtcNow;
            var assignment = Assignment(now);
            var files = new AtomicFileStore(root);
            var journals = new EditorialJournalStore(files);
            var recovery = Recovery(files);
            var pending = new PendingClaimStore(files);
            var client = new RecoveryClient(assignment, now, failFirstClaim: true);
            var control = new WorkerControlState(1, 1);
            var source = new OrchestratorJobSource(
                client,
                control,
                journals,
                recovery,
                pending,
                Applied(assignment));

            await Assert.ThrowsAsync<OrchestratorRequestException>(
                () => source.ClaimAsync(1, CancellationToken.None));
            var durable = await pending.ReadAsync();
            Assert.NotNull(durable);

            var jobs = await source.ClaimAsync(1, CancellationToken.None);

            Assert.Single(jobs);
            Assert.Equal([durable.RequestId, durable.RequestId], client.RequestIds);
            Assert.Null(await pending.ReadAsync());
            Assert.NotNull(await journals.ReadAsync(assignment.AssignmentId));
            Assert.NotNull(await recovery.ReadAsync(assignment.AssignmentId));
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    private static ProtectedEditorialRecoveryStore Recovery(AtomicFileStore files) =>
        new(files, new MachineSecretProtector(), "node-1");

    private static string TemporaryRoot()
    {
        var path = Path.Combine(
            Path.GetTempPath(),
            "hch-worker-recovery-tests",
            Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(path);
        return path;
    }

    private static EditorialJobJournal Journal(
        WorkerAssignment assignment,
        EditorialJournalPhase phase,
        string requestId,
        DateTimeOffset now) => new(
            EditorialJobJournal.CurrentSchemaVersion,
            assignment.AssignmentId,
            assignment.GenerationPlanHash,
            HchDigest.Sha256Hex(assignment.LeaseToken),
            ProtocolTime.ParseTimestamp(assignment.LeaseExpiresAt, "leaseExpiresAt"),
            phase,
            requestId,
            HchDigest.Sha256Hex([]),
            DraftHash: null,
            LastErrorCode: null,
            UpdatedAt: now);

    private static AppliedRuntimeContract Applied(WorkerAssignment assignment) => new(
        assignment.RuntimeProfile.ManifestSequence,
        assignment.RuntimeProfile.ManifestHash,
        assignment.RuntimeProfile.PolicyHash,
        assignment.RuntimeProfile.PromptConfigHash,
        assignment.RuntimeProfile.Provider,
        assignment.RuntimeProfile.EngineAdapter,
        assignment.RuntimeProfile.EngineAdapterVersion,
        assignment.RuntimeProfile.Model,
        assignment.RuntimeProfile.ModelDigest,
        assignment.RuntimeProfile.Protocol,
        assignment.RuntimeProfile.RuntimeProfileHash,
        new string('f', 64));

    private static WorkerAssignment Assignment(DateTimeOffset now)
    {
        var entry = JsonSerializer.SerializeToElement(new { entryId = "entry-1" });
        var plan = new GenerationPlan
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
            PolicyHash = new string('b', 64),
        };
        var profileValues = new Dictionary<string, object?>(StringComparer.Ordinal)
        {
            ["contextWindow"] = 2048,
            ["engineAdapter"] = "ollama-chat",
            ["engineAdapterVersion"] = "1.0.0",
            ["manifestHash"] = new string('d', 64),
            ["manifestSequence"] = 1L,
            ["maxOutputTokens"] = 100,
            ["model"] = "model:latest",
            ["modelDigest"] = new string('a', 64),
            ["pipelineVersion"] = "editorial-v1",
            ["policyHash"] = new string('b', 64),
            ["policyId"] = "editorial-policy",
            ["policyVersion"] = "1.0.0",
            ["promptConfigHash"] = new string('c', 64),
            ["protocol"] = "ollama-chat",
            ["provider"] = "ollama",
            ["temperature"] = 0d,
        };
        var profile = new WorkerRuntimeProfile
        {
            Provider = "ollama",
            EngineAdapter = "ollama-chat",
            EngineAdapterVersion = "1.0.0",
            Model = "model:latest",
            ModelDigest = new string('a', 64),
            Protocol = "ollama-chat",
            Temperature = 0,
            ContextWindow = 2048,
            MaxOutputTokens = 100,
            PolicyId = "editorial-policy",
            PolicyVersion = "1.0.0",
            PolicyHash = new string('b', 64),
            PromptConfigHash = new string('c', 64),
            PipelineVersion = "editorial-v1",
            ManifestSequence = 1,
            ManifestHash = new string('d', 64),
            RuntimeProfileHash = HchDigest.Sha256Hex(JcsCanonicalizer.Serialize(profileValues)),
        };
        return new WorkerAssignment
        {
            AssignmentId = "11111111-2222-4333-8444-555555555555",
            LeaseToken = "lease-token-0123456789abcdef",
            LeaseExpiresAt = now.AddMinutes(10).ToString("O"),
            Status = "processing",
            InputSnapshotHash = HchDigest.Sha256Hex(JcsCanonicalizer.Canonicalize(entry)),
            Entry = entry,
            RuntimeProfile = profile,
            GenerationPlan = plan,
            GenerationPlanHash = HchDigest.Sha256Hex(JcsCanonicalizer.Serialize(plan)),
        };
    }

    private sealed class RecoveryClient : IOrchestratorClient
    {
        private readonly WorkerAssignment? assignment;
        private readonly DateTimeOffset now;
        private readonly bool failFirstClaim;
        private readonly bool failFirstFailure;

        public RecoveryClient(
            WorkerAssignment? assignment = null,
            DateTimeOffset now = default,
            bool failFirstClaim = false,
            bool failFirstFailure = false)
        {
            this.assignment = assignment;
            this.now = now;
            this.failFirstClaim = failFirstClaim;
            this.failFirstFailure = failFirstFailure;
        }

        public int ClaimCalls { get; private set; }
        public int CompleteCalls { get; private set; }
        public int FailCalls { get; private set; }
        public List<string> RequestIds { get; } = [];
        public List<string> FailureCodes { get; } = [];

        public Task<ClaimResponse> ClaimAsync(
            int requestedCapacity,
            CancellationToken cancellationToken,
            string? requestId = null,
            bool acceptExpiredAssignmentsForRecovery = false)
        {
            ClaimCalls++;
            RequestIds.Add(requestId ?? throw new InvalidOperationException());
            if (failFirstClaim && ClaimCalls == 1)
            {
                throw new OrchestratorRequestException(
                    "network-request-failed",
                    null,
                    retryable: true,
                    outcomeUnknown: true);
            }

            return Task.FromResult(new ClaimResponse
            {
                RequestId = requestId,
                NodeId = "node-1",
                Assignments = [assignment ?? throw new InvalidOperationException()],
                Capacity = new CapacityDecision
                {
                    RequestedCapacity = requestedCapacity,
                    GrantedCapacity = requestedCapacity,
                    AvailableSlots = 0,
                    ActiveAssignments = 1,
                    Reason = "test",
                    GrantedUntil = now.AddMinutes(5).ToString("O"),
                },
                Replayed = ClaimCalls > 1,
                ServerTime = now.ToString("O"),
            });
        }

        public Task<CompleteAssignmentResponse> CompleteAsync(
            WorkerAssignment value,
            object draft,
            string requestId,
            CancellationToken cancellationToken)
        {
            CompleteCalls++;
            RequestIds.Add(requestId);
            return Task.FromResult(new CompleteAssignmentResponse
            {
                AssignmentId = value.AssignmentId,
                GenerationPlanHash = value.GenerationPlanHash,
                CommitAccepted = true,
                Status = "pending-review",
                AutomaticApproval = false,
                AutomaticPublication = false,
                Replayed = true,
                ServerTime = DateTimeOffset.UtcNow.ToString("O"),
            });
        }

        public Task<FailAssignmentResponse> FailAsync(
            WorkerAssignment value,
            string errorCode,
            string requestId,
            CancellationToken cancellationToken)
        {
            FailCalls++;
            RequestIds.Add(requestId);
            FailureCodes.Add(errorCode);
            if (failFirstFailure && FailCalls == 1)
            {
                throw new OrchestratorRequestException(
                    "network-request-failed",
                    null,
                    retryable: true,
                    outcomeUnknown: true);
            }

            return Task.FromResult(new FailAssignmentResponse
            {
                AssignmentId = value.AssignmentId,
                GenerationPlanHash = value.GenerationPlanHash,
                Status = "failed-attempt",
                Replayed = true,
                ServerTime = DateTimeOffset.UtcNow.ToString("O"),
            });
        }

        public Task<AssignmentHeartbeatResponse> HeartbeatAssignmentAsync(
            WorkerAssignment assignment,
            AssignmentProgress progress,
            CancellationToken cancellationToken) => throw new NotSupportedException();

        public Task<NodeHeartbeatResponse> HeartbeatNodeAsync(
            int requestedCapacity,
            CancellationToken cancellationToken) => throw new NotSupportedException();
    }
}
