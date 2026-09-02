using Hch.Worker.Core;
using Hch.Worker.Persistence;
using Hch.Worker.Protocol;
using Hch.Worker.Service;

namespace Hch.Worker.Tests;

public sealed class ServiceJournalTests
{
    [Fact]
    public async Task UnknownCompletionIsDurableAndKeepsStableRequestEvidence()
    {
        var root = Path.Combine(Path.GetTempPath(), "hch-worker-service-tests", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            var now = DateTimeOffset.UtcNow;
            var assignment = Assignment(now);
            var files = new AtomicFileStore(root);
            var journals = new EditorialJournalStore(files);
            var recovery = new ProtectedEditorialRecoveryStore(
                files,
                new MachineSecretProtector(),
                "node-1");
            var requestId = Guid.NewGuid().ToString("D");
            await journals.WriteAsync(new EditorialJobJournal(
                EditorialJobJournal.CurrentSchemaVersion,
                assignment.AssignmentId,
                assignment.GenerationPlanHash,
                HchDigest.Sha256Hex(assignment.LeaseToken),
                now.AddMinutes(5),
                EditorialJournalPhase.DraftReady,
                requestId,
                HchDigest.Sha256Hex([]),
                new string('d', 64),
                null,
                now));
            var client = new UnknownCompletionClient();
            var unsafeCodes = new List<string>();
            var reporter = new JournaledJobReporter(
                client,
                journals,
                recovery,
                new AssignmentRuntimeRegistry(),
                "node-1",
                "key-1",
                unsafeCodes.Add);
            var job = new WorkerJob(
                assignment.AssignmentId,
                assignment.LeaseToken,
                now.AddMinutes(5),
                assignment.GenerationPlanHash,
                assignment);

            await Assert.ThrowsAsync<OrchestratorRequestException>(() => reporter.CompleteAsync(
                job,
                new JobExecutionResult(job.AssignmentId, "pending-editorial-review", new { value = "draft" }),
                CancellationToken.None));

            var journal = await journals.ReadAsync(assignment.AssignmentId);
            Assert.NotNull(journal);
            Assert.Equal(EditorialJournalPhase.CommitUnknown, journal.Phase);
            Assert.True(journal.RequiresReconciliation);
            Assert.Equal(requestId, client.RequestId);
            Assert.Equal(requestId, journal.RequestId);
            Assert.True(HchDigest.IsLowerSha256(journal.RequestBodyDigest));
            Assert.Equal(["assignment-complete-unknown"], unsafeCodes);
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    private static WorkerAssignment Assignment(DateTimeOffset now) => new()
    {
        AssignmentId = "11111111-2222-4333-8444-555555555555",
        LeaseToken = "lease-token-0123456789abcdef",
        LeaseExpiresAt = now.AddMinutes(5).ToString("O"),
        Status = "processing",
        InputSnapshotHash = new string('a', 64),
        Entry = System.Text.Json.JsonSerializer.SerializeToElement(new { value = "input" }),
        RuntimeProfile = new WorkerRuntimeProfile
        {
            Provider = "ollama",
            EngineAdapter = "chat",
            EngineAdapterVersion = "1",
            Model = "model",
            ModelDigest = new string('a', 64),
            Protocol = "chat",
            Temperature = 0,
            ContextWindow = 100,
            MaxOutputTokens = 10,
            PolicyId = "p",
            PolicyVersion = "1",
            PolicyHash = new string('b', 64),
            PromptConfigHash = new string('c', 64),
            PipelineVersion = "1",
            ManifestSequence = 1,
            ManifestHash = new string('d', 64),
            RuntimeProfileHash = new string('e', 64),
        },
        GenerationPlan = new GenerationPlan
        {
            AlgorithmVersion = "hch-adaptive-work-v1",
            TierId = "minimum",
            TierRank = 0,
            MaxOutputTokens = 10,
            EditorialProfile = "EDITORIAL_MINIMUM",
            MinimumUnit = true,
            ProcessingWindowSeconds = 600,
            NearWindowSeconds = 60,
            FirstProgressGraceSeconds = 60,
            StallAfterSeconds = 60,
            FinalizationGraceSeconds = 60,
            PolicyHash = new string('b', 64),
        },
        GenerationPlanHash = new string('f', 64),
    };

    private sealed class UnknownCompletionClient : IOrchestratorClient
    {
        public string? RequestId { get; private set; }

        public Task<CompleteAssignmentResponse> CompleteAsync(
            WorkerAssignment assignment, object draft, string requestId, CancellationToken cancellationToken)
        {
            RequestId = requestId;
            throw new OrchestratorRequestException(
                "network-request-failed", null, retryable: true, outcomeUnknown: true);
        }

        public Task<ClaimResponse> ClaimAsync(
            int requestedCapacity,
            CancellationToken cancellationToken,
            string? requestId = null,
            bool acceptExpiredAssignmentsForRecovery = false) =>
            throw new NotSupportedException();
        public Task<FailAssignmentResponse> FailAsync(WorkerAssignment assignment, string errorCode, string requestId, CancellationToken cancellationToken) =>
            throw new NotSupportedException();
        public Task<AssignmentHeartbeatResponse> HeartbeatAssignmentAsync(WorkerAssignment assignment, AssignmentProgress progress, CancellationToken cancellationToken) =>
            throw new NotSupportedException();
        public Task<NodeHeartbeatResponse> HeartbeatNodeAsync(int requestedCapacity, CancellationToken cancellationToken) =>
            throw new NotSupportedException();
    }
}
