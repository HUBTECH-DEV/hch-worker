using System.Collections.Concurrent;
using System.Text.Json;
using System.Text.Json.Serialization;
using Hch.Worker.Core;
using Hch.Worker.Ollama;
using Hch.Worker.Persistence;
using Hch.Worker.Protocol;

namespace Hch.Worker.Service;

public sealed class AssignmentRuntimeRegistry(TimeProvider? timeProvider = null)
{
    public static readonly TimeSpan HeartbeatInterval = TimeSpan.FromSeconds(30);
    private readonly ConcurrentDictionary<string, AssignmentRuntimeContext> active = new(StringComparer.Ordinal);
    private readonly TimeProvider clock = timeProvider ?? TimeProvider.System;

    public AssignmentExecutionLease Begin(
        WorkerAssignment assignment,
        int itemIndex = 1,
        int batchTotal = 1)
    {
        ArgumentNullException.ThrowIfNull(assignment);
        if (batchTotal is < 1 or > WorkerControlState.MaximumParallelism
            || itemIndex < 1 || itemIndex > batchTotal)
        {
            throw new WorkerJobException(
                "assignment-batch-metadata-invalid",
                "The assignment batch position is invalid.");
        }

        var context = new AssignmentRuntimeContext(
            assignment,
            itemIndex,
            batchTotal,
            clock.GetUtcNow());
        if (!active.TryAdd(assignment.AssignmentId, context))
        {
            context.Dispose();
            throw new WorkerJobException("assignment-duplicate", "The assignment is already executing.");
        }

        return new AssignmentExecutionLease(context);
    }

    public void Finish(string assignmentId)
    {
        if (active.TryRemove(assignmentId, out var context))
        {
            context.Dispose();
        }
    }

    public IReadOnlyList<WorkerJobProgress> Snapshot() => active.Values
        .Select(context => context.Snapshot())
        .OrderBy(static progress => progress.AssignmentId, StringComparer.Ordinal)
        .ToArray();

    public TimeSpan? Elapsed(string assignmentId, DateTimeOffset completedAt)
    {
        if (!active.TryGetValue(assignmentId, out AssignmentRuntimeContext? context))
        {
            return null;
        }

        return context.Elapsed(completedAt);
    }

    public async Task RunHeartbeatLoopAsync(
        IOrchestratorClient client,
        CancellationToken serviceStopping)
    {
        while (!serviceStopping.IsCancellationRequested)
        {
            await Task.Delay(HeartbeatInterval, clock, serviceStopping).ConfigureAwait(false);
            await RunHeartbeatPassAsync(client, serviceStopping).ConfigureAwait(false);
        }
    }

    internal Task RunHeartbeatPassAsync(
        IOrchestratorClient client,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(client);
        AssignmentRuntimeContext[] contexts = active.Values.ToArray();
        return Task.WhenAll(contexts.Select(context =>
            HeartbeatOneIsolatedAsync(client, context, cancellationToken)));
    }

    private async Task HeartbeatOneIsolatedAsync(
        IOrchestratorClient client,
        AssignmentRuntimeContext context,
        CancellationToken cancellationToken)
    {
        try
        {
            await HeartbeatOneAsync(client, context, cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception error) when (IsRecoverableHeartbeatFailure(error))
        {
            // Any failure not already classified below belongs to this
            // assignment. Abort it with a fixed code instead of terminating
            // the heartbeat loop for every other active assignment.
            context.Abort("assignment-heartbeat-internal-error");
        }
    }

    private async Task HeartbeatOneAsync(
        IOrchestratorClient client,
        AssignmentRuntimeContext context,
        CancellationToken cancellationToken)
    {
        if (!context.TryProtocolSnapshot(out AssignmentProgress snapshot))
        {
            return;
        }

        var now = clock.GetUtcNow();
        var grace = snapshot.Phase switch
        {
            "starting" => context.Assignment.GenerationPlan.FirstProgressGraceSeconds,
            "finalizing" => context.Assignment.GenerationPlan.FinalizationGraceSeconds,
            _ => context.Assignment.GenerationPlan.StallAfterSeconds,
        };
        if (now - context.LastMaterialProgressAt > TimeSpan.FromSeconds(grace))
        {
            context.Abort(snapshot.Phase == "starting" ? "generator-first-progress-timeout" : "generator-stalled");
            return;
        }

        if (now >= context.LeaseExpiresAt)
        {
            context.Abort("assignment-lease-expired");
            return;
        }

        try
        {
            var response = await client.HeartbeatAssignmentAsync(
                context.Assignment,
                snapshot,
                cancellationToken).ConfigureAwait(false);
            context.RenewLease(ProtocolTime.ParseTimestamp(response.LeaseExpiresAt, "leaseExpiresAt"));
        }
        catch (OrchestratorRequestException error)
            when (error.StatusCode == System.Net.HttpStatusCode.Conflict
                && error.Code == "generator-stalled"
                && error.ResponseGenerationPlanHash == context.Assignment.GenerationPlanHash)
        {
            context.Abort("generator-stalled");
        }
        catch (OrchestratorRequestException error) when (error.Retryable)
        {
            // The lease and signed liveness timers decide when a transient outage
            // becomes fatal. A single missed HTTP exchange never cancels work.
        }
        catch (OrchestratorRequestException error)
        {
            context.Abort(error.Code);
        }
        catch (ProtocolValidationException)
        {
            // A syntactically valid HTTP exchange can still carry a response
            // that violates the assignment contract. Fail only that assignment;
            // one bad response must not terminate heartbeats for the other work.
            context.Abort("assignment-heartbeat-response-invalid");
        }
    }

    private static bool IsRecoverableHeartbeatFailure(Exception error) => error is not (
        OutOfMemoryException
        or StackOverflowException
        or AccessViolationException
        or AppDomainUnloadedException
        or BadImageFormatException);

    internal sealed class AssignmentRuntimeContext : IDisposable
    {
        private readonly object gate = new();
        private readonly CancellationTokenSource abort = new();
        private readonly CancellationToken abortToken;
        private AssignmentProgress progress;
        private DateTimeOffset observedAt;
        private DateTimeOffset lastMaterialProgressAt;
        private DateTimeOffset leaseExpiresAt;
        private double? percent;
        private string? abortReason;
        private bool disposed;

        public AssignmentRuntimeContext(
            WorkerAssignment assignment,
            int itemIndex,
            int batchTotal,
            DateTimeOffset now)
        {
            Assignment = assignment;
            abortToken = abort.Token;
            progress = new AssignmentProgress { Phase = "starting", Attempt = 1, Sequence = 0, ContentBytes = 0 };
            ItemIndex = itemIndex;
            BatchTotal = batchTotal;
            percent = 0d;
            StartedAt = now;
            observedAt = now;
            lastMaterialProgressAt = now;
            leaseExpiresAt = ProtocolTime.ParseTimestamp(assignment.LeaseExpiresAt, "leaseExpiresAt");
        }

        public WorkerAssignment Assignment { get; }

        public int ItemIndex { get; }

        public int BatchTotal { get; }

        public DateTimeOffset StartedAt { get; }

        public CancellationToken CancellationToken => abortToken;

        public DateTimeOffset LastMaterialProgressAt
        {
            get { lock (gate) { return lastMaterialProgressAt; } }
        }

        public DateTimeOffset LeaseExpiresAt
        {
            get { lock (gate) { return leaseExpiresAt; } }
        }

        public string? AbortReason
        {
            get { lock (gate) { return abortReason; } }
        }

        public TimeSpan Elapsed(DateTimeOffset completedAt) =>
            completedAt <= StartedAt ? TimeSpan.Zero : completedAt - StartedAt;

        public void Update(OllamaProgress value)
        {
            if (value.Percent is { } reportedPercent
                && (!double.IsFinite(reportedPercent) || reportedPercent is < 0 or > 100))
            {
                throw new WorkerJobException(
                    "assignment-progress-percent-invalid",
                    "Assignment progress percent must be between zero and one hundred.");
            }

            var next = new AssignmentProgress
            {
                Phase = value.Phase,
                Attempt = value.Attempt,
                Sequence = value.Sequence,
                ContentBytes = value.ContentBytes,
            };
            AssignmentContractValidator.Validate(next);
            lock (gate)
            {
                if (next.Attempt < progress.Attempt
                    || next.Attempt == progress.Attempt && next.Sequence < progress.Sequence
                    || next.ContentBytes < progress.ContentBytes
                    || next.Attempt == progress.Attempt
                        && value.Percent is { } nextPercent
                        && percent is { } priorPercent
                        && nextPercent < priorPercent)
                {
                    throw new WorkerJobException("assignment-progress-regressed", "Assignment progress cannot regress.");
                }

                var material = next.Sequence > progress.Sequence || next.ContentBytes > progress.ContentBytes;
                progress = next;
                percent = value.Percent ?? percent;
                observedAt = value.ObservedAt;
                if (material)
                {
                    lastMaterialProgressAt = value.ObservedAt;
                }
            }
        }

        public bool TryProtocolSnapshot(out AssignmentProgress snapshot)
        {
            lock (gate)
            {
                if (disposed)
                {
                    snapshot = null!;
                    return false;
                }

                snapshot = new AssignmentProgress
                {
                    Phase = progress.Phase,
                    Attempt = progress.Attempt,
                    Sequence = progress.Sequence,
                    ContentBytes = progress.ContentBytes,
                };
                return true;
            }
        }

        public WorkerJobProgress Snapshot()
        {
            lock (gate)
            {
                return new WorkerJobProgress(
                    Assignment.AssignmentId,
                    progress.Phase,
                    progress.Attempt,
                    progress.Sequence,
                    progress.ContentBytes,
                    percent,
                    ItemIndex,
                    BatchTotal,
                    observedAt);
            }
        }

        public void RenewLease(DateTimeOffset expiresAt)
        {
            lock (gate)
            {
                if (!disposed && expiresAt > leaseExpiresAt)
                {
                    leaseExpiresAt = expiresAt;
                }
            }
        }

        public void Abort(string reason)
        {
            lock (gate)
            {
                if (disposed)
                {
                    return;
                }

                abortReason ??= SignedOrchestratorClient.SafeErrorCode(reason);
                abort.Cancel();
            }
        }

        public void Dispose()
        {
            lock (gate)
            {
                if (disposed)
                {
                    return;
                }

                disposed = true;
                abort.Dispose();
            }
        }
    }
}

public sealed class AssignmentExecutionLease
{
    private readonly AssignmentRuntimeRegistry.AssignmentRuntimeContext context;

    internal AssignmentExecutionLease(AssignmentRuntimeRegistry.AssignmentRuntimeContext context) =>
        this.context = context;

    public CancellationToken CancellationToken => context.CancellationToken;

    public string? AbortReason => context.AbortReason;

    public ValueTask ReportAsync(OllamaProgress progress)
    {
        context.Update(progress);
        return ValueTask.CompletedTask;
    }
}

public sealed record AppliedRuntimeContract(
    long ManifestSequence,
    string ManifestHash,
    string PolicyHash,
    string PromptConfigHash,
    string Provider,
    string Adapter,
    string AdapterVersion,
    string Model,
    string ModelDigest,
    string Protocol,
    string RuntimeProfileHash,
    string ContentContractHash)
{
    public static AppliedRuntimeContract FromAppliedState(AppliedManifestState state)
    {
        ArgumentNullException.ThrowIfNull(state);
        if (state.SchemaVersion != 1
            || state.ManifestSequence < 1
            || !HchDigest.IsLowerSha256(state.ManifestHash)
            || !HchDigest.IsLowerSha256(state.ContentContractHash)
            || !HchDigest.IsLowerSha256(state.PolicyHash)
            || !HchDigest.IsLowerSha256(state.PromptConfigHash)
            || !HchDigest.IsLowerSha256(state.RuntimeProfileHash))
        {
            throw new WorkerServiceException(
                "applied-manifest-state-invalid",
                "The durable applied-manifest state is invalid.");
        }

        AssignmentContractValidator.Validate(state.RuntimeProfile);
        var profile = state.RuntimeProfile;
        if (profile.ManifestSequence != state.ManifestSequence
            || profile.ManifestHash != state.ManifestHash
            || profile.PolicyHash != state.PolicyHash
            || profile.PromptConfigHash != state.PromptConfigHash
            || profile.RuntimeProfileHash != state.RuntimeProfileHash
            || profile.Provider != state.Provider
            || profile.EngineAdapter != state.EngineAdapter
            || profile.EngineAdapterVersion != state.EngineAdapterVersion
            || profile.Model != state.Model
            || NormalizeDigest(profile.ModelDigest) != NormalizeDigest(state.ModelDigest)
            || profile.Protocol != state.Protocol)
        {
            throw new WorkerServiceException(
                "applied-runtime-profile-mismatch",
                "The applied-manifest state does not match its immutable runtime profile.");
        }

        return new AppliedRuntimeContract(
            state.ManifestSequence,
            state.ManifestHash,
            state.PolicyHash,
            state.PromptConfigHash,
            state.Provider,
            state.EngineAdapter,
            state.EngineAdapterVersion,
            state.Model,
            state.ModelDigest,
            state.Protocol,
            state.RuntimeProfileHash,
            state.ContentContractHash);
    }

    public void Validate(WorkerAssignment assignment)
    {
        var profile = assignment.RuntimeProfile;
        if (profile.ManifestSequence != ManifestSequence || profile.ManifestHash != ManifestHash
            || profile.PolicyHash != PolicyHash || profile.PromptConfigHash != PromptConfigHash
            || profile.Provider != Provider || profile.EngineAdapter != Adapter
            || profile.EngineAdapterVersion != AdapterVersion || profile.Model != Model
            || NormalizeDigest(profile.ModelDigest) != NormalizeDigest(ModelDigest)
            || profile.Protocol != Protocol || profile.RuntimeProfileHash != RuntimeProfileHash)
        {
            throw new WorkerJobException(
                "assignment-runtime-profile-mismatch",
                "The assignment runtime profile differs from the trusted applied manifest.");
        }
    }

    private static string NormalizeDigest(string value) =>
        value.StartsWith("sha256:", StringComparison.OrdinalIgnoreCase)
            ? value[7..].ToLowerInvariant()
            : value.ToLowerInvariant();
}

/// <summary>
/// Durable result of a previously signature-verified manifest application.
/// Its absence of a download expiry is intentional: an expired download
/// manifest must not invalidate already verified runtime/content state.
/// </summary>
public sealed class AppliedManifestState
{
    [JsonRequired]
    public required int SchemaVersion { get; init; }

    [JsonRequired]
    public required long ManifestSequence { get; init; }

    [JsonRequired]
    public required string ManifestHash { get; init; }

    [JsonRequired]
    public required string ContentContractHash { get; init; }

    [JsonRequired]
    public required string PolicyHash { get; init; }

    [JsonRequired]
    public required string PromptConfigHash { get; init; }

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
    public required string RuntimeProfileHash { get; init; }

    [JsonRequired]
    public required WorkerRuntimeProfile RuntimeProfile { get; init; }

    [JsonExtensionData]
    public IDictionary<string, JsonElement>? AdditionalProperties { get; init; }
}

public sealed class OrchestratorJobSource(
    IOrchestratorClient client,
    WorkerControlState control,
    EditorialJournalStore journals,
    ProtectedEditorialRecoveryStore recovery,
    PendingClaimStore pendingClaims,
    AppliedRuntimeContract? appliedRuntime,
    TimeProvider? timeProvider = null) : IWorkerJobSource
{
    private static readonly byte[] EmptyBody = [];
    private readonly TimeProvider clock = timeProvider ?? TimeProvider.System;
    private readonly SemaphoreSlim claimGate = new(1, 1);

    public async Task<IReadOnlyList<WorkerJob>> ClaimAsync(
        int requestedCount,
        CancellationToken cancellationToken)
    {
        await claimGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var pending = await pendingClaims.ReadAsync(cancellationToken).ConfigureAwait(false);
            if (pending is null)
            {
                if (!control.IsClaimRequestAuthorized(requestedCount))
                {
                    return [];
                }

                pending = new PendingClaimRecord
                {
                    SchemaVersion = 1,
                    RequestId = Guid.NewGuid().ToString("D"),
                    RequestedCapacity = requestedCount,
                    CreatedAt = clock.GetUtcNow(),
                };
                await pendingClaims.WriteAsync(pending, cancellationToken).ConfigureAwait(false);
            }
            else if (pending.RequestedCapacity != requestedCount)
            {
                throw new WorkerServiceException(
                    "pending-claim-capacity-mismatch",
                    "A durable pending claim must be recovered before capacity can change.");
            }

            var response = await client.ClaimAsync(
                pending.RequestedCapacity,
                cancellationToken,
                pending.RequestId).ConfigureAwait(false);
            var jobs = await PersistClaimResponseAsync(
                response,
                validateAppliedRuntime: true,
                cancellationToken).ConfigureAwait(false);
            pendingClaims.Delete();
            if (jobs.Count == 0)
            {
                await Task.Delay(TimeSpan.FromSeconds(5), clock, cancellationToken).ConfigureAwait(false);
            }

            return jobs;
        }
        finally
        {
            claimGate.Release();
        }
    }

    public async Task<int> RecoverPendingClaimAsync(CancellationToken cancellationToken = default)
    {
        await claimGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var pending = await pendingClaims.ReadAsync(cancellationToken).ConfigureAwait(false);
            if (pending is null)
            {
                return 0;
            }

            var response = await client.ClaimAsync(
                pending.RequestedCapacity,
                cancellationToken,
                pending.RequestId,
                acceptExpiredAssignmentsForRecovery: true).ConfigureAwait(false);
            var jobs = await PersistClaimResponseAsync(
                response,
                validateAppliedRuntime: false,
                cancellationToken).ConfigureAwait(false);
            pendingClaims.Delete();
            return jobs.Count;
        }
        finally
        {
            claimGate.Release();
        }
    }

    private async Task<IReadOnlyList<WorkerJob>> PersistClaimResponseAsync(
        ClaimResponse response,
        bool validateAppliedRuntime,
        CancellationToken cancellationToken)
    {
        var jobs = new List<WorkerJob>(response.Assignments.Count);
        for (var assignmentIndex = 0; assignmentIndex < response.Assignments.Count; assignmentIndex++)
        {
            var assignment = response.Assignments[assignmentIndex];
            if (validateAppliedRuntime)
            {
                (appliedRuntime ?? throw new WorkerServiceException(
                    "applied-runtime-contract-missing",
                    "New claims require a trusted applied runtime contract."))
                    .Validate(assignment);
            }

            await recovery.EnsureClaimAsync(assignment, cancellationToken).ConfigureAwait(false);
            var leaseExpiresAt = ProtocolTime.ParseTimestamp(assignment.LeaseExpiresAt, "leaseExpiresAt");
            var prior = await journals.ReadAsync(assignment.AssignmentId, cancellationToken).ConfigureAwait(false);
            if (prior is null)
            {
                prior = new EditorialJobJournal(
                    EditorialJobJournal.CurrentSchemaVersion,
                    assignment.AssignmentId,
                    assignment.GenerationPlanHash,
                    HchDigest.Sha256Hex(assignment.LeaseToken),
                    leaseExpiresAt,
                    EditorialJournalPhase.Claimed,
                    Guid.NewGuid().ToString("D"),
                    HchDigest.Sha256Hex(EmptyBody),
                    DraftHash: null,
                    LastErrorCode: null,
                    UpdatedAt: clock.GetUtcNow());
                await journals.WriteAsync(prior, cancellationToken).ConfigureAwait(false);
            }
            else if (prior.Phase != EditorialJournalPhase.Claimed
                || prior.GenerationPlanHash != assignment.GenerationPlanHash
                || prior.LeaseTokenHash != HchDigest.Sha256Hex(assignment.LeaseToken)
                || prior.LeaseExpiresAt != leaseExpiresAt)
            {
                throw new WorkerServiceException(
                    "pending-claim-journal-mismatch",
                    "The replayed claim differs from its durable assignment journal.");
            }

            jobs.Add(new WorkerJob(
                assignment.AssignmentId,
                assignment.LeaseToken,
                leaseExpiresAt,
                assignment.GenerationPlanHash,
                assignment,
                ItemIndex: assignmentIndex + 1,
                BatchTotal: response.Assignments.Count));
        }

        return jobs;
    }
}

public sealed class OllamaEditorialJobExecutor(
    OllamaChatClient ollama,
    EditorialJournalStore journals,
    ProtectedEditorialRecoveryStore recovery,
    AssignmentRuntimeRegistry progress,
    AppliedRuntimeContract appliedRuntime,
    TimeProvider? timeProvider = null) : IWorkerJobExecutor
{
    private readonly TimeProvider clock = timeProvider ?? TimeProvider.System;

    public async Task<JobExecutionResult> ExecuteAsync(WorkerJob job, CancellationToken cancellationToken)
    {
        var assignment = Payload(job);
        appliedRuntime.Validate(assignment);
        var lease = progress.Begin(assignment, job.ItemIndex, job.BatchTotal);
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, lease.CancellationToken);
        var journal = await RequiredJournalAsync(job.AssignmentId, cancellationToken).ConfigureAwait(false);
        if (journal.Phase != EditorialJournalPhase.Claimed)
        {
            throw new WorkerJobException("assignment-journal-phase-invalid", "The assignment is not in Claimed state.");
        }

        journal = journal.Transition(EditorialJournalPhase.Generating, clock.GetUtcNow());
        await journals.WriteAsync(journal, cancellationToken).ConfigureAwait(false);
        try
        {
            var runtime = assignment.RuntimeProfile;
            var generation = assignment.GenerationPlan;
            var plan = new OllamaGenerationPlan(
                runtime.Model,
                runtime.Temperature,
                runtime.ContextWindow,
                Math.Min(runtime.MaxOutputTokens, generation.MaxOutputTokens),
                generation.FirstProgressGraceSeconds,
                generation.StallAfterSeconds,
                generation.FinalizationGraceSeconds).Validate();
            var result = await ollama.GenerateJsonAsync(
                plan,
                SystemPrompt(generation.EditorialProfile),
                assignment.Entry,
                attempt: 1,
                lease.ReportAsync,
                linked.Token).ConfigureAwait(false);
            var draft = EditorialDraftBuilder.Build(
                result.Content,
                ContentKind(generation.EditorialProfile),
                result.Model,
                assignment.GenerationPlanHash,
                appliedRuntime.ContentContractHash,
                clock);
            var draftHash = HchDigest.Sha256Hex(ProtocolJson.SerializeCanonicalToUtf8(draft));
            await recovery.SaveDraftAsync(assignment, draft, CancellationToken.None).ConfigureAwait(false);
            journal = journal.Transition(EditorialJournalPhase.DraftReady, clock.GetUtcNow(), draftHash);
            await journals.WriteAsync(journal, CancellationToken.None).ConfigureAwait(false);
            return new JobExecutionResult(job.AssignmentId, "pending-editorial-review", draft);
        }
        catch (OperationCanceledException error) when (lease.CancellationToken.IsCancellationRequested)
        {
            throw new WorkerJobException(
                lease.AbortReason ?? "assignment-liveness-cancelled",
                "The assignment liveness contract cancelled local generation.",
                error);
        }
    }

    private async Task<EditorialJobJournal> RequiredJournalAsync(string assignmentId, CancellationToken cancellationToken) =>
        await journals.ReadAsync(assignmentId, cancellationToken).ConfigureAwait(false)
        ?? throw new WorkerJobException("assignment-journal-missing", "The durable assignment journal is missing.");

    private static WorkerAssignment Payload(WorkerJob job) => job.Payload as WorkerAssignment
        ?? throw new WorkerJobException("assignment-payload-invalid", "The scheduler payload is not an assignment.");

    private static EditorialContentKind ContentKind(string profile) => profile switch
    {
        "CATALOG_SUMMARY" => EditorialContentKind.Catalog,
        "EVENT_LISTING" => EditorialContentKind.Event,
        _ => EditorialContentKind.Article,
    };

    private static string SystemPrompt(string profile) =>
        $"Gere conteúdo editorial HCH no perfil assinado {profile}. Preserve fatos da entrada e cite as fontes fornecidas.";
}

public sealed class JournaledJobReporter(
    IOrchestratorClient client,
    EditorialJournalStore journals,
    ProtectedEditorialRecoveryStore recovery,
    AssignmentRuntimeRegistry progress,
    string nodeId,
    string keyId,
    Action<string>? unsafeOutcome = null,
    Action<TimeSpan?>? completed = null,
    Action? failed = null,
    TimeProvider? timeProvider = null) : IWorkerJobReporter
{
    private readonly TimeProvider clock = timeProvider ?? TimeProvider.System;

    public async Task CompleteAsync(
        WorkerJob job,
        JobExecutionResult result,
        CancellationToken cancellationToken)
    {
        var assignment = Payload(job);
        var draft = result.Draft ?? throw new WorkerJobException("editorial-draft-missing", "Completion requires a draft.");
        var journal = await RequiredJournalAsync(job.AssignmentId, cancellationToken).ConfigureAwait(false);
        if (journal.Phase == EditorialJournalPhase.Generating)
        {
            journal = journal.Transition(
                EditorialJournalPhase.DraftReady,
                clock.GetUtcNow(),
                HchDigest.Sha256Hex(ProtocolJson.SerializeCanonicalToUtf8(draft)));
        }

        if (journal.Phase != EditorialJournalPhase.DraftReady)
        {
            throw new WorkerJobException("assignment-journal-phase-invalid", "Completion is not recoverable from this journal phase.");
        }

        var request = OutcomeBodies.Complete(nodeId, keyId, assignment, draft);
        journal = (journal with
        {
            RequestBodyDigest = HchDigest.Sha256Hex(ProtocolJson.SerializeCanonicalToUtf8(request)),
        }).Transition(EditorialJournalPhase.Completing, clock.GetUtcNow());
        await journals.WriteAsync(journal, cancellationToken).ConfigureAwait(false);
        try
        {
            await client.CompleteAsync(assignment, draft, journal.RequestId, cancellationToken).ConfigureAwait(false);
            journal = journal.Transition(EditorialJournalPhase.Completed, clock.GetUtcNow());
            await journals.WriteAsync(journal, cancellationToken).ConfigureAwait(false);
            recovery.Delete(job.AssignmentId);
            completed?.Invoke(progress.Elapsed(job.AssignmentId, clock.GetUtcNow()));
        }
        catch (Exception error) when (error is OrchestratorRequestException or WorkerServiceException)
        {
            journal = journal.Transition(
                EditorialJournalPhase.CommitUnknown,
                clock.GetUtcNow(),
                lastErrorCode: ErrorCode(error));
            await journals.WriteAsync(journal, CancellationToken.None).ConfigureAwait(false);
            unsafeOutcome?.Invoke("assignment-complete-unknown");
            throw;
        }
        finally
        {
            progress.Finish(job.AssignmentId);
        }
    }

    public async Task FailAsync(WorkerJob job, string errorCode, CancellationToken cancellationToken)
    {
        var assignment = Payload(job);
        var safeCode = SignedOrchestratorClient.SafeErrorCode(errorCode);
        var journal = await RequiredJournalAsync(job.AssignmentId, cancellationToken).ConfigureAwait(false);
        if (journal.Phase is not (EditorialJournalPhase.Claimed or EditorialJournalPhase.Generating
            or EditorialJournalPhase.DraftReady or EditorialJournalPhase.FailUnknown))
        {
            throw new WorkerJobException("assignment-journal-phase-invalid", "Failure is not recoverable from this journal phase.");
        }

        var request = OutcomeBodies.Fail(nodeId, keyId, assignment, safeCode);
        journal = journal with
        {
            RequestBodyDigest = HchDigest.Sha256Hex(ProtocolJson.SerializeCanonicalToUtf8(request)),
        };
        journal = journal.Transition(EditorialJournalPhase.FailUnknown, clock.GetUtcNow(), lastErrorCode: safeCode);
        await journals.WriteAsync(journal, cancellationToken).ConfigureAwait(false);
        try
        {
            await client.FailAsync(assignment, safeCode, journal.RequestId, cancellationToken).ConfigureAwait(false);
            journal = journal.Transition(EditorialJournalPhase.Failed, clock.GetUtcNow(), lastErrorCode: safeCode);
            await journals.WriteAsync(journal, cancellationToken).ConfigureAwait(false);
            recovery.Delete(job.AssignmentId);
            failed?.Invoke();
        }
        catch (Exception error) when (error is OrchestratorRequestException or WorkerServiceException)
        {
            journal = journal.Transition(
                EditorialJournalPhase.FailUnknown,
                clock.GetUtcNow(),
                lastErrorCode: ErrorCode(error));
            await journals.WriteAsync(journal, CancellationToken.None).ConfigureAwait(false);
            unsafeOutcome?.Invoke("assignment-fail-unknown");
            throw;
        }
        finally
        {
            progress.Finish(job.AssignmentId);
        }
    }

    private async Task<EditorialJobJournal> RequiredJournalAsync(string assignmentId, CancellationToken cancellationToken) =>
        await journals.ReadAsync(assignmentId, cancellationToken).ConfigureAwait(false)
        ?? throw new WorkerJobException("assignment-journal-missing", "The durable assignment journal is missing.");

    private static WorkerAssignment Payload(WorkerJob job) => job.Payload as WorkerAssignment
        ?? throw new WorkerJobException("assignment-payload-invalid", "The scheduler payload is not an assignment.");

    private static string ErrorCode(Exception error) => error switch
    {
        OrchestratorRequestException request => request.Code,
        WorkerServiceException service => service.Code,
        _ => "assignment-outcome-unknown",
    };
}
