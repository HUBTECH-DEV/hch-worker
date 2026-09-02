using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using Hch.Worker.Persistence;
using Hch.Worker.Protocol;

namespace Hch.Worker.Service;

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed class PendingClaimRecord
{
    [JsonRequired]
    public required int SchemaVersion { get; init; }

    [JsonRequired]
    public required string RequestId { get; init; }

    [JsonRequired]
    public required int RequestedCapacity { get; init; }

    [JsonRequired]
    public required DateTimeOffset CreatedAt { get; init; }
}

/// <summary>
/// Persists the claim request identifier before contacting HCH. Replaying the
/// same request after a crash recovers the exact centrally committed claim.
/// The record contains no lease, token, content or private key material.
/// </summary>
public sealed class PendingClaimStore(AtomicFileStore files)
{
    public const string RelativePath = "journals/pending-claim.json";

    public async Task<PendingClaimRecord?> ReadAsync(CancellationToken cancellationToken = default)
    {
        var value = await files.ReadJsonAsync<PendingClaimRecord>(RelativePath, cancellationToken)
            .ConfigureAwait(false);
        if (value is not null)
        {
            Validate(value);
        }

        return value;
    }

    public Task WriteAsync(PendingClaimRecord value, CancellationToken cancellationToken = default)
    {
        Validate(value);
        return files.WriteJsonAsync(RelativePath, value, cancellationToken);
    }

    public void Delete()
    {
        var path = files.Resolve(RelativePath);
        if (File.Exists(path))
        {
            File.Delete(path);
        }
    }

    private static void Validate(PendingClaimRecord value)
    {
        if (value.SchemaVersion != 1
            || !Guid.TryParseExact(value.RequestId, "D", out var requestId)
            || requestId == Guid.Empty
            || value.RequestedCapacity is < 1 or > 64
            || value.CreatedAt == default)
        {
            throw new WorkerServiceException(
                "pending-claim-state-invalid",
                "The durable pending claim record is invalid.");
        }
    }
}

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed class EditorialRecoveryEvidence
{
    [JsonRequired]
    public required int SchemaVersion { get; init; }

    [JsonRequired]
    public required WorkerAssignment Assignment { get; init; }

    [JsonRequired]
    public required JsonElement? Draft { get; init; }

    [JsonRequired]
    public required DateTimeOffset UpdatedAt { get; init; }
}

/// <summary>
/// Stores the lease-bearing assignment and any generated draft under DPAPI
/// LocalMachine protection. Public journals retain only hashes and state.
/// </summary>
public sealed class ProtectedEditorialRecoveryStore(
    AtomicFileStore files,
    MachineSecretProtector protector,
    string nodeId,
    TimeProvider? timeProvider = null)
{
    private readonly TimeProvider clock = timeProvider ?? TimeProvider.System;

    public async Task EnsureClaimAsync(
        WorkerAssignment assignment,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(assignment);
        ValidateAssignmentForRecovery(assignment);
        var current = await ReadAsync(assignment.AssignmentId, cancellationToken).ConfigureAwait(false);
        if (current is not null)
        {
            EnsureSameAssignment(current.Assignment, assignment);
            return;
        }

        await WriteAsync(new EditorialRecoveryEvidence
        {
            SchemaVersion = 1,
            Assignment = assignment,
            Draft = null,
            UpdatedAt = clock.GetUtcNow(),
        }, cancellationToken).ConfigureAwait(false);
    }

    public async Task SaveDraftAsync(
        WorkerAssignment assignment,
        object draft,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(assignment);
        ArgumentNullException.ThrowIfNull(draft);
        var current = await ReadAsync(assignment.AssignmentId, cancellationToken).ConfigureAwait(false)
            ?? throw new WorkerServiceException(
                "assignment-recovery-evidence-missing",
                "Protected recovery evidence is missing for the assignment.");
        EnsureSameAssignment(current.Assignment, assignment);
        var draftElement = JsonSerializer.SerializeToElement(draft, ProtocolJson.SerializerOptions);
        if (draftElement.ValueKind != JsonValueKind.Object)
        {
            throw new WorkerServiceException(
                "assignment-recovery-draft-invalid",
                "The protected recovery draft must be a JSON object.");
        }

        if (current.Draft is { } existing
            && !CryptographicOperations.FixedTimeEquals(
                SHA256.HashData(ProtocolJson.SerializeCanonicalToUtf8(existing)),
                SHA256.HashData(ProtocolJson.SerializeCanonicalToUtf8(draftElement))))
        {
            throw new WorkerServiceException(
                "assignment-recovery-draft-mismatch",
                "Protected recovery evidence already contains a different draft.");
        }

        await WriteAsync(new EditorialRecoveryEvidence
        {
            SchemaVersion = 1,
            Assignment = current.Assignment,
            Draft = draftElement,
            UpdatedAt = clock.GetUtcNow(),
        }, cancellationToken).ConfigureAwait(false);
    }

    public async Task<EditorialRecoveryEvidence?> ReadAsync(
        string assignmentId,
        CancellationToken cancellationToken = default)
    {
        ValidateAssignmentId(assignmentId);
        var path = files.Resolve(PathFor(assignmentId));
        if (!File.Exists(path))
        {
            return null;
        }

        byte[] protectedBytes = await File.ReadAllBytesAsync(path, cancellationToken).ConfigureAwait(false);
        byte[]? plaintext = null;
        try
        {
            plaintext = protector.Unprotect(protectedBytes, Purpose(assignmentId));
            var value = ProtocolJson.Deserialize<EditorialRecoveryEvidence>(plaintext);
            Validate(value, assignmentId);
            return value;
        }
        catch (CryptographicException error)
        {
            throw new WorkerServiceException(
                "assignment-recovery-evidence-unprotect-failed",
                "Protected assignment recovery evidence cannot be opened.",
                error);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(protectedBytes);
            if (plaintext is not null)
            {
                CryptographicOperations.ZeroMemory(plaintext);
            }
        }
    }

    public void Delete(string assignmentId)
    {
        ValidateAssignmentId(assignmentId);
        var path = files.Resolve(PathFor(assignmentId));
        if (File.Exists(path))
        {
            File.Delete(path);
        }
    }

    private async Task WriteAsync(
        EditorialRecoveryEvidence value,
        CancellationToken cancellationToken)
    {
        Validate(value, value.Assignment.AssignmentId);
        byte[] plaintext = ProtocolJson.SerializeCanonicalToUtf8(value);
        byte[]? protectedBytes = null;
        try
        {
            protectedBytes = protector.Protect(plaintext, Purpose(value.Assignment.AssignmentId));
            await files.WriteBytesAsync(
                PathFor(value.Assignment.AssignmentId),
                protectedBytes,
                cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plaintext);
            if (protectedBytes is not null)
            {
                CryptographicOperations.ZeroMemory(protectedBytes);
            }
        }
    }

    private void Validate(EditorialRecoveryEvidence value, string expectedAssignmentId)
    {
        if (value.SchemaVersion != 1
            || value.UpdatedAt == default
            || value.Assignment.AssignmentId != expectedAssignmentId
            || value.Draft is { ValueKind: not JsonValueKind.Object })
        {
            throw new WorkerServiceException(
                "assignment-recovery-evidence-invalid",
                "Protected assignment recovery evidence is invalid.");
        }

        ValidateAssignmentForRecovery(value.Assignment);
    }

    private static void ValidateAssignmentForRecovery(WorkerAssignment assignment)
    {
        var expiresAt = ProtocolTime.ParseTimestamp(assignment.LeaseExpiresAt, "leaseExpiresAt");
        AssignmentContractValidator.Validate(assignment, expiresAt.Subtract(TimeSpan.FromTicks(1)));
    }

    private static void EnsureSameAssignment(WorkerAssignment left, WorkerAssignment right)
    {
        var leftDigest = SHA256.HashData(ProtocolJson.SerializeCanonicalToUtf8(left));
        var rightDigest = SHA256.HashData(ProtocolJson.SerializeCanonicalToUtf8(right));
        try
        {
            if (!CryptographicOperations.FixedTimeEquals(leftDigest, rightDigest))
            {
                throw new WorkerServiceException(
                    "assignment-recovery-evidence-mismatch",
                    "Protected recovery evidence differs from the claimed assignment.");
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(leftDigest);
            CryptographicOperations.ZeroMemory(rightDigest);
        }
    }

    private static string PathFor(string assignmentId) =>
        Path.Combine("journals", "recovery", assignmentId + ".json.dpapi");

    private string Purpose(string assignmentId) => $"assignment-recovery:{nodeId}:{assignmentId}";

    private static void ValidateAssignmentId(string assignmentId)
    {
        if (!Guid.TryParseExact(assignmentId, "D", out var value) || value == Guid.Empty)
        {
            throw new ArgumentException("The assignment identifier is invalid.", nameof(assignmentId));
        }
    }
}

public sealed record EditorialReconciliationResult(
    int Scanned,
    int Reconciled,
    int Pending,
    IReadOnlyList<string> ErrorCodes);

/// <summary>
/// Replays only durable complete/fail operations. It never regenerates content.
/// Active pre-draft work interrupted by an SCM/process restart is reported as a
/// failure; a protected draft is completed with the original requestId.
/// </summary>
public sealed class EditorialOutcomeReconciler(
    IOrchestratorClient client,
    EditorialJournalStore journals,
    ProtectedEditorialRecoveryStore recovery,
    string nodeId,
    string keyId,
    Action? completed = null,
    Action? failed = null,
    TimeProvider? timeProvider = null)
{
    public const string RestartFailureCode = "worker-restarted-before-outcome";
    private readonly TimeProvider clock = timeProvider ?? TimeProvider.System;

    public async Task<EditorialReconciliationResult> ReconcileAsync(
        CancellationToken cancellationToken = default)
    {
        var scanned = 0;
        var reconciled = 0;
        var pending = 0;
        var errors = new List<string>();
        foreach (var assignmentId in journals.ListAssignmentIds())
        {
            cancellationToken.ThrowIfCancellationRequested();
            scanned++;
            var journal = await journals.ReadAsync(assignmentId, cancellationToken).ConfigureAwait(false);
            if (journal is null)
            {
                pending++;
                errors.Add("assignment-journal-missing");
                continue;
            }

            if (!journal.RequiresReconciliation && !journal.IsActive)
            {
                recovery.Delete(assignmentId);
                continue;
            }

            try
            {
                var evidence = await recovery.ReadAsync(assignmentId, cancellationToken).ConfigureAwait(false)
                    ?? throw new WorkerServiceException(
                        "assignment-recovery-evidence-missing",
                        "Protected recovery evidence is missing for an unfinished assignment.");
                ValidateCorrelation(journal, evidence);
                if (journal.Phase is EditorialJournalPhase.DraftReady
                    or EditorialJournalPhase.Completing
                    or EditorialJournalPhase.CommitUnknown
                    || journal.Phase == EditorialJournalPhase.Generating && evidence.Draft is not null)
                {
                    journal = await ReconcileCompletionAsync(journal, evidence, cancellationToken)
                        .ConfigureAwait(false);
                    completed?.Invoke();
                }
                else
                {
                    journal = await ReconcileFailureAsync(journal, evidence, cancellationToken)
                        .ConfigureAwait(false);
                    failed?.Invoke();
                }

                recovery.Delete(assignmentId);
                reconciled++;
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception error) when (error is OrchestratorRequestException
                or WorkerServiceException
                or ProtocolValidationException
                or CryptographicException
                or JsonException)
            {
                pending++;
                errors.Add(ErrorCode(error));
            }
        }

        return new EditorialReconciliationResult(scanned, reconciled, pending, errors);
    }

    private async Task<EditorialJobJournal> ReconcileCompletionAsync(
        EditorialJobJournal journal,
        EditorialRecoveryEvidence evidence,
        CancellationToken cancellationToken)
    {
        if (evidence.Draft is not { } draft)
        {
            throw new WorkerServiceException(
                "assignment-recovery-draft-missing",
                "Completion reconciliation requires the protected draft.");
        }

        var draftHash = HchDigest.Sha256Hex(ProtocolJson.SerializeCanonicalToUtf8(draft));
        if (journal.DraftHash is not null && journal.DraftHash != draftHash)
        {
            throw new WorkerServiceException(
                "assignment-recovery-draft-hash-mismatch",
                "The protected draft differs from the public journal digest.");
        }

        if (journal.Phase == EditorialJournalPhase.Generating)
        {
            journal = journal.Transition(EditorialJournalPhase.DraftReady, clock.GetUtcNow(), draftHash);
            await journals.WriteAsync(journal, cancellationToken).ConfigureAwait(false);
        }

        var request = OutcomeBodies.Complete(nodeId, keyId, evidence.Assignment, draft);
        var requestDigest = HchDigest.Sha256Hex(ProtocolJson.SerializeCanonicalToUtf8(request));
        if (journal.Phase == EditorialJournalPhase.DraftReady)
        {
            journal = (journal with { RequestBodyDigest = requestDigest })
                .Transition(EditorialJournalPhase.Completing, clock.GetUtcNow(), draftHash);
            await journals.WriteAsync(journal, cancellationToken).ConfigureAwait(false);
        }
        else if (journal.RequestBodyDigest != requestDigest)
        {
            throw new WorkerServiceException(
                "assignment-recovery-request-digest-mismatch",
                "The completion request differs from its durable journal digest.");
        }

        try
        {
            await client.CompleteAsync(
                evidence.Assignment,
                draft,
                journal.RequestId,
                cancellationToken).ConfigureAwait(false);
            journal = journal.Transition(EditorialJournalPhase.Completed, clock.GetUtcNow());
            await journals.WriteAsync(journal, cancellationToken).ConfigureAwait(false);
            return journal;
        }
        catch (Exception error) when (error is OrchestratorRequestException or WorkerServiceException)
        {
            journal = journal.Transition(
                EditorialJournalPhase.CommitUnknown,
                clock.GetUtcNow(),
                lastErrorCode: ErrorCode(error));
            await journals.WriteAsync(journal, CancellationToken.None).ConfigureAwait(false);
            throw;
        }
    }

    private async Task<EditorialJobJournal> ReconcileFailureAsync(
        EditorialJobJournal journal,
        EditorialRecoveryEvidence evidence,
        CancellationToken cancellationToken)
    {
        var errorCode = journal.Phase == EditorialJournalPhase.FailUnknown
            ? SignedOrchestratorClient.SafeErrorCode(journal.LastErrorCode ?? RestartFailureCode)
            : RestartFailureCode;
        var request = OutcomeBodies.Fail(nodeId, keyId, evidence.Assignment, errorCode);
        var requestDigest = HchDigest.Sha256Hex(ProtocolJson.SerializeCanonicalToUtf8(request));
        if (journal.Phase != EditorialJournalPhase.FailUnknown)
        {
            journal = (journal with { RequestBodyDigest = requestDigest })
                .Transition(
                    EditorialJournalPhase.FailUnknown,
                    clock.GetUtcNow(),
                    lastErrorCode: errorCode);
            await journals.WriteAsync(journal, cancellationToken).ConfigureAwait(false);
        }
        else if (journal.RequestBodyDigest != requestDigest)
        {
            throw new WorkerServiceException(
                "assignment-recovery-request-digest-mismatch",
                "The failure request differs from its durable journal digest.");
        }

        try
        {
            await client.FailAsync(
                evidence.Assignment,
                errorCode,
                journal.RequestId,
                cancellationToken).ConfigureAwait(false);
            journal = journal.Transition(
                EditorialJournalPhase.Failed,
                clock.GetUtcNow(),
                lastErrorCode: errorCode);
            await journals.WriteAsync(journal, cancellationToken).ConfigureAwait(false);
            return journal;
        }
        catch (Exception error) when (error is OrchestratorRequestException or WorkerServiceException)
        {
            journal = journal.Transition(
                EditorialJournalPhase.FailUnknown,
                clock.GetUtcNow(),
                lastErrorCode: errorCode);
            await journals.WriteAsync(journal, CancellationToken.None).ConfigureAwait(false);
            throw;
        }
    }

    private static void ValidateCorrelation(
        EditorialJobJournal journal,
        EditorialRecoveryEvidence evidence)
    {
        if (journal.AssignmentId != evidence.Assignment.AssignmentId
            || journal.GenerationPlanHash != evidence.Assignment.GenerationPlanHash
            || journal.LeaseTokenHash != HchDigest.Sha256Hex(evidence.Assignment.LeaseToken))
        {
            throw new WorkerServiceException(
                "assignment-recovery-correlation-mismatch",
                "Protected recovery evidence does not match the public journal.");
        }
    }

    private static string ErrorCode(Exception error) => error switch
    {
        OrchestratorRequestException request => request.Code,
        WorkerServiceException service => service.Code,
        ProtocolValidationException protocol => protocol.Code,
        CryptographicException => "assignment-recovery-cryptographic-failure",
        JsonException => "assignment-recovery-json-invalid",
        _ => "assignment-recovery-failed",
    };
}

internal static class OutcomeBodies
{
    public static CompleteAssignmentRequest Complete(
        string nodeId,
        string keyId,
        WorkerAssignment assignment,
        object draft) => new()
        {
            AssignmentId = assignment.AssignmentId,
            NodeId = nodeId,
            WorkerKeyId = keyId,
            LeaseToken = assignment.LeaseToken,
            GenerationPlanHash = assignment.GenerationPlanHash,
            ManifestSequence = assignment.RuntimeProfile.ManifestSequence,
            ManifestHash = assignment.RuntimeProfile.ManifestHash,
            PolicyHash = assignment.RuntimeProfile.PolicyHash,
            RuntimeProfileHash = assignment.RuntimeProfile.RuntimeProfileHash,
            InputSnapshotHash = assignment.InputSnapshotHash,
            Draft = draft,
        };

    public static FailAssignmentRequest Fail(
        string nodeId,
        string keyId,
        WorkerAssignment assignment,
        string errorCode) => new()
        {
            AssignmentId = assignment.AssignmentId,
            NodeId = nodeId,
            WorkerKeyId = keyId,
            LeaseToken = assignment.LeaseToken,
            GenerationPlanHash = assignment.GenerationPlanHash,
            ErrorCode = errorCode,
        };
}
