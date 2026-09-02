using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Hch.Worker.Protocol;
using Hch.Worker.Security;

namespace Hch.Worker.Persistence;

/// <summary>
/// Performs the Windows 3.1 to 4.x state hand-off without mutating the legacy
/// installation. Readiness and signed applied state are retained as evidence
/// only; V4 must bootstrap and attest again while Paused/Drain.
/// </summary>
public sealed partial class LegacyWindowsWorkerMigrator(
    IMachineSecretProtector secretProtector,
    ILegacyWorkerRuntimePreflight runtimePreflight,
    TimeProvider? timeProvider = null,
    ILegacyMigrationFaultInjector? faultInjector = null)
{
    private const int MaximumSnapshotFiles = 50_000;
    private const long MaximumSnapshotFileBytes = 512L * 1024 * 1024;
    private const long MaximumSnapshotBytes = 4L * 1024 * 1024 * 1024;
    private const string BackupReceiptFileName = "backup-receipt.json";
    private const string ReadinessDisposition = "rebuild-by-v4-bootstrap-attestation";

    private static readonly string[] BackupOnlyState =
    [
        "applied-manifest",
        "ready",
        "trust-state",
        "enrollment-receipt",
        "pending-operations",
        "journals",
        "update-evidence",
    ];

    private readonly SemaphoreSlim migrationGate = new(1, 1);
    private readonly TimeProvider clock = timeProvider ?? TimeProvider.System;

    public async Task<LegacyWindowsMigrationResult> MigrateAsync(
        LegacyWindowsMigrationRequest request,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        await migrationGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        string? migrationId = null;
        string? targetRoot = null;
        try
        {
            (string sourceRoot, targetRoot) = ValidateRequest(request);
            LegacyConfigurationProjection legacy = await LegacyWindowsMigrationParsing
                .ReadConfigurationAsync(sourceRoot, cancellationToken).ConfigureAwait(false);
            string serviceName = CreateLegacyServiceName(legacy.NodeId);
            var descriptor = new LegacyWorkerSourceDescriptor(
                sourceRoot,
                legacy.StateRoot,
                legacy.NodeId,
                serviceName);

            MigrationInspection firstInspection = await new LegacyWorkerStateInspector(
                legacy.StateRoot,
                clock).InspectAsync(cancellationToken).ConfigureAwait(false);
            EnsureNoStateBlockers(firstInspection);
            LegacyRuntimePreflightEvidence firstPreflight = await runtimePreflight
                .CaptureAsync(descriptor, cancellationToken).ConfigureAwait(false);
            ValidatePreflight(firstPreflight, descriptor);

            IReadOnlyList<LegacySnapshotFile> firstSnapshot = await BuildSnapshotAsync(
                sourceRoot,
                cancellationToken).ConfigureAwait(false);
            ValidateAclCoverage(firstPreflight, firstSnapshot);
            string snapshotDigest = SnapshotDigest(firstSnapshot);

            using Ed25519Identity identity = await LegacyWindowsMigrationParsing
                .ReadAndValidateIdentityAsync(sourceRoot, legacy, cancellationToken).ConfigureAwait(false);
            LegacyControlProjection control = await LegacyWindowsMigrationParsing
                .ReadControlAsync(sourceRoot, legacy, cancellationToken).ConfigureAwait(false);
            LegacyRootTrustProjection trust = await LegacyWindowsMigrationParsing
                .ReadRootTrustAsync(sourceRoot, legacy, cancellationToken).ConfigureAwait(false);
            migrationId = CreateMigrationId(
                request.SourceVersion,
                request.TargetVersion,
                legacy.NodeId,
                identity.Fingerprint,
                snapshotDigest);

            string stateRoot = Path.Combine(targetRoot, "state");
            Directory.CreateDirectory(stateRoot);
            RejectReparsePoints(stateRoot, targetRoot);
            var targetState = new AtomicFileStore(stateRoot);
            LegacyWindowsMigrationJournal? existing = await ReadJournalAsync(
                targetState,
                cancellationToken).ConfigureAwait(false);
            if (existing is not null)
            {
                if (existing.MigrationId != migrationId)
                {
                    throw Fail("legacy-migration-target-journal-conflict");
                }

                if (existing.Phase == MigrationPhase.Committed)
                {
                    await ValidateCommittedAsync(targetRoot, existing, cancellationToken).ConfigureAwait(false);
                    return Result(targetRoot, stateRoot, existing);
                }

                if (existing.Phase != MigrationPhase.RolledBack)
                {
                    await RollbackInternalAsync(
                        targetRoot,
                        targetState,
                        existing,
                        CancellationToken.None).ConfigureAwait(false);
                }
            }

            EnsureTargetUninitialized(targetRoot);
            string backupRelativePath = $"migration-backups/{migrationId}";
            string backupRoot = targetState.Resolve(backupRelativePath);
            var prepared = CreateJournal(
                request,
                sourceRoot,
                snapshotDigest,
                backupRelativePath,
                legacy.NodeId,
                identity.Fingerprint,
                control,
                MigrationPhase.Prepared,
                targetArtifacts: [],
                importedRelativePaths: [],
                lastErrorCode: null);
            await WriteJournalAsync(targetState, prepared, cancellationToken).ConfigureAwait(false);

            await EnsureImmutableBackupAsync(
                sourceRoot,
                backupRoot,
                prepared,
                firstSnapshot,
                firstPreflight,
                cancellationToken).ConfigureAwait(false);
            prepared = prepared with
            {
                Phase = MigrationPhase.BackedUp,
                UpdatedAt = Timestamp(),
            };
            await WriteJournalAsync(targetState, prepared, cancellationToken).ConfigureAwait(false);

            IReadOnlyList<LegacySnapshotFile> secondSnapshot = await BuildSnapshotAsync(
                sourceRoot,
                cancellationToken).ConfigureAwait(false);
            if (!firstSnapshot.SequenceEqual(secondSnapshot)
                || snapshotDigest != SnapshotDigest(secondSnapshot))
            {
                throw Fail("legacy-source-changed-during-migration");
            }

            MigrationInspection secondInspection = await new LegacyWorkerStateInspector(
                legacy.StateRoot,
                clock).InspectAsync(cancellationToken).ConfigureAwait(false);
            EnsureNoStateBlockers(secondInspection);
            LegacyRuntimePreflightEvidence secondPreflight = await runtimePreflight
                .CaptureAsync(descriptor, cancellationToken).ConfigureAwait(false);
            ValidatePreflight(secondPreflight, descriptor);
            ValidateAclCoverage(secondPreflight, secondSnapshot);
            if (PreflightDigest(firstPreflight) != PreflightDigest(secondPreflight))
            {
                throw Fail("legacy-preflight-changed-during-migration");
            }

            MigratedWorkerConfiguration targetConfiguration = LegacyWindowsMigrationParsing
                .ProjectTargetConfiguration(
                    targetRoot,
                    request.OwnerSid,
                    legacy,
                    control,
                    trust,
                    identity.Fingerprint);
            IReadOnlyList<LegacyTargetArtifact> artifacts = await StageTargetArtifactsAsync(
                targetRoot,
                targetState,
                migrationId,
                targetConfiguration,
                trust,
                identity,
                cancellationToken).ConfigureAwait(false);
            LegacyWindowsMigrationJournal importing = prepared with
            {
                Phase = MigrationPhase.Imported,
                TargetArtifacts = artifacts,
                UpdatedAt = Timestamp(),
            };
            await WriteJournalAsync(targetState, importing, cancellationToken).ConfigureAwait(false);

            var importedPaths = new List<string>();
            for (int index = 0; index < artifacts.Count; index++)
            {
                LegacyTargetArtifact artifact = artifacts[index];
                importedPaths.Add(artifact.RelativePath);
                importing = importing with
                {
                    ImportedRelativePaths = importedPaths.ToArray(),
                    UpdatedAt = Timestamp(),
                };
                // Persist intent first. A crash after the atomic move remains
                // selectively recoverable even before the next journal write.
                await WriteJournalAsync(targetState, importing, cancellationToken).ConfigureAwait(false);
                CommitStagedArtifact(targetRoot, targetState, migrationId, artifact);
                if (faultInjector is not null)
                {
                    await faultInjector.AfterTargetArtifactAsync(
                        artifact.RelativePath,
                        importedPaths.Count,
                        cancellationToken).ConfigureAwait(false);
                }
            }

            LegacyWindowsMigrationJournal committed = importing with
            {
                Phase = MigrationPhase.Committed,
                UpdatedAt = Timestamp(),
                LastErrorCode = null,
            };
            await WriteJournalAsync(targetState, committed, cancellationToken).ConfigureAwait(false);
            TryDeleteStaging(targetState, migrationId);
            return Result(targetRoot, stateRoot, committed);
        }
        catch (OperationCanceledException)
        {
            if (migrationId is not null && targetRoot is not null)
            {
                await TryRollbackAfterFailureAsync(
                    targetRoot,
                    migrationId,
                    "legacy-migration-cancelled").ConfigureAwait(false);
            }

            throw;
        }
        catch (LegacyMigrationException error)
        {
            if (migrationId is not null && targetRoot is not null)
            {
                await TryRollbackAfterFailureAsync(targetRoot, migrationId, error.Code).ConfigureAwait(false);
            }

            throw;
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException
            or JsonException or CryptographicException or InvalidOperationException
            or ArgumentException)
        {
            if (migrationId is not null && targetRoot is not null)
            {
                await TryRollbackAfterFailureAsync(
                    targetRoot,
                    migrationId,
                    "legacy-migration-transaction-failed").ConfigureAwait(false);
            }

            throw Fail("legacy-migration-transaction-failed");
        }
        finally
        {
            migrationGate.Release();
        }
    }

    public async Task RollbackAsync(
        string targetProductRoot,
        string migrationId,
        CancellationToken cancellationToken = default)
    {
        await migrationGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            string targetRoot = ValidateLocalAbsolutePath(targetProductRoot, "legacy-target-root-invalid");
            string stateRoot = Path.Combine(targetRoot, "state");
            var targetState = new AtomicFileStore(stateRoot);
            LegacyWindowsMigrationJournal journal = await ReadJournalAsync(targetState, cancellationToken)
                .ConfigureAwait(false)
                ?? throw Fail("legacy-migration-journal-missing");
            if (journal.MigrationId != migrationId)
            {
                throw Fail("legacy-migration-id-mismatch");
            }

            await RollbackInternalAsync(targetRoot, targetState, journal, cancellationToken)
                .ConfigureAwait(false);
        }
        finally
        {
            migrationGate.Release();
        }
    }

    public static string CreateLegacyServiceName(string nodeId)
    {
        if (string.IsNullOrWhiteSpace(nodeId))
        {
            throw Fail("legacy-node-id-invalid");
        }

        string slug = ServiceSlugCharacters().Replace(nodeId.ToLowerInvariant(), "-").Trim('-');
        if (slug.Length == 0)
        {
            slug = "node";
        }

        if (slug.Length > 40)
        {
            slug = slug[..40].TrimEnd('-');
        }

        string digest = HchDigest.Sha256Hex(Encoding.UTF8.GetBytes(nodeId));
        return $"HchEditorialWorker-{slug}-{digest[..12]}";
    }

    private async Task TryRollbackAfterFailureAsync(string targetRoot, string migrationId, string errorCode)
    {
        try
        {
            var state = new AtomicFileStore(Path.Combine(targetRoot, "state"));
            LegacyWindowsMigrationJournal? journal = await ReadJournalAsync(state, CancellationToken.None)
                .ConfigureAwait(false);
            if (journal is null || journal.MigrationId != migrationId)
            {
                return;
            }

            journal = journal with { LastErrorCode = errorCode, UpdatedAt = Timestamp() };
            await WriteJournalAsync(state, journal, CancellationToken.None).ConfigureAwait(false);
            await RollbackInternalAsync(targetRoot, state, journal, CancellationToken.None)
                .ConfigureAwait(false);
        }
        catch (Exception rollbackError) when (rollbackError is IOException or UnauthorizedAccessException
            or JsonException or LegacyMigrationException)
        {
            throw Fail("legacy-migration-rollback-incomplete");
        }
    }

    private async Task RollbackInternalAsync(
        string targetRoot,
        AtomicFileStore targetState,
        LegacyWindowsMigrationJournal journal,
        CancellationToken cancellationToken)
    {
        if (journal.Phase == MigrationPhase.RolledBack)
        {
            return;
        }

        var artifacts = journal.TargetArtifacts.ToDictionary(
            static item => item.RelativePath,
            StringComparer.OrdinalIgnoreCase);
        foreach (string relativePath in journal.ImportedRelativePaths.Reverse())
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (!artifacts.TryGetValue(relativePath, out LegacyTargetArtifact? artifact)
                || artifact.ExistedBeforeMigration)
            {
                throw Fail("legacy-migration-rollback-plan-invalid");
            }

            string target = ResolveTarget(targetRoot, artifact.RelativePath);
            if (!File.Exists(target))
            {
                continue;
            }

            string currentHash = await HashFileAsync(target, cancellationToken).ConfigureAwait(false);
            if (currentHash != artifact.Sha256)
            {
                LegacyWindowsMigrationJournal refused = journal with
                {
                    LastErrorCode = "legacy-migration-rollback-target-modified",
                    UpdatedAt = Timestamp(),
                };
                await WriteJournalAsync(targetState, refused, cancellationToken).ConfigureAwait(false);
                throw Fail("legacy-migration-rollback-target-modified");
            }

            File.Delete(target);
            DeleteEmptyTargetParents(targetRoot, Path.GetDirectoryName(target));
        }

        TryDeleteStaging(targetState, journal.MigrationId);
        LegacyWindowsMigrationJournal rolledBack = journal with
        {
            Phase = MigrationPhase.RolledBack,
            UpdatedAt = Timestamp(),
        };
        await WriteJournalAsync(targetState, rolledBack, cancellationToken).ConfigureAwait(false);
    }

    private async Task<IReadOnlyList<LegacyTargetArtifact>> StageTargetArtifactsAsync(
        string targetRoot,
        AtomicFileStore targetState,
        string migrationId,
        MigratedWorkerConfiguration configuration,
        LegacyRootTrustProjection trust,
        Ed25519Identity identity,
        CancellationToken cancellationToken)
    {
        string stagingRelative = $"migration-staging/{migrationId}";
        string stagingRoot = targetState.Resolve(stagingRelative);
        if (Directory.Exists(stagingRoot))
        {
            DeleteTreeGuarded(stagingRoot, targetState.Root);
        }

        Directory.CreateDirectory(stagingRoot);
        var staging = new AtomicFileStore(stagingRoot);
        byte[] pkcs8 = identity.ExportPkcs8PrivateKey();
        byte[]? protectedPkcs8 = null;
        byte[] configurationBytes = JsonSerializer.SerializeToUtf8Bytes(
            configuration,
            AtomicFileStore.JsonOptions);
        byte[] trustBytes = new UTF8Encoding(false, true).GetBytes(trust.PublicKeyPem);
        try
        {
            protectedPkcs8 = secretProtector.Protect(
                pkcs8,
                $"operational-identity:{configuration.NodeId}");
            if (protectedPkcs8.Length == 0)
            {
                throw Fail("legacy-identity-protection-failed");
            }

            var staged = new[]
            {
                (LegacyWindowsWorkerPaths.TargetIdentityRelativePath, protectedPkcs8),
                (LegacyWindowsWorkerPaths.TargetRootPublicKeyRelativePath, trustBytes),
                // config.json is committed last and therefore remains the
                // installation visibility/activation boundary.
                (LegacyWindowsWorkerPaths.TargetConfigurationRelativePath, configurationBytes),
            };
            var artifacts = new List<LegacyTargetArtifact>(staged.Length);
            foreach ((string relativePath, byte[] bytes) in staged)
            {
                string target = ResolveTarget(targetRoot, relativePath);
                if (File.Exists(target) || Directory.Exists(target))
                {
                    throw Fail("legacy-migration-target-artifact-exists");
                }

                string stageName = StageName(relativePath);
                await staging.WriteBytesAsync(stageName, bytes, cancellationToken).ConfigureAwait(false);
                artifacts.Add(new LegacyTargetArtifact(
                    relativePath,
                    HchDigest.Sha256Hex(bytes),
                    ExistedBeforeMigration: false));
            }

            return artifacts;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(pkcs8);
            CryptographicOperations.ZeroMemory(configurationBytes);
            CryptographicOperations.ZeroMemory(trustBytes);
            if (protectedPkcs8 is not null)
            {
                CryptographicOperations.ZeroMemory(protectedPkcs8);
            }
        }
    }

    private static void CommitStagedArtifact(
        string targetRoot,
        AtomicFileStore targetState,
        string migrationId,
        LegacyTargetArtifact artifact)
    {
        string stagingRoot = targetState.Resolve($"migration-staging/{migrationId}");
        string staged = Path.Combine(stagingRoot, StageName(artifact.RelativePath));
        string target = ResolveTarget(targetRoot, artifact.RelativePath);
        string directory = Path.GetDirectoryName(target)
            ?? throw Fail("legacy-migration-target-path-invalid");
        Directory.CreateDirectory(directory);
        RejectReparsePoints(directory, targetRoot);
        if (!File.Exists(staged) || File.Exists(target) || Directory.Exists(target))
        {
            throw Fail("legacy-migration-target-commit-refused");
        }

        File.Move(staged, target, overwrite: false);
    }

    private async Task EnsureImmutableBackupAsync(
        string sourceRoot,
        string backupRoot,
        LegacyWindowsMigrationJournal journal,
        IReadOnlyList<LegacySnapshotFile> snapshot,
        LegacyRuntimePreflightEvidence preflight,
        CancellationToken cancellationToken)
    {
        string receiptPath = Path.Combine(backupRoot, BackupReceiptFileName);
        if (File.Exists(receiptPath))
        {
            await ValidateBackupAsync(
                backupRoot,
                journal,
                snapshot,
                preflight,
                cancellationToken).ConfigureAwait(false);
            return;
        }

        if (Directory.Exists(backupRoot))
        {
            throw Fail("legacy-backup-incomplete");
        }

        Directory.CreateDirectory(backupRoot);
        try
        {
            string sourceBackupRoot = Path.Combine(backupRoot, "source");
            Directory.CreateDirectory(sourceBackupRoot);
            foreach (LegacySnapshotFile file in snapshot)
            {
                cancellationToken.ThrowIfCancellationRequested();
                string source = LegacyWindowsMigrationParsing.Resolve(sourceRoot, file.RelativePath);
                string destination = ResolveBackup(sourceBackupRoot, file.RelativePath);
                Directory.CreateDirectory(Path.GetDirectoryName(destination)!);
                await CopyCreateNewAsync(source, destination, cancellationToken).ConfigureAwait(false);
                string backupHash = await HashFileAsync(destination, cancellationToken).ConfigureAwait(false);
                if (backupHash != file.Sha256)
                {
                    throw Fail("legacy-backup-hash-mismatch");
                }

                File.SetAttributes(destination, File.GetAttributes(destination) | FileAttributes.ReadOnly);
            }

            var payload = new LegacyBackupReceiptPayload(
                SchemaVersion: 1,
                journal.MigrationId,
                journal.SourceVersion,
                journal.SourceProductRoot,
                journal.SourceSnapshotSha256,
                journal.NodeId,
                journal.KeyId,
                snapshot,
                NormalizeAcls(preflight.AclReceipts),
                preflight.ServiceDefinition,
                CapturedAt: Timestamp());
            string receiptDigest = HchDigest.Sha256Hex(ProtocolJson.SerializeCanonicalToUtf8(payload));
            var receipt = new LegacyBackupReceipt(payload, receiptDigest);
            var backupStore = new AtomicFileStore(backupRoot);
            await backupStore.WriteJsonAsync(BackupReceiptFileName, receipt, cancellationToken)
                .ConfigureAwait(false);
            File.SetAttributes(receiptPath, File.GetAttributes(receiptPath) | FileAttributes.ReadOnly);
        }
        catch
        {
            DeleteTreeGuarded(backupRoot, Path.GetDirectoryName(backupRoot)!);
            throw;
        }
    }

    private static async Task ValidateBackupAsync(
        string backupRoot,
        LegacyWindowsMigrationJournal journal,
        IReadOnlyList<LegacySnapshotFile> snapshot,
        LegacyRuntimePreflightEvidence preflight,
        CancellationToken cancellationToken)
    {
        var backupStore = new AtomicFileStore(backupRoot);
        LegacyBackupReceipt receipt;
        try
        {
            receipt = await backupStore.ReadJsonAsync<LegacyBackupReceipt>(
                BackupReceiptFileName,
                cancellationToken).ConfigureAwait(false)
                ?? throw Fail("legacy-backup-receipt-missing");
        }
        catch (JsonException)
        {
            throw Fail("legacy-backup-receipt-invalid");
        }

        string digest = HchDigest.Sha256Hex(ProtocolJson.SerializeCanonicalToUtf8(receipt.Payload));
        if (receipt.Payload.SchemaVersion != 1
            || receipt.Payload.MigrationId != journal.MigrationId
            || receipt.Payload.SourceSnapshotSha256 != journal.SourceSnapshotSha256
            || receipt.ReceiptSha256 != digest
            || !receipt.Payload.Files.SequenceEqual(snapshot)
            || !receipt.Payload.AclReceipts.SequenceEqual(NormalizeAcls(preflight.AclReceipts))
            || receipt.Payload.ServiceDefinition != preflight.ServiceDefinition)
        {
            throw Fail("legacy-backup-receipt-invalid");
        }

        string sourceBackupRoot = Path.Combine(backupRoot, "source");
        foreach (LegacySnapshotFile file in snapshot)
        {
            string backup = ResolveBackup(sourceBackupRoot, file.RelativePath);
            if (!File.Exists(backup)
                || await HashFileAsync(backup, cancellationToken).ConfigureAwait(false) != file.Sha256)
            {
                throw Fail("legacy-backup-hash-mismatch");
            }
        }
    }

    private static async Task<IReadOnlyList<LegacySnapshotFile>> BuildSnapshotAsync(
        string sourceRoot,
        CancellationToken cancellationToken)
    {
        var files = new List<string>();
        foreach (string topLevel in new[] { "config", "state", "trust" })
        {
            string root = Path.Combine(sourceRoot, topLevel);
            if (!Directory.Exists(root))
            {
                continue;
            }

            EnumerateFilesSafe(sourceRoot, root, files);
        }

        if (files.Count == 0 || files.Count > MaximumSnapshotFiles)
        {
            throw Fail("legacy-snapshot-file-count-invalid");
        }

        var snapshot = new List<LegacySnapshotFile>(files.Count);
        long total = 0;
        foreach (string path in files.Order(StringComparer.Ordinal))
        {
            cancellationToken.ThrowIfCancellationRequested();
            var info = new FileInfo(path);
            if (info.Length < 0 || info.Length > MaximumSnapshotFileBytes)
            {
                throw Fail("legacy-snapshot-file-size-invalid");
            }

            total = checked(total + info.Length);
            if (total > MaximumSnapshotBytes)
            {
                throw Fail("legacy-snapshot-size-invalid");
            }

            snapshot.Add(new LegacySnapshotFile(
                NormalizeRelative(Path.GetRelativePath(sourceRoot, path)),
                info.Length,
                await HashFileAsync(path, cancellationToken).ConfigureAwait(false)));
        }

        RequireSnapshotFile(snapshot, LegacyWindowsWorkerPaths.ConfigurationRelativePath);
        RequireSnapshotFile(snapshot, LegacyWindowsWorkerPaths.IdentityMetadataRelativePath);
        RequireSnapshotFile(snapshot, LegacyWindowsWorkerPaths.PrivateKeyRelativePath);
        RequireSnapshotFile(snapshot, LegacyWindowsWorkerPaths.PublicKeyRelativePath);
        RequireSnapshotFile(snapshot, LegacyWindowsWorkerPaths.RootPublicKeyRelativePath);
        RequireSnapshotFile(snapshot, LegacyWindowsWorkerPaths.TrustStateRelativePath);
        return snapshot;
    }

    private static void EnumerateFilesSafe(string sourceRoot, string current, ICollection<string> files)
    {
        RejectReparsePoints(current, sourceRoot);
        foreach (string entry in Directory.EnumerateFileSystemEntries(current))
        {
            FileAttributes attributes = File.GetAttributes(entry);
            if ((attributes & FileAttributes.ReparsePoint) != 0)
            {
                throw Fail("legacy-snapshot-reparse-point-refused");
            }

            if ((attributes & FileAttributes.Directory) != 0)
            {
                EnumerateFilesSafe(sourceRoot, entry, files);
            }
            else
            {
                files.Add(entry);
                if (files.Count > MaximumSnapshotFiles)
                {
                    throw Fail("legacy-snapshot-file-count-invalid");
                }
            }
        }
    }

    private static void ValidatePreflight(
        LegacyRuntimePreflightEvidence evidence,
        LegacyWorkerSourceDescriptor descriptor)
    {
        ArgumentNullException.ThrowIfNull(evidence);
        if (!evidence.ServiceInstalled
            || evidence.ServiceName != descriptor.ServiceName
            || !evidence.ServiceState.Equals("Stopped", StringComparison.OrdinalIgnoreCase)
            || evidence.ServiceProcessId is not (null or 0)
            || !evidence.ExclusiveWriterLocksAvailable
            || evidence.ServiceDefinition.ServiceName != descriptor.ServiceName
            || !ReferencesLegacyServiceExecutable(evidence.ServiceDefinition.ImagePath)
            || !evidence.ServiceDefinition.AccountName.Equals(
                $@"NT SERVICE\{descriptor.ServiceName}",
                StringComparison.OrdinalIgnoreCase)
            || evidence.ServiceDefinition.StartMode != 2
            || evidence.ServiceDefinition.ServiceType != 16
            || !evidence.ServiceDefinition.DelayedAutomaticStart
            || !HchDigest.IsLowerSha256(evidence.ServiceDefinition.FailureActionsSha256)
            || string.IsNullOrWhiteSpace(evidence.ServiceDefinition.SecurityDescriptorSddl)
            || evidence.CapturedAt == default
            || evidence.CapturedAt < DateTimeOffset.UtcNow.AddMinutes(-5)
            || evidence.CapturedAt > DateTimeOffset.UtcNow.AddMinutes(5))
        {
            throw Fail("legacy-runtime-preflight-unproven");
        }
    }

    private static bool ReferencesLegacyServiceExecutable(string imagePath)
    {
        if (string.IsNullOrWhiteSpace(imagePath))
        {
            return false;
        }

        ReadOnlySpan<char> command = imagePath.AsSpan().Trim();
        ReadOnlySpan<char> executable;
        if (command[0] == '"')
        {
            int closingQuote = command[1..].IndexOf('"');
            if (closingQuote < 0)
            {
                return false;
            }

            closingQuote++;
            executable = command[1..closingQuote];
            ReadOnlySpan<char> arguments = command[(closingQuote + 1)..];
            if (!arguments.IsEmpty && !char.IsWhiteSpace(arguments[0]))
            {
                return false;
            }
        }
        else
        {
            int firstWhitespace = command.IndexOfAny(" \t\r\n");
            executable = firstWhitespace < 0 ? command : command[..firstWhitespace];
        }

        string candidate = executable.ToString();
        try
        {
            return Path.IsPathFullyQualified(candidate)
                && !candidate.StartsWith("\\\\", StringComparison.Ordinal)
                && Path.GetFileName(candidate).Equals(
                    "HchEditorialWorkerService.exe",
                    StringComparison.OrdinalIgnoreCase);
        }
        catch (Exception error) when (error is ArgumentException or NotSupportedException
            or PathTooLongException)
        {
            return false;
        }
    }

    private static void ValidateAclCoverage(
        LegacyRuntimePreflightEvidence evidence,
        IReadOnlyList<LegacySnapshotFile> snapshot)
    {
        IReadOnlyList<LegacyAclReceipt> normalized = NormalizeAcls(evidence.AclReceipts);
        var byPath = normalized.ToDictionary(
            static receipt => receipt.RelativePath,
            StringComparer.OrdinalIgnoreCase);
        foreach (LegacySnapshotFile file in snapshot)
        {
            if (!byPath.TryGetValue(file.RelativePath, out LegacyAclReceipt? receipt)
                || string.IsNullOrWhiteSpace(receipt.SecurityDescriptorSddl))
            {
                throw Fail("legacy-acl-receipt-incomplete");
            }
        }
    }

    private static IReadOnlyList<LegacyAclReceipt> NormalizeAcls(
        IReadOnlyList<LegacyAclReceipt> receipts)
    {
        if (receipts is null || receipts.Count == 0)
        {
            throw Fail("legacy-acl-receipt-incomplete");
        }

        var normalized = new List<LegacyAclReceipt>(receipts.Count);
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (LegacyAclReceipt receipt in receipts)
        {
            string relative = NormalizeRelative(receipt.RelativePath);
            if (relative == "."
                || relative.StartsWith("../", StringComparison.Ordinal)
                || Path.IsPathFullyQualified(relative)
                || !seen.Add(relative)
                || string.IsNullOrWhiteSpace(receipt.SecurityDescriptorSddl))
            {
                throw Fail("legacy-acl-receipt-invalid");
            }

            normalized.Add(new LegacyAclReceipt(relative, receipt.SecurityDescriptorSddl));
        }

        return normalized.OrderBy(static value => value.RelativePath, StringComparer.Ordinal).ToArray();
    }

    private static string PreflightDigest(LegacyRuntimePreflightEvidence evidence)
    {
        var comparable = new
        {
            evidence.ServiceInstalled,
            evidence.ServiceName,
            State = evidence.ServiceState.ToUpperInvariant(),
            ProcessId = evidence.ServiceProcessId ?? 0,
            evidence.ExclusiveWriterLocksAvailable,
            evidence.ServiceDefinition,
            Acls = NormalizeAcls(evidence.AclReceipts),
        };
        return HchDigest.Sha256Hex(ProtocolJson.SerializeCanonicalToUtf8(comparable));
    }

    private static void EnsureNoStateBlockers(MigrationInspection inspection)
    {
        if (!inspection.CanMigrate || inspection.Blockers.Count != 0)
        {
            throw Fail("legacy-state-reconciliation-required");
        }
    }

    private LegacyWindowsMigrationJournal CreateJournal(
        LegacyWindowsMigrationRequest request,
        string sourceRoot,
        string snapshotDigest,
        string backupRelativePath,
        string nodeId,
        string keyId,
        LegacyControlProjection control,
        MigrationPhase phase,
        IReadOnlyList<LegacyTargetArtifact> targetArtifacts,
        IReadOnlyList<string> importedRelativePaths,
        string? lastErrorCode) => new(
            SchemaVersion: 1,
            MigrationId: CreateMigrationId(
                request.SourceVersion,
                request.TargetVersion,
                nodeId,
                keyId,
                snapshotDigest),
            request.SourceVersion,
            request.TargetVersion,
            phase,
            sourceRoot,
            snapshotDigest,
            backupRelativePath,
            nodeId,
            keyId,
            control.LastNonZeroMaxConcurrentJobs,
            control.ClaimBatchSize,
            OperationalState: "Paused/Drain",
            ClaimsEnabled: false,
            ReadinessDisposition,
            BackupOnlyState,
            targetArtifacts,
            importedRelativePaths,
            UpdatedAt: Timestamp(),
            lastErrorCode);

    private static async Task ValidateCommittedAsync(
        string targetRoot,
        LegacyWindowsMigrationJournal journal,
        CancellationToken cancellationToken)
    {
        if (journal.SchemaVersion != 1
            || journal.Phase != MigrationPhase.Committed
            || journal.ClaimsEnabled
            || journal.OperationalState != "Paused/Drain"
            || journal.ReadinessDisposition != ReadinessDisposition
            || journal.ImportedRelativePaths.Count != journal.TargetArtifacts.Count)
        {
            throw Fail("legacy-migration-committed-state-invalid");
        }

        foreach (LegacyTargetArtifact artifact in journal.TargetArtifacts)
        {
            string target = ResolveTarget(targetRoot, artifact.RelativePath);
            if (!File.Exists(target)
                || await HashFileAsync(target, cancellationToken).ConfigureAwait(false) != artifact.Sha256)
            {
                throw Fail("legacy-migration-committed-artifact-invalid");
            }
        }
    }

    private static LegacyWindowsMigrationResult Result(
        string targetRoot,
        string stateRoot,
        LegacyWindowsMigrationJournal journal) => new(
            journal.MigrationId,
            journal.NodeId,
            journal.KeyId,
            Path.Combine(stateRoot, journal.BackupRelativePath.Replace('/', Path.DirectorySeparatorChar)),
            ResolveTarget(targetRoot, LegacyWindowsWorkerPaths.TargetConfigurationRelativePath),
            ResolveTarget(targetRoot, LegacyWindowsWorkerPaths.TargetIdentityRelativePath),
            ResolveTarget(targetRoot, LegacyWindowsWorkerPaths.TargetRootPublicKeyRelativePath),
            journal.Phase,
            journal.ClaimsEnabled,
            journal.ReadinessDisposition);

    private static void EnsureTargetUninitialized(string targetRoot)
    {
        foreach (string relativePath in new[]
        {
            LegacyWindowsWorkerPaths.TargetConfigurationRelativePath,
            LegacyWindowsWorkerPaths.TargetIdentityRelativePath,
            LegacyWindowsWorkerPaths.TargetRootPublicKeyRelativePath,
            "state/ready.json",
            "state/applied-manifest.json",
            "state/trust-state.json",
        })
        {
            string path = ResolveTarget(targetRoot, relativePath);
            if (File.Exists(path) || Directory.Exists(path))
            {
                throw Fail("legacy-migration-target-already-initialized");
            }
        }
    }

    private static (string SourceRoot, string TargetRoot) ValidateRequest(
        LegacyWindowsMigrationRequest request)
    {
        string sourceRoot = ValidateLocalAbsolutePath(
            request.LegacyProductRoot,
            "legacy-source-root-invalid");
        string targetRoot = ValidateLocalAbsolutePath(
            request.TargetProductRoot,
            "legacy-target-root-invalid");
        if (!Directory.Exists(sourceRoot)
            || IsSameOrNested(sourceRoot, targetRoot)
            || IsSameOrNested(targetRoot, sourceRoot)
            || request.SourceVersion != "3.1.0"
            || !TargetVersionPattern().IsMatch(request.TargetVersion)
            || !OwnerSidPattern().IsMatch(request.OwnerSid))
        {
            throw Fail("legacy-migration-request-invalid");
        }

        RejectReparsePoints(sourceRoot, sourceRoot);
        if (Directory.Exists(targetRoot))
        {
            RejectReparsePoints(targetRoot, targetRoot);
        }

        return (sourceRoot, targetRoot);
    }

    private static string ValidateLocalAbsolutePath(string path, string code)
    {
        if (string.IsNullOrWhiteSpace(path)
            || !Path.IsPathFullyQualified(path)
            || path.StartsWith("\\\\", StringComparison.Ordinal))
        {
            throw Fail(code);
        }

        try
        {
            return Path.GetFullPath(path).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        }
        catch (Exception error) when (error is ArgumentException or NotSupportedException or PathTooLongException)
        {
            throw Fail(code);
        }
    }

    private static bool IsSameOrNested(string parent, string candidate)
    {
        string parentPrefix = parent.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar)
            + Path.DirectorySeparatorChar;
        return candidate.Equals(parent, StringComparison.OrdinalIgnoreCase)
            || candidate.StartsWith(parentPrefix, StringComparison.OrdinalIgnoreCase);
    }

    private static string SnapshotDigest(IReadOnlyList<LegacySnapshotFile> snapshot) =>
        HchDigest.Sha256Hex(ProtocolJson.SerializeCanonicalToUtf8(snapshot));

    private static string CreateMigrationId(
        string sourceVersion,
        string targetVersion,
        string nodeId,
        string keyId,
        string snapshotDigest)
    {
        var input = new { sourceVersion, targetVersion, nodeId, keyId, snapshotDigest };
        return "legacy-windows-" + HchDigest.Sha256Hex(ProtocolJson.SerializeCanonicalToUtf8(input));
    }

    private static async Task<LegacyWindowsMigrationJournal?> ReadJournalAsync(
        AtomicFileStore state,
        CancellationToken cancellationToken)
    {
        try
        {
            return await state.ReadJsonAsync<LegacyWindowsMigrationJournal>(
                LegacyWindowsWorkerPaths.TargetMigrationJournalRelativePath,
                cancellationToken).ConfigureAwait(false);
        }
        catch (JsonException)
        {
            throw Fail("legacy-migration-journal-invalid");
        }
    }

    private static Task WriteJournalAsync(
        AtomicFileStore state,
        LegacyWindowsMigrationJournal journal,
        CancellationToken cancellationToken) =>
        state.WriteJsonAsync(
            LegacyWindowsWorkerPaths.TargetMigrationJournalRelativePath,
            journal,
            cancellationToken);

    private static async Task<string> HashFileAsync(
        string path,
        CancellationToken cancellationToken)
    {
        if (!File.Exists(path) || (File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
        {
            throw Fail("legacy-file-hash-refused");
        }

        try
        {
            await using var stream = new FileStream(
                path,
                FileMode.Open,
                FileAccess.Read,
                FileShare.Read,
                128 * 1024,
                FileOptions.Asynchronous | FileOptions.SequentialScan);
            byte[] digest = await SHA256.HashDataAsync(stream, cancellationToken).ConfigureAwait(false);
            try
            {
                return Convert.ToHexStringLower(digest);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(digest);
            }
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException)
        {
            throw Fail("legacy-file-hash-failed");
        }
    }

    private static async Task CopyCreateNewAsync(
        string source,
        string destination,
        CancellationToken cancellationToken)
    {
        try
        {
            await using var input = new FileStream(
                source,
                FileMode.Open,
                FileAccess.Read,
                FileShare.Read,
                128 * 1024,
                FileOptions.Asynchronous | FileOptions.SequentialScan);
            await using var output = new FileStream(
                destination,
                FileMode.CreateNew,
                FileAccess.Write,
                FileShare.None,
                128 * 1024,
                FileOptions.Asynchronous | FileOptions.WriteThrough);
            await input.CopyToAsync(output, cancellationToken).ConfigureAwait(false);
            await output.FlushAsync(cancellationToken).ConfigureAwait(false);
            output.Flush(flushToDisk: true);
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException)
        {
            throw Fail("legacy-backup-copy-failed");
        }
    }

    private static void RequireSnapshotFile(
        IReadOnlyList<LegacySnapshotFile> snapshot,
        string relativePath)
    {
        if (!snapshot.Any(file => file.RelativePath.Equals(relativePath, StringComparison.OrdinalIgnoreCase)))
        {
            throw Fail("legacy-snapshot-required-file-missing");
        }
    }

    private static string ResolveTarget(string targetRoot, string relativePath)
    {
        string root = Path.GetFullPath(targetRoot);
        string target = Path.GetFullPath(Path.Combine(
            root,
            relativePath.Replace('/', Path.DirectorySeparatorChar)));
        string prefix = root.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar)
            + Path.DirectorySeparatorChar;
        if (!target.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
        {
            throw Fail("legacy-migration-target-path-invalid");
        }

        return target;
    }

    private static string ResolveBackup(string backupRoot, string relativePath)
    {
        string target = ResolveTarget(backupRoot, relativePath);
        RejectReparsePoints(Path.GetDirectoryName(target)!, backupRoot);
        return target;
    }

    private static void RejectReparsePoints(string path, string boundary)
    {
        string root = Path.GetFullPath(boundary);
        for (string? current = Path.GetFullPath(path);
             !string.IsNullOrEmpty(current) && IsSameOrNested(root, current);
             current = Path.GetDirectoryName(current))
        {
            if ((File.Exists(current) || Directory.Exists(current))
                && (File.GetAttributes(current) & FileAttributes.ReparsePoint) != 0)
            {
                throw Fail("legacy-migration-reparse-point-refused");
            }

            if (current.Equals(root, StringComparison.OrdinalIgnoreCase))
            {
                break;
            }
        }
    }

    private static void TryDeleteStaging(AtomicFileStore state, string migrationId)
    {
        string staging = state.Resolve($"migration-staging/{migrationId}");
        if (Directory.Exists(staging))
        {
            DeleteTreeGuarded(staging, state.Root);
        }

        string parent = state.Resolve("migration-staging");
        if (Directory.Exists(parent) && !Directory.EnumerateFileSystemEntries(parent).Any())
        {
            Directory.Delete(parent);
        }
    }

    private static void DeleteTreeGuarded(string path, string boundary)
    {
        string root = Path.GetFullPath(boundary);
        string target = Path.GetFullPath(path);
        if (!IsSameOrNested(root, target) || target.Equals(root, StringComparison.OrdinalIgnoreCase))
        {
            throw Fail("legacy-migration-delete-boundary-invalid");
        }

        RejectReparsePoints(target, root);
        if (!Directory.Exists(target))
        {
            return;
        }

        var pending = new Stack<string>();
        var directories = new List<string>();
        var files = new List<string>();
        pending.Push(target);
        while (pending.Count > 0)
        {
            string directory = pending.Pop();
            RejectDeletionCandidate(directory, target);
            foreach (string entry in Directory.EnumerateFileSystemEntries(directory))
            {
                RejectDeletionCandidate(entry, target);
                if (Directory.Exists(entry))
                {
                    directories.Add(entry);
                    pending.Push(entry);
                }
                else
                {
                    files.Add(entry);
                }
            }
        }

        foreach (string file in files)
        {
            RejectDeletionCandidate(file, target);
            File.SetAttributes(file, FileAttributes.Normal);
            File.Delete(file);
        }

        foreach (string directory in directories.OrderByDescending(static value => value.Length))
        {
            RejectDeletionCandidate(directory, target);
            File.SetAttributes(directory, FileAttributes.Normal);
            Directory.Delete(directory, recursive: false);
        }

        RejectDeletionCandidate(target, target);
        File.SetAttributes(target, FileAttributes.Normal);
        Directory.Delete(target, recursive: false);
    }

    private static void RejectDeletionCandidate(string path, string targetRoot)
    {
        string target = Path.GetFullPath(targetRoot);
        string candidate = Path.GetFullPath(path);
        if (!IsSameOrNested(target, candidate)
            || (!File.Exists(candidate) && !Directory.Exists(candidate))
            || (File.GetAttributes(candidate) & FileAttributes.ReparsePoint) != 0)
        {
            throw Fail("legacy-migration-delete-candidate-invalid");
        }
    }

    private static void DeleteEmptyTargetParents(string targetRoot, string? directory)
    {
        string root = Path.GetFullPath(targetRoot);
        while (!string.IsNullOrEmpty(directory)
            && IsSameOrNested(root, directory)
            && !directory.Equals(root, StringComparison.OrdinalIgnoreCase)
            && Directory.Exists(directory)
            && !Directory.EnumerateFileSystemEntries(directory).Any())
        {
            Directory.Delete(directory);
            directory = Path.GetDirectoryName(directory);
        }
    }

    private static string NormalizeRelative(string value) =>
        value.Replace(Path.DirectorySeparatorChar, '/').Replace(Path.AltDirectorySeparatorChar, '/');

    private static string StageName(string relativePath) =>
        HchDigest.Sha256Hex(Encoding.UTF8.GetBytes(relativePath)) + ".stage";

    private string Timestamp() => clock.GetUtcNow().UtcDateTime.ToString("O");

    private static LegacyMigrationException Fail(string code) => new(code);

    [GeneratedRegex("[^a-z0-9]+", RegexOptions.CultureInvariant)]
    private static partial Regex ServiceSlugCharacters();

    [GeneratedRegex("^4\\.[0-9]+\\.[0-9]+(?:[-+][A-Za-z0-9.-]+)?$", RegexOptions.CultureInvariant)]
    private static partial Regex TargetVersionPattern();

    [GeneratedRegex("^S-1-(?:[0-9]+-){1,14}[0-9]+$", RegexOptions.CultureInvariant)]
    private static partial Regex OwnerSidPattern();
}
