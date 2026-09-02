using System.Text.RegularExpressions;

namespace Hch.Worker.Persistence;

public static class LegacyWindowsWorkerPaths
{
    public const string DefaultProductRoot = @"C:\ProgramData\HCH\EditorialWorker";
    public const string ConfigurationRelativePath = "config/WorkerConfig.psd1";
    public const string StateRelativePath = "state";
    public const string PrivateKeyRelativePath = "state/identity/worker-private.pk8.pem";
    public const string PublicKeyRelativePath = "state/identity/worker-public.spki.pem";
    public const string IdentityMetadataRelativePath = "state/identity/identity.json";
    public const string RootPublicKeyRelativePath = "trust/orchestrator-root.pem";
    public const string TrustStateRelativePath = "state/trust-state.json";

    public const string TargetIdentityRelativePath = "state/identity/worker-ed25519.pkcs8.dpapi";
    public const string TargetRootPublicKeyRelativePath = "trust/orchestrator-root.pem";
    public const string TargetConfigurationRelativePath = "config.json";
    public const string TargetMigrationJournalRelativePath = "migration/legacy-windows-v3.json";
}

public sealed record LegacyWorkerSourceDescriptor(
    string ProductRoot,
    string StateRoot,
    string NodeId,
    string ServiceName);

public sealed record LegacyServiceDefinitionReceipt(
    string ServiceName,
    string ImagePath,
    string AccountName,
    int StartMode,
    int ServiceType,
    bool DelayedAutomaticStart,
    string FailureActionsSha256,
    string SecurityDescriptorSddl);

public sealed record LegacyAclReceipt(string RelativePath, string SecurityDescriptorSddl);

/// <summary>
/// Evidence collected twice around the immutable snapshot. A migrator accepts
/// the source only when both captures prove the same stopped service, the same
/// definition/ACLs, and availability of every legacy writer lock.
/// </summary>
public sealed record LegacyRuntimePreflightEvidence(
    bool ServiceInstalled,
    string ServiceName,
    string ServiceState,
    int? ServiceProcessId,
    bool ExclusiveWriterLocksAvailable,
    LegacyServiceDefinitionReceipt ServiceDefinition,
    IReadOnlyList<LegacyAclReceipt> AclReceipts,
    DateTimeOffset CapturedAt);

public interface ILegacyWorkerRuntimePreflight
{
    Task<LegacyRuntimePreflightEvidence> CaptureAsync(
        LegacyWorkerSourceDescriptor source,
        CancellationToken cancellationToken = default);
}

public interface ILegacyMigrationFaultInjector
{
    Task AfterTargetArtifactAsync(
        string relativePath,
        int committedArtifactCount,
        CancellationToken cancellationToken);
}

public sealed record LegacyWindowsMigrationRequest(
    string LegacyProductRoot,
    string TargetProductRoot,
    string OwnerSid,
    string SourceVersion = "3.1.0",
    string TargetVersion = "4.0.0");

public sealed record LegacyWindowsMigrationResult(
    string MigrationId,
    string NodeId,
    string KeyId,
    string BackupPath,
    string ConfigurationPath,
    string IdentityPath,
    string RootPublicKeyPath,
    MigrationPhase Phase,
    bool ClaimsEnabled,
    string ReadinessDisposition);

public sealed record LegacySnapshotFile(
    string RelativePath,
    long Size,
    string Sha256);

public sealed record LegacyTargetArtifact(
    string RelativePath,
    string Sha256,
    bool ExistedBeforeMigration);

public sealed record LegacyBackupReceiptPayload(
    int SchemaVersion,
    string MigrationId,
    string SourceVersion,
    string SourceProductRoot,
    string SourceSnapshotSha256,
    string NodeId,
    string KeyId,
    IReadOnlyList<LegacySnapshotFile> Files,
    IReadOnlyList<LegacyAclReceipt> AclReceipts,
    LegacyServiceDefinitionReceipt ServiceDefinition,
    string CapturedAt);

public sealed record LegacyBackupReceipt(
    LegacyBackupReceiptPayload Payload,
    string ReceiptSha256);

public sealed record LegacyWindowsMigrationJournal(
    int SchemaVersion,
    string MigrationId,
    string SourceVersion,
    string TargetVersion,
    MigrationPhase Phase,
    string SourceProductRoot,
    string SourceSnapshotSha256,
    string BackupRelativePath,
    string NodeId,
    string KeyId,
    int LastNonZeroMaxConcurrentJobs,
    int ClaimBatchSize,
    string OperationalState,
    bool ClaimsEnabled,
    string ReadinessDisposition,
    IReadOnlyList<string> BackupOnlyState,
    IReadOnlyList<LegacyTargetArtifact> TargetArtifacts,
    IReadOnlyList<string> ImportedRelativePaths,
    string UpdatedAt,
    string? LastErrorCode);

public sealed partial class LegacyMigrationException : Exception
{
    public LegacyMigrationException(string code)
        : base("Legacy Worker migration failed.")
    {
        string candidate = code ?? string.Empty;
        Code = ErrorCode().IsMatch(candidate)
            ? candidate
            : "legacy-migration-failed";
    }

    public string Code { get; }

    [GeneratedRegex("^[a-z0-9][a-z0-9.-]{0,119}$", RegexOptions.CultureInvariant)]
    private static partial Regex ErrorCode();
}
