using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Hch.Worker.Persistence;
using Hch.Worker.Security;

namespace Hch.Worker.Tests;

public sealed class LegacyWindowsMigrationTests
{
    [Fact]
    public async Task MigrationPreservesIdentityAndNodeButRebuildsReadinessPaused()
    {
        await using var fixture = await LegacyFixture.CreateAsync();
        string sourceDigestBefore = await fixture.SourceDigestAsync();
        var protector = new TestMachineProtector();
        var migrator = new LegacyWindowsWorkerMigrator(
            protector,
            new FixturePreflight());

        LegacyWindowsMigrationResult first = await migrator.MigrateAsync(fixture.Request);
        string configDigest = await HashFileAsync(first.ConfigurationPath);
        DateTime configWriteTime = File.GetLastWriteTimeUtc(first.ConfigurationPath);
        LegacyWindowsMigrationResult second = await migrator.MigrateAsync(fixture.Request);

        Assert.Equal(MigrationPhase.Committed, first.Phase);
        Assert.Equal(first, second);
        Assert.Equal(fixture.NodeId, first.NodeId);
        Assert.Equal(fixture.WorkerFingerprint, first.KeyId);
        Assert.False(first.ClaimsEnabled);
        Assert.Equal("rebuild-by-v4-bootstrap-attestation", first.ReadinessDisposition);
        Assert.Equal(sourceDigestBefore, await fixture.SourceDigestAsync());
        Assert.Equal(configDigest, await HashFileAsync(first.ConfigurationPath));
        Assert.Equal(configWriteTime, File.GetLastWriteTimeUtc(first.ConfigurationPath));

        using (JsonDocument config = JsonDocument.Parse(await File.ReadAllBytesAsync(first.ConfigurationPath)))
        {
            JsonElement root = config.RootElement;
            Assert.Equal(fixture.NodeId, root.GetProperty("nodeId").GetString());
            Assert.Equal(fixture.WorkerFingerprint, root.GetProperty("keyId").GetString());
            Assert.Equal(5, root.GetProperty("lastNonZeroMaxConcurrentJobs").GetInt32());
            Assert.Equal(5, root.GetProperty("claimBatchSize").GetInt32());
            Assert.Equal(8, root.GetProperty("localResourceLimit").GetInt32());
        }

        byte[] protectedPkcs8 = await File.ReadAllBytesAsync(first.IdentityPath);
        byte[] pkcs8 = protector.Unprotect(
            protectedPkcs8,
            $"operational-identity:{fixture.NodeId}");
        try
        {
            using Ed25519Identity imported = Ed25519Identity.ImportPkcs8(pkcs8);
            Assert.Equal(fixture.WorkerFingerprint, imported.Fingerprint);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(protectedPkcs8);
            CryptographicOperations.ZeroMemory(pkcs8);
        }

        Assert.False(File.Exists(Path.Combine(fixture.TargetRoot, "state", "ready.json")));
        Assert.False(File.Exists(Path.Combine(fixture.TargetRoot, "state", "applied-manifest.json")));
        Assert.False(File.Exists(Path.Combine(fixture.TargetRoot, "state", "trust-state.json")));
        Assert.True(File.Exists(Path.Combine(first.BackupPath, "source", "state", "ready.json")));
        Assert.True(File.Exists(Path.Combine(first.BackupPath, "source", "state", "applied-manifest.json")));
        Assert.True(File.Exists(Path.Combine(first.BackupPath, "source", "state", "trust-state.json")));

        var backupStore = new AtomicFileStore(first.BackupPath);
        LegacyBackupReceipt backupReceipt = Assert.IsType<LegacyBackupReceipt>(
            await backupStore.ReadJsonAsync<LegacyBackupReceipt>("backup-receipt.json"));
        Assert.Equal(first.MigrationId, backupReceipt.Payload.MigrationId);
        Assert.Equal(fixture.NodeId, backupReceipt.Payload.NodeId);
        Assert.Equal(fixture.WorkerFingerprint, backupReceipt.Payload.KeyId);
        Assert.NotEmpty(backupReceipt.Payload.Files);
        Assert.NotEmpty(backupReceipt.Payload.AclReceipts);
        Assert.Equal(
            LegacyWindowsWorkerMigrator.CreateLegacyServiceName(fixture.NodeId),
            backupReceipt.Payload.ServiceDefinition.ServiceName);
        Assert.Matches("^[0-9a-f]{64}$", backupReceipt.ReceiptSha256);
        Assert.All(
            backupReceipt.Payload.Files,
            file => Assert.True(
                (File.GetAttributes(Path.Combine(
                    first.BackupPath,
                    "source",
                    file.RelativePath.Replace('/', Path.DirectorySeparatorChar)))
                    & FileAttributes.ReadOnly) != 0));

        var state = new AtomicFileStore(Path.Combine(fixture.TargetRoot, "state"));
        LegacyWindowsMigrationJournal journal = Assert.IsType<LegacyWindowsMigrationJournal>(
            await state.ReadJsonAsync<LegacyWindowsMigrationJournal>(
                LegacyWindowsWorkerPaths.TargetMigrationJournalRelativePath));
        Assert.Equal("Paused/Drain", journal.OperationalState);
        Assert.False(journal.ClaimsEnabled);
        Assert.Contains("ready", journal.BackupOnlyState);
        Assert.Contains("trust-state", journal.BackupOnlyState);
        Assert.Contains("journals", journal.BackupOnlyState);
    }

    [Theory]
    [InlineData("complete-assignment-01.json")]
    [InlineData("fail-assignment-01.json")]
    public async Task PendingTerminalOperationBlocksMigration(string operationFileName)
    {
        await using var fixture = await LegacyFixture.CreateAsync();
        string pending = Path.Combine(fixture.SourceRoot, "state", "pending-operations");
        Directory.CreateDirectory(pending);
        await File.WriteAllTextAsync(
            Path.Combine(pending, operationFileName),
            "{\"schema\":\"hch.pending-operation/v1\"}");
        var protector = new TestMachineProtector();
        var migrator = new LegacyWindowsWorkerMigrator(protector, new FixturePreflight());

        LegacyMigrationException error = await Assert.ThrowsAsync<LegacyMigrationException>(
            () => migrator.MigrateAsync(fixture.Request));

        Assert.Equal("legacy-state-reconciliation-required", error.Code);
        Assert.False(File.Exists(Path.Combine(fixture.TargetRoot, "config.json")));
        Assert.Equal(0, protector.ProtectCalls);
    }

    [Fact]
    public async Task ActiveCapacityBlocksMigrationEvenWithoutAnActiveBatchFile()
    {
        await using var fixture = await LegacyFixture.CreateAsync();
        await File.WriteAllTextAsync(
            Path.Combine(fixture.SourceRoot, "state", "capacity.json"),
            "{\"activeAssignments\":1}");
        var migrator = new LegacyWindowsWorkerMigrator(
            new TestMachineProtector(),
            new FixturePreflight());

        LegacyMigrationException error = await Assert.ThrowsAsync<LegacyMigrationException>(
            () => migrator.MigrateAsync(fixture.Request));

        Assert.Equal("legacy-state-reconciliation-required", error.Code);
    }

    [Fact]
    public async Task NodeMismatchFailsClosedBeforeSecretConversion()
    {
        await using var fixture = await LegacyFixture.CreateAsync();
        await fixture.WriteIdentityMetadataAsync("different-node", fixture.WorkerFingerprint);
        var protector = new TestMachineProtector();
        var migrator = new LegacyWindowsWorkerMigrator(protector, new FixturePreflight());

        LegacyMigrationException error = await Assert.ThrowsAsync<LegacyMigrationException>(
            () => migrator.MigrateAsync(fixture.Request));

        Assert.Equal("legacy-identity-metadata-invalid", error.Code);
        Assert.Equal(0, protector.ProtectCalls);
        Assert.False(File.Exists(Path.Combine(fixture.TargetRoot, "config.json")));
    }

    [Fact]
    public async Task PublicAndPrivateKeyMismatchFailsClosed()
    {
        await using var fixture = await LegacyFixture.CreateAsync();
        using (Ed25519Identity replacement = Ed25519Identity.Generate())
        {
            await File.WriteAllTextAsync(
                Path.Combine(fixture.SourceRoot, "state", "identity", "worker-public.spki.pem"),
                replacement.ExportSubjectPublicKeyInfoPem());
        }

        var protector = new TestMachineProtector();
        var migrator = new LegacyWindowsWorkerMigrator(protector, new FixturePreflight());

        LegacyMigrationException error = await Assert.ThrowsAsync<LegacyMigrationException>(
            () => migrator.MigrateAsync(fixture.Request));

        Assert.Equal("legacy-identity-keypair-mismatch", error.Code);
        Assert.Equal(0, protector.ProtectCalls);
    }

    [Fact]
    public async Task UnprovenStoppedServiceBlocksMigration()
    {
        await using var fixture = await LegacyFixture.CreateAsync();
        var migrator = new LegacyWindowsWorkerMigrator(
            new TestMachineProtector(),
            new FixturePreflight(serviceState: "Running", processId: 9876));

        LegacyMigrationException error = await Assert.ThrowsAsync<LegacyMigrationException>(
            () => migrator.MigrateAsync(fixture.Request));

        Assert.Equal("legacy-runtime-preflight-unproven", error.Code);
        Assert.False(File.Exists(Path.Combine(fixture.TargetRoot, "config.json")));
    }

    [Fact]
    public async Task UnrelatedServiceExecutableBlocksMigration()
    {
        await using var fixture = await LegacyFixture.CreateAsync();
        var migrator = new LegacyWindowsWorkerMigrator(
            new TestMachineProtector(),
            new FixturePreflight(
                imagePath: "\"C:\\Program Files\\HCH\\EditorialWorker\\NotHchEditorialWorkerService.exe\""));

        LegacyMigrationException error = await Assert.ThrowsAsync<LegacyMigrationException>(
            () => migrator.MigrateAsync(fixture.Request));

        Assert.Equal("legacy-runtime-preflight-unproven", error.Code);
        Assert.False(File.Exists(Path.Combine(fixture.TargetRoot, "config.json")));
    }

    [Fact]
    public async Task FailureRollsBackOnlyCreatedArtifactsAndKeepsImmutableBackup()
    {
        await using var fixture = await LegacyFixture.CreateAsync();
        string unrelated = Path.Combine(fixture.TargetRoot, "operator-note.txt");
        await File.WriteAllTextAsync(unrelated, "preserve-me");
        const string secretMarker = "SHOULD-NOT-APPEAR-IN-ERRORS";
        var migrator = new LegacyWindowsWorkerMigrator(
            new TestMachineProtector(),
            new FixturePreflight(),
            faultInjector: new FailAfterFirstArtifact(secretMarker));

        LegacyMigrationException error = await Assert.ThrowsAsync<LegacyMigrationException>(
            () => migrator.MigrateAsync(fixture.Request));

        Assert.Equal("legacy-migration-transaction-failed", error.Code);
        Assert.DoesNotContain(secretMarker, error.ToString(), StringComparison.Ordinal);
        Assert.Equal("preserve-me", await File.ReadAllTextAsync(unrelated));
        Assert.False(File.Exists(Path.Combine(fixture.TargetRoot, "config.json")));
        Assert.False(File.Exists(Path.Combine(
            fixture.TargetRoot,
            "state",
            "identity",
            "worker-ed25519.pkcs8.dpapi")));
        Assert.False(File.Exists(Path.Combine(
            fixture.TargetRoot,
            "trust",
            "orchestrator-root.pem")));

        var state = new AtomicFileStore(Path.Combine(fixture.TargetRoot, "state"));
        LegacyWindowsMigrationJournal journal = Assert.IsType<LegacyWindowsMigrationJournal>(
            await state.ReadJsonAsync<LegacyWindowsMigrationJournal>(
                LegacyWindowsWorkerPaths.TargetMigrationJournalRelativePath));
        Assert.Equal(MigrationPhase.RolledBack, journal.Phase);
        Assert.NotEmpty(journal.BackupRelativePath);
        string backup = state.Resolve(journal.BackupRelativePath);
        Assert.True(File.Exists(Path.Combine(backup, "backup-receipt.json")));

        foreach (string json in Directory.EnumerateFiles(
            Path.Combine(fixture.TargetRoot, "state"),
            "*.json",
            SearchOption.AllDirectories))
        {
            Assert.DoesNotContain(secretMarker, await File.ReadAllTextAsync(json), StringComparison.Ordinal);
        }
    }

    [Fact]
    public async Task ExplicitRollbackIsSelectiveAndIdempotent()
    {
        await using var fixture = await LegacyFixture.CreateAsync();
        string unrelated = Path.Combine(fixture.TargetRoot, "state", "owned-by-operator.txt");
        Directory.CreateDirectory(Path.GetDirectoryName(unrelated)!);
        await File.WriteAllTextAsync(unrelated, "keep");
        var migrator = new LegacyWindowsWorkerMigrator(
            new TestMachineProtector(),
            new FixturePreflight());
        LegacyWindowsMigrationResult result = await migrator.MigrateAsync(fixture.Request);

        await migrator.RollbackAsync(fixture.TargetRoot, result.MigrationId);
        await migrator.RollbackAsync(fixture.TargetRoot, result.MigrationId);

        Assert.Equal("keep", await File.ReadAllTextAsync(unrelated));
        Assert.False(File.Exists(result.ConfigurationPath));
        Assert.False(File.Exists(result.IdentityPath));
        Assert.False(File.Exists(result.RootPublicKeyPath));
        Assert.True(File.Exists(Path.Combine(result.BackupPath, "backup-receipt.json")));
    }

    private static async Task<string> HashFileAsync(string path)
    {
        await using FileStream stream = File.OpenRead(path);
        return Convert.ToHexStringLower(await SHA256.HashDataAsync(stream));
    }

    private sealed class TestMachineProtector : IMachineSecretProtector
    {
        private const byte Mask = 0xA7;

        public int ProtectCalls { get; private set; }

        public byte[] Protect(ReadOnlySpan<byte> plaintext, string purpose)
        {
            ProtectCalls++;
            return Transform(plaintext, purpose);
        }

        public byte[] Unprotect(ReadOnlySpan<byte> ciphertext, string purpose) =>
            Transform(ciphertext, purpose);

        private static byte[] Transform(ReadOnlySpan<byte> value, string purpose)
        {
            Assert.StartsWith("operational-identity:", purpose, StringComparison.Ordinal);
            byte[] transformed = value.ToArray();
            for (int index = 0; index < transformed.Length; index++)
            {
                transformed[index] ^= Mask;
            }

            return transformed;
        }
    }

    private sealed class FixturePreflight(
        string serviceState = "Stopped",
        int? processId = null,
        string imagePath = "\"C:\\Program Files\\HCH\\EditorialWorker\\HchEditorialWorkerService.exe\"")
        : ILegacyWorkerRuntimePreflight
    {
        public Task<LegacyRuntimePreflightEvidence> CaptureAsync(
            LegacyWorkerSourceDescriptor source,
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            IReadOnlyList<LegacyAclReceipt> acls = Directory
                .EnumerateFiles(source.ProductRoot, "*", SearchOption.AllDirectories)
                .Select(path => new LegacyAclReceipt(
                    Path.GetRelativePath(source.ProductRoot, path)
                        .Replace(Path.DirectorySeparatorChar, '/'),
                    "O:BAG:BAD:(A;;FA;;;SY)(A;;FA;;;BA)"))
                .OrderBy(static receipt => receipt.RelativePath, StringComparer.Ordinal)
                .ToArray();
            var definition = new LegacyServiceDefinitionReceipt(
                source.ServiceName,
                imagePath,
                $@"NT SERVICE\{source.ServiceName}",
                StartMode: 2,
                ServiceType: 16,
                DelayedAutomaticStart: true,
                FailureActionsSha256: new string('0', 64),
                SecurityDescriptorSddl: "O:SYG:SYD:(A;;CCLCSWRPWPDTLOCRRC;;;SY)");
            return Task.FromResult(new LegacyRuntimePreflightEvidence(
                ServiceInstalled: true,
                source.ServiceName,
                serviceState,
                processId,
                ExclusiveWriterLocksAvailable: true,
                definition,
                acls,
                DateTimeOffset.UtcNow));
        }
    }

    private sealed class FailAfterFirstArtifact(string secret) : ILegacyMigrationFaultInjector
    {
        public Task AfterTargetArtifactAsync(
            string relativePath,
            int committedArtifactCount,
            CancellationToken cancellationToken)
        {
            if (committedArtifactCount == 1)
            {
                throw new InvalidOperationException(secret);
            }

            return Task.CompletedTask;
        }
    }

    private sealed class LegacyFixture : IAsyncDisposable
    {
        private LegacyFixture(
            string root,
            string sourceRoot,
            string targetRoot,
            string nodeId,
            string workerFingerprint)
        {
            Root = root;
            SourceRoot = sourceRoot;
            TargetRoot = targetRoot;
            NodeId = nodeId;
            WorkerFingerprint = workerFingerprint;
            Request = new LegacyWindowsMigrationRequest(
                sourceRoot,
                targetRoot,
                "S-1-5-21-100-200-300-1001");
        }

        public string Root { get; }
        public string SourceRoot { get; }
        public string TargetRoot { get; }
        public string NodeId { get; }
        public string WorkerFingerprint { get; }
        public LegacyWindowsMigrationRequest Request { get; }

        public static async Task<LegacyFixture> CreateAsync()
        {
            string root = Path.Combine(
                Path.GetTempPath(),
                "hch-legacy-migration-tests",
                Guid.NewGuid().ToString("N"));
            string source = Path.Combine(root, "legacy");
            string target = Path.Combine(root, "v4");
            string nodeId = "windows-worker-test-01";
            Directory.CreateDirectory(Path.Combine(source, "config"));
            Directory.CreateDirectory(Path.Combine(source, "state", "identity"));
            Directory.CreateDirectory(Path.Combine(source, "state", "receipts"));
            Directory.CreateDirectory(Path.Combine(source, "trust"));
            Directory.CreateDirectory(target);

            using Ed25519Identity worker = Ed25519Identity.Generate();
            byte[] workerPkcs8 = worker.ExportPkcs8PrivateKey();
            try
            {
                await File.WriteAllTextAsync(
                    Path.Combine(source, "state", "identity", "worker-private.pk8.pem"),
                    PemEncoding.WriteString("PRIVATE KEY", workerPkcs8));
            }
            finally
            {
                CryptographicOperations.ZeroMemory(workerPkcs8);
            }

            await File.WriteAllTextAsync(
                Path.Combine(source, "state", "identity", "worker-public.spki.pem"),
                worker.ExportSubjectPublicKeyInfoPem());

            var fixture = new LegacyFixture(root, source, target, nodeId, worker.Fingerprint);
            await fixture.WriteIdentityMetadataAsync(nodeId, worker.Fingerprint);
            await File.WriteAllTextAsync(
                Path.Combine(source, "config", "WorkerConfig.psd1"),
                fixture.ConfigurationText());
            await WriteJsonAsync(
                Path.Combine(source, "state", "worker-control.json"),
                new
                {
                    schema = "hch.worker-control/v1",
                    schemaVersion = 1,
                    nodeId,
                    acceptingClaims = true,
                    requestedParallelism = 5,
                    lastNonZeroParallelism = 5,
                    drainRequested = false,
                    updatedAt = DateTimeOffset.UtcNow.ToString("O"),
                    updatedBy = "test",
                });

            using Ed25519Identity rootIdentity = Ed25519Identity.Generate();
            await File.WriteAllTextAsync(
                Path.Combine(source, "trust", "orchestrator-root.pem"),
                rootIdentity.ExportSubjectPublicKeyInfoPem());
            await WriteJsonAsync(
                Path.Combine(source, "state", "trust-state.json"),
                new
                {
                    schema = "hch.worker-trust-state/v1",
                    schemaVersion = 1,
                    rootKeyId = "hch-root-test-v1",
                    rootFingerprint = rootIdentity.Fingerprint,
                    releaseKeyId = "release-test",
                    manifestSequence = 12,
                });
            await File.WriteAllTextAsync(
                Path.Combine(source, "state", "ready.json"),
                "{\"ready\":true,\"sourceVersion\":\"3.1.0\"}");
            await File.WriteAllTextAsync(
                Path.Combine(source, "state", "applied-manifest.json"),
                "{\"manifestSequence\":12,\"manifestHash\":\"legacy-evidence-only\"}");
            await File.WriteAllTextAsync(
                Path.Combine(source, "state", "receipts", "update.json"),
                "{\"result\":\"applied\"}");
            return fixture;
        }

        public async Task WriteIdentityMetadataAsync(string nodeId, string keyId)
        {
            await WriteJsonAsync(
                Path.Combine(SourceRoot, "state", "identity", "identity.json"),
                new
                {
                    schemaVersion = 2,
                    nodeId,
                    keyId,
                    algorithm = "Ed25519",
                    privateKeyFormat = "PKCS8-PEM",
                    publicKeyFormat = "SPKI-PEM",
                    privateKeyPath = Path.Combine(
                        SourceRoot,
                        "state",
                        "identity",
                        "worker-private.pk8.pem"),
                    publicKeyPath = Path.Combine(
                        SourceRoot,
                        "state",
                        "identity",
                        "worker-public.spki.pem"),
                    createdAt = DateTimeOffset.UtcNow.ToString("O"),
                });
        }

        public async Task<string> SourceDigestAsync()
        {
            var digest = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
            foreach (string path in Directory
                .EnumerateFiles(SourceRoot, "*", SearchOption.AllDirectories)
                .Order(StringComparer.Ordinal))
            {
                digest.AppendData(Encoding.UTF8.GetBytes(
                    Path.GetRelativePath(SourceRoot, path).Replace(Path.DirectorySeparatorChar, '/')));
                digest.AppendData(await File.ReadAllBytesAsync(path));
            }

            return Convert.ToHexStringLower(digest.GetHashAndReset());
        }

        public ValueTask DisposeAsync()
        {
            if (Directory.Exists(Root))
            {
                foreach (string file in Directory.EnumerateFiles(Root, "*", SearchOption.AllDirectories))
                {
                    File.SetAttributes(file, FileAttributes.Normal);
                }

                Directory.Delete(Root, recursive: true);
            }

            return ValueTask.CompletedTask;
        }

        private string ConfigurationText() => $$"""
            @{
              SchemaVersion = 2
              NodeId = '{{NodeId}}'
              ControlPlaneBaseUri = 'https://hubtech.online'
              RequestedCapacity = 5
              LocalParallelismLimit = 8
              RootPublicKeyPath = '{{Path.Combine(SourceRoot, "trust", "orchestrator-root.pem")}}'
              StateRoot = '{{Path.Combine(SourceRoot, "state")}}'
              InstallRoot = '{{Path.Combine(SourceRoot, "runtime")}}'
              OllamaBaseUri = 'http://127.0.0.1:11434'
            }
            """;

        private static Task WriteJsonAsync(string path, object value) =>
            File.WriteAllBytesAsync(
                path,
                JsonSerializer.SerializeToUtf8Bytes(value, AtomicFileStore.JsonOptions));
    }
}
