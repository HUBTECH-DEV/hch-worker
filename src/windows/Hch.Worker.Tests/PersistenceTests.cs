using System.Security.Cryptography;
using Hch.Worker.Persistence;

namespace Hch.Worker.Tests;

public sealed class PersistenceTests
{
    [Fact]
    public async Task PersistentUnlockedLegacyLockFilesDoNotBlockMigration()
    {
        string root = TemporaryDirectory();
        try
        {
            Directory.CreateDirectory(Path.Combine(root, "cycles"));
            await File.WriteAllBytesAsync(Path.Combine(root, "bootstrap.lock"), []);
            await File.WriteAllBytesAsync(Path.Combine(root, "cycles", "cycle.lock"), []);

            var inspection = await new LegacyWorkerStateInspector(root).InspectAsync();

            Assert.True(inspection.CanMigrate);
            Assert.Empty(inspection.Blockers);
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task AtomicStoreRejectsTraversalAndRoundTripsStrictJson()
    {
        var root = TemporaryDirectory();
        try
        {
            var store = new AtomicFileStore(root);
            Assert.Throws<ArgumentException>(() => store.Resolve("..\\outside.json"));
            var value = new MigrationJournal(
                1,
                "migration-1",
                "3.1.0",
                "4.0.0",
                MigrationPhase.Prepared,
                "backup",
                [],
                DateTimeOffset.UtcNow,
                null);
            await store.WriteJsonAsync("migration.json", value);
            var restored = await store.ReadJsonAsync<MigrationJournal>("migration.json");
            Assert.NotNull(restored);
            Assert.Equal(value.SchemaVersion, restored.SchemaVersion);
            Assert.Equal(value.MigrationId, restored.MigrationId);
            Assert.Equal(value.SourceVersion, restored.SourceVersion);
            Assert.Equal(value.TargetVersion, restored.TargetVersion);
            Assert.Equal(value.Phase, restored.Phase);
            Assert.Equal(value.BackupPath, restored.BackupPath);
            Assert.Equal(value.ImportedRelativePaths, restored.ImportedRelativePaths);
            Assert.Equal(value.UpdatedAt, restored.UpdatedAt);
            Assert.Equal(value.LastErrorCode, restored.LastErrorCode);
            Assert.Empty(Directory.EnumerateFiles(root, "*.tmp", SearchOption.AllDirectories));
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task LegacyInspectorBlocksActiveAndAmbiguousWork()
    {
        var root = TemporaryDirectory();
        try
        {
            var work = Path.Combine(root, "cycles", "work-1");
            Directory.CreateDirectory(work);
            await File.WriteAllTextAsync(Path.Combine(work, "assignment.json"), "{\"phase\":\"commit-unknown\"}");
            Directory.CreateDirectory(Path.Combine(root, "pending-operations"));
            await File.WriteAllTextAsync(Path.Combine(root, "pending-operations", "complete.json"), "{}");

            var inspection = await new LegacyWorkerStateInspector(root).InspectAsync();

            Assert.False(inspection.CanMigrate);
            Assert.Contains(inspection.Blockers, blocker => blocker.Code == "legacy-journal-commit-unknown");
            Assert.Contains(inspection.Blockers, blocker => blocker.Code == "legacy-operation-pending");
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public void JobJournalPreventsRegenerationAfterCommitAmbiguity()
    {
        var journal = new EditorialJobJournal(
            1,
            "assignment-1",
            new string('a', 64),
            new string('b', 64),
            DateTimeOffset.UtcNow.AddMinutes(3),
            EditorialJournalPhase.DraftReady,
            Guid.NewGuid().ToString("D"),
            new string('c', 64),
            new string('d', 64),
            null,
            DateTimeOffset.UtcNow);

        var ambiguous = journal.Transition(EditorialJournalPhase.CommitUnknown, DateTimeOffset.UtcNow);
        Assert.True(ambiguous.RequiresReconciliation);
        Assert.Throws<InvalidOperationException>(() =>
            ambiguous.Transition(EditorialJournalPhase.Generating, DateTimeOffset.UtcNow));
    }

    [Fact]
    public void MachineProtectionRoundTripsWithoutPersistingPlaintext()
    {
        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        var protector = new MachineSecretProtector();
        var secret = RandomNumberGenerator.GetBytes(64);
        try
        {
            var protectedBytes = protector.Protect(secret, "worker-operational-key:test-node");
            Assert.NotEqual(secret, protectedBytes);
            Assert.Equal(secret, protector.Unprotect(protectedBytes, "worker-operational-key:test-node"));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(secret);
        }
    }

    private static string TemporaryDirectory()
    {
        var path = Path.Combine(Path.GetTempPath(), "hch-worker-tests", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(path);
        return path;
    }
}
