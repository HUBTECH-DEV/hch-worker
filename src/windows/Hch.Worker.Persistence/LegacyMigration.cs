using System.Text.Json;

namespace Hch.Worker.Persistence;

public sealed record MigrationBlocker(string Code, string RelativePath);

public sealed record MigrationInspection(
    bool CanMigrate,
    IReadOnlyList<MigrationBlocker> Blockers,
    DateTimeOffset InspectedAt);

public sealed class LegacyWorkerStateInspector(string legacyStateRoot, TimeProvider? timeProvider = null)
{
    private static readonly IReadOnlySet<string> BlockingPhases = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
    {
        "claimed",
        "generating",
        "draft-ready",
        "completing",
        "fail-unknown",
        "commit-unknown",
    };

    private readonly string _root = Path.GetFullPath(legacyStateRoot);
    private readonly TimeProvider _timeProvider = timeProvider ?? TimeProvider.System;

    public async Task<MigrationInspection> InspectAsync(CancellationToken cancellationToken = default)
    {
        var blockers = new List<MigrationBlocker>();
        if (!Directory.Exists(_root) || IsReparsePoint(_root))
        {
            blockers.Add(new MigrationBlocker("legacy-state-root-invalid", "."));
            return new MigrationInspection(false, blockers, _timeProvider.GetUtcNow());
        }

        AddIfLocked(blockers, "legacy-bootstrap-running", "bootstrap.lock");
        AddIfLocked(blockers, "legacy-cycle-running", Path.Combine("cycles", "cycle.lock"));
        AddIfExists(blockers, "legacy-active-batch-present", Path.Combine("cycles", "active-batch.json"));
        await InspectCapacityAsync(blockers, cancellationToken).ConfigureAwait(false);
        await InspectStatusAsync(blockers, cancellationToken).ConfigureAwait(false);

        var pendingOperations = Resolve(Path.Combine("pending-operations"));
        if (Directory.Exists(pendingOperations))
        {
            if (IsReparsePoint(pendingOperations))
            {
                blockers.Add(new MigrationBlocker("legacy-pending-operations-invalid", "pending-operations"));
            }
            else
            {
                foreach (var file in Directory.EnumerateFiles(pendingOperations, "*.json", SearchOption.TopDirectoryOnly))
                {
                    if (IsReparsePoint(file))
                    {
                        blockers.Add(new MigrationBlocker("legacy-pending-operation-invalid", Relative(file)));
                    }
                    else
                    {
                        blockers.Add(new MigrationBlocker("legacy-operation-pending", Relative(file)));
                    }
                }
            }
        }

        var cycles = Resolve("cycles");
        if (Directory.Exists(cycles))
        {
            foreach (var journalPath in EnumerateAssignmentJournals(cycles, blockers))
            {
                cancellationToken.ThrowIfCancellationRequested();
                var phase = await ReadPhaseAsync(journalPath, cancellationToken).ConfigureAwait(false);
                if (phase is null || BlockingPhases.Contains(phase))
                {
                    blockers.Add(new MigrationBlocker(
                        phase is null ? "legacy-journal-invalid" : $"legacy-journal-{phase.ToLowerInvariant()}",
                        Relative(journalPath)));
                }
            }
        }

        return new MigrationInspection(blockers.Count == 0, blockers, _timeProvider.GetUtcNow());
    }

    private async Task InspectCapacityAsync(
        ICollection<MigrationBlocker> blockers,
        CancellationToken cancellationToken)
    {
        string path = Resolve("capacity.json");
        if (!File.Exists(path))
        {
            return;
        }

        if (IsReparsePoint(path))
        {
            blockers.Add(new MigrationBlocker(
                "legacy-state-reparse-point-refused",
                "capacity.json"));
            return;
        }

        try
        {
            await using var stream = File.OpenRead(path);
            using JsonDocument document = await JsonDocument.ParseAsync(
                stream,
                new JsonDocumentOptions
                {
                    AllowTrailingCommas = false,
                    CommentHandling = JsonCommentHandling.Disallow,
                    MaxDepth = 32,
                },
                cancellationToken).ConfigureAwait(false);
            if (!document.RootElement.TryGetProperty("activeAssignments", out JsonElement active)
                || !active.TryGetInt32(out int activeAssignments)
                || activeAssignments < 0)
            {
                blockers.Add(new MigrationBlocker("legacy-capacity-state-invalid", "capacity.json"));
            }
            else if (activeAssignments > 0)
            {
                blockers.Add(new MigrationBlocker("legacy-active-assignment-present", "capacity.json"));
            }
        }
        catch (Exception error) when (error is JsonException or IOException or UnauthorizedAccessException)
        {
            blockers.Add(new MigrationBlocker("legacy-capacity-state-invalid", "capacity.json"));
        }
    }

    private async Task InspectStatusAsync(
        ICollection<MigrationBlocker> blockers,
        CancellationToken cancellationToken)
    {
        string path = Resolve("status.json");
        if (!File.Exists(path))
        {
            return;
        }

        if (IsReparsePoint(path))
        {
            blockers.Add(new MigrationBlocker(
                "legacy-state-reparse-point-refused",
                "status.json"));
            return;
        }

        try
        {
            await using var stream = File.OpenRead(path);
            using JsonDocument document = await JsonDocument.ParseAsync(
                stream,
                new JsonDocumentOptions
                {
                    AllowTrailingCommas = false,
                    CommentHandling = JsonCommentHandling.Disallow,
                    MaxDepth = 64,
                },
                cancellationToken).ConfigureAwait(false);
            JsonElement root = document.RootElement;
            if (root.TryGetProperty("currentBatch", out JsonElement batch)
                && batch.ValueKind is not JsonValueKind.Null and not JsonValueKind.Undefined)
            {
                blockers.Add(new MigrationBlocker("legacy-status-active-batch-present", "status.json"));
            }

            if (root.TryGetProperty("progress", out JsonElement progress)
                && progress.ValueKind is not JsonValueKind.Null and not JsonValueKind.Undefined)
            {
                blockers.Add(new MigrationBlocker("legacy-status-active-progress-present", "status.json"));
            }
        }
        catch (Exception error) when (error is JsonException or IOException or UnauthorizedAccessException)
        {
            blockers.Add(new MigrationBlocker("legacy-status-state-invalid", "status.json"));
        }
    }

    private async Task<string?> ReadPhaseAsync(string path, CancellationToken cancellationToken)
    {
        try
        {
            if (IsReparsePoint(path))
            {
                return null;
            }

            await using var stream = File.OpenRead(path);
            using var document = await JsonDocument.ParseAsync(
                stream,
                new JsonDocumentOptions { AllowTrailingCommas = false, CommentHandling = JsonCommentHandling.Disallow, MaxDepth = 32 },
                cancellationToken).ConfigureAwait(false);
            var root = document.RootElement;
            foreach (var name in new[] { "phase", "state", "status" })
            {
                if (root.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String)
                {
                    return value.GetString();
                }
            }

            return null;
        }
        catch (JsonException)
        {
            return null;
        }
    }

    private void AddIfExists(ICollection<MigrationBlocker> blockers, string code, string relativePath)
    {
        string path = Resolve(relativePath);
        if (File.Exists(path))
        {
            blockers.Add(new MigrationBlocker(
                IsReparsePoint(path) ? "legacy-state-reparse-point-refused" : code,
                relativePath.Replace(Path.DirectorySeparatorChar, '/')));
        }
    }

    private void AddIfLocked(ICollection<MigrationBlocker> blockers, string code, string relativePath)
    {
        string path = Resolve(relativePath);
        if (!File.Exists(path))
        {
            return;
        }

        if (IsReparsePoint(path))
        {
            blockers.Add(new MigrationBlocker(
                "legacy-state-reparse-point-refused",
                relativePath.Replace(Path.DirectorySeparatorChar, '/')));
            return;
        }

        try
        {
            using var probe = new FileStream(path, FileMode.Open, FileAccess.ReadWrite, FileShare.None);
        }
        catch (IOException)
        {
            blockers.Add(new MigrationBlocker(code, relativePath.Replace(Path.DirectorySeparatorChar, '/')));
        }
        catch (UnauthorizedAccessException)
        {
            blockers.Add(new MigrationBlocker("legacy-lock-state-unverifiable", relativePath.Replace(Path.DirectorySeparatorChar, '/')));
        }
    }

    private string Resolve(string relativePath)
    {
        var path = Path.GetFullPath(Path.Combine(_root, relativePath));
        var prefix = _root.TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;
        if (!path.StartsWith(prefix, StringComparison.OrdinalIgnoreCase) &&
            !string.Equals(path, _root, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException("Legacy path escapes the state root.");
        }

        return path;
    }

    private string Relative(string path) => Path.GetRelativePath(_root, path).Replace(Path.DirectorySeparatorChar, '/');

    private IEnumerable<string> EnumerateAssignmentJournals(
        string root,
        ICollection<MigrationBlocker> blockers)
    {
        var pending = new Stack<string>();
        pending.Push(root);
        while (pending.Count > 0)
        {
            string directory = pending.Pop();
            if (IsReparsePoint(directory))
            {
                blockers.Add(new MigrationBlocker(
                    "legacy-state-reparse-point-refused",
                    Relative(directory)));
                continue;
            }

            foreach (string entry in Directory.EnumerateFileSystemEntries(directory))
            {
                if (IsReparsePoint(entry))
                {
                    blockers.Add(new MigrationBlocker(
                        "legacy-state-reparse-point-refused",
                        Relative(entry)));
                    continue;
                }

                if (Directory.Exists(entry))
                {
                    pending.Push(entry);
                }
                else if (Path.GetFileName(entry).Equals("assignment.json", StringComparison.OrdinalIgnoreCase))
                {
                    yield return entry;
                }
            }
        }
    }

    private static bool IsReparsePoint(string path) =>
        (File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0;
}

public enum MigrationPhase
{
    Prepared,
    BackedUp,
    Imported,
    ServiceInstalled,
    Validated,
    Committed,
    RolledBack,
}

public sealed record MigrationJournal(
    int SchemaVersion,
    string MigrationId,
    string SourceVersion,
    string TargetVersion,
    MigrationPhase Phase,
    string BackupPath,
    IReadOnlyList<string> ImportedRelativePaths,
    DateTimeOffset UpdatedAt,
    string? LastErrorCode);
