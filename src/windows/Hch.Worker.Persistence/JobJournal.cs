namespace Hch.Worker.Persistence;

public enum EditorialJournalPhase
{
    Claimed,
    Generating,
    DraftReady,
    Completing,
    FailUnknown,
    CommitUnknown,
    Completed,
    Failed,
    Abandoned,
}

public sealed record EditorialJobJournal(
    int SchemaVersion,
    string AssignmentId,
    string GenerationPlanHash,
    string LeaseTokenHash,
    DateTimeOffset LeaseExpiresAt,
    EditorialJournalPhase Phase,
    string RequestId,
    string RequestBodyDigest,
    string? DraftHash,
    string? LastErrorCode,
    DateTimeOffset UpdatedAt)
{
    public const int CurrentSchemaVersion = 1;

    public EditorialJobJournal Transition(
        EditorialJournalPhase next,
        DateTimeOffset now,
        string? draftHash = null,
        string? lastErrorCode = null)
    {
        if (!AllowedTransitions.TryGetValue(Phase, out var allowed) || !allowed.Contains(next))
        {
            throw new InvalidOperationException($"Journal transition {Phase} -> {next} is not allowed.");
        }

        return this with
        {
            Phase = next,
            DraftHash = draftHash ?? DraftHash,
            LastErrorCode = lastErrorCode,
            UpdatedAt = now,
        };
    }

    public bool RequiresReconciliation => Phase is
        EditorialJournalPhase.DraftReady or
        EditorialJournalPhase.Completing or
        EditorialJournalPhase.FailUnknown or
        EditorialJournalPhase.CommitUnknown;

    public bool IsActive => Phase is EditorialJournalPhase.Claimed or EditorialJournalPhase.Generating;

    private static IReadOnlyDictionary<EditorialJournalPhase, IReadOnlySet<EditorialJournalPhase>> AllowedTransitions { get; } =
        new Dictionary<EditorialJournalPhase, IReadOnlySet<EditorialJournalPhase>>
        {
            [EditorialJournalPhase.Claimed] = Set(EditorialJournalPhase.Generating, EditorialJournalPhase.FailUnknown, EditorialJournalPhase.Failed, EditorialJournalPhase.Abandoned),
            [EditorialJournalPhase.Generating] = Set(EditorialJournalPhase.DraftReady, EditorialJournalPhase.FailUnknown, EditorialJournalPhase.Failed, EditorialJournalPhase.Abandoned),
            [EditorialJournalPhase.DraftReady] = Set(EditorialJournalPhase.Completing, EditorialJournalPhase.FailUnknown, EditorialJournalPhase.CommitUnknown),
            [EditorialJournalPhase.Completing] = Set(EditorialJournalPhase.Completed, EditorialJournalPhase.CommitUnknown),
            [EditorialJournalPhase.FailUnknown] = Set(EditorialJournalPhase.Failed, EditorialJournalPhase.FailUnknown),
            [EditorialJournalPhase.CommitUnknown] = Set(EditorialJournalPhase.Completed, EditorialJournalPhase.CommitUnknown),
            [EditorialJournalPhase.Abandoned] = Set(EditorialJournalPhase.Failed),
            [EditorialJournalPhase.Completed] = Set(),
            [EditorialJournalPhase.Failed] = Set(),
        };

    private static IReadOnlySet<EditorialJournalPhase> Set(params EditorialJournalPhase[] phases) =>
        new HashSet<EditorialJournalPhase>(phases);
}

public sealed class EditorialJournalStore(AtomicFileStore files)
{
    public Task<EditorialJobJournal?> ReadAsync(string assignmentId, CancellationToken cancellationToken = default) =>
        files.ReadJsonAsync<EditorialJobJournal>(PathFor(assignmentId), cancellationToken);

    public Task WriteAsync(EditorialJobJournal journal, CancellationToken cancellationToken = default)
    {
        ValidateIdentifier(journal.AssignmentId);
        return files.WriteJsonAsync(PathFor(journal.AssignmentId), journal, cancellationToken);
    }

    public IReadOnlyList<string> ListAssignmentIds()
    {
        var directory = files.Resolve(Path.Combine("journals", "assignments"));
        if (!Directory.Exists(directory))
        {
            return [];
        }

        return Directory.EnumerateFiles(directory, "*.json", SearchOption.TopDirectoryOnly)
            .Select(Path.GetFileNameWithoutExtension)
            .Where(static value => value is not null)
            .Select(static value => value!)
            .Select(static value =>
            {
                ValidateIdentifier(value);
                return value;
            })
            .OrderBy(static value => value, StringComparer.Ordinal)
            .ToArray();
    }

    private static string PathFor(string assignmentId)
    {
        ValidateIdentifier(assignmentId);
        return Path.Combine("journals", "assignments", assignmentId + ".json");
    }

    private static void ValidateIdentifier(string value)
    {
        if (string.IsNullOrWhiteSpace(value) || value.Length > 160 ||
            value.Any(static item => !(char.IsAsciiLetterOrDigit(item) || item is '.' or '_' or '-')))
        {
            throw new ArgumentException("The assignment identifier is not path-safe.", nameof(value));
        }
    }
}
