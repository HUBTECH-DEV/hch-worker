using System.Text.Json;
using System.Text.RegularExpressions;
using Hch.Worker.Persistence;

namespace Hch.Worker.Service;

public sealed record SanitizedLogEntry(
    DateTimeOffset Timestamp,
    string Level,
    string EventCode,
    string Message,
    IReadOnlyDictionary<string, string> Fields);

public sealed partial class SanitizedLogStore
{
    private const int MaximumMessageCharacters = 1_000;
    private const int MaximumFieldCount = 24;
    private const int MaximumFieldCharacters = 300;
    private const long MaximumLogBytes = 8 * 1024 * 1024;

    private static readonly IReadOnlySet<string> AllowedLevels = new HashSet<string>(StringComparer.Ordinal)
    {
        "debug", "information", "warning", "error", "critical",
    };

    private readonly string _path;
    private readonly SemaphoreSlim _writeLock = new(1, 1);
    private readonly TimeProvider _timeProvider;

    public SanitizedLogStore(string stateRoot, TimeProvider? timeProvider = null)
    {
        var files = new AtomicFileStore(stateRoot);
        _path = files.Resolve(Path.Combine("logs", "worker.jsonl"));
        _timeProvider = timeProvider ?? TimeProvider.System;
    }

    public async Task WriteAsync(
        string level,
        string eventCode,
        string message,
        IReadOnlyDictionary<string, string>? fields = null,
        CancellationToken cancellationToken = default)
    {
        var entry = CreateEntry(level, eventCode, message, fields);
        var line = JsonSerializer.Serialize(entry) + Environment.NewLine;
        var bytes = System.Text.Encoding.UTF8.GetBytes(line);
        await _writeLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var directory = Path.GetDirectoryName(_path)!;
            Directory.CreateDirectory(directory);
            if (File.Exists(_path) && new FileInfo(_path).Length + bytes.Length > MaximumLogBytes)
            {
                var archived = Path.Combine(directory, "worker.previous.jsonl");
                File.Move(_path, archived, overwrite: true);
            }

            await using var stream = new FileStream(
                _path,
                FileMode.Append,
                FileAccess.Write,
                FileShare.Read,
                16 * 1024,
                FileOptions.Asynchronous | FileOptions.WriteThrough);
            await stream.WriteAsync(bytes, cancellationToken).ConfigureAwait(false);
            await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            _writeLock.Release();
        }
    }

    public async Task<IReadOnlyList<SanitizedLogEntry>> ReadAsync(
        DateTimeOffset? since,
        int maximumEntries,
        CancellationToken cancellationToken = default)
    {
        if (maximumEntries is < 1 or > 2_000)
        {
            throw new ArgumentOutOfRangeException(nameof(maximumEntries));
        }

        if (!File.Exists(_path))
        {
            return [];
        }

        var result = new Queue<SanitizedLogEntry>(maximumEntries);
        await using var stream = new FileStream(
            _path,
            FileMode.Open,
            FileAccess.Read,
            FileShare.ReadWrite,
            64 * 1024,
            FileOptions.Asynchronous | FileOptions.SequentialScan);
        using var reader = new StreamReader(stream);
        while (await reader.ReadLineAsync(cancellationToken).ConfigureAwait(false) is { } line)
        {
            SanitizedLogEntry? entry;
            try
            {
                entry = JsonSerializer.Deserialize<SanitizedLogEntry>(line);
            }
            catch (JsonException)
            {
                continue;
            }

            if (entry is null || since is not null && entry.Timestamp < since)
            {
                continue;
            }

            if (result.Count == maximumEntries)
            {
                result.Dequeue();
            }

            result.Enqueue(entry);
        }

        return result.ToArray();
    }

    private SanitizedLogEntry CreateEntry(
        string level,
        string eventCode,
        string message,
        IReadOnlyDictionary<string, string>? fields)
    {
        var safeLevel = level.Trim().ToLowerInvariant();
        if (!AllowedLevels.Contains(safeLevel))
        {
            throw new ArgumentException("The log level is invalid.", nameof(level));
        }

        var safeCode = SafeCode(eventCode);
        var safeFields = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var (key, value) in fields ?? new Dictionary<string, string>())
        {
            if (safeFields.Count >= MaximumFieldCount)
            {
                break;
            }

            var safeKey = SafeCode(key);
            if (SecretNamePattern().IsMatch(safeKey))
            {
                continue;
            }

            safeFields[safeKey] = Sanitize(value, MaximumFieldCharacters);
        }

        return new SanitizedLogEntry(
            _timeProvider.GetUtcNow(),
            safeLevel,
            safeCode,
            Sanitize(message, MaximumMessageCharacters),
            safeFields);
    }

    private static string SafeCode(string value)
    {
        var normalized = CodeCharacterPattern().Replace(value.Trim().ToLowerInvariant(), "-").Trim('-');
        if (normalized.Length is < 1 or > 120)
        {
            throw new ArgumentException("The structured log code is invalid.", nameof(value));
        }

        return normalized;
    }

    private static string Sanitize(string value, int maximum)
    {
        var normalized = ControlPattern().Replace(value, " ").Trim();
        return normalized.Length > maximum ? normalized[..maximum] : normalized;
    }

    [GeneratedRegex("[^a-z0-9._-]+", RegexOptions.CultureInvariant)]
    private static partial Regex CodeCharacterPattern();

    [GeneratedRegex("(?:password|passwd|secret|token|private|lease|authorization|cookie)", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex SecretNamePattern();

    [GeneratedRegex("[\\x00-\\x1F\\x7F]+", RegexOptions.CultureInvariant)]
    private static partial Regex ControlPattern();
}
