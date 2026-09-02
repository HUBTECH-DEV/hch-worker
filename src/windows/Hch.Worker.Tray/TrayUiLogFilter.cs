using Hch.Worker.IPC.Contracts;

namespace Hch.Worker.Tray;

internal static class TrayUiLogFilter
{
    public static IReadOnlyList<SanitizedLogEntryPayload> Apply(
        IEnumerable<SanitizedLogEntryPayload> entries,
        string? query,
        string? level)
    {
        ArgumentNullException.ThrowIfNull(entries);
        string[] terms = (query ?? string.Empty)
            .Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

        return entries
            .Where(entry => string.IsNullOrWhiteSpace(level)
                || string.Equals(entry.Level, level, StringComparison.OrdinalIgnoreCase))
            .Where(entry => terms.Length == 0 || terms.All(term => Contains(entry, term)))
            .OrderByDescending(entry => entry.Timestamp)
            .ToArray();
    }

    public static string DisplayText(SanitizedLogEntryPayload entry) =>
        $"{entry.Timestamp.ToLocalTime():yyyy-MM-dd HH:mm:ss} [{entry.Level}] {entry.EventCode}: {entry.Message}";

    private static bool Contains(SanitizedLogEntryPayload entry, string term) =>
        entry.Timestamp.ToString("O").Contains(term, StringComparison.OrdinalIgnoreCase)
        || entry.Level.Contains(term, StringComparison.OrdinalIgnoreCase)
        || entry.EventCode.Contains(term, StringComparison.OrdinalIgnoreCase)
        || entry.Message.Contains(term, StringComparison.OrdinalIgnoreCase)
        || entry.Fields.Any(field => field.Key.Contains(term, StringComparison.OrdinalIgnoreCase)
            || field.Value.Contains(term, StringComparison.OrdinalIgnoreCase));
}
