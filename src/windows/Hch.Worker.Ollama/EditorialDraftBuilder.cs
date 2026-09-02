using System.Text.Json;
using System.Text.RegularExpressions;
using Hch.Worker.Core;

namespace Hch.Worker.Ollama;

public sealed record EditorialParagraph(string ParagraphId, string Text, IReadOnlyList<EditorialClaim> Claims);

public sealed record EditorialClaim(
    string ClaimId,
    string Text,
    string ClaimType,
    IReadOnlyList<string> SourceIds);

public sealed record EditorialDraft(
    string SchemaVersion,
    string ContentId,
    string ContentType,
    string Locale,
    string Title,
    string Excerpt,
    IReadOnlyList<EditorialParagraph> Paragraphs,
    string ModelIdentifier,
    string GenerationPlanHash,
    string ContentContractHash,
    DateTimeOffset GeneratedAt,
    string ReviewStatus);

public static partial class EditorialDraftBuilder
{
    public static EditorialDraft Build(
        JsonElement candidate,
        EditorialContentKind contentKind,
        string model,
        string generationPlanHash,
        string contentContractHash,
        TimeProvider? timeProvider = null)
    {
        if (candidate.ValueKind != JsonValueKind.Object ||
            !candidate.TryGetProperty("title", out var titleValue) || titleValue.ValueKind != JsonValueKind.String ||
            !candidate.TryGetProperty("excerpt", out var excerptValue) || excerptValue.ValueKind != JsonValueKind.String ||
            !candidate.TryGetProperty("paragraphs", out var paragraphsValue) || paragraphsValue.ValueKind != JsonValueKind.Array)
        {
            throw new WorkerJobException(
                "editorial-candidate-schema-invalid",
                "The generated candidate is missing required editorial fields.");
        }

        ValidateHash(generationPlanHash, nameof(generationPlanHash));
        ValidateHash(contentContractHash, nameof(contentContractHash));
        var title = Sanitize(titleValue.GetString());
        var excerpt = Sanitize(excerptValue.GetString());
        if (title.Length < 8 || excerpt.Length < 20)
        {
            throw new WorkerJobException(
                "editorial-candidate-content-invalid",
                "The generated title or excerpt is below the signed minimum.");
        }

        var paragraphs = new List<EditorialParagraph>();
        foreach (var item in paragraphsValue.EnumerateArray())
        {
            if (item.ValueKind != JsonValueKind.String)
            {
                throw new WorkerJobException(
                    "editorial-candidate-content-invalid",
                    "Every generated paragraph must be final text.");
            }

            var text = EnsureCitation(Sanitize(item.GetString()));
            if (text.Length == 0)
            {
                continue;
            }

            var index = paragraphs.Count + 1;
            paragraphs.Add(new EditorialParagraph(
                $"P{index}",
                text,
                [new EditorialClaim($"P{index}C1", text, "source-statement", ["S1"])]));
        }

        if (paragraphs.Count == 0)
        {
            throw new WorkerJobException("editorial-candidate-content-invalid", "No usable paragraph was generated.");
        }

        return new EditorialDraft(
            "1.1",
            "hch-generated-" + Guid.NewGuid().ToString("D"),
            contentKind.ToString().ToLowerInvariant(),
            "pt-BR",
            title,
            excerpt,
            paragraphs,
            model,
            generationPlanHash,
            contentContractHash,
            (timeProvider ?? TimeProvider.System).GetUtcNow(),
            "pending-editorial-review");
    }

    private static string Sanitize(string? value) => WhitespacePattern().Replace(
        HtmlPattern().Replace(value ?? string.Empty, " ")
            .Replace("**", string.Empty, StringComparison.Ordinal)
            .Replace("__", string.Empty, StringComparison.Ordinal)
            .Replace("`", string.Empty, StringComparison.Ordinal)
            .Replace('“', '\'')
            .Replace('”', '\''),
        " ").Trim();

    private static string EnsureCitation(string value) => CitationPattern().IsMatch(value)
        ? value
        : value.TrimEnd() + " [S1]";

    private static void ValidateHash(string value, string parameterName)
    {
        if (value.Length != 64 || value.Any(static c => !char.IsAsciiHexDigit(c) || char.IsUpper(c)))
        {
            throw new ArgumentException("Expected a lowercase SHA-256 hexadecimal digest.", parameterName);
        }
    }

    [GeneratedRegex("<[^>]+>", RegexOptions.CultureInvariant)]
    private static partial Regex HtmlPattern();

    [GeneratedRegex("\\s+", RegexOptions.CultureInvariant)]
    private static partial Regex WhitespacePattern();

    [GeneratedRegex("\\[S1\\]\\s*$", RegexOptions.CultureInvariant)]
    private static partial Regex CitationPattern();
}
