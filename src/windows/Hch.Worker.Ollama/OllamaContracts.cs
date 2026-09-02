using System.Collections.ObjectModel;
using System.Text.Json;
using Hch.Worker.Core;

namespace Hch.Worker.Ollama;

public enum EditorialContentKind
{
    News,
    Article,
    Event,
    Radar,
    Catalog,
}

public sealed record OllamaGenerationPlan(
    string Model,
    double Temperature,
    int ContextWindow,
    int MaximumOutputTokens,
    int FirstProgressGraceSeconds,
    int StallAfterSeconds,
    int FinalizationGraceSeconds,
    int? NumberOfThreads = null)
{
    public OllamaGenerationPlan Validate()
    {
        if (string.IsNullOrWhiteSpace(Model) || Model.Length > 200 ||
            Model.Any(static c => char.IsControl(c) || char.IsWhiteSpace(c)))
        {
            throw new WorkerJobException("ollama-model-invalid", "The signed Ollama model identifier is invalid.");
        }

        if (!double.IsFinite(Temperature) || Temperature is < 0 or > 2 ||
            ContextWindow is < 256 or > 2_000_000 ||
            MaximumOutputTokens is < 1 or > 262_144 ||
            FirstProgressGraceSeconds is < 1 or > 3_600 ||
            StallAfterSeconds is < 1 or > 3_600 ||
            FinalizationGraceSeconds is < 1 or > 600 ||
            NumberOfThreads is < 1 or > 64)
        {
            throw new WorkerJobException("generation-plan-invalid", "The signed generation limits are invalid.");
        }

        return this;
    }
}

public sealed record SignedModelPolicy(
    string ContentContractHash,
    IReadOnlyDictionary<EditorialContentKind, OllamaGenerationPlan> Profiles)
{
    public OllamaGenerationPlan Select(EditorialContentKind contentKind)
    {
        if (ContentContractHash.Length != 64 ||
            ContentContractHash.Any(static c => !char.IsAsciiHexDigit(c) || char.IsUpper(c)))
        {
            throw new WorkerJobException("content-contract-hash-invalid", "The signed content contract hash is invalid.");
        }

        if (!Profiles.TryGetValue(contentKind, out var plan))
        {
            throw new WorkerJobException(
                "ollama-model-policy-missing",
                "No signed model policy exists for this editorial content type.");
        }

        return plan.Validate();
    }
}

public sealed record OllamaProgress(
    string Phase,
    int Attempt,
    long Sequence,
    long ContentBytes,
    DateTimeOffset ObservedAt,
    double? Percent = null);

public sealed record OllamaGenerationResult(
    JsonElement Content,
    string Model,
    long ContentBytes,
    string DoneReason,
    TimeSpan Duration);

public sealed record OllamaModelStatus(
    bool Available,
    string Model,
    string? Digest,
    long? SizeBytes,
    string? ErrorCode);

internal static class OllamaJson
{
    public static JsonSerializerOptions Options { get; } = new(JsonSerializerDefaults.Web)
    {
        AllowTrailingCommas = false,
        MaxDepth = 64,
        PropertyNameCaseInsensitive = false,
        ReadCommentHandling = JsonCommentHandling.Disallow,
        UnmappedMemberHandling = System.Text.Json.Serialization.JsonUnmappedMemberHandling.Skip,
        WriteIndented = false,
    };
}
