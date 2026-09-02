using System.Net;
using System.Net.Http.Headers;
using System.Text.Json;
using System.Text.Json.Nodes;
using Hch.Worker.Ollama;
using Hch.Worker.Persistence;
using Hch.Worker.Protocol;

namespace Hch.Worker.Service;

public sealed record ManifestArtifactDownload(byte[] Bytes, string MediaType);

public interface IManifestArtifactSource
{
    Task<ManifestArtifactDownload> DownloadAsync(
        ManifestArtifactContract artifact,
        CancellationToken cancellationToken);
}

public sealed record OllamaManifestProbeResult(string? ObservedEngineVersion);

public interface IOllamaManifestProbe
{
    Task<OllamaManifestProbeResult> VerifyExactModelAsync(
        string model,
        string modelDigest,
        CancellationToken cancellationToken);
}

public sealed record ManifestApplyContext(
    string NodeId,
    string WorkerKeyId,
    string WorkerRuntimeVersion);

public sealed record ManifestApplyResult(
    AppliedManifestState AppliedState,
    WorkerRuntimeProfile RuntimeProfile,
    AttestationChecksContract Checks,
    UpdateReceiptContract UpdateReceipt,
    bool MetadataOnly);

/// <summary>Origin-pinned, bounded artifact downloader for signed manifest artifacts.</summary>
public sealed class HttpManifestArtifactSource : IManifestArtifactSource
{
    private const long DefaultMaximumArtifactBytes = 64L * 1024 * 1024;
    private readonly HttpClient http;
    private readonly Uri baseUri;
    private readonly long maximumArtifactBytes;

    public HttpManifestArtifactSource(
        HttpClient http,
        Uri orchestratorBaseUri,
        long maximumArtifactBytes = DefaultMaximumArtifactBytes)
    {
        this.http = http ?? throw new ArgumentNullException(nameof(http));
        baseUri = ValidateBaseUri(orchestratorBaseUri);
        if (maximumArtifactBytes is < 1 or > 1024L * 1024 * 1024)
        {
            throw new ArgumentOutOfRangeException(nameof(maximumArtifactBytes));
        }

        this.maximumArtifactBytes = maximumArtifactBytes;
    }

    public async Task<ManifestArtifactDownload> DownloadAsync(
        ManifestArtifactContract artifact,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(artifact);
        if (artifact.Bytes > maximumArtifactBytes)
        {
            throw Error("artifact-too-large", "The signed artifact exceeds the local size limit.");
        }

        if (!Uri.TryCreate(baseUri, artifact.Url, out var target)
            || target.Scheme != baseUri.Scheme
            || !target.Host.Equals(baseUri.Host, StringComparison.OrdinalIgnoreCase)
            || target.Port != baseUri.Port
            || target.UserInfo.Length > 0)
        {
            throw Error("artifact-origin-refused", "The artifact URL left the configured control-plane origin.");
        }

        var expectedPath = "/api/editorial/orchestrator/artifacts/" + Uri.EscapeDataString(artifact.Name);
        var expectedQuery = "?sha256=" + artifact.Sha256;
        if (!target.AbsolutePath.Equals(expectedPath, StringComparison.Ordinal)
            || !target.Query.Equals(expectedQuery, StringComparison.Ordinal)
            || target.Fragment.Length > 0)
        {
            throw Error(
                "artifact-path-refused",
                "The artifact URL does not bind the signed name and digest to the artifact endpoint.");
        }

        using var request = new HttpRequestMessage(HttpMethod.Get, target);
        request.Headers.Accept.ParseAdd(artifact.MediaType);
        HttpResponseMessage response;
        try
        {
            response = await http.SendAsync(
                request,
                HttpCompletionOption.ResponseHeadersRead,
                cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            throw Error("network-request-timeout", "The artifact request timed out.");
        }
        catch (HttpRequestException error)
        {
            throw Error("network-request-failed", "The artifact request failed.", error);
        }

        using (response)
        {
            if (response.RequestMessage?.RequestUri != target)
            {
                throw Error("artifact-redirect-refused", "Artifact redirects are not accepted.");
            }

            if (!response.IsSuccessStatusCode)
            {
                throw Error(
                    "artifact-request-rejected",
                    $"The artifact request was rejected with HTTP {(int)response.StatusCode}.");
            }

            var bytes = await ReadExactlyBoundedAsync(
                response.Content,
                artifact.Bytes,
                cancellationToken).ConfigureAwait(false);
            var mediaType = response.Content.Headers.ContentType?.ToString() ?? string.Empty;
            return new ManifestArtifactDownload(bytes, mediaType);
        }
    }

    private static async Task<byte[]> ReadExactlyBoundedAsync(
        HttpContent content,
        long expectedBytes,
        CancellationToken cancellationToken)
    {
        if (content.Headers.ContentLength is { } declared && declared > expectedBytes)
        {
            throw Error("artifact-size-mismatch", "The artifact Content-Length exceeds its declaration.");
        }

        await using var stream = await content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
        using var output = new MemoryStream(checked((int)Math.Min(expectedBytes, int.MaxValue)));
        var buffer = new byte[32 * 1024];
        while (true)
        {
            var read = await stream.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
            if (read == 0)
            {
                break;
            }

            if (output.Length + read > expectedBytes)
            {
                throw Error("artifact-size-mismatch", "The artifact exceeds its signed byte count.");
            }

            output.Write(buffer, 0, read);
        }

        if (output.Length != expectedBytes)
        {
            throw Error("artifact-size-mismatch", "The artifact does not match its signed byte count.");
        }

        return output.ToArray();
    }

    private static Uri ValidateBaseUri(Uri value)
    {
        ArgumentNullException.ThrowIfNull(value);
        if (!value.IsAbsoluteUri || value.Scheme != Uri.UriSchemeHttps || value.UserInfo.Length > 0
            || value.AbsolutePath != "/" || value.Query.Length > 0 || value.Fragment.Length > 0)
        {
            throw new ArgumentException("orchestrator-base-uri-invalid", nameof(value));
        }

        return value;
    }

    private static WorkerServiceException Error(string code, string message, Exception? cause = null) =>
        new(code, message, cause);
}

/// <summary>Checks the exact Ollama model tag/name and immutable digest from /api/tags.</summary>
public sealed class HttpOllamaManifestProbe : IOllamaManifestProbe
{
    private const int MaximumResponseBytes = 4 * 1024 * 1024;
    private readonly HttpClient http;
    private readonly Uri baseUri;
    private readonly Uri tagsUri;
    private readonly IOllamaEndpointGuard endpointGuard;

    public HttpOllamaManifestProbe(
        HttpClient http,
        Uri ollamaBaseUri,
        IOllamaEndpointGuard endpointGuard)
    {
        this.http = http ?? throw new ArgumentNullException(nameof(http));
        this.endpointGuard = endpointGuard
            ?? throw new ArgumentNullException(nameof(endpointGuard));
        ArgumentNullException.ThrowIfNull(ollamaBaseUri);
        var loopback = ollamaBaseUri.Host is "127.0.0.1" or "::1"
            || ollamaBaseUri.Host.Equals("localhost", StringComparison.OrdinalIgnoreCase);
        if (!ollamaBaseUri.IsAbsoluteUri || ollamaBaseUri.Scheme != Uri.UriSchemeHttp || !loopback
            || ollamaBaseUri.AbsolutePath != "/" || ollamaBaseUri.Query.Length > 0
            || ollamaBaseUri.Fragment.Length > 0 || ollamaBaseUri.UserInfo.Length > 0)
        {
            throw new ArgumentException("ollama-base-uri-invalid", nameof(ollamaBaseUri));
        }

        baseUri = ollamaBaseUri;
        tagsUri = new Uri(ollamaBaseUri, "/api/tags");
    }

    public async Task<OllamaManifestProbeResult> VerifyExactModelAsync(
        string model,
        string modelDigest,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(model);
        var expectedDigest = NormalizeDigest(modelDigest);
        if (!HchDigest.IsLowerSha256(expectedDigest))
        {
            throw new ArgumentException("model-digest-invalid", nameof(modelDigest));
        }

        try
        {
            await endpointGuard.EnsureTrustedAsync(baseUri, cancellationToken).ConfigureAwait(false);
        }
        catch (OllamaEndpointTrustException error)
        {
            throw new WorkerServiceException(
                error.Code,
                "The local Ollama endpoint is not trusted.",
                error);
        }

        using var request = new HttpRequestMessage(HttpMethod.Get, tagsUri);
        request.Headers.Accept.ParseAdd("application/json");
        HttpResponseMessage response;
        try
        {
            response = await http.SendAsync(
                request,
                HttpCompletionOption.ResponseHeadersRead,
                cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException error) when (!cancellationToken.IsCancellationRequested)
        {
            throw new WorkerServiceException(
                "local-engine-unavailable",
                "The local Ollama engine did not return a trusted response.",
                error);
        }
        catch (HttpRequestException error)
        {
            throw new WorkerServiceException(
                "local-engine-unavailable",
                "The local Ollama engine did not return a trusted response.",
                error);
        }

        using (response)
        {
            if (response.RequestMessage?.RequestUri != tagsUri || !response.IsSuccessStatusCode)
            {
                throw new WorkerServiceException(
                    "local-engine-unavailable",
                    "The local Ollama engine rejected the model probe.");
            }

            var bytes = await ReadBoundedAsync(response.Content, cancellationToken).ConfigureAwait(false);
            try
            {
                using var document = JsonDocument.Parse(bytes);
                if (!document.RootElement.TryGetProperty("models", out var models)
                    || models.ValueKind != JsonValueKind.Array)
                {
                    throw new WorkerServiceException(
                        "model-list-invalid",
                        "Ollama /api/tags did not return a model list.");
                }

                var found = models.EnumerateArray().Any(candidate =>
                {
                    if (candidate.ValueKind != JsonValueKind.Object)
                    {
                        return false;
                    }

                    var name = OptionalString(candidate, "name") ?? OptionalString(candidate, "model");
                    var digest = NormalizeDigest(OptionalString(candidate, "digest") ?? string.Empty);
                    return name == model && digest == expectedDigest;
                });
                if (!found)
                {
                    throw new WorkerServiceException(
                        "model-digest-unavailable",
                        "The exact signed Ollama model and digest are not installed.");
                }

                var observed = OptionalString(document.RootElement, "version");
                if (observed is null
                    && response.Headers.TryGetValues("x-ollama-version", out var versions))
                {
                    observed = versions.FirstOrDefault();
                }
                return new OllamaManifestProbeResult(SanitizeVersion(observed));
            }
            catch (JsonException error)
            {
                throw new WorkerServiceException(
                    "local-engine-invalid-json",
                    "Ollama /api/tags returned invalid JSON.",
                    error);
            }
        }
    }

    private static async Task<byte[]> ReadBoundedAsync(
        HttpContent content,
        CancellationToken cancellationToken)
    {
        if (content.Headers.ContentLength > MaximumResponseBytes)
        {
            throw new WorkerServiceException("response-too-large", "The Ollama response is too large.");
        }

        await using var stream = await content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
        using var output = new MemoryStream();
        var buffer = new byte[32 * 1024];
        while (true)
        {
            var read = await stream.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
            if (read == 0)
            {
                return output.ToArray();
            }

            if (output.Length + read > MaximumResponseBytes)
            {
                throw new WorkerServiceException("response-too-large", "The Ollama response is too large.");
            }

            output.Write(buffer, 0, read);
        }
    }

    private static string? OptionalString(JsonElement value, string name) =>
        value.TryGetProperty(name, out var property) && property.ValueKind == JsonValueKind.String
            ? property.GetString()
            : null;

    private static string NormalizeDigest(string value) =>
        value.StartsWith("sha256:", StringComparison.OrdinalIgnoreCase)
            ? value[7..].ToLowerInvariant()
            : value.ToLowerInvariant();

    private static string? SanitizeVersion(string? value) =>
        !string.IsNullOrWhiteSpace(value) && value.Length <= 160
            && value.All(character => !char.IsControl(character))
            ? value.Trim()
            : null;
}

/// <summary>
/// Stages, verifies and atomically publishes the signed editorial runtime
/// contract. The durable applied state intentionally contains no download or
/// signature expiry field.
/// </summary>
public sealed class ManifestArtifactApplier(
    AtomicFileStore files,
    IManifestArtifactSource artifacts,
    IOllamaManifestProbe ollama,
    TimeProvider? timeProvider = null)
{
    private static readonly IReadOnlyDictionary<string, string> EditorialDestinations =
        new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["policy"] = "runtime/editorial/policy.json",
            ["prompt"] = "runtime/editorial/prompt.md",
            ["editorial-content-schema"] = "runtime/editorial/editorial-content-schema.json",
            ["editorial-source-schema"] = "runtime/editorial/editorial-source-schema.json",
        };

    private readonly TimeProvider clock = timeProvider ?? TimeProvider.System;

    public async Task<ManifestApplyResult> ApplyAsync(
        VerifiedManifestDelivery verified,
        AppliedManifestState? previousApplied,
        ManifestApplyContext context,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(verified);
        ArgumentNullException.ThrowIfNull(context);
        if (context.NodeId.Length == 0 || context.WorkerKeyId.Length == 0)
        {
            throw new ArgumentException("apply-context-invalid", nameof(context));
        }

        var manifest = verified.Manifest;
        ManifestContractValidator.Validate(manifest);
        if (ManifestContentContract.ComputeHash(manifest) != verified.ContentContractHash)
        {
            throw new WorkerServiceException(
                "manifest-content-contract-hash-mismatch",
                "The verified content-contract hash no longer matches the manifest.");
        }

        ValidateVerifiedArtifacts(verified);
        var profile = CreateRuntimeProfile(manifest);
        var capacityPolicyHash = ManifestPolicyValidator.CapacityPolicyHash(manifest.CapacityPolicy);
        var adaptivePolicy = manifest.AdaptiveWorkPolicy
            ?? throw new WorkerServiceException(
                "adaptive-work-policy-missing",
                "The signed adaptive work policy is missing.");
        var adaptivePolicyHash = ManifestPolicyValidator.AdaptiveWorkPolicyHash(adaptivePolicy);
        var metadataOnly = previousApplied is not null
            && previousApplied.ContentContractHash == verified.ContentContractHash;

        var staged = new Dictionary<string, byte[]>(StringComparer.Ordinal);
        var artifactHashes = verified.Artifacts.ToDictionary(
            artifact => artifact.Name,
            artifact => artifact.Sha256,
            StringComparer.Ordinal);
        if (!metadataOnly)
        {
            foreach (var artifact in verified.Artifacts)
            {
                var downloaded = await artifacts.DownloadAsync(artifact, cancellationToken).ConfigureAwait(false);
                ValidateDownload(artifact, downloaded);
                staged.Add(artifact.Name, downloaded.Bytes);
                await files.WriteBytesAsync(
                    Path.Combine("staging", manifest.Hash, artifact.Name),
                    downloaded.Bytes,
                    cancellationToken).ConfigureAwait(false);
            }
        }

        foreach (var required in EditorialDestinations.Keys)
        {
            if (!artifactHashes.ContainsKey(required))
            {
                throw new WorkerServiceException(
                    "artifact-required-missing",
                    $"Required signed artifact {required} is missing.");
            }
        }

        var receiptPath = Path.Combine("receipts", $"{manifest.Hash}.json");
        var targets = verified.Artifacts
            .Select(artifact => Path.Combine("runtime", "artifacts", artifact.Name))
            .Concat(EditorialDestinations.Values)
            .Append(Path.Combine("runtime", "config", "engine.json"))
            .Append("applied-manifest.json")
            .Append(receiptPath)
            .Distinct(StringComparer.Ordinal)
            .ToArray();
        var backup = await BackupAsync(targets, cancellationToken).ConfigureAwait(false);
        var appliedAt = clock.GetUtcNow().ToString("O");
        try
        {
            if (!metadataOnly)
            {
                foreach (var artifact in verified.Artifacts)
                {
                    await files.WriteBytesAsync(
                        Path.Combine("runtime", "artifacts", artifact.Name),
                        staged[artifact.Name],
                        cancellationToken).ConfigureAwait(false);
                }

                foreach (var destination in EditorialDestinations)
                {
                    await files.WriteBytesAsync(
                        destination.Value,
                        staged[destination.Key],
                        cancellationToken).ConfigureAwait(false);
                }
            }

            await files.WriteJsonAsync(
                Path.Combine("runtime", "config", "engine.json"),
                EngineConfiguration(
                    manifest,
                    verified.ContentContractHash,
                    capacityPolicyHash,
                    adaptivePolicyHash),
                cancellationToken).ConfigureAwait(false);
            var observed = await ollama.VerifyExactModelAsync(
                manifest.Engine.Model,
                manifest.Engine.ModelDigest,
                cancellationToken).ConfigureAwait(false);
            await VerifyInstalledArtifactsAsync(verified, cancellationToken).ConfigureAwait(false);

            var appliedState = CreateAppliedState(
                verified,
                context,
                profile,
                capacityPolicyHash,
                adaptivePolicyHash,
                artifactHashes,
                appliedAt);
            await files.WriteJsonAsync(
                "applied-manifest.json",
                appliedState,
                cancellationToken).ConfigureAwait(false);

            var checks = new AttestationChecksContract
            {
                ConfigurationApplied = true,
                ArtifactsVerified = true,
                ModelAvailable = true,
                GeneratorReachable = true,
                SelfTestPassed = true,
            };
            var receiptCore = new SortedDictionary<string, object?>(StringComparer.Ordinal)
            {
                ["previousManifestHash"] = previousApplied?.ManifestHash,
                ["targetManifestHash"] = manifest.Hash,
                ["artifactHashes"] = artifactHashes,
                ["result"] = previousApplied?.ManifestHash == manifest.Hash
                    ? "no-change"
                    : "applied",
                ["rollbackPerformed"] = false,
                ["appliedAt"] = appliedAt,
            };
            var receiptHash = HchDigest.Sha256Hex(JcsCanonicalizer.Serialize(receiptCore));
            var journal = CreateJournal(
                verified,
                context,
                profile,
                capacityPolicyHash,
                adaptivePolicyHash,
                artifactHashes,
                appliedAt,
                receiptHash,
                receiptCore,
                checks,
                observed.ObservedEngineVersion,
                metadataOnly);
            var localAuditHash = HchDigest.Sha256Hex(JcsCanonicalizer.Serialize(journal));
            var receipt = new UpdateReceiptContract
            {
                PreviousManifestHash = previousApplied?.ManifestHash,
                TargetManifestHash = manifest.Hash,
                ArtifactHashes = artifactHashes,
                Result = (string)receiptCore["result"]!,
                RollbackPerformed = false,
                AppliedAt = appliedAt,
                ReceiptHash = receiptHash,
                LocalAuditHash = localAuditHash,
            };
            await files.WriteJsonAsync(
                receiptPath,
                new
                {
                    schemaVersion = 1,
                    journal,
                    localAuditHash,
                    updateReceipt = receipt,
                },
                cancellationToken).ConfigureAwait(false);
            return new ManifestApplyResult(appliedState, profile, checks, receipt, metadataOnly);
        }
        catch
        {
            await RestoreAsync(backup, CancellationToken.None).ConfigureAwait(false);
            throw;
        }
    }

    public async Task VerifyInstalledArtifactsAsync(
        VerifiedManifestDelivery verified,
        CancellationToken cancellationToken)
    {
        foreach (var artifact in verified.Artifacts)
        {
            var path = files.Resolve(Path.Combine("runtime", "artifacts", artifact.Name));
            if (!File.Exists(path))
            {
                throw new WorkerServiceException(
                    "installed-artifact-invalid",
                    $"Installed artifact {artifact.Name} is missing.");
            }

            var info = new FileInfo(path);
            if (info.Length != artifact.Bytes || (info.Attributes & FileAttributes.ReparsePoint) != 0)
            {
                throw new WorkerServiceException(
                    "installed-artifact-invalid",
                    $"Installed artifact {artifact.Name} has invalid metadata.");
            }

            var bytes = await File.ReadAllBytesAsync(path, cancellationToken).ConfigureAwait(false);
            if (HchDigest.Sha256Hex(bytes) != artifact.Sha256)
            {
                throw new WorkerServiceException(
                    "installed-artifact-invalid",
                    $"Installed artifact {artifact.Name} does not match its signed digest.");
            }
        }
    }

    private static void ValidateDownload(
        ManifestArtifactContract artifact,
        ManifestArtifactDownload downloaded)
    {
        if (downloaded.Bytes.LongLength != artifact.Bytes)
        {
            throw new WorkerServiceException(
                "artifact-size-mismatch",
                $"Artifact {artifact.Name} has an unexpected byte count.");
        }

        if (HchDigest.Sha256Hex(downloaded.Bytes) != artifact.Sha256)
        {
            throw new WorkerServiceException(
                "artifact-hash-mismatch",
                $"Artifact {artifact.Name} failed SHA-256 verification.");
        }

        var expected = NormalizeMediaType(artifact.MediaType);
        var received = NormalizeMediaType(downloaded.MediaType);
        if (!expected.Equals(received, StringComparison.OrdinalIgnoreCase))
        {
            throw new WorkerServiceException(
                "artifact-media-type-mismatch",
                $"Artifact {artifact.Name} has an unexpected media type.");
        }
    }

    private static void ValidateVerifiedArtifacts(VerifiedManifestDelivery verified)
    {
        if (verified.Manifest.Artifacts.ValueKind != JsonValueKind.Array
            || verified.Manifest.Artifacts.GetArrayLength() != verified.Artifacts.Count
            || verified.Artifacts.Select(artifact => artifact.Name)
                .Distinct(StringComparer.Ordinal).Count() != verified.Artifacts.Count)
        {
            throw new WorkerServiceException(
                "manifest-artifact-invalid",
                "The verified artifact view is inconsistent with the signed manifest.");
        }

        var declared = verified.Manifest.Artifacts.EnumerateArray().ToArray();
        foreach (var artifact in verified.Artifacts)
        {
            var safeName = artifact.Name.Length is >= 1 and <= 80
                && char.IsAsciiLetterOrDigit(artifact.Name[0])
                && artifact.Name.All(character =>
                    character is >= 'a' and <= 'z' || char.IsAsciiDigit(character) || character == '-');
            if (!safeName || artifact.Bytes < 1 || !HchDigest.IsLowerSha256(artifact.Sha256)
                || artifact.AuthorizationClass != "release")
            {
                throw new WorkerServiceException(
                    "manifest-artifact-invalid",
                    "The verified artifact view contains an unsafe declaration.");
            }

            var raw = declared.SingleOrDefault(candidate =>
                candidate.ValueKind == JsonValueKind.Object
                && candidate.TryGetProperty("name", out var name)
                && name.ValueKind == JsonValueKind.String
                && name.GetString() == artifact.Name);
            if (raw.ValueKind == JsonValueKind.Undefined
                || !raw.TryGetProperty("mediaType", out var mediaType)
                || mediaType.GetString() != artifact.MediaType
                || !raw.TryGetProperty("bytes", out var bytes)
                || !bytes.TryGetInt64(out var byteCount) || byteCount != artifact.Bytes
                || !raw.TryGetProperty("sha256", out var sha256)
                || sha256.GetString() != artifact.Sha256
                || !raw.TryGetProperty("url", out var url) || url.GetString() != artifact.Url
                || !raw.TryGetProperty("authorizationClass", out var authorization)
                || authorization.GetString() != artifact.AuthorizationClass)
            {
                throw new WorkerServiceException(
                    "manifest-artifact-invalid",
                    "The verified artifact view differs from the signed manifest.");
            }
        }
    }

    private static string NormalizeMediaType(string value)
    {
        try
        {
            return MediaTypeHeaderValue.Parse(value).MediaType?.Trim().ToLowerInvariant() ?? string.Empty;
        }
        catch (FormatException)
        {
            return string.Empty;
        }
    }

    private static WorkerRuntimeProfile CreateRuntimeProfile(ManifestPayload manifest)
    {
        var generation = manifest.Generation;
        var policyId = RequiredEditorialExtension(manifest.Editorial, "policyId");
        var policyVersion = RequiredEditorialExtension(manifest.Editorial, "policyVersion");
        var core = new SortedDictionary<string, object?>(StringComparer.Ordinal)
        {
            ["contextWindow"] = RequiredInt(generation, "contextWindow"),
            ["engineAdapter"] = manifest.Engine.Adapter,
            ["engineAdapterVersion"] = manifest.Engine.AdapterVersion,
            ["manifestHash"] = manifest.Hash,
            ["manifestSequence"] = manifest.Sequence,
            ["maxOutputTokens"] = RequiredInt(generation, "maxOutputTokens"),
            ["model"] = manifest.Engine.Model,
            ["modelDigest"] = NormalizeDigest(manifest.Engine.ModelDigest),
            ["pipelineVersion"] = manifest.Editorial.PipelineVersion,
            ["policyHash"] = manifest.Editorial.PolicyHash,
            ["policyId"] = policyId,
            ["policyVersion"] = policyVersion,
            ["promptConfigHash"] = manifest.Editorial.PromptConfigHash,
            ["protocol"] = manifest.Engine.Protocol,
            ["provider"] = manifest.Engine.Provider,
            ["temperature"] = RequiredDouble(generation, "temperature"),
        };
        var profile = new WorkerRuntimeProfile
        {
            Provider = manifest.Engine.Provider,
            EngineAdapter = manifest.Engine.Adapter,
            EngineAdapterVersion = manifest.Engine.AdapterVersion,
            Model = manifest.Engine.Model,
            ModelDigest = NormalizeDigest(manifest.Engine.ModelDigest),
            Protocol = manifest.Engine.Protocol,
            Temperature = (double)core["temperature"]!,
            ContextWindow = (int)core["contextWindow"]!,
            MaxOutputTokens = (int)core["maxOutputTokens"]!,
            PolicyId = policyId,
            PolicyVersion = policyVersion,
            PolicyHash = manifest.Editorial.PolicyHash,
            PromptConfigHash = manifest.Editorial.PromptConfigHash,
            PipelineVersion = manifest.Editorial.PipelineVersion,
            ManifestSequence = manifest.Sequence,
            ManifestHash = manifest.Hash,
            RuntimeProfileHash = HchDigest.Sha256Hex(JcsCanonicalizer.Serialize(core)),
        };
        AssignmentContractValidator.Validate(profile);
        return profile;
    }

    private static AppliedManifestState CreateAppliedState(
        VerifiedManifestDelivery verified,
        ManifestApplyContext context,
        WorkerRuntimeProfile profile,
        string capacityPolicyHash,
        string adaptivePolicyHash,
        IReadOnlyDictionary<string, string> artifactHashes,
        string appliedAt)
    {
        var manifest = verified.Manifest;
        return new AppliedManifestState
        {
            SchemaVersion = 1,
            ManifestSequence = manifest.Sequence,
            ManifestHash = manifest.Hash,
            ContentContractHash = verified.ContentContractHash,
            PolicyHash = manifest.Editorial.PolicyHash,
            PromptConfigHash = manifest.Editorial.PromptConfigHash,
            Provider = manifest.Engine.Provider,
            EngineAdapter = manifest.Engine.Adapter,
            EngineAdapterVersion = manifest.Engine.AdapterVersion,
            Model = manifest.Engine.Model,
            ModelDigest = NormalizeDigest(manifest.Engine.ModelDigest),
            Protocol = manifest.Engine.Protocol,
            RuntimeProfileHash = profile.RuntimeProfileHash,
            RuntimeProfile = profile,
            AdditionalProperties = new Dictionary<string, JsonElement>(StringComparer.Ordinal)
            {
                ["previousManifestHash"] = JsonSerializer.SerializeToElement(manifest.PreviousManifestHash),
                ["releaseId"] = JsonSerializer.SerializeToElement(manifest.ReleaseId),
                ["workerRuntimeVersion"] = JsonSerializer.SerializeToElement(context.WorkerRuntimeVersion),
                ["pipelineVersion"] = JsonSerializer.SerializeToElement(manifest.Editorial.PipelineVersion),
                ["capacityPolicyHash"] = JsonSerializer.SerializeToElement(capacityPolicyHash),
                ["capacityPolicy"] = manifest.CapacityPolicy.Clone(),
                ["adaptiveWorkPolicyHash"] = JsonSerializer.SerializeToElement(adaptivePolicyHash),
                ["adaptiveWorkPolicy"] = manifest.AdaptiveWorkPolicy!.Value.Clone(),
                ["artifacts"] = manifest.Artifacts.Clone(),
                ["artifactHashes"] = JsonSerializer.SerializeToElement(artifactHashes),
                ["appliedAt"] = JsonSerializer.SerializeToElement(appliedAt),
            },
        };
    }

    private static object EngineConfiguration(
        ManifestPayload manifest,
        string contentContractHash,
        string capacityPolicyHash,
        string adaptivePolicyHash) => new
        {
            schemaVersion = 1,
            provider = manifest.Engine.Provider,
            adapter = manifest.Engine.Adapter,
            adapterVersion = manifest.Engine.AdapterVersion,
            model = manifest.Engine.Model,
            modelDigest = NormalizeDigest(manifest.Engine.ModelDigest),
            protocol = manifest.Engine.Protocol,
            generation = manifest.Generation,
            capacityPolicy = manifest.CapacityPolicy,
            capacityPolicyHash,
            adaptiveWorkPolicy = manifest.AdaptiveWorkPolicy,
            adaptiveWorkPolicyHash = adaptivePolicyHash,
            contentContractHash,
            sourceManifestHash = manifest.Hash,
        };

    private static SortedDictionary<string, object?> CreateJournal(
        VerifiedManifestDelivery verified,
        ManifestApplyContext context,
        WorkerRuntimeProfile profile,
        string capacityPolicyHash,
        string adaptivePolicyHash,
        IReadOnlyDictionary<string, string> artifactHashes,
        string appliedAt,
        string receiptHash,
        SortedDictionary<string, object?> receiptCore,
        AttestationChecksContract checks,
        string? observedEngineVersion,
        bool metadataOnly)
    {
        var manifest = verified.Manifest;
        return new SortedDictionary<string, object?>(StringComparer.Ordinal)
        {
            ["schemaVersion"] = 1,
            ["nodeId"] = context.NodeId,
            ["keyId"] = context.WorkerKeyId,
            ["manifestSequence"] = manifest.Sequence,
            ["manifestHash"] = manifest.Hash,
            ["contentContractHash"] = verified.ContentContractHash,
            ["releaseId"] = manifest.ReleaseId,
            ["workerRuntimeVersion"] = context.WorkerRuntimeVersion,
            ["receiptHash"] = receiptHash,
            ["receipt"] = receiptCore,
            ["actionResults"] = verified.Actions.Select(action => new
            {
                type = action.Type,
                authorizationClass = action.AuthorizationClass,
                result = metadataOnly ? "unchanged-compatible" : ActionResult(action.Type),
            }).ToArray(),
            ["artifacts"] = verified.Artifacts.Select(artifact => new
            {
                name = artifact.Name,
                bytes = artifact.Bytes,
                sha256 = artifact.Sha256,
            }).ToArray(),
            ["artifactHashes"] = artifactHashes,
            ["checks"] = checks,
            ["engine"] = new
            {
                provider = manifest.Engine.Provider,
                adapter = manifest.Engine.Adapter,
                adapterVersion = manifest.Engine.AdapterVersion,
                observedEngineVersion,
                model = manifest.Engine.Model,
                modelDigest = NormalizeDigest(manifest.Engine.ModelDigest),
                protocol = manifest.Engine.Protocol,
            },
            ["runtimeProfile"] = profile,
            ["capacityPolicyHash"] = capacityPolicyHash,
            ["adaptiveWorkPolicyHash"] = adaptivePolicyHash,
            ["appliedAt"] = appliedAt,
        };
    }

    private async Task<IReadOnlyDictionary<string, byte[]?>> BackupAsync(
        IEnumerable<string> targets,
        CancellationToken cancellationToken)
    {
        var backup = new Dictionary<string, byte[]?>(StringComparer.Ordinal);
        foreach (var target in targets)
        {
            var path = files.Resolve(target);
            if (!File.Exists(path))
            {
                backup[target] = null;
                continue;
            }

            if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
            {
                throw new WorkerServiceException(
                    "state-reparse-point-refused",
                    "A runtime target is a reparse point.");
            }

            backup[target] = await File.ReadAllBytesAsync(path, cancellationToken).ConfigureAwait(false);
        }

        return backup;
    }

    private async Task RestoreAsync(
        IReadOnlyDictionary<string, byte[]?> backup,
        CancellationToken cancellationToken)
    {
        foreach (var entry in backup)
        {
            if (entry.Value is null)
            {
                var path = files.Resolve(entry.Key);
                if (File.Exists(path) && (File.GetAttributes(path) & FileAttributes.ReparsePoint) == 0)
                {
                    File.Delete(path);
                }
            }
            else
            {
                await files.WriteBytesAsync(entry.Key, entry.Value, cancellationToken).ConfigureAwait(false);
            }
        }
    }

    private static string RequiredEditorialExtension(EditorialManifest editorial, string name)
    {
        if (editorial.AdditionalProperties is null
            || !editorial.AdditionalProperties.TryGetValue(name, out var value)
            || value.ValueKind != JsonValueKind.String
            || string.IsNullOrWhiteSpace(value.GetString()))
        {
            throw new WorkerServiceException(
                "manifest-editorial-invalid",
                $"The signed editorial {name} is missing.");
        }

        return value.GetString()!;
    }

    private static int RequiredInt(JsonElement value, string name)
    {
        if (!value.TryGetProperty(name, out var property) || !property.TryGetInt32(out var result))
        {
            throw new WorkerServiceException("manifest-generation-invalid", $"{name} is invalid.");
        }

        return result;
    }

    private static double RequiredDouble(JsonElement value, string name)
    {
        if (!value.TryGetProperty(name, out var property) || !property.TryGetDouble(out var result))
        {
            throw new WorkerServiceException("manifest-generation-invalid", $"{name} is invalid.");
        }

        return result;
    }

    private static string NormalizeDigest(string value) =>
        value.StartsWith("sha256:", StringComparison.OrdinalIgnoreCase)
            ? value[7..].ToLowerInvariant()
            : value.ToLowerInvariant();

    private static string ActionResult(string action) => action switch
    {
        "verify-artifact" => "verified",
        "configure-engine" => "applied",
        "pull-model-by-digest" => "verified-present",
        "apply-editorial-policy" => "applied",
        "self-test" => "passed",
        _ => throw new WorkerServiceException("manifest-action-refused", "The action is not allowlisted."),
    };
}
