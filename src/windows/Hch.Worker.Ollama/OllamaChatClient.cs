using System.Diagnostics;
using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Hch.Worker.Core;

namespace Hch.Worker.Ollama;

public sealed class OllamaChatClient
{
    public const int DefaultMaximumResponseBytes = 2 * 1024 * 1024;
    public const int MaximumNdjsonLineBytes = 512 * 1024;

    private readonly HttpClient _http;
    private readonly Uri _baseUri;
    private readonly IOllamaEndpointGuard _endpointGuard;
    private readonly TimeProvider _timeProvider;
    private readonly int _maximumResponseBytes;

    public OllamaChatClient(
        HttpClient httpClient,
        Uri baseUri,
        IOllamaEndpointGuard endpointGuard,
        TimeProvider? timeProvider = null,
        int maximumResponseBytes = DefaultMaximumResponseBytes)
    {
        ArgumentNullException.ThrowIfNull(httpClient);
        _http = httpClient;
        _baseUri = ValidateBaseUri(baseUri);
        _endpointGuard = endpointGuard ?? throw new ArgumentNullException(nameof(endpointGuard));
        _timeProvider = timeProvider ?? TimeProvider.System;
        if (maximumResponseBytes is < 1 or > 16 * 1024 * 1024)
        {
            throw new ArgumentOutOfRangeException(nameof(maximumResponseBytes));
        }

        _maximumResponseBytes = maximumResponseBytes;
    }

    public async Task<OllamaGenerationResult> GenerateJsonAsync(
        OllamaGenerationPlan generationPlan,
        string systemPrompt,
        JsonElement userInput,
        int attempt,
        Func<OllamaProgress, ValueTask>? progress = null,
        CancellationToken cancellationToken = default)
    {
        generationPlan.Validate();
        if (attempt is < 1 or > 8)
        {
            throw new ArgumentOutOfRangeException(nameof(attempt));
        }

        ArgumentException.ThrowIfNullOrWhiteSpace(systemPrompt);
        try
        {
            await _endpointGuard.EnsureTrustedAsync(_baseUri, cancellationToken).ConfigureAwait(false);
        }
        catch (OllamaEndpointTrustException error)
        {
            throw new WorkerJobException(
                error.Code,
                "The local generator endpoint is not trusted.",
                error);
        }

        var requestBody = JsonSerializer.SerializeToUtf8Bytes(new
        {
            model = generationPlan.Model,
            stream = true,
            format = "json",
            options = new
            {
                temperature = generationPlan.Temperature,
                num_ctx = generationPlan.ContextWindow,
                num_predict = generationPlan.MaximumOutputTokens,
                num_thread = generationPlan.NumberOfThreads,
            },
            messages = new object[]
            {
                new { role = "system", content = systemPrompt + "\n\nRetorne exclusivamente o objeto JSON solicitado, sem Markdown ou comentários." },
                new { role = "user", content = userInput.GetRawText() },
            },
        }, OllamaJson.Options);

        try
        {
            using var request = new HttpRequestMessage(HttpMethod.Post, new Uri(_baseUri, "/api/chat"))
            {
                Content = new ByteArrayContent(requestBody),
            };
            request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/x-ndjson"));
            request.Headers.AcceptEncoding.Add(new StringWithQualityHeaderValue("identity"));
            request.Content.Headers.ContentType = new MediaTypeHeaderValue("application/json")
            {
                CharSet = "utf-8",
            };

            var stopwatch = Stopwatch.StartNew();
            using var response = await _http.SendAsync(
                request,
                HttpCompletionOption.ResponseHeadersRead,
                cancellationToken).ConfigureAwait(false);
            if (response.StatusCode is < HttpStatusCode.OK or >= HttpStatusCode.MultipleChoices)
            {
                throw new WorkerJobException(
                    $"local-generator-http-{(int)response.StatusCode}",
                    "The local generator rejected the request.");
            }

            await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
            using var reader = new StreamReader(
                stream,
                new UTF8Encoding(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true),
                detectEncodingFromByteOrderMarks: false,
                bufferSize: 16 * 1024,
                leaveOpen: false);

            var content = new StringBuilder();
            long receivedBytes = 0;
            long contentBytes = 0;
            long sequence = 0;
            string? doneReason = null;
            var terminalSeen = false;
            var firstContent = true;

            while (true)
            {
                string? line;
                try
                {
                    var timeout = TimeSpan.FromSeconds(
                        firstContent ? generationPlan.FirstProgressGraceSeconds : generationPlan.StallAfterSeconds);
                    line = await reader.ReadLineAsync(cancellationToken).AsTask()
                        .WaitAsync(timeout, _timeProvider, cancellationToken).ConfigureAwait(false);
                }
                catch (TimeoutException error)
                {
                    throw new WorkerJobException(
                        firstContent ? "generator-first-progress-timeout" : "generator-stalled",
                        "The local generator stopped demonstrating material progress.",
                        error);
                }
                catch (DecoderFallbackException error)
                {
                    throw new WorkerJobException(
                        "local-generator-response-invalid",
                        "Ollama returned invalid UTF-8.",
                        error);
                }

                if (line is null)
                {
                    break;
                }

                var lineBytes = Encoding.UTF8.GetByteCount(line) + 1L;
                if (lineBytes > MaximumNdjsonLineBytes || receivedBytes + lineBytes > _maximumResponseBytes)
                {
                    throw new WorkerJobException(
                        "local-generator-response-too-large",
                        "Ollama exceeded the bounded response size.");
                }

                receivedBytes += lineBytes;
                if (string.IsNullOrWhiteSpace(line))
                {
                    continue;
                }

                if (terminalSeen)
                {
                    throw new WorkerJobException(
                        "local-generator-response-invalid",
                        "Ollama returned data after the terminal streaming event.");
                }

                using var chunkDocument = ParseChunk(line);
                var root = chunkDocument.RootElement;
                if (root.TryGetProperty("error", out var errorValue) &&
                    errorValue.ValueKind == JsonValueKind.String &&
                    !string.IsNullOrWhiteSpace(errorValue.GetString()))
                {
                    throw new WorkerJobException("local-generator-error", "Ollama returned an inference error.");
                }

                if (root.TryGetProperty("message", out var message) &&
                    message.ValueKind == JsonValueKind.Object &&
                    message.TryGetProperty("content", out var fragmentValue) &&
                    fragmentValue.ValueKind == JsonValueKind.String)
                {
                    var fragment = fragmentValue.GetString() ?? string.Empty;
                    if (fragment.Length > 0)
                    {
                        firstContent = false;
                        content.Append(fragment);
                        contentBytes += Encoding.UTF8.GetByteCount(fragment);
                        sequence++;
                        if (progress is not null)
                        {
                            await progress(new OllamaProgress(
                                "responding",
                                attempt,
                                sequence,
                                contentBytes,
                                _timeProvider.GetUtcNow(),
                                EstimateGenerationPercent(
                                    sequence,
                                    contentBytes,
                                    generationPlan.MaximumOutputTokens))).ConfigureAwait(false);
                        }
                    }
                }

                if (root.TryGetProperty("done", out var done) && done.ValueKind == JsonValueKind.True)
                {
                    terminalSeen = true;
                    doneReason = root.TryGetProperty("done_reason", out var reason) && reason.ValueKind == JsonValueKind.String
                        ? reason.GetString()
                        : null;
                }
            }

            if (!terminalSeen)
            {
                throw new WorkerJobException(
                    "generator-output-terminal-missing",
                    "Ollama ended the stream without a terminal event.");
            }

            if (doneReason == "length")
            {
                throw new WorkerJobException(
                    "generator-output-budget-exhausted",
                    "Ollama reached the signed output budget before completing the response.");
            }

            if (!string.Equals(doneReason, "stop", StringComparison.Ordinal))
            {
                throw new WorkerJobException(
                    string.IsNullOrWhiteSpace(doneReason)
                        ? "generator-output-terminal-reason-missing"
                        : "generator-output-terminal-reason-unknown",
                    "Ollama returned an unsupported terminal reason.");
            }

            if (contentBytes == 0)
            {
                throw new WorkerJobException("generator-output-empty", "Ollama completed without content.");
            }

            if (progress is not null)
            {
                await progress(new OllamaProgress(
                    "finalizing",
                    attempt,
                    sequence + 1,
                    contentBytes,
                    _timeProvider.GetUtcNow(),
                    Percent: 100d)).ConfigureAwait(false);
            }

            JsonDocument candidate;
            try
            {
                candidate = JsonDocument.Parse(content.ToString(), new JsonDocumentOptions
                {
                    AllowTrailingCommas = false,
                    CommentHandling = JsonCommentHandling.Disallow,
                    MaxDepth = 64,
                });
            }
            catch (JsonException error)
            {
                throw new WorkerJobException(
                    "generator-json-invalid",
                    "Ollama did not return one valid JSON object.",
                    error);
            }

            using (candidate)
            {
                if (candidate.RootElement.ValueKind != JsonValueKind.Object)
                {
                    throw new WorkerJobException(
                        "generator-output-invalid",
                        "Ollama returned JSON that is not an object.");
                }

                stopwatch.Stop();
                return new OllamaGenerationResult(
                    candidate.RootElement.Clone(),
                    generationPlan.Model,
                    contentBytes,
                    doneReason!,
                    stopwatch.Elapsed);
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(requestBody);
        }
    }

    public async Task<OllamaModelStatus> GetModelStatusAsync(
        string model,
        CancellationToken cancellationToken = default)
    {
        try
        {
            await _endpointGuard.EnsureTrustedAsync(_baseUri, cancellationToken).ConfigureAwait(false);
        }
        catch (OllamaEndpointTrustException error)
        {
            return new(false, model, null, null, error.Code);
        }

        using var request = new HttpRequestMessage(HttpMethod.Get, new Uri(_baseUri, "/api/tags"));
        try
        {
            using var response = await _http.SendAsync(request, cancellationToken).ConfigureAwait(false);
            if (!response.IsSuccessStatusCode)
            {
                return new(false, model, null, null, $"ollama-tags-http-{(int)response.StatusCode}");
            }

            await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
            using var document = await JsonDocument.ParseAsync(stream, cancellationToken: cancellationToken)
                .ConfigureAwait(false);
            if (!document.RootElement.TryGetProperty("models", out var models) ||
                models.ValueKind != JsonValueKind.Array)
            {
                return new(false, model, null, null, "ollama-tags-invalid");
            }

            foreach (var item in models.EnumerateArray())
            {
                var name = item.TryGetProperty("name", out var nameValue) ? nameValue.GetString() : null;
                if (!string.Equals(name, model, StringComparison.Ordinal))
                {
                    continue;
                }

                var digest = item.TryGetProperty("digest", out var digestValue) ? digestValue.GetString() : null;
                long? size = item.TryGetProperty("size", out var sizeValue) && sizeValue.TryGetInt64(out var sizeNumber)
                    ? sizeNumber
                    : null;
                return new(true, model, digest, size, null);
            }

            return new(false, model, null, null, "ollama-model-not-installed");
        }
        catch (HttpRequestException)
        {
            return new(false, model, null, null, "ollama-unavailable");
        }
    }

    private static JsonDocument ParseChunk(string line)
    {
        try
        {
            return JsonDocument.Parse(line, new JsonDocumentOptions
            {
                AllowTrailingCommas = false,
                CommentHandling = JsonCommentHandling.Disallow,
                MaxDepth = 32,
            });
        }
        catch (JsonException error)
        {
            throw new WorkerJobException(
                "local-generator-response-invalid",
                "Ollama returned an invalid NDJSON event.",
                error);
        }
    }

    private static double EstimateGenerationPercent(
        long sequence,
        long contentBytes,
        int maximumOutputTokens)
    {
        // Ollama reports the exact eval count only in the terminal event. Until
        // then the UI presents a monotonic estimate against the signed output
        // budget, while sequence/contentBytes remain the authoritative heartbeat.
        var estimatedTokens = Math.Max(sequence, contentBytes / 4d);
        return Math.Clamp(5d + estimatedTokens * 90d / maximumOutputTokens, 5d, 95d);
    }

    private static Uri ValidateBaseUri(Uri value)
    {
        ArgumentNullException.ThrowIfNull(value);
        if (!value.IsAbsoluteUri ||
            value.Scheme != Uri.UriSchemeHttp ||
            value.UserInfo.Length > 0 ||
            !string.IsNullOrEmpty(value.Query) ||
            !string.IsNullOrEmpty(value.Fragment) ||
            value.AbsolutePath != "/" ||
            value.HostNameType is UriHostNameType.Unknown or UriHostNameType.Dns &&
                !value.Host.Equals("localhost", StringComparison.OrdinalIgnoreCase) ||
            value.HostNameType == UriHostNameType.IPv4 && value.Host != "127.0.0.1" ||
            value.HostNameType == UriHostNameType.IPv6 && value.Host != "::1")
        {
            throw new WorkerJobException(
                "local-generator-url-refused",
                "Ollama must use an explicit loopback HTTP base URL.");
        }

        return value;
    }
}
