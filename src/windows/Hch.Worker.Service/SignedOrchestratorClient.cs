using System.Diagnostics;
using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.RegularExpressions;
using Hch.Worker.Protocol;

namespace Hch.Worker.Service;

public interface IOrchestratorClient
{
    Task<ClaimResponse> ClaimAsync(
        int requestedCapacity,
        CancellationToken cancellationToken,
        string? requestId = null,
        bool acceptExpiredAssignmentsForRecovery = false);

    Task<NodeHeartbeatResponse> HeartbeatNodeAsync(int requestedCapacity, CancellationToken cancellationToken);

    Task<AssignmentHeartbeatResponse> HeartbeatAssignmentAsync(
        WorkerAssignment assignment,
        AssignmentProgress progress,
        CancellationToken cancellationToken);

    Task<CompleteAssignmentResponse> CompleteAsync(
        WorkerAssignment assignment,
        object draft,
        string requestId,
        CancellationToken cancellationToken);

    Task<FailAssignmentResponse> FailAsync(
        WorkerAssignment assignment,
        string errorCode,
        string requestId,
        CancellationToken cancellationToken);
}

public interface IRequestIdentifierSource
{
    string NewRequestId();

    string NewClientNonce();
}

public sealed class CryptographicRequestIdentifierSource : IRequestIdentifierSource
{
    public string NewRequestId() => Guid.NewGuid().ToString("D");

    public string NewClientNonce() => $"client-{Guid.NewGuid():D}-{Guid.NewGuid():D}";
}

/// <summary>HCH v2 signed control-plane client with bounded, no-redirect HTTP.</summary>
public sealed partial class SignedOrchestratorClient : IOrchestratorClient
{
    public const string JsonContentType = "application/json";
    public const int MaximumJsonResponseBytes = 4 * 1024 * 1024;
    private const string ChallengePath = "/api/editorial/orchestrator/challenge";

    private readonly HttpClient http;
    private readonly Uri baseUri;
    private readonly string nodeId;
    private readonly string keyId;
    private readonly IEd25519SignatureProvider signatureProvider;
    private readonly IRequestIdentifierSource identifiers;
    private readonly TimeProvider timeProvider;
    private readonly int requestRetries;

    public SignedOrchestratorClient(
        HttpClient http,
        Uri baseUri,
        string nodeId,
        string keyId,
        IEd25519SignatureProvider signatureProvider,
        TimeProvider? timeProvider = null,
        IRequestIdentifierSource? identifiers = null,
        int requestRetries = 1)
    {
        this.http = http ?? throw new ArgumentNullException(nameof(http));
        this.baseUri = ValidateBaseUri(baseUri);
        this.nodeId = RequiredIdentifier(nodeId, nameof(nodeId), 128);
        this.keyId = RequiredIdentifier(keyId, nameof(keyId), 256);
        this.signatureProvider = signatureProvider ?? throw new ArgumentNullException(nameof(signatureProvider));
        this.timeProvider = timeProvider ?? TimeProvider.System;
        this.identifiers = identifiers ?? new CryptographicRequestIdentifierSource();
        if (requestRetries is < 0 or > 5)
        {
            throw new ArgumentOutOfRangeException(nameof(requestRetries));
        }

        this.requestRetries = requestRetries;
    }

    public async Task<ClaimResponse> ClaimAsync(
        int requestedCapacity,
        CancellationToken cancellationToken,
        string? requestId = null,
        bool acceptExpiredAssignmentsForRecovery = false)
    {
        ValidateCapacity(requestedCapacity, allowZero: false);
        requestId = requestId is null ? identifiers.NewRequestId() : RequiredRequestId(requestId);
        var result = await PostSignedAsync<ClaimRequest, ClaimResponse>(
            "/api/editorial/orchestrator/claim",
            "claim",
            new ClaimRequest
            {
                NodeId = nodeId,
                WorkerKeyId = keyId,
                RequestedCapacity = requestedCapacity,
            },
            requestId,
            requestRetries,
            cancellationToken).ConfigureAwait(false);
        OrchestratorContractValidator.Validate(
            result.Value,
            requestId,
            nodeId,
            requestedCapacity,
            timeProvider.GetUtcNow(),
            acceptExpiredAssignmentsForRecovery);
        return result.Value;
    }

    public async Task<NodeHeartbeatResponse> HeartbeatNodeAsync(
        int requestedCapacity,
        CancellationToken cancellationToken)
    {
        ValidateCapacity(requestedCapacity, allowZero: true);
        var requestId = identifiers.NewRequestId();
        var result = await PostSignedAsync<NodeHeartbeatRequest, NodeHeartbeatResponse>(
            "/api/editorial/orchestrator/nodes/heartbeat",
            "node-heartbeat",
            new NodeHeartbeatRequest
            {
                NodeId = nodeId,
                WorkerKeyId = keyId,
                RequestedCapacity = requestedCapacity,
            },
            requestId,
            retries: 0,
            cancellationToken).ConfigureAwait(false);
        OrchestratorContractValidator.Validate(result.Value, requestId, nodeId, requestedCapacity);
        return result.Value;
    }

    public async Task<AssignmentHeartbeatResponse> HeartbeatAssignmentAsync(
        WorkerAssignment assignment,
        AssignmentProgress progress,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(assignment);
        AssignmentContractValidator.Validate(progress);
        var request = new AssignmentHeartbeatRequest
        {
            AssignmentId = assignment.AssignmentId,
            NodeId = nodeId,
            WorkerKeyId = keyId,
            LeaseToken = assignment.LeaseToken,
            GenerationPlanHash = assignment.GenerationPlanHash,
            Progress = progress,
        };
        AssignmentContractValidator.Validate(request);
        var result = await PostSignedAsync<AssignmentHeartbeatRequest, AssignmentHeartbeatResponse>(
            AssignmentPath(assignment.AssignmentId, "heartbeat"),
            "heartbeat",
            request,
            identifiers.NewRequestId(),
            retries: 0,
            cancellationToken).ConfigureAwait(false);
        AssignmentContractValidator.Validate(result.Value, assignment);
        return result.Value;
    }

    public async Task<CompleteAssignmentResponse> CompleteAsync(
        WorkerAssignment assignment,
        object draft,
        string requestId,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(assignment);
        ArgumentNullException.ThrowIfNull(draft);
        var profile = assignment.RuntimeProfile;
        var result = await PostSignedAsync<CompleteAssignmentRequest, CompleteAssignmentResponse>(
            AssignmentPath(assignment.AssignmentId, "complete"),
            "complete",
            new CompleteAssignmentRequest
            {
                AssignmentId = assignment.AssignmentId,
                NodeId = nodeId,
                WorkerKeyId = keyId,
                LeaseToken = assignment.LeaseToken,
                GenerationPlanHash = assignment.GenerationPlanHash,
                ManifestSequence = profile.ManifestSequence,
                ManifestHash = profile.ManifestHash,
                PolicyHash = profile.PolicyHash,
                RuntimeProfileHash = profile.RuntimeProfileHash,
                InputSnapshotHash = assignment.InputSnapshotHash,
                Draft = draft,
            },
            RequiredRequestId(requestId),
            requestRetries,
            cancellationToken).ConfigureAwait(false);
        OrchestratorContractValidator.Validate(result.Value, assignment);
        return result.Value;
    }

    public async Task<FailAssignmentResponse> FailAsync(
        WorkerAssignment assignment,
        string errorCode,
        string requestId,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(assignment);
        var result = await PostSignedAsync<FailAssignmentRequest, FailAssignmentResponse>(
            AssignmentPath(assignment.AssignmentId, "fail"),
            "fail",
            new FailAssignmentRequest
            {
                AssignmentId = assignment.AssignmentId,
                NodeId = nodeId,
                WorkerKeyId = keyId,
                LeaseToken = assignment.LeaseToken,
                GenerationPlanHash = assignment.GenerationPlanHash,
                ErrorCode = SafeErrorCode(errorCode),
            },
            RequiredRequestId(requestId),
            requestRetries,
            cancellationToken).ConfigureAwait(false);
        OrchestratorContractValidator.Validate(result.Value, assignment);
        return result.Value;
    }

    internal async Task<SignedOperationResult<TResponse>> PostSignedAsync<TRequest, TResponse>(
        string path,
        string purpose,
        TRequest body,
        string requestId,
        int retries,
        CancellationToken cancellationToken)
    {
        path = ValidatePath(path);
        purpose = RequiredIdentifier(purpose, nameof(purpose), 64);
        requestId = RequiredRequestId(requestId);
        var bodyBytes = ProtocolJson.SerializeCanonicalToUtf8(body);
        OrchestratorRequestException? lastError = null;

        for (var attempt = 0; attempt <= retries; attempt++)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ChallengeResponse challenge;
            try
            {
                challenge = await RequestChallengeAsync(purpose, cancellationToken).ConfigureAwait(false);
            }
            catch (OrchestratorRequestException error)
            {
                lastError = error;
                if (!error.Retryable || attempt == retries)
                {
                    throw;
                }

                continue;
            }

            var now = timeProvider.GetUtcNow();
            var created = now.ToUnixTimeSeconds();
            var challengeExpires = ProtocolTime.ParseTimestamp(challenge.ExpiresAt, "expiresAt").ToUnixTimeSeconds();
            var expires = Math.Min(created + 120, challengeExpires);
            if (expires <= created)
            {
                lastError = new OrchestratorRequestException(
                    "challenge-expired",
                    null,
                    retryable: true,
                    outcomeUnknown: false);
                if (attempt == retries)
                {
                    throw lastError;
                }

                continue;
            }

            var signed = await HchHttpMessageSignatures.SignAsync(
                new HchHttpSignatureRequest(
                    "POST",
                    baseUri.Authority,
                    path,
                    JsonContentType,
                    bodyBytes,
                    nodeId,
                    keyId,
                    requestId,
                    created,
                    expires,
                    challenge.Nonce),
                signatureProvider,
                cancellationToken).ConfigureAwait(false);

            try
            {
                var stopwatch = Stopwatch.StartNew();
                var value = await SendAsync<TResponse>(path, bodyBytes, signed.Headers, operation: true, cancellationToken)
                    .ConfigureAwait(false);
                stopwatch.Stop();
                return new SignedOperationResult<TResponse>(value, requestId, stopwatch.Elapsed);
            }
            catch (OrchestratorRequestException error)
            {
                lastError = error;
                if (!error.Retryable || attempt == retries)
                {
                    throw;
                }
            }
        }

        throw lastError ?? new OrchestratorRequestException(
            "network-request-failed", null, retryable: true, outcomeUnknown: true);
    }

    private async Task<ChallengeResponse> RequestChallengeAsync(string purpose, CancellationToken cancellationToken)
    {
        var body = ProtocolJson.SerializeCanonicalToUtf8(new ChallengeRequest
        {
            KeyId = keyId,
            NodeId = nodeId,
            Purpose = purpose,
        });
        var requestId = identifiers.NewRequestId();
        var created = timeProvider.GetUtcNow().ToUnixTimeSeconds();
        var signed = await HchHttpMessageSignatures.SignAsync(
            new HchHttpSignatureRequest(
                "POST",
                baseUri.Authority,
                ChallengePath,
                JsonContentType,
                body,
                nodeId,
                keyId,
                requestId,
                created,
                created + 120,
                identifiers.NewClientNonce()),
            signatureProvider,
            cancellationToken).ConfigureAwait(false);
        var challenge = await SendAsync<ChallengeResponse>(
            ChallengePath,
            body,
            signed.Headers,
            operation: false,
            cancellationToken).ConfigureAwait(false);
        OrchestratorContractValidator.Validate(challenge, nodeId, keyId, purpose, timeProvider.GetUtcNow());
        return challenge;
    }

    private async Task<T> SendAsync<T>(
        string path,
        byte[] body,
        IReadOnlyDictionary<string, string> headers,
        bool operation,
        CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, new Uri(baseUri, path))
        {
            Content = new ByteArrayContent(body),
        };
        foreach (var pair in headers)
        {
            if (pair.Key.Equals("Content-Type", StringComparison.OrdinalIgnoreCase))
            {
                request.Content.Headers.ContentType = MediaTypeHeaderValue.Parse(pair.Value);
            }
            else if (pair.Key.Equals("Content-Digest", StringComparison.OrdinalIgnoreCase))
            {
                request.Content.Headers.TryAddWithoutValidation(pair.Key, pair.Value);
            }
            else
            {
                request.Headers.TryAddWithoutValidation(pair.Key, pair.Value);
            }
        }

        HttpResponseMessage response;
        try
        {
            response = await http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken)
                .ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            throw new OrchestratorRequestException(
                "network-request-timeout", null, retryable: true, outcomeUnknown: operation);
        }
        catch (HttpRequestException error)
        {
            throw new OrchestratorRequestException(
                "network-request-failed", null, retryable: true, outcomeUnknown: operation, error);
        }

        using (response)
        {
            var bytes = await ReadBoundedAsync(response.Content, cancellationToken).ConfigureAwait(false);
            if (!response.IsSuccessStatusCode)
            {
                throw CreateResponseError(response.StatusCode, bytes);
            }

            try
            {
                return ProtocolJson.Deserialize<T>(bytes);
            }
            catch (Exception error) when (error is ProtocolValidationException or JsonException)
            {
                throw new OrchestratorRequestException(
                    "orchestrator-invalid-json", response.StatusCode, retryable: false, outcomeUnknown: false, error);
            }
        }
    }

    private static async Task<byte[]> ReadBoundedAsync(HttpContent content, CancellationToken cancellationToken)
    {
        if (content.Headers.ContentLength > MaximumJsonResponseBytes)
        {
            throw new OrchestratorRequestException(
                "response-too-large", null, retryable: false, outcomeUnknown: false);
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

            if (output.Length + read > MaximumJsonResponseBytes)
            {
                throw new OrchestratorRequestException(
                    "response-too-large", null, retryable: false, outcomeUnknown: false);
            }

            output.Write(buffer, 0, read);
        }
    }

    private static OrchestratorRequestException CreateResponseError(HttpStatusCode status, byte[] bytes)
    {
        var code = "orchestrator-request-rejected";
        string? responseGenerationPlanHash = null;
        try
        {
            using var document = JsonDocument.Parse(bytes);
            if (document.RootElement.ValueKind == JsonValueKind.Object)
            {
                if (document.RootElement.TryGetProperty("code", out var codeValue)
                    && codeValue.ValueKind == JsonValueKind.String)
                {
                    code = SafeErrorCode(codeValue.GetString());
                }

                if (status == HttpStatusCode.Conflict
                    && document.RootElement.TryGetProperty("generationPlanHash", out var hashValue)
                    && hashValue.ValueKind == JsonValueKind.String
                    && HchDigest.IsLowerSha256(hashValue.GetString()))
                {
                    responseGenerationPlanHash = hashValue.GetString();
                }
            }
        }
        catch (JsonException)
        {
            // Remote error details are deliberately not surfaced.
        }

        var numericStatus = (int)status;
        return new OrchestratorRequestException(
            code,
            status,
            retryable: numericStatus == 429 || numericStatus >= 500,
            outcomeUnknown: false,
            responseGenerationPlanHash: responseGenerationPlanHash);
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

    private static string AssignmentPath(string assignmentId, string operation)
    {
        if (!Guid.TryParseExact(assignmentId, "D", out var parsed) || parsed == Guid.Empty)
        {
            throw new ArgumentException("assignment-id-invalid", nameof(assignmentId));
        }

        return $"/api/editorial/orchestrator/assignments/{assignmentId}/{operation}";
    }

    private static string ValidatePath(string value)
    {
        if (string.IsNullOrWhiteSpace(value) || !value.StartsWith('/')
            || value.IndexOfAny(['?', '#', '\r', '\n']) >= 0)
        {
            throw new ArgumentException("signed-request-path-invalid", nameof(value));
        }

        return value;
    }

    private static string RequiredIdentifier(string value, string parameterName, int maximum)
    {
        ArgumentNullException.ThrowIfNull(value);
        if (value.Length is < 1 || value.Length > maximum
            || value.Any(character => character <= ' ' || character == '\x7f' || char.IsSurrogate(character)))
        {
            throw new ArgumentException("protocol-identifier-invalid", parameterName);
        }

        return value;
    }

    private static string RequiredRequestId(string value)
    {
        if (!Guid.TryParseExact(value, "D", out var parsed) || parsed == Guid.Empty)
        {
            throw new ArgumentException("request-id-invalid", nameof(value));
        }

        return value;
    }

    private static void ValidateCapacity(int value, bool allowZero)
    {
        if (value > 64 || value < (allowZero ? 0 : 1))
        {
            throw new ArgumentOutOfRangeException(nameof(value));
        }
    }

    public static string SafeErrorCode(string? value)
    {
        var normalized = ErrorCodeCharacters().Replace(
            (value ?? "worker-generation-failed").Trim().ToLowerInvariant(), "-").Trim('-');
        if (normalized.Length > 200)
        {
            normalized = normalized[..200].TrimEnd('-');
        }

        return normalized.Length == 0 ? "worker-generation-failed" : normalized;
    }

    [GeneratedRegex("[^a-z0-9._-]+", RegexOptions.CultureInvariant)]
    private static partial Regex ErrorCodeCharacters();
}

public sealed record SignedOperationResult<T>(T Value, string RequestId, TimeSpan Latency);

public sealed class OrchestratorRequestException : Exception
{
    public OrchestratorRequestException(
        string code,
        HttpStatusCode? statusCode,
        bool retryable,
        bool outcomeUnknown,
        Exception? innerException = null,
        string? responseGenerationPlanHash = null)
        : base("A trusted orchestrator response was not available.", innerException)
    {
        Code = SignedOrchestratorClient.SafeErrorCode(code);
        StatusCode = statusCode;
        Retryable = retryable;
        OutcomeUnknown = outcomeUnknown;
        ResponseGenerationPlanHash = responseGenerationPlanHash;
    }

    public string Code { get; }

    public HttpStatusCode? StatusCode { get; }

    public bool Retryable { get; }

    public bool OutcomeUnknown { get; }

    public string? ResponseGenerationPlanHash { get; }
}

public sealed class WorkerServiceException(string code, string message, Exception? innerException = null)
    : Exception(message, innerException)
{
    public string Code { get; } = SignedOrchestratorClient.SafeErrorCode(code);
}
