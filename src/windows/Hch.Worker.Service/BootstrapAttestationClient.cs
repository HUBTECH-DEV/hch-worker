using System.Net;
using System.Text.Json;
using Hch.Worker.Protocol;

namespace Hch.Worker.Service;

public interface IWorkerBootstrapClient
{
    Task<ManifestDelivery> FetchManifestAsync(CancellationToken cancellationToken);

    Task<BootstrapResponseContract> BootstrapAsync(
        BootstrapRequestContract request,
        string requestId,
        CancellationToken cancellationToken);

    Task<AttestationResponseContract> AttestAsync(
        string bootstrapSessionId,
        AttestationRequestContract request,
        string requestId,
        CancellationToken cancellationToken);
}

/// <summary>
/// Fetches signed manifest material and delegates authenticated POST operations
/// to the existing fixed HCH HTTP Message Signatures transport.
/// </summary>
public sealed class BootstrapAttestationClient : IWorkerBootstrapClient
{
    private const string ManifestPath = "/api/editorial/orchestrator/manifest";
    private const string BootstrapPath = "/api/editorial/orchestrator/bootstrap";
    private readonly HttpClient http;
    private readonly Uri baseUri;
    private readonly SignedOrchestratorClient signedClient;

    public BootstrapAttestationClient(
        HttpClient http,
        Uri baseUri,
        SignedOrchestratorClient signedClient)
    {
        this.http = http ?? throw new ArgumentNullException(nameof(http));
        this.baseUri = ValidateBaseUri(baseUri);
        this.signedClient = signedClient ?? throw new ArgumentNullException(nameof(signedClient));
    }

    public async Task<ManifestDelivery> FetchManifestAsync(CancellationToken cancellationToken)
    {
        var target = new Uri(baseUri, ManifestPath);
        using var request = new HttpRequestMessage(HttpMethod.Get, target);
        request.Headers.Accept.ParseAdd(SignedOrchestratorClient.JsonContentType);
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
            throw new OrchestratorRequestException(
                "network-request-timeout",
                null,
                retryable: true,
                outcomeUnknown: false);
        }
        catch (HttpRequestException error)
        {
            throw new OrchestratorRequestException(
                "network-request-failed",
                null,
                retryable: true,
                outcomeUnknown: false,
                error);
        }

        using (response)
        {
            if (response.RequestMessage?.RequestUri is not { } finalUri
                || finalUri != target)
            {
                throw new OrchestratorRequestException(
                    "manifest-redirect-refused",
                    response.StatusCode,
                    retryable: false,
                    outcomeUnknown: false);
            }

            var bytes = await ReadBoundedAsync(response.Content, cancellationToken).ConfigureAwait(false);
            if (!response.IsSuccessStatusCode)
            {
                throw ResponseError(response.StatusCode, bytes);
            }

            try
            {
                return ProtocolJson.Deserialize<ManifestDelivery>(bytes);
            }
            catch (Exception error) when (error is ProtocolValidationException or JsonException)
            {
                throw new OrchestratorRequestException(
                    "orchestrator-invalid-json",
                    response.StatusCode,
                    retryable: false,
                    outcomeUnknown: false,
                    error);
            }
        }
    }

    public async Task<BootstrapResponseContract> BootstrapAsync(
        BootstrapRequestContract request,
        string requestId,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        var result = await signedClient.PostSignedAsync<BootstrapRequestContract, BootstrapResponseContract>(
            BootstrapPath,
            "bootstrap",
            request,
            requestId,
            retries: 1,
            cancellationToken).ConfigureAwait(false);
        return result.Value;
    }

    public async Task<AttestationResponseContract> AttestAsync(
        string bootstrapSessionId,
        AttestationRequestContract request,
        string requestId,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (!Guid.TryParseExact(bootstrapSessionId, "D", out var sessionId) || sessionId == Guid.Empty)
        {
            throw new WorkerServiceException(
                "bootstrap-session-id-invalid",
                "The bootstrap session identifier is invalid.");
        }

        var path = $"/api/editorial/orchestrator/bootstrap/{bootstrapSessionId}/attest";
        var result = await signedClient.PostSignedAsync<AttestationRequestContract, AttestationResponseContract>(
            path,
            "attest",
            request,
            requestId,
            retries: 1,
            cancellationToken).ConfigureAwait(false);
        return result.Value;
    }

    private static async Task<byte[]> ReadBoundedAsync(
        HttpContent content,
        CancellationToken cancellationToken)
    {
        if (content.Headers.ContentLength > SignedOrchestratorClient.MaximumJsonResponseBytes)
        {
            throw new OrchestratorRequestException(
                "response-too-large",
                null,
                retryable: false,
                outcomeUnknown: false);
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

            if (output.Length + read > SignedOrchestratorClient.MaximumJsonResponseBytes)
            {
                throw new OrchestratorRequestException(
                    "response-too-large",
                    null,
                    retryable: false,
                    outcomeUnknown: false);
            }

            output.Write(buffer, 0, read);
        }
    }

    private static OrchestratorRequestException ResponseError(HttpStatusCode status, byte[] bytes)
    {
        var code = "orchestrator-request-rejected";
        try
        {
            using var document = JsonDocument.Parse(bytes);
            if (document.RootElement.ValueKind == JsonValueKind.Object
                && document.RootElement.TryGetProperty("code", out var value)
                && value.ValueKind == JsonValueKind.String)
            {
                code = SignedOrchestratorClient.SafeErrorCode(value.GetString());
            }
        }
        catch (JsonException)
        {
            // Untrusted remote details are deliberately not exposed.
        }

        var numeric = (int)status;
        return new OrchestratorRequestException(
            code,
            status,
            retryable: numeric == 429 || numeric >= 500,
            outcomeUnknown: false);
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
}
