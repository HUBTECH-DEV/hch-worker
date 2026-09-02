using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;
using Hch.Worker.Persistence;
using Hch.Worker.Protocol;
using Hch.Worker.Security;

namespace Hch.Worker.Service;

public sealed record OperationalEnrollmentReceipt(
    int SchemaVersion,
    string Protocol,
    string RequestId,
    string TokenId,
    string NodeId,
    string WorkerKeyId,
    string WorkerPublicKeyPem,
    string WorkerPublicKeyFingerprint,
    string OwnerUserId,
    string OwnerEmail,
    string OwnerSshKeyId,
    string OwnerSshKeyFingerprint,
    string Status,
    string EnrolledAt);

public sealed record PendingOperationalEnrollment(
    int SchemaVersion,
    string ExpectedOwnerSshKeyId,
    string ExpectedOwnerSshKeyFingerprint,
    OperationalEnrollmentChallengeRequest ChallengeRequest,
    OperationalEnrollmentChallengeResponse ChallengeResponse,
    OperationalEnrollmentRequest EnrollmentRequest);

/// <summary>
/// Completes the one-time HCH operational-key enrollment without persisting the
/// bearer token. Only the resulting public trust receipt is stored.
/// </summary>
public sealed partial class OperationalEnrollmentCoordinator(
    WorkerConfiguration configuration,
    Ed25519Identity identity,
    AtomicFileStore files,
    HttpClient http,
    TimeProvider? timeProvider = null)
{
    public const string ReceiptPath = "enrollment/operational-key.json";
    public const string PendingPath = "enrollment/pending-operational-key.json";

    private readonly SemaphoreSlim enrollmentGate = new(1, 1);
    private readonly TimeProvider clock = timeProvider ?? TimeProvider.System;
    private readonly OperationalEnrollmentHttpClient enrollmentHttp = new(
        http,
        configuration.OrchestratorBaseUri);

    public OperationalEnrollmentContext PublicContext()
    {
        string publicKeyPem = identity.ExportSubjectPublicKeyInfoPem().Trim();
        return new OperationalEnrollmentContext(
            OperationalEnrollmentContract.Protocol,
            configuration.NodeId,
            configuration.KeyId,
            publicKeyPem,
            identity.Fingerprint,
            OperationalEnrollmentContract.RuntimeVersion);
    }

    public async Task<OperationalEnrollmentReceipt> CompleteAsync(
        ReadOnlyMemory<byte> enrollmentTokenUtf8,
        string expectedOwnerSshKeyId,
        string expectedOwnerSshKeyFingerprint,
        CancellationToken cancellationToken = default)
    {
        await enrollmentGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            ValidateExpectedOwner(expectedOwnerSshKeyId, expectedOwnerSshKeyFingerprint);
            var existing = await files.ReadJsonAsync<OperationalEnrollmentReceipt>(
                ReceiptPath,
                cancellationToken).ConfigureAwait(false);
            if (existing is not null)
            {
                ValidateReceipt(existing, expectedOwnerSshKeyId, expectedOwnerSshKeyFingerprint);
                return existing;
            }

            string token = DecodeToken(enrollmentTokenUtf8.Span);
            try
            {
                PendingOperationalEnrollment? pending = await files
                    .ReadJsonAsync<PendingOperationalEnrollment>(PendingPath, cancellationToken)
                    .ConfigureAwait(false);
                if (pending is not null)
                {
                    await ValidatePendingAsync(
                        pending,
                        expectedOwnerSshKeyId,
                        expectedOwnerSshKeyFingerprint,
                        cancellationToken).ConfigureAwait(false);
                    try
                    {
                        return await CompletePendingAsync(
                            token,
                            pending,
                            cancellationToken).ConfigureAwait(false);
                    }
                    catch (OperationalEnrollmentException error) when (IsRefreshableChallenge(error))
                    {
                        // If a previously persisted challenge expired while the
                        // token remained active, HCH will issue a replacement for
                        // the same deterministic requestId. A consumed token would
                        // already have returned the stored idempotent response.
                    }
                }

                pending = await BeginPendingAsync(
                    token,
                    expectedOwnerSshKeyId,
                    expectedOwnerSshKeyFingerprint,
                    cancellationToken).ConfigureAwait(false);
                return await CompletePendingAsync(token, pending, cancellationToken).ConfigureAwait(false);
            }
            finally
            {
                // System.Net.Http requires the bearer parameter as a string. It
                // is scoped to the request and is never logged or persisted.
                token = string.Empty;
            }
        }
        catch (ProtocolValidationException error)
        {
            throw new OperationalEnrollmentException(error.Code, retryable: false);
        }
        catch (JsonException)
        {
            throw new OperationalEnrollmentException("enrollment-state-invalid", retryable: false);
        }
        finally
        {
            enrollmentGate.Release();
        }
    }

    private async Task<PendingOperationalEnrollment> BeginPendingAsync(
        string token,
        string expectedOwnerSshKeyId,
        string expectedOwnerSshKeyFingerprint,
        CancellationToken cancellationToken)
    {
        OperationalEnrollmentContext context = PublicContext();
        var request = OperationalEnrollmentContract.CreateChallengeRequest(
            context.NodeId,
            context.WorkerKeyId,
            context.WorkerPublicKeyPem);
        OperationalEnrollmentChallengeResponse? challenge = null;
        for (var attempt = 0; attempt < 2; attempt++)
        {
            try
            {
                challenge = await enrollmentHttp.PostAsync<
                    OperationalEnrollmentChallengeRequest,
                    OperationalEnrollmentChallengeResponse>(
                        OperationalEnrollmentContract.ChallengePath,
                        token,
                        request,
                        cancellationToken).ConfigureAwait(false);
                break;
            }
            catch (OperationalEnrollmentException error) when (error.Retryable && attempt == 0)
            {
                // Challenge issuance has no enrollment side effect and can be
                // repeated safely with the same deterministic requestId.
            }
        }

        if (challenge is null)
        {
            throw new OperationalEnrollmentException(
                "enrollment-challenge-unavailable",
                retryable: true);
        }
        var enrollment = await OperationalEnrollmentContract.CreateEnrollmentRequestAsync(
            request,
            challenge,
            expectedOwnerSshKeyId,
            expectedOwnerSshKeyFingerprint,
            identity,
            clock.GetUtcNow(),
            cancellationToken).ConfigureAwait(false);
        var pending = new PendingOperationalEnrollment(
            SchemaVersion: 1,
            expectedOwnerSshKeyId,
            expectedOwnerSshKeyFingerprint,
            request,
            challenge,
            enrollment);
        await ValidatePendingAsync(
            pending,
            expectedOwnerSshKeyId,
            expectedOwnerSshKeyFingerprint,
            cancellationToken).ConfigureAwait(false);
        await files.WriteJsonAsync(PendingPath, pending, cancellationToken).ConfigureAwait(false);
        return pending;
    }

    private async Task<OperationalEnrollmentReceipt> CompletePendingAsync(
        string token,
        PendingOperationalEnrollment pending,
        CancellationToken cancellationToken)
    {
        OperationalEnrollmentResponse? response = null;
        for (var attempt = 0; attempt < 2; attempt++)
        {
            try
            {
                response = await enrollmentHttp.PostAsync<
                    OperationalEnrollmentRequest,
                    OperationalEnrollmentResponse>(
                        OperationalEnrollmentContract.EnrollmentPath,
                        token,
                        pending.EnrollmentRequest,
                        cancellationToken).ConfigureAwait(false);
                break;
            }
            catch (OperationalEnrollmentException error) when (error.Retryable && attempt == 0)
            {
                // The same completion request is replayed first. If the first
                // response was lost after commit, HCH returns its stored response.
            }
        }

        if (response is null)
        {
            throw new OperationalEnrollmentException(
                "enrollment-completion-unavailable",
                retryable: true);
        }
        OperationalEnrollmentContract.Validate(
            response,
            pending.ChallengeRequest,
            pending.ChallengeResponse);

        var receipt = new OperationalEnrollmentReceipt(
            SchemaVersion: 1,
            OperationalEnrollmentContract.Protocol,
            pending.ChallengeRequest.RequestId,
            pending.ChallengeResponse.Proof.TokenId,
            response.NodeId,
            response.KeyId,
            pending.ChallengeRequest.PublicKeyPem,
            response.Fingerprint,
            response.OwnerUserId,
            response.OwnerEmail,
            response.OwnerSshKeyId,
            response.OwnerSshKeyFingerprint,
            response.Status,
            response.EnrolledAt);
        ValidateReceipt(
            receipt,
            pending.ExpectedOwnerSshKeyId,
            pending.ExpectedOwnerSshKeyFingerprint);
        await files.WriteJsonAsync(ReceiptPath, receipt, cancellationToken).ConfigureAwait(false);
        DeletePending();
        return receipt;
    }

    private async Task ValidatePendingAsync(
        PendingOperationalEnrollment pending,
        string expectedOwnerSshKeyId,
        string expectedOwnerSshKeyFingerprint,
        CancellationToken cancellationToken)
    {
        OperationalEnrollmentContext context = PublicContext();
        OperationalEnrollmentChallengeRequest expectedRequest =
            OperationalEnrollmentContract.CreateChallengeRequest(
                context.NodeId,
                context.WorkerKeyId,
                context.WorkerPublicKeyPem);
        if (pending.SchemaVersion != 1 ||
            pending.ExpectedOwnerSshKeyId != expectedOwnerSshKeyId ||
            pending.ExpectedOwnerSshKeyFingerprint != expectedOwnerSshKeyFingerprint ||
            pending.ChallengeRequest != expectedRequest)
        {
            throw new OperationalEnrollmentException("enrollment-pending-state-mismatch", retryable: false);
        }

        if (!DateTimeOffset.TryParse(
                pending.ChallengeResponse.ExpiresAt,
                System.Globalization.CultureInfo.InvariantCulture,
                System.Globalization.DateTimeStyles.AssumeUniversal |
                System.Globalization.DateTimeStyles.AdjustToUniversal,
                out var expiration))
        {
            throw new OperationalEnrollmentException("enrollment-pending-state-invalid", retryable: false);
        }

        OperationalEnrollmentRequest expectedEnrollment =
            await OperationalEnrollmentContract.CreateEnrollmentRequestAsync(
                expectedRequest,
                pending.ChallengeResponse,
                expectedOwnerSshKeyId,
                expectedOwnerSshKeyFingerprint,
                identity,
                expiration.Subtract(TimeSpan.FromSeconds(1)),
                cancellationToken).ConfigureAwait(false);
        if (pending.EnrollmentRequest != expectedEnrollment)
        {
            throw new OperationalEnrollmentException("enrollment-pending-proof-invalid", retryable: false);
        }
    }

    private void DeletePending()
    {
        string path = files.Resolve(PendingPath);
        if (File.Exists(path))
        {
            File.Delete(path);
        }
    }

    private static bool IsRefreshableChallenge(OperationalEnrollmentException error) =>
        error.Code is "enrollment-rejected" or "enrollment-conflict" or
            "enrollment-challenge-rejected";

    private void ValidateReceipt(
        OperationalEnrollmentReceipt receipt,
        string expectedOwnerSshKeyId,
        string expectedOwnerSshKeyFingerprint)
    {
        if (receipt.SchemaVersion != 1 ||
            receipt.Protocol != OperationalEnrollmentContract.Protocol ||
            receipt.NodeId != configuration.NodeId ||
            receipt.WorkerKeyId != configuration.KeyId ||
            receipt.WorkerPublicKeyFingerprint != identity.Fingerprint ||
            receipt.OwnerSshKeyId != expectedOwnerSshKeyId ||
            receipt.OwnerSshKeyFingerprint != expectedOwnerSshKeyFingerprint ||
            receipt.Status != "active")
        {
            throw new OperationalEnrollmentException("enrollment-receipt-mismatch", retryable: false);
        }

        byte[] publicKey = Ed25519KeyEncoding.DecodePublicKeyPem(receipt.WorkerPublicKeyPem);
        try
        {
            if (Ed25519KeyEncoding.Fingerprint(publicKey) != receipt.WorkerPublicKeyFingerprint)
            {
                throw new OperationalEnrollmentException("enrollment-receipt-key-invalid", retryable: false);
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(publicKey);
        }
    }

    private static void ValidateExpectedOwner(string keyId, string fingerprint)
    {
        if (!OwnerKeyId().IsMatch(keyId ?? string.Empty))
        {
            throw new OperationalEnrollmentException("enrollment-owner-key-id-invalid", retryable: false);
        }

        if (!Fingerprint().IsMatch(fingerprint ?? string.Empty))
        {
            throw new OperationalEnrollmentException("enrollment-owner-fingerprint-invalid", retryable: false);
        }
    }

    private static string DecodeToken(ReadOnlySpan<byte> value)
    {
        if (value.Length is < 43 or > 160)
        {
            throw new OperationalEnrollmentException("enrollment-token-invalid", retryable: false);
        }

        foreach (byte character in value)
        {
            if (!(character is >= (byte)'A' and <= (byte)'Z' or
                  >= (byte)'a' and <= (byte)'z' or
                  >= (byte)'0' and <= (byte)'9' or
                  (byte)'_' or (byte)'-'))
            {
                throw new OperationalEnrollmentException("enrollment-token-invalid", retryable: false);
            }
        }

        string token = Encoding.ASCII.GetString(value);
        if (!EnrollmentToken().IsMatch(token))
        {
            throw new OperationalEnrollmentException("enrollment-token-invalid", retryable: false);
        }

        return token;
    }

    [GeneratedRegex("^[A-Za-z0-9][A-Za-z0-9._:@/|-]{0,255}$", RegexOptions.CultureInvariant)]
    private static partial Regex OwnerKeyId();

    [GeneratedRegex("^SHA256:[A-Za-z0-9_-]{43}$", RegexOptions.CultureInvariant)]
    private static partial Regex Fingerprint();

    [GeneratedRegex("^hch_enroll_[A-Za-z0-9_-]{32,128}$", RegexOptions.CultureInvariant)]
    private static partial Regex EnrollmentToken();
}

public sealed record OperationalEnrollmentContext(
    string Protocol,
    string NodeId,
    string WorkerKeyId,
    string WorkerPublicKeyPem,
    string WorkerPublicKeyFingerprint,
    string WorkerRuntimeVersion);

public sealed class OperationalEnrollmentException(string code, bool retryable)
    : Exception("Operational enrollment failed.")
{
    public string Code { get; } = SanitizeCode(code);
    public bool Retryable { get; } = retryable;

    private static string SanitizeCode(string value)
    {
        if (string.IsNullOrEmpty(value) ||
            !Regex.IsMatch(value, "^[a-z0-9][a-z0-9.-]{0,119}$", RegexOptions.CultureInvariant))
        {
            return "enrollment-request-failed";
        }

        return value;
    }
}

internal sealed class OperationalEnrollmentHttpClient(HttpClient http, Uri baseUri)
{
    private const int MaximumResponseBytes = 64 * 1024;
    private readonly Uri origin = ValidateOrigin(baseUri);

    private static JsonSerializerOptions StrictJson { get; } = new(JsonSerializerDefaults.Web)
    {
        AllowTrailingCommas = false,
        MaxDepth = 32,
        NumberHandling = JsonNumberHandling.Strict,
        PropertyNameCaseInsensitive = false,
        ReadCommentHandling = JsonCommentHandling.Disallow,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
    };

    public async Task<TResponse> PostAsync<TRequest, TResponse>(
        string path,
        string bearerToken,
        TRequest value,
        CancellationToken cancellationToken)
    {
        byte[] requestBytes = ProtocolJson.SerializeCanonicalToUtf8(value);
        try
        {
            using var request = new HttpRequestMessage(HttpMethod.Post, new Uri(origin, path));
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", bearerToken);
            request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
            request.Headers.CacheControl = new CacheControlHeaderValue { NoStore = true };
            request.Content = new ByteArrayContent(requestBytes);
            request.Content.Headers.ContentType = new MediaTypeHeaderValue("application/json")
            {
                CharSet = "utf-8",
            };

            HttpResponseMessage response;
            try
            {
                response = await http.SendAsync(
                    request,
                    HttpCompletionOption.ResponseHeadersRead,
                    cancellationToken).ConfigureAwait(false);
            }
            catch (HttpRequestException)
            {
                throw new OperationalEnrollmentException("enrollment-network-unavailable", retryable: true);
            }
            catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
            {
                throw new OperationalEnrollmentException("enrollment-network-timeout", retryable: true);
            }

            using (response)
            {
                byte[] responseBytes = await ReadBoundedAsync(response.Content, cancellationToken).ConfigureAwait(false);
                try
                {
                    if (!response.IsSuccessStatusCode)
                    {
                        string code = ReadSafeErrorCode(responseBytes) ?? HttpErrorCode(response.StatusCode);
                        throw new OperationalEnrollmentException(code, IsRetryable(response.StatusCode));
                    }

                    if (response.Content.Headers.ContentType?.MediaType is not string mediaType ||
                        !mediaType.Equals("application/json", StringComparison.OrdinalIgnoreCase))
                    {
                        throw new OperationalEnrollmentException("enrollment-response-content-type-invalid", retryable: false);
                    }

                    byte[] canonical = JcsCanonicalizer.CanonicalizeToUtf8(responseBytes);
                    try
                    {
                        return JsonSerializer.Deserialize<TResponse>(canonical, StrictJson)
                            ?? throw new OperationalEnrollmentException("enrollment-response-empty", retryable: false);
                    }
                    catch (JsonException)
                    {
                        throw new OperationalEnrollmentException("enrollment-response-invalid", retryable: false);
                    }
                    finally
                    {
                        CryptographicOperations.ZeroMemory(canonical);
                    }
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(responseBytes);
                }
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(requestBytes);
        }
    }

    private static async Task<byte[]> ReadBoundedAsync(
        HttpContent content,
        CancellationToken cancellationToken)
    {
        if (content.Headers.ContentLength is > MaximumResponseBytes)
        {
            throw new OperationalEnrollmentException("enrollment-response-too-large", retryable: false);
        }

        await using Stream source = await content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
        using var destination = new MemoryStream();
        byte[] buffer = new byte[8192];
        try
        {
            int read;
            while ((read = await source.ReadAsync(buffer, cancellationToken).ConfigureAwait(false)) > 0)
            {
                if (destination.Length + read > MaximumResponseBytes)
                {
                    throw new OperationalEnrollmentException("enrollment-response-too-large", retryable: false);
                }

                destination.Write(buffer, 0, read);
            }

            return destination.ToArray();
        }
        finally
        {
            CryptographicOperations.ZeroMemory(buffer);
        }
    }

    private static string? ReadSafeErrorCode(ReadOnlySpan<byte> response)
    {
        try
        {
            var reader = new Utf8JsonReader(response, new JsonReaderOptions
            {
                AllowTrailingCommas = false,
                CommentHandling = JsonCommentHandling.Disallow,
                MaxDepth = 8,
            });
            using JsonDocument document = JsonDocument.ParseValue(ref reader);
            if (document.RootElement.ValueKind != JsonValueKind.Object ||
                !document.RootElement.TryGetProperty("code", out JsonElement code) ||
                code.ValueKind != JsonValueKind.String)
            {
                return null;
            }

            string? value = code.GetString();
            return Regex.IsMatch(value ?? string.Empty, "^[a-z0-9][a-z0-9.-]{0,119}$", RegexOptions.CultureInvariant)
                ? value
                : null;
        }
        catch (JsonException)
        {
            return null;
        }
    }

    private static string HttpErrorCode(HttpStatusCode status) => status switch
    {
        HttpStatusCode.Unauthorized => "enrollment-unauthorized",
        HttpStatusCode.Forbidden => "enrollment-forbidden",
        HttpStatusCode.Conflict => "enrollment-conflict",
        HttpStatusCode.RequestEntityTooLarge => "enrollment-request-too-large",
        HttpStatusCode.UnsupportedMediaType => "enrollment-content-type-rejected",
        _ => "enrollment-request-rejected",
    };

    private static bool IsRetryable(HttpStatusCode status) =>
        status is HttpStatusCode.RequestTimeout or HttpStatusCode.TooManyRequests ||
        (int)status >= 500;

    private static Uri ValidateOrigin(Uri value)
    {
        if (!value.IsAbsoluteUri || value.Scheme != Uri.UriSchemeHttps ||
            value.UserInfo.Length != 0 || value.AbsolutePath != "/" ||
            value.Query.Length != 0 || value.Fragment.Length != 0)
        {
            throw new ArgumentException("enrollment-origin-invalid", nameof(value));
        }

        return value;
    }
}
