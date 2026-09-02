using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Hch.Worker.Tray;

public sealed record HihDesktopAuthentication(string CorrelationId, string DisplayEmail, DateTimeOffset ExpiresAt);

public sealed record HihEnrollmentResult(
    string Status,
    string UserSshKeyId,
    string UserSshKeyFingerprint);

public sealed class HchSelfEnrollmentToken(
    byte[] tokenUtf8,
    string tokenId,
    DateTimeOffset expiresAt,
    string intendedNodeId,
    string ownerSshKeyId,
    string ownerSshKeyFingerprint) : IDisposable
{
    public byte[] TokenUtf8 { get; } = tokenUtf8;
    public string TokenId { get; } = tokenId;
    public DateTimeOffset ExpiresAt { get; } = expiresAt;
    public string IntendedNodeId { get; } = intendedNodeId;
    public string OwnerSshKeyId { get; } = ownerSshKeyId;
    public string OwnerSshKeyFingerprint { get; } = ownerSshKeyFingerprint;

    public void Dispose() => CryptographicOperations.ZeroMemory(TokenUtf8);
}

public static class HihDesktopClient
{
    private const string NativeClientId = "hch-worker-windows";
    private const string NativeAudience = "hch";
    private const int MaximumResponseBytes = 256 * 1024;
    private const int MaximumLoopbackRequestHeadBytes = 16 * 1024;
    private static readonly TimeSpan LoopbackConnectionTimeout = TimeSpan.FromSeconds(3);
    private static readonly Uri HihOrigin = new("https://hah.hubtech.online/");
    private static readonly Uri HchOrigin = new("https://hubtech.online/");
    private static readonly ConcurrentDictionary<string, NativeSession> Sessions = new(StringComparer.Ordinal);
    private static readonly SemaphoreSlim DiscoveryGate = new(1, 1);
    private static readonly HttpClient Http = CreateHttpClient();
    private static NativeDiscovery? discovery;

    public static async Task<HihDesktopAuthentication> AuthenticateAsync(
        string email,
        string password,
        CancellationToken cancellationToken = default)
    {
        NativeDiscovery endpoints = await GetDiscoveryAsync(cancellationToken).ConfigureAwait(false);
        byte[] body = SerializePasswordRequest(email, password, endpoints.Resource.TenantId);
        try
        {
            using var request = NewRequest(HttpMethod.Post, endpoints.Endpoints.NativePassword);
            request.Content = new ByteArrayContent(body);
            request.Content.Headers.ContentType = new MediaTypeHeaderValue("application/json") { CharSet = "utf-8" };
            NativeTokenResponse result = await SendJsonAsync<NativeTokenResponse>(request, cancellationToken).ConfigureAwait(false);
            return KeepSession(result, endpoints);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(body);
        }
    }

    public static async Task<HihDesktopAuthentication> AuthorizeWithBrowserAsync(
        CancellationToken cancellationToken = default)
    {
        NativeDiscovery endpoints = await GetDiscoveryAsync(cancellationToken).ConfigureAwait(false);
        byte[] verifierBytes = RandomNumberGenerator.GetBytes(32);
        byte[] stateBytes = RandomNumberGenerator.GetBytes(32);
        string verifier = Base64Url(verifierBytes);
        string state = Base64Url(stateBytes);
        CryptographicOperations.ZeroMemory(verifierBytes);
        CryptographicOperations.ZeroMemory(stateBytes);

        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start(8);
        try
        {
            int port = ((IPEndPoint)listener.LocalEndpoint).Port;
            string redirectUri = $"http://127.0.0.1:{port}/callback";
            byte[] verifierAscii = Encoding.ASCII.GetBytes(verifier);
            string challenge;
            try
            {
                challenge = Base64Url(SHA256.HashData(verifierAscii));
            }
            finally
            {
                CryptographicOperations.ZeroMemory(verifierAscii);
            }

            Uri authorizeUri = BuildUri(endpoints.Endpoints.Authorization, new Dictionary<string, string>
            {
                ["response_type"] = "code",
                ["client_id"] = NativeClientId,
                ["redirect_uri"] = redirectUri,
                ["code_challenge"] = challenge,
                ["code_challenge_method"] = "S256",
                ["state"] = state,
            });
            _ = Process.Start(new ProcessStartInfo(authorizeUri.AbsoluteUri) { UseShellExecute = true });

            using var callbackTimeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            callbackTimeout.CancelAfter(TimeSpan.FromMinutes(5));
            string code = await ReceiveAuthorizationCodeAsync(listener, state, callbackTimeout.Token).ConfigureAwait(false);

            using var request = NewRequest(HttpMethod.Post, endpoints.Endpoints.Token);
            request.Content = JsonContent(new
            {
                grant_type = "authorization_code",
                client_id = NativeClientId,
                code,
                redirect_uri = redirectUri,
                code_verifier = verifier,
            });
            NativeTokenResponse result = await SendJsonAsync<NativeTokenResponse>(request, cancellationToken).ConfigureAwait(false);
            return KeepSession(result, endpoints);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            throw new HihDesktopAuthenticationException("A autorização no navegador expirou. Inicie o fluxo novamente.");
        }
        catch (HihDesktopLoginRequiredException)
        {
            OpenTrustedExternal(endpoints.Endpoints.Login);
            throw new HihDesktopAuthenticationException(
                "Entre no HAH na janela aberta e clique novamente em Entrar com o HIH.");
        }
        finally
        {
            listener.Stop();
            verifier = string.Empty;
            state = string.Empty;
        }
    }

    public static async Task<HihEnrollmentResult> RegisterPublicKeyAsync(
        string correlationId,
        UserSshPublicKey key,
        string nodeId,
        CancellationToken cancellationToken = default)
    {
        NativeSession session = RequireSession(correlationId);
        NativeDiscovery endpoints = await GetDiscoveryAsync(cancellationToken).ConfigureAwait(false);

        string label = $"HCH Worker {nodeId}";
        WorkerSshKeyChallengeEnvelope challenge;
        using (var request = NewAuthorizedRequest(
            HttpMethod.Post,
            endpoints.Endpoints.WorkerSshKeyChallenge,
            session.AccessToken))
        {
            request.Content = JsonContent(new { label, publicKey = key.PublicKey });
            challenge = await SendJsonAsync<WorkerSshKeyChallengeEnvelope>(
                request,
                cancellationToken).ConfigureAwait(false);
        }

        byte[]? signature = null;
        try
        {
            if (string.IsNullOrWhiteSpace(key.PrivateKeyPath))
            {
                throw new HihDesktopAuthenticationException(
                    "A chave pública foi selecionada sem a chave privada correspondente; não é possível provar a posse.");
            }

            using ValidatedWorkerSshKeyProof validatedProof = WorkerSshKeyProofValidator.Validate(
                challenge,
                key,
                label,
                new WorkerSshKeyProofContext(
                    session.UserId,
                    session.TenantId,
                    session.ExpiresAt,
                    endpoints.ProofOfPossession.ChallengeTtlSeconds),
                DateTimeOffset.UtcNow);
            signature = await UserSshKeyManager.SignRegistrationProofAsync(
                key.PrivateKeyPath,
                validatedProof,
                cancellationToken).ConfigureAwait(false);
            using var request = NewAuthorizedRequest(
                HttpMethod.Post,
                endpoints.Endpoints.WorkerSshKeyRegistration,
                session.AccessToken);
            request.Content = JsonContent(new
            {
                challengeId = challenge.ChallengeId,
                nonce = challenge.Nonce,
                label,
                publicKey = key.PublicKey,
                signature = Base64Url(signature),
            });
            RegisteredKeyResponse registered = await SendJsonAsync<RegisteredKeyResponse>(request, cancellationToken).ConfigureAwait(false);
            if (!registered.ProofVerified ||
                !(string.Equals(registered.Key.Algorithm, "Ed25519", StringComparison.OrdinalIgnoreCase) ||
                  string.Equals(registered.Key.Algorithm, "ssh-ed25519", StringComparison.OrdinalIgnoreCase)) ||
                !string.Equals(registered.Key.Fingerprint, key.Fingerprint, StringComparison.Ordinal))
            {
                throw new HihDesktopAuthenticationException(
                    "O HIH não confirmou a mesma chave pública Ed25519 gerada localmente.");
            }

            return new HihEnrollmentResult(
                "Chave pública registrada com prova de posse. O HCH já pode autorizar este Worker em self-service.",
                registered.Key.Id,
                registered.Key.Fingerprint);
        }
        finally
        {
            if (signature is not null)
            {
                CryptographicOperations.ZeroMemory(signature);
            }
        }
    }

    public static async Task<HchSelfEnrollmentToken> IssueSelfEnrollmentTokenAsync(
        string correlationId,
        string requestId,
        string nodeId,
        string ownerSshKeyId,
        string ownerSshKeyFingerprint,
        CancellationToken cancellationToken = default)
    {
        NativeSession session = RequireSession(correlationId);
        using var request = NewAuthorizedRequest(
            HttpMethod.Post,
            new Uri(HchOrigin, "api/editorial/orchestrator/enrollment/self-token"),
            session.AccessToken);
        request.Content = JsonContent(new { requestId, nodeId, ownerSshKeyId });
        using HttpResponseMessage response = await SendHttpAsync(request, cancellationToken).ConfigureAwait(false);
        byte[] payload = await ReadBoundedAsync(response.Content, cancellationToken).ConfigureAwait(false);
        try
        {
            if (!response.IsSuccessStatusCode)
            {
                ApiErrorEnvelope? failure = TryDeserialize<ApiErrorEnvelope>(payload);
                throw new HihDesktopAuthenticationException(
                    failure?.Error.Message ?? "O HCH recusou a autorização self-service do Worker.");
            }

            return ParseSelfEnrollmentToken(
                payload,
                nodeId,
                ownerSshKeyId,
                ownerSshKeyFingerprint);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(payload);
        }
    }

    public static async Task<Uri> GetPasswordRecoveryUriAsync(
        CancellationToken cancellationToken = default) =>
        (await GetDiscoveryAsync(cancellationToken).ConfigureAwait(false)).Endpoints.PasswordRecovery;

    public static async Task<Uri> GetCreateAccountUriAsync(
        CancellationToken cancellationToken = default) =>
        (await GetDiscoveryAsync(cancellationToken).ConfigureAwait(false)).Endpoints.CreateAccount;

    public static async Task RevokeAsync(string correlationId, CancellationToken cancellationToken = default)
    {
        if (!Sessions.TryRemove(correlationId, out NativeSession? session))
        {
            return;
        }

        try
        {
            NativeDiscovery endpoints = await GetDiscoveryAsync(cancellationToken).ConfigureAwait(false);
            using var request = NewRequest(HttpMethod.Post, endpoints.Endpoints.Revoke);
            byte[] body = SerializeRevokeRequest(session.AccessToken);
            try
            {
                request.Content = new ByteArrayContent(body);
                request.Content.Headers.ContentType = new MediaTypeHeaderValue("application/json") { CharSet = "utf-8" };
                using HttpResponseMessage response = await SendHttpAsync(
                request,
                cancellationToken).ConfigureAwait(false);
                _ = response.IsSuccessStatusCode;
            }
            finally
            {
                CryptographicOperations.ZeroMemory(body);
            }
        }
        finally
        {
            session.Clear();
        }
    }

    public static async Task RevokeSilentlyAsync(string correlationId)
    {
        try
        {
            await RevokeAsync(correlationId).ConfigureAwait(false);
        }
        catch (HihDesktopAuthenticationException)
        {
            // The local bearer is already removed and zeroed by RevokeAsync.
            // The remote opaque session will expire within its short TTL.
        }
    }

    private static HihDesktopAuthentication KeepSession(
        NativeTokenResponse response,
        NativeDiscovery discoveryContract)
    {
        if (response.Identity is null
            || discoveryContract.Resource is null
            || !string.Equals(response.TokenType, "Bearer", StringComparison.OrdinalIgnoreCase)
            || !string.Equals(response.Audience, NativeAudience, StringComparison.Ordinal)
            || !string.Equals(response.Scope, "hch.worker.enroll.self", StringComparison.Ordinal)
            || !string.Equals(response.Identity.ClientId, NativeClientId, StringComparison.Ordinal)
            || !string.Equals(response.Identity.Audience, NativeAudience, StringComparison.Ordinal)
            || !string.Equals(response.Identity.TenantId, discoveryContract.Resource.TenantId, StringComparison.Ordinal)
            || response.ExpiresAt <= DateTimeOffset.UtcNow
            || response.ExpiresAt > DateTimeOffset.UtcNow.AddHours(1)
            || response.ExpiresIn is < 60 or > 3600
            || response.Identity.ExpiresAt != response.ExpiresAt
            || !IsBase64Url(response.AccessToken, 43)
            || !IsCanonicalUuid(response.Identity.NativeSessionId)
            || !IsCanonicalUuid(response.Identity.UserId)
            || !IsCanonicalUuid(response.Identity.PersonId)
            || !IsCanonicalUuid(response.Identity.TenantId)
            || !IsCanonicalUuid(response.Identity.MembershipId)
            || response.Identity.Permissions is null
            || !response.Identity.Permissions.Contains("hch.worker.enroll.self", StringComparer.Ordinal))
        {
            throw new HihDesktopAuthenticationException("O HIH retornou uma sessão nativa inválida.");
        }

        string handle = Guid.NewGuid().ToString("D");
        Sessions[handle] = new NativeSession(
            response.AccessToken.ToCharArray(),
            response.ExpiresAt,
            response.Identity.UserId,
            response.Identity.TenantId);
        return new HihDesktopAuthentication(handle, response.Identity.Email, response.ExpiresAt);
    }

    private static NativeSession RequireSession(string correlationId)
    {
        if (!Guid.TryParseExact(correlationId, "D", out _)
            || !Sessions.TryGetValue(correlationId, out NativeSession? session)
            || session.ExpiresAt <= DateTimeOffset.UtcNow)
        {
            if (!string.IsNullOrWhiteSpace(correlationId))
            {
                Sessions.TryRemove(correlationId, out NativeSession? expired);
                expired?.Clear();
            }

            throw new HihDesktopAuthenticationException("A sessão HIH expirou. Entre novamente.");
        }

        return session;
    }

    internal static async Task<string> ReceiveAuthorizationCodeAsync(
        TcpListener listener,
        string expectedState,
        CancellationToken cancellationToken,
        TimeSpan? connectionTimeout = null)
    {
        TimeSpan perConnectionTimeout = connectionTimeout ?? LoopbackConnectionTimeout;
        if (perConnectionTimeout <= TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(nameof(connectionTimeout));
        }

        int port = ((IPEndPoint)listener.LocalEndpoint).Port;
        string expectedAuthority = $"127.0.0.1:{port}";
        while (true)
        {
            cancellationToken.ThrowIfCancellationRequested();
            using TcpClient client = await listener.AcceptTcpClientAsync(cancellationToken).ConfigureAwait(false);
            if (client.Client.RemoteEndPoint is not IPEndPoint remoteEndpoint
                || !IPAddress.IsLoopback(remoteEndpoint.Address))
            {
                continue;
            }

            client.NoDelay = true;
            await using NetworkStream stream = client.GetStream();
            using var acceptedConnectionTimeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            acceptedConnectionTimeout.CancelAfter(perConnectionTimeout);

            LoopbackAuthorizationCallback callback;
            try
            {
                string? requestHead = await ReadLoopbackRequestHeadAsync(
                    stream,
                    acceptedConnectionTimeout.Token).ConfigureAwait(false);
                callback = requestHead is null
                    ? new(LoopbackAuthorizationCallbackKind.Invalid)
                    : LoopbackAuthorizationCallbackParser.Parse(
                        requestHead,
                        expectedAuthority,
                        expectedState);
            }
            catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
            {
                continue;
            }
            catch (IOException) when (!cancellationToken.IsCancellationRequested)
            {
                continue;
            }
            catch (SocketException) when (!cancellationToken.IsCancellationRequested)
            {
                continue;
            }

            switch (callback.Kind)
            {
                case LoopbackAuthorizationCallbackKind.AuthorizationCode:
                    await TryWriteLoopbackResponseAsync(
                        stream,
                        HttpStatusCode.OK,
                        "Autorização concluída. Você pode fechar esta janela e retornar ao HCH Worker.",
                        acceptedConnectionTimeout.Token,
                        cancellationToken).ConfigureAwait(false);
                    cancellationToken.ThrowIfCancellationRequested();
                    return callback.AuthorizationCode!;

                case LoopbackAuthorizationCallbackKind.LoginRequired:
                    await TryWriteLoopbackResponseAsync(
                        stream,
                        HttpStatusCode.Unauthorized,
                        "Entre no HAH e repita a autorização no HCH Worker.",
                        acceptedConnectionTimeout.Token,
                        cancellationToken).ConfigureAwait(false);
                    cancellationToken.ThrowIfCancellationRequested();
                    throw new HihDesktopLoginRequiredException();

                case LoopbackAuthorizationCallbackKind.AccessDenied:
                    await TryWriteLoopbackResponseAsync(
                        stream,
                        HttpStatusCode.Forbidden,
                        "Autorização negada. Nenhuma chave foi registrada; você pode fechar esta janela.",
                        acceptedConnectionTimeout.Token,
                        cancellationToken).ConfigureAwait(false);
                    cancellationToken.ThrowIfCancellationRequested();
                    throw new HihDesktopAuthenticationException(
                        "A autorização do HCH Worker foi negada no HIH. Nenhuma chave foi registrada; revise suas permissões ou inicie novamente.");

                case LoopbackAuthorizationCallbackKind.ServerError:
                    await TryWriteLoopbackResponseAsync(
                        stream,
                        HttpStatusCode.BadGateway,
                        "O HIH não conseguiu concluir a autorização. Retorne ao HCH Worker e tente novamente.",
                        acceptedConnectionTimeout.Token,
                        cancellationToken).ConfigureAwait(false);
                    cancellationToken.ThrowIfCancellationRequested();
                    throw new HihDesktopAuthenticationException(
                        "O HIH não conseguiu concluir a autorização. Tente novamente em instantes.");

                default:
                    await TryWriteLoopbackResponseAsync(
                        stream,
                        HttpStatusCode.BadRequest,
                        "Esta conexão não corresponde ao retorno de autorização esperado.",
                        acceptedConnectionTimeout.Token,
                        cancellationToken).ConfigureAwait(false);
                    break;
            }
        }
    }

    private static async Task<string?> ReadLoopbackRequestHeadAsync(
        Stream stream,
        CancellationToken cancellationToken)
    {
        byte[] request = new byte[MaximumLoopbackRequestHeadBytes];
        int length = 0;
        while (length < request.Length)
        {
            int previousLength = length;
            int read = await stream.ReadAsync(
                request.AsMemory(length, Math.Min(1024, request.Length - length)),
                cancellationToken).ConfigureAwait(false);
            if (read == 0)
            {
                return null;
            }

            length += read;
            for (int index = previousLength; index < length; index++)
            {
                if (request[index] is 0 or > 0x7f)
                {
                    return null;
                }
            }

            int searchFrom = Math.Max(0, previousLength - 3);
            for (int index = searchFrom; index <= length - 4; index++)
            {
                if (request[index] == '\r'
                    && request[index + 1] == '\n'
                    && request[index + 2] == '\r'
                    && request[index + 3] == '\n')
                {
                    return index + 4 == length
                        ? Encoding.ASCII.GetString(request, 0, length)
                        : null;
                }
            }
        }

        return null;
    }

    private static async Task TryWriteLoopbackResponseAsync(
        Stream stream,
        HttpStatusCode status,
        string message,
        CancellationToken connectionCancellationToken,
        CancellationToken globalCancellationToken)
    {
        try
        {
            await WriteLoopbackResponseAsync(
                stream,
                status,
                message,
                connectionCancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (!globalCancellationToken.IsCancellationRequested)
        {
        }
        catch (IOException)
        {
        }
        catch (SocketException)
        {
        }
    }

    private static async Task WriteLoopbackResponseAsync(
        Stream stream,
        HttpStatusCode status,
        string message,
        CancellationToken cancellationToken)
    {
        string html = $"<!doctype html><html lang=\"pt-BR\"><meta charset=\"utf-8\"><title>HCH Worker</title><body><h1>HCH Worker</h1><p>{WebUtility.HtmlEncode(message)}</p></body></html>";
        byte[] body = Encoding.UTF8.GetBytes(html);
        byte[] headers = Encoding.ASCII.GetBytes(
            $"HTTP/1.1 {(int)status} {status}\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {body.Length}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n");
        await stream.WriteAsync(headers, cancellationToken).ConfigureAwait(false);
        await stream.WriteAsync(body, cancellationToken).ConfigureAwait(false);
        await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
    }

    private static async Task<NativeDiscovery> GetDiscoveryAsync(CancellationToken cancellationToken)
    {
        if (discovery is not null)
        {
            return discovery;
        }

        await DiscoveryGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (discovery is not null)
            {
                return discovery;
            }

            using var request = NewRequest(
                HttpMethod.Get,
                new Uri(HihOrigin, "api/v1/native-auth/discovery"));
            NativeDiscovery candidate = await SendJsonAsync<NativeDiscovery>(
                request,
                cancellationToken).ConfigureAwait(false);
            ValidateDiscovery(candidate);
            discovery = candidate;
            return candidate;
        }
        finally
        {
            DiscoveryGate.Release();
        }
    }

    private static void ValidateDiscovery(NativeDiscovery value)
    {
        Uri issuer = new(HihOrigin, "api/v1");
        bool valid = value.Resource is not null
            && value.Client is not null
            && value.Capabilities is not null
            && value.Endpoints is not null
            && value.Token is not null
            && value.ProofOfPossession is not null
            && value.SchemaVersion == "1.1"
            && SameUri(value.Issuer, issuer)
            && value.Resource.Audience == NativeAudience
            && IsCanonicalUuid(value.Resource.TenantId)
            && !string.IsNullOrWhiteSpace(value.Resource.TenantName)
            && !string.IsNullOrWhiteSpace(value.Resource.TenantSlug)
            && value.Resource.MembershipRequired
            && value.Client.ClientId == NativeClientId
            && value.Client.ClientType == "public"
            && !value.Client.ClientSecretRequired
            && value.Client.RedirectUriPattern == "http://127.0.0.1:{dynamicPort}/callback"
            && value.Capabilities.AuthorizationCodePkce
            && value.Capabilities.PkceCodeChallengeMethods is not null
            && value.Capabilities.PkceCodeChallengeMethods.SequenceEqual(["S256"], StringComparer.Ordinal)
            && !value.Capabilities.DeviceCode
            && value.Capabilities.NativePassword
            && !value.Capabilities.MfaVerification
            && value.Capabilities.MfaRequiredPolicy == "fail-closed"
            && SameUri(value.Endpoints.Authorization, new Uri(issuer.AbsoluteUri + "/native-auth/authorize"))
            && SameUri(value.Endpoints.Token, new Uri(issuer.AbsoluteUri + "/native-auth/token"))
            && SameUri(value.Endpoints.Revoke, new Uri(issuer.AbsoluteUri + "/native-auth/revoke"))
            && SameUri(value.Endpoints.Session, new Uri(issuer.AbsoluteUri + "/native-auth/session"))
            && SameUri(value.Endpoints.NativePassword, new Uri(issuer.AbsoluteUri + "/native-auth/password"))
            && value.Endpoints.DeviceAuthorization is null
            && SameUri(value.Endpoints.WorkerSshKeyChallenge, new Uri(issuer.AbsoluteUri + "/hch/worker-ssh-keys/challenges"))
            && SameUri(value.Endpoints.WorkerSshKeyRegistration, new Uri(issuer.AbsoluteUri + "/hch/worker-ssh-keys"))
            && IsTrustedHahPage(value.Endpoints.Login)
            && IsTrustedHahPage(value.Endpoints.PasswordRecovery)
            && IsTrustedHahPage(value.Endpoints.CreateAccount)
            && value.Token.Type == "Bearer"
            && value.Token.Format == "opaque"
            && value.Token.TtlSeconds is >= 60 and <= 3600
            && value.Token.Audience == NativeAudience
            && value.Token.Scope == "hch.worker.enroll.self"
            && !value.Token.RefreshTokenIssued
            && value.ProofOfPossession.Algorithm == "Ed25519"
            && value.ProofOfPossession.Canonicalization == "RFC8785"
            && value.ProofOfPossession.SignatureEncoding == "base64url-no-padding"
            && value.ProofOfPossession.ChallengeTtlSeconds is >= 30 and <= 600;
        if (!valid)
        {
            throw new HihDesktopAuthenticationException("A descoberta nativa do HIH não corresponde ao contrato homologado.");
        }
    }

    internal static void ValidateDiscoveryContract(ReadOnlySpan<byte> payload)
    {
        NativeDiscovery value = JsonSerializer.Deserialize<NativeDiscovery>(payload, JsonOptions)
            ?? throw new HihDesktopAuthenticationException("A descoberta nativa do HIH está vazia.");
        ValidateDiscovery(value);
    }

    private static bool SameUri(Uri? actual, Uri expected) =>
        actual is not null
        && actual.IsAbsoluteUri
        && actual.AbsoluteUri.Equals(expected.AbsoluteUri, StringComparison.Ordinal);

    private static bool IsCanonicalUuid(string? value) =>
        value is not null
        && Guid.TryParseExact(value, "D", out Guid parsed)
        && string.Equals(value, parsed.ToString("D"), StringComparison.Ordinal);

    private static bool IsTrustedHahPage(Uri? uri) =>
        uri is not null
        && uri.IsAbsoluteUri
        && uri.Scheme == Uri.UriSchemeHttps
        && uri.Host.Equals(HihOrigin.Host, StringComparison.OrdinalIgnoreCase)
        && uri.Port == 443
        && string.IsNullOrEmpty(uri.UserInfo)
        && string.IsNullOrEmpty(uri.Fragment);

    private static void OpenTrustedExternal(Uri uri)
    {
        if (!IsTrustedHahPage(uri))
        {
            throw new HihDesktopAuthenticationException("O HIH retornou uma URL externa não autorizada.");
        }

        _ = Process.Start(new ProcessStartInfo(uri.AbsoluteUri) { UseShellExecute = true });
    }

    private static HchSelfEnrollmentToken ParseSelfEnrollmentToken(
        ReadOnlySpan<byte> payload,
        string expectedNodeId,
        string expectedOwnerSshKeyId,
        string expectedOwnerSshKeyFingerprint)
    {
        byte[]? token = null;
        try
        {
            var reader = new Utf8JsonReader(payload, new JsonReaderOptions
            {
                AllowTrailingCommas = false,
                CommentHandling = JsonCommentHandling.Disallow,
                MaxDepth = 16,
            });
            if (!reader.Read() || reader.TokenType != JsonTokenType.StartObject)
            {
                throw new JsonException();
            }

            SelfEnrollmentRecord? record = null;
            var fields = new HashSet<string>(StringComparer.Ordinal);
            while (reader.Read() && reader.TokenType != JsonTokenType.EndObject)
            {
                if (reader.TokenType != JsonTokenType.PropertyName)
                {
                    throw new JsonException();
                }

                string property = reader.GetString() ?? throw new JsonException();
                if (!fields.Add(property) || !reader.Read())
                {
                    throw new JsonException();
                }

                if (property == "token")
                {
                    if (reader.TokenType != JsonTokenType.String || reader.ValueIsEscaped || reader.HasValueSequence)
                    {
                        throw new JsonException();
                    }

                    ReadOnlySpan<byte> value = reader.ValueSpan;
                    if (!IsEnrollmentToken(value))
                    {
                        throw new JsonException();
                    }

                    token = value.ToArray();
                }
                else if (property == "record")
                {
                    using JsonDocument document = JsonDocument.ParseValue(ref reader);
                    record = document.RootElement.Deserialize<SelfEnrollmentRecord>(JsonOptions)
                        ?? throw new JsonException();
                }
                else
                {
                    throw new JsonException();
                }
            }

            if (reader.TokenType != JsonTokenType.EndObject || reader.Read() || token is null || record is null
                || !Guid.TryParseExact(record.Id, "D", out _)
                || record.Status is not ("active" or "consumed")
                || record.ExpiresAt <= DateTimeOffset.UtcNow
                || record.ExpiresAt > DateTimeOffset.UtcNow.AddMinutes(11)
                || record.IntendedNodeId != expectedNodeId
                || record.OwnerSshKeyId != expectedOwnerSshKeyId
                || record.OwnerSshKeyFingerprint != expectedOwnerSshKeyFingerprint
                || record.EnrollmentProtocol != "operational-key-proof-v1")
            {
                throw new JsonException();
            }

            byte[] resultToken = token;
            token = null;
            return new HchSelfEnrollmentToken(
                resultToken,
                record.Id,
                record.ExpiresAt,
                record.IntendedNodeId,
                record.OwnerSshKeyId,
                record.OwnerSshKeyFingerprint);
        }
        catch (JsonException)
        {
            throw new HihDesktopAuthenticationException("O HCH retornou um token self-service inválido.");
        }
        finally
        {
            if (token is not null)
            {
                CryptographicOperations.ZeroMemory(token);
            }
        }
    }

    private static bool IsEnrollmentToken(ReadOnlySpan<byte> value)
    {
        ReadOnlySpan<byte> prefix = "hch_enroll_"u8;
        return value.Length == prefix.Length + 43
            && value.StartsWith(prefix)
            && value[prefix.Length..].IndexOfAnyExcept(
                "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"u8) < 0;
    }

    private static bool IsBase64Url(string value, int length) =>
        value.Length == length
        && value.All(static character => char.IsAsciiLetterOrDigit(character) || character is '-' or '_');

    private static byte[] SerializePasswordRequest(string email, string password, string tenantId)
    {
        using var stream = new MemoryStream();
        using (var writer = new Utf8JsonWriter(stream))
        {
            writer.WriteStartObject();
            writer.WriteString("clientId", NativeClientId);
            writer.WriteString("email", email);
            writer.WriteString("password", password);
            writer.WriteString("tenantId", tenantId);
            writer.WriteEndObject();
        }

        return stream.ToArray();
    }

    private static byte[] SerializeRevokeRequest(ReadOnlySpan<char> token)
    {
        using var stream = new MemoryStream();
        using (var writer = new Utf8JsonWriter(stream))
        {
            writer.WriteStartObject();
            writer.WriteString("token", token);
            writer.WriteEndObject();
        }

        return stream.ToArray();
    }

    private static ByteArrayContent JsonContent<T>(T value)
    {
        byte[] bytes = JsonSerializer.SerializeToUtf8Bytes(value, JsonOptions);
        var content = new ByteArrayContent(bytes);
        content.Headers.ContentType = new MediaTypeHeaderValue("application/json") { CharSet = "utf-8" };
        return content;
    }

    private static HttpRequestMessage NewRequest(HttpMethod method, Uri endpoint) => new(method, endpoint);

    private static HttpRequestMessage NewAuthorizedRequest(HttpMethod method, Uri endpoint, char[] token)
    {
        var request = NewRequest(method, endpoint);
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", new string(token));
        return request;
    }

    private static async Task<T> SendJsonAsync<T>(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        using HttpResponseMessage response = await SendHttpAsync(request, cancellationToken).ConfigureAwait(false);
        byte[] payload = await ReadBoundedAsync(response.Content, cancellationToken).ConfigureAwait(false);
        try
        {
            if (!response.IsSuccessStatusCode)
            {
                ApiErrorEnvelope? error = TryDeserialize<ApiErrorEnvelope>(payload);
                throw new HihDesktopAuthenticationException(
                    error?.Error.Message ?? "O HIH recusou a solicitação de onboarding.");
            }

            return JsonSerializer.Deserialize<T>(payload, JsonOptions)
                ?? throw new HihDesktopAuthenticationException("O HIH retornou uma resposta vazia.");
        }
        catch (JsonException)
        {
            throw new HihDesktopAuthenticationException("O HIH retornou uma resposta inválida.");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(payload);
        }
    }

    private static async Task<HttpResponseMessage> SendHttpAsync(
        HttpRequestMessage request,
        CancellationToken cancellationToken)
    {
        try
        {
            return await Http.SendAsync(
                request,
                HttpCompletionOption.ResponseHeadersRead,
                cancellationToken).ConfigureAwait(false);
        }
        catch (HttpRequestException)
        {
            throw new HihDesktopAuthenticationException("Não foi possível estabelecer uma conexão segura com o HIH.");
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            throw new HihDesktopAuthenticationException("A comunicação com o HIH excedeu o tempo limite.");
        }
    }

    private static async Task<byte[]> ReadBoundedAsync(HttpContent content, CancellationToken cancellationToken)
    {
        if (content.Headers.ContentLength is > MaximumResponseBytes)
        {
            throw new HihDesktopAuthenticationException("A resposta do HIH excedeu o limite permitido.");
        }

        await using Stream source = await content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
        using var destination = new MemoryStream();
        byte[] buffer = new byte[16 * 1024];
        try
        {
            int read;
            while ((read = await source.ReadAsync(buffer, cancellationToken).ConfigureAwait(false)) > 0)
            {
                if (destination.Length + read > MaximumResponseBytes)
                {
                    throw new HihDesktopAuthenticationException("A resposta do HIH excedeu o limite permitido.");
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

    private static T? TryDeserialize<T>(ReadOnlySpan<byte> payload)
    {
        try
        {
            return JsonSerializer.Deserialize<T>(payload, JsonOptions);
        }
        catch (JsonException)
        {
            return default;
        }
    }

    private static Uri BuildUri(Uri endpoint, IReadOnlyDictionary<string, string> query)
    {
        string encoded = string.Join('&', query.Select(static pair =>
            $"{Uri.EscapeDataString(pair.Key)}={Uri.EscapeDataString(pair.Value)}"));
        return new UriBuilder(endpoint) { Query = encoded }.Uri;
    }

    private static string Base64Url(ReadOnlySpan<byte> value) =>
        Convert.ToBase64String(value).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    private static HttpClient CreateHttpClient()
    {
        var handler = new SocketsHttpHandler
        {
            AllowAutoRedirect = false,
            UseCookies = false,
            AutomaticDecompression = DecompressionMethods.GZip | DecompressionMethods.Deflate,
            ConnectTimeout = TimeSpan.FromSeconds(10),
        };
        var client = new HttpClient(handler)
        {
            BaseAddress = HihOrigin,
            Timeout = TimeSpan.FromSeconds(30),
        };
        client.DefaultRequestHeaders.UserAgent.ParseAdd("HCH-Worker/4.0.0");
        client.DefaultRequestHeaders.Accept.ParseAdd("application/json");
        return client;
    }

    private static JsonSerializerOptions JsonOptions { get; } = new(JsonSerializerDefaults.Web)
    {
        AllowTrailingCommas = false,
        MaxDepth = 24,
        PropertyNameCaseInsensitive = false,
        ReadCommentHandling = JsonCommentHandling.Disallow,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
    };

    private sealed record NativeSession(
        char[] AccessToken,
        DateTimeOffset ExpiresAt,
        string UserId,
        string TenantId)
    {
        public void Clear() => AccessToken.AsSpan().Clear();
    }

    private sealed record NativeTokenResponse(
        [property: JsonPropertyName("access_token")] string AccessToken,
        [property: JsonPropertyName("token_type")] string TokenType,
        [property: JsonPropertyName("expires_in")] int ExpiresIn,
        [property: JsonPropertyName("expires_at")] DateTimeOffset ExpiresAt,
        string Audience,
        string Scope,
        NativeIdentity Identity);

    private sealed record NativeIdentity(
        string NativeSessionId,
        string ClientId,
        string Audience,
        string UserId,
        string PersonId,
        string TenantId,
        string MembershipId,
        string Email,
        string DisplayName,
        IReadOnlyList<string> Permissions,
        DateTimeOffset ExpiresAt);

    private sealed record NativeDiscovery(
        string SchemaVersion,
        Uri Issuer,
        NativeDiscoveryResource Resource,
        NativeDiscoveryClient Client,
        NativeDiscoveryCapabilities Capabilities,
        NativeDiscoveryEndpoints Endpoints,
        NativeDiscoveryToken Token,
        NativeDiscoveryProof ProofOfPossession);

    private sealed record NativeDiscoveryResource(
        string Audience,
        string TenantId,
        string TenantName,
        string TenantSlug,
        bool MembershipRequired);

    private sealed record NativeDiscoveryClient(
        string ClientId,
        string ClientType,
        bool ClientSecretRequired,
        string RedirectUriPattern);

    private sealed record NativeDiscoveryCapabilities(
        bool AuthorizationCodePkce,
        IReadOnlyList<string> PkceCodeChallengeMethods,
        bool DeviceCode,
        bool NativePassword,
        bool MfaVerification,
        string MfaRequiredPolicy);

    private sealed record NativeDiscoveryEndpoints(
        Uri Authorization,
        Uri Token,
        Uri Revoke,
        Uri Session,
        Uri NativePassword,
        Uri? DeviceAuthorization,
        Uri WorkerSshKeyChallenge,
        Uri WorkerSshKeyRegistration,
        Uri Login,
        Uri PasswordRecovery,
        Uri CreateAccount);

    private sealed record NativeDiscoveryToken(
        string Type,
        string Format,
        int TtlSeconds,
        string Audience,
        string Scope,
        bool RefreshTokenIssued);

    private sealed record NativeDiscoveryProof(
        string Algorithm,
        string Canonicalization,
        string SignatureEncoding,
        int ChallengeTtlSeconds);

    private sealed record RegisteredKeyResponse(RegisteredKey Key, bool ProofVerified);

    private sealed record RegisteredKey(
        string Id,
        string Label,
        string Algorithm,
        string Fingerprint,
        string PublicKeyPem,
        string PublicKeyOpenSsh,
        DateTimeOffset CreatedAt);

    private sealed record SelfEnrollmentRecord(
        string Id,
        string Status,
        DateTimeOffset ExpiresAt,
        string IntendedNodeId,
        string OwnerSshKeyId,
        string OwnerSshKeyFingerprint,
        string EnrollmentProtocol);

    private sealed record ApiErrorEnvelope(ApiErrorDetail Error);

    private sealed record ApiErrorDetail(string Code, string Message, int Status);
}

internal sealed class HihDesktopLoginRequiredException() : Exception("HAH login is required.");

public sealed class HihDesktopAuthenticationException : Exception
{
    public HihDesktopAuthenticationException(string userMessage)
        : this(userMessage, null)
    {
    }

    internal HihDesktopAuthenticationException(string userMessage, Exception? innerException)
        : base("HIH native onboarding failed.", innerException)
    {
        UserMessage = userMessage.Length <= 240
            ? userMessage
            : "O HIH recusou a solicitação de onboarding.";
    }

    public string UserMessage { get; }
}
