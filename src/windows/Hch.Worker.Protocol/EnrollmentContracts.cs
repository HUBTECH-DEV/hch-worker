using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;

namespace Hch.Worker.Protocol;

/// <summary>Wire contract for the HCH Worker 4 operational-key enrollment.</summary>
public static partial class OperationalEnrollmentContract
{
    public const string Protocol = "operational-key-proof-v1";
    public const string ProofDomain = "hch-editorial-worker-enrollment/operational-key-proof-v1";
    public const string RuntimeVersion = "4.0.0";
    public const string ChallengePath = "/api/editorial/orchestrator/enrollment/challenge";
    public const string EnrollmentPath = "/api/editorial/orchestrator/enrollment";

    public static OperationalEnrollmentChallengeRequest CreateChallengeRequest(
        string nodeId,
        string keyId,
        string publicKeyPem,
        DateTimeOffset? keyExpiresAt = null)
    {
        nodeId = RequiredIdentifier(nodeId, "nodeId", NodeIdentifier());
        keyId = RequiredIdentifier(keyId, "keyId", ProofIdentifier());
        publicKeyPem = NormalizePublicKeyPem(publicKeyPem);
        string? expiresAt = keyExpiresAt is null ? null : JavaScriptIsoTimestamp(keyExpiresAt.Value);

        var seed = new OperationalEnrollmentRequestSeed(
            expiresAt,
            keyId,
            nodeId,
            Protocol,
            publicKeyPem,
            RuntimeVersion);
        byte[] seedHash = SHA256.HashData(ProtocolJson.SerializeCanonicalToUtf8(seed));
        string requestId;
        try
        {
            requestId = $"enroll-v4-{Convert.ToHexStringLower(seedHash)}";
        }
        finally
        {
            CryptographicOperations.ZeroMemory(seedHash);
        }

        return new OperationalEnrollmentChallengeRequest(
            Protocol,
            requestId,
            nodeId,
            keyId,
            publicKeyPem,
            RuntimeVersion,
            expiresAt);
    }

    public static string ComputeRequestHash(OperationalEnrollmentChallengeRequest request)
    {
        Validate(request);
        var hashInput = new OperationalEnrollmentRequestHashInput(
            request.ExpiresAt,
            request.KeyId,
            request.NodeId,
            request.Protocol,
            request.PublicKeyPem,
            request.RequestId,
            request.WorkerRuntimeVersion);
        byte[] digest = SHA256.HashData(ProtocolJson.SerializeCanonicalToUtf8(hashInput));
        try
        {
            return Convert.ToHexStringLower(digest);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(digest);
        }
    }

    public static void Validate(OperationalEnrollmentChallengeRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        RequireConstant(request.Protocol, Protocol, "enrollment-protocol-invalid");
        _ = RequiredIdentifier(request.RequestId, "requestId", ProofIdentifier());
        _ = RequiredIdentifier(request.NodeId, "nodeId", NodeIdentifier());
        _ = RequiredIdentifier(request.KeyId, "keyId", ProofIdentifier());
        _ = NormalizePublicKeyPem(request.PublicKeyPem);
        RequireConstant(request.WorkerRuntimeVersion, RuntimeVersion, "enrollment-runtime-version-invalid");
        if (request.ExpiresAt is not null && request.ExpiresAt != NormalizeJavaScriptIsoTimestamp(request.ExpiresAt))
        {
            throw Invalid("enrollment-key-expiration-invalid");
        }
    }

    public static void ValidateChallenge(
        OperationalEnrollmentChallengeRequest request,
        OperationalEnrollmentChallengeResponse response,
        string expectedOwnerSshKeyId,
        string expectedOwnerSshKeyFingerprint,
        DateTimeOffset now)
    {
        Validate(request);
        ArgumentNullException.ThrowIfNull(response);
        ArgumentNullException.ThrowIfNull(response.Proof);
        ArgumentNullException.ThrowIfNull(response.SignatureProfile);

        RequireConstant(response.Protocol, Protocol, "enrollment-challenge-protocol-invalid");
        RequireConstant(response.Proof.Protocol, Protocol, "enrollment-proof-protocol-invalid");
        RequireConstant(response.Proof.Domain, ProofDomain, "enrollment-proof-domain-invalid");
        RequireConstant(response.SignatureProfile.Algorithm, "Ed25519", "enrollment-signature-algorithm-invalid");
        RequireConstant(response.SignatureProfile.Encoding, "base64url", "enrollment-signature-encoding-invalid");
        RequireConstant(response.SignatureProfile.Canonicalization, "RFC8785", "enrollment-canonicalization-invalid");

        string challengeId = RequiredIdentifier(response.ChallengeId, "challengeId", BroadIdentifier());
        string challenge = RequiredChallenge(response.Challenge);
        string expiresAt = NormalizeJavaScriptIsoTimestamp(response.ExpiresAt);
        DateTimeOffset challengeExpiration = DateTimeOffset.ParseExact(
            expiresAt,
            "yyyy-MM-dd'T'HH:mm:ss.fff'Z'",
            CultureInfo.InvariantCulture,
            DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal);
        if (challengeExpiration <= now.Subtract(TimeSpan.FromSeconds(5)) ||
            challengeExpiration > now.AddMinutes(6))
        {
            throw Invalid("enrollment-challenge-expired");
        }

        var proof = response.Proof;
        RequireConstant(proof.ChallengeId, challengeId, "enrollment-proof-challenge-id-mismatch");
        RequireConstant(proof.Challenge, challenge, "enrollment-proof-challenge-mismatch");
        RequireConstant(proof.ExpiresAt, expiresAt, "enrollment-proof-expiration-mismatch");
        RequireConstant(proof.RequestId, request.RequestId, "enrollment-proof-request-id-mismatch");
        RequireConstant(proof.RequestHash, ComputeRequestHash(request), "enrollment-proof-request-hash-mismatch");
        RequireConstant(proof.WorkerNodeId, request.NodeId, "enrollment-proof-node-id-mismatch");
        RequireConstant(proof.WorkerKeyId, request.KeyId, "enrollment-proof-key-id-mismatch");
        RequireConstant(proof.WorkerRuntimeVersion, request.WorkerRuntimeVersion, "enrollment-proof-runtime-version-mismatch");

        byte[] subjectPublicKeyInfo = Ed25519KeyEncoding.DecodePublicKeyPem(request.PublicKeyPem);
        string workerFingerprint;
        try
        {
            workerFingerprint = Ed25519KeyEncoding.Fingerprint(subjectPublicKeyInfo);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(subjectPublicKeyInfo);
        }

        RequireConstant(
            proof.WorkerPublicKeyFingerprint,
            workerFingerprint,
            "enrollment-proof-worker-fingerprint-mismatch");
        expectedOwnerSshKeyId = RequiredIdentifier(
            expectedOwnerSshKeyId,
            "ownerSshKeyId",
            BroadIdentifier());
        expectedOwnerSshKeyFingerprint = RequiredFingerprint(expectedOwnerSshKeyFingerprint);
        RequireConstant(
            proof.OwnerSshKeyId,
            expectedOwnerSshKeyId,
            "enrollment-proof-owner-key-id-mismatch");
        RequireConstant(
            proof.OwnerSshKeyFingerprint,
            expectedOwnerSshKeyFingerprint,
            "enrollment-proof-owner-fingerprint-mismatch");
        if (CryptographicOperations.FixedTimeEquals(
                Encoding.ASCII.GetBytes(workerFingerprint),
                Encoding.ASCII.GetBytes(expectedOwnerSshKeyFingerprint)))
        {
            throw Invalid("enrollment-identities-not-distinct");
        }

        _ = RequiredIdentifier(proof.OwnerUserId, "ownerUserId", BroadIdentifier());
        _ = RequiredIdentifier(proof.TokenId, "tokenId", BroadIdentifier());
    }

    public static async Task<OperationalEnrollmentRequest> CreateEnrollmentRequestAsync(
        OperationalEnrollmentChallengeRequest request,
        OperationalEnrollmentChallengeResponse challenge,
        string expectedOwnerSshKeyId,
        string expectedOwnerSshKeyFingerprint,
        IEd25519SignatureProvider signatureProvider,
        DateTimeOffset now,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(signatureProvider);
        ValidateChallenge(request, challenge, expectedOwnerSshKeyId, expectedOwnerSshKeyFingerprint, now);
        byte[] canonicalProof = ProtocolJson.SerializeCanonicalToUtf8(challenge.Proof);
        byte[]? signature = null;
        try
        {
            signature = await signatureProvider.SignAsync(canonicalProof, cancellationToken).ConfigureAwait(false);
            if (signature.Length != Ed25519KeyEncoding.SignatureLength)
            {
                throw Invalid("enrollment-proof-signature-length-invalid");
            }

            return new OperationalEnrollmentRequest(
                request.Protocol,
                request.RequestId,
                request.NodeId,
                request.KeyId,
                request.PublicKeyPem,
                request.WorkerRuntimeVersion,
                request.ExpiresAt,
                challenge.ChallengeId,
                challenge.Challenge,
                HchDigest.Base64UrlEncode(signature));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(canonicalProof);
            if (signature is not null)
            {
                CryptographicOperations.ZeroMemory(signature);
            }
        }
    }

    public static void Validate(
        OperationalEnrollmentResponse response,
        OperationalEnrollmentChallengeRequest request,
        OperationalEnrollmentChallengeResponse challenge)
    {
        ArgumentNullException.ThrowIfNull(response);
        RequireConstant(response.NodeId, request.NodeId, "enrollment-response-node-id-mismatch");
        RequireConstant(response.KeyId, request.KeyId, "enrollment-response-key-id-mismatch");
        RequireConstant(response.EnrollmentProtocol, Protocol, "enrollment-response-protocol-mismatch");
        RequireConstant(response.Status, "active", "enrollment-response-status-invalid");
        RequireConstant(
            RequiredFingerprint(response.Fingerprint),
            challenge.Proof.WorkerPublicKeyFingerprint,
            "enrollment-response-worker-fingerprint-mismatch");
        RequireConstant(
            response.OwnerUserId,
            challenge.Proof.OwnerUserId,
            "enrollment-response-owner-user-mismatch");
        RequireConstant(
            response.OwnerSshKeyId,
            challenge.Proof.OwnerSshKeyId,
            "enrollment-response-owner-key-id-mismatch");
        RequireConstant(
            RequiredFingerprint(response.OwnerSshKeyFingerprint),
            challenge.Proof.OwnerSshKeyFingerprint,
            "enrollment-response-owner-fingerprint-mismatch");
        if (string.IsNullOrWhiteSpace(response.OwnerEmail) || response.OwnerEmail.Length > 254 ||
            !response.OwnerEmail.Contains('@', StringComparison.Ordinal))
        {
            throw Invalid("enrollment-response-owner-email-invalid");
        }

        _ = NormalizeJavaScriptIsoTimestamp(response.EnrolledAt);
    }

    private static string NormalizePublicKeyPem(string value)
    {
        string pem = (value ?? string.Empty).Trim();
        byte[] subjectPublicKeyInfo = Ed25519KeyEncoding.DecodePublicKeyPem(pem);
        try
        {
            return Ed25519KeyEncoding.EncodePublicKeyPem(subjectPublicKeyInfo).Trim();
        }
        finally
        {
            CryptographicOperations.ZeroMemory(subjectPublicKeyInfo);
        }
    }

    private static string JavaScriptIsoTimestamp(DateTimeOffset value) =>
        value.UtcDateTime.ToString("yyyy-MM-dd'T'HH:mm:ss.fff'Z'", CultureInfo.InvariantCulture);

    private static string NormalizeJavaScriptIsoTimestamp(string value)
    {
        if (!DateTimeOffset.TryParse(
                value,
                CultureInfo.InvariantCulture,
                DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal,
                out var parsed))
        {
            throw Invalid("enrollment-timestamp-invalid");
        }

        return JavaScriptIsoTimestamp(parsed);
    }

    private static string RequiredIdentifier(string value, string name, Regex expression)
    {
        string text = (value ?? string.Empty).Trim();
        if (!expression.IsMatch(text))
        {
            throw Invalid($"enrollment-{name.ToLowerInvariant()}-invalid");
        }

        return text;
    }

    private static string RequiredFingerprint(string value)
    {
        string text = value ?? string.Empty;
        if (!Fingerprint().IsMatch(text))
        {
            throw Invalid("enrollment-fingerprint-invalid");
        }

        return text;
    }

    private static string RequiredChallenge(string value)
    {
        string text = value ?? string.Empty;
        if (!Challenge().IsMatch(text))
        {
            throw Invalid("enrollment-challenge-invalid");
        }

        return text;
    }

    private static void RequireConstant(string actual, string expected, string code)
    {
        byte[] actualBytes = Encoding.UTF8.GetBytes(actual ?? string.Empty);
        byte[] expectedBytes = Encoding.UTF8.GetBytes(expected);
        try
        {
            if (actualBytes.Length != expectedBytes.Length ||
                !CryptographicOperations.FixedTimeEquals(actualBytes, expectedBytes))
            {
                throw Invalid(code);
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(actualBytes);
            CryptographicOperations.ZeroMemory(expectedBytes);
        }
    }

    private static ProtocolValidationException Invalid(string code) => new(
        code,
        "The operational enrollment contract is invalid.");

    [GeneratedRegex("^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$", RegexOptions.CultureInvariant)]
    private static partial Regex NodeIdentifier();

    [GeneratedRegex("^[A-Za-z0-9][A-Za-z0-9._:-]{0,159}$", RegexOptions.CultureInvariant)]
    private static partial Regex ProofIdentifier();

    [GeneratedRegex("^[A-Za-z0-9][A-Za-z0-9._:@/|-]{0,255}$", RegexOptions.CultureInvariant)]
    private static partial Regex BroadIdentifier();

    [GeneratedRegex("^SHA256:[A-Za-z0-9_-]{43}$", RegexOptions.CultureInvariant)]
    private static partial Regex Fingerprint();

    [GeneratedRegex("^[A-Za-z0-9_-]{43}$", RegexOptions.CultureInvariant)]
    private static partial Regex Challenge();

    private sealed record OperationalEnrollmentRequestSeed(
        [property: JsonPropertyName("expiresAt")] string? ExpiresAt,
        [property: JsonPropertyName("keyId")] string KeyId,
        [property: JsonPropertyName("nodeId")] string NodeId,
        [property: JsonPropertyName("protocol")] string Protocol,
        [property: JsonPropertyName("publicKeyPem")] string PublicKeyPem,
        [property: JsonPropertyName("workerRuntimeVersion")] string WorkerRuntimeVersion);

    private sealed record OperationalEnrollmentRequestHashInput(
        [property: JsonPropertyName("expiresAt")] string? ExpiresAt,
        [property: JsonPropertyName("keyId")] string KeyId,
        [property: JsonPropertyName("nodeId")] string NodeId,
        [property: JsonPropertyName("protocol")] string Protocol,
        [property: JsonPropertyName("publicKeyPem")] string PublicKeyPem,
        [property: JsonPropertyName("requestId")] string RequestId,
        [property: JsonPropertyName("workerRuntimeVersion")] string WorkerRuntimeVersion);
}

public sealed record OperationalEnrollmentChallengeRequest(
    string Protocol,
    string RequestId,
    string NodeId,
    string KeyId,
    string PublicKeyPem,
    string WorkerRuntimeVersion,
    string? ExpiresAt);

public sealed record OperationalEnrollmentChallengeResponse(
    string Protocol,
    string ChallengeId,
    string Challenge,
    string ExpiresAt,
    OperationalEnrollmentProof Proof,
    OperationalEnrollmentSignatureProfile SignatureProfile);

public sealed record OperationalEnrollmentProof(
    string Challenge,
    string ChallengeId,
    string Domain,
    string ExpiresAt,
    string OwnerSshKeyFingerprint,
    string OwnerSshKeyId,
    string OwnerUserId,
    string Protocol,
    string RequestHash,
    string RequestId,
    string TokenId,
    string WorkerKeyId,
    string WorkerNodeId,
    string WorkerPublicKeyFingerprint,
    string WorkerRuntimeVersion);

public sealed record OperationalEnrollmentSignatureProfile(
    string Algorithm,
    string Encoding,
    string Canonicalization);

public sealed record OperationalEnrollmentRequest(
    string Protocol,
    string RequestId,
    string NodeId,
    string KeyId,
    string PublicKeyPem,
    string WorkerRuntimeVersion,
    string? ExpiresAt,
    string ChallengeId,
    string Challenge,
    string ProofSignature);

public sealed record OperationalEnrollmentResponse(
    string NodeId,
    string KeyId,
    string Fingerprint,
    string Status,
    string EnrolledAt,
    string EnrollmentProtocol,
    string OwnerUserId,
    string OwnerEmail,
    string OwnerSshKeyId,
    string OwnerSshKeyFingerprint);
