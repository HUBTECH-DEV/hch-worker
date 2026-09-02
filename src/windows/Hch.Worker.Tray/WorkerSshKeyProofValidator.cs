using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Hch.Worker.Protocol;
using Hch.Worker.Security;

namespace Hch.Worker.Tray;

internal sealed record WorkerSshKeyChallengeEnvelope(
    string ChallengeId,
    string Nonce,
    DateTimeOffset ExpiresAt,
    WorkerSshKeyChallengeProof Proof,
    WorkerSshKeyChallengePublicKey PublicKey);

internal sealed record WorkerSshKeyChallengeProof(
    string Canonicalization,
    string SignatureAlgorithm,
    JsonElement Payload,
    string CanonicalPayload);

internal sealed record WorkerSshKeyChallengePublicKey(
    string Algorithm,
    string Fingerprint,
    string PublicKeyPem,
    string PublicKeyOpenSsh);

internal sealed record WorkerSshKeyProofContext(
    string UserId,
    string TenantId,
    DateTimeOffset SessionExpiresAt,
    int ChallengeTtlSeconds);

internal sealed record WorkerSshKeyRegistrationProof(
    string Action,
    string Algorithm,
    string ChallengeId,
    string Fingerprint,
    string Label,
    string Nonce,
    string PublicKeySpki,
    string TenantId,
    string UserId);

/// <summary>
/// Capability object returned only after every server-controlled proof field has
/// been correlated with local/session state. It owns and clears the bytes that
/// the user identity is permitted to sign.
/// </summary>
internal sealed class ValidatedWorkerSshKeyProof : IDisposable
{
    private byte[]? canonicalPayload;

    private ValidatedWorkerSshKeyProof(byte[] canonicalPayload, string expectedFingerprint)
    {
        this.canonicalPayload = canonicalPayload;
        ExpectedFingerprint = expectedFingerprint;
    }

    internal ReadOnlyMemory<byte> CanonicalPayload => canonicalPayload
        ?? throw new ObjectDisposedException(nameof(ValidatedWorkerSshKeyProof));

    internal string ExpectedFingerprint { get; }

    internal static ValidatedWorkerSshKeyProof Create(
        byte[] canonicalPayload,
        string expectedFingerprint) =>
        new(canonicalPayload, expectedFingerprint);

    public void Dispose()
    {
        byte[]? value = Interlocked.Exchange(ref canonicalPayload, null);
        if (value is not null)
        {
            CryptographicOperations.ZeroMemory(value);
        }
    }
}

/// <summary>
/// Reconstructs the domain-separated RFC 8785 proof locally. Neither the
/// server-provided payload nor canonicalPayload is ever used as signing input.
/// </summary>
internal static class WorkerSshKeyProofValidator
{
    private const string ProofAction = "hih.worker-ssh-key.register";
    private const string ProofAlgorithm = "Ed25519";
    private const string ProofCanonicalization = "RFC8785";
    private static readonly UTF8Encoding StrictUtf8 = new(false, true);

    internal static ValidatedWorkerSshKeyProof Validate(
        WorkerSshKeyChallengeEnvelope challenge,
        UserSshPublicKey localKey,
        string expectedLabel,
        WorkerSshKeyProofContext context,
        DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(challenge);
        ArgumentNullException.ThrowIfNull(localKey);
        ArgumentException.ThrowIfNullOrWhiteSpace(expectedLabel);
        ArgumentNullException.ThrowIfNull(context);

        byte[]? localSpki = null;
        byte[]? challengeOpenSshSpki = null;
        byte[]? challengePemSpki = null;
        byte[]? nonce = null;
        byte[]? expectedCanonical = null;
        byte[]? suppliedPayloadCanonical = null;
        byte[]? suppliedCanonicalText = null;
        try
        {
            if (!IsCanonicalUuid(challenge.ChallengeId)
                || !TryDecodeCanonicalBase64Url(challenge.Nonce, 32, out nonce)
                || challenge.ExpiresAt <= now
                || challenge.ExpiresAt > now.AddSeconds(context.ChallengeTtlSeconds + 30)
                || challenge.ExpiresAt > context.SessionExpiresAt
                || context.ChallengeTtlSeconds is < 30 or > 600
                || !string.Equals(
                    challenge.Proof.Canonicalization,
                    ProofCanonicalization,
                    StringComparison.Ordinal)
                || !string.Equals(
                    challenge.Proof.SignatureAlgorithm,
                    ProofAlgorithm,
                    StringComparison.Ordinal)
                || challenge.Proof.Payload.ValueKind != JsonValueKind.Object
                || !string.Equals(localKey.Algorithm, "ssh-ed25519", StringComparison.Ordinal)
                || !IsCanonicalUuid(context.UserId)
                || !IsCanonicalUuid(context.TenantId)
                || expectedLabel.Length is < 3 or > 120)
            {
                throw InvalidChallenge();
            }

            localSpki = OpenSshEd25519PublicKey.DecodeSubjectPublicKeyInfo(localKey.PublicKey);
            challengeOpenSshSpki = OpenSshEd25519PublicKey.DecodeSubjectPublicKeyInfo(
                challenge.PublicKey.PublicKeyOpenSsh);
            challengePemSpki = Ed25519KeyEncoding.DecodePublicKeyPem(
                challenge.PublicKey.PublicKeyPem);
            string localFingerprint = Ed25519KeyEncoding.Fingerprint(localSpki);
            if (!string.Equals(challenge.PublicKey.Algorithm, ProofAlgorithm, StringComparison.Ordinal)
                || !FixedTextEquals(localKey.Fingerprint, localFingerprint)
                || !FixedTextEquals(challenge.PublicKey.Fingerprint, localFingerprint)
                || !FixedBytesEqual(localSpki, challengeOpenSshSpki)
                || !FixedBytesEqual(localSpki, challengePemSpki))
            {
                throw InvalidChallenge();
            }

            string spkiBase64Url = Base64Url(localSpki);
            var expected = new WorkerSshKeyRegistrationProof(
                ProofAction,
                ProofAlgorithm,
                challenge.ChallengeId,
                localFingerprint,
                expectedLabel,
                challenge.Nonce,
                spkiBase64Url,
                context.TenantId,
                context.UserId);
            expectedCanonical = ProtocolJson.SerializeCanonicalToUtf8(expected);

            suppliedPayloadCanonical = JcsCanonicalizer.CanonicalizeToUtf8(
                StrictUtf8.GetBytes(challenge.Proof.Payload.GetRawText()));
            suppliedCanonicalText = StrictUtf8.GetBytes(challenge.Proof.CanonicalPayload);
            if (!FixedBytesEqual(expectedCanonical, suppliedPayloadCanonical)
                || !FixedBytesEqual(expectedCanonical, suppliedCanonicalText))
            {
                throw InvalidChallenge();
            }

            byte[] ownedCanonical = expectedCanonical;
            expectedCanonical = null;
            return ValidatedWorkerSshKeyProof.Create(ownedCanonical, localFingerprint);
        }
        catch (HihDesktopAuthenticationException)
        {
            throw;
        }
        catch (Exception error) when (error is CryptographicException
            or JsonException or DecoderFallbackException
            or Hch.Worker.Protocol.ProtocolValidationException
            or ArgumentException or FormatException or OverflowException)
        {
            throw new HihDesktopAuthenticationException(
                "O HIH retornou um desafio de prova de posse inválido.",
                error);
        }
        finally
        {
            Zero(localSpki);
            Zero(challengeOpenSshSpki);
            Zero(challengePemSpki);
            Zero(nonce);
            Zero(expectedCanonical);
            Zero(suppliedPayloadCanonical);
            Zero(suppliedCanonicalText);
        }
    }

    private static bool IsCanonicalUuid(string? value) =>
        value is not null
        && Guid.TryParseExact(value, "D", out Guid parsed)
        && string.Equals(value, parsed.ToString("D"), StringComparison.Ordinal);

    private static bool TryDecodeCanonicalBase64Url(
        string? value,
        int expectedBytes,
        out byte[]? decoded)
    {
        decoded = null;
        if (value is null || value.Length == 0 || value.Any(static character =>
                !(char.IsAsciiLetterOrDigit(character) || character is '-' or '_')))
        {
            return false;
        }

        string padded = value.Replace('-', '+').Replace('_', '/');
        padded += (padded.Length % 4) switch
        {
            0 => string.Empty,
            2 => "==",
            3 => "=",
            _ => "!",
        };
        try
        {
            byte[] candidate = Convert.FromBase64String(padded);
            if (candidate.Length != expectedBytes
                || !string.Equals(Base64Url(candidate), value, StringComparison.Ordinal))
            {
                CryptographicOperations.ZeroMemory(candidate);
                return false;
            }

            decoded = candidate;
            return true;
        }
        catch (FormatException)
        {
            return false;
        }
    }

    private static bool FixedTextEquals(string? left, string? right)
    {
        if (left is null || right is null)
        {
            return false;
        }

        byte[] leftBytes = StrictUtf8.GetBytes(left);
        byte[] rightBytes = StrictUtf8.GetBytes(right);
        try
        {
            return FixedBytesEqual(leftBytes, rightBytes);
        }
        finally
        {
            Zero(leftBytes);
            Zero(rightBytes);
        }
    }

    private static bool FixedBytesEqual(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right)
    {
        byte[] leftHash = SHA256.HashData(left);
        byte[] rightHash = SHA256.HashData(right);
        try
        {
            bool digestMatches = CryptographicOperations.FixedTimeEquals(leftHash, rightHash);
            bool exactMatches = left.Length == right.Length
                && CryptographicOperations.FixedTimeEquals(left, right);
            return digestMatches & exactMatches;
        }
        finally
        {
            Zero(leftHash);
            Zero(rightHash);
        }
    }

    private static string Base64Url(ReadOnlySpan<byte> value) =>
        Convert.ToBase64String(value).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    private static HihDesktopAuthenticationException InvalidChallenge() =>
        new("O HIH retornou um desafio de prova de posse inválido.");

    private static void Zero(byte[]? value)
    {
        if (value is not null)
        {
            CryptographicOperations.ZeroMemory(value);
        }
    }
}
