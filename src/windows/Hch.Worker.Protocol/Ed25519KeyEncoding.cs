using System.Security.Cryptography;

namespace Hch.Worker.Protocol;

/// <summary>Strict Ed25519 public-key encoding and fingerprint helpers.</summary>
public static class Ed25519KeyEncoding
{
    private static ReadOnlySpan<byte> SubjectPublicKeyInfoPrefix =>
        [0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00];

    public const int RawPublicKeyLength = 32;
    public const int SubjectPublicKeyInfoLength = 44;
    public const int SignatureLength = 64;

    /// <summary>Wraps a raw 32-byte Ed25519 key in the RFC 8410 SPKI encoding.</summary>
    public static byte[] CreateSubjectPublicKeyInfo(ReadOnlySpan<byte> rawPublicKey)
    {
        if (rawPublicKey.Length != RawPublicKeyLength)
        {
            throw new ProtocolValidationException(
                "ed25519-public-key-length-invalid",
                "An Ed25519 public key must contain exactly 32 bytes.");
        }

        var result = new byte[SubjectPublicKeyInfoLength];
        SubjectPublicKeyInfoPrefix.CopyTo(result);
        rawPublicKey.CopyTo(result.AsSpan(SubjectPublicKeyInfoPrefix.Length));
        return result;
    }

    /// <summary>Validates and copies a parameter-free RFC 8410 Ed25519 SPKI.</summary>
    public static byte[] NormalizeSubjectPublicKeyInfo(ReadOnlySpan<byte> subjectPublicKeyInfo)
    {
        if (subjectPublicKeyInfo.Length != SubjectPublicKeyInfoLength
            || !subjectPublicKeyInfo[..SubjectPublicKeyInfoPrefix.Length].SequenceEqual(SubjectPublicKeyInfoPrefix))
        {
            throw new ProtocolValidationException(
                "ed25519-spki-invalid",
                "Only a parameter-free RFC 8410 Ed25519 SubjectPublicKeyInfo is accepted.");
        }

        return subjectPublicKeyInfo.ToArray();
    }

    /// <summary>Reads an exact PEM PUBLIC KEY block and validates its SPKI.</summary>
    public static byte[] DecodePublicKeyPem(string pem)
    {
        ArgumentNullException.ThrowIfNull(pem);
        const string label = "PUBLIC KEY";
        var trimmed = pem.AsSpan().Trim();
        if (!PemEncoding.TryFind(trimmed, out var fields))
        {
            throw new ProtocolValidationException("ed25519-pem-invalid", "Expected one PEM encoded PUBLIC KEY.");
        }

        var location = fields.Location.GetOffsetAndLength(trimmed.Length);
        if (!trimmed[fields.Label].SequenceEqual(label)
            || location.Offset != 0
            || location.Length != trimmed.Length)
        {
            throw new ProtocolValidationException("ed25519-pem-invalid", "Expected one PEM encoded PUBLIC KEY.");
        }

        var decoded = new byte[fields.DecodedDataLength];
        if (!Convert.TryFromBase64Chars(trimmed[fields.Base64Data], decoded, out var bytesWritten)
            || bytesWritten != decoded.Length)
        {
            throw new ProtocolValidationException("ed25519-pem-invalid", "Expected one PEM encoded PUBLIC KEY.");
        }

        return NormalizeSubjectPublicKeyInfo(decoded);
    }

    /// <summary>Encodes a validated Ed25519 SPKI as a PEM PUBLIC KEY.</summary>
    public static string EncodePublicKeyPem(ReadOnlySpan<byte> subjectPublicKeyInfo)
    {
        var normalized = NormalizeSubjectPublicKeyInfo(subjectPublicKeyInfo);
        return PemEncoding.WriteString("PUBLIC KEY", normalized);
    }

    /// <summary>
    /// Computes the stable HCH fingerprint over the complete SPKI bytes.
    /// </summary>
    public static string Fingerprint(ReadOnlySpan<byte> subjectPublicKeyInfo)
    {
        var normalized = NormalizeSubjectPublicKeyInfo(subjectPublicKeyInfo);
        return "SHA256:" + HchDigest.Base64UrlEncode(SHA256.HashData(normalized));
    }

    /// <summary>Returns the raw 32-byte key after strict SPKI validation.</summary>
    public static byte[] GetRawPublicKey(ReadOnlySpan<byte> subjectPublicKeyInfo)
    {
        var normalized = NormalizeSubjectPublicKeyInfo(subjectPublicKeyInfo);
        return normalized[SubjectPublicKeyInfoPrefix.Length..];
    }
}
