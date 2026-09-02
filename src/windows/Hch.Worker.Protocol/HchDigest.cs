using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace Hch.Worker.Protocol;

/// <summary>SHA-256 helpers used by the HCH wire protocol.</summary>
public static partial class HchDigest
{
    /// <summary>Calculates a lowercase SHA-256 hexadecimal digest.</summary>
    public static string Sha256Hex(ReadOnlySpan<byte> content) =>
        Convert.ToHexStringLower(SHA256.HashData(content));

    /// <summary>Calculates a lowercase SHA-256 digest over UTF-8 text.</summary>
    public static string Sha256Hex(string content)
    {
        ArgumentNullException.ThrowIfNull(content);
        return Sha256Hex(Encoding.UTF8.GetBytes(content));
    }

    /// <summary>Returns an RFC 9530 sha-256 Content-Digest field value.</summary>
    public static string CreateContentDigest(ReadOnlySpan<byte> content) =>
        $"sha-256=:{Convert.ToBase64String(SHA256.HashData(content))}:";

    /// <summary>Returns an RFC 9530 sha-256 Content-Digest for UTF-8 text.</summary>
    public static string CreateContentDigest(string content)
    {
        ArgumentNullException.ThrowIfNull(content);
        return CreateContentDigest(Encoding.UTF8.GetBytes(content));
    }

    /// <summary>Validates a lowercase protocol SHA-256 hexadecimal value.</summary>
    public static bool IsLowerSha256(string? value) =>
        value is not null && LowerSha256Pattern().IsMatch(value);

    /// <summary>Compares a received Content-Digest without data-dependent timing.</summary>
    public static bool MatchesContentDigest(string? fieldValue, ReadOnlySpan<byte> content)
    {
        if (!TryParseContentDigest(fieldValue, out var supplied))
        {
            return false;
        }

        var expected = SHA256.HashData(content);
        return CryptographicOperations.FixedTimeEquals(supplied, expected);
    }

    /// <summary>Parses the exact HCH RFC 9530 sha-256 dictionary member.</summary>
    public static bool TryParseContentDigest(string? fieldValue, out byte[] digest)
    {
        digest = [];
        if (fieldValue is null || !fieldValue.StartsWith("sha-256=:", StringComparison.Ordinal)
            || !fieldValue.EndsWith(':') || fieldValue.Length <= 10)
        {
            return false;
        }

        try
        {
            digest = Convert.FromBase64String(fieldValue[9..^1]);
            if (digest.Length != 32)
            {
                digest = [];
                return false;
            }

            return Convert.ToBase64String(digest).Equals(fieldValue[9..^1], StringComparison.Ordinal);
        }
        catch (FormatException)
        {
            digest = [];
            return false;
        }
    }

    internal static string Base64UrlEncode(ReadOnlySpan<byte> value) =>
        Convert.ToBase64String(value).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    internal static byte[] Base64UrlDecode(string value, string name)
    {
        ArgumentNullException.ThrowIfNull(value);
        if (value.Length == 0 || value.Any(character =>
                !char.IsAsciiLetterOrDigit(character) && character is not '-' and not '_'))
        {
            throw new ProtocolValidationException("base64url-invalid", $"{name} must be unpadded base64url.");
        }

        var padded = value.Replace('-', '+').Replace('_', '/');
        padded += (padded.Length % 4) switch
        {
            0 => string.Empty,
            2 => "==",
            3 => "=",
            _ => throw new ProtocolValidationException("base64url-invalid", $"{name} is invalid base64url."),
        };

        try
        {
            var decoded = Convert.FromBase64String(padded);
            if (!Base64UrlEncode(decoded).Equals(value, StringComparison.Ordinal))
            {
                throw new ProtocolValidationException("base64url-noncanonical", $"{name} is not canonical base64url.");
            }

            return decoded;
        }
        catch (FormatException error)
        {
            throw new ProtocolValidationException("base64url-invalid", $"{name} is invalid base64url.")
            {
                Data = { ["cause"] = error.GetType().FullName },
            };
        }
    }

    [GeneratedRegex("^[a-f0-9]{64}$", RegexOptions.CultureInvariant)]
    private static partial Regex LowerSha256Pattern();
}
