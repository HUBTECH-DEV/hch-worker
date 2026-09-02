using System.Security.Cryptography;
using System.Text;

namespace Hch.Worker.Tray;

internal enum LoopbackAuthorizationCallbackKind
{
    Invalid,
    AuthorizationCode,
    LoginRequired,
    AccessDenied,
    ServerError,
}

internal readonly record struct LoopbackAuthorizationCallback(
    LoopbackAuthorizationCallbackKind Kind,
    string? AuthorizationCode = null);

internal static class LoopbackAuthorizationCallbackParser
{
    private const string CallbackPath = "/callback";
    private const int MaximumRequestLineCharacters = 4096;
    private const int MaximumHeaderCharacters = 8192;
    private const int MaximumHeaderCount = 64;
    private const int OAuthTokenCharacters = 43;
    private const int MaximumErrorDescriptionCharacters = 512;
    private const int MaximumErrorCodeCharacters = 128;
    private static readonly UTF8Encoding StrictUtf8 = new(
        encoderShouldEmitUTF8Identifier: false,
        throwOnInvalidBytes: true);

    internal static LoopbackAuthorizationCallback Parse(
        string requestHead,
        string expectedAuthority,
        string expectedState)
    {
        if (string.IsNullOrEmpty(requestHead)
            || string.IsNullOrEmpty(expectedAuthority)
            || !IsBase64UrlToken(expectedState, OAuthTokenCharacters)
            || !requestHead.EndsWith("\r\n\r\n", StringComparison.Ordinal))
        {
            return Invalid();
        }

        string[] lines = requestHead[..^4].Split("\r\n", StringSplitOptions.None);
        if (lines.Length < 2
            || lines.Length - 1 > MaximumHeaderCount
            || !TryParseRequestLine(lines[0], out string? queryText)
            || !ValidateHeaders(lines.AsSpan(1), expectedAuthority)
            || !TryParseQuery(queryText, out Dictionary<string, string>? query)
            || !HasExpectedState(query, expectedState))
        {
            return Invalid();
        }

        if (query.Count == 2
            && query.TryGetValue("code", out string? code)
            && IsBase64UrlToken(code, OAuthTokenCharacters))
        {
            return new LoopbackAuthorizationCallback(
                LoopbackAuthorizationCallbackKind.AuthorizationCode,
                code);
        }

        if (!IsExactErrorQuery(query, out string? error))
        {
            return Invalid();
        }

        return error switch
        {
            "login_required" => new(LoopbackAuthorizationCallbackKind.LoginRequired),
            "access_denied" => new(LoopbackAuthorizationCallbackKind.AccessDenied),
            "server_error" => new(LoopbackAuthorizationCallbackKind.ServerError),
            _ => Invalid(),
        };
    }

    private static bool TryParseRequestLine(string requestLine, out string queryText)
    {
        queryText = string.Empty;
        if (requestLine.Length is 0 or > MaximumRequestLineCharacters
            || requestLine.Any(static character => character is < ' ' or > '~'))
        {
            return false;
        }

        int firstSpace = requestLine.IndexOf(' ');
        int secondSpace = firstSpace < 0 ? -1 : requestLine.IndexOf(' ', firstSpace + 1);
        if (firstSpace != 3
            || secondSpace < 0
            || requestLine.IndexOf(' ', secondSpace + 1) >= 0
            || !requestLine.AsSpan(0, firstSpace).SequenceEqual("GET")
            || !requestLine.AsSpan(secondSpace + 1).SequenceEqual("HTTP/1.1"))
        {
            return false;
        }

        ReadOnlySpan<char> requestTarget = requestLine.AsSpan(firstSpace + 1, secondSpace - firstSpace - 1);
        if (requestTarget.Length <= CallbackPath.Length + 1
            || !requestTarget.StartsWith(CallbackPath, StringComparison.Ordinal)
            || requestTarget[CallbackPath.Length] != '?'
            || requestTarget[(CallbackPath.Length + 1)..].IndexOfAny('?', '#') >= 0)
        {
            return false;
        }

        queryText = requestTarget[(CallbackPath.Length + 1)..].ToString();
        return true;
    }

    private static bool ValidateHeaders(ReadOnlySpan<string> headers, string expectedAuthority)
    {
        var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        string? host = null;
        foreach (string header in headers)
        {
            if (header.Length is 0 or > MaximumHeaderCharacters)
            {
                return false;
            }

            int separator = header.IndexOf(':');
            if (separator <= 0
                || !IsHeaderName(header.AsSpan(0, separator))
                || !names.Add(header[..separator]))
            {
                return false;
            }

            string value = header[(separator + 1)..].Trim(' ', '\t');
            if (value.Any(static character => character < ' ' && character != '\t' || character == '\u007f'))
            {
                return false;
            }

            string name = header[..separator];
            if (name.Equals("Host", StringComparison.OrdinalIgnoreCase))
            {
                host = value;
            }
            else if (name.Equals("Content-Length", StringComparison.OrdinalIgnoreCase)
                || name.Equals("Transfer-Encoding", StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }
        }

        return string.Equals(host, expectedAuthority, StringComparison.Ordinal);
    }

    private static bool TryParseQuery(
        string queryText,
        out Dictionary<string, string> values)
    {
        values = new Dictionary<string, string>(StringComparer.Ordinal);
        string[] fields = queryText.Split('&', StringSplitOptions.None);
        if (fields.Length is < 2 or > 4)
        {
            return false;
        }

        foreach (string field in fields)
        {
            int separator = field.IndexOf('=');
            string name = separator > 0 ? field[..separator] : string.Empty;
            string encodedValue = separator > 0 ? field[(separator + 1)..] : string.Empty;
            if (separator <= 0
                || separator != field.LastIndexOf('=')
                || !TryDecodeQueryValue(encodedValue, out string? value)
                || name != "error_description"
                    && !string.Equals(encodedValue, value, StringComparison.Ordinal)
                || !values.TryAdd(name, value))
            {
                return false;
            }
        }

        return true;
    }

    private static bool HasExpectedState(
        IReadOnlyDictionary<string, string> query,
        string expectedState)
    {
        if (!query.TryGetValue("state", out string? state)
            || state.Length != expectedState.Length
            || !IsBase64UrlToken(state, OAuthTokenCharacters))
        {
            return false;
        }

        return CryptographicOperations.FixedTimeEquals(
            Encoding.ASCII.GetBytes(state),
            Encoding.ASCII.GetBytes(expectedState));
    }

    private static bool IsExactErrorQuery(
        IReadOnlyDictionary<string, string> query,
        out string? error)
    {
        error = null;
        if (query.Count is < 3 or > 4
            || !query.TryGetValue("error", out error)
            || !query.TryGetValue("error_description", out string? description)
            || description.Length > MaximumErrorDescriptionCharacters
            || query.Keys.Any(static name => name is not (
                "error" or "error_description" or "error_code" or "state")))
        {
            return false;
        }

        return !query.TryGetValue("error_code", out string? errorCode)
            || errorCode.Length <= MaximumErrorCodeCharacters;
    }

    private static bool TryDecodeQueryValue(string encoded, out string value)
    {
        value = string.Empty;
        if (encoded.Length > MaximumRequestLineCharacters)
        {
            return false;
        }

        byte[] bytes = new byte[encoded.Length];
        int length = 0;
        for (int index = 0; index < encoded.Length; index++)
        {
            char character = encoded[index];
            if (character == '%')
            {
                if (index + 2 >= encoded.Length
                    || !TryHex(encoded[index + 1], out int high)
                    || !TryHex(encoded[index + 2], out int low))
                {
                    return false;
                }

                bytes[length++] = (byte)((high << 4) | low);
                index += 2;
            }
            else if (character == '+')
            {
                bytes[length++] = (byte)' ';
            }
            else if (character is >= '!' and <= '~')
            {
                bytes[length++] = (byte)character;
            }
            else
            {
                return false;
            }
        }

        try
        {
            value = StrictUtf8.GetString(bytes, 0, length);
            return !value.Any(static character => char.IsControl(character));
        }
        catch (DecoderFallbackException)
        {
            return false;
        }
    }

    private static bool IsHeaderName(ReadOnlySpan<char> name)
    {
        foreach (char character in name)
        {
            if (!char.IsAsciiLetterOrDigit(character)
                && character is not ('!' or '#' or '$' or '%' or '&' or '\'' or '*'
                    or '+' or '-' or '.' or '^' or '_' or '`' or '|' or '~'))
            {
                return false;
            }
        }

        return !name.IsEmpty;
    }

    private static bool IsBase64UrlToken(string value, int expectedLength) =>
        value.Length == expectedLength
        && value.All(static character => char.IsAsciiLetterOrDigit(character) || character is '-' or '_');

    private static bool TryHex(char character, out int value)
    {
        value = character switch
        {
            >= '0' and <= '9' => character - '0',
            >= 'A' and <= 'F' => character - 'A' + 10,
            >= 'a' and <= 'f' => character - 'a' + 10,
            _ => -1,
        };
        return value >= 0;
    }

    private static LoopbackAuthorizationCallback Invalid() =>
        new(LoopbackAuthorizationCallbackKind.Invalid);
}
