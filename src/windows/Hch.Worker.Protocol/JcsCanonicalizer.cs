using System.Buffers;
using System.Globalization;
using System.Text;
using System.Text.Json;

namespace Hch.Worker.Protocol;

/// <summary>
/// Canonicalizes the I-JSON subset accepted by HCH according to RFC 8785.
/// </summary>
/// <remarks>
/// Object member names are ordered by their UTF-16 code units. Duplicate
/// member names, unpaired surrogates, invalid UTF-8, sparse/non-JSON values and
/// numbers that cannot be represented by an IEEE-754 binary64 are rejected.
/// </remarks>
public static class JcsCanonicalizer
{
    private static readonly UTF8Encoding StrictUtf8 = new(
        encoderShouldEmitUTF8Identifier: false,
        throwOnInvalidBytes: true);

    /// <summary>Canonicalizes one UTF-8 encoded JSON value.</summary>
    public static byte[] CanonicalizeToUtf8(ReadOnlySpan<byte> json)
    {
        if (json.IsEmpty)
        {
            throw Invalid("jcs-empty", "A JSON value is required.");
        }

        var input = json.ToArray();
        var reader = new Utf8JsonReader(input, new JsonReaderOptions
        {
            AllowTrailingCommas = false,
            CommentHandling = JsonCommentHandling.Disallow,
            MaxDepth = 128,
        });

        try
        {
            if (!reader.Read())
            {
                throw Invalid("jcs-empty", "A JSON value is required.");
            }

            var canonical = ReadValue(ref reader);
            if (reader.Read())
            {
                throw Invalid("jcs-trailing-data", "Only one JSON value is accepted.");
            }

            return StrictUtf8.GetBytes(canonical);
        }
        catch (ProtocolValidationException)
        {
            throw;
        }
        catch (JsonException error)
        {
            throw Invalid("jcs-invalid-json", "The input is not valid I-JSON.", error);
        }
        catch (DecoderFallbackException error)
        {
            throw Invalid("jcs-invalid-utf8", "The input contains invalid UTF-8.", error);
        }
    }

    /// <summary>Canonicalizes one JSON text value.</summary>
    public static string Canonicalize(string json)
    {
        ArgumentNullException.ThrowIfNull(json);
        try
        {
            return StrictUtf8.GetString(CanonicalizeToUtf8(StrictUtf8.GetBytes(json)));
        }
        catch (EncoderFallbackException error)
        {
            throw Invalid("jcs-unpaired-surrogate", "JSON text contains an unpaired Unicode surrogate.", error);
        }
    }

    /// <summary>Canonicalizes a <see cref="JsonElement"/> without changing its value.</summary>
    public static string Canonicalize(JsonElement value) => Canonicalize(value.GetRawText());

    /// <summary>Serializes and canonicalizes a protocol DTO.</summary>
    public static string Serialize<T>(T value, JsonSerializerOptions? options = null)
    {
        var serialized = JsonSerializer.Serialize(value, options ?? ProtocolJson.SerializerOptions);
        return Canonicalize(serialized);
    }

    /// <summary>Validates that a JSON input is already in canonical form.</summary>
    public static bool IsCanonical(ReadOnlySpan<byte> json)
    {
        var canonical = CanonicalizeToUtf8(json);
        return json.SequenceEqual(canonical);
    }

    private static string ReadValue(ref Utf8JsonReader reader) => reader.TokenType switch
    {
        JsonTokenType.StartObject => ReadObject(ref reader),
        JsonTokenType.StartArray => ReadArray(ref reader),
        JsonTokenType.String => Quote(ReadString(ref reader, "JSON string")),
        JsonTokenType.Number => FormatNumber(ref reader),
        JsonTokenType.True => "true",
        JsonTokenType.False => "false",
        JsonTokenType.Null => "null",
        _ => throw Invalid("jcs-invalid-token", $"Unexpected JSON token {reader.TokenType}."),
    };

    private static string ReadObject(ref Utf8JsonReader reader)
    {
        var members = new SortedDictionary<string, string>(StringComparer.Ordinal);
        while (reader.Read() && reader.TokenType != JsonTokenType.EndObject)
        {
            if (reader.TokenType != JsonTokenType.PropertyName)
            {
                throw Invalid("jcs-object-property-expected", "A JSON object member name was expected.");
            }

            var name = ReadString(ref reader, "JSON property name");
            if (!members.TryAdd(name, string.Empty))
            {
                throw Invalid("jcs-duplicate-property", $"Duplicate JSON property name: {name}.");
            }

            if (!reader.Read())
            {
                throw Invalid("jcs-object-value-missing", "A JSON object member value is missing.");
            }

            members[name] = ReadValue(ref reader);
        }

        if (reader.TokenType != JsonTokenType.EndObject)
        {
            throw Invalid("jcs-object-not-closed", "The JSON object is not closed.");
        }

        var builder = new StringBuilder();
        builder.Append('{');
        var first = true;
        foreach (var member in members)
        {
            if (!first)
            {
                builder.Append(',');
            }

            first = false;
            builder.Append(Quote(member.Key));
            builder.Append(':');
            builder.Append(member.Value);
        }

        return builder.Append('}').ToString();
    }

    private static string ReadArray(ref Utf8JsonReader reader)
    {
        var builder = new StringBuilder();
        builder.Append('[');
        var first = true;
        while (reader.Read() && reader.TokenType != JsonTokenType.EndArray)
        {
            if (!first)
            {
                builder.Append(',');
            }

            first = false;
            builder.Append(ReadValue(ref reader));
        }

        if (reader.TokenType != JsonTokenType.EndArray)
        {
            throw Invalid("jcs-array-not-closed", "The JSON array is not closed.");
        }

        return builder.Append(']').ToString();
    }

    private static string ReadString(ref Utf8JsonReader reader, string name)
    {
        ValidateRawStringToken(reader.ValueSpan, name);
        string value;
        try
        {
            value = reader.GetString()
                ?? throw Invalid("jcs-invalid-string", $"{name} is invalid.");
        }
        catch (InvalidOperationException error)
        {
            throw Invalid("jcs-invalid-utf8", $"{name} contains invalid UTF-8.", error);
        }
        catch (DecoderFallbackException error)
        {
            throw Invalid("jcs-invalid-utf8", $"{name} contains invalid UTF-8.", error);
        }

        EnsureWellFormed(value, name);
        return value;
    }

    private static void ValidateRawStringToken(ReadOnlySpan<byte> raw, string name)
    {
        for (var index = 0; index < raw.Length; index++)
        {
            if (raw[index] != (byte)'\\')
            {
                continue;
            }

            index++;
            if (index >= raw.Length)
            {
                throw Invalid("jcs-invalid-string", $"{name} has an incomplete escape.");
            }

            if (raw[index] != (byte)'u')
            {
                continue;
            }

            var unit = ParseHexUnit(raw, index + 1, name);
            index += 4;
            if (char.IsHighSurrogate((char)unit))
            {
                if (index + 6 >= raw.Length || raw[index + 1] != (byte)'\\' || raw[index + 2] != (byte)'u')
                {
                    throw Invalid("jcs-unpaired-surrogate", $"{name} contains an unpaired Unicode surrogate.");
                }

                var low = ParseHexUnit(raw, index + 3, name);
                if (!char.IsLowSurrogate((char)low))
                {
                    throw Invalid("jcs-unpaired-surrogate", $"{name} contains an unpaired Unicode surrogate.");
                }

                index += 6;
            }
            else if (char.IsLowSurrogate((char)unit))
            {
                throw Invalid("jcs-unpaired-surrogate", $"{name} contains an unpaired Unicode surrogate.");
            }
        }
    }

    private static int ParseHexUnit(ReadOnlySpan<byte> raw, int start, string name)
    {
        if (start + 4 > raw.Length)
        {
            throw Invalid("jcs-invalid-string", $"{name} has an incomplete Unicode escape.");
        }

        var value = 0;
        for (var index = start; index < start + 4; index++)
        {
            var digit = raw[index] switch
            {
                >= (byte)'0' and <= (byte)'9' => raw[index] - (byte)'0',
                >= (byte)'a' and <= (byte)'f' => raw[index] - (byte)'a' + 10,
                >= (byte)'A' and <= (byte)'F' => raw[index] - (byte)'A' + 10,
                _ => -1,
            };
            if (digit < 0)
            {
                throw Invalid("jcs-invalid-string", $"{name} has an invalid Unicode escape.");
            }

            value = (value << 4) | digit;
        }

        return value;
    }

    private static string FormatNumber(ref Utf8JsonReader reader)
    {
        if (!reader.TryGetDouble(out var value) || !double.IsFinite(value))
        {
            throw Invalid("jcs-non-finite-number", "JCS accepts only finite IEEE-754 binary64 numbers.");
        }

        return EcmaScriptNumber.Format(value);
    }

    private static string Quote(string value)
    {
        EnsureWellFormed(value, "JSON string");
        var builder = new StringBuilder(value.Length + 2);
        builder.Append('"');
        foreach (var character in value)
        {
            switch (character)
            {
                case '"': builder.Append("\\\""); break;
                case '\\': builder.Append("\\\\"); break;
                case '\b': builder.Append("\\b"); break;
                case '\t': builder.Append("\\t"); break;
                case '\n': builder.Append("\\n"); break;
                case '\f': builder.Append("\\f"); break;
                case '\r': builder.Append("\\r"); break;
                case < ' ':
                    builder.Append("\\u");
                    builder.Append(((int)character).ToString("x4", CultureInfo.InvariantCulture));
                    break;
                default:
                    builder.Append(character);
                    break;
            }
        }

        return builder.Append('"').ToString();
    }

    private static void EnsureWellFormed(string value, string name)
    {
        for (var index = 0; index < value.Length; index++)
        {
            var unit = value[index];
            if (char.IsHighSurrogate(unit))
            {
                if (++index >= value.Length || !char.IsLowSurrogate(value[index]))
                {
                    throw Invalid("jcs-unpaired-surrogate", $"{name} contains an unpaired Unicode surrogate.");
                }
            }
            else if (char.IsLowSurrogate(unit))
            {
                throw Invalid("jcs-unpaired-surrogate", $"{name} contains an unpaired Unicode surrogate.");
            }
        }
    }

    private static ProtocolValidationException Invalid(string code, string message, Exception? inner = null)
    {
        var exception = new ProtocolValidationException(code, message);
        if (inner is not null)
        {
            exception.Data["cause"] = inner.GetType().FullName;
        }

        return exception;
    }

    private static class EcmaScriptNumber
    {
        public static string Format(double value)
        {
            if (!double.IsFinite(value))
            {
                throw Invalid("jcs-non-finite-number", "JCS accepts only finite numbers.");
            }

            if (value == 0d)
            {
                return "0";
            }

            var negative = value < 0;
            var roundTrip = Math.Abs(value).ToString("R", CultureInfo.InvariantCulture);
            var exponentMarker = roundTrip.IndexOfAny(['E', 'e']);
            var significand = exponentMarker >= 0 ? roundTrip[..exponentMarker] : roundTrip;
            var explicitExponent = exponentMarker >= 0
                ? int.Parse(roundTrip[(exponentMarker + 1)..], NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture)
                : 0;
            var decimalPoint = significand.IndexOf('.');
            var integerDigits = decimalPoint >= 0 ? decimalPoint : significand.Length;
            var digits = decimalPoint >= 0 ? significand.Remove(decimalPoint, 1) : significand;
            var n = checked(integerDigits + explicitExponent);

            string magnitude;
            if (n > 0 && n <= 21)
            {
                magnitude = digits.Length <= n
                    ? digits + new string('0', n - digits.Length)
                    : digits.Insert(n, ".");
            }
            else if (n > -6 && n <= 0)
            {
                magnitude = "0." + new string('0', -n) + digits;
            }
            else
            {
                var mantissa = digits.Length == 1 ? digits : digits.Insert(1, ".");
                var scientificExponent = n - 1;
                magnitude = mantissa + "e" + (scientificExponent >= 0 ? "+" : string.Empty)
                    + scientificExponent.ToString(CultureInfo.InvariantCulture);
            }

            return negative ? "-" + magnitude : magnitude;
        }
    }
}
