using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Hch.Worker.Protocol;

/// <summary>Strict JSON entry points for HCH protocol DTOs.</summary>
public static class ProtocolJson
{
    private static readonly UTF8Encoding StrictUtf8 = new(false, true);

    public static JsonSerializerOptions SerializerOptions { get; } = CreateOptions();

    /// <summary>
    /// Rejects duplicate names/non-I-JSON values before deserializing a DTO.
    /// </summary>
    public static T Deserialize<T>(ReadOnlySpan<byte> json)
    {
        var canonical = JcsCanonicalizer.CanonicalizeToUtf8(json);
        try
        {
            return JsonSerializer.Deserialize<T>(canonical, SerializerOptions)
                ?? throw new ProtocolValidationException(
                    "protocol-json-null",
                    $"A non-null {typeof(T).Name} JSON value is required.");
        }
        catch (JsonException error)
        {
            throw new ProtocolValidationException(
                "protocol-json-contract-invalid",
                $"The JSON value does not satisfy the {typeof(T).Name} contract.")
            {
                Data = { ["cause"] = error.GetType().FullName },
            };
        }
    }

    public static T Deserialize<T>(string json)
    {
        ArgumentNullException.ThrowIfNull(json);
        return Deserialize<T>(StrictUtf8.GetBytes(json));
    }

    public static byte[] SerializeCanonicalToUtf8<T>(T value) =>
        JcsCanonicalizer.CanonicalizeToUtf8(JsonSerializer.SerializeToUtf8Bytes(value, SerializerOptions));

    public static string SerializeCanonical<T>(T value) =>
        StrictUtf8.GetString(SerializeCanonicalToUtf8(value));

    private static JsonSerializerOptions CreateOptions() => new(JsonSerializerDefaults.Web)
    {
        AllowTrailingCommas = false,
        NumberHandling = JsonNumberHandling.Strict,
        PropertyNameCaseInsensitive = false,
        ReadCommentHandling = JsonCommentHandling.Disallow,
        WriteIndented = false,
    };
}
