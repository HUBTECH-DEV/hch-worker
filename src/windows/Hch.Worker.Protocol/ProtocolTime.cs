using System.Globalization;
using System.Text.RegularExpressions;

namespace Hch.Worker.Protocol;

/// <summary>Culture-invariant timestamp and protocol-window validation.</summary>
public static partial class ProtocolTime
{
    public const long JavaScriptMaximumSafeInteger = 9_007_199_254_740_991;
    public const int DefaultClockSkewSeconds = 30;
    public const int WorkerRequestMaximumLifetimeSeconds = 5 * 60;
    public const int ManifestSignatureMaximumLifetimeSeconds = 31 * 24 * 60 * 60;
    public const int AssignmentRequestTimeoutMinimumSeconds = 3;
    public const int AssignmentRequestTimeoutMaximumSeconds = 15;
    public const int NodeHeartbeatIntervalSeconds = 60;

    public static DateTimeOffset ParseTimestamp(string value, string name = "timestamp")
    {
        ArgumentNullException.ThrowIfNull(value);
        if (!IsoTimestampPattern().IsMatch(value)
            || !DateTimeOffset.TryParse(
                value,
                CultureInfo.InvariantCulture,
                DateTimeStyles.None,
                out var parsed))
        {
            throw new ProtocolValidationException(
                "timestamp-iso8601-invalid",
                $"{name} must be an explicit ISO-8601 timestamp with an offset.");
        }

        return parsed;
    }

    public static void ValidateUnixWindow(
        long created,
        long expires,
        DateTimeOffset now,
        int maximumLifetimeSeconds = WorkerRequestMaximumLifetimeSeconds,
        int clockSkewSeconds = DefaultClockSkewSeconds,
        bool allowExpired = false)
    {
        if (created < 0 || expires < 0
            || created > JavaScriptMaximumSafeInteger
            || expires > JavaScriptMaximumSafeInteger)
        {
            throw new ProtocolValidationException("signature-time-invalid", "Signature times must be non-negative Unix seconds.");
        }

        if (expires <= created)
        {
            throw new ProtocolValidationException("signature-window-invalid", "expires must be greater than created.");
        }

        if (maximumLifetimeSeconds <= 0 || clockSkewSeconds < 0)
        {
            throw new ArgumentOutOfRangeException(
                maximumLifetimeSeconds <= 0 ? nameof(maximumLifetimeSeconds) : nameof(clockSkewSeconds));
        }

        var nowSeconds = now.ToUnixTimeSeconds();
        if (created > nowSeconds + clockSkewSeconds)
        {
            throw new ProtocolValidationException("not-yet-valid", "The signature creation time is in the future.");
        }

        if (!allowExpired && expires < nowSeconds - clockSkewSeconds)
        {
            throw new ProtocolValidationException("expired", "The signature has expired.");
        }

        if (expires - created > maximumLifetimeSeconds)
        {
            throw new ProtocolValidationException("lifetime-too-long", "The signature validity interval is too long.");
        }
    }

    public static void ValidateRequestTimeout(int seconds)
    {
        if (seconds is < AssignmentRequestTimeoutMinimumSeconds or > AssignmentRequestTimeoutMaximumSeconds)
        {
            throw new ProtocolValidationException(
                "heartbeat-request-timeout-out-of-range",
                $"The request timeout must be between {AssignmentRequestTimeoutMinimumSeconds} and {AssignmentRequestTimeoutMaximumSeconds} seconds.");
        }
    }

    [GeneratedRegex(
        "^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\\.[0-9]{1,7})?(?:Z|[+-][0-9]{2}:[0-9]{2})$",
        RegexOptions.CultureInvariant)]
    private static partial Regex IsoTimestampPattern();
}
