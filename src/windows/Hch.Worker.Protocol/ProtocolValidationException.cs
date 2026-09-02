namespace Hch.Worker.Protocol;

/// <summary>
/// Represents a deterministic, non-secret protocol validation failure.
/// </summary>
public sealed class ProtocolValidationException : FormatException
{
    public ProtocolValidationException(string code, string message)
        : base(message)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(code);
        Code = code;
    }

    /// <summary>Stable machine-readable failure code.</summary>
    public string Code { get; }
}
