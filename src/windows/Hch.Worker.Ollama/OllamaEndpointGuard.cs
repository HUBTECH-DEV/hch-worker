namespace Hch.Worker.Ollama;

/// <summary>
/// Proves that the configured loopback Ollama endpoint is owned by an allowed,
/// trusted process before an HTTP request is allowed to leave the Worker.
/// </summary>
public interface IOllamaEndpointGuard
{
    ValueTask EnsureTrustedAsync(Uri baseUri, CancellationToken cancellationToken);
}

public sealed class OllamaEndpointTrustException(string code, Exception? innerException = null)
    : Exception("The local Ollama endpoint is not trusted.", innerException)
{
    public string Code { get; } = code;
}
