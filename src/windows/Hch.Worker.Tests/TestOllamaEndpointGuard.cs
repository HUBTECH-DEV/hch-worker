using Hch.Worker.Ollama;

namespace Hch.Worker.Tests;

internal sealed class TestOllamaEndpointGuard : IOllamaEndpointGuard
{
    public ValueTask EnsureTrustedAsync(Uri baseUri, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return ValueTask.CompletedTask;
    }
}
