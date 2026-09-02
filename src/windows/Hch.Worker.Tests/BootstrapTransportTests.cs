using System.Net;
using Hch.Worker.Protocol;
using Hch.Worker.Security;
using Hch.Worker.Service;

namespace Hch.Worker.Tests;

public sealed class BootstrapTransportTests
{
    private static readonly Uri Orchestrator = new("https://hubtech.online/");

    [Fact]
    public async Task ManifestFetchRefusesAResponseWhoseFinalUriWasRedirected()
    {
        using var identity = Ed25519Identity.Generate();
        using var http = new HttpClient(new DelegateHandler((request, _) => Task.FromResult(
            Response(
                request,
                new Uri("https://redirect.invalid/manifest"),
                "{}",
                "application/json"))));
        var signed = new SignedOrchestratorClient(
            http,
            Orchestrator,
            "node-transport-test",
            "worker-key:transport-test",
            identity);
        var client = new BootstrapAttestationClient(http, Orchestrator, signed);

        var error = await Assert.ThrowsAsync<OrchestratorRequestException>(
            () => client.FetchManifestAsync(CancellationToken.None));

        Assert.Equal("manifest-redirect-refused", error.Code);
    }

    [Fact]
    public async Task ArtifactFetchRefusesAResponseWhoseFinalUriWasRedirected()
    {
        const string body = "signed artifact";
        var digest = HchDigest.Sha256Hex(System.Text.Encoding.UTF8.GetBytes(body));
        using var http = new HttpClient(new DelegateHandler((request, _) => Task.FromResult(
            Response(
                request,
                new Uri("https://redirect.invalid/artifact"),
                body,
                "text/plain"))));
        var source = new HttpManifestArtifactSource(http, Orchestrator);
        var artifact = new ManifestArtifactContract(
            "policy",
            "text/plain",
            body.Length,
            digest,
            $"/api/editorial/orchestrator/artifacts/policy?sha256={digest}",
            "release");

        var error = await Assert.ThrowsAsync<WorkerServiceException>(
            () => source.DownloadAsync(artifact, CancellationToken.None));

        Assert.Equal("artifact-redirect-refused", error.Code);
    }

    [Fact]
    public async Task ArtifactFetchAcceptsOnlyCanonicalSignedNameAndDigestUrl()
    {
        const string body = "signed artifact";
        var digest = HchDigest.Sha256Hex(System.Text.Encoding.UTF8.GetBytes(body));
        using var http = new HttpClient(new DelegateHandler((request, _) => Task.FromResult(
            Response(request, request.RequestUri!, body, "text/plain"))));
        var source = new HttpManifestArtifactSource(http, Orchestrator);
        var artifact = new ManifestArtifactContract(
            "policy",
            "text/plain",
            body.Length,
            digest,
            $"/api/editorial/orchestrator/artifacts/policy?sha256={digest}",
            "release");

        var downloaded = await source.DownloadAsync(artifact, CancellationToken.None);

        Assert.Equal(body, System.Text.Encoding.UTF8.GetString(downloaded.Bytes));
        Assert.StartsWith("text/plain", downloaded.MediaType, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("/api/editorial/orchestrator/artifacts/other?sha256={0}")]
    [InlineData("/api/editorial/orchestrator/artifacts/policy?sha256=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")]
    [InlineData("/api/editorial/orchestrator/artifacts/policy?sha256={0}&download=1")]
    [InlineData("/api/editorial/orchestrator/artifacts/policy")]
    public async Task ArtifactFetchRefusesUrlNotBoundToSignedNameAndDigest(string urlTemplate)
    {
        const string body = "signed artifact";
        var digest = HchDigest.Sha256Hex(System.Text.Encoding.UTF8.GetBytes(body));
        using var http = new HttpClient(new DelegateHandler((request, _) => Task.FromResult(
            Response(request, request.RequestUri!, body, "text/plain"))));
        var source = new HttpManifestArtifactSource(http, Orchestrator);
        var artifact = new ManifestArtifactContract(
            "policy",
            "text/plain",
            body.Length,
            digest,
            string.Format(System.Globalization.CultureInfo.InvariantCulture, urlTemplate, digest),
            "release");

        var error = await Assert.ThrowsAsync<WorkerServiceException>(
            () => source.DownloadAsync(artifact, CancellationToken.None));

        Assert.Equal("artifact-path-refused", error.Code);
    }

    [Fact]
    public async Task OllamaProbePreservesCallerCancellation()
    {
        using var http = new HttpClient(new DelegateHandler(async (_, cancellationToken) =>
        {
            await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken);
            throw new InvalidOperationException("unreachable");
        }));
        var probe = new HttpOllamaManifestProbe(
            http,
            new Uri("http://127.0.0.1:11434/"),
            new TestOllamaEndpointGuard());
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => probe.VerifyExactModelAsync(
            "qwen3:8b",
            new string('a', 64),
            cancellation.Token));
    }

    private static HttpResponseMessage Response(
        HttpRequestMessage original,
        Uri finalUri,
        string body,
        string mediaType)
    {
        var finalRequest = new HttpRequestMessage(original.Method, finalUri);
        return new HttpResponseMessage(HttpStatusCode.OK)
        {
            RequestMessage = finalRequest,
            Content = new StringContent(body, System.Text.Encoding.UTF8, mediaType),
        };
    }

    private sealed class DelegateHandler(
        Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> handler) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken) => handler(request, cancellationToken);
    }
}
