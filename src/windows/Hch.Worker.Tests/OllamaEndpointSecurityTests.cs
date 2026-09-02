using System.Net;
using System.Net.Sockets;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using Hch.Worker.Core;
using Hch.Worker.Ollama;
using Hch.Worker.Service;
using Hch.Worker.Windows;

namespace Hch.Worker.Tests;

public sealed class OllamaEndpointSecurityTests
{
    [Fact]
    public async Task ChatRefusesPortSquatterBeforeAnyHttpByte()
    {
        using var listener = StartLoopbackListener(out Uri endpoint);
        Task<int> observedBytes = ObserveFirstConnectionAsync(listener);
        var handler = new CountingHandler();
        using var http = new HttpClient(handler);
        var guard = CreateGuard(endpoint, includeOwner: true);
        var sut = new OllamaChatClient(http, endpoint, guard);
        using var input = JsonDocument.Parse("{\"operation\":\"generate\"}");

        WorkerJobException error = await Assert.ThrowsAsync<WorkerJobException>(() =>
            sut.GenerateJsonAsync(Plan(), "System prompt", input.RootElement, 1));

        Assert.Equal("ollama-endpoint-untrusted", error.Code);
        Assert.Equal(0, handler.RequestCount);
        Assert.Equal(0, await observedBytes.WaitAsync(TimeSpan.FromSeconds(10)));
    }

    [Fact]
    public async Task ManifestProbeRefusesPortSquatterBeforeAnyHttpByte()
    {
        using var listener = StartLoopbackListener(out Uri endpoint);
        Task<int> observedBytes = ObserveFirstConnectionAsync(listener);
        var handler = new CountingHandler();
        using var http = new HttpClient(handler);
        var probe = new HttpOllamaManifestProbe(
            http,
            endpoint,
            CreateGuard(endpoint, includeOwner: true));

        WorkerServiceException error = await Assert.ThrowsAsync<WorkerServiceException>(() =>
            probe.VerifyExactModelAsync(
                "qwen3:8b",
                new string('a', 64),
                CancellationToken.None));

        Assert.Equal("ollama-endpoint-untrusted", error.Code);
        Assert.Equal(0, handler.RequestCount);
        Assert.Equal(0, await observedBytes.WaitAsync(TimeSpan.FromSeconds(10)));
    }

    [Fact]
    public async Task ModelStatusDoesNotReachTagsTransportWhenGuardRefusesEndpoint()
    {
        var handler = new CountingHandler();
        using var http = new HttpClient(handler);
        var sut = new OllamaChatClient(
            http,
            new Uri("http://127.0.0.1:11434/"),
            new RefusingGuard("ollama-endpoint-owner-invalid"));

        OllamaModelStatus status = await sut.GetModelStatusAsync("qwen3:8b");

        Assert.False(status.Available);
        Assert.Equal("ollama-endpoint-owner-invalid", status.ErrorCode);
        Assert.Equal(0, handler.RequestCount);
    }

    [Fact]
    public async Task ListenerOwnedByUnconfiguredUserIsRefusedWithoutBytes()
    {
        using var listener = StartLoopbackListener(out Uri endpoint);
        Task<int> observedBytes = ObserveFirstConnectionAsync(listener);
        var guard = CreateGuard(endpoint, includeOwner: false);

        OllamaEndpointTrustException error = await Assert.ThrowsAsync<OllamaEndpointTrustException>(
            async () =>
            {
                using Stream ignored = await guard.ConnectAuthenticatedAsync(
                    new DnsEndPoint(endpoint.Host, endpoint.Port),
                    CancellationToken.None);
            });

        Assert.Equal("ollama-endpoint-untrusted", error.Code);
        Assert.Equal(0, await observedBytes.WaitAsync(TimeSpan.FromSeconds(10)));
    }

    [Theory]
    [InlineData("owner")]
    [InlineData("path")]
    [InlineData("acl")]
    [InlineData("signature")]
    [InlineData("liveness")]
    public void TrustedProcessPolicyFailsClosedForEachNegativeGate(string gate)
    {
        var evidence = new WindowsTrustedProcessEvidence(
            ProcessUserAllowed: gate != "owner",
            ImageNameMatches: gate != "path",
            ImagePathCanonicalAndReparseFree: true,
            ImageAclSafe: gate != "acl",
            AuthenticodeTrusted: gate != "signature",
            ProcessAlive: gate != "liveness");

        Assert.Throws<UnauthorizedAccessException>(() =>
            WindowsTrustedProcessSecurityPolicy.Validate(evidence));
    }

    [Fact]
    public async Task InstalledOllamaCanBeAttestedWhenExplicitlyEnabled()
    {
        if (!string.Equals(
                Environment.GetEnvironmentVariable("HCH_TEST_OLLAMA_TRUST"),
                "1",
                StringComparison.Ordinal))
        {
            return;
        }

        var endpoint = new Uri("http://127.0.0.1:11434/");
        WindowsOllamaEndpointGuard guard = CreateGuard(endpoint, includeOwner: true);
        using var transport = new SocketsHttpHandler
        {
            AllowAutoRedirect = false,
            UseCookies = false,
            UseProxy = false,
            ConnectCallback = (context, cancellationToken) =>
                guard.ConnectAuthenticatedAsync(context.DnsEndPoint, cancellationToken),
        };
        using var http = new HttpClient(transport);
        var client = new OllamaChatClient(http, endpoint, guard);

        OllamaModelStatus status = await client.GetModelStatusAsync(
            "hch-endpoint-attestation-probe:0",
            CancellationToken.None);

        Assert.False(status.Available);
        Assert.Equal("ollama-model-not-installed", status.ErrorCode);
    }

    private static WindowsOllamaEndpointGuard CreateGuard(Uri endpoint, bool includeOwner)
    {
        string? ownerSid = includeOwner
            ? WindowsIdentity.GetCurrent().User?.Value
                ?? throw new InvalidOperationException("test-user-sid-unavailable")
            : null;
        return new WindowsOllamaEndpointGuard(endpoint, ownerSid, "EventLog");
    }

    private static TcpListener StartLoopbackListener(out Uri endpoint)
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        int port = ((IPEndPoint)listener.LocalEndpoint).Port;
        endpoint = new Uri($"http://127.0.0.1:{port}/");
        return listener;
    }

    private static async Task<int> ObserveFirstConnectionAsync(TcpListener listener)
    {
        using Socket socket = await listener.AcceptSocketAsync();
        var buffer = new byte[1];
        return await socket.ReceiveAsync(buffer, SocketFlags.None);
    }

    private static OllamaGenerationPlan Plan() => new(
        "qwen3:8b",
        0.2,
        8_192,
        2_048,
        30,
        30,
        15,
        4);

    private sealed class CountingHandler : HttpMessageHandler
    {
        private int requestCount;

        public int RequestCount => Volatile.Read(ref requestCount);

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            Interlocked.Increment(ref requestCount);
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent("{}", Encoding.UTF8, "application/json"),
            });
        }
    }

    private sealed class RefusingGuard(string code) : IOllamaEndpointGuard
    {
        public ValueTask EnsureTrustedAsync(Uri baseUri, CancellationToken cancellationToken) =>
            ValueTask.FromException(new OllamaEndpointTrustException(code));
    }
}
