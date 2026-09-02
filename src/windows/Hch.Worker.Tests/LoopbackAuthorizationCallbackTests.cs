using System.Net;
using System.Net.Sockets;
using System.Text;
using Hch.Worker.Tray;

namespace Hch.Worker.Tests;

public sealed class LoopbackAuthorizationCallbackTests
{
    private const string ExpectedAuthority = "127.0.0.1:43191";
    private static readonly string State = new('s', 43);
    private static readonly string Code = new('c', 43);

    [Fact]
    public void ParserAcceptsOnlyTheExactAuthorizationCodeCallback()
    {
        string request = Request($"/callback?code={Code}&state={State}");

        LoopbackAuthorizationCallback callback = LoopbackAuthorizationCallbackParser.Parse(
            request,
            ExpectedAuthority,
            State);

        Assert.Equal(LoopbackAuthorizationCallbackKind.AuthorizationCode, callback.Kind);
        Assert.Equal(Code, callback.AuthorizationCode);
    }

    [Theory]
    [MemberData(nameof(InvalidRequestHeads))]
    public void ParserRejectsAmbiguousOrMalformedHttpRequests(string request)
    {
        LoopbackAuthorizationCallback callback = LoopbackAuthorizationCallbackParser.Parse(
            request,
            ExpectedAuthority,
            State);

        Assert.Equal(LoopbackAuthorizationCallbackKind.Invalid, callback.Kind);
        Assert.Null(callback.AuthorizationCode);
    }

    [Theory]
    [InlineData("login_required", "LoginRequired")]
    [InlineData("access_denied", "AccessDenied")]
    [InlineData("server_error", "ServerError")]
    public void ParserRecognizesOnlyTheHomologatedOauthErrors(
        string error,
        string expectedKind)
    {
        string request = Request(
            $"/callback?error={error}&error_description=Falha+controlada&error_code=NATIVE_FAILURE&state={State}");

        LoopbackAuthorizationCallback callback = LoopbackAuthorizationCallbackParser.Parse(
            request,
            ExpectedAuthority,
            State);

        Assert.Equal(expectedKind, callback.Kind.ToString());
        Assert.Null(callback.AuthorizationCode);
    }

    [Fact]
    public async Task ListenerIgnoresAnUnrelatedRequestBeforeTheValidCallback()
    {
        using TcpListener listener = StartListener(out int port);
        using var globalTimeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        Task<string> receive = HihDesktopClient.ReceiveAuthorizationCodeAsync(
            listener,
            State,
            globalTimeout.Token,
            TimeSpan.FromSeconds(1));

        string unrelatedResponse = await SendRequestAsync(
            port,
            Request("/favicon.ico", $"127.0.0.1:{port}"),
            globalTimeout.Token);
        string validResponse = await SendRequestAsync(
            port,
            Request($"/callback?code={Code}&state={State}", $"127.0.0.1:{port}"),
            globalTimeout.Token);

        Assert.StartsWith("HTTP/1.1 400", unrelatedResponse, StringComparison.Ordinal);
        Assert.StartsWith("HTTP/1.1 200", validResponse, StringComparison.Ordinal);
        Assert.Equal(Code, await receive);
    }

    [Fact]
    public async Task ListenerContinuesAfterAnAcceptedConnectionTimesOut()
    {
        using TcpListener listener = StartListener(out int port);
        using var globalTimeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        Task<string> receive = HihDesktopClient.ReceiveAuthorizationCodeAsync(
            listener,
            State,
            globalTimeout.Token,
            TimeSpan.FromMilliseconds(150));

        using var stalledClient = new TcpClient();
        await stalledClient.ConnectAsync(IPAddress.Loopback, port, globalTimeout.Token);
        await Task.Delay(TimeSpan.FromMilliseconds(350), globalTimeout.Token);

        string validResponse = await SendRequestAsync(
            port,
            Request($"/callback?code={Code}&state={State}", $"127.0.0.1:{port}"),
            globalTimeout.Token);

        Assert.StartsWith("HTTP/1.1 200", validResponse, StringComparison.Ordinal);
        Assert.Equal(Code, await receive);
    }

    [Fact]
    public async Task ListenerReportsAccessDeniedWithSpecificUserGuidance()
    {
        using TcpListener listener = StartListener(out int port);
        using var globalTimeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        Task<string> receive = HihDesktopClient.ReceiveAuthorizationCodeAsync(
            listener,
            State,
            globalTimeout.Token,
            TimeSpan.FromSeconds(1));

        string response = await SendRequestAsync(
            port,
            Request(
                $"/callback?error=access_denied&error_description=O+usu%C3%A1rio+negou&state={State}",
                $"127.0.0.1:{port}"),
            globalTimeout.Token);
        HihDesktopAuthenticationException failure = await Assert.ThrowsAsync<HihDesktopAuthenticationException>(
            async () => await receive);

        Assert.StartsWith("HTTP/1.1 403", response, StringComparison.Ordinal);
        Assert.Contains("foi negada no HIH", failure.UserMessage, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("Nenhuma chave foi registrada", failure.UserMessage, StringComparison.Ordinal);
    }

    public static TheoryData<string> InvalidRequestHeads()
    {
        string success = $"code={Code}&state={State}";
        string wrongState = new('x', 43);
        return new TheoryData<string>
        {
            Request($"/callback?{success}").Replace("HTTP/1.1", "HTTP/1.0", StringComparison.Ordinal),
            Request($"http://127.0.0.1:43191/callback?{success}"),
            Request($"/callback/?{success}"),
            Request($"/%63allback?{success}"),
            Request($"/callback?{success}#fragment"),
            Request($"/callback?{success}&extra=value"),
            Request($"/callback?code={Code}&code={Code}&state={State}"),
            Request($"/callback?code={Code}&state={wrongState}"),
            Request($"/callback?code={Code}&state=%73{State[1..]}"),
            Request($"/callback?code={Code[..42]}&state={State}"),
            Request($"/callback?error=unsupported&error_description=failure&state={State}"),
            Request($"/callback?error=access_denied&state={State}"),
            Request($"/callback?error=access_denied&error_description=%GG&state={State}"),
            Request($"/callback?{success}", "127.0.0.1:43192"),
            Request($"/callback?{success}", includeHost: false),
            Request($"/callback?{success}").Replace(
                $"Host: {ExpectedAuthority}\r\n",
                $"Host: {ExpectedAuthority}\r\nHost: {ExpectedAuthority}\r\n",
                StringComparison.Ordinal),
            Request($"/callback?{success}").Replace(
                "User-Agent: Hch.Worker.Tests\r\n",
                "Content-Length: 0\r\n",
                StringComparison.Ordinal),
            Request($"/callback?{success}").Replace("\r\n", "\n", StringComparison.Ordinal),
            $"GET /callback?{success} HTTP/1.1\r\nBroken header\r\n\r\n",
            $"GET /callback?{success} HTTP/1.1\r\nHost : {ExpectedAuthority}\r\n\r\n",
        };
    }

    private static TcpListener StartListener(out int port)
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start(8);
        port = ((IPEndPoint)listener.LocalEndpoint).Port;
        return listener;
    }

    private static string Request(
        string requestTarget,
        string authority = ExpectedAuthority,
        bool includeHost = true)
    {
        string host = includeHost ? $"Host: {authority}\r\n" : string.Empty;
        return $"GET {requestTarget} HTTP/1.1\r\n{host}User-Agent: Hch.Worker.Tests\r\nAccept: text/html\r\n\r\n";
    }

    private static async Task<string> SendRequestAsync(
        int port,
        string request,
        CancellationToken cancellationToken)
    {
        using var client = new TcpClient();
        await client.ConnectAsync(IPAddress.Loopback, port, cancellationToken);
        await using NetworkStream stream = client.GetStream();
        byte[] payload = Encoding.ASCII.GetBytes(request);
        await stream.WriteAsync(payload, cancellationToken);
        await stream.FlushAsync(cancellationToken);

        var response = new StringBuilder();
        byte[] buffer = new byte[1024];
        while (true)
        {
            int read = await stream.ReadAsync(buffer, cancellationToken);
            if (read == 0)
            {
                break;
            }

            response.Append(Encoding.UTF8.GetString(buffer, 0, read));
        }

        return response.ToString();
    }
}
