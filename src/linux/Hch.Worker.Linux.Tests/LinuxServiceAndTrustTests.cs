using Hch.Worker.Linux;
using Hch.Worker.Ollama;

namespace Hch.Worker.Linux.Tests;

[CollectionDefinition(Name, DisableParallelization = true)]
public sealed class EnvironmentCollection : ICollectionFixture<object>
{
    public const string Name = "process-environment";
}

[Collection(EnvironmentCollection.Name)]
public sealed class LinuxServiceAndTrustTests
{
    [Fact]
    public void ServiceStateReportsCurrentAndMissingProcesses()
    {
        var provider = new LinuxServiceStateProvider();

        LinuxServiceStatus running = provider.Collect(Environment.ProcessId);
        LinuxServiceStatus stopped = provider.Collect(int.MaxValue);

        Assert.Equal("Running", running.State);
        Assert.Equal(Environment.ProcessId, running.ProcessId);
        Assert.Equal("Stopped", stopped.State);
        Assert.Equal(0, stopped.ProcessId);
        Assert.Throws<ArgumentOutOfRangeException>(() => provider.Collect(0));
    }

    [Fact]
    public void ServiceStateAcceptsOnlyCanonicalSystemdInvocationId()
    {
        string? original = Environment.GetEnvironmentVariable("INVOCATION_ID");
        try
        {
            var provider = new LinuxServiceStateProvider();
            Environment.SetEnvironmentVariable("INVOCATION_ID", "ABCDEF0123456789ABCDEF0123456789");

            LinuxServiceStatus systemd = provider.Collect(Environment.ProcessId);

            Assert.True(systemd.RunningUnderSystemd);
            Assert.Equal("abcdef0123456789abcdef0123456789", systemd.InvocationId);

            Environment.SetEnvironmentVariable("INVOCATION_ID", "not-an-invocation-id");
            LinuxServiceStatus standalone = provider.Collect(Environment.ProcessId);
            Assert.False(standalone.RunningUnderSystemd);
            Assert.Null(standalone.InvocationId);
        }
        finally
        {
            Environment.SetEnvironmentVariable("INVOCATION_ID", original);
        }
    }

    [Theory]
    [InlineData("https://127.0.0.1:11434/")]
    [InlineData("http://127.0.0.1:11434/api")]
    [InlineData("http://user@127.0.0.1:11434/")]
    [InlineData("http://127.0.0.1:11434/?query=1")]
    [InlineData("http://192.0.2.1:11434/")]
    public async Task OllamaGuardRejectsEndpointBeforeProcessDiscovery(string endpoint)
    {
        using var fixture = new TemporaryDirectory();
        var guard = new LinuxOllamaEndpointGuard(
            [Path.Combine(fixture.Path, "missing-ollama")]);

        OllamaEndpointTrustException error = await Assert.ThrowsAsync<OllamaEndpointTrustException>(
            async () => await guard.EnsureTrustedAsync(new Uri(endpoint), CancellationToken.None));

        Assert.Equal("ollama-linux-endpoint-invalid", error.Code);
    }

    [Fact]
    public async Task OllamaGuardFailsClosedWhenTrustedProcessIsAbsent()
    {
        using var fixture = new TemporaryDirectory();
        var guard = new LinuxOllamaEndpointGuard(
            [Path.Combine(fixture.Path, "missing-ollama")]);

        OllamaEndpointTrustException error = await Assert.ThrowsAsync<OllamaEndpointTrustException>(
            async () => await guard.EnsureTrustedAsync(
                new Uri("http://127.0.0.1:11434/"), CancellationToken.None));

        Assert.Equal("ollama-linux-trusted-process-not-found", error.Code);
    }

    [Fact]
    public void WorkerPathsValidateAndCanonicalize()
    {
        var paths = new LinuxWorkerPaths("/tmp/config/../config", "/tmp/state", "/tmp/run", "/tmp/log");

        LinuxWorkerPaths validated = paths.Validate();

        Assert.Equal("/tmp/config", validated.ConfigurationDirectory);
    }
}
