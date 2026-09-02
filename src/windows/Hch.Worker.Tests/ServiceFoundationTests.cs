using Hch.Worker.Service;

namespace Hch.Worker.Tests;

public sealed class ServiceFoundationTests
{
    [Fact]
    public void ConfigurationRejectsRemoteOllamaAndHttpOrchestrator()
    {
        var valid = WorkerConfigurationStore.CreatePausedDefault("node-1", "worker/node-1");
        Assert.Throws<WorkerConfigurationException>(() =>
            (valid with { OllamaBaseUri = new Uri("http://192.168.1.2:11434/") }).Validate());
        Assert.Throws<WorkerConfigurationException>(() =>
            (valid with { OrchestratorBaseUri = new Uri("http://hubtech.online/") }).Validate());
    }

    [Fact]
    public async Task SanitizedLogsDropSensitiveFieldsAndRemainBounded()
    {
        var root = Path.Combine(Path.GetTempPath(), "hch-worker-tests", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            var logs = new SanitizedLogStore(root);
            await logs.WriteAsync("error", "network-failed", "Falha controlada", new Dictionary<string, string>
            {
                ["assignmentId"] = "assignment-1",
                ["token"] = "never-write-this",
                ["privateKey"] = "never-write-this-either",
            });

            var entries = await logs.ReadAsync(null, 10);
            var entry = Assert.Single(entries);
            Assert.Equal("network-failed", entry.EventCode);
            Assert.Equal("assignment-1", entry.Fields["assignmentid"]);
            Assert.DoesNotContain(entry.Fields.Keys, key => key.Contains("token", StringComparison.OrdinalIgnoreCase));
            Assert.DoesNotContain(entry.Fields.Keys, key => key.Contains("private", StringComparison.OrdinalIgnoreCase));
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }
}
