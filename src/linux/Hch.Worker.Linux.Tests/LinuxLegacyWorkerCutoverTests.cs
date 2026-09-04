namespace Hch.Worker.Linux.Tests;

public sealed class LinuxLegacyWorkerCutoverTests
{
    [Fact]
    public async Task AllowsOnlyCompleteInactiveEvidence()
    {
        LinuxLegacyWorkerCutoverEvidence evidence = SafeEvidence();
        var guard = new LinuxLegacyWorkerCutoverGuard("node-1", new FixedProbe(evidence));

        await guard.EnsureExclusiveAsync();
    }

    [Theory]
    [InlineData("pid")]
    [InlineData("systemd")]
    [InlineData("process")]
    [InlineData("incomplete")]
    [InlineData("node")]
    public async Task RejectsAnyAmbiguousOrConflictingEvidence(string mutation)
    {
        LinuxLegacyWorkerCutoverEvidence safe = SafeEvidence();
        LinuxLegacyWorkerCutoverEvidence evidence = mutation switch
        {
            "pid" => safe with
            {
                PidFile = safe.PidFile with { Exists = true, ProcessId = 123, ProcessAlive = true },
            },
            "systemd" => safe with
            {
                Units = [safe.Units[0] with { LoadState = "loaded", UnitFileState = "enabled" }],
            },
            "process" => safe with
            {
                ConflictingProcesses = [new LinuxLegacyProcessEvidence(123, "node worker.js node-1")],
            },
            "incomplete" => safe with { ProcessScanComplete = false },
            "node" => safe with { NodeId = "node-2" },
            _ => throw new InvalidOperationException(),
        };
        var guard = new LinuxLegacyWorkerCutoverGuard("node-1", new FixedProbe(evidence));

        LinuxLegacyWorkerCutoverException error =
            await Assert.ThrowsAsync<LinuxLegacyWorkerCutoverException>(
                () => guard.EnsureExclusiveAsync());

        Assert.Equal("linux-exclusive-claiming-conflict", error.Code);
    }

    [Fact]
    public async Task MapsProbeFailureToUnverifiable()
    {
        var guard = new LinuxLegacyWorkerCutoverGuard("node-1", new FailingProbe());

        LinuxLegacyWorkerCutoverException error =
            await Assert.ThrowsAsync<LinuxLegacyWorkerCutoverException>(
                () => guard.EnsureExclusiveAsync());

        Assert.Equal("linux-exclusive-claiming-unverifiable", error.Code);
    }

    private static LinuxLegacyWorkerCutoverEvidence SafeEvidence() => new(
        "node-1",
        new LinuxLegacyPidFileEvidence("/run/hch-worker/legacy-node-1.pid", false, null, false, true),
        [
            new LinuxLegacySystemdEvidence(
                "hch-editorial-worker.service", "not-found", "inactive", "not-found", null),
        ],
        [],
        true);

    private sealed class FixedProbe(LinuxLegacyWorkerCutoverEvidence evidence)
        : ILinuxLegacyWorkerCutoverProbe
    {
        public ValueTask<LinuxLegacyWorkerCutoverEvidence> CaptureAsync(
            string nodeId,
            CancellationToken cancellationToken) => ValueTask.FromResult(evidence);
    }

    private sealed class FailingProbe : ILinuxLegacyWorkerCutoverProbe
    {
        public ValueTask<LinuxLegacyWorkerCutoverEvidence> CaptureAsync(
            string nodeId,
            CancellationToken cancellationToken) => throw new IOException("probe-failed");
    }
}
