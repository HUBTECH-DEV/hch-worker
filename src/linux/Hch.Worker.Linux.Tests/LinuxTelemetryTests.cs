using Hch.Worker.Linux;

namespace Hch.Worker.Linux.Tests;

public sealed class LinuxTelemetryTests
{
    [Fact]
    public void NvidiaParserSelectsLargestAdapterAndConvertsMebibytes()
    {
        LinuxGpuTelemetry sample = NvidiaSmiTelemetryProvider.Parse(
            "92.5, 100, 4096, Small GPU\n17, 512, 24576, Large GPU\n");

        Assert.Equal(17, sample.UtilizationPercent);
        Assert.Equal(512UL * 1024 * 1024, sample.MemoryUsedBytes);
        Assert.Equal(24576UL * 1024 * 1024, sample.MemoryTotalBytes);
        Assert.Equal("Large GPU", sample.AdapterName);
    }

    [Theory]
    [InlineData("")]
    [InlineData("malformed")]
    [InlineData("101, -1, invalid, ")]
    public void NvidiaParserFailsClosedForInvalidSamples(string output)
    {
        LinuxGpuTelemetry sample = NvidiaSmiTelemetryProvider.Parse(output);

        Assert.Null(sample.UtilizationPercent);
        Assert.Null(sample.MemoryUsedBytes);
        Assert.Null(sample.MemoryTotalBytes);
    }

    [Fact]
    public void NvidiaParserDoesNotOverflowOnUntrustedMetric()
    {
        LinuxGpuTelemetry sample = NvidiaSmiTelemetryProvider.Parse(
            "50, 18446744073709551615, 18446744073709551615, overflow");

        Assert.Equal(50, sample.UtilizationPercent);
        Assert.Null(sample.MemoryUsedBytes);
        Assert.Null(sample.MemoryTotalBytes);
    }

    [Fact]
    public async Task MissingNvidiaBinaryReturnsUnavailableTelemetry()
    {
        using var fixture = new TemporaryDirectory();
        var provider = new NvidiaSmiTelemetryProvider(Path.Combine(fixture.Path, "missing-nvidia-smi"));

        LinuxGpuTelemetry sample = await provider.CollectAsync();

        Assert.Equal(new LinuxGpuTelemetry(null, null, null, null), sample);
    }

    [Fact]
    public async Task CollectorUsesProcWithoutRootOrGpuAndClampsAuxiliaryCount()
    {
        using var fixture = new TemporaryDirectory();
        var provider = new NvidiaSmiTelemetryProvider(Path.Combine(fixture.Path, "missing-nvidia-smi"));
        using var collector = new LinuxTelemetryCollector(gpuProvider: provider);

        LinuxTelemetrySnapshot sample = await collector.CollectAsync(int.MaxValue);

        Assert.Equal(Environment.ProcessId, sample.ProcessId);
        Assert.Equal(1024, sample.AuxiliaryProcessCount);
        Assert.True(sample.TotalMemoryBytes > 0);
        Assert.True(sample.AvailableMemoryBytes > 0);
        Assert.Null(sample.GpuName);
    }
}
