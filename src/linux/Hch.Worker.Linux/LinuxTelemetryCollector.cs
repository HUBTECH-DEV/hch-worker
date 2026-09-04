using System.Diagnostics;
using System.Globalization;
using System.Net.NetworkInformation;

namespace Hch.Worker.Linux;

public sealed record LinuxTelemetrySnapshot(
    DateTimeOffset CapturedAt,
    int ProcessId,
    double? ProcessCpuPercent,
    double? SystemCpuPercent,
    long? ProcessWorkingSetBytes,
    long? ProcessPeakWorkingSetBytes,
    ulong? TotalMemoryBytes,
    ulong? AvailableMemoryBytes,
    ulong? ProcessReadBytes,
    ulong? ProcessWriteBytes,
    long? NetworkReceivedBytes,
    long? NetworkSentBytes,
    double? GpuPercent,
    ulong? VramUsedBytes,
    string? GpuName,
    ulong? VramTotalBytes,
    int AuxiliaryProcessCount);

public sealed class LinuxTelemetryCollector : IDisposable
{
    private readonly object gate = new();
    private readonly Process process;
    private readonly bool ownsProcess;
    private readonly NvidiaSmiTelemetryProvider gpuProvider;
    private long? previousTimestamp;
    private TimeSpan? previousProcessCpu;

    public LinuxTelemetryCollector(Process? process = null, NvidiaSmiTelemetryProvider? gpuProvider = null)
    {
        if (!OperatingSystem.IsLinux())
        {
            throw new PlatformNotSupportedException("linux-platform-required");
        }

        this.process = process ?? Process.GetCurrentProcess();
        ownsProcess = process is null;
        this.gpuProvider = gpuProvider ?? new NvidiaSmiTelemetryProvider();
    }

    public async ValueTask<LinuxTelemetrySnapshot> CollectAsync(
        int auxiliaryProcessCount = 0,
        CancellationToken cancellationToken = default)
    {
        long timestamp = Stopwatch.GetTimestamp();
        double? processCpu = CollectProcessCpu(timestamp);
        (ulong? total, ulong? available) = CollectMemory();
        (ulong? read, ulong? written) = CollectIo(process.Id);
        (long? received, long? sent) = CollectNetwork();
        LinuxGpuTelemetry gpu = await gpuProvider.CollectAsync(cancellationToken).ConfigureAwait(false);
        process.Refresh();
        return new LinuxTelemetrySnapshot(
            DateTimeOffset.UtcNow,
            process.Id,
            processCpu,
            null,
            SafeLong(() => process.WorkingSet64),
            SafeLong(() => process.PeakWorkingSet64),
            total,
            available,
            read,
            written,
            received,
            sent,
            gpu.UtilizationPercent,
            gpu.MemoryUsedBytes,
            gpu.AdapterName,
            gpu.MemoryTotalBytes,
            Math.Clamp(auxiliaryProcessCount, 0, 1_024));
    }

    public void Dispose()
    {
        if (ownsProcess)
        {
            process.Dispose();
        }

        GC.SuppressFinalize(this);
    }

    private double? CollectProcessCpu(long timestamp)
    {
        lock (gate)
        {
            try
            {
                TimeSpan cpu = process.TotalProcessorTime;
                double? result = null;
                if (previousTimestamp is long priorTimestamp && previousProcessCpu is TimeSpan priorCpu)
                {
                    double elapsed = Stopwatch.GetElapsedTime(priorTimestamp, timestamp).TotalSeconds;
                    if (elapsed > 0)
                    {
                        result = Math.Clamp((cpu - priorCpu).TotalSeconds / elapsed
                            / Math.Max(1, Environment.ProcessorCount) * 100, 0, 100);
                    }
                }

                previousTimestamp = timestamp;
                previousProcessCpu = cpu;
                return result;
            }
            catch (InvalidOperationException)
            {
                return null;
            }
        }
    }

    private static (ulong? Total, ulong? Available) CollectMemory()
    {
        try
        {
            Dictionary<string, ulong> values = File.ReadLines("/proc/meminfo")
                .Select(static line => line.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries))
                .Where(static fields => fields.Length >= 2)
                .Select(static fields => (Key: fields[0].TrimEnd(':'), Value: ParseKib(fields[1])))
                .Where(static item => item.Value.HasValue)
                .ToDictionary(static item => item.Key, static item => item.Value!.Value, StringComparer.Ordinal);
            return (values.GetValueOrDefault("MemTotal"), values.GetValueOrDefault("MemAvailable"));
        }
        catch (IOException)
        {
            return (null, null);
        }
    }

    private static (ulong? Read, ulong? Written) CollectIo(int pid)
    {
        try
        {
            Dictionary<string, ulong> values = File.ReadLines($"/proc/{pid}/io")
                .Select(static line => line.Split(':', 2, StringSplitOptions.TrimEntries))
                .Where(static fields => fields.Length == 2
                    && ulong.TryParse(fields[1], NumberStyles.None, CultureInfo.InvariantCulture, out _))
                .ToDictionary(static fields => fields[0], static fields => ulong.Parse(
                    fields[1], CultureInfo.InvariantCulture), StringComparer.Ordinal);
            return (values.GetValueOrDefault("read_bytes"), values.GetValueOrDefault("write_bytes"));
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException)
        {
            return (null, null);
        }
    }

    private static (long? Received, long? Sent) CollectNetwork()
    {
        try
        {
            long received = 0;
            long sent = 0;
            foreach (NetworkInterface adapter in NetworkInterface.GetAllNetworkInterfaces())
            {
                IPv4InterfaceStatistics statistics = adapter.GetIPv4Statistics();
                received = checked(received + statistics.BytesReceived);
                sent = checked(sent + statistics.BytesSent);
            }

            return (received, sent);
        }
        catch (Exception error) when (error is NetworkInformationException or OverflowException)
        {
            return (null, null);
        }
    }

    private static ulong? ParseKib(string value) =>
        ulong.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out ulong kib)
            ? checked(kib * 1024UL) : null;

    private static long? SafeLong(Func<long> read)
    {
        try { return read(); }
        catch (InvalidOperationException) { return null; }
    }
}
