using System.ComponentModel;
using System.Diagnostics;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;

namespace Hch.Worker.Windows;

/// <summary>Base Windows telemetry snapshot. Unavailable values remain null.</summary>
public sealed record WindowsTelemetrySnapshot(
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
    ulong? VramUsedBytes);

public readonly record struct GpuTelemetry(double? UtilizationPercent, ulong? VramUsedBytes);

public interface IGpuTelemetryProvider
{
    GpuTelemetry Collect();
}

/// <summary>Explicit null provider; missing GPU data is never reported as zero.</summary>
public sealed class UnavailableGpuTelemetryProvider : IGpuTelemetryProvider
{
    public static UnavailableGpuTelemetryProvider Instance { get; } = new();

    private UnavailableGpuTelemetryProvider()
    {
    }

    public GpuTelemetry Collect() => new(null, null);
}

/// <summary>Collects process and host counters without WMI or localized counters.</summary>
public sealed class WindowsTelemetryCollector : IDisposable
{
    private readonly object gate = new();
    private readonly Process process;
    private readonly bool ownsProcess;
    private readonly IGpuTelemetryProvider gpuProvider;

    private long? previousTimestamp;
    private TimeSpan? previousProcessCpu;
    private CpuTimes? previousSystemCpu;

    public WindowsTelemetryCollector(
        Process? process = null,
        IGpuTelemetryProvider? gpuProvider = null)
    {
        this.process = process ?? Process.GetCurrentProcess();
        ownsProcess = process is null;
        this.gpuProvider = gpuProvider ?? UnavailableGpuTelemetryProvider.Instance;
    }

    public WindowsTelemetrySnapshot Collect()
    {
        lock (gate)
        {
            long timestamp = Stopwatch.GetTimestamp();
            double? processCpu = CollectProcessCpu(timestamp);
            double? systemCpu = CollectSystemCpu();
            (long? workingSet, long? peakWorkingSet) = CollectProcessMemory();
            (ulong? totalMemory, ulong? availableMemory) = CollectSystemMemory();
            (ulong? readBytes, ulong? writeBytes) = CollectProcessIo();
            (long? receivedBytes, long? sentBytes) = CollectNetwork();
            GpuTelemetry gpu = CollectGpu();

            return new WindowsTelemetrySnapshot(
                DateTimeOffset.UtcNow,
                process.Id,
                processCpu,
                systemCpu,
                workingSet,
                peakWorkingSet,
                totalMemory,
                availableMemory,
                readBytes,
                writeBytes,
                receivedBytes,
                sentBytes,
                gpu.UtilizationPercent,
                gpu.VramUsedBytes);
        }
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
        TimeSpan current;
        try
        {
            current = process.TotalProcessorTime;
        }
        catch (Exception error) when (error is InvalidOperationException or NotSupportedException or Win32Exception)
        {
            return null;
        }

        double? result = null;
        if (previousTimestamp is long priorTimestamp && previousProcessCpu is TimeSpan priorCpu)
        {
            double elapsedSeconds = (timestamp - priorTimestamp) / (double)Stopwatch.Frequency;
            if (elapsedSeconds > 0)
            {
                result = NormalizePercent(
                    (current - priorCpu).TotalSeconds
                    / elapsedSeconds
                    / Math.Max(1, Environment.ProcessorCount)
                    * 100d);
            }
        }

        previousTimestamp = timestamp;
        previousProcessCpu = current;
        return result;
    }

    private double? CollectSystemCpu()
    {
        if (!GetSystemTimes(out NativeFileTime idle, out NativeFileTime kernel, out NativeFileTime user))
        {
            return null;
        }

        var current = new CpuTimes(idle.ToUInt64(), kernel.ToUInt64(), user.ToUInt64());
        double? result = null;
        if (previousSystemCpu is CpuTimes prior)
        {
            if (current.Idle >= prior.Idle
                && current.Kernel >= prior.Kernel
                && current.User >= prior.User)
            {
                ulong idleDelta = current.Idle - prior.Idle;
                ulong kernelDelta = current.Kernel - prior.Kernel;
                ulong userDelta = current.User - prior.User;
                ulong total = kernelDelta + userDelta;
                if (total > 0 && idleDelta <= total)
                {
                    result = NormalizePercent((total - idleDelta) * 100d / total);
                }
            }
        }

        previousSystemCpu = current;
        return result;
    }

    private (long? WorkingSet, long? PeakWorkingSet) CollectProcessMemory()
    {
        try
        {
            process.Refresh();
            return (process.WorkingSet64, process.PeakWorkingSet64);
        }
        catch (Exception error) when (error is InvalidOperationException or NotSupportedException or Win32Exception)
        {
            return (null, null);
        }
    }

    private static (ulong? Total, ulong? Available) CollectSystemMemory()
    {
        var status = new MemoryStatus
        {
            Length = checked((uint)Marshal.SizeOf<MemoryStatus>()),
        };
        return GlobalMemoryStatusEx(ref status)
            ? (status.TotalPhysical, status.AvailablePhysical)
            : (null, null);
    }

    private (ulong? Read, ulong? Write) CollectProcessIo()
    {
        try
        {
            return GetProcessIoCounters(process.Handle, out IoCounters counters)
                ? (counters.ReadTransferCount, counters.WriteTransferCount)
                : (null, null);
        }
        catch (Exception error) when (error is InvalidOperationException or NotSupportedException or Win32Exception)
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
            foreach (NetworkInterface networkInterface in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (networkInterface.OperationalStatus != OperationalStatus.Up)
                {
                    continue;
                }

                IPInterfaceStatistics statistics = networkInterface.GetIPStatistics();
                received = checked(received + statistics.BytesReceived);
                sent = checked(sent + statistics.BytesSent);
            }

            return (received, sent);
        }
        catch (Exception error) when (error is NetworkInformationException or OverflowException or PlatformNotSupportedException)
        {
            return (null, null);
        }
    }

    private GpuTelemetry CollectGpu()
    {
        try
        {
            GpuTelemetry result = gpuProvider.Collect();
            double? utilization = result.UtilizationPercent is double value
                ? NormalizePercent(value)
                : null;
            return new GpuTelemetry(utilization, result.VramUsedBytes);
        }
        catch (Exception error) when (error is NotSupportedException or Win32Exception or InvalidOperationException)
        {
            return new GpuTelemetry(null, null);
        }
    }

    private static double? NormalizePercent(double value) =>
        double.IsFinite(value) ? Math.Clamp(value, 0d, 100d) : null;

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetSystemTimes(
        out NativeFileTime idleTime,
        out NativeFileTime kernelTime,
        out NativeFileTime userTime);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GlobalMemoryStatusEx(ref MemoryStatus buffer);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetProcessIoCounters(nint processHandle, out IoCounters counters);

    private readonly record struct CpuTimes(ulong Idle, ulong Kernel, ulong User);

    [StructLayout(LayoutKind.Sequential)]
    private struct NativeFileTime
    {
        public uint Low;
        public uint High;

        public readonly ulong ToUInt64() => ((ulong)High << 32) | Low;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
    private struct MemoryStatus
    {
        public uint Length;
        public uint MemoryLoad;
        public ulong TotalPhysical;
        public ulong AvailablePhysical;
        public ulong TotalPageFile;
        public ulong AvailablePageFile;
        public ulong TotalVirtual;
        public ulong AvailableVirtual;
        public ulong AvailableExtendedVirtual;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct IoCounters
    {
        public ulong ReadOperationCount;
        public ulong WriteOperationCount;
        public ulong OtherOperationCount;
        public ulong ReadTransferCount;
        public ulong WriteTransferCount;
        public ulong OtherTransferCount;
    }
}
