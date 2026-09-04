using System.Diagnostics;
using System.Globalization;

namespace Hch.Worker.Linux;

public sealed record LinuxGpuTelemetry(
    double? UtilizationPercent,
    ulong? MemoryUsedBytes,
    ulong? MemoryTotalBytes,
    string? AdapterName);

/// <summary>Collects NVIDIA metrics without invoking a shell.</summary>
public sealed class NvidiaSmiTelemetryProvider
{
    private const int MaximumOutputCharacters = 16 * 1024;
    private static readonly TimeSpan MinimumCollectionInterval = TimeSpan.FromSeconds(10);
    private readonly object gate = new();
    private readonly string executablePath;
    private DateTimeOffset lastCollectedAt = DateTimeOffset.MinValue;
    private LinuxGpuTelemetry lastSample = new(null, null, null, null);

    public NvidiaSmiTelemetryProvider(string executablePath = "/usr/bin/nvidia-smi")
    {
        this.executablePath = LinuxPathSecurity.RequireAbsoluteCanonicalPath(executablePath);
    }

    public async ValueTask<LinuxGpuTelemetry> CollectAsync(CancellationToken cancellationToken = default)
    {
        lock (gate)
        {
            if (DateTimeOffset.UtcNow - lastCollectedAt < MinimumCollectionInterval)
            {
                return lastSample;
            }
        }

        LinuxGpuTelemetry sample = await CollectCoreAsync(cancellationToken).ConfigureAwait(false);
        lock (gate)
        {
            lastSample = sample;
            lastCollectedAt = DateTimeOffset.UtcNow;
            return lastSample;
        }
    }

    private async Task<LinuxGpuTelemetry> CollectCoreAsync(CancellationToken cancellationToken)
    {
        if (!File.Exists(executablePath))
        {
            return new(null, null, null, null);
        }

        if ((File.GetUnixFileMode(executablePath)
            & (UnixFileMode.GroupWrite | UnixFileMode.OtherWrite)) != 0)
        {
            throw new UnauthorizedAccessException("nvidia-smi-permissions-unsafe");
        }

        var startInfo = new ProcessStartInfo
        {
            FileName = executablePath,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
        };
        startInfo.ArgumentList.Add("--query-gpu=utilization.gpu,memory.used,memory.total,name");
        startInfo.ArgumentList.Add("--format=csv,noheader,nounits");

        using var process = new Process { StartInfo = startInfo };
        try
        {
            if (!process.Start())
            {
                return new(null, null, null, null);
            }

            Task<string> outputTask = process.StandardOutput.ReadToEndAsync(cancellationToken);
            Task<string> errorTask = process.StandardError.ReadToEndAsync(cancellationToken);
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeout.CancelAfter(TimeSpan.FromSeconds(3));
            await process.WaitForExitAsync(timeout.Token).ConfigureAwait(false);
            string output = await outputTask.ConfigureAwait(false);
            _ = await errorTask.ConfigureAwait(false);
            if (process.ExitCode != 0 || output.Length > MaximumOutputCharacters)
            {
                return new(null, null, null, null);
            }

            return Parse(output);
        }
        catch (Exception error) when (error is IOException
            or InvalidOperationException
            or UnauthorizedAccessException
            or System.ComponentModel.Win32Exception
            or OperationCanceledException && !cancellationToken.IsCancellationRequested)
        {
            TryKill(process);
            return new(null, null, null, null);
        }
    }

    public static LinuxGpuTelemetry Parse(string output)
    {
        ArgumentNullException.ThrowIfNull(output);
        var samples = new List<LinuxGpuTelemetry>();
        foreach (string line in output.Split('\n', StringSplitOptions.RemoveEmptyEntries
            | StringSplitOptions.TrimEntries).Take(64))
        {
            string[] fields = line.Split(',', 4, StringSplitOptions.TrimEntries);
            if (fields.Length != 4)
            {
                continue;
            }

            double? utilization = ParseDouble(fields[0]);
            ulong? used = ParseMebibytes(fields[1]);
            ulong? total = ParseMebibytes(fields[2]);
            string? name = NormalizeName(fields[3]);
            samples.Add(new(utilization, used, total, name));
        }

        LinuxGpuTelemetry? selected = samples
            .OrderByDescending(static sample => sample.MemoryTotalBytes ?? 0)
            .ThenBy(static sample => sample.AdapterName, StringComparer.Ordinal)
            .FirstOrDefault();
        return selected ?? new(null, null, null, null);
    }

    private static double? ParseDouble(string value) =>
        double.TryParse(value, NumberStyles.Float, CultureInfo.InvariantCulture, out double parsed)
            && parsed is >= 0 and <= 100 ? parsed : null;

    private static ulong? ParseMebibytes(string value)
    {
        if (!ulong.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out ulong parsed)
            || parsed > ulong.MaxValue / (1024UL * 1024UL))
        {
            return null;
        }

        return parsed * 1024UL * 1024UL;
    }

    private static string? NormalizeName(string value)
    {
        string normalized = new(value.Where(static c => !char.IsControl(c)).Take(128).ToArray());
        return string.IsNullOrWhiteSpace(normalized) ? null : normalized.Trim();
    }

    private static void TryKill(Process process)
    {
        try
        {
            if (!process.HasExited)
            {
                process.Kill(entireProcessTree: true);
            }
        }
        catch (InvalidOperationException)
        {
        }
    }
}
