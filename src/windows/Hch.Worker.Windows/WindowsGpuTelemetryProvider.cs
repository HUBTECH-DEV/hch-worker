using System.Buffers.Binary;
using Microsoft.Win32;

namespace Hch.Worker.Windows;

/// <summary>
/// Collects non-sensitive GPU adapter metadata without PowerShell, WMI, a
/// shell, or an external executable. Dynamic utilization and VRAM-use metrics
/// deliberately remain unavailable until an in-process provider is available.
/// </summary>
public sealed class WindowsGpuTelemetryProvider : IGpuTelemetryProvider
{
    private static readonly TimeSpan MinimumCollectionInterval = TimeSpan.FromSeconds(10);
    private readonly object gate = new();
    private DateTimeOffset lastCollectedAt = DateTimeOffset.MinValue;
    private GpuTelemetry lastSample = new(null, null);

    public static WindowsGpuTelemetryProvider Instance { get; } = new();

    public GpuTelemetry Collect()
    {
        lock (gate)
        {
            DateTimeOffset now = DateTimeOffset.UtcNow;
            if (now - lastCollectedAt < MinimumCollectionInterval)
            {
                return lastSample;
            }

            lastSample = CollectDisplayAdapterMetadata();
            lastCollectedAt = now;
            return lastSample;
        }
    }

    private static GpuTelemetry CollectDisplayAdapterMetadata()
    {
        try
        {
            using RegistryKey? video = Registry.LocalMachine.OpenSubKey(
                @"SYSTEM\CurrentControlSet\Control\Video",
                writable: false);
            if (video is null)
            {
                return new GpuTelemetry(null, null);
            }

            var candidates = new List<(string Name, ulong? Capacity)>();
            foreach (string adapterId in video.GetSubKeyNames().Take(128))
            {
                using RegistryKey? adapter = video.OpenSubKey($@"{adapterId}\0000", writable: false);
                string? name = NormalizeName(adapter?.GetValue(
                    "HardwareInformation.AdapterString",
                    null,
                    RegistryValueOptions.DoNotExpandEnvironmentNames) as string);
                if (name is null || name.Contains("Microsoft Basic", StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                candidates.Add((name, ReadMemorySize(adapter)));
            }

            (string Name, ulong? Capacity) selected = candidates
                .OrderByDescending(static candidate => candidate.Capacity ?? 0)
                .ThenBy(static candidate => candidate.Name, StringComparer.Ordinal)
                .FirstOrDefault();
            return string.IsNullOrEmpty(selected.Name)
                ? new GpuTelemetry(null, null)
                : new GpuTelemetry(null, null, selected.Name, selected.Capacity);
        }
        catch (Exception error) when (error is System.Security.SecurityException
            or UnauthorizedAccessException
            or IOException
            or PlatformNotSupportedException)
        {
            return new GpuTelemetry(null, null);
        }
    }

    private static ulong? ReadMemorySize(RegistryKey? adapter)
    {
        object? value = adapter?.GetValue(
            "HardwareInformation.MemorySize",
            null,
            RegistryValueOptions.DoNotExpandEnvironmentNames);
        return value switch
        {
            int signed => unchecked((uint)signed) is uint normalized && normalized > 0
                ? normalized
                : null,
            long signed when signed > 0 => checked((ulong)signed),
            byte[] bytes when bytes.Length >= sizeof(ulong) => BinaryPrimitives.ReadUInt64LittleEndian(bytes),
            byte[] bytes when bytes.Length >= sizeof(uint) => BinaryPrimitives.ReadUInt32LittleEndian(bytes),
            _ => null,
        };
    }

    private static string? NormalizeName(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return null;
        }

        string normalized = new(value.Trim()
            .Where(static character => !char.IsControl(character))
            .Take(128)
            .ToArray());
        return normalized.Length == 0 ? null : normalized;
    }

}
