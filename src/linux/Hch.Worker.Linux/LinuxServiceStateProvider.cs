namespace Hch.Worker.Linux;

public sealed record LinuxServiceStatus(
    string State,
    int ProcessId,
    bool RunningUnderSystemd,
    string? InvocationId);

/// <summary>Reports local runtime state without invoking systemctl or a shell.</summary>
public sealed class LinuxServiceStateProvider
{
    public LinuxServiceStatus Collect(int expectedProcessId)
    {
        if (!OperatingSystem.IsLinux())
        {
            throw new PlatformNotSupportedException("linux-platform-required");
        }

        if (expectedProcessId < 1)
        {
            throw new ArgumentOutOfRangeException(nameof(expectedProcessId));
        }

        string? invocationId = NormalizeInvocationId(
            Environment.GetEnvironmentVariable("INVOCATION_ID"));
        bool alive = Directory.Exists($"/proc/{expectedProcessId}");
        return new LinuxServiceStatus(
            alive ? "Running" : "Stopped",
            alive ? expectedProcessId : 0,
            invocationId is not null,
            invocationId);
    }

    private static string? NormalizeInvocationId(string? value)
    {
        if (value?.Length != 32 || value.Any(static character => !Uri.IsHexDigit(character)))
        {
            return null;
        }

        return value.ToLowerInvariant();
    }
}
