namespace Hch.Worker.Linux;

public sealed record LinuxWorkerPaths(
    string ConfigurationDirectory,
    string StateDirectory,
    string RuntimeDirectory,
    string LogDirectory)
{
    public static LinuxWorkerPaths System { get; } = new(
        "/etc/hch-worker",
        "/var/lib/hch-worker",
        "/run/hch-worker",
        "/var/log/hch-worker");

    public LinuxWorkerPaths Validate()
    {
        return new LinuxWorkerPaths(
            LinuxPathSecurity.RequireAbsoluteCanonicalPath(ConfigurationDirectory),
            LinuxPathSecurity.RequireAbsoluteCanonicalPath(StateDirectory),
            LinuxPathSecurity.RequireAbsoluteCanonicalPath(RuntimeDirectory),
            LinuxPathSecurity.RequireAbsoluteCanonicalPath(LogDirectory));
    }
}
