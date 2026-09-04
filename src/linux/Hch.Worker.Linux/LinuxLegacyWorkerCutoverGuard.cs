using System.Diagnostics;
using System.Globalization;

namespace Hch.Worker.Linux;

public sealed record LinuxLegacyPidFileEvidence(
    string Path,
    bool Exists,
    int? ProcessId,
    bool ProcessAlive,
    bool Secure);

public sealed record LinuxLegacySystemdEvidence(
    string UnitName,
    string LoadState,
    string ActiveState,
    string UnitFileState,
    int? MainProcessId);

public sealed record LinuxLegacyProcessEvidence(int ProcessId, string Command);

public sealed record LinuxLegacyWorkerCutoverEvidence(
    string NodeId,
    LinuxLegacyPidFileEvidence PidFile,
    IReadOnlyList<LinuxLegacySystemdEvidence> Units,
    IReadOnlyList<LinuxLegacyProcessEvidence> ConflictingProcesses,
    bool ProcessScanComplete);

public interface ILinuxLegacyWorkerCutoverProbe
{
    ValueTask<LinuxLegacyWorkerCutoverEvidence> CaptureAsync(
        string nodeId,
        CancellationToken cancellationToken);
}

public sealed class LinuxLegacyWorkerCutoverException : Exception
{
    public LinuxLegacyWorkerCutoverException(string code, Exception? innerException = null)
        : base("Linux Worker exclusivity could not be proven.", innerException) => Code = code;

    public string Code { get; }
}

/// <summary>
/// Requires independent pidfile, systemd and /proc evidence before this Worker
/// may leave Paused/Drain. Missing or ambiguous evidence always rejects.
/// </summary>
public sealed class LinuxLegacyWorkerCutoverGuard
{
    private readonly string nodeId;
    private readonly ILinuxLegacyWorkerCutoverProbe probe;

    public LinuxLegacyWorkerCutoverGuard(
        string nodeId,
        ILinuxLegacyWorkerCutoverProbe? probe = null)
    {
        ValidateNodeId(nodeId);
        this.nodeId = nodeId;
        this.probe = probe ?? new LinuxLegacyWorkerCutoverProbe();
    }

    public async Task EnsureExclusiveAsync(CancellationToken cancellationToken = default)
    {
        LinuxLegacyWorkerCutoverEvidence evidence;
        try
        {
            evidence = await probe.CaptureAsync(nodeId, cancellationToken).ConfigureAwait(false);
        }
        catch (LinuxLegacyWorkerCutoverException)
        {
            throw;
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception error) when (error is IOException
            or UnauthorizedAccessException
            or InvalidDataException
            or System.ComponentModel.Win32Exception)
        {
            throw new LinuxLegacyWorkerCutoverException(
                "linux-exclusive-claiming-unverifiable", error);
        }

        ValidateExclusive(evidence, nodeId);
    }

    public static void ValidateExclusive(
        LinuxLegacyWorkerCutoverEvidence evidence,
        string expectedNodeId)
    {
        ArgumentNullException.ThrowIfNull(evidence);
        ValidateNodeId(expectedNodeId);
        if (!string.Equals(evidence.NodeId, expectedNodeId, StringComparison.Ordinal)
            || !evidence.ProcessScanComplete
            || evidence.ConflictingProcesses.Count != 0
            || !evidence.PidFile.Secure
            || evidence.PidFile.Exists && (evidence.PidFile.ProcessId is null
                || evidence.PidFile.ProcessAlive))
        {
            throw new LinuxLegacyWorkerCutoverException("linux-exclusive-claiming-conflict");
        }

        if (evidence.Units.Count == 0
            || evidence.Units.Any(static unit => !IsSafelyInactive(unit)))
        {
            throw new LinuxLegacyWorkerCutoverException("linux-exclusive-claiming-conflict");
        }
    }

    private static bool IsSafelyInactive(LinuxLegacySystemdEvidence unit)
    {
        bool absent = unit.LoadState.Equals("not-found", StringComparison.Ordinal);
        bool stopped = unit.ActiveState.Equals("inactive", StringComparison.Ordinal)
            || unit.ActiveState.Equals("failed", StringComparison.Ordinal);
        bool cannotAutoStart = unit.UnitFileState.Equals("disabled", StringComparison.Ordinal)
            || unit.UnitFileState.Equals("masked", StringComparison.Ordinal)
            || unit.UnitFileState.Equals("not-found", StringComparison.Ordinal);
        return unit.MainProcessId is null or 0 && (absent || stopped && cannotAutoStart);
    }

    internal static void ValidateNodeId(string nodeId)
    {
        if (string.IsNullOrWhiteSpace(nodeId) || nodeId.Length > 128
            || nodeId.Any(static value => !(char.IsAsciiLetterOrDigit(value)
                || value is '.' or '_' or '-')))
        {
            throw new ArgumentException("linux-cutover-node-id-invalid", nameof(nodeId));
        }
    }
}

public sealed class LinuxLegacyWorkerCutoverProbe : ILinuxLegacyWorkerCutoverProbe
{
    private static readonly string[] DefaultLegacyUnits =
        ["hch-editorial-worker.service"];
    private readonly string runtimeDirectory;
    private readonly string systemctlPath;
    private readonly IReadOnlyList<string> legacyUnits;

    public LinuxLegacyWorkerCutoverProbe(
        string runtimeDirectory = "/run/hch-worker",
        string systemctlPath = "/usr/bin/systemctl",
        IReadOnlyList<string>? legacyUnits = null)
    {
        this.runtimeDirectory = LinuxPathSecurity.RequireAbsoluteCanonicalPath(runtimeDirectory);
        this.systemctlPath = LinuxPathSecurity.RequireAbsoluteCanonicalPath(systemctlPath);
        this.legacyUnits = legacyUnits ?? DefaultLegacyUnits;
        if (this.legacyUnits.Count == 0 || this.legacyUnits.Any(static unit =>
            string.IsNullOrWhiteSpace(unit) || !unit.EndsWith(".service", StringComparison.Ordinal)
            || unit.Any(static character => !(char.IsAsciiLetterOrDigit(character)
                || character is '.' or '_' or '-' or '@'))))
        {
            throw new ArgumentException("linux-cutover-unit-list-invalid", nameof(legacyUnits));
        }
    }

    public async ValueTask<LinuxLegacyWorkerCutoverEvidence> CaptureAsync(
        string nodeId,
        CancellationToken cancellationToken)
    {
        LinuxLegacyWorkerCutoverGuard.ValidateNodeId(nodeId);
        LinuxLegacyPidFileEvidence pid = CapturePidFile(
            Path.Combine(runtimeDirectory, $"legacy-{nodeId}.pid"));
        var units = new List<LinuxLegacySystemdEvidence>(legacyUnits.Count);
        foreach (string unit in legacyUnits)
        {
            units.Add(await CaptureUnitAsync(unit, cancellationToken).ConfigureAwait(false));
        }

        IReadOnlyList<LinuxLegacyProcessEvidence> conflicts = CaptureProcesses(nodeId);
        return new LinuxLegacyWorkerCutoverEvidence(nodeId, pid, units, conflicts, true);
    }

    private static LinuxLegacyPidFileEvidence CapturePidFile(string path)
    {
        LinuxFileMetadata metadata;
        try
        {
            metadata = LinuxPathSecurity.ReadMetadata(path);
        }
        catch (IOException error) when (error.InnerException is System.ComponentModel.Win32Exception native
            && native.NativeErrorCode == 2)
        {
            return new LinuxLegacyPidFileEvidence(path, false, null, false, true);
        }

        uint currentUid = LinuxPathSecurity.ReadMetadata($"/proc/{Environment.ProcessId}").OwnerUid;
        UnixFileMode mode = File.GetUnixFileMode(path);
        bool secure = metadata.IsRegularFile
            && (metadata.OwnerUid == 0 || metadata.OwnerUid == currentUid)
            && (mode & (UnixFileMode.GroupWrite | UnixFileMode.OtherWrite)) == 0;
        if (!secure)
        {
            return new LinuxLegacyPidFileEvidence(path, true, null, false, false);
        }

        string text = File.ReadAllText(path).Trim();
        int? processId = int.TryParse(text, NumberStyles.None, CultureInfo.InvariantCulture, out int parsed)
            && parsed > 0 ? parsed : null;
        return new LinuxLegacyPidFileEvidence(
            path,
            true,
            processId,
            processId is int value && Directory.Exists($"/proc/{value}"),
            secure);
    }

    private async Task<LinuxLegacySystemdEvidence> CaptureUnitAsync(
        string unit,
        CancellationToken cancellationToken)
    {
        if (!File.Exists(systemctlPath)
            || (File.GetUnixFileMode(systemctlPath)
                & (UnixFileMode.GroupWrite | UnixFileMode.OtherWrite)) != 0)
        {
            throw new LinuxLegacyWorkerCutoverException("linux-exclusive-systemd-unverifiable");
        }

        var start = new ProcessStartInfo
        {
            FileName = systemctlPath,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
        };
        start.ArgumentList.Add("show");
        start.ArgumentList.Add(unit);
        start.ArgumentList.Add("--no-pager");
        start.ArgumentList.Add("--property=LoadState,ActiveState,UnitFileState,MainPID");
        using var process = new Process { StartInfo = start };
        if (!process.Start())
        {
            throw new LinuxLegacyWorkerCutoverException("linux-exclusive-systemd-unverifiable");
        }

        Task<string> stdout = process.StandardOutput.ReadToEndAsync(cancellationToken);
        Task<string> stderr = process.StandardError.ReadToEndAsync(cancellationToken);
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(TimeSpan.FromSeconds(3));
        try
        {
            await process.WaitForExitAsync(timeout.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            TryKill(process);
            throw new LinuxLegacyWorkerCutoverException("linux-exclusive-systemd-unverifiable");
        }
        string output = await stdout.ConfigureAwait(false);
        string error = await stderr.ConfigureAwait(false);
        if (output.Length > 16 * 1024 || error.Length > 16 * 1024)
        {
            throw new LinuxLegacyWorkerCutoverException("linux-exclusive-systemd-unverifiable");
        }

        Dictionary<string, string> values = output.Split('\n', StringSplitOptions.RemoveEmptyEntries)
            .Select(static line => line.Split('=', 2))
            .Where(static fields => fields.Length == 2)
            .ToDictionary(static fields => fields[0], static fields => fields[1], StringComparer.Ordinal);
        if (!values.TryGetValue("LoadState", out string? load)
            || !values.TryGetValue("ActiveState", out string? active)
            || !values.TryGetValue("UnitFileState", out string? enabled)
            || !values.TryGetValue("MainPID", out string? pidText)
            || !int.TryParse(pidText, out int pid))
        {
            throw new LinuxLegacyWorkerCutoverException("linux-exclusive-systemd-unverifiable");
        }

        return new LinuxLegacySystemdEvidence(unit, load, active, enabled, pid == 0 ? null : pid);
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

    private static IReadOnlyList<LinuxLegacyProcessEvidence> CaptureProcesses(string nodeId)
    {
        var conflicts = new List<LinuxLegacyProcessEvidence>();
        foreach (string directory in Directory.EnumerateDirectories("/proc"))
        {
            if (!int.TryParse(Path.GetFileName(directory), out int pid)
                || pid == Environment.ProcessId)
            {
                continue;
            }

            try
            {
                string comm = File.ReadAllText(Path.Combine(directory, "comm")).Trim();
                if (!comm.Contains("hch", StringComparison.OrdinalIgnoreCase)
                    && !comm.Contains("worker", StringComparison.OrdinalIgnoreCase)
                    && !comm.Contains("node", StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                byte[] bytes = File.ReadAllBytes(Path.Combine(directory, "cmdline"));
                if (bytes.Length > 64 * 1024)
                {
                    throw new InvalidDataException("linux-cutover-process-command-too-large");
                }

                string command = System.Text.Encoding.UTF8.GetString(bytes).Replace('\0', ' ').Trim();
                if (command.Contains(nodeId, StringComparison.Ordinal))
                {
                    conflicts.Add(new LinuxLegacyProcessEvidence(pid, command[..Math.Min(512, command.Length)]));
                }
            }
            catch (IOException) when (!Directory.Exists(directory))
            {
                // Process exited during the scan.
            }
        }

        return conflicts;
    }
}
