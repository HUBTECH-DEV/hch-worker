using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security;
using Microsoft.Win32;
using Microsoft.Win32.SafeHandles;
using Hch.Worker.Persistence;

namespace Hch.Worker.Windows;

/// <summary>
/// Prevents the migrated 3.1 service and the native V4 service from claiming
/// work for the same node. The legacy installation is deliberately retained
/// for rollback, but it must be both stopped and disabled before V4 can leave
/// Paused/Drain.
/// </summary>
public sealed class WindowsLegacyWorkerCutoverGuard
{
    private readonly string nodeId;
    private readonly string legacyProductRoot;
    private readonly ILegacyWorkerCutoverProbe probe;

    public WindowsLegacyWorkerCutoverGuard(
        string nodeId,
        string? legacyProductRoot = null,
        ILegacyWorkerCutoverProbe? probe = null)
    {
        if (string.IsNullOrWhiteSpace(nodeId))
        {
            throw new ArgumentException("legacy-worker-node-id-invalid", nameof(nodeId));
        }

        this.nodeId = nodeId;
        this.legacyProductRoot = Path.GetFullPath(
            legacyProductRoot ?? LegacyWindowsWorkerPaths.DefaultProductRoot);
        this.probe = probe ?? new WindowsLegacyWorkerCutoverProbe();
    }

    public Task EnsureExclusiveAsync(CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        string serviceName = LegacyWindowsWorkerMigrator.CreateLegacyServiceName(nodeId);
        LegacyWorkerCutoverEvidence evidence;
        try
        {
            evidence = probe.Capture(serviceName);
        }
        catch (LegacyWorkerCutoverException)
        {
            throw;
        }
        catch (Exception error) when (error is Win32Exception or IOException or SecurityException
            or UnauthorizedAccessException or InvalidCastException or OverflowException)
        {
            throw new LegacyWorkerCutoverException(
                "legacy-worker-cutover-unverifiable",
                error);
        }

        if (!Directory.Exists(legacyProductRoot) && !evidence.ServiceInstalled)
        {
            return Task.CompletedTask;
        }

        ValidateExclusive(evidence, serviceName);
        return Task.CompletedTask;
    }

    public static void ValidateExclusive(
        LegacyWorkerCutoverEvidence evidence,
        string expectedServiceName)
    {
        ArgumentNullException.ThrowIfNull(evidence);
        if (!evidence.ServiceInstalled
            || !string.Equals(evidence.ServiceName, expectedServiceName, StringComparison.Ordinal)
            || !string.Equals(evidence.ServiceState, "Stopped", StringComparison.Ordinal)
            || evidence.ServiceProcessId is not null and not 0
            || evidence.StartMode != WindowsLegacyWorkerCutoverProbe.StartDisabled)
        {
            throw new LegacyWorkerCutoverException("legacy-worker-cutover-not-exclusive");
        }
    }
}

public sealed record LegacyWorkerCutoverEvidence(
    bool ServiceInstalled,
    string ServiceName,
    string ServiceState,
    int? ServiceProcessId,
    int StartMode);

public interface ILegacyWorkerCutoverProbe
{
    LegacyWorkerCutoverEvidence Capture(string serviceName);
}

public sealed class LegacyWorkerCutoverException : Exception
{
    public LegacyWorkerCutoverException(string code, Exception? innerException = null)
        : base("The legacy Worker cutover is not exclusive.", innerException)
    {
        Code = code;
    }

    public string Code { get; }
}

internal sealed class WindowsLegacyWorkerCutoverProbe : ILegacyWorkerCutoverProbe
{
    internal const int StartDisabled = 4;
    private const uint ScManagerConnect = 0x0001;
    private const uint ServiceQueryStatus = 0x0004;
    private const int ScStatusProcessInfo = 0;
    private const uint ServiceStopped = 0x00000001;

    public LegacyWorkerCutoverEvidence Capture(string serviceName)
    {
        using RegistryKey? key = Registry.LocalMachine.OpenSubKey(
            $@"SYSTEM\CurrentControlSet\Services\{serviceName}",
            writable: false);
        if (key is null)
        {
            return new LegacyWorkerCutoverEvidence(
                false,
                serviceName,
                "Missing",
                null,
                -1);
        }

        int startMode = key.GetValue(
            "Start",
            null,
            RegistryValueOptions.DoNotExpandEnvironmentNames) is int start
                ? start
                : throw new LegacyWorkerCutoverException("legacy-worker-cutover-unverifiable");

        using SafeServiceHandle manager = OpenSCManager(null, null, ScManagerConnect);
        if (manager.IsInvalid)
        {
            throw new Win32Exception(Marshal.GetLastWin32Error());
        }

        using SafeServiceHandle service = OpenService(manager, serviceName, ServiceQueryStatus);
        if (service.IsInvalid)
        {
            throw new Win32Exception(Marshal.GetLastWin32Error());
        }

        ServiceStatusProcess status = QueryStatus(service);
        return new LegacyWorkerCutoverEvidence(
            true,
            serviceName,
            status.CurrentState == ServiceStopped ? "Stopped" : "Running",
            status.ProcessId == 0 ? null : checked((int)status.ProcessId),
            startMode);
    }

    private static ServiceStatusProcess QueryStatus(SafeServiceHandle service)
    {
        int size = Marshal.SizeOf<ServiceStatusProcess>();
        IntPtr buffer = Marshal.AllocHGlobal(size);
        try
        {
            if (!QueryServiceStatusEx(
                service,
                ScStatusProcessInfo,
                buffer,
                size,
                out int bytesNeeded)
                || bytesNeeded > size)
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }

            return Marshal.PtrToStructure<ServiceStatusProcess>(buffer);
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ServiceStatusProcess
    {
        public uint ServiceType;
        public uint CurrentState;
        public uint ControlsAccepted;
        public uint Win32ExitCode;
        public uint ServiceSpecificExitCode;
        public uint CheckPoint;
        public uint WaitHint;
        public uint ProcessId;
        public uint ServiceFlags;
    }

    private sealed class SafeServiceHandle : SafeHandleZeroOrMinusOneIsInvalid
    {
        private SafeServiceHandle() : base(ownsHandle: true)
        {
        }

        protected override bool ReleaseHandle() => CloseServiceHandle(handle);
    }

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeServiceHandle OpenSCManager(
        string? machineName,
        string? databaseName,
        uint desiredAccess);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeServiceHandle OpenService(
        SafeServiceHandle serviceManager,
        string serviceName,
        uint desiredAccess);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool QueryServiceStatusEx(
        SafeServiceHandle service,
        int infoLevel,
        IntPtr buffer,
        int bufferSize,
        out int bytesNeeded);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseServiceHandle(IntPtr serviceHandle);
}
