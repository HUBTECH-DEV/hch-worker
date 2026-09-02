using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace Hch.Worker.Windows;

public sealed record WindowsServiceStatus(
    string State,
    bool Available,
    string? UnavailableReason = null);

public interface IWindowsServiceStateProvider
{
    WindowsServiceStatus Collect(string serviceName, int expectedProcessId);
}

/// <summary>
/// Reads the authoritative SCM state and binds a running state to this exact
/// process. Query failures become Unknown and never masquerade as Running.
/// </summary>
public sealed class WindowsServiceStateProvider : IWindowsServiceStateProvider
{
    private const uint ScManagerConnect = 0x0001;
    private const uint ServiceQueryStatus = 0x0004;
    private const int ScStatusProcessInfo = 0;
    private const int ErrorServiceDoesNotExist = 1060;

    public static WindowsServiceStateProvider Instance { get; } = new();

    public WindowsServiceStatus Collect(string serviceName, int expectedProcessId)
    {
        if (string.IsNullOrWhiteSpace(serviceName) || expectedProcessId < 1)
        {
            return new WindowsServiceStatus("Unknown", false, "service-query-input-invalid");
        }

        if (!OperatingSystem.IsWindows())
        {
            return new WindowsServiceStatus("Unknown", false, "service-query-platform-unsupported");
        }

        try
        {
            using SafeServiceHandle manager = OpenSCManager(null, null, ScManagerConnect);
            if (manager.IsInvalid)
            {
                return Unknown("service-manager-unavailable");
            }

            using SafeServiceHandle service = OpenService(manager, serviceName, ServiceQueryStatus);
            if (service.IsInvalid)
            {
                return Marshal.GetLastWin32Error() == ErrorServiceDoesNotExist
                    ? new WindowsServiceStatus("NotInstalled", true)
                    : Unknown("service-query-unavailable");
            }

            ServiceStatusProcess status = QueryStatus(service);
            return Normalize(status.CurrentState, status.ProcessId, checked((uint)expectedProcessId));
        }
        catch (Exception error) when (error is Win32Exception
            or OverflowException
            or InvalidOperationException)
        {
            return Unknown("service-query-failed");
        }
    }

    internal static WindowsServiceStatus Normalize(
        uint nativeState,
        uint processId,
        uint expectedProcessId)
    {
        string? state = nativeState switch
        {
            0x00000001 => "Stopped",
            0x00000002 => "StartPending",
            0x00000003 => "StopPending",
            0x00000004 => "Running",
            0x00000005 => "ContinuePending",
            0x00000006 => "PausePending",
            0x00000007 => "Paused",
            _ => null,
        };
        if (state is null)
        {
            return Unknown("service-state-invalid");
        }

        if (nativeState == 0x00000001)
        {
            return processId == 0
                ? new WindowsServiceStatus(state, true)
                : Unknown("service-stopped-process-mismatch");
        }

        return processId == expectedProcessId
            ? new WindowsServiceStatus(state, true)
            : Unknown("service-process-mismatch");
    }

    private static WindowsServiceStatus Unknown(string reason) =>
        new("Unknown", false, reason);

    private static ServiceStatusProcess QueryStatus(SafeServiceHandle service)
    {
        int size = Marshal.SizeOf<ServiceStatusProcess>();
        nint buffer = Marshal.AllocHGlobal(size);
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
        nint buffer,
        int bufferSize,
        out int bytesNeeded);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseServiceHandle(nint serviceHandle);
}
