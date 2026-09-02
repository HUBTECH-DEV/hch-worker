using System.ComponentModel;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Security.Principal;
using Microsoft.Win32.SafeHandles;

namespace Hch.Worker.Windows;

/// <summary>
/// Authenticates the process at the server end of a connected local pipe before
/// the client is permitted to transmit an IPC frame.
/// </summary>
public interface ILocalPipeServerAuthenticator
{
    void Authenticate(NamedPipeClientStream pipe);
}

/// <summary>
/// Binds the tray connection to the one SCM-owned HCH Worker service process.
/// </summary>
public sealed class WindowsServicePipeServerAuthenticator(string serviceName)
    : ILocalPipeServerAuthenticator
{
    private const uint ScManagerConnect = 0x0001;
    private const uint ServiceQueryConfig = 0x0001;
    private const uint ServiceQueryStatus = 0x0004;
    private const int ScStatusProcessInfo = 0;
    private const int ErrorInsufficientBuffer = 122;

    public void Authenticate(NamedPipeClientStream pipe)
    {
        ArgumentNullException.ThrowIfNull(pipe);
        string validatedServiceName = ValidateServiceName(serviceName);
        try
        {
            NamedPipeServerIdentity pipeIdentityBefore = LocalNamedPipe.GetServerIdentity(pipe);
            ServiceSnapshot serviceBefore = ReadService(validatedServiceName);
            SecurityIdentifier serviceSid = WindowsServiceIdentity.ResolveServiceSid(validatedServiceName);
            var systemSid = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
            string configuredImage = ParseExecutablePath(serviceBefore.BinaryPath);
            using WindowsTrustedProcessLease process = WindowsTrustedProcessVerifier.Verify(
                pipeIdentityBefore.ProcessId,
                Path.GetFileName(configuredImage),
                [systemSid, serviceSid],
                [serviceSid]);
            string processImage = process.ImagePath;
            bool imagePathMatches = string.Equals(
                configuredImage,
                processImage,
                StringComparison.OrdinalIgnoreCase);

            NamedPipeServerIdentity pipeIdentityAfter = LocalNamedPipe.GetServerIdentity(pipe);
            ServiceSnapshot serviceAfter = ReadService(validatedServiceName);
            process.EnsureAlive();
            WindowsPipeServerSecurityPolicy.Validate(new WindowsPipeServerEvidence(
                validatedServiceName,
                pipeIdentityBefore.ProcessId,
                pipeIdentityAfter.ProcessId,
                pipeIdentityBefore.SessionId,
                serviceBefore.ProcessId,
                serviceAfter.ProcessId,
                serviceBefore.CurrentState,
                serviceBefore.ServiceType,
                serviceBefore.ServiceStartName,
                process.UserSid,
                serviceSid,
                configuredImage,
                processImage,
                ImageDaclSafe: imagePathMatches,
                AuthenticodeTrusted: imagePathMatches));
        }
        catch (UnauthorizedAccessException)
        {
            throw;
        }
        catch (Exception error) when (error is Win32Exception or IOException
            or InvalidOperationException or ArgumentException
            or System.Security.Cryptography.CryptographicException)
        {
            throw new UnauthorizedAccessException(
                "windows-local-pipe-server-attestation-failed",
                error);
        }
    }

    private static ServiceSnapshot ReadService(string validatedServiceName)
    {
        using SafeServiceHandle manager = OpenSCManager(null, null, ScManagerConnect);
        if (manager.IsInvalid)
        {
            throw new Win32Exception(Marshal.GetLastWin32Error());
        }

        using SafeServiceHandle service = OpenService(
            manager,
            validatedServiceName,
            ServiceQueryConfig | ServiceQueryStatus);
        if (service.IsInvalid)
        {
            throw new Win32Exception(Marshal.GetLastWin32Error());
        }

        int statusSize = Marshal.SizeOf<ServiceStatusProcess>();
        nint statusBuffer = Marshal.AllocHGlobal(statusSize);
        try
        {
            if (!QueryServiceStatusEx(
                    service,
                    ScStatusProcessInfo,
                    statusBuffer,
                    statusSize,
                    out int statusBytesNeeded)
                || statusBytesNeeded > statusSize)
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }

            ServiceStatusProcess status = Marshal.PtrToStructure<ServiceStatusProcess>(statusBuffer);
            QueryServiceConfig(service, out string binaryPath, out string serviceStartName);
            return new ServiceSnapshot(
                status.ProcessId,
                status.CurrentState,
                status.ServiceType,
                binaryPath,
                serviceStartName);
        }
        finally
        {
            Marshal.FreeHGlobal(statusBuffer);
        }
    }

    private static void QueryServiceConfig(
        SafeServiceHandle service,
        out string binaryPath,
        out string serviceStartName)
    {
        _ = QueryServiceConfigNative(service, nint.Zero, 0, out uint bytesNeeded);
        int error = Marshal.GetLastWin32Error();
        if (error != ErrorInsufficientBuffer || bytesNeeded == 0)
        {
            throw new Win32Exception(error);
        }

        nint buffer = Marshal.AllocHGlobal(checked((int)bytesNeeded));
        try
        {
            if (!QueryServiceConfigNative(service, buffer, bytesNeeded, out _))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }

            QueryServiceConfigValue config = Marshal.PtrToStructure<QueryServiceConfigValue>(buffer);
            binaryPath = Marshal.PtrToStringUni(config.BinaryPathName)
                ?? throw new InvalidOperationException("windows-service-image-path-unavailable");
            serviceStartName = Marshal.PtrToStringUni(config.ServiceStartName)
                ?? throw new InvalidOperationException("windows-service-account-unavailable");
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    private static string ParseExecutablePath(string commandLine)
    {
        string expanded = Environment.ExpandEnvironmentVariables(commandLine).Trim();
        if (expanded.Length == 0)
        {
            throw new InvalidOperationException("windows-service-image-path-invalid");
        }

        string executable;
        if (expanded[0] == '"')
        {
            int closingQuote = expanded.IndexOf('"', 1);
            if (closingQuote <= 1)
            {
                throw new InvalidOperationException("windows-service-image-path-invalid");
            }

            executable = expanded[1..closingQuote];
        }
        else
        {
            int executableEnd = expanded.IndexOf(".exe", StringComparison.OrdinalIgnoreCase);
            if (executableEnd < 1)
            {
                throw new InvalidOperationException("windows-service-image-path-invalid");
            }

            executableEnd += 4;
            if (executableEnd < expanded.Length && !char.IsWhiteSpace(expanded[executableEnd]))
            {
                throw new InvalidOperationException("windows-service-image-path-invalid");
            }

            executable = expanded[..executableEnd];
        }

        return CanonicalPath(executable);
    }

    private static string CanonicalPath(string path)
    {
        if (string.IsNullOrWhiteSpace(path) || !Path.IsPathFullyQualified(path)
            || path.StartsWith("\\\\", StringComparison.Ordinal))
        {
            throw new InvalidOperationException("windows-service-image-path-invalid");
        }

        string fullPath = Path.GetFullPath(path);
        if (!File.Exists(fullPath))
        {
            throw new FileNotFoundException("windows-service-image-not-found", fullPath);
        }

        RejectReparsePoints(fullPath);
        return new FileInfo(fullPath).FullName;
    }

    private static void RejectReparsePoints(string path)
    {
        string? current = path;
        while (!string.IsNullOrEmpty(current))
        {
            if ((File.GetAttributes(current) & FileAttributes.ReparsePoint) != 0)
            {
                throw new IOException("windows-service-image-reparse-point-refused");
            }

            string? parent = Path.GetDirectoryName(current);
            if (string.Equals(parent, current, StringComparison.OrdinalIgnoreCase))
            {
                break;
            }

            current = parent;
        }
    }

    private static string ValidateServiceName(string value)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(value);
        if (value.Length > 80 || value.Any(static character =>
                !(char.IsAsciiLetterOrDigit(character) || character is '.' or '_' or '-')))
        {
            throw new ArgumentException("windows-service-name-invalid", nameof(value));
        }

        return value;
    }

    private sealed record ServiceSnapshot(
        uint ProcessId,
        uint CurrentState,
        uint ServiceType,
        string BinaryPath,
        string ServiceStartName);

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

    [StructLayout(LayoutKind.Sequential)]
    private struct QueryServiceConfigValue
    {
        public uint ServiceType;
        public uint StartType;
        public uint ErrorControl;
        public nint BinaryPathName;
        public nint LoadOrderGroup;
        public uint TagId;
        public nint Dependencies;
        public nint ServiceStartName;
        public nint DisplayName;
    }

    private sealed class SafeServiceHandle : SafeHandleZeroOrMinusOneIsInvalid
    {
        private SafeServiceHandle()
            : base(ownsHandle: true)
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

    [DllImport("advapi32.dll", EntryPoint = "QueryServiceConfigW", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool QueryServiceConfigNative(
        SafeServiceHandle service,
        nint serviceConfig,
        uint bufferSize,
        out uint bytesNeeded);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseServiceHandle(nint serviceHandle);

}

/// <summary>Immutable facts used by the attestation policy and adversarial tests.</summary>
public sealed record WindowsPipeServerEvidence(
    string ExpectedServiceName,
    uint PipeProcessIdBefore,
    uint PipeProcessIdAfter,
    uint? PipeSessionId,
    uint ServiceProcessIdBefore,
    uint ServiceProcessIdAfter,
    uint ServiceState,
    uint ServiceType,
    string ServiceStartName,
    SecurityIdentifier ProcessUserSid,
    SecurityIdentifier ServiceSid,
    string ConfiguredImagePath,
    string ProcessImagePath,
    bool ImageDaclSafe,
    bool AuthenticodeTrusted);

/// <summary>Pure fail-closed policy for authenticating the pipe server.</summary>
public static class WindowsPipeServerSecurityPolicy
{
    private const uint ServiceWin32OwnProcess = 0x00000010;
    private const uint ServiceWin32ShareProcess = 0x00000020;
    private const uint ServiceRunning = 0x00000004;

    public static void Validate(WindowsPipeServerEvidence evidence)
    {
        ArgumentNullException.ThrowIfNull(evidence);
        var systemSid = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
        bool serviceAccountAllowed = IsLocalSystemAccount(evidence.ServiceStartName)
            || evidence.ServiceStartName.Equals(
                $"NT SERVICE\\{evidence.ExpectedServiceName}",
                StringComparison.OrdinalIgnoreCase);
        bool processIdentityAllowed = evidence.ProcessUserSid.Equals(systemSid)
            || evidence.ProcessUserSid.Equals(evidence.ServiceSid);

        if (evidence.PipeProcessIdBefore == 0
            || evidence.PipeProcessIdBefore != evidence.PipeProcessIdAfter
            || evidence.PipeProcessIdBefore != evidence.ServiceProcessIdBefore
            || evidence.PipeProcessIdBefore != evidence.ServiceProcessIdAfter
            || evidence.PipeSessionId != 0
            || evidence.ServiceState != ServiceRunning
            || (evidence.ServiceType & ServiceWin32OwnProcess) == 0
            || (evidence.ServiceType & ServiceWin32ShareProcess) != 0
            || !serviceAccountAllowed
            || !processIdentityAllowed
            || !string.Equals(
                Path.GetFullPath(evidence.ConfiguredImagePath),
                Path.GetFullPath(evidence.ProcessImagePath),
                StringComparison.OrdinalIgnoreCase)
            || !evidence.ImageDaclSafe
            || !evidence.AuthenticodeTrusted)
        {
            throw new UnauthorizedAccessException("windows-local-pipe-server-untrusted");
        }
    }

    private static bool IsLocalSystemAccount(string value) =>
        value.Equals("LocalSystem", StringComparison.OrdinalIgnoreCase)
        || value.Equals(@".\LocalSystem", StringComparison.OrdinalIgnoreCase)
        || value.Equals(@"NT AUTHORITY\SYSTEM", StringComparison.OrdinalIgnoreCase);

}
