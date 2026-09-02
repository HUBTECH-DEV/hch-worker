using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.AccessControl;
using System.Security.Cryptography;
using Microsoft.Win32;
using Microsoft.Win32.SafeHandles;
using Hch.Worker.Persistence;

namespace Hch.Worker.Windows;

/// <summary>
/// Captures fail-closed Windows evidence for the legacy Worker. It never stops,
/// reconfigures, deletes, or writes the legacy service/state.
/// </summary>
public sealed class WindowsLegacyWorkerRuntimePreflight : ILegacyWorkerRuntimePreflight
{
    private const uint ScManagerConnect = 0x0001;
    private const uint ServiceQueryStatus = 0x0004;
    private const uint ReadControl = 0x00020000;
    private const int ScStatusProcessInfo = 0;
    private const uint ServiceStopped = 0x00000001;
    private const uint OwnerSecurityInformation = 0x00000001;
    private const uint GroupSecurityInformation = 0x00000002;
    private const uint DaclSecurityInformation = 0x00000004;
    private const int ErrorInsufficientBuffer = 122;

    public Task<LegacyRuntimePreflightEvidence> CaptureAsync(
        LegacyWorkerSourceDescriptor source,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(source);
        cancellationToken.ThrowIfCancellationRequested();
        try
        {
            using SafeServiceHandle manager = OpenSCManager(null, null, ScManagerConnect);
            if (manager.IsInvalid)
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }

            using SafeServiceHandle service = OpenService(
                manager,
                source.ServiceName,
                ServiceQueryStatus | ReadControl);
            if (service.IsInvalid)
            {
                throw new LegacyMigrationException("legacy-service-status-unverifiable");
            }

            ServiceStatusProcess status = QueryStatus(service);
            LegacyServiceDefinitionReceipt definition = ReadServiceDefinition(
                service,
                source.ServiceName);
            IReadOnlyList<LegacyAclReceipt> acls = CaptureAcls(source.ProductRoot);
            bool writerLocksAvailable = ProbeWriterLocks(source.StateRoot);
            return Task.FromResult(new LegacyRuntimePreflightEvidence(
                ServiceInstalled: true,
                source.ServiceName,
                ServiceState(status.CurrentState),
                status.ProcessId == 0 ? null : checked((int)status.ProcessId),
                writerLocksAvailable,
                definition,
                acls,
                DateTimeOffset.UtcNow));
        }
        catch (LegacyMigrationException)
        {
            throw;
        }
        catch (Exception error) when (error is Win32Exception or IOException
            or UnauthorizedAccessException or SecurityException or InvalidCastException
            or OverflowException or ArgumentException or NotSupportedException
            or PathTooLongException)
        {
            throw new LegacyMigrationException("legacy-runtime-preflight-unverifiable");
        }
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

    private static LegacyServiceDefinitionReceipt ReadServiceDefinition(
        SafeServiceHandle service,
        string serviceName)
    {
        using RegistryKey? key = Registry.LocalMachine.OpenSubKey(
            $@"SYSTEM\CurrentControlSet\Services\{serviceName}",
            writable: false);
        if (key is null)
        {
            throw new LegacyMigrationException("legacy-service-definition-missing");
        }

        string imagePath = RequiredRegistryString(key, "ImagePath");
        string executablePath = ResolveServiceExecutable(imagePath);
        (string executableVersion, string executableSha256) = CaptureExecutable(executablePath);
        string accountName = RequiredRegistryString(key, "ObjectName");
        int start = RequiredRegistryInteger(key, "Start");
        int type = RequiredRegistryInteger(key, "Type");
        bool delayed = OptionalRegistryInteger(key, "DelayedAutoStart") == 1;
        byte[] failureActions = key.GetValue(
            "FailureActions",
            Array.Empty<byte>(),
            RegistryValueOptions.DoNotExpandEnvironmentNames) as byte[] ?? [];
        string failureActionsHash;
        try
        {
            failureActionsHash = Convert.ToHexStringLower(SHA256.HashData(failureActions));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(failureActions);
        }

        return new LegacyServiceDefinitionReceipt(
            serviceName,
            imagePath,
            executablePath,
            executableVersion,
            executableSha256,
            accountName,
            start,
            type,
            delayed,
            failureActionsHash,
            ReadServiceSecurityDescriptor(service));
    }

    private static string ResolveServiceExecutable(string imagePath)
    {
        ReadOnlySpan<char> command = imagePath.AsSpan().Trim();
        if (command.IsEmpty)
        {
            throw new LegacyMigrationException("legacy-service-executable-invalid");
        }

        ReadOnlySpan<char> executable;
        if (command[0] == '"')
        {
            int closingQuote = command[1..].IndexOf('"');
            if (closingQuote < 0)
            {
                throw new LegacyMigrationException("legacy-service-executable-invalid");
            }

            closingQuote++;
            executable = command[1..closingQuote];
            ReadOnlySpan<char> arguments = command[(closingQuote + 1)..];
            if (!arguments.IsEmpty && !char.IsWhiteSpace(arguments[0]))
            {
                throw new LegacyMigrationException("legacy-service-executable-invalid");
            }
        }
        else
        {
            int firstWhitespace = command.IndexOfAny(" \t\r\n");
            executable = firstWhitespace < 0 ? command : command[..firstWhitespace];
        }

        string candidate = executable.ToString();
        if (!Path.IsPathFullyQualified(candidate)
            || candidate.StartsWith("\\\\", StringComparison.Ordinal))
        {
            throw new LegacyMigrationException("legacy-service-executable-invalid");
        }

        string path = Path.GetFullPath(candidate);
        if (!File.Exists(path)
            || (File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0
            || !Path.GetFileName(path).Equals(
                "HchEditorialWorkerService.exe",
                StringComparison.OrdinalIgnoreCase))
        {
            throw new LegacyMigrationException("legacy-service-executable-invalid");
        }

        return path;
    }

    private static (string Version, string Sha256) CaptureExecutable(string executablePath)
    {
        // Deny concurrent write/delete while reading both the Win32 version
        // resource and the bytes whose hash is bound into migration evidence.
        using var stream = new FileStream(
            executablePath,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            128 * 1024,
            FileOptions.SequentialScan);
        FileVersionInfo version = FileVersionInfo.GetVersionInfo(executablePath);
        if (version.FileMajorPart != 3
            || version.FileMinorPart != 1
            || version.FileBuildPart is not (0 or 1)
            || version.FilePrivatePart != 0)
        {
            throw new LegacyMigrationException("legacy-source-version-unsupported");
        }

        byte[] digest = SHA256.HashData(stream);
        try
        {
            return (
                $"{version.FileMajorPart}.{version.FileMinorPart}.{version.FileBuildPart}",
                Convert.ToHexStringLower(digest));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(digest);
        }
    }

    private static string ReadServiceSecurityDescriptor(SafeServiceHandle service)
    {
        uint information = OwnerSecurityInformation | GroupSecurityInformation | DaclSecurityInformation;
        _ = QueryServiceObjectSecurity(service, information, null, 0, out uint needed);
        if (needed == 0 || Marshal.GetLastWin32Error() != ErrorInsufficientBuffer || needed > 64 * 1024)
        {
            throw new Win32Exception(Marshal.GetLastWin32Error());
        }

        byte[] descriptorBytes = new byte[checked((int)needed)];
        try
        {
            if (!QueryServiceObjectSecurity(
                service,
                information,
                descriptorBytes,
                needed,
                out uint written)
                || written > needed)
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }

            var descriptor = new RawSecurityDescriptor(descriptorBytes, 0);
            return descriptor.GetSddlForm(
                AccessControlSections.Owner | AccessControlSections.Group | AccessControlSections.Access);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(descriptorBytes);
        }
    }

    private static IReadOnlyList<LegacyAclReceipt> CaptureAcls(string productRoot)
    {
        string root = Path.GetFullPath(productRoot);
        var receipts = new List<LegacyAclReceipt>();
        foreach (string topLevel in new[] { "config", "state", "trust" })
        {
            string path = Path.Combine(root, topLevel);
            if (Directory.Exists(path))
            {
                CaptureAclTree(root, path, receipts);
            }
        }

        return receipts
            .OrderBy(static value => value.RelativePath, StringComparer.Ordinal)
            .ToArray();
    }

    private static void CaptureAclTree(
        string root,
        string current,
        ICollection<LegacyAclReceipt> receipts)
    {
        FileAttributes attributes = File.GetAttributes(current);
        if ((attributes & FileAttributes.ReparsePoint) != 0)
        {
            throw new LegacyMigrationException("legacy-acl-reparse-point-refused");
        }

        if ((attributes & FileAttributes.Directory) != 0)
        {
            var directory = new DirectoryInfo(current);
            receipts.Add(new LegacyAclReceipt(
                Relative(root, current),
                directory.GetAccessControl(
                    AccessControlSections.Owner | AccessControlSections.Group | AccessControlSections.Access)
                    .GetSecurityDescriptorSddlForm(
                        AccessControlSections.Owner | AccessControlSections.Group | AccessControlSections.Access)));
            foreach (string child in Directory.EnumerateFileSystemEntries(current))
            {
                CaptureAclTree(root, child, receipts);
            }
        }
        else
        {
            var file = new FileInfo(current);
            receipts.Add(new LegacyAclReceipt(
                Relative(root, current),
                file.GetAccessControl(
                    AccessControlSections.Owner | AccessControlSections.Group | AccessControlSections.Access)
                    .GetSecurityDescriptorSddlForm(
                        AccessControlSections.Owner | AccessControlSections.Group | AccessControlSections.Access)));
        }
    }

    private static bool ProbeWriterLocks(string stateRoot)
    {
        foreach (string relativePath in new[]
        {
            "bootstrap.lock",
            Path.Combine("cycles", "cycle.lock"),
        })
        {
            string path = Path.Combine(stateRoot, relativePath);
            if (!File.Exists(path))
            {
                continue;
            }

            try
            {
                using var probe = new FileStream(
                    path,
                    FileMode.Open,
                    FileAccess.ReadWrite,
                    FileShare.None);
            }
            catch (Exception error) when (error is IOException or UnauthorizedAccessException)
            {
                return false;
            }
        }

        return true;
    }

    private static string RequiredRegistryString(RegistryKey key, string name) =>
        key.GetValue(name, null, RegistryValueOptions.DoNotExpandEnvironmentNames) is string value
        && !string.IsNullOrWhiteSpace(value)
            ? value
            : throw new LegacyMigrationException("legacy-service-definition-invalid");

    private static int RequiredRegistryInteger(RegistryKey key, string name) =>
        key.GetValue(name, null, RegistryValueOptions.DoNotExpandEnvironmentNames) is int value
            ? value
            : throw new LegacyMigrationException("legacy-service-definition-invalid");

    private static int OptionalRegistryInteger(RegistryKey key, string name) =>
        key.GetValue(name, 0, RegistryValueOptions.DoNotExpandEnvironmentNames) is int value
            ? value
            : throw new LegacyMigrationException("legacy-service-definition-invalid");

    private static string Relative(string root, string path) =>
        Path.GetRelativePath(root, path).Replace(Path.DirectorySeparatorChar, '/');

    private static string ServiceState(uint state) => state switch
    {
        ServiceStopped => "Stopped",
        2 => "StartPending",
        3 => "StopPending",
        4 => "Running",
        5 => "ContinuePending",
        6 => "PausePending",
        7 => "Paused",
        _ => "Unknown",
    };

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
        private SafeServiceHandle()
            : base(ownsHandle: true)
        {
        }

        protected override bool ReleaseHandle() => CloseServiceHandle(handle);
    }

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern SafeServiceHandle OpenSCManager(
        string? machineName,
        string? databaseName,
        uint desiredAccess);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
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
    private static extern bool QueryServiceObjectSecurity(
        SafeServiceHandle service,
        uint securityInformation,
        byte[]? securityDescriptor,
        uint bufferSize,
        out uint bytesNeeded);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseServiceHandle(IntPtr serviceHandle);
}
