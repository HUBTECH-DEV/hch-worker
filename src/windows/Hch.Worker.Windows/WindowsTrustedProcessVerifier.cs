using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace Hch.Worker.Windows;

/// <summary>
/// Security-relevant facts collected while a stable process handle is held.
/// Kept separate from collection so every negative gate has deterministic,
/// adversarial unit coverage.
/// </summary>
public sealed record WindowsTrustedProcessEvidence(
    bool ProcessUserAllowed,
    bool ImageNameMatches,
    bool ImagePathCanonicalAndReparseFree,
    bool ImageAclSafe,
    bool AuthenticodeTrusted,
    bool ProcessAlive);

public static class WindowsTrustedProcessSecurityPolicy
{
    public static void Validate(WindowsTrustedProcessEvidence evidence)
    {
        ArgumentNullException.ThrowIfNull(evidence);
        if (!evidence.ProcessUserAllowed || !evidence.ImageNameMatches)
        {
            throw new UnauthorizedAccessException("windows-trusted-process-identity-invalid");
        }

        if (!evidence.ImagePathCanonicalAndReparseFree)
        {
            throw new UnauthorizedAccessException("windows-trusted-process-image-path-invalid");
        }

        if (!evidence.ImageAclSafe || !evidence.AuthenticodeTrusted)
        {
            throw new UnauthorizedAccessException("windows-trusted-process-image-untrusted");
        }

        if (!evidence.ProcessAlive)
        {
            throw new UnauthorizedAccessException("windows-trusted-process-exited");
        }
    }
}

/// <summary>
/// Anchors one Windows process object while its identity, image, ACL and
/// Authenticode trust are evaluated. Keeping the handle open prevents PID reuse
/// from changing the meaning of the collected evidence.
/// </summary>
public sealed class WindowsTrustedProcessLease : IDisposable
{
    private const uint StillActive = 259;
    private SafeProcessHandle? process;

    internal WindowsTrustedProcessLease(
        SafeProcessHandle process,
        uint processId,
        string imagePath,
        SecurityIdentifier userSid)
    {
        this.process = process;
        ProcessId = processId;
        ImagePath = imagePath;
        UserSid = userSid;
    }

    public uint ProcessId { get; }

    public string ImagePath { get; }

    public SecurityIdentifier UserSid { get; }

    public void EnsureAlive()
    {
        SafeProcessHandle handle = process
            ?? throw new ObjectDisposedException(nameof(WindowsTrustedProcessLease));
        if (!GetExitCodeProcess(handle, out uint exitCode) || exitCode != StillActive)
        {
            throw new UnauthorizedAccessException("windows-trusted-process-exited");
        }
    }

    public void Dispose()
    {
        SafeProcessHandle? handle = Interlocked.Exchange(ref process, null);
        handle?.Dispose();
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetExitCodeProcess(
        SafeProcessHandle process,
        out uint exitCode);
}

/// <summary>Shared fail-closed verifier for trusted Worker-side executables.</summary>
public static class WindowsTrustedProcessVerifier
{
    private const uint ProcessQueryLimitedInformation = 0x1000;
    private const uint TokenQuery = 0x0008;
    private const int TokenUserInformation = 1;
    private const int ErrorInsufficientBuffer = 122;
    private const uint WinTrustUiNone = 2;
    private const uint WinTrustChoiceFile = 1;
    private const uint WinTrustRevocationChecksNone = 0;
    private const uint WinTrustCacheOnlyUrlRetrieval = 0x00001000;
    private const uint WinTrustRevocationCheckNone = 0x00000010;
    private const uint WinTrustSaferFlag = 0x00000100;

    private static readonly SecurityIdentifier SystemSid =
        new(WellKnownSidType.LocalSystemSid, null);

    private static readonly SecurityIdentifier AdministratorsSid =
        new(WellKnownSidType.BuiltinAdministratorsSid, null);

    private static readonly Guid WinTrustActionGenericVerifyV2 =
        new("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");

    public static WindowsTrustedProcessLease Verify(
        uint processId,
        string expectedImageFileName,
        IEnumerable<SecurityIdentifier> permittedProcessUsers,
        IEnumerable<SecurityIdentifier>? additionalPermittedWriters = null)
    {
        if (processId == 0)
        {
            throw new UnauthorizedAccessException("windows-trusted-process-pid-invalid");
        }

        ValidateImageFileName(expectedImageFileName);
        ArgumentNullException.ThrowIfNull(permittedProcessUsers);
        var processUsers = permittedProcessUsers
            .Where(static sid => sid is not null)
            .ToDictionary(static sid => sid.Value, StringComparer.Ordinal);
        if (processUsers.Count == 0)
        {
            throw new ArgumentException(
                "windows-trusted-process-users-empty",
                nameof(permittedProcessUsers));
        }

        SafeProcessHandle process = OpenProcess(
            ProcessQueryLimitedInformation,
            inheritHandle: false,
            processId);
        if (process.IsInvalid)
        {
            process.Dispose();
            throw new Win32Exception(Marshal.GetLastWin32Error());
        }

        try
        {
            string imagePath = ReadImagePath(process);
            SecurityIdentifier userSid = ReadTokenUser(process);
            bool processUserAllowed = processUsers.ContainsKey(userSid.Value);
            bool imageNameMatches = string.Equals(
                Path.GetFileName(imagePath),
                expectedImageFileName,
                StringComparison.OrdinalIgnoreCase);

            var writers = new Dictionary<string, SecurityIdentifier>(StringComparer.Ordinal)
            {
                [SystemSid.Value] = SystemSid,
                [AdministratorsSid.Value] = AdministratorsSid,
                [userSid.Value] = userSid,
            };
            if (additionalPermittedWriters is not null)
            {
                foreach (SecurityIdentifier sid in additionalPermittedWriters)
                {
                    ArgumentNullException.ThrowIfNull(sid);
                    writers[sid.Value] = sid;
                }
            }

            try
            {
                SecurityIdentifier trustedInstaller =
                    WindowsServiceIdentity.ResolveAccountSid("NT SERVICE\\TrustedInstaller");
                writers[trustedInstaller.Value] = trustedInstaller;
            }
            catch (Win32Exception)
            {
                // Reduced Windows images can omit TrustedInstaller. No broad
                // fallback identity is introduced.
            }

            bool imageAclSafe = IsPathAclSafe(
                imagePath,
                writers.Keys.ToHashSet(StringComparer.Ordinal));
            bool authenticodeTrusted = VerifyAuthenticode(imagePath);

            var lease = new WindowsTrustedProcessLease(process, processId, imagePath, userSid);
            process = null!;
            try
            {
                lease.EnsureAlive();
                WindowsTrustedProcessSecurityPolicy.Validate(new WindowsTrustedProcessEvidence(
                    processUserAllowed,
                    imageNameMatches,
                    ImagePathCanonicalAndReparseFree: true,
                    imageAclSafe,
                    authenticodeTrusted,
                    ProcessAlive: true));
                return lease;
            }
            catch
            {
                lease.Dispose();
                throw;
            }
        }
        finally
        {
            process?.Dispose();
        }
    }

    private static string ReadImagePath(SafeProcessHandle process)
    {
        var image = new StringBuilder(32_768);
        uint imageLength = checked((uint)image.Capacity);
        if (!QueryFullProcessImageName(process, 0, image, ref imageLength)
            || imageLength == 0)
        {
            throw new Win32Exception(Marshal.GetLastWin32Error());
        }

        string path = image.ToString();
        if (!Path.IsPathFullyQualified(path) || path.StartsWith("\\\\", StringComparison.Ordinal))
        {
            throw new UnauthorizedAccessException("windows-trusted-process-image-path-invalid");
        }

        string fullPath = Path.GetFullPath(path);
        string? root = Path.GetPathRoot(fullPath);
        if (string.IsNullOrEmpty(root) || new DriveInfo(root).DriveType != DriveType.Fixed
            || !File.Exists(fullPath))
        {
            throw new UnauthorizedAccessException("windows-trusted-process-image-path-invalid");
        }

        RejectReparsePoints(fullPath);
        return new FileInfo(fullPath).FullName;
    }

    private static SecurityIdentifier ReadTokenUser(SafeProcessHandle process)
    {
        if (!OpenProcessToken(process, TokenQuery, out SafeAccessTokenHandle token)
            || token.IsInvalid)
        {
            token?.Dispose();
            throw new Win32Exception(Marshal.GetLastWin32Error());
        }

        using (token)
        {
            _ = GetTokenInformation(token, TokenUserInformation, nint.Zero, 0, out uint bytesNeeded);
            int error = Marshal.GetLastWin32Error();
            if (error != ErrorInsufficientBuffer || bytesNeeded == 0)
            {
                throw new Win32Exception(error);
            }

            nint buffer = Marshal.AllocHGlobal(checked((int)bytesNeeded));
            try
            {
                if (!GetTokenInformation(token, TokenUserInformation, buffer, bytesNeeded, out _))
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                }

                TokenUserValue user = Marshal.PtrToStructure<TokenUserValue>(buffer);
                return new SecurityIdentifier(user.User.Sid);
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }
    }

    private static bool IsPathAclSafe(string imagePath, IReadOnlySet<string> trusted)
    {
        return IsAclSafe(new FileInfo(imagePath).GetAccessControl(
                AccessControlSections.Owner | AccessControlSections.Access), trusted)
            && IsAclSafe(new DirectoryInfo(Path.GetDirectoryName(imagePath)!).GetAccessControl(
                AccessControlSections.Owner | AccessControlSections.Access), trusted);
    }

    private static bool IsAclSafe(FileSystemSecurity security, IReadOnlySet<string> trusted)
    {
        SecurityIdentifier? owner = security.GetOwner(typeof(SecurityIdentifier)) as SecurityIdentifier;
        if (owner is null || !trusted.Contains(owner.Value))
        {
            return false;
        }

        const FileSystemRights mutatingRights = FileSystemRights.WriteData
            | FileSystemRights.AppendData
            | FileSystemRights.WriteExtendedAttributes
            | FileSystemRights.WriteAttributes
            | FileSystemRights.Delete
            | FileSystemRights.DeleteSubdirectoriesAndFiles
            | FileSystemRights.ChangePermissions
            | FileSystemRights.TakeOwnership;
        AuthorizationRuleCollection rules = security.GetAccessRules(
            includeExplicit: true,
            includeInherited: true,
            typeof(SecurityIdentifier));
        foreach (FileSystemAccessRule rule in rules.Cast<FileSystemAccessRule>())
        {
            if (rule.AccessControlType != AccessControlType.Allow
                || (rule.PropagationFlags & PropagationFlags.InheritOnly) != 0
                || (rule.FileSystemRights & mutatingRights) == 0)
            {
                continue;
            }

            if (rule.IdentityReference is not SecurityIdentifier sid
                || !trusted.Contains(sid.Value))
            {
                return false;
            }
        }

        return true;
    }

    private static bool VerifyAuthenticode(string imagePath)
    {
        nint pathPointer = Marshal.StringToCoTaskMemUni(imagePath);
        nint filePointer = nint.Zero;
        try
        {
            var file = new WinTrustFileInfo
            {
                Size = checked((uint)Marshal.SizeOf<WinTrustFileInfo>()),
                FilePath = pathPointer,
            };
            filePointer = Marshal.AllocHGlobal(Marshal.SizeOf<WinTrustFileInfo>());
            Marshal.StructureToPtr(file, filePointer, fDeleteOld: false);
            var data = new WinTrustData
            {
                Size = checked((uint)Marshal.SizeOf<WinTrustData>()),
                UiChoice = WinTrustUiNone,
                RevocationChecks = WinTrustRevocationChecksNone,
                UnionChoice = WinTrustChoiceFile,
                File = filePointer,
                ProviderFlags = WinTrustCacheOnlyUrlRetrieval
                    | WinTrustRevocationCheckNone
                    | WinTrustSaferFlag,
            };
            Guid action = WinTrustActionGenericVerifyV2;
            return WinVerifyTrust(nint.Zero, ref action, ref data) == 0;
        }
        finally
        {
            if (filePointer != nint.Zero)
            {
                Marshal.FreeHGlobal(filePointer);
            }

            Marshal.FreeCoTaskMem(pathPointer);
        }
    }

    private static void RejectReparsePoints(string path)
    {
        string? current = path;
        while (!string.IsNullOrEmpty(current))
        {
            if ((File.GetAttributes(current) & FileAttributes.ReparsePoint) != 0)
            {
                throw new UnauthorizedAccessException("windows-trusted-process-image-reparse-point-refused");
            }

            string? parent = Path.GetDirectoryName(current);
            if (string.Equals(parent, current, StringComparison.OrdinalIgnoreCase))
            {
                break;
            }

            current = parent;
        }
    }

    private static void ValidateImageFileName(string value)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(value);
        if (value.Length > 128 || value != Path.GetFileName(value)
            || value.Any(static character =>
                !(char.IsAsciiLetterOrDigit(character) || character is '.' or '_' or '-')))
        {
            throw new ArgumentException("windows-trusted-process-image-name-invalid", nameof(value));
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct SidAndAttributes
    {
        public nint Sid;
        public uint Attributes;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct TokenUserValue
    {
        public SidAndAttributes User;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WinTrustFileInfo
    {
        public uint Size;
        public nint FilePath;
        public nint FileHandle;
        public nint KnownSubject;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WinTrustData
    {
        public uint Size;
        public nint PolicyCallbackData;
        public nint SipClientData;
        public uint UiChoice;
        public uint RevocationChecks;
        public uint UnionChoice;
        public nint File;
        public uint StateAction;
        public nint StateData;
        public nint UrlReference;
        public uint ProviderFlags;
        public uint UiContext;
        public nint SignatureSettings;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern SafeProcessHandle OpenProcess(
        uint desiredAccess,
        [MarshalAs(UnmanagedType.Bool)] bool inheritHandle,
        uint processId);

    [DllImport("kernel32.dll", EntryPoint = "QueryFullProcessImageNameW", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool QueryFullProcessImageName(
        SafeProcessHandle process,
        uint flags,
        StringBuilder executableName,
        ref uint size);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool OpenProcessToken(
        SafeProcessHandle process,
        uint desiredAccess,
        out SafeAccessTokenHandle token);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetTokenInformation(
        SafeAccessTokenHandle token,
        int tokenInformationClass,
        nint tokenInformation,
        uint tokenInformationLength,
        out uint returnLength);

    [DllImport("wintrust.dll", PreserveSig = true, SetLastError = true)]
    private static extern int WinVerifyTrust(
        nint window,
        ref Guid actionId,
        ref WinTrustData trustData);
}
