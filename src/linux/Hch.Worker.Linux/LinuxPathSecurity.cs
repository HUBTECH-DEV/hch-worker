namespace Hch.Worker.Linux;

using System.Runtime.InteropServices;

public static class LinuxPathSecurity
{
    private const UnixFileMode UnsafeWriteBits =
        UnixFileMode.GroupWrite | UnixFileMode.OtherWrite;

    public static string RequireAbsoluteCanonicalPath(string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        if (!OperatingSystem.IsLinux())
        {
            throw new PlatformNotSupportedException("linux-platform-required");
        }

        if (!Path.IsPathFullyQualified(path) || path.IndexOf('\0') >= 0)
        {
            throw new ArgumentException("linux-path-invalid", nameof(path));
        }

        string canonical = Path.GetFullPath(path);
        if (canonical == "/")
        {
            throw new ArgumentException("linux-path-root-refused", nameof(path));
        }

        return canonical;
    }

    public static void EnsurePrivateDirectory(string path)
    {
        string canonical = RequireAbsoluteCanonicalPath(path);
        Directory.CreateDirectory(canonical, UnixFileMode.UserRead
            | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        File.SetUnixFileMode(canonical, UnixFileMode.UserRead
            | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        RejectSymbolicLink(canonical);
        LinuxFileMetadata metadata = ReadMetadata(canonical);
        if (!metadata.IsDirectory || metadata.OwnerUid != GetEffectiveUserId())
        {
            throw new UnauthorizedAccessException("linux-private-directory-owner-or-type-invalid");
        }

        RejectUnsafeWritePermissions(canonical);
    }

    public static void RequirePrivateFile(string path)
    {
        string canonical = RequireAbsoluteCanonicalPath(path);
        if (!File.Exists(canonical))
        {
            throw new FileNotFoundException("linux-private-file-not-found", canonical);
        }

        RejectSymbolicLink(canonical);
        LinuxFileMetadata metadata = ReadMetadata(canonical);
        if (!metadata.IsRegularFile || metadata.OwnerUid != GetEffectiveUserId())
        {
            throw new UnauthorizedAccessException("linux-private-file-owner-or-type-invalid");
        }

        UnixFileMode mode = File.GetUnixFileMode(canonical);
        if ((mode & (UnsafeWriteBits | UnixFileMode.GroupRead | UnixFileMode.OtherRead)) != 0)
        {
            throw new UnauthorizedAccessException("linux-private-file-permissions-unsafe");
        }
    }

    public static LinuxFileMetadata ReadMetadata(string path)
    {
        string canonical = RequireAbsoluteCanonicalPath(path);
        const int atFdcwd = -100;
        const int atSymlinkNoFollow = 0x100;
        const uint statxBasicStats = 0x7ff;
        nint buffer = Marshal.AllocHGlobal(256);
        try
        {
            for (int offset = 0; offset < 256; offset += sizeof(long))
            {
                Marshal.WriteInt64(buffer, offset, 0);
            }

            if (Statx(atFdcwd, canonical, atSymlinkNoFollow, statxBasicStats, buffer) != 0)
            {
                throw new IOException("linux-statx-failed", new System.ComponentModel.Win32Exception(
                    Marshal.GetLastWin32Error()));
            }

            uint uid = unchecked((uint)Marshal.ReadInt32(buffer, 20));
            ushort mode = unchecked((ushort)Marshal.ReadInt16(buffer, 28));
            ushort fileType = unchecked((ushort)(mode & 0xf000));
            return new LinuxFileMetadata(
                uid,
                IsRegularFile: fileType == 0x8000,
                IsDirectory: fileType == 0x4000,
                IsSocket: fileType == 0xc000);
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    private static void RejectUnsafeWritePermissions(string path)
    {
        if ((File.GetUnixFileMode(path) & UnsafeWriteBits) != 0)
        {
            throw new UnauthorizedAccessException("linux-path-permissions-unsafe");
        }
    }

    private static void RejectSymbolicLink(string path)
    {
        FileSystemInfo info = Directory.Exists(path)
            ? new DirectoryInfo(path)
            : new FileInfo(path);
        if (info.LinkTarget is not null
            || (info.Attributes & FileAttributes.ReparsePoint) != 0)
        {
            throw new UnauthorizedAccessException("linux-symbolic-link-refused");
        }
    }

    [DllImport("libc", EntryPoint = "statx", SetLastError = true)]
    private static extern int Statx(int directoryFd, string path, int flags, uint mask, nint buffer);

    [DllImport("libc", EntryPoint = "geteuid", SetLastError = false)]
    private static extern uint GetEffectiveUserId();
}

public readonly record struct LinuxFileMetadata(
    uint OwnerUid,
    bool IsRegularFile,
    bool IsDirectory,
    bool IsSocket);
