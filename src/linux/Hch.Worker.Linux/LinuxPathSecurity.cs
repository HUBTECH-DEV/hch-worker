namespace Hch.Worker.Linux;

using System.Runtime.InteropServices;

public static class LinuxPathSecurity
{
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
        LinuxSecureFile.EnsurePrivateDirectory(path);
    }

    public static void RequirePrivateFile(string path)
    {
        using FileStream _ = LinuxSecureFile.OpenPrivateFileForRead(
            path,
            missingReturnsNull: false)!;
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

    [DllImport("libc", EntryPoint = "statx", SetLastError = true)]
    private static extern int Statx(int directoryFd, string path, int flags, uint mask, nint buffer);

}

public readonly record struct LinuxFileMetadata(
    uint OwnerUid,
    bool IsRegularFile,
    bool IsDirectory,
    bool IsSocket);
