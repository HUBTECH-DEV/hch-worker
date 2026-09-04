using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace Hch.Worker.Linux;

/// <summary>
/// Opens Linux filesystem objects without following the final symbolic link and
/// validates security metadata on the same descriptor used for I/O.
/// </summary>
internal static class LinuxSecureFile
{
    private const int OpenReadOnly = 0;
    private const int OpenWriteOnly = 1;
    private const int OpenCreate = 0x40;
    private const int OpenExclusive = 0x80;
    private const int OpenNonBlocking = 0x800;
    private const int OpenDirectory = 0x10000;
    private const int OpenNoFollow = 0x20000;
    private const int OpenCloseOnExec = 0x80000;
    private const int AtEmptyPath = 0x1000;
    private const int AtSymlinkNoFollow = 0x100;
    private const uint StatxBasicStats = 0x7ff;
    private const int OwnerReadWrite = 0x180;
    private const int OwnerReadWriteExecute = 0x1c0;
    private const ushort FileTypeMask = 0xf000;
    private const ushort RegularFileType = 0x8000;
    private const ushort DirectoryType = 0x4000;
    private const ushort GroupOrOtherPermissions = 0x003f;

    internal static void EnsurePrivateDirectory(string path)
    {
        string canonical = LinuxPathSecurity.RequireAbsoluteCanonicalPath(path);
        try
        {
            Directory.CreateDirectory(canonical, UnixFileMode.UserRead
                | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        }
        catch (IOException error)
        {
            throw new UnauthorizedAccessException("linux-private-directory-create-refused", error);
        }

        using SafeFileHandle handle = OpenHandle(
            canonical,
            OpenReadOnly | OpenDirectory | OpenNoFollow | OpenCloseOnExec,
            0,
            missingReturnsNull: false)!;
        LinuxDescriptorMetadata metadata = ReadMetadata(handle);
        if (metadata.FileType != DirectoryType || metadata.OwnerUid != GetEffectiveUserId())
        {
            throw new UnauthorizedAccessException("linux-private-directory-owner-or-type-invalid");
        }

        // chmod is deliberately descriptor-relative and happens only after the
        // descriptor was proven to be the expected owned directory.
        if (Fchmod(handle, OwnerReadWriteExecute) != 0)
        {
            throw NativeIo("linux-private-directory-chmod-failed");
        }
    }

    internal static SafeFileHandle OpenPrivateDirectory(string path)
    {
        EnsurePrivateDirectory(path);
        SafeFileHandle handle = OpenHandle(
            LinuxPathSecurity.RequireAbsoluteCanonicalPath(path),
            OpenReadOnly | OpenDirectory | OpenNoFollow | OpenCloseOnExec,
            0,
            missingReturnsNull: false)!;
        try
        {
            LinuxDescriptorMetadata metadata = ReadMetadata(handle);
            if (metadata.FileType != DirectoryType || metadata.OwnerUid != GetEffectiveUserId()
                || (metadata.Mode & GroupOrOtherPermissions) != 0)
            {
                throw new UnauthorizedAccessException(
                    "linux-private-directory-owner-or-type-invalid");
            }

            return handle;
        }
        catch
        {
            handle.Dispose();
            throw;
        }
    }

    internal static FileStream CreatePrivateFileAt(SafeFileHandle directory, string fileName)
    {
        ValidateFileName(fileName);
        SafeFileHandle handle = OpenHandleAt(
            directory,
            fileName,
            OpenWriteOnly | OpenCreate | OpenExclusive | OpenNoFollow | OpenCloseOnExec,
            OwnerReadWrite,
            missingReturnsNull: false)!;
        try
        {
            ValidatePrivateRegularFile(handle);
            return new FileStream(handle, FileAccess.Write, 4096, isAsync: false);
        }
        catch
        {
            handle.Dispose();
            throw;
        }
    }

    internal static FileStream? OpenPrivateFileForReadAt(
        SafeFileHandle directory,
        string fileName,
        bool missingReturnsNull)
    {
        ValidateFileName(fileName);
        SafeFileHandle? handle = OpenHandleAt(
            directory,
            fileName,
            OpenReadOnly | OpenNonBlocking | OpenNoFollow | OpenCloseOnExec,
            0,
            missingReturnsNull);
        if (handle is null)
        {
            return null;
        }

        try
        {
            ValidatePrivateRegularFile(handle);
            return new FileStream(handle, FileAccess.Read, 4096, isAsync: false);
        }
        catch
        {
            handle.Dispose();
            throw;
        }
    }

    internal static void ReplaceAt(
        SafeFileHandle directory,
        string sourceFileName,
        string destinationFileName)
    {
        ValidateFileName(sourceFileName);
        ValidateFileName(destinationFileName);
        if (RenameAt(directory, sourceFileName, directory, destinationFileName) != 0)
        {
            throw NativeIo("linux-secure-rename-failed");
        }
    }

    internal static void DeleteAt(SafeFileHandle directory, string fileName)
    {
        ValidateFileName(fileName);
        if (UnlinkAt(directory, fileName, 0) != 0)
        {
            throw NativeIo("linux-secure-unlink-failed");
        }
    }

    internal static FileStream? OpenPrivateFileForRead(string path, bool missingReturnsNull)
    {
        string canonical = LinuxPathSecurity.RequireAbsoluteCanonicalPath(path);
        SafeFileHandle? handle = OpenHandle(
            canonical,
            OpenReadOnly | OpenNonBlocking | OpenNoFollow | OpenCloseOnExec,
            0,
            missingReturnsNull);
        if (handle is null)
        {
            return null;
        }

        try
        {
            ValidatePrivateRegularFile(handle);
            return new FileStream(handle, FileAccess.Read, 4096, isAsync: false);
        }
        catch
        {
            handle.Dispose();
            throw;
        }
    }

    private static void ValidatePrivateRegularFile(SafeFileHandle handle)
    {
        LinuxDescriptorMetadata metadata = ReadMetadata(handle);
        if (metadata.FileType != RegularFileType || metadata.OwnerUid != GetEffectiveUserId()
            || metadata.LinkCount != 1)
        {
            throw new UnauthorizedAccessException("linux-private-file-owner-or-type-invalid");
        }

        if ((metadata.Mode & GroupOrOtherPermissions) != 0)
        {
            throw new UnauthorizedAccessException("linux-private-file-permissions-unsafe");
        }
    }

    private static SafeFileHandle? OpenHandle(
        string path,
        int flags,
        int mode,
        bool missingReturnsNull)
    {
        int descriptor = Open(path, flags, mode);
        if (descriptor >= 0)
        {
            return new SafeFileHandle(descriptor, ownsHandle: true);
        }

        int error = Marshal.GetLastPInvokeError();
        if (missingReturnsNull && error == 2)
        {
            return null;
        }

        if (error is 40 or 20)
        {
            throw new UnauthorizedAccessException(
                "linux-symbolic-link-refused",
                new Win32Exception(error));
        }

        if (error == 2)
        {
            throw new FileNotFoundException("linux-private-file-not-found", path);
        }

        throw NativeIo("linux-secure-open-failed", error);
    }

    private static SafeFileHandle? OpenHandleAt(
        SafeFileHandle directory,
        string fileName,
        int flags,
        int mode,
        bool missingReturnsNull)
    {
        int descriptor = OpenAt(directory, fileName, flags, mode);
        if (descriptor >= 0)
        {
            return new SafeFileHandle(descriptor, ownsHandle: true);
        }

        int error = Marshal.GetLastPInvokeError();
        if (missingReturnsNull && error == 2)
        {
            return null;
        }

        if (error is 40 or 20)
        {
            throw new UnauthorizedAccessException(
                "linux-symbolic-link-refused",
                new Win32Exception(error));
        }

        if (error == 2)
        {
            throw new FileNotFoundException("linux-private-file-not-found", fileName);
        }

        throw NativeIo("linux-secure-openat-failed", error);
    }

    private static void ValidateFileName(string fileName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(fileName);
        if (fileName is "." or ".." || fileName.IndexOfAny(['/', '\\', '\0']) >= 0)
        {
            throw new ArgumentException("linux-secure-file-name-invalid", nameof(fileName));
        }
    }

    private static LinuxDescriptorMetadata ReadMetadata(SafeFileHandle handle)
    {
        nint buffer = Marshal.AllocHGlobal(256);
        try
        {
            for (int offset = 0; offset < 256; offset += sizeof(long))
            {
                Marshal.WriteInt64(buffer, offset, 0);
            }

            if (Statx(handle, string.Empty, AtEmptyPath | AtSymlinkNoFollow,
                StatxBasicStats, buffer) != 0)
            {
                throw NativeIo("linux-secure-fstat-failed");
            }

            return new LinuxDescriptorMetadata(
                LinkCount: unchecked((uint)Marshal.ReadInt32(buffer, 16)),
                OwnerUid: unchecked((uint)Marshal.ReadInt32(buffer, 20)),
                Mode: unchecked((ushort)Marshal.ReadInt16(buffer, 28)));
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    private static IOException NativeIo(string message, int? error = null)
    {
        int nativeError = error ?? Marshal.GetLastPInvokeError();
        return new IOException(message, new Win32Exception(nativeError));
    }

    private readonly record struct LinuxDescriptorMetadata(
        uint LinkCount,
        uint OwnerUid,
        ushort Mode)
    {
        internal ushort FileType => unchecked((ushort)(Mode & FileTypeMask));
    }

    [DllImport("libc", EntryPoint = "open", SetLastError = true)]
    private static extern int Open(string path, int flags, int mode);

    [DllImport("libc", EntryPoint = "openat", SetLastError = true)]
    private static extern int OpenAt(
        SafeFileHandle directoryFd,
        string path,
        int flags,
        int mode);

    [DllImport("libc", EntryPoint = "renameat", SetLastError = true)]
    private static extern int RenameAt(
        SafeFileHandle oldDirectoryFd,
        string oldPath,
        SafeFileHandle newDirectoryFd,
        string newPath);

    [DllImport("libc", EntryPoint = "unlinkat", SetLastError = true)]
    private static extern int UnlinkAt(SafeFileHandle directoryFd, string path, int flags);

    [DllImport("libc", EntryPoint = "fchmod", SetLastError = true)]
    private static extern int Fchmod(SafeFileHandle descriptor, int mode);

    [DllImport("libc", EntryPoint = "statx", SetLastError = true)]
    private static extern int Statx(
        SafeFileHandle directoryFd,
        string path,
        int flags,
        uint mask,
        nint buffer);

    [DllImport("libc", EntryPoint = "geteuid", SetLastError = false)]
    private static extern uint GetEffectiveUserId();
}
