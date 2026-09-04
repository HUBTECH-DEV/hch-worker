using Hch.Worker.Linux;
using System.ComponentModel;
using System.Runtime.InteropServices;

namespace Hch.Worker.Linux.Tests;

public sealed class LinuxPathSecurityTests
{
    [Theory]
    [InlineData("relative/path")]
    [InlineData("/")]
    public void CanonicalPathRejectsUnsafeRoots(string path)
    {
        Assert.Throws<ArgumentException>(() => LinuxPathSecurity.RequireAbsoluteCanonicalPath(path));
    }

    [Fact]
    public void PrivateDirectoryIsCreatedWithOwnerOnlyPermissions()
    {
        using var fixture = new TemporaryDirectory();
        string directory = Path.Combine(fixture.Path, "state");

        LinuxPathSecurity.EnsurePrivateDirectory(directory);

        Assert.Equal(
            UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute,
            File.GetUnixFileMode(directory));
    }

    [Fact]
    public void SymbolicLinkDirectoryIsRefused()
    {
        using var fixture = new TemporaryDirectory();
        string target = Path.Combine(fixture.Path, "target");
        string link = Path.Combine(fixture.Path, "link");
        Directory.CreateDirectory(target);
        File.SetUnixFileMode(target, UnixFileMode.UserRead | UnixFileMode.UserWrite
            | UnixFileMode.UserExecute | UnixFileMode.GroupRead | UnixFileMode.GroupExecute
            | UnixFileMode.OtherRead | UnixFileMode.OtherExecute);
        UnixFileMode originalMode = File.GetUnixFileMode(target);
        Directory.CreateSymbolicLink(link, target);

        Assert.Throws<UnauthorizedAccessException>(() =>
            LinuxPathSecurity.EnsurePrivateDirectory(link));
        Assert.Equal(originalMode, File.GetUnixFileMode(target));
    }

    [Fact]
    public void PrivateFileRequiresRegularOwnerOnlyFile()
    {
        using var fixture = new TemporaryDirectory();
        string file = Path.Combine(fixture.Path, "secret");
        File.WriteAllText(file, "secret");
        File.SetUnixFileMode(file, UnixFileMode.UserRead | UnixFileMode.UserWrite);

        LinuxPathSecurity.RequirePrivateFile(file);
        LinuxFileMetadata metadata = LinuxPathSecurity.ReadMetadata(file);

        Assert.True(metadata.IsRegularFile);
    }

    [Theory]
    [InlineData(UnixFileMode.GroupRead)]
    [InlineData(UnixFileMode.OtherRead)]
    [InlineData(UnixFileMode.GroupWrite)]
    [InlineData(UnixFileMode.OtherWrite)]
    public void PrivateFileRejectsPermissionsGrantedToOthers(UnixFileMode unsafeMode)
    {
        using var fixture = new TemporaryDirectory();
        string file = Path.Combine(fixture.Path, "secret");
        File.WriteAllText(file, "secret");
        File.SetUnixFileMode(file, UnixFileMode.UserRead | UnixFileMode.UserWrite | unsafeMode);

        Assert.Throws<UnauthorizedAccessException>(() => LinuxPathSecurity.RequirePrivateFile(file));
    }

    [Fact]
    public void PrivateFileRejectsSymbolicAndHardLinks()
    {
        using var fixture = new TemporaryDirectory();
        string target = Path.Combine(fixture.Path, "target");
        string symbolicLink = Path.Combine(fixture.Path, "symbolic");
        string hardLink = Path.Combine(fixture.Path, "hard");
        File.WriteAllText(target, "secret");
        File.SetUnixFileMode(target, UnixFileMode.UserRead | UnixFileMode.UserWrite);
        File.CreateSymbolicLink(symbolicLink, target);
        if (CreateHardLink(target, hardLink) != 0)
        {
            throw new Win32Exception(Marshal.GetLastPInvokeError());
        }

        Assert.Throws<UnauthorizedAccessException>(() =>
            LinuxPathSecurity.RequirePrivateFile(symbolicLink));
        Assert.Throws<UnauthorizedAccessException>(() =>
            LinuxPathSecurity.RequirePrivateFile(hardLink));
    }

    [DllImport("libc", EntryPoint = "link", SetLastError = true)]
    private static extern int CreateHardLink(string existingPath, string newPath);
}

internal sealed class TemporaryDirectory : IDisposable
{
    public TemporaryDirectory()
    {
        Path = System.IO.Path.Combine(
            System.IO.Path.GetTempPath(),
            "hch-worker-linux-tests",
            Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(Path);
    }

    public string Path { get; }

    public void Dispose() => Directory.Delete(Path, recursive: true);
}
