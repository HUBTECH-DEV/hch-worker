using Hch.Worker.Linux;

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
        Directory.CreateSymbolicLink(link, target);

        Assert.Throws<UnauthorizedAccessException>(() =>
            LinuxPathSecurity.EnsurePrivateDirectory(link));
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
