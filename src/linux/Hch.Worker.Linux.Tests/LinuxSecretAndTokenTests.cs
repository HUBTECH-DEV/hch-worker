using System.Security.Cryptography;
using Hch.Worker.Linux;

namespace Hch.Worker.Linux.Tests;

public sealed class LinuxSecretAndTokenTests
{
    [Fact]
    public void MachineProtectorRoundTripsWithoutPersistingPlaintext()
    {
        using var fixture = new TemporaryDirectory();
        var protector = new LinuxMachineSecretProtector(fixture.Path);
        byte[] plaintext = "credential-value"u8.ToArray();

        byte[] protectedBytes = protector.Protect(plaintext, "enrollment");
        byte[] restored = protector.Unprotect(protectedBytes, "enrollment");

        Assert.Equal(plaintext, restored);
        Assert.DoesNotContain(Convert.ToHexString(plaintext), Convert.ToHexString(protectedBytes));
        Assert.Equal(
            UnixFileMode.UserRead | UnixFileMode.UserWrite,
            File.GetUnixFileMode(Path.Combine(fixture.Path, "machine-secret.key")));
    }

    [Fact]
    public void MachineProtectorFailsClosedForWrongPurposeAndTampering()
    {
        using var fixture = new TemporaryDirectory();
        var protector = new LinuxMachineSecretProtector(fixture.Path);
        byte[] protectedBytes = protector.Protect("secret"u8, "purpose-a");

        Assert.ThrowsAny<CryptographicException>(() =>
            protector.Unprotect(protectedBytes, "purpose-b"));
        protectedBytes[^1] ^= 0xff;
        Assert.ThrowsAny<CryptographicException>(() =>
            protector.Unprotect(protectedBytes, "purpose-a"));
    }

    [Fact]
    public void MachineProtectorRejectsUnsafeOrInvalidKey()
    {
        using var fixture = new TemporaryDirectory();
        string keyPath = Path.Combine(fixture.Path, "machine-secret.key");
        File.WriteAllBytes(keyPath, new byte[32]);
        File.SetUnixFileMode(keyPath, UnixFileMode.UserRead | UnixFileMode.UserWrite
            | UnixFileMode.GroupRead);
        var protector = new LinuxMachineSecretProtector(fixture.Path);

        Assert.Throws<UnauthorizedAccessException>(() => protector.Protect("secret"u8, "purpose"));

        File.SetUnixFileMode(keyPath, UnixFileMode.UserRead | UnixFileMode.UserWrite);
        File.WriteAllBytes(keyPath, new byte[31]);
        Assert.Throws<CryptographicException>(() => protector.Protect("secret"u8, "purpose"));
    }

    [Fact]
    public void TokenStoreRoundTripsRedactsAndRevokes()
    {
        using var fixture = new TemporaryDirectory();
        var store = new LinuxRevocableTokenStore(fixture.Path);
        byte[] token = "opaque-enrollment-token"u8.ToArray();

        store.Store("enrollment.current-1", token);
        using LinuxTokenSecret secret = Assert.IsType<LinuxTokenSecret>(
            store.Read("enrollment.current-1"));

        Assert.Equal(token, secret.Value.ToArray());
        Assert.Equal("[REDACTED]", secret.ToString());
        Assert.Equal(
            UnixFileMode.UserRead | UnixFileMode.UserWrite,
            File.GetUnixFileMode(Path.Combine(
                fixture.Path, "credentials", "enrollment.current-1.token")));
        Assert.True(store.Revoke("enrollment.current-1"));
        Assert.False(store.Revoke("enrollment.current-1"));
        Assert.Null(store.Read("enrollment.current-1"));
    }

    [Theory]
    [InlineData("../escape")]
    [InlineData("nested/token")]
    [InlineData("token with spaces")]
    [InlineData("")]
    public void TokenStoreRejectsInvalidIdentifiers(string tokenId)
    {
        using var fixture = new TemporaryDirectory();
        var store = new LinuxRevocableTokenStore(fixture.Path);

        Assert.Throws<ArgumentException>(() => store.Store(tokenId, "token"u8));
    }

    [Fact]
    public void TokenStoreFailsClosedForUnsafePersistedToken()
    {
        using var fixture = new TemporaryDirectory();
        string credentials = Path.Combine(fixture.Path, "credentials");
        Directory.CreateDirectory(credentials);
        string tokenPath = Path.Combine(credentials, "unsafe.token");
        File.WriteAllText(tokenPath, "token");
        File.SetUnixFileMode(tokenPath, UnixFileMode.UserRead | UnixFileMode.UserWrite
            | UnixFileMode.OtherRead);
        var store = new LinuxRevocableTokenStore(fixture.Path);

        Assert.Throws<UnauthorizedAccessException>(() => store.Read("unsafe"));
        Assert.Throws<UnauthorizedAccessException>(() => store.Revoke("unsafe"));
    }
}
