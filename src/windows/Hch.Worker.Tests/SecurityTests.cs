using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Hch.Worker.Protocol;
using Hch.Worker.Security;

namespace Hch.Worker.Tests;

public sealed class SecurityTests
{
    [Fact]
    public async Task GeneratedIdentitySignsAndVerifiesOnlyMatchingContentAndKey()
    {
        using var identity = Ed25519Identity.Generate();
        using var otherIdentity = Ed25519Identity.Generate();
        byte[] message = Encoding.UTF8.GetBytes("hch-worker-ed25519-test");
        byte[] changedMessage = Encoding.UTF8.GetBytes("hch-worker-ed25519-test-changed");
        byte[] signature = await identity.SignAsync(message);

        try
        {
            Assert.Equal(Ed25519KeyEncoding.SignatureLength, signature.Length);
            Assert.True(await identity.VerifyAsync(
                identity.ExportSubjectPublicKeyInfo(),
                message,
                signature));
            Assert.False(await identity.VerifyAsync(
                identity.ExportSubjectPublicKeyInfo(),
                changedMessage,
                signature));
            Assert.False(await identity.VerifyAsync(
                otherIdentity.ExportSubjectPublicKeyInfo(),
                message,
                signature));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(signature);
        }
    }

    [Fact]
    public async Task Pkcs8RoundTripPreservesPublicIdentityAndSigningCapability()
    {
        using var generated = Ed25519Identity.Generate();
        byte[] encodedPrivateKey = generated.ExportPkcs8PrivateKey();
        byte[] message = Encoding.UTF8.GetBytes("hch-worker-pkcs8-round-trip");

        try
        {
            using var imported = Ed25519Identity.ImportPkcs8(encodedPrivateKey);
            Assert.Equal(generated.Fingerprint, imported.Fingerprint);
            Assert.Equal(
                generated.ExportSubjectPublicKeyInfo(),
                imported.ExportSubjectPublicKeyInfo());

            byte[] signature = await imported.SignAsync(message);
            try
            {
                Assert.True(await generated.VerifyAsync(
                    generated.ExportSubjectPublicKeyInfo(),
                    message,
                    signature));
            }
            finally
            {
                CryptographicOperations.ZeroMemory(signature);
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(encodedPrivateKey);
        }
    }

    [Fact]
    public async Task OpenSshPrivatePemRoundTripPreservesIdentityAndSigningCapability()
    {
        using var generated = Ed25519Identity.Generate();
        byte[] encodedPrivateKey = generated.ExportOpenSshPrivateKeyPem();
        byte[] message = Encoding.UTF8.GetBytes("hch-worker-openssh-round-trip");

        try
        {
            Assert.StartsWith("-----BEGIN OPENSSH PRIVATE KEY-----", Encoding.ASCII.GetString(encodedPrivateKey));
            using var imported = Ed25519Identity.ImportOpenSshPrivateKeyPem(encodedPrivateKey);
            Assert.Equal(generated.Fingerprint, imported.Fingerprint);

            byte[] signature = await imported.SignAsync(message);
            try
            {
                Assert.True(await generated.VerifyAsync(
                    generated.ExportSubjectPublicKeyInfo(),
                    message,
                    signature));
            }
            finally
            {
                CryptographicOperations.ZeroMemory(signature);
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(encodedPrivateKey);
        }
    }

    [Fact]
    public void PublicSpkiPemAndOpenSshFormatsRoundTripStrictly()
    {
        using var identity = Ed25519Identity.Generate();
        byte[] expected = identity.ExportSubjectPublicKeyInfo();

        Assert.Equal(
            expected,
            Ed25519KeyEncoding.DecodePublicKeyPem(identity.ExportSubjectPublicKeyInfoPem()));
        Assert.Equal(
            expected,
            OpenSshEd25519PublicKey.DecodeSubjectPublicKeyInfo(
                identity.ExportOpenSshPublicKey("hch-worker-test")));
        Assert.Throws<CryptographicException>(() =>
            OpenSshEd25519PublicKey.DecodeSubjectPublicKeyInfo("ssh-rsa AAAA"));
        Assert.Throws<ArgumentException>(() => identity.ExportOpenSshPublicKey("bad\ncomment"));
    }

    [Fact]
    public void DiagnosticsAndDefaultJsonExposeOnlyPublicMetadata()
    {
        using var identity = Ed25519Identity.Generate();
        byte[] encodedPrivateKey = identity.ExportPkcs8PrivateKey();

        try
        {
            string privateMaterial = Convert.ToBase64String(encodedPrivateKey);
            string diagnostic = identity.ToString();
            string json = JsonSerializer.Serialize(identity);

            Assert.Contains(identity.Fingerprint, diagnostic, StringComparison.Ordinal);
            Assert.Contains(identity.Fingerprint, json, StringComparison.Ordinal);
            Assert.DoesNotContain(privateMaterial, diagnostic, StringComparison.Ordinal);
            Assert.DoesNotContain(privateMaterial, json, StringComparison.Ordinal);
            Assert.DoesNotContain("private", json, StringComparison.OrdinalIgnoreCase);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(encodedPrivateKey);
        }
    }

    [Fact]
    public async Task DisposedIdentityCannotSignOrExportPrivateMaterial()
    {
        var identity = Ed25519Identity.Generate();
        identity.Dispose();

        await Assert.ThrowsAsync<ObjectDisposedException>(async () =>
            await identity.SignAsync(Array.Empty<byte>()));
        Assert.Throws<ObjectDisposedException>(() => identity.ExportPkcs8PrivateKey());
    }
}
