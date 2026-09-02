using Hch.Worker.Security;
using Hch.Worker.Service;

namespace Hch.Worker.Tests;

public sealed class ManifestTrustPinsLoaderTests
{
    [Fact]
    public async Task LoadsOnlyTheExplicitPemWhoseFingerprintIsPinned()
    {
        var root = NewRoot();
        using var identity = Ed25519Identity.Generate();
        try
        {
            var pemPath = Path.Combine(root, "orchestrator-root.pem");
            await File.WriteAllTextAsync(pemPath, identity.ExportSubjectPublicKeyInfoPem());
            var configuration = WorkerConfigurationStore.CreatePausedDefault(
                "node-trust-test",
                "worker-key:trust-test",
                "hch-root-v1",
                identity.Fingerprint,
                pemPath) with
            {
                StateRoot = Path.Combine(root, "state"),
            };

            var pins = await ManifestTrustPinsLoader.LoadAsync(configuration.Validate());

            Assert.Equal("hch-root-v1", pins.RootKeyId);
            Assert.Equal(identity.Fingerprint, pins.RootPublicKeyFingerprint);
            Assert.NotEmpty(pins.ExportRootSubjectPublicKeyInfo());
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task RefusesMissingPinsInsteadOfTrustingTheObservedKey()
    {
        var configuration = WorkerConfigurationStore.CreatePausedDefault(
            "node-no-trust-test",
            "worker-key:no-trust-test");

        var error = await Assert.ThrowsAsync<WorkerServiceException>(
            () => ManifestTrustPinsLoader.LoadAsync(configuration));

        Assert.Equal("root-trust-pins-missing", error.Code);
    }

    [Fact]
    public async Task RefusesAValidPemWhenItDoesNotMatchThePinnedFingerprint()
    {
        var root = NewRoot();
        using var expected = Ed25519Identity.Generate();
        using var substituted = Ed25519Identity.Generate();
        try
        {
            var pemPath = Path.Combine(root, "orchestrator-root.pem");
            await File.WriteAllTextAsync(pemPath, substituted.ExportSubjectPublicKeyInfoPem());
            var configuration = WorkerConfigurationStore.CreatePausedDefault(
                "node-mismatch-test",
                "worker-key:mismatch-test",
                "hch-root-v1",
                expected.Fingerprint,
                pemPath) with
            {
                StateRoot = Path.Combine(root, "state"),
            };

            var error = await Assert.ThrowsAsync<WorkerServiceException>(
                () => ManifestTrustPinsLoader.LoadAsync(configuration.Validate()));

            Assert.Equal("root-trust-key-invalid", error.Code);
            Assert.IsType<Hch.Worker.Protocol.ProtocolValidationException>(error.InnerException);
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    private static string NewRoot()
    {
        var path = Path.Combine(Path.GetTempPath(), $"hch-root-trust-{Guid.NewGuid():N}");
        Directory.CreateDirectory(path);
        return path;
    }
}
