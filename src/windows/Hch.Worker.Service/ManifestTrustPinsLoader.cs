using System.Security.Cryptography;
using System.Text;
using Hch.Worker.Protocol;

namespace Hch.Worker.Service;

/// <summary>Loads an explicitly configured public root without any TOFU fallback.</summary>
public static class ManifestTrustPinsLoader
{
    private const int MaximumPemBytes = 16 * 1024;
    private static readonly UTF8Encoding StrictUtf8 = new(false, true);

    public static async Task<ManifestTrustPins> LoadAsync(
        WorkerConfiguration configuration,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(configuration);
        if (!configuration.HasRootTrustPins)
        {
            throw Error("root-trust-pins-missing", "Explicit orchestrator root trust is not configured.");
        }

        var path = Path.GetFullPath(configuration.RootPublicKeyPath!);
        byte[] encoded;
        try
        {
            var attributes = File.GetAttributes(path);
            if ((attributes & FileAttributes.ReparsePoint) != 0)
            {
                throw Error("root-trust-reparse-point-refused", "The root trust file cannot be a reparse point.");
            }

            var info = new FileInfo(path);
            if (info.Length is < 1 or > MaximumPemBytes)
            {
                throw Error("root-trust-file-invalid", "The root trust file has an invalid size.");
            }

            await using var stream = new FileStream(
                path,
                FileMode.Open,
                FileAccess.Read,
                FileShare.Read,
                16 * 1024,
                FileOptions.Asynchronous | FileOptions.SequentialScan);
            encoded = new byte[checked((int)stream.Length)];
            await stream.ReadExactlyAsync(encoded, cancellationToken).ConfigureAwait(false);
            if (stream.Length != encoded.Length
                || (File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
            {
                throw Error("root-trust-file-changed", "The root trust file changed while it was read.");
            }
        }
        catch (WorkerServiceException)
        {
            throw;
        }
        catch (Exception error) when (
            error is IOException or UnauthorizedAccessException or NotSupportedException)
        {
            throw Error("root-trust-file-unavailable", "The configured public root key is unavailable.", error);
        }

        byte[]? subjectPublicKeyInfo = null;
        try
        {
            var pem = StrictUtf8.GetString(encoded);
            subjectPublicKeyInfo = Ed25519KeyEncoding.DecodePublicKeyPem(pem);
            return new ManifestTrustPins(
                configuration.RootKeyId!,
                configuration.RootPublicKeyFingerprint!,
                subjectPublicKeyInfo);
        }
        catch (ProtocolValidationException error)
        {
            throw Error("root-trust-key-invalid", "The configured public root key is invalid.", error);
        }
        catch (DecoderFallbackException error)
        {
            throw Error("root-trust-key-invalid", "The configured public root key is not strict UTF-8.", error);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(encoded);
            if (subjectPublicKeyInfo is not null)
            {
                CryptographicOperations.ZeroMemory(subjectPublicKeyInfo);
            }
        }
    }

    private static WorkerServiceException Error(string code, string message, Exception? cause = null) =>
        new(code, message, cause);
}
