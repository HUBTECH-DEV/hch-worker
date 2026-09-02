using System.Security.Cryptography;
using Hch.Worker.Persistence;
using Hch.Worker.Security;

namespace Hch.Worker.Service;

/// <summary>Loads the service identity from DPAPI LocalMachine protected state.</summary>
public sealed class MachineWorkerIdentityStore(
    AtomicFileStore files,
    MachineSecretProtector protector)
{
    private const string RelativePath = "identity/worker-ed25519.pkcs8.dpapi";

    public async Task<Ed25519Identity?> LoadAsync(
        string nodeId,
        string expectedKeyId,
        CancellationToken cancellationToken = default)
    {
        var path = files.Resolve(RelativePath);
        if (!File.Exists(path))
        {
            return null;
        }

        var protectedBytes = await File.ReadAllBytesAsync(path, cancellationToken).ConfigureAwait(false);
        byte[]? pkcs8 = null;
        try
        {
            pkcs8 = protector.Unprotect(protectedBytes, Purpose(nodeId));
            var identity = Ed25519Identity.ImportPkcs8(pkcs8);
            if (!CryptographicOperations.FixedTimeEquals(
                    System.Text.Encoding.ASCII.GetBytes(identity.Fingerprint),
                    System.Text.Encoding.ASCII.GetBytes(expectedKeyId)))
            {
                identity.Dispose();
                throw new WorkerServiceException(
                    "worker-identity-key-id-mismatch",
                    "The protected Worker identity does not match the enrolled public key.");
            }

            return identity;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(protectedBytes);
            if (pkcs8 is not null)
            {
                CryptographicOperations.ZeroMemory(pkcs8);
            }
        }
    }

    public async Task SaveAsync(
        string nodeId,
        Ed25519Identity identity,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(identity);
        var pkcs8 = identity.ExportPkcs8PrivateKey();
        byte[]? protectedBytes = null;
        try
        {
            protectedBytes = protector.Protect(pkcs8, Purpose(nodeId));
            await files.WriteBytesAsync(RelativePath, protectedBytes, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(pkcs8);
            if (protectedBytes is not null)
            {
                CryptographicOperations.ZeroMemory(protectedBytes);
            }
        }
    }

    private static string Purpose(string nodeId) => $"operational-identity:{nodeId}";
}

public static class WorkerInstalledVersion
{
    /// <summary>Version of the installed service assembly; never sourced from a manifest.</summary>
    public static string Current
    {
        get
        {
            var version = typeof(WorkerInstalledVersion).Assembly.GetName().Version
                ?? throw new WorkerServiceException("installed-version-unavailable", "Assembly version is unavailable.");
            return $"{version.Major}.{version.Minor}.{version.Build}";
        }
    }
}
