using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using Hch.Worker.Protocol;
using Hch.Worker.Security;
using Hch.Worker.Windows;

namespace Hch.Worker.Tray;

public sealed record UserSshPublicKey(
    string Algorithm,
    string PrivateKeyPath,
    string PublicKeyPath,
    string Fingerprint,
    string PublicKey);

public static class UserSshKeyManager
{
    private const int MaximumPublicKeyBytes = 16 * 1024;
    private const int MaximumPrivateKeyBytes = 16 * 1024;

    public static string RecommendedPrivateKeyPath(string nodeId)
    {
        string safeNodeId = new(nodeId.Select(static character =>
            char.IsAsciiLetterOrDigit(character) || character is '-' or '_' ? character : '-').ToArray());
        safeNodeId = safeNodeId.Trim('-');
        if (safeNodeId.Length == 0 || safeNodeId.Length > 96)
        {
            throw new ArgumentException("user-key-node-id-invalid", nameof(nodeId));
        }

        return Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
            ".ssh",
            $"id_ed25519_hch_{safeNodeId}");
    }

    public static async Task<UserSshPublicKey> GenerateAsync(
        string privateKeyPath,
        string nodeId,
        CancellationToken cancellationToken = default)
    {
        string privatePath = ValidateFixedLocalAbsolutePath(privateKeyPath);
        string publicPath = ValidateFixedLocalAbsolutePath(privatePath + ".pub");
        string directory = Path.GetDirectoryName(privatePath)
            ?? throw new ArgumentException("user-key-directory-invalid", nameof(privateKeyPath));
        var ownerSid = WindowsIdentity.GetCurrent().User
            ?? throw new InvalidOperationException("user-key-owner-sid-unavailable");
        _ = WindowsAcl.CreateOrValidateUserKeyDirectory(directory, ownerSid);

        if (File.Exists(privatePath) || File.Exists(publicPath))
        {
            throw new IOException("user-key-target-already-exists");
        }

        string privateStaging = Path.Combine(directory, $".hch-private-{Guid.NewGuid():N}.tmp");
        string publicStaging = Path.Combine(directory, $".hch-public-{Guid.NewGuid():N}.tmp");
        byte[]? privatePem = null;
        byte[]? publicBytes = null;
        bool privateCommitted = false;
        try
        {
            using var identity = Ed25519Identity.Generate();
            privatePem = identity.ExportOpenSshPrivateKeyPem();
            string publicKey = identity.ExportOpenSshPublicKey($"hch:{nodeId}");
            publicBytes = Encoding.UTF8.GetBytes(publicKey + Environment.NewLine);

            await WriteNewFileAsync(
                privateStaging,
                privatePem,
                ownerSid,
                cancellationToken).ConfigureAwait(false);
            await WriteNewFileAsync(
                publicStaging,
                publicBytes,
                ownerSid,
                cancellationToken).ConfigureAwait(false);

            File.Move(privateStaging, privatePath, overwrite: false);
            privateCommitted = true;
            File.Move(publicStaging, publicPath, overwrite: false);
            WindowsAcl.ValidateUserPrivateFile(privatePath, ownerSid);

            return new UserSshPublicKey(
                "ssh-ed25519",
                privatePath,
                publicPath,
                identity.Fingerprint,
                publicKey);
        }
        catch
        {
            TryDelete(privateStaging);
            TryDelete(publicStaging);
            if (privateCommitted && !File.Exists(publicPath))
            {
                TryDelete(privatePath);
            }

            throw;
        }
        finally
        {
            if (privatePem is not null)
            {
                CryptographicOperations.ZeroMemory(privatePem);
            }

            if (publicBytes is not null)
            {
                CryptographicOperations.ZeroMemory(publicBytes);
            }
        }
    }

    public static async Task<UserSshPublicKey> ReadExistingAsync(
        string publicKeyPath,
        CancellationToken cancellationToken = default)
    {
        string publicPath = ValidateFixedLocalAbsolutePath(publicKeyPath);
        RejectReparsePoints(publicPath);
        var ownerSid = WindowsIdentity.GetCurrent().User
            ?? throw new InvalidOperationException("user-key-owner-sid-unavailable");
        string directory = Path.GetDirectoryName(publicPath)
            ?? throw new ArgumentException("user-key-directory-invalid", nameof(publicKeyPath));
        WindowsAcl.ValidateUserKeyDirectory(directory, ownerSid);
        var info = new FileInfo(publicPath);
        if (!info.Exists || info.Length is <= 0 or > MaximumPublicKeyBytes)
        {
            throw new IOException("user-public-key-file-invalid");
        }

        string publicKey = (await File.ReadAllTextAsync(publicPath, cancellationToken).ConfigureAwait(false)).Trim();
        byte[] subjectPublicKeyInfo = OpenSshEd25519PublicKey.DecodeSubjectPublicKeyInfo(publicKey);
        try
        {
            string candidatePrivatePath = publicPath.EndsWith(".pub", StringComparison.OrdinalIgnoreCase)
                ? publicPath[..^4]
                : string.Empty;
            string privatePath = string.Empty;
            if (candidatePrivatePath.Length > 0 && File.Exists(candidatePrivatePath))
            {
                WindowsAcl.ValidateUserPrivateFile(candidatePrivatePath, ownerSid);
                privatePath = candidatePrivatePath;
            }

            return new UserSshPublicKey(
                "ssh-ed25519",
                privatePath,
                publicPath,
                Ed25519KeyEncoding.Fingerprint(subjectPublicKeyInfo),
                publicKey);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(subjectPublicKeyInfo);
        }
    }

    internal static async Task<byte[]> SignRegistrationProofAsync(
        string privateKeyPath,
        ValidatedWorkerSshKeyProof proof,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(proof);
        string privatePath = ValidateFixedLocalAbsolutePath(privateKeyPath);
        RejectReparsePoints(privatePath);
        var ownerSid = WindowsIdentity.GetCurrent().User
            ?? throw new InvalidOperationException("user-key-owner-sid-unavailable");
        string directory = Path.GetDirectoryName(privatePath)
            ?? throw new ArgumentException("user-key-directory-invalid", nameof(privateKeyPath));
        WindowsAcl.ValidateUserKeyDirectory(directory, ownerSid);
        WindowsAcl.ValidateUserPrivateFile(privatePath, ownerSid);
        var info = new FileInfo(privatePath);
        if (!info.Exists || info.Length is <= 0 or > MaximumPrivateKeyBytes)
        {
            throw new IOException("user-private-key-file-invalid");
        }

        byte[] pem = await ReadPrivateFileAsync(
            privatePath,
            checked((int)info.Length),
            cancellationToken).ConfigureAwait(false);
        try
        {
            using var identity = Ed25519Identity.ImportOpenSshPrivateKeyPem(pem);
            if (!FixedTextEquals(identity.Fingerprint, proof.ExpectedFingerprint))
            {
                throw new CryptographicException("user-private-key-public-key-mismatch");
            }

            return await identity.SignAsync(
                proof.CanonicalPayload,
                cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(pem);
        }
    }

    private static async Task WriteNewFileAsync(
        string path,
        ReadOnlyMemory<byte> contents,
        SecurityIdentifier ownerSid,
        CancellationToken cancellationToken)
    {
        await using FileStream stream = WindowsAcl.CreatePrivateUserFile(path, ownerSid);
        await stream.WriteAsync(contents, cancellationToken).ConfigureAwait(false);
        await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
        stream.Flush(flushToDisk: true);
    }

    private static async Task<byte[]> ReadPrivateFileAsync(
        string path,
        int length,
        CancellationToken cancellationToken)
    {
        byte[] contents = new byte[length];
        try
        {
            await using var stream = new FileStream(
                path,
                FileMode.Open,
                FileAccess.Read,
                FileShare.None,
                16 * 1024,
                FileOptions.Asynchronous | FileOptions.SequentialScan);
            if (stream.Length != length)
            {
                throw new IOException("user-private-key-file-changed");
            }

            await stream.ReadExactlyAsync(contents, cancellationToken).ConfigureAwait(false);
            if (stream.Position != stream.Length)
            {
                throw new IOException("user-private-key-file-changed");
            }

            return contents;
        }
        catch
        {
            CryptographicOperations.ZeroMemory(contents);
            throw;
        }
    }

    private static bool FixedTextEquals(string left, string right)
    {
        byte[] leftBytes = Encoding.UTF8.GetBytes(left);
        byte[] rightBytes = Encoding.UTF8.GetBytes(right);
        byte[] leftHash = SHA256.HashData(leftBytes);
        byte[] rightHash = SHA256.HashData(rightBytes);
        try
        {
            bool digestMatches = CryptographicOperations.FixedTimeEquals(leftHash, rightHash);
            bool exactMatches = leftBytes.Length == rightBytes.Length
                && CryptographicOperations.FixedTimeEquals(leftBytes, rightBytes);
            return digestMatches & exactMatches;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(leftBytes);
            CryptographicOperations.ZeroMemory(rightBytes);
            CryptographicOperations.ZeroMemory(leftHash);
            CryptographicOperations.ZeroMemory(rightHash);
        }
    }

    private static string ValidateFixedLocalAbsolutePath(string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        if (!Path.IsPathFullyQualified(path) || path.StartsWith("\\\\", StringComparison.Ordinal))
        {
            throw new ArgumentException("user-key-path-must-be-local-and-absolute", nameof(path));
        }

        string fullPath = Path.GetFullPath(path);
        string? root = Path.GetPathRoot(fullPath);
        try
        {
            if (string.IsNullOrEmpty(root) || new DriveInfo(root).DriveType != DriveType.Fixed)
            {
                throw new ArgumentException("user-key-path-volume-invalid", nameof(path));
            }
        }
        catch (IOException)
        {
            throw new ArgumentException("user-key-path-volume-invalid", nameof(path));
        }

        RejectReparsePoints(fullPath);
        return fullPath;
    }

    private static void RejectReparsePoints(string path)
    {
        string? current = path;
        while (!string.IsNullOrEmpty(current))
        {
            if ((File.Exists(current) || Directory.Exists(current))
                && (File.GetAttributes(current) & FileAttributes.ReparsePoint) != 0)
            {
                throw new IOException("user-key-path-reparse-point-refused");
            }

            string? parent = Path.GetDirectoryName(current);
            if (string.Equals(parent, current, StringComparison.OrdinalIgnoreCase))
            {
                break;
            }

            current = parent;
        }
    }

    private static void TryDelete(string path)
    {
        try
        {
            File.Delete(path);
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException)
        {
            // A failed cleanup is intentionally not allowed to mask the original
            // error. The random staging name contains no credential material.
        }
    }
}
