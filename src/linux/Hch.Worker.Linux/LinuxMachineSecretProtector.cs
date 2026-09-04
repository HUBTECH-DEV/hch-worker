using System.Security.Cryptography;
using System.Text;
using Hch.Worker.Persistence;

namespace Hch.Worker.Linux;

/// <summary>
/// Protects machine-local secrets using AES-256-GCM and an owner-only key file.
/// File ownership and mode are validated before every key read.
/// </summary>
public sealed class LinuxMachineSecretProtector : IMachineSecretProtector
{
    private static ReadOnlySpan<byte> Magic => "HCHLNX1\0"u8;
    private const int KeySize = 32;
    private const int NonceSize = 12;
    private const int TagSize = 16;
    private readonly string keyPath;

    public LinuxMachineSecretProtector(string stateDirectory)
    {
        string state = LinuxPathSecurity.RequireAbsoluteCanonicalPath(stateDirectory);
        keyPath = Path.Combine(state, "machine-secret.key");
    }

    public byte[] Protect(ReadOnlySpan<byte> plaintext, string purpose)
    {
        Validate(plaintext, purpose);
        byte[] key = ReadOrCreateKey();
        byte[] nonce = RandomNumberGenerator.GetBytes(NonceSize);
        byte[] ciphertext = new byte[plaintext.Length];
        byte[] tag = new byte[TagSize];
        byte[] aad = PurposeEntropy(purpose);
        try
        {
            using var aes = new AesGcm(key, TagSize);
            aes.Encrypt(nonce, plaintext, ciphertext, tag, aad);
            byte[] output = new byte[Magic.Length + NonceSize + TagSize + ciphertext.Length];
            Magic.CopyTo(output);
            nonce.CopyTo(output.AsSpan(Magic.Length));
            tag.CopyTo(output.AsSpan(Magic.Length + NonceSize));
            ciphertext.CopyTo(output.AsSpan(Magic.Length + NonceSize + TagSize));
            return output;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
            CryptographicOperations.ZeroMemory(aad);
        }
    }

    public byte[] Unprotect(ReadOnlySpan<byte> protectedBytes, string purpose)
    {
        Validate(protectedBytes, purpose);
        int headerSize = Magic.Length + NonceSize + TagSize;
        if (protectedBytes.Length <= headerSize
            || !protectedBytes[..Magic.Length].SequenceEqual(Magic))
        {
            throw new CryptographicException("linux-protected-secret-format-invalid");
        }

        byte[] key = ReadOrCreateKey();
        byte[] aad = PurposeEntropy(purpose);
        byte[] plaintext = new byte[protectedBytes.Length - headerSize];
        try
        {
            using var aes = new AesGcm(key, TagSize);
            aes.Decrypt(
                protectedBytes.Slice(Magic.Length, NonceSize),
                protectedBytes.Slice(Magic.Length + NonceSize, TagSize),
                protectedBytes[headerSize..],
                plaintext,
                aad);
            return plaintext;
        }
        catch
        {
            CryptographicOperations.ZeroMemory(plaintext);
            throw;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
            CryptographicOperations.ZeroMemory(aad);
        }
    }

    private byte[] ReadOrCreateKey()
    {
        string directory = Path.GetDirectoryName(keyPath)!;
        LinuxPathSecurity.EnsurePrivateDirectory(directory);
        try
        {
            using var stream = new FileStream(keyPath, new FileStreamOptions
            {
                Access = FileAccess.Write,
                Mode = FileMode.CreateNew,
                Share = FileShare.None,
                Options = FileOptions.WriteThrough,
                UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite,
            });
            byte[] generated = RandomNumberGenerator.GetBytes(KeySize);
            try
            {
                stream.Write(generated);
                stream.Flush(flushToDisk: true);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(generated);
            }
        }
        catch (IOException) when (File.Exists(keyPath))
        {
            // Another process or an earlier installation created the key.
        }

        LinuxPathSecurity.RequirePrivateFile(keyPath);
        byte[] key = File.ReadAllBytes(keyPath);
        if (key.Length != KeySize)
        {
            CryptographicOperations.ZeroMemory(key);
            throw new CryptographicException("linux-machine-key-length-invalid");
        }

        return key;
    }

    private static void Validate(ReadOnlySpan<byte> value, string purpose)
    {
        if (value.IsEmpty)
        {
            throw new ArgumentException("secret-material-empty", nameof(value));
        }

        ArgumentException.ThrowIfNullOrWhiteSpace(purpose);
    }

    private static byte[] PurposeEntropy(string purpose) =>
        SHA256.HashData(Encoding.UTF8.GetBytes("hch-worker-v4-linux:" + purpose));
}
