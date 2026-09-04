using System.Security.Cryptography;
using System.Text.RegularExpressions;

namespace Hch.Worker.Linux;

/// <summary>Stores revocable opaque tokens as owner-only files.</summary>
public sealed partial class LinuxRevocableTokenStore
{
    private const int MaximumTokenBytes = 2560;
    private readonly string directory;

    public LinuxRevocableTokenStore(string stateDirectory)
    {
        string state = LinuxPathSecurity.RequireAbsoluteCanonicalPath(stateDirectory);
        directory = Path.Combine(state, "credentials");
    }

    public void Store(string tokenId, ReadOnlySpan<byte> token)
    {
        string destination = TokenPath(tokenId);
        if (token.IsEmpty || token.Length > MaximumTokenBytes)
        {
            throw new ArgumentException("credential-token-length-invalid", nameof(token));
        }

        using Microsoft.Win32.SafeHandles.SafeFileHandle directoryHandle =
            LinuxSecureFile.OpenPrivateDirectory(directory);
        string temporaryFileName = $".{Guid.NewGuid():N}.tmp";
        byte[] buffer = token.ToArray();
        try
        {
            using (FileStream stream = LinuxSecureFile.CreatePrivateFileAt(
                directoryHandle,
                temporaryFileName))
            {
                stream.Write(buffer);
                stream.Flush(flushToDisk: true);
            }

            LinuxSecureFile.ReplaceAt(
                directoryHandle,
                temporaryFileName,
                Path.GetFileName(destination));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(buffer);
            try
            {
                LinuxSecureFile.DeleteAt(directoryHandle, temporaryFileName);
            }
            catch (IOException error) when (error.InnerException is System.ComponentModel.Win32Exception
                { NativeErrorCode: 2 })
            {
            }
        }
    }

    public LinuxTokenSecret? Read(string tokenId)
    {
        string path = TokenPath(tokenId);
        using Microsoft.Win32.SafeHandles.SafeFileHandle directoryHandle =
            LinuxSecureFile.OpenPrivateDirectory(directory);
        using FileStream? stream = LinuxSecureFile.OpenPrivateFileForReadAt(
            directoryHandle,
            Path.GetFileName(path),
            missingReturnsNull: true);
        if (stream is null)
        {
            return null;
        }

        byte[] value = new byte[MaximumTokenBytes + 1];
        int length = 0;
        while (length < value.Length)
        {
            int read = stream.Read(value, length, value.Length - length);
            if (read == 0)
            {
                break;
            }

            length += read;
        }

        if (length is < 1 or > MaximumTokenBytes)
        {
            CryptographicOperations.ZeroMemory(value);
            throw new InvalidDataException("credential-token-blob-invalid");
        }

        Array.Resize(ref value, length);
        return new LinuxTokenSecret(value);
    }

    public bool Revoke(string tokenId)
    {
        string path = TokenPath(tokenId);
        using Microsoft.Win32.SafeHandles.SafeFileHandle directoryHandle =
            LinuxSecureFile.OpenPrivateDirectory(directory);
        using FileStream? stream = LinuxSecureFile.OpenPrivateFileForReadAt(
            directoryHandle,
            Path.GetFileName(path),
            missingReturnsNull: true);
        if (stream is null)
        {
            return false;
        }

        LinuxSecureFile.DeleteAt(directoryHandle, Path.GetFileName(path));
        return true;
    }

    private string TokenPath(string tokenId)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(tokenId);
        if (!TokenIdPattern().IsMatch(tokenId))
        {
            throw new ArgumentException("credential-token-id-invalid", nameof(tokenId));
        }

        return Path.Combine(directory, tokenId + ".token");
    }

    [GeneratedRegex("^[A-Za-z0-9_.-]{1,128}$", RegexOptions.CultureInvariant)]
    private static partial Regex TokenIdPattern();
}

public sealed class LinuxTokenSecret : IDisposable
{
    private byte[]? value;

    internal LinuxTokenSecret(byte[] value) => this.value = value;

    public ReadOnlyMemory<byte> Value => value
        ?? throw new ObjectDisposedException(nameof(LinuxTokenSecret));

    public override string ToString() => "[REDACTED]";

    public void Dispose()
    {
        byte[]? secret = Interlocked.Exchange(ref value, null);
        if (secret is not null)
        {
            CryptographicOperations.ZeroMemory(secret);
        }
    }
}
