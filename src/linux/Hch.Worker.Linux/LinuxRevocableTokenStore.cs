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

        LinuxPathSecurity.EnsurePrivateDirectory(directory);
        string temporary = Path.Combine(directory, $".{Guid.NewGuid():N}.tmp");
        byte[] buffer = token.ToArray();
        try
        {
            using (var stream = new FileStream(temporary, new FileStreamOptions
            {
                Access = FileAccess.Write,
                Mode = FileMode.CreateNew,
                Share = FileShare.None,
                Options = FileOptions.WriteThrough,
                UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite,
            }))
            {
                stream.Write(buffer);
                stream.Flush(flushToDisk: true);
            }

            File.SetUnixFileMode(temporary, UnixFileMode.UserRead | UnixFileMode.UserWrite);
            File.Move(temporary, destination, overwrite: true);
            LinuxPathSecurity.RequirePrivateFile(destination);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(buffer);
            if (File.Exists(temporary))
            {
                File.Delete(temporary);
            }
        }
    }

    public LinuxTokenSecret? Read(string tokenId)
    {
        string path = TokenPath(tokenId);
        if (!File.Exists(path))
        {
            return null;
        }

        LinuxPathSecurity.RequirePrivateFile(path);
        byte[] value = File.ReadAllBytes(path);
        if (value.Length is < 1 or > MaximumTokenBytes)
        {
            CryptographicOperations.ZeroMemory(value);
            throw new InvalidDataException("credential-token-blob-invalid");
        }

        return new LinuxTokenSecret(value);
    }

    public bool Revoke(string tokenId)
    {
        string path = TokenPath(tokenId);
        if (!File.Exists(path))
        {
            return false;
        }

        LinuxPathSecurity.RequirePrivateFile(path);
        File.Delete(path);
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
