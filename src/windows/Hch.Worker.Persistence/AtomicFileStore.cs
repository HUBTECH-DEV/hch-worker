using System.Text.Json;
using System.Text.Json.Serialization;

namespace Hch.Worker.Persistence;

public sealed class AtomicFileStore
{
    private readonly string _root;
    private readonly string _rootPrefix;

    public AtomicFileStore(string root)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(root);
        _root = Path.GetFullPath(root);
        if (!Path.IsPathFullyQualified(_root))
        {
            throw new ArgumentException("The state root must be absolute.", nameof(root));
        }

        _rootPrefix = _root.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar) +
            Path.DirectorySeparatorChar;
    }

    public string Root => _root;

    public static JsonSerializerOptions JsonOptions { get; } = new(JsonSerializerDefaults.Web)
    {
        AllowTrailingCommas = false,
        MaxDepth = 64,
        NumberHandling = JsonNumberHandling.Strict,
        PropertyNameCaseInsensitive = false,
        ReadCommentHandling = JsonCommentHandling.Disallow,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
        WriteIndented = false,
    };

    public string Resolve(string relativePath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(relativePath);
        if (Path.IsPathFullyQualified(relativePath))
        {
            throw new ArgumentException("State paths must be relative.", nameof(relativePath));
        }

        var fullPath = Path.GetFullPath(Path.Combine(_root, relativePath));
        if (!fullPath.StartsWith(_rootPrefix, StringComparison.OrdinalIgnoreCase))
        {
            throw new ArgumentException("The state path escapes the state root.", nameof(relativePath));
        }

        return fullPath;
    }

    public async Task<T?> ReadJsonAsync<T>(string relativePath, CancellationToken cancellationToken = default)
    {
        var path = Resolve(relativePath);
        if (!File.Exists(path))
        {
            return default;
        }

        EnsureNoReparsePoint(path, includeLeaf: true);
        await using var stream = new FileStream(
            path,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            64 * 1024,
            FileOptions.Asynchronous | FileOptions.SequentialScan);
        return await JsonSerializer.DeserializeAsync<T>(stream, JsonOptions, cancellationToken)
            .ConfigureAwait(false);
    }

    public Task WriteJsonAsync<T>(string relativePath, T value, CancellationToken cancellationToken = default)
    {
        var bytes = JsonSerializer.SerializeToUtf8Bytes(value, JsonOptions);
        return WriteBytesAsync(relativePath, bytes, cancellationToken);
    }

    public async Task WriteBytesAsync(
        string relativePath,
        ReadOnlyMemory<byte> bytes,
        CancellationToken cancellationToken = default)
    {
        var destination = Resolve(relativePath);
        var directory = Path.GetDirectoryName(destination)
            ?? throw new InvalidOperationException("The destination has no directory.");
        Directory.CreateDirectory(directory);
        EnsureNoReparsePoint(directory, includeLeaf: true);
        if (File.Exists(destination))
        {
            EnsureNoReparsePoint(destination, includeLeaf: true);
        }

        var temporary = destination + "." + Guid.NewGuid().ToString("N") + ".tmp";
        try
        {
            await using (var stream = new FileStream(
                temporary,
                FileMode.CreateNew,
                FileAccess.Write,
                FileShare.None,
                64 * 1024,
                FileOptions.Asynchronous | FileOptions.WriteThrough))
            {
                await stream.WriteAsync(bytes, cancellationToken).ConfigureAwait(false);
                await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
                stream.Flush(flushToDisk: true);
            }

            File.Move(temporary, destination, overwrite: true);
        }
        finally
        {
            if (File.Exists(temporary))
            {
                File.Delete(temporary);
            }
        }
    }

    private void EnsureNoReparsePoint(string path, bool includeLeaf)
    {
        var current = includeLeaf ? path : Path.GetDirectoryName(path);
        while (!string.IsNullOrEmpty(current) &&
               current.StartsWith(_root, StringComparison.OrdinalIgnoreCase))
        {
            if (File.Exists(current) || Directory.Exists(current))
            {
                var attributes = File.GetAttributes(current);
                if ((attributes & FileAttributes.ReparsePoint) != 0)
                {
                    throw new IOException("State paths cannot traverse a reparse point.");
                }
            }

            if (string.Equals(current, _root, StringComparison.OrdinalIgnoreCase))
            {
                break;
            }

            current = Path.GetDirectoryName(current);
        }
    }
}
