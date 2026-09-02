using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text.Json;

namespace Hch.Worker.IPC.Contracts;

public static class IpcFraming
{
    public const int HeaderBytes = sizeof(int);

    public static async Task WriteAsync<T>(
        Stream stream,
        T message,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(stream);
        var payload = JsonSerializer.SerializeToUtf8Bytes(message, IpcJson.Options);
        try
        {
            if (payload.Length is < 1 or > IpcProtocol.MaximumFrameBytes)
            {
                throw new IpcContractException("ipc-frame-size-invalid");
            }

            var header = new byte[HeaderBytes];
            BinaryPrimitives.WriteInt32LittleEndian(header, payload.Length);
            await stream.WriteAsync(header, cancellationToken).ConfigureAwait(false);
            await stream.WriteAsync(payload, cancellationToken).ConfigureAwait(false);
            await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(payload);
        }
    }

    public static async Task<T> ReadAsync<T>(
        Stream stream,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(stream);
        var header = new byte[HeaderBytes];
        await ReadExactlyAsync(stream, header, cancellationToken).ConfigureAwait(false);
        var length = BinaryPrimitives.ReadInt32LittleEndian(header);
        if (length is < 1 or > IpcProtocol.MaximumFrameBytes)
        {
            throw new IpcContractException("ipc-frame-size-invalid");
        }

        var payload = new byte[length];
        await ReadExactlyAsync(stream, payload, cancellationToken).ConfigureAwait(false);
        try
        {
            return JsonSerializer.Deserialize<T>(payload, IpcJson.Options)
                ?? throw new IpcContractException("ipc-frame-json-invalid");
        }
        catch (JsonException error)
        {
            throw new IpcContractException("ipc-frame-json-invalid", error);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(payload);
        }
    }

    private static async Task ReadExactlyAsync(
        Stream stream,
        Memory<byte> buffer,
        CancellationToken cancellationToken)
    {
        var offset = 0;
        while (offset < buffer.Length)
        {
            var read = await stream.ReadAsync(buffer[offset..], cancellationToken).ConfigureAwait(false);
            if (read == 0)
            {
                throw new EndOfStreamException("ipc-frame-truncated");
            }

            offset += read;
        }
    }
}
