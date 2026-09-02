using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using Hch.Worker.Protocol;

namespace Hch.Worker.Security;

/// <summary>Strict OpenSSH public-key codec for Ed25519.</summary>
public static class OpenSshEd25519PublicKey
{
    private const string Algorithm = "ssh-ed25519";
    private const int MaximumCommentLength = 256;

    public static string Encode(ReadOnlySpan<byte> subjectPublicKeyInfo, string? comment = null)
    {
        byte[] rawPublicKey = Ed25519KeyEncoding.GetRawPublicKey(subjectPublicKeyInfo);
        ValidateComment(comment);

        byte[] algorithm = Encoding.ASCII.GetBytes(Algorithm);
        byte[] blob = new byte[sizeof(uint) + algorithm.Length + sizeof(uint) + rawPublicKey.Length];
        int offset = 0;
        WriteField(blob, ref offset, algorithm);
        WriteField(blob, ref offset, rawPublicKey);

        string suffix = string.IsNullOrEmpty(comment) ? string.Empty : " " + comment;
        return $"{Algorithm} {Convert.ToBase64String(blob)}{suffix}";
    }

    public static byte[] DecodeSubjectPublicKeyInfo(string authorizedKey)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(authorizedKey);
        string[] fields = authorizedKey.Trim().Split(' ', 3, StringSplitOptions.RemoveEmptyEntries);
        if (fields.Length < 2 || !string.Equals(fields[0], Algorithm, StringComparison.Ordinal))
        {
            throw new CryptographicException("openssh-ed25519-algorithm-invalid");
        }

        if (fields.Length == 3)
        {
            ValidateComment(fields[2]);
        }

        byte[] blob;
        try
        {
            blob = Convert.FromBase64String(fields[1]);
        }
        catch (FormatException)
        {
            throw new CryptographicException("openssh-ed25519-base64-invalid");
        }

        ReadOnlySpan<byte> remaining = blob;
        ReadOnlySpan<byte> algorithm = ReadField(ref remaining);
        ReadOnlySpan<byte> rawPublicKey = ReadField(ref remaining);
        if (!remaining.IsEmpty
            || !algorithm.SequenceEqual(Encoding.ASCII.GetBytes(Algorithm))
            || rawPublicKey.Length != Ed25519KeyEncoding.RawPublicKeyLength)
        {
            throw new CryptographicException("openssh-ed25519-blob-invalid");
        }

        return Ed25519KeyEncoding.CreateSubjectPublicKeyInfo(rawPublicKey);
    }

    private static void WriteField(Span<byte> destination, ref int offset, ReadOnlySpan<byte> value)
    {
        BinaryPrimitives.WriteUInt32BigEndian(destination[offset..], checked((uint)value.Length));
        offset += sizeof(uint);
        value.CopyTo(destination[offset..]);
        offset += value.Length;
    }

    private static ReadOnlySpan<byte> ReadField(ref ReadOnlySpan<byte> value)
    {
        if (value.Length < sizeof(uint))
        {
            throw new CryptographicException("openssh-ed25519-blob-invalid");
        }

        uint length = BinaryPrimitives.ReadUInt32BigEndian(value);
        value = value[sizeof(uint)..];
        if (length > int.MaxValue || value.Length < (int)length)
        {
            throw new CryptographicException("openssh-ed25519-blob-invalid");
        }

        ReadOnlySpan<byte> field = value[..(int)length];
        value = value[(int)length..];
        return field;
    }

    private static void ValidateComment(string? comment)
    {
        if (comment is null)
        {
            return;
        }

        if (comment.Length > MaximumCommentLength
            || comment.IndexOfAny(['\r', '\n', '\0']) >= 0)
        {
            throw new ArgumentException("openssh-ed25519-comment-invalid", nameof(comment));
        }
    }
}
