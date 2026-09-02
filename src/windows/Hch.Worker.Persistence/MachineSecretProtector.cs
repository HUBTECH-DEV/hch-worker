using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;

namespace Hch.Worker.Persistence;

/// <summary>
/// Protects machine-scoped secret material. The abstraction exists so migration
/// can be exercised with synthetic state without invoking or weakening DPAPI.
/// </summary>
public interface IMachineSecretProtector
{
    byte[] Protect(ReadOnlySpan<byte> plaintext, string purpose);

    byte[] Unprotect(ReadOnlySpan<byte> ciphertext, string purpose);
}

[SupportedOSPlatform("windows")]
public sealed class MachineSecretProtector : IMachineSecretProtector
{
    private const int CryptProtectUiForbidden = 0x1;
    private const int CryptProtectLocalMachine = 0x4;

    public byte[] Protect(ReadOnlySpan<byte> plaintext, string purpose)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(purpose);
        return Transform(plaintext, PurposeEntropy(purpose), protect: true);
    }

    public byte[] Unprotect(ReadOnlySpan<byte> ciphertext, string purpose)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(purpose);
        return Transform(ciphertext, PurposeEntropy(purpose), protect: false);
    }

    private static byte[] Transform(ReadOnlySpan<byte> input, byte[] entropy, bool protect)
    {
        if (input.IsEmpty)
        {
            throw new ArgumentException("Secret material cannot be empty.", nameof(input));
        }

        var inputBlob = DataBlob.Allocate(input);
        var entropyBlob = DataBlob.Allocate(entropy);
        DataBlob outputBlob = default;
        try
        {
            var succeeded = protect
                ? CryptProtectData(
                    ref inputBlob,
                    null,
                    ref entropyBlob,
                    IntPtr.Zero,
                    IntPtr.Zero,
                    CryptProtectUiForbidden | CryptProtectLocalMachine,
                    out outputBlob)
                : CryptUnprotectData(
                    ref inputBlob,
                    IntPtr.Zero,
                    ref entropyBlob,
                    IntPtr.Zero,
                    IntPtr.Zero,
                    CryptProtectUiForbidden,
                    out outputBlob);
            if (!succeeded)
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }

            var output = new byte[outputBlob.Length];
            Marshal.Copy(outputBlob.Data, output, 0, output.Length);
            return output;
        }
        finally
        {
            inputBlob.Free(zero: true);
            entropyBlob.Free(zero: true);
            outputBlob.Free(zero: true, localFree: true);
            CryptographicOperations.ZeroMemory(entropy);
        }
    }

    private static byte[] PurposeEntropy(string purpose) =>
        SHA256.HashData(Encoding.UTF8.GetBytes("hch-worker-v4:" + purpose));

    [StructLayout(LayoutKind.Sequential)]
    private struct DataBlob
    {
        public int Length;
        public IntPtr Data;

        public static DataBlob Allocate(ReadOnlySpan<byte> value)
        {
            var data = Marshal.AllocHGlobal(value.Length);
            var copy = value.ToArray();
            try
            {
                Marshal.Copy(copy, 0, data, copy.Length);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(copy);
            }

            return new DataBlob { Length = value.Length, Data = data };
        }

        public void Free(bool zero, bool localFree = false)
        {
            if (Data == IntPtr.Zero)
            {
                return;
            }

            if (zero && Length > 0)
            {
                var zeros = new byte[Length];
                Marshal.Copy(zeros, 0, Data, Length);
            }

            if (localFree)
            {
                _ = LocalFree(Data);
            }
            else
            {
                Marshal.FreeHGlobal(Data);
            }

            Data = IntPtr.Zero;
            Length = 0;
        }
    }

    [DllImport("crypt32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CryptProtectData(
        ref DataBlob input,
        string? description,
        ref DataBlob optionalEntropy,
        IntPtr reserved,
        IntPtr prompt,
        int flags,
        out DataBlob output);

    [DllImport("crypt32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CryptUnprotectData(
        ref DataBlob input,
        IntPtr description,
        ref DataBlob optionalEntropy,
        IntPtr reserved,
        IntPtr prompt,
        int flags,
        out DataBlob output);

    [DllImport("kernel32.dll")]
    private static extern IntPtr LocalFree(IntPtr memory);
}
