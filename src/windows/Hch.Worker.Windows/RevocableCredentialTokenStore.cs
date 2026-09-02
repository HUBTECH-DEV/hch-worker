using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text.RegularExpressions;

namespace Hch.Worker.Windows;

/// <summary>
/// Stores only revocable opaque tokens in the current user's Credential Manager.
/// </summary>
public sealed partial class RevocableCredentialTokenStore
{
    private const uint GenericCredential = 1;
    private const uint PersistOnLocalMachine = 2;
    private const int ErrorNotFound = 1168;
    private const int MaximumCredentialBlobBytes = 2560;
    private const string TargetPrefix = "HubTech/HCH/Worker/token/";

    private static readonly Regex TokenIdPattern = TokenIdExpression();

    public void Store(string tokenId, ReadOnlySpan<byte> token)
    {
        string target = CreateTarget(tokenId);
        if (token.IsEmpty || token.Length > MaximumCredentialBlobBytes)
        {
            throw new ArgumentException("credential-token-length-invalid", nameof(token));
        }

        byte[] temporary = token.ToArray();
        nint blob = Marshal.AllocHGlobal(temporary.Length);
        try
        {
            Marshal.Copy(temporary, 0, blob, temporary.Length);
            var credential = new NativeCredential
            {
                Type = GenericCredential,
                TargetName = target,
                CredentialBlobSize = checked((uint)temporary.Length),
                CredentialBlob = blob,
                Persist = PersistOnLocalMachine,
                UserName = string.Empty,
            };
            if (!CredWrite(ref credential, flags: 0))
            {
                throw new Win32Exception(
                    Marshal.GetLastWin32Error(),
                    "credential-token-write-failed");
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(temporary);
            ZeroUnmanagedMemory(blob, token.Length);
            Marshal.FreeHGlobal(blob);
        }
    }

    public RevocableTokenSecret? Read(string tokenId)
    {
        string target = CreateTarget(tokenId);
        if (!CredRead(target, GenericCredential, flags: 0, out nint credentialPointer))
        {
            int error = Marshal.GetLastWin32Error();
            if (error == ErrorNotFound)
            {
                return null;
            }

            throw new Win32Exception(error, "credential-token-read-failed");
        }

        try
        {
            var credential = Marshal.PtrToStructure<NativeCredential>(credentialPointer);
            if (credential.CredentialBlobSize == 0
                || credential.CredentialBlobSize > MaximumCredentialBlobBytes
                || credential.CredentialBlob == 0)
            {
                throw new InvalidDataException("credential-token-blob-invalid");
            }

            int secretLength = checked((int)credential.CredentialBlobSize);
            var secret = new byte[secretLength];
            Marshal.Copy(credential.CredentialBlob, secret, 0, secret.Length);
            return new RevocableTokenSecret(secret);
        }
        finally
        {
            CredFree(credentialPointer);
        }
    }

    public bool Revoke(string tokenId)
    {
        string target = CreateTarget(tokenId);
        if (CredDelete(target, GenericCredential, flags: 0))
        {
            return true;
        }

        int error = Marshal.GetLastWin32Error();
        if (error == ErrorNotFound)
        {
            return false;
        }

        throw new Win32Exception(error, "credential-token-delete-failed");
    }

    public static string CreateTarget(string tokenId)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(tokenId);
        if (!TokenIdPattern.IsMatch(tokenId))
        {
            throw new ArgumentException("credential-token-id-invalid", nameof(tokenId));
        }

        return TargetPrefix + tokenId;
    }

    private static void ZeroUnmanagedMemory(nint pointer, int length)
    {
        for (int index = 0; index < length; index++)
        {
            Marshal.WriteByte(pointer, index, 0);
        }
    }

    [DllImport("advapi32.dll", EntryPoint = "CredWriteW", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CredWrite(ref NativeCredential credential, uint flags);

    [DllImport("advapi32.dll", EntryPoint = "CredReadW", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CredRead(
        string target,
        uint type,
        uint flags,
        out nint credential);

    [DllImport("advapi32.dll", EntryPoint = "CredDeleteW", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CredDelete(string target, uint type, uint flags);

    [DllImport("advapi32.dll")]
    private static extern void CredFree(nint buffer);

    [GeneratedRegex("^[A-Za-z0-9_.-]{1,128}$", RegexOptions.CultureInvariant)]
    private static partial Regex TokenIdExpression();

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct NativeCredential
    {
        public uint Flags;
        public uint Type;
        [MarshalAs(UnmanagedType.LPWStr)] public string? TargetName;
        [MarshalAs(UnmanagedType.LPWStr)] public string? Comment;
        public System.Runtime.InteropServices.ComTypes.FILETIME LastWritten;
        public uint CredentialBlobSize;
        public nint CredentialBlob;
        public uint Persist;
        public uint AttributeCount;
        public nint Attributes;
        [MarshalAs(UnmanagedType.LPWStr)] public string? TargetAlias;
        [MarshalAs(UnmanagedType.LPWStr)] public string? UserName;
    }
}

/// <summary>
/// Disposable token value whose string representation is always redacted.
/// </summary>
public sealed class RevocableTokenSecret : IDisposable
{
    private byte[]? value;

    internal RevocableTokenSecret(byte[] value)
    {
        this.value = value;
    }

    public int Length => value?.Length ?? 0;

    /// <summary>Explicitly copies the secret for one authenticated request.</summary>
    public byte[] CopySecret()
    {
        ObjectDisposedException.ThrowIf(value is null, this);
        return value.ToArray();
    }

    public override string ToString() => "[REDACTED]";

    public void Dispose()
    {
        if (value is null)
        {
            return;
        }

        CryptographicOperations.ZeroMemory(value);
        value = null;
        GC.SuppressFinalize(this);
    }
}
