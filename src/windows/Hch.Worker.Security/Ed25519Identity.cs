using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using Hch.Worker.Protocol;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Crypto.Utilities;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;

namespace Hch.Worker.Security;

/// <summary>
/// Opaque, disposable Ed25519 identity backed by a private RFC 8032 seed.
/// </summary>
/// <remarks>
/// The private seed is never exposed as a property and therefore cannot be
/// included accidentally in a DTO. Private-key export is an explicit method
/// intended only for protected persistence and migration boundaries. Callers
/// must clear the returned buffer after protecting or importing it.
/// </remarks>
[DebuggerDisplay("Ed25519Identity({Fingerprint,nq})")]
public sealed class Ed25519Identity : IEd25519SignatureProvider, IDisposable
{
    private const int PrivateSeedLength = 32;
    private const int MaximumPkcs8Length = 4096;
    private const int MaximumOpenSshPemLength = 16 * 1024;
    private const string OpenSshPrivateKeyLabel = "OPENSSH PRIVATE KEY";

    private readonly object gate = new();
    private readonly byte[] subjectPublicKeyInfo;
    private byte[]? privateSeed;

    private Ed25519Identity(byte[] seed, bool takeOwnership)
    {
        if (seed.Length != PrivateSeedLength)
        {
            throw new CryptographicException("ed25519-private-seed-length-invalid");
        }

        privateSeed = takeOwnership ? seed : seed.ToArray();
        var privateKey = new Ed25519PrivateKeyParameters(privateSeed, 0);
        subjectPublicKeyInfo = Ed25519KeyEncoding.NormalizeSubjectPublicKeyInfo(
            SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(privateKey.GeneratePublicKey())
                .GetDerEncoded());
        Fingerprint = Ed25519KeyEncoding.Fingerprint(subjectPublicKeyInfo);
    }

    /// <summary>Stable HCH fingerprint over the RFC 8410 public SPKI.</summary>
    public string Fingerprint { get; }

    /// <summary>Generates a new identity using the operating-system CSPRNG.</summary>
    public static Ed25519Identity Generate()
    {
        var seed = new byte[PrivateSeedLength];
        RandomNumberGenerator.Fill(seed);
        try
        {
            return new Ed25519Identity(seed, takeOwnership: true);
        }
        catch
        {
            CryptographicOperations.ZeroMemory(seed);
            throw;
        }
    }

    /// <summary>Imports an Ed25519 PKCS#8 PrivateKeyInfo.</summary>
    public static Ed25519Identity ImportPkcs8(ReadOnlySpan<byte> privateKeyInfo)
    {
        if (privateKeyInfo.IsEmpty || privateKeyInfo.Length > MaximumPkcs8Length)
        {
            throw new CryptographicException("ed25519-pkcs8-length-invalid");
        }

        byte[] encoded = privateKeyInfo.ToArray();
        byte[]? seed = null;
        try
        {
            var parsed = PrivateKeyFactory.CreateKey(encoded);
            if (parsed is not Ed25519PrivateKeyParameters privateKey)
            {
                throw new CryptographicException("ed25519-pkcs8-algorithm-invalid");
            }

            seed = privateKey.GetEncoded();
            return new Ed25519Identity(seed, takeOwnership: true);
        }
        catch (CryptographicException)
        {
            if (seed is not null)
            {
                CryptographicOperations.ZeroMemory(seed);
            }

            throw;
        }
        catch (Exception)
        {
            if (seed is not null)
            {
                CryptographicOperations.ZeroMemory(seed);
            }

            throw new CryptographicException("ed25519-pkcs8-invalid");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(encoded);
        }
    }

    /// <summary>Imports an unencrypted OpenSSH Ed25519 private-key PEM.</summary>
    public static Ed25519Identity ImportOpenSshPrivateKeyPem(ReadOnlySpan<byte> pem)
    {
        if (pem.IsEmpty || pem.Length > MaximumOpenSshPemLength)
        {
            throw new CryptographicException("ed25519-openssh-private-key-length-invalid");
        }

        var characters = new char[Encoding.ASCII.GetCharCount(pem)];
        _ = Encoding.ASCII.GetChars(pem, characters);
        byte[]? decoded = null;
        byte[]? seed = null;
        try
        {
            if (!PemEncoding.TryFind(characters, out PemFields fields)
                || !characters.AsSpan()[fields.Label].SequenceEqual(OpenSshPrivateKeyLabel))
            {
                throw new CryptographicException("ed25519-openssh-private-key-pem-invalid");
            }

            ReadOnlySpan<char> base64 = characters.AsSpan()[fields.Base64Data];
            decoded = new byte[checked(base64.Length * 3 / 4 + 3)];
            if (!Convert.TryFromBase64Chars(base64, decoded, out int written))
            {
                throw new CryptographicException("ed25519-openssh-private-key-base64-invalid");
            }

            byte[] blob = decoded.AsSpan(0, written).ToArray();
            try
            {
                var parsed = OpenSshPrivateKeyUtilities.ParsePrivateKeyBlob(blob);
                if (parsed is not Ed25519PrivateKeyParameters privateKey)
                {
                    throw new CryptographicException("ed25519-openssh-private-key-algorithm-invalid");
                }

                seed = privateKey.GetEncoded();
                return new Ed25519Identity(seed, takeOwnership: true);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(blob);
            }
        }
        catch (CryptographicException)
        {
            if (seed is not null)
            {
                CryptographicOperations.ZeroMemory(seed);
            }

            throw;
        }
        catch (Exception)
        {
            if (seed is not null)
            {
                CryptographicOperations.ZeroMemory(seed);
            }

            throw new CryptographicException("ed25519-openssh-private-key-invalid");
        }
        finally
        {
            characters.AsSpan().Clear();
            if (decoded is not null)
            {
                CryptographicOperations.ZeroMemory(decoded);
            }
        }
    }

    /// <summary>
    /// Explicitly exports PKCS#8 for immediate transfer to protected storage.
    /// </summary>
    public byte[] ExportPkcs8PrivateKey()
    {
        byte[] seed = CopyPrivateSeed();
        try
        {
            var privateKey = new Ed25519PrivateKeyParameters(seed, 0);
            return PrivateKeyInfoFactory.CreatePrivateKeyInfo(privateKey).GetDerEncoded();
        }
        finally
        {
            CryptographicOperations.ZeroMemory(seed);
        }
    }

    /// <summary>
    /// Explicitly exports an unencrypted OpenSSH private-key PEM for immediate
    /// write to a user-only ACL. The returned buffer must be cleared by the caller.
    /// </summary>
    public byte[] ExportOpenSshPrivateKeyPem()
    {
        byte[] seed = CopyPrivateSeed();
        byte[]? blob = null;
        char[]? pem = null;
        try
        {
            var privateKey = new Ed25519PrivateKeyParameters(seed, 0);
            blob = OpenSshPrivateKeyUtilities.EncodePrivateKey(privateKey);
            pem = new char[PemEncoding.GetEncodedSize(OpenSshPrivateKeyLabel.Length, blob.Length)];
            if (!PemEncoding.TryWrite(OpenSshPrivateKeyLabel, blob, pem, out int charsWritten))
            {
                throw new CryptographicException("ed25519-openssh-private-key-pem-export-failed");
            }

            byte[] output = new byte[Encoding.ASCII.GetByteCount(pem.AsSpan(0, charsWritten))];
            _ = Encoding.ASCII.GetBytes(pem.AsSpan(0, charsWritten), output);
            return output;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(seed);
            if (blob is not null)
            {
                CryptographicOperations.ZeroMemory(blob);
            }

            pem?.AsSpan().Clear();
        }
    }

    /// <summary>Returns a copy of the parameter-free RFC 8410 public SPKI.</summary>
    public byte[] ExportSubjectPublicKeyInfo() => subjectPublicKeyInfo.ToArray();

    /// <summary>Returns the public key as a PEM PUBLIC KEY block.</summary>
    public string ExportSubjectPublicKeyInfoPem() =>
        Ed25519KeyEncoding.EncodePublicKeyPem(subjectPublicKeyInfo);

    /// <summary>Returns the public key in the OpenSSH authorized_keys format.</summary>
    public string ExportOpenSshPublicKey(string? comment = null) =>
        OpenSshEd25519PublicKey.Encode(subjectPublicKeyInfo, comment);

    public ValueTask<byte[]> SignAsync(
        ReadOnlyMemory<byte> message,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        byte[] seed = CopyPrivateSeed();
        byte[] input = message.ToArray();
        try
        {
            var signer = new Ed25519Signer();
            signer.Init(forSigning: true, new Ed25519PrivateKeyParameters(seed, 0));
            signer.BlockUpdate(input, 0, input.Length);
            byte[] signature = signer.GenerateSignature();
            if (signature.Length != Ed25519KeyEncoding.SignatureLength)
            {
                CryptographicOperations.ZeroMemory(signature);
                throw new CryptographicException("ed25519-signature-length-invalid");
            }

            cancellationToken.ThrowIfCancellationRequested();
            return ValueTask.FromResult(signature);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(seed);
        }
    }

    public ValueTask<bool> VerifyAsync(
        ReadOnlyMemory<byte> subjectPublicKeyInfo,
        ReadOnlyMemory<byte> message,
        ReadOnlyMemory<byte> signature,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (signature.Length != Ed25519KeyEncoding.SignatureLength)
        {
            return ValueTask.FromResult(false);
        }

        byte[] normalized = Ed25519KeyEncoding.NormalizeSubjectPublicKeyInfo(
            subjectPublicKeyInfo.Span);
        byte[] input = message.ToArray();
        byte[] signatureCopy = signature.ToArray();
        try
        {
            var publicKey = PublicKeyFactory.CreateKey(normalized);
            if (publicKey is not Ed25519PublicKeyParameters ed25519PublicKey)
            {
                return ValueTask.FromResult(false);
            }

            var verifier = new Ed25519Signer();
            verifier.Init(forSigning: false, ed25519PublicKey);
            verifier.BlockUpdate(input, 0, input.Length);
            bool valid = verifier.VerifySignature(signatureCopy);
            cancellationToken.ThrowIfCancellationRequested();
            return ValueTask.FromResult(valid);
        }
        catch (ArgumentException)
        {
            return ValueTask.FromResult(false);
        }
    }

    public override string ToString() => $"Ed25519Identity({Fingerprint})";

    public void Dispose()
    {
        lock (gate)
        {
            if (privateSeed is null)
            {
                return;
            }

            CryptographicOperations.ZeroMemory(privateSeed);
            privateSeed = null;
        }

        GC.SuppressFinalize(this);
    }

    private byte[] CopyPrivateSeed()
    {
        lock (gate)
        {
            ObjectDisposedException.ThrowIf(privateSeed is null, this);
            return privateSeed.ToArray();
        }
    }
}
