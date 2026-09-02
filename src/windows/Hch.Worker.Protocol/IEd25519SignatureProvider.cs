namespace Hch.Worker.Protocol;

/// <summary>
/// Security boundary for raw Ed25519 signing and verification.
/// </summary>
/// <remarks>
/// .NET 10 does not expose a general-purpose raw Ed25519 signature API in its
/// base class library. The protocol assembly therefore does not embed a
/// private-key implementation or introduce an unaudited crypto dependency.
/// The Windows service must supply a separately reviewed provider backed by
/// the machine-protected worker identity. Implementations must return and
/// accept 64-byte RFC 8032 signatures and must never export the private key.
/// </remarks>
public interface IEd25519SignatureProvider
{
    /// <summary>Signs a message with the provider-bound worker identity.</summary>
    ValueTask<byte[]> SignAsync(
        ReadOnlyMemory<byte> message,
        CancellationToken cancellationToken = default);

    /// <summary>Verifies a message using a validated RFC 8410 public SPKI.</summary>
    ValueTask<bool> VerifyAsync(
        ReadOnlyMemory<byte> subjectPublicKeyInfo,
        ReadOnlyMemory<byte> message,
        ReadOnlyMemory<byte> signature,
        CancellationToken cancellationToken = default);
}
