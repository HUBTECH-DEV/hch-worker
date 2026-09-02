using System.Text;
using Hch.Worker.Protocol;

namespace Hch.Worker.Tests;

public sealed class ProtocolCryptographyTests
{
    [Fact]
    public void ProducesRepositoryGoldenSha256AndContentDigest()
    {
        var body = Encoding.UTF8.GetBytes("{}");

        Assert.Equal(
            "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a",
            HchDigest.Sha256Hex(body));
        Assert.Equal(
            "sha-256=:RBNvo1WzZ4oRRq0W9+hknpT7T8If536DEMBg9hyq/4o=:",
            HchDigest.CreateContentDigest(body));
        Assert.True(HchDigest.MatchesContentDigest(HchDigest.CreateContentDigest(body), body));
        Assert.False(HchDigest.MatchesContentDigest("sha-256=:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=:", body));
    }

    [Fact]
    public void ProducesSpkiFingerprintOverTheCompleteRfc8410Value()
    {
        var raw = new byte[Ed25519KeyEncoding.RawPublicKeyLength];
        var spki = Ed25519KeyEncoding.CreateSubjectPublicKeyInfo(raw);

        Assert.Equal(44, spki.Length);
        Assert.Equal("302a300506032b6570032100", Convert.ToHexStringLower(spki.AsSpan(0, 12)));
        Assert.Equal("SHA256:ciq9EumaU2fzda65ZyqOB3EuA8Kt0W-o1pFNHPou_gw", Ed25519KeyEncoding.Fingerprint(spki));
        Assert.Equal(raw, Ed25519KeyEncoding.GetRawPublicKey(spki));

        var pem = Ed25519KeyEncoding.EncodePublicKeyPem(spki);
        Assert.Equal(spki, Ed25519KeyEncoding.DecodePublicKeyPem(pem));
    }

    [Fact]
    public void RejectsSpkiWithAlgorithmParametersOrWrongLength()
    {
        var valid = Ed25519KeyEncoding.CreateSubjectPublicKeyInfo(new byte[32]);
        valid[9] = 0x05;

        Assert.Equal(
            "ed25519-spki-invalid",
            Assert.Throws<ProtocolValidationException>(() => Ed25519KeyEncoding.Fingerprint(valid)).Code);
        Assert.Throws<ProtocolValidationException>(() => Ed25519KeyEncoding.CreateSubjectPublicKeyInfo(new byte[31]));
    }
}
