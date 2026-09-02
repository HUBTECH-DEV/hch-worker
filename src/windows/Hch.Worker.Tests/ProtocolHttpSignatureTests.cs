using System.Text;
using Hch.Worker.Protocol;

namespace Hch.Worker.Tests;

public sealed class ProtocolHttpSignatureTests
{
    private static readonly HchHttpSignatureRequest GoldenRequest = new(
        Method: "post",
        Authority: "HUBTECH.ONLINE",
        Path: "/api/editorial/orchestrator/claim",
        ContentType: " application/json ",
        Body: Encoding.UTF8.GetBytes("{}"),
        NodeId: "windows-worker-01",
        KeyId: "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        RequestId: "0123456789abcdef0123456789abcdef",
        Created: 1_800_000_000,
        Expires: 1_800_000_120,
        Nonce: "01234567-89ab-cdef-0123-456789abcdef");

    [Fact]
    public void MatchesRepositoryGoldenSignatureBaseAndHeaders()
    {
        var material = HchHttpMessageSignatures.CreateSignatureMaterial(GoldenRequest);
        const string expectedParameters = "(\"@method\" \"@authority\" \"@path\" \"content-digest\" \"content-type\" \"x-hch-node-id\" \"x-hch-key-id\" \"x-hch-request-id\" \"x-hch-created\" \"x-hch-expires\" \"x-hch-nonce\");created=1800000000;expires=1800000120;keyid=\"SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\";alg=\"ed25519\";tag=\"hch-editorial-worker-request/v1\"";
        var expectedBase = string.Join('\n',
            "\"@method\": POST",
            "\"@authority\": hubtech.online",
            "\"@path\": /api/editorial/orchestrator/claim",
            "\"content-digest\": sha-256=:RBNvo1WzZ4oRRq0W9+hknpT7T8If536DEMBg9hyq/4o=:",
            "\"content-type\": application/json",
            "\"x-hch-node-id\": windows-worker-01",
            "\"x-hch-key-id\": SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "\"x-hch-request-id\": 0123456789abcdef0123456789abcdef",
            "\"x-hch-created\": 1800000000",
            "\"x-hch-expires\": 1800000120",
            "\"x-hch-nonce\": 01234567-89ab-cdef-0123-456789abcdef",
            $"\"@signature-params\": {expectedParameters}");

        Assert.Equal(expectedParameters, material.SignatureParameters);
        Assert.Equal(expectedBase, material.SignatureBase);

        var signature = Enumerable.Range(0, 64).Select(index => (byte)index).ToArray();
        var headers = HchHttpMessageSignatures.CreateHeaders(material, signature);
        Assert.Equal($"hch={expectedParameters}", headers["Signature-Input"]);
        Assert.Equal($"hch=:{Convert.ToBase64String(signature)}:", headers["Signature"]);
        Assert.Equal(signature, HchHttpMessageSignatures.ParseSignatureHeader(headers["Signature"]));
    }

    [Fact]
    public async Task UsesTheReviewedProviderBoundaryWithoutPrivateKeyMaterial()
    {
        var provider = new TestProvider();
        var signed = await HchHttpMessageSignatures.SignAsync(GoldenRequest, provider);
        var spki = Ed25519KeyEncoding.CreateSubjectPublicKeyInfo(new byte[32]);

        var valid = await HchHttpMessageSignatures.VerifyAsync(
            GoldenRequest,
            signed.Headers,
            spki,
            provider,
            DateTimeOffset.FromUnixTimeSeconds(1_800_000_010));

        Assert.True(valid);
        Assert.NotEmpty(provider.LastMessage);
        Assert.Equal(signed.Material.SignatureBase, Encoding.UTF8.GetString(provider.LastMessage));
    }

    [Theory]
    [InlineData("GET", "bad host/name", "/ok")]
    [InlineData("GET", "hubtech.online", "/ok?query=1")]
    [InlineData("GET\r\nInjected", "hubtech.online", "/ok")]
    public void RejectsAmbiguousRoutingInputs(string method, string authority, string path)
    {
        var request = GoldenRequest with { Method = method, Authority = authority, Path = path };
        Assert.Throws<ProtocolValidationException>(() => HchHttpMessageSignatures.CreateSignatureMaterial(request));
    }

    [Fact]
    public void RejectsWrongSignatureLengthAndExpiredWindows()
    {
        Assert.Throws<ProtocolValidationException>(() =>
            HchHttpMessageSignatures.CreateHeaders(
                HchHttpMessageSignatures.CreateSignatureMaterial(GoldenRequest),
                new byte[63]));
        Assert.Equal(
            "expired",
            Assert.Throws<ProtocolValidationException>(() =>
                ProtocolTime.ValidateUnixWindow(
                    GoldenRequest.Created,
                    GoldenRequest.Expires,
                    DateTimeOffset.FromUnixTimeSeconds(GoldenRequest.Expires + 31))).Code);
        Assert.Equal(
            "signature-time-invalid",
            Assert.Throws<ProtocolValidationException>(() =>
                ProtocolTime.ValidateUnixWindow(
                    ProtocolTime.JavaScriptMaximumSafeInteger + 1,
                    ProtocolTime.JavaScriptMaximumSafeInteger + 2,
                    DateTimeOffset.UnixEpoch)).Code);
    }

    private sealed class TestProvider : IEd25519SignatureProvider
    {
        public byte[] LastMessage { get; private set; } = [];

        public ValueTask<byte[]> SignAsync(ReadOnlyMemory<byte> message, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            LastMessage = message.ToArray();
            var signature = new byte[64];
            for (var index = 0; index < signature.Length; index++)
            {
                signature[index] = (byte)(LastMessage[index % LastMessage.Length] ^ index);
            }

            return ValueTask.FromResult(signature);
        }

        public ValueTask<bool> VerifyAsync(
            ReadOnlyMemory<byte> subjectPublicKeyInfo,
            ReadOnlyMemory<byte> message,
            ReadOnlyMemory<byte> signature,
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Assert.Equal(44, subjectPublicKeyInfo.Length);
            var expected = SignAsync(message, cancellationToken).Result;
            return ValueTask.FromResult(signature.Span.SequenceEqual(expected));
        }
    }
}
