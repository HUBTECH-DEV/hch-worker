using System.Text;
using Hch.Worker.Protocol;

namespace Hch.Worker.Tests;

public sealed class ProtocolJcsTests
{
    [Fact]
    public void CanonicalizesRfc8785LiteralAndNumberVector()
    {
        const string input = """
            {
              "numbers": [333333333.33333329, 1E30, 4.50, 2e-3, 0.000000000000000000000000001],
              "string": "€$\u000f\nA'B\"\\\"/",
              "literals": [null, true, false]
            }
            """;
        const string expected = "{\"literals\":[null,true,false],\"numbers\":[333333333.3333333,1e+30,4.5,0.002,1e-27],\"string\":\"€$\\u000f\\nA'B\\\"\\\\\\\"/\"}";

        Assert.Equal(expected, JcsCanonicalizer.Canonicalize(input));
    }

    [Fact]
    public void OrdersObjectNamesByUtf16CodeUnits()
    {
        const string input = "{\"€\":5,\"\\r\":1,\"דּ\":7,\"1\":2,\"😀\":6,\"\\u0080\":3,\"ö\":4}";
        const string expected = "{\"\\r\":1,\"1\":2,\"\":3,\"ö\":4,\"€\":5,\"😀\":6,\"דּ\":7}";

        Assert.Equal(expected, JcsCanonicalizer.Canonicalize(input));
    }

    [Theory]
    [InlineData("{\"a\":1,\"a\":2}", "jcs-duplicate-property")]
    [InlineData("{\"a\":1,\"\\u0061\":2}", "jcs-duplicate-property")]
    [InlineData("1e400", "jcs-non-finite-number")]
    [InlineData("\"\\ud800\"", "jcs-unpaired-surrogate")]
    [InlineData("\"\\udc00\"", "jcs-unpaired-surrogate")]
    public void RejectsValuesOutsideTheIJsonSubset(string json, string code)
    {
        var error = Assert.Throws<ProtocolValidationException>(() => JcsCanonicalizer.Canonicalize(json));
        Assert.Equal(code, error.Code);
    }

    [Fact]
    public void RejectsInvalidUtf8()
    {
        var invalid = new byte[] { (byte)'"', 0xc3, 0x28, (byte)'"' };
        var error = Assert.Throws<ProtocolValidationException>(() => JcsCanonicalizer.CanonicalizeToUtf8(invalid));
        Assert.Contains(error.Code, new[] { "jcs-invalid-json", "jcs-invalid-utf8" });
    }

    [Fact]
    public void RejectsAnActualUnpairedUtf16SurrogateBeforeEncoding()
    {
        var malformed = "\"" + '\ud800' + "\"";
        var error = Assert.Throws<ProtocolValidationException>(() => JcsCanonicalizer.Canonicalize(malformed));
        Assert.Equal("jcs-unpaired-surrogate", error.Code);
    }

    [Theory]
    [InlineData("-0", "0")]
    [InlineData("1e20", "100000000000000000000")]
    [InlineData("1e21", "1e+21")]
    [InlineData("1e-6", "0.000001")]
    [InlineData("1e-7", "1e-7")]
    [InlineData("5e-324", "5e-324")]
    [InlineData("-5e-324", "-5e-324")]
    [InlineData("1.7976931348623157e308", "1.7976931348623157e+308")]
    [InlineData("295147905179352825856", "295147905179352830000")]
    [InlineData("9.999999999999997e22", "9.999999999999997e+22")]
    [InlineData("1e23", "1e+23")]
    [InlineData("1.0000000000000001e23", "1.0000000000000001e+23")]
    [InlineData("999999999999999700000", "999999999999999700000")]
    [InlineData("999999999999999900000", "999999999999999900000")]
    [InlineData("333333333.3333332", "333333333.3333332")]
    [InlineData("333333333.33333325", "333333333.33333325")]
    [InlineData("-0.0000033333333333333333", "-0.0000033333333333333333")]
    public void UsesEcmaScriptBinary64Formatting(string input, string expected)
    {
        Assert.Equal(expected, JcsCanonicalizer.Canonicalize(input));
        Assert.True(JcsCanonicalizer.IsCanonical(Encoding.UTF8.GetBytes(expected)));
    }
}
