using System.Collections.ObjectModel;
using System.Globalization;
using System.Text;
using System.Text.RegularExpressions;

namespace Hch.Worker.Protocol;

/// <summary>The fixed HCH HTTP Message Signatures profile.</summary>
public static partial class HchHttpMessageSignatures
{
    public const string SignatureLabel = "hch";
    public const string SignatureTag = "hch-editorial-worker-request/v1";

    public static IReadOnlyList<string> CoveredComponents { get; } = Array.AsReadOnly(
    [
        "@method",
        "@authority",
        "@path",
        "content-digest",
        "content-type",
        "x-hch-node-id",
        "x-hch-key-id",
        "x-hch-request-id",
        "x-hch-created",
        "x-hch-expires",
        "x-hch-nonce",
    ]);

    /// <summary>Normalizes a request and produces all bytes covered by Ed25519.</summary>
    public static HchHttpSignatureMaterial CreateSignatureMaterial(HchHttpSignatureRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (request.Created < 0 || request.Expires < 0
            || request.Created > ProtocolTime.JavaScriptMaximumSafeInteger
            || request.Expires > ProtocolTime.JavaScriptMaximumSafeInteger
            || request.Expires <= request.Created)
        {
            throw new ProtocolValidationException(
                "signature-window-invalid",
                "expires must be greater than created and both must be non-negative Unix seconds.");
        }

        var method = NormalizeMethod(request.Method);
        var authority = NormalizeAuthority(request.Authority);
        var path = NormalizePath(request.Path);
        var contentType = NormalizeHeaderValue(request.ContentType, "contentType", 256);
        var nodeId = RequiredIdentifier(request.NodeId, "nodeId", 128);
        var keyId = RequiredIdentifier(request.KeyId, "keyId", 256);
        var requestId = RequiredIdentifier(request.RequestId, "requestId", 128, 8);
        var nonce = RequiredIdentifier(request.Nonce, "nonce", 256, 16);
        var contentDigest = HchDigest.CreateContentDigest(request.Body.Span);
        var signatureParameters = CreateSignatureParameters(request.Created, request.Expires, keyId);

        var values = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["@authority"] = authority,
            ["@method"] = method,
            ["@path"] = path,
            ["content-digest"] = contentDigest,
            ["content-type"] = contentType,
            ["x-hch-created"] = request.Created.ToString(CultureInfo.InvariantCulture),
            ["x-hch-expires"] = request.Expires.ToString(CultureInfo.InvariantCulture),
            ["x-hch-key-id"] = keyId,
            ["x-hch-node-id"] = nodeId,
            ["x-hch-nonce"] = nonce,
            ["x-hch-request-id"] = requestId,
        };
        var lines = CoveredComponents.Select(component => $"\"{component}\": {values[component]}")
            .Append($"\"@signature-params\": {signatureParameters}");
        var signatureBase = string.Join('\n', lines);

        return new HchHttpSignatureMaterial(
            method,
            authority,
            path,
            contentType,
            nodeId,
            keyId,
            requestId,
            request.Created,
            request.Expires,
            nonce,
            contentDigest,
            signatureParameters,
            signatureBase);
    }

    /// <summary>Signs and returns the exact request headers used by HCH.</summary>
    public static async ValueTask<HchSignedHttpRequest> SignAsync(
        HchHttpSignatureRequest request,
        IEd25519SignatureProvider provider,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(provider);
        var material = CreateSignatureMaterial(request);
        var signature = await provider.SignAsync(
            Encoding.UTF8.GetBytes(material.SignatureBase),
            cancellationToken).ConfigureAwait(false);
        ValidateSignature(signature);
        return new HchSignedHttpRequest(material, CreateHeaders(material, signature));
    }

    /// <summary>Creates protocol headers after a provider has produced the raw signature.</summary>
    public static IReadOnlyDictionary<string, string> CreateHeaders(
        HchHttpSignatureMaterial material,
        ReadOnlySpan<byte> signature)
    {
        ArgumentNullException.ThrowIfNull(material);
        ValidateSignature(signature);
        return new ReadOnlyDictionary<string, string>(new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["Content-Digest"] = material.ContentDigest,
            ["Content-Type"] = material.ContentType,
            ["Signature-Input"] = $"{SignatureLabel}={material.SignatureParameters}",
            ["Signature"] = $"{SignatureLabel}=:{Convert.ToBase64String(signature)}:",
            ["X-HCH-Created"] = material.Created.ToString(CultureInfo.InvariantCulture),
            ["X-HCH-Expires"] = material.Expires.ToString(CultureInfo.InvariantCulture),
            ["X-HCH-Key-Id"] = material.KeyId,
            ["X-HCH-Node-Id"] = material.NodeId,
            ["X-HCH-Nonce"] = material.Nonce,
            ["X-HCH-Request-Id"] = material.RequestId,
        });
    }

    /// <summary>
    /// Verifies the fixed profile against actual HTTP routing data and body.
    /// Replay-token consumption remains the orchestrator caller's responsibility.
    /// </summary>
    public static async ValueTask<bool> VerifyAsync(
        HchHttpSignatureRequest request,
        IReadOnlyDictionary<string, string> receivedHeaders,
        ReadOnlyMemory<byte> subjectPublicKeyInfo,
        IEd25519SignatureProvider provider,
        DateTimeOffset now,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(receivedHeaders);
        ArgumentNullException.ThrowIfNull(provider);
        var material = CreateSignatureMaterial(request);
        ProtocolTime.ValidateUnixWindow(material.Created, material.Expires, now);

        RequireHeader(receivedHeaders, "content-digest", material.ContentDigest);
        RequireHeader(receivedHeaders, "content-type", material.ContentType);
        RequireHeader(receivedHeaders, "x-hch-node-id", material.NodeId);
        RequireHeader(receivedHeaders, "x-hch-key-id", material.KeyId);
        RequireHeader(receivedHeaders, "x-hch-request-id", material.RequestId);
        RequireHeader(receivedHeaders, "x-hch-created", material.Created.ToString(CultureInfo.InvariantCulture));
        RequireHeader(receivedHeaders, "x-hch-expires", material.Expires.ToString(CultureInfo.InvariantCulture));
        RequireHeader(receivedHeaders, "x-hch-nonce", material.Nonce);
        RequireHeader(receivedHeaders, "signature-input", $"{SignatureLabel}={material.SignatureParameters}");

        var signature = ParseSignatureHeader(GetHeader(receivedHeaders, "signature"));
        var spki = Ed25519KeyEncoding.NormalizeSubjectPublicKeyInfo(subjectPublicKeyInfo.Span);
        return await provider.VerifyAsync(
            spki,
            Encoding.UTF8.GetBytes(material.SignatureBase),
            signature,
            cancellationToken).ConfigureAwait(false);
    }

    public static byte[] ParseSignatureHeader(string value)
    {
        var normalized = NormalizeHeaderValue(value, "Signature", 512);
        var match = SignaturePattern().Match(normalized);
        if (!match.Success)
        {
            throw new ProtocolValidationException("signature-header-malformed", "Malformed HCH Signature header.");
        }

        byte[] signature;
        try
        {
            signature = Convert.FromBase64String(match.Groups[1].Value);
        }
        catch (FormatException error)
        {
            throw new ProtocolValidationException("signature-header-malformed", "Malformed HCH Signature header.")
            {
                Data = { ["cause"] = error.GetType().FullName },
            };
        }

        ValidateSignature(signature);
        return signature;
    }

    private static string CreateSignatureParameters(long created, long expires, string keyId)
    {
        var covered = string.Join(' ', CoveredComponents.Select(component => $"\"{component}\""));
        return $"({covered});created={created.ToString(CultureInfo.InvariantCulture)};expires={expires.ToString(CultureInfo.InvariantCulture)};keyid={StructuredFieldString(keyId)};alg=\"ed25519\";tag=\"{SignatureTag}\"";
    }

    private static string NormalizeMethod(string value)
    {
        var method = RequiredIdentifier(value, "method", 32).ToUpperInvariant();
        if (!HttpMethodPattern().IsMatch(method))
        {
            throw new ProtocolValidationException("http-method-invalid", "Invalid HTTP method.");
        }

        return method;
    }

    private static string NormalizeAuthority(string value)
    {
        var authority = RequiredIdentifier(value, "authority", 255).ToLowerInvariant();
        if (authority.Any(character =>
                character is '/' or '\\' or '?' or '#' or '@'
                || char.IsWhiteSpace(character)
                || char.IsControl(character)))
        {
            throw new ProtocolValidationException("http-authority-invalid", "Invalid HTTP authority.");
        }

        return authority;
    }

    private static string NormalizePath(string value)
    {
        var path = RequiredIdentifier(value, "path", 2048);
        if (!path.StartsWith('/') || path.IndexOfAny(['?', '#', '\r', '\n']) >= 0)
        {
            throw new ProtocolValidationException(
                "http-path-invalid",
                "The signed path must be an absolute path without a query or fragment.");
        }

        return path;
    }

    private static string NormalizeHeaderValue(string value, string name, int maximum)
    {
        ArgumentNullException.ThrowIfNull(value);
        if (value.Length > maximum || value.IndexOfAny(['\r', '\n', '\0']) >= 0)
        {
            throw new ProtocolValidationException("http-header-invalid", $"{name} contains invalid characters.");
        }

        var normalized = LinearWhitespacePattern().Replace(value.Trim(), " ");
        if (normalized.Length == 0)
        {
            throw new ProtocolValidationException("http-header-empty", $"{name} must not be empty.");
        }

        return normalized;
    }

    private static string RequiredIdentifier(string value, string name, int maximum, int minimum = 1)
    {
        ArgumentNullException.ThrowIfNull(value);
        var normalized = value.Trim();
        if (normalized.Length < minimum || normalized.Length > maximum
            || normalized.Any(character => character <= ' ' || character == '\x7f' || char.IsSurrogate(character)))
        {
            throw new ProtocolValidationException(
                "identifier-invalid",
                $"{name} has an invalid length or contains whitespace/control characters.");
        }

        return normalized;
    }

    private static string StructuredFieldString(string value)
    {
        if (value.Any(character => character is < ' ' or > '~'))
        {
            throw new ProtocolValidationException(
                "signature-key-id-invalid",
                "HTTP Signature keyId must contain printable ASCII only.");
        }

        return $"\"{value.Replace("\\", "\\\\", StringComparison.Ordinal).Replace("\"", "\\\"", StringComparison.Ordinal)}\"";
    }

    private static void ValidateSignature(ReadOnlySpan<byte> signature)
    {
        if (signature.Length != Ed25519KeyEncoding.SignatureLength)
        {
            throw new ProtocolValidationException(
                "ed25519-signature-length-invalid",
                "An Ed25519 signature must contain exactly 64 bytes.");
        }
    }

    private static string GetHeader(IReadOnlyDictionary<string, string> headers, string name)
    {
        var matches = headers.Where(pair => pair.Key.Equals(name, StringComparison.OrdinalIgnoreCase)).ToArray();
        if (matches.Length != 1 || string.IsNullOrWhiteSpace(matches[0].Value))
        {
            throw new ProtocolValidationException("http-header-missing", $"Missing or ambiguous {name} header.");
        }

        return NormalizeHeaderValue(matches[0].Value, name, 2048);
    }

    private static void RequireHeader(IReadOnlyDictionary<string, string> headers, string name, string expected)
    {
        var supplied = GetHeader(headers, name);
        if (!supplied.Equals(expected, StringComparison.Ordinal))
        {
            throw new ProtocolValidationException(
                name.Equals("content-digest", StringComparison.Ordinal) ? "content-digest-mismatch" : "signature-input-mismatch",
                $"The {name} header does not match the required HCH profile.");
        }
    }

    [GeneratedRegex("^[A-Z!#$%&'*+.^_`|~-]+$", RegexOptions.CultureInvariant)]
    private static partial Regex HttpMethodPattern();

    [GeneratedRegex("[ \\t]+", RegexOptions.CultureInvariant)]
    private static partial Regex LinearWhitespacePattern();

    [GeneratedRegex("^hch=:([A-Za-z0-9+/]+={0,2}):$", RegexOptions.CultureInvariant)]
    private static partial Regex SignaturePattern();
}

public sealed record HchHttpSignatureRequest(
    string Method,
    string Authority,
    string Path,
    string ContentType,
    ReadOnlyMemory<byte> Body,
    string NodeId,
    string KeyId,
    string RequestId,
    long Created,
    long Expires,
    string Nonce);

public sealed record HchHttpSignatureMaterial(
    string Method,
    string Authority,
    string Path,
    string ContentType,
    string NodeId,
    string KeyId,
    string RequestId,
    long Created,
    long Expires,
    string Nonce,
    string ContentDigest,
    string SignatureParameters,
    string SignatureBase);

public sealed record HchSignedHttpRequest(
    HchHttpSignatureMaterial Material,
    IReadOnlyDictionary<string, string> Headers);
