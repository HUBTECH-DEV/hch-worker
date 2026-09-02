using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Hch.Worker.Protocol;
using Hch.Worker.Security;

namespace Hch.Worker.Persistence;

internal sealed record LegacyConfigurationProjection(
    string NodeId,
    Uri OrchestratorBaseUri,
    Uri OllamaBaseUri,
    int RequestedCapacity,
    int LocalParallelismLimit,
    string RootPublicKeyPath,
    string StateRoot,
    string InstallRoot);

internal sealed record LegacyControlProjection(
    int LastNonZeroMaxConcurrentJobs,
    int ClaimBatchSize);

internal sealed record LegacyRootTrustProjection(
    string RootKeyId,
    string RootPublicKeyFingerprint,
    string PublicKeyPem);

internal sealed record MigratedWorkerConfiguration(
    int SchemaVersion,
    string NodeId,
    string WorkerName,
    string KeyId,
    string OwnerSid,
    string RootKeyId,
    string RootPublicKeyFingerprint,
    string RootPublicKeyPath,
    Uri OrchestratorBaseUri,
    Uri OllamaBaseUri,
    int LastNonZeroMaxConcurrentJobs,
    int ClaimBatchSize,
    int ManifestCapacityLimit,
    int LocalResourceLimit,
    string StateRoot);

internal static partial class LegacyWindowsMigrationParsing
{
    private const int MaximumConfigurationBytes = 1024 * 1024;
    private const int MaximumJsonBytes = 4 * 1024 * 1024;
    private const int MaximumPrivateKeyBytes = 16 * 1024;
    private const int MaximumPublicKeyBytes = 64 * 1024;

    private static readonly UTF8Encoding StrictUtf8 = new(false, true);

    public static async Task<LegacyConfigurationProjection> ReadConfigurationAsync(
        string legacyProductRoot,
        CancellationToken cancellationToken)
    {
        string configurationPath = Resolve(
            legacyProductRoot,
            LegacyWindowsWorkerPaths.ConfigurationRelativePath);
        byte[] bytes = await ReadBoundedAsync(
            configurationPath,
            MaximumConfigurationBytes,
            cancellationToken).ConfigureAwait(false);
        try
        {
            string text;
            try
            {
                text = StrictUtf8.GetString(bytes);
            }
            catch (DecoderFallbackException)
            {
                throw Fail("legacy-config-encoding-invalid");
            }

            ValidateUniqueAssignments(text);
            Dictionary<string, string> strings = ParseStringAssignments(text);
            Dictionary<string, int> integers = ParseIntegerAssignments(text);
            if (RequiredInteger(integers, "SchemaVersion") != 2)
            {
                throw Fail("legacy-config-schema-unsupported");
            }

            string nodeId = RequiredString(strings, "NodeId");
            if (!NodeIdPattern().IsMatch(nodeId))
            {
                throw Fail("legacy-node-id-invalid");
            }

            string productRoot = Path.GetFullPath(legacyProductRoot);
            string stateRoot = ValidateExpectedPath(
                RequiredString(strings, "StateRoot"),
                Path.Combine(productRoot, "state"),
                "legacy-state-root-mismatch");
            string installRoot = ValidateExpectedPath(
                RequiredString(strings, "InstallRoot"),
                Path.Combine(productRoot, "runtime"),
                "legacy-install-root-mismatch");
            string rootPublicKeyPath = ValidateExpectedPath(
                RequiredString(strings, "RootPublicKeyPath"),
                Path.Combine(productRoot, "trust", "orchestrator-root.pem"),
                "legacy-root-key-path-mismatch");

            int localLimit = OptionalInteger(integers, "LocalParallelismLimit", 8);
            int requested = OptionalInteger(integers, "RequestedCapacity", 1);
            if (localLimit is < 1 or > 64 || requested is < 1 or > 64 || requested > localLimit)
            {
                throw Fail("legacy-capacity-invalid");
            }

            Uri orchestrator = ValidateOrigin(
                RequiredString(strings, "ControlPlaneBaseUri"),
                requireHttps: true,
                requireLoopback: false,
                "legacy-orchestrator-origin-invalid");
            Uri ollama = ValidateOrigin(
                strings.TryGetValue("OllamaBaseUri", out string? ollamaValue)
                    ? ollamaValue
                    : "http://127.0.0.1:11434",
                requireHttps: false,
                requireLoopback: true,
                "legacy-ollama-origin-invalid");

            return new LegacyConfigurationProjection(
                nodeId,
                orchestrator,
                ollama,
                requested,
                localLimit,
                rootPublicKeyPath,
                stateRoot,
                installRoot);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(bytes);
        }
    }

    public static async Task<LegacyControlProjection> ReadControlAsync(
        string legacyProductRoot,
        LegacyConfigurationProjection configuration,
        CancellationToken cancellationToken)
    {
        string path = Resolve(legacyProductRoot, "state/worker-control.json");
        if (!File.Exists(path))
        {
            return new LegacyControlProjection(
                configuration.RequestedCapacity,
                configuration.RequestedCapacity);
        }

        LegacyWorkerControl control = await ReadJsonAsync<LegacyWorkerControl>(
            path,
            cancellationToken).ConfigureAwait(false);
        if (control.Schema != "hch.worker-control/v1"
            || control.SchemaVersion != 1
            || control.NodeId != configuration.NodeId
            || control.RequestedParallelism is < 0 or > 64
            || control.LastNonZeroParallelism is < 1 or > 64
            || control.RequestedParallelism > configuration.LocalParallelismLimit
            || control.LastNonZeroParallelism > configuration.LocalParallelismLimit
            || control.AcceptingClaims && (control.RequestedParallelism == 0 || control.DrainRequested)
            || string.IsNullOrWhiteSpace(control.UpdatedBy))
        {
            throw Fail("legacy-control-invalid");
        }

        // Version 3 used requestedParallelism as both concurrency and maximum
        // claim batch. V4 starts paused but preserves that last non-zero value
        // independently in both controls until the operator changes either one.
        return new LegacyControlProjection(
            control.LastNonZeroParallelism,
            control.LastNonZeroParallelism);
    }

    public static async Task<Ed25519Identity> ReadAndValidateIdentityAsync(
        string legacyProductRoot,
        LegacyConfigurationProjection configuration,
        CancellationToken cancellationToken)
    {
        string metadataPath = Resolve(
            legacyProductRoot,
            LegacyWindowsWorkerPaths.IdentityMetadataRelativePath);
        LegacyIdentityMetadata metadata = await ReadJsonAsync<LegacyIdentityMetadata>(
            metadataPath,
            cancellationToken).ConfigureAwait(false);
        string expectedPrivatePath = Resolve(
            legacyProductRoot,
            LegacyWindowsWorkerPaths.PrivateKeyRelativePath);
        string expectedPublicPath = Resolve(
            legacyProductRoot,
            LegacyWindowsWorkerPaths.PublicKeyRelativePath);
        string metadataKeyId = metadata.KeyId ?? string.Empty;
        if (metadata.SchemaVersion != 2
            || metadata.NodeId != configuration.NodeId
            || metadata.Algorithm != "Ed25519"
            || metadata.PrivateKeyFormat != "PKCS8-PEM"
            || metadata.PublicKeyFormat != "SPKI-PEM"
            || !FingerprintPattern().IsMatch(metadataKeyId)
            || !SamePath(metadata.PrivateKeyPath, expectedPrivatePath)
            || !SamePath(metadata.PublicKeyPath, expectedPublicPath)
            || !DateTimeOffset.TryParse(
                metadata.CreatedAt,
                CultureInfo.InvariantCulture,
                DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal,
                out _))
        {
            throw Fail("legacy-identity-metadata-invalid");
        }

        byte[] privatePem = await ReadBoundedAsync(
            expectedPrivatePath,
            MaximumPrivateKeyBytes,
            cancellationToken).ConfigureAwait(false);
        byte[] publicPemBytes = await ReadBoundedAsync(
            expectedPublicPath,
            MaximumPublicKeyBytes,
            cancellationToken).ConfigureAwait(false);
        byte[]? privateKeyInfo = null;
        byte[]? publicKeyInfo = null;
        Ed25519Identity? identity = null;
        try
        {
            privateKeyInfo = DecodeExactPem(privatePem, "PRIVATE KEY", MaximumPrivateKeyBytes);
            identity = Ed25519Identity.ImportPkcs8(privateKeyInfo);
            string publicPem;
            try
            {
                publicPem = StrictUtf8.GetString(publicPemBytes);
            }
            catch (DecoderFallbackException)
            {
                throw Fail("legacy-public-key-encoding-invalid");
            }

            publicKeyInfo = Ed25519KeyEncoding.DecodePublicKeyPem(publicPem);
            string publicFingerprint = Ed25519KeyEncoding.Fingerprint(publicKeyInfo);
            byte[] derivedPublicKey = identity.ExportSubjectPublicKeyInfo();
            try
            {
                if (!FixedTimeTextEquals(metadataKeyId, publicFingerprint)
                    || !FixedTimeTextEquals(identity.Fingerprint, publicFingerprint)
                    || derivedPublicKey.Length != publicKeyInfo.Length
                    || !CryptographicOperations.FixedTimeEquals(derivedPublicKey, publicKeyInfo))
                {
                    throw Fail("legacy-identity-keypair-mismatch");
                }
            }
            finally
            {
                CryptographicOperations.ZeroMemory(derivedPublicKey);
            }

            Ed25519Identity result = identity;
            identity = null;
            return result;
        }
        catch (LegacyMigrationException)
        {
            throw;
        }
        catch (Exception error) when (error is CryptographicException or ProtocolValidationException
            or FormatException or ArgumentException)
        {
            throw Fail("legacy-identity-cryptographic-validation-failed");
        }
        finally
        {
            identity?.Dispose();
            CryptographicOperations.ZeroMemory(privatePem);
            CryptographicOperations.ZeroMemory(publicPemBytes);
            if (privateKeyInfo is not null)
            {
                CryptographicOperations.ZeroMemory(privateKeyInfo);
            }

            if (publicKeyInfo is not null)
            {
                CryptographicOperations.ZeroMemory(publicKeyInfo);
            }
        }
    }

    public static async Task<LegacyRootTrustProjection> ReadRootTrustAsync(
        string legacyProductRoot,
        LegacyConfigurationProjection configuration,
        CancellationToken cancellationToken)
    {
        string trustPath = Resolve(
            legacyProductRoot,
            LegacyWindowsWorkerPaths.RootPublicKeyRelativePath);
        string statePath = Resolve(
            legacyProductRoot,
            LegacyWindowsWorkerPaths.TrustStateRelativePath);
        if (!SamePath(configuration.RootPublicKeyPath, trustPath)
            || !File.Exists(trustPath)
            || !File.Exists(statePath))
        {
            throw Fail("legacy-root-trust-incomplete");
        }

        byte[] trustState = await ReadBoundedAsync(
            statePath,
            MaximumJsonBytes,
            cancellationToken).ConfigureAwait(false);
        byte[] publicPemBytes = await ReadBoundedAsync(
            trustPath,
            MaximumPublicKeyBytes,
            cancellationToken).ConfigureAwait(false);
        byte[]? subjectPublicKeyInfo = null;
        byte[]? canonicalTrustState = null;
        try
        {
            canonicalTrustState = JcsCanonicalizer.CanonicalizeToUtf8(trustState);
            using JsonDocument document = ParseJson(canonicalTrustState, "legacy-trust-state-invalid");
            JsonElement root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object
                || RequiredJsonString(root, "schema", "legacy-trust-state-invalid") != "hch.worker-trust-state/v1"
                || !root.TryGetProperty("schemaVersion", out JsonElement version)
                || !version.TryGetInt32(out int schemaVersion)
                || schemaVersion != 1)
            {
                throw Fail("legacy-trust-state-invalid");
            }

            string rootKeyId = RequiredJsonString(root, "rootKeyId", "legacy-trust-state-invalid");
            string fingerprint = RequiredJsonString(root, "rootFingerprint", "legacy-trust-state-invalid");
            if (!KeyIdPattern().IsMatch(rootKeyId) || !FingerprintPattern().IsMatch(fingerprint))
            {
                throw Fail("legacy-trust-state-invalid");
            }

            string pem;
            try
            {
                pem = StrictUtf8.GetString(publicPemBytes);
            }
            catch (DecoderFallbackException)
            {
                throw Fail("legacy-root-key-encoding-invalid");
            }

            subjectPublicKeyInfo = Ed25519KeyEncoding.DecodePublicKeyPem(pem);
            string calculated = Ed25519KeyEncoding.Fingerprint(subjectPublicKeyInfo);
            if (!FixedTimeTextEquals(calculated, fingerprint))
            {
                throw Fail("legacy-root-key-fingerprint-mismatch");
            }

            return new LegacyRootTrustProjection(rootKeyId, calculated, pem.Trim() + Environment.NewLine);
        }
        catch (LegacyMigrationException)
        {
            throw;
        }
        catch (Exception error) when (error is JsonException or ProtocolValidationException
            or CryptographicException)
        {
            throw Fail("legacy-root-trust-invalid");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(trustState);
            CryptographicOperations.ZeroMemory(publicPemBytes);
            if (subjectPublicKeyInfo is not null)
            {
                CryptographicOperations.ZeroMemory(subjectPublicKeyInfo);
            }

            if (canonicalTrustState is not null)
            {
                CryptographicOperations.ZeroMemory(canonicalTrustState);
            }
        }
    }

    public static MigratedWorkerConfiguration ProjectTargetConfiguration(
        string targetProductRoot,
        string ownerSid,
        LegacyConfigurationProjection legacy,
        LegacyControlProjection control,
        LegacyRootTrustProjection trust,
        string keyId)
    {
        string stateRoot = Path.Combine(Path.GetFullPath(targetProductRoot), "state");
        string rootPath = Path.Combine(Path.GetFullPath(targetProductRoot), "trust", "orchestrator-root.pem");
        return new MigratedWorkerConfiguration(
            SchemaVersion: 1,
            legacy.NodeId,
            WorkerName: $"HCH Worker - {legacy.NodeId}",
            KeyId: keyId,
            OwnerSid: ownerSid,
            trust.RootKeyId,
            trust.RootPublicKeyFingerprint,
            RootPublicKeyPath: rootPath,
            legacy.OrchestratorBaseUri,
            legacy.OllamaBaseUri,
            control.LastNonZeroMaxConcurrentJobs,
            control.ClaimBatchSize,
            ManifestCapacityLimit: 64,
            LocalResourceLimit: legacy.LocalParallelismLimit,
            StateRoot: stateRoot);
    }

    public static string Resolve(string root, string relativePath)
    {
        string canonicalRoot = Path.GetFullPath(root);
        string path = Path.GetFullPath(Path.Combine(
            canonicalRoot,
            relativePath.Replace('/', Path.DirectorySeparatorChar)));
        string prefix = canonicalRoot.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar)
            + Path.DirectorySeparatorChar;
        if (!path.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
        {
            throw Fail("legacy-path-escape-refused");
        }

        return path;
    }

    private static Dictionary<string, string> ParseStringAssignments(string text)
    {
        var values = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (string line in text.Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries))
        {
            Match match = StringAssignment().Match(line);
            if (!match.Success)
            {
                continue;
            }

            string name = match.Groups["name"].Value;
            string value = match.Groups["value"].Value.Replace("''", "'", StringComparison.Ordinal);
            if (!values.TryAdd(name, value))
            {
                throw Fail("legacy-config-assignment-duplicate");
            }
        }

        return values;
    }

    private static void ValidateUniqueAssignments(string text)
    {
        var names = new HashSet<string>(StringComparer.Ordinal);
        foreach (string line in text.Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries))
        {
            Match match = AnyAssignment().Match(line);
            if (match.Success && !names.Add(match.Groups["name"].Value))
            {
                throw Fail("legacy-config-assignment-duplicate");
            }
        }
    }

    private static Dictionary<string, int> ParseIntegerAssignments(string text)
    {
        var values = new Dictionary<string, int>(StringComparer.Ordinal);
        foreach (string line in text.Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries))
        {
            Match match = IntegerAssignment().Match(line);
            if (!match.Success)
            {
                continue;
            }

            string name = match.Groups["name"].Value;
            if (!int.TryParse(match.Groups["value"].Value, NumberStyles.None, CultureInfo.InvariantCulture, out int value)
                || !values.TryAdd(name, value))
            {
                throw Fail("legacy-config-assignment-invalid");
            }
        }

        return values;
    }

    private static string RequiredString(IReadOnlyDictionary<string, string> values, string name) =>
        values.TryGetValue(name, out string? value) && !string.IsNullOrWhiteSpace(value)
            ? value
            : throw Fail("legacy-config-required-value-missing");

    private static int RequiredInteger(IReadOnlyDictionary<string, int> values, string name) =>
        values.TryGetValue(name, out int value)
            ? value
            : throw Fail("legacy-config-required-value-missing");

    private static int OptionalInteger(IReadOnlyDictionary<string, int> values, string name, int fallback) =>
        values.TryGetValue(name, out int value) ? value : fallback;

    private static string ValidateExpectedPath(string supplied, string expected, string code)
    {
        if (!Path.IsPathFullyQualified(supplied)
            || supplied.StartsWith("\\\\", StringComparison.Ordinal)
            || !SamePath(supplied, expected))
        {
            throw Fail(code);
        }

        return Path.GetFullPath(supplied);
    }

    private static bool SamePath(string left, string right)
    {
        try
        {
            return Path.GetFullPath(left).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar)
                .Equals(
                    Path.GetFullPath(right).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar),
                    StringComparison.OrdinalIgnoreCase);
        }
        catch (Exception error) when (error is ArgumentException or NotSupportedException or PathTooLongException)
        {
            return false;
        }
    }

    private static Uri ValidateOrigin(
        string text,
        bool requireHttps,
        bool requireLoopback,
        string code)
    {
        if (!Uri.TryCreate(text, UriKind.Absolute, out Uri? value)
            || value.UserInfo.Length != 0
            || value.Query.Length != 0
            || value.Fragment.Length != 0
            || value.AbsolutePath != "/"
            || requireHttps && value.Scheme != Uri.UriSchemeHttps
            || !requireHttps && value.Scheme != Uri.UriSchemeHttp
            || requireLoopback && !(value.Host.Equals("localhost", StringComparison.OrdinalIgnoreCase)
                || value.Host == "127.0.0.1"
                || value.Host == "::1"))
        {
            throw Fail(code);
        }

        return value;
    }

    private static async Task<T> ReadJsonAsync<T>(string path, CancellationToken cancellationToken)
    {
        byte[] bytes = await ReadBoundedAsync(path, MaximumJsonBytes, cancellationToken).ConfigureAwait(false);
        byte[]? canonical = null;
        try
        {
            canonical = JcsCanonicalizer.CanonicalizeToUtf8(bytes);
            return JsonSerializer.Deserialize<T>(canonical, AtomicFileStore.JsonOptions)
                ?? throw Fail("legacy-json-empty");
        }
        catch (Exception error) when (error is JsonException or ProtocolValidationException)
        {
            throw Fail("legacy-json-invalid");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(bytes);
            if (canonical is not null)
            {
                CryptographicOperations.ZeroMemory(canonical);
            }
        }
    }

    private static JsonDocument ParseJson(byte[] bytes, string code)
    {
        try
        {
            return JsonDocument.Parse(bytes, new JsonDocumentOptions
            {
                AllowTrailingCommas = false,
                CommentHandling = JsonCommentHandling.Disallow,
                MaxDepth = 64,
            });
        }
        catch (JsonException)
        {
            throw Fail(code);
        }
    }

    private static async Task<byte[]> ReadBoundedAsync(
        string path,
        int maximumBytes,
        CancellationToken cancellationToken)
    {
        EnsureRegularFile(path);
        var info = new FileInfo(path);
        if (info.Length is <= 0 || info.Length > maximumBytes)
        {
            throw Fail("legacy-file-length-invalid");
        }

        try
        {
            await using var stream = new FileStream(
                path,
                FileMode.Open,
                FileAccess.Read,
                FileShare.Read,
                64 * 1024,
                FileOptions.Asynchronous | FileOptions.SequentialScan);
            byte[] bytes = new byte[checked((int)info.Length)];
            await stream.ReadExactlyAsync(bytes, cancellationToken).ConfigureAwait(false);
            if (stream.ReadByte() != -1)
            {
                CryptographicOperations.ZeroMemory(bytes);
                throw Fail("legacy-file-changed-during-read");
            }

            return bytes;
        }
        catch (LegacyMigrationException)
        {
            throw;
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException)
        {
            throw Fail("legacy-file-read-failed");
        }
    }

    private static byte[] DecodeExactPem(byte[] pemBytes, string expectedLabel, int maximumBytes)
    {
        if (pemBytes.Length == 0 || pemBytes.Length > maximumBytes)
        {
            throw Fail("legacy-private-key-length-invalid");
        }

        char[] characters;
        try
        {
            characters = StrictUtf8.GetChars(pemBytes);
        }
        catch (DecoderFallbackException)
        {
            throw Fail("legacy-private-key-encoding-invalid");
        }

        try
        {
            ReadOnlySpan<char> trimmed = characters.AsSpan().Trim();
            if (!PemEncoding.TryFind(trimmed, out PemFields fields))
            {
                throw Fail("legacy-private-key-pem-invalid");
            }

            Range location = fields.Location;
            (int offset, int length) = location.GetOffsetAndLength(trimmed.Length);
            if (offset != 0 || length != trimmed.Length
                || !trimmed[fields.Label].SequenceEqual(expectedLabel))
            {
                throw Fail("legacy-private-key-pem-invalid");
            }

            byte[] decoded = new byte[fields.DecodedDataLength];
            if (!Convert.TryFromBase64Chars(trimmed[fields.Base64Data], decoded, out int written)
                || written != decoded.Length)
            {
                CryptographicOperations.ZeroMemory(decoded);
                throw Fail("legacy-private-key-pem-invalid");
            }

            return decoded;
        }
        finally
        {
            characters.AsSpan().Clear();
        }
    }

    private static void EnsureRegularFile(string path)
    {
        if (!File.Exists(path))
        {
            throw Fail("legacy-required-file-missing");
        }

        FileAttributes attributes = File.GetAttributes(path);
        if ((attributes & (FileAttributes.Directory | FileAttributes.ReparsePoint)) != 0)
        {
            throw Fail("legacy-file-type-invalid");
        }
    }

    private static string RequiredJsonString(JsonElement value, string propertyName, string code) =>
        value.TryGetProperty(propertyName, out JsonElement property)
        && property.ValueKind == JsonValueKind.String
        && !string.IsNullOrWhiteSpace(property.GetString())
            ? property.GetString()!
            : throw Fail(code);

    private static bool FixedTimeTextEquals(string left, string right)
    {
        byte[] leftBytes = Encoding.ASCII.GetBytes(left);
        byte[] rightBytes = Encoding.ASCII.GetBytes(right);
        try
        {
            return leftBytes.Length == rightBytes.Length
                && CryptographicOperations.FixedTimeEquals(leftBytes, rightBytes);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(leftBytes);
            CryptographicOperations.ZeroMemory(rightBytes);
        }
    }

    private static LegacyMigrationException Fail(string code) => new(code);

    [GeneratedRegex(
        "^\\s*(?<name>[A-Za-z][A-Za-z0-9]*)\\s*=\\s*'(?<value>(?:[^']|'')*)'\\s*(?:#.*)?$",
        RegexOptions.CultureInvariant)]
    private static partial Regex StringAssignment();

    [GeneratedRegex(
        "^\\s*(?<name>[A-Za-z][A-Za-z0-9]*)\\s*=\\s*(?<value>[0-9]+)\\s*(?:#.*)?$",
        RegexOptions.CultureInvariant)]
    private static partial Regex IntegerAssignment();

    [GeneratedRegex(
        "^\\s*(?<name>[A-Za-z][A-Za-z0-9]*)\\s*=",
        RegexOptions.CultureInvariant)]
    private static partial Regex AnyAssignment();

    [GeneratedRegex("^[a-z0-9][a-z0-9._-]{2,63}$", RegexOptions.CultureInvariant)]
    private static partial Regex NodeIdPattern();

    [GeneratedRegex("^[A-Za-z0-9][A-Za-z0-9._:/-]{0,159}$", RegexOptions.CultureInvariant)]
    private static partial Regex KeyIdPattern();

    [GeneratedRegex("^SHA256:[A-Za-z0-9_-]{43}$", RegexOptions.CultureInvariant)]
    private static partial Regex FingerprintPattern();

    private sealed record LegacyIdentityMetadata(
        int SchemaVersion,
        string NodeId,
        string KeyId,
        string Algorithm,
        string PrivateKeyFormat,
        string PublicKeyFormat,
        string PrivateKeyPath,
        string PublicKeyPath,
        string CreatedAt);

    private sealed record LegacyWorkerControl(
        string Schema,
        int SchemaVersion,
        string NodeId,
        bool AcceptingClaims,
        int RequestedParallelism,
        int LastNonZeroParallelism,
        bool DrainRequested,
        string? UpdatedAt,
        string UpdatedBy);
}
