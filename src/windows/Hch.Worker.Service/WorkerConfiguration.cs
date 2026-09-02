using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;

namespace Hch.Worker.Service;

public sealed partial record WorkerConfiguration(
    int SchemaVersion,
    string NodeId,
    string WorkerName,
    string KeyId,
    string? OwnerSid,
    string? RootKeyId,
    string? RootPublicKeyFingerprint,
    string? RootPublicKeyPath,
    Uri OrchestratorBaseUri,
    Uri OllamaBaseUri,
    int LastNonZeroMaxConcurrentJobs,
    int ClaimBatchSize,
    int ManifestCapacityLimit,
    int LocalResourceLimit,
    string StateRoot)
{
    public const int CurrentSchemaVersion = 1;

    public WorkerConfiguration Validate()
    {
        if (SchemaVersion != CurrentSchemaVersion)
        {
            throw new WorkerConfigurationException("configuration-schema-unsupported");
        }

        ValidateIdentifier(NodeId, nameof(NodeId), 128);
        ValidateIdentifier(KeyId, nameof(KeyId), 256);
        if (string.IsNullOrWhiteSpace(WorkerName) || WorkerName.Length > 160 ||
            WorkerName.Any(static character => char.IsControl(character)))
        {
            throw new WorkerConfigurationException("configuration-worker-name-invalid");
        }

        if (OwnerSid is not null && !SidPattern().IsMatch(OwnerSid))
        {
            throw new WorkerConfigurationException("configuration-owner-sid-invalid");
        }

        ValidateRootTrust();

        ValidateHttpsOrigin(OrchestratorBaseUri);
        ValidateLoopbackOrigin(OllamaBaseUri);
        ValidatePositiveCapacity(LastNonZeroMaxConcurrentJobs, nameof(LastNonZeroMaxConcurrentJobs));
        ValidatePositiveCapacity(ClaimBatchSize, nameof(ClaimBatchSize));
        ValidatePositiveCapacity(ManifestCapacityLimit, nameof(ManifestCapacityLimit));
        ValidatePositiveCapacity(LocalResourceLimit, nameof(LocalResourceLimit));
        if (!Path.IsPathFullyQualified(StateRoot))
        {
            throw new WorkerConfigurationException("configuration-state-root-invalid");
        }

        return this with { StateRoot = Path.GetFullPath(StateRoot) };
    }

    public bool HasRootTrustPins =>
        RootKeyId is not null && RootPublicKeyFingerprint is not null && RootPublicKeyPath is not null;

    private void ValidateRootTrust()
    {
        int configured = (RootKeyId is null ? 0 : 1)
            + (RootPublicKeyFingerprint is null ? 0 : 1)
            + (RootPublicKeyPath is null ? 0 : 1);
        if (configured == 0)
        {
            return;
        }

        if (configured != 3)
        {
            throw new WorkerConfigurationException("configuration-root-trust-incomplete");
        }

        ValidateIdentifier(RootKeyId!, nameof(RootKeyId), 160);
        if (!RootFingerprintPattern().IsMatch(RootPublicKeyFingerprint!))
        {
            throw new WorkerConfigurationException("configuration-root-trust-fingerprint-invalid");
        }

        string rootPublicKeyPath = RootPublicKeyPath!;
        if (!Path.IsPathFullyQualified(rootPublicKeyPath)
            || rootPublicKeyPath.StartsWith("\\\\", StringComparison.Ordinal))
        {
            throw new WorkerConfigurationException("configuration-root-trust-path-invalid");
        }
    }

    private static void ValidateHttpsOrigin(Uri value)
    {
        if (!value.IsAbsoluteUri || value.Scheme != Uri.UriSchemeHttps ||
            value.UserInfo.Length > 0 || value.AbsolutePath != "/" ||
            value.Query.Length > 0 || value.Fragment.Length > 0)
        {
            throw new WorkerConfigurationException("configuration-orchestrator-url-invalid");
        }
    }

    private static void ValidateLoopbackOrigin(Uri value)
    {
        var loopback = value.Host.Equals("localhost", StringComparison.OrdinalIgnoreCase) ||
            value.Host == "127.0.0.1" || value.Host == "::1";
        if (!value.IsAbsoluteUri || value.Scheme != Uri.UriSchemeHttp || !loopback ||
            value.UserInfo.Length > 0 || value.AbsolutePath != "/" ||
            value.Query.Length > 0 || value.Fragment.Length > 0)
        {
            throw new WorkerConfigurationException("configuration-ollama-url-invalid");
        }
    }

    private static void ValidateIdentifier(string value, string name, int maximum)
    {
        if (string.IsNullOrWhiteSpace(value) || value.Length > maximum ||
            value.Any(static character =>
                !(char.IsAsciiLetterOrDigit(character) || character is '.' or '_' or '-' or ':' or '/')))
        {
            throw new WorkerConfigurationException($"configuration-{name.ToLowerInvariant()}-invalid");
        }
    }

    private static void ValidatePositiveCapacity(int value, string name)
    {
        if (value is < 1 or > 64)
        {
            throw new WorkerConfigurationException($"configuration-{name.ToLowerInvariant()}-invalid");
        }
    }

    [GeneratedRegex("^S-1-(?:[0-9]+-){1,14}[0-9]+$", RegexOptions.CultureInvariant)]
    private static partial Regex SidPattern();

    [GeneratedRegex("^SHA256:[A-Za-z0-9_-]{43}$", RegexOptions.CultureInvariant)]
    private static partial Regex RootFingerprintPattern();
}

public static class WorkerConfigurationStore
{
    public const string ProductDirectoryName = "HCH Worker";
    public const string VendorDirectoryName = "HubTech";

    private static JsonSerializerOptions Options { get; } = new(JsonSerializerDefaults.Web)
    {
        AllowTrailingCommas = false,
        MaxDepth = 32,
        PropertyNameCaseInsensitive = false,
        ReadCommentHandling = JsonCommentHandling.Disallow,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
        WriteIndented = true,
    };

    public static string DefaultProductRoot => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
        VendorDirectoryName,
        ProductDirectoryName);

    public static string DefaultConfigurationPath => Path.Combine(DefaultProductRoot, "config.json");

    public static async Task<WorkerConfiguration> ReadAsync(
        string? path = null,
        CancellationToken cancellationToken = default)
    {
        var absolute = Path.GetFullPath(path ?? DefaultConfigurationPath);
        await using var stream = new FileStream(
            absolute,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            64 * 1024,
            FileOptions.Asynchronous | FileOptions.SequentialScan);
        try
        {
            var value = await JsonSerializer.DeserializeAsync<WorkerConfiguration>(
                stream,
                Options,
                cancellationToken).ConfigureAwait(false);
            return (value ?? throw new WorkerConfigurationException("configuration-empty")).Validate();
        }
        catch (JsonException error)
        {
            throw new WorkerConfigurationException("configuration-json-invalid", error);
        }
    }

    public static async Task WriteAsync(
        WorkerConfiguration configuration,
        string? path = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(configuration);
        WorkerConfiguration validated = configuration.Validate();
        string absolute = Path.GetFullPath(path ?? DefaultConfigurationPath);
        string directory = Path.GetDirectoryName(absolute)
            ?? throw new WorkerConfigurationException("configuration-path-invalid");
        string fileName = Path.GetFileName(absolute);
        if (string.IsNullOrWhiteSpace(fileName))
        {
            throw new WorkerConfigurationException("configuration-path-invalid");
        }

        var store = new Hch.Worker.Persistence.AtomicFileStore(directory);
        await store.WriteJsonAsync(fileName, validated, cancellationToken).ConfigureAwait(false);
    }

    public static WorkerConfiguration CreatePausedDefault(
        string nodeId,
        string keyId,
        string? rootKeyId = null,
        string? rootPublicKeyFingerprint = null,
        string? rootPublicKeyPath = null) => new WorkerConfiguration(
        WorkerConfiguration.CurrentSchemaVersion,
        nodeId,
        $"HCH Worker - {Environment.MachineName}",
        keyId,
        OwnerSid: null,
        rootKeyId,
        rootPublicKeyFingerprint,
        rootPublicKeyPath,
        new Uri("https://hubtech.online/"),
        new Uri("http://127.0.0.1:11434/"),
        LastNonZeroMaxConcurrentJobs: 1,
        ClaimBatchSize: 1,
        ManifestCapacityLimit: 64,
        LocalResourceLimit: 64,
        StateRoot: Path.Combine(DefaultProductRoot, "state")).Validate();
}

public sealed class WorkerConfigurationException(string code, Exception? innerException = null)
    : Exception("The Worker configuration is invalid.", innerException)
{
    public string Code { get; } = code;
}
