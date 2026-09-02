using System.IO.Pipes;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text.Json;
using System.Text.RegularExpressions;
using Hch.Worker.Persistence;
using Hch.Worker.IPC.Contracts;
using Hch.Worker.Protocol;
using Hch.Worker.Security;
using Hch.Worker.Windows;

namespace Hch.Worker.Installer;

internal static partial class Program
{
    private const string ServiceName = "HchWorker";
    private const string ConfigFileName = "config.json";
    private const string MarkerFileName = ".bootstrap-v4.pending";
    private const string IdentityRelativePath = "identity/worker-ed25519.pkcs8.dpapi";
    private const string RootTrustRelativePath = "trust/orchestrator-root.pem";
    private const string PackagedTrustMetadataFileName = "root-trust.json";
    private const string PackagedTrustPublicKeyFileName = "orchestrator-root.pem";
    private const string LegacyProductRoot = LegacyWindowsWorkerPaths.DefaultProductRoot;
    private const int MaximumPublicTrustFileLength = 64 * 1024;
    private const int MaximumTrustStateLength = 1024 * 1024;
    private const int MaximumConfigurationLength = 1024 * 1024;

    private static readonly SecurityIdentifier SystemSid =
        new(WellKnownSidType.LocalSystemSid, null);

    private static readonly SecurityIdentifier AdministratorsSid =
        new(WellKnownSidType.BuiltinAdministratorsSid, null);

    private static readonly HashSet<string> RefusedOwnerSids = new(StringComparer.Ordinal)
    {
        new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null).Value,
        new SecurityIdentifier(WellKnownSidType.LocalServiceSid, null).Value,
        new SecurityIdentifier(WellKnownSidType.NetworkServiceSid, null).Value,
    };

    public static async Task<int> Main(string[] args)
    {
        if (!OperatingSystem.IsWindows())
        {
            return Fail("installer-windows-required");
        }

        try
        {
            if (args.Length == 1 && args[0] == "self-test")
            {
                return await SelfTestAsync().ConfigureAwait(false);
            }

            var options = ParseOptions(args);
            return options.Command switch
            {
                "bootstrap" => await BootstrapAsync(
                    options.ProductRoot,
                    options.OwnerSid,
                    options.MachineName,
                    WindowsServiceIdentity.ResolveServiceSid(ServiceName),
                    options.RootKeyId,
                    options.RootPublicKeyFingerprint,
                    options.RootPublicKeyPath,
                    installMode: options.InstallMode).ConfigureAwait(false),
                "rollback" => await RollbackAsync(options.ProductRoot).ConfigureAwait(false),
                "commit" => Commit(options.ProductRoot),
                "maintenance-preflight" => await MaintenancePreflightAsync(options.ProductRoot)
                    .ConfigureAwait(false),
                _ => Fail("installer-command-invalid"),
            };
        }
        catch (LegacyMigrationException error)
        {
            return Fail(error.Code);
        }
        catch (Exception error) when (error is ArgumentException or CryptographicException
            or IOException or UnauthorizedAccessException or InvalidOperationException
            or JsonException or ProtocolValidationException)
        {
            return Fail(error.Message);
        }
    }

    private static async Task<int> BootstrapAsync(
        string productRoot,
        string ownerSidText,
        string machineName,
        SecurityIdentifier serviceSid,
        string? rootKeyId = null,
        string? rootPublicKeyFingerprint = null,
        string? rootPublicKeyPath = null,
        bool probeInstalledTrust = true,
        InstallerInstallMode installMode = InstallerInstallMode.Fresh)
    {
        string root = ValidateLocalFixedPath(productRoot);
        string configPath = Path.Combine(root, ConfigFileName);
        string markerPath = Path.Combine(root, MarkerFileName);
        string stateRoot = Path.Combine(root, "state");
        string identityPath = Path.Combine(stateRoot, IdentityRelativePath.Replace('/', Path.DirectorySeparatorChar));
        LegacyWindowsWorkerMigrator? legacyMigrator = null;
        string? legacyMigrationId = null;
        bool legacyMigrationAttempted = false;

        var ownerSid = ValidateOwnerSid(ownerSidText);
        if (installMode == InstallerInstallMode.Upgrade)
        {
            _ = await ValidateExistingInstallationAsync(root, serviceSid).ConfigureAwait(false);
            return 0;
        }

        if (installMode != InstallerInstallMode.Fresh)
        {
            throw new InvalidOperationException("installer-install-mode-invalid");
        }

        Directory.CreateDirectory(root);
        RejectReparsePoints(root);
        WindowsAcl.ProtectProductDirectory(root, serviceSid, ownerSid);
        // The ACL is protected before this decisive check. A principal that
        // can create children under ProgramData therefore cannot win a race
        // between the emptiness check and the first bootstrap write.
        if (Directory.EnumerateFileSystemEntries(root).Any())
        {
            throw new InvalidOperationException("installer-target-preinitialized-refused");
        }

        await using (var marker = new FileStream(
            markerPath,
            FileMode.CreateNew,
            FileAccess.Write,
            FileShare.None,
            1,
            FileOptions.WriteThrough))
        {
            await marker.FlushAsync().ConfigureAwait(false);
            marker.Flush(flushToDisk: true);
        }

        try
        {
            WindowsAcl.CreatePrivateServiceDirectory(stateRoot, serviceSid);
            if (probeInstalledTrust && Directory.Exists(LegacyProductRoot))
            {
                legacyMigrationAttempted = true;
                await WriteMarkerAsync(
                    markerPath,
                    createdRootTrustPath: null,
                    legacyMigrationId: null,
                    legacyMigrationAttempted: true).ConfigureAwait(false);
                legacyMigrator = new LegacyWindowsWorkerMigrator(
                    new MachineSecretProtector(),
                    new WindowsLegacyWorkerRuntimePreflight());
                LegacyWindowsMigrationResult migrated = await legacyMigrator.MigrateAsync(
                    new LegacyWindowsMigrationRequest(
                        LegacyProductRoot,
                        root,
                        ownerSid.Value)).ConfigureAwait(false);
                legacyMigrationId = migrated.MigrationId;
                WindowsAcl.ProtectServiceFile(migrated.IdentityPath, serviceSid);
                ProtectConfigurationFile(migrated.ConfigurationPath, ownerSid, serviceSid);
                ProtectConfigurationFile(migrated.RootPublicKeyPath, ownerSid, serviceSid);
                await WriteMarkerAsync(
                    markerPath,
                    migrated.RootPublicKeyPath,
                    migrated.MigrationId,
                    legacyMigrationAttempted: true).ConfigureAwait(false);
                return 0;
            }

            RootTrustPins? rootTrust = await ResolveRootTrustAsync(
                root,
                markerPath,
                ownerSid,
                serviceSid,
                rootKeyId,
                rootPublicKeyFingerprint,
                rootPublicKeyPath,
                probeInstalledTrust).ConfigureAwait(false);
            var state = new AtomicFileStore(stateRoot);
            string nodeId = CreateNodeId(machineName);
            using var identity = Ed25519Identity.Generate();
            byte[] pkcs8 = identity.ExportPkcs8PrivateKey();
            byte[]? protectedPkcs8 = null;
            try
            {
                protectedPkcs8 = new MachineSecretProtector().Protect(
                    pkcs8,
                    IdentityPurpose(nodeId));
                await state.WriteBytesAsync(IdentityRelativePath, protectedPkcs8).ConfigureAwait(false);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(pkcs8);
                if (protectedPkcs8 is not null)
                {
                    CryptographicOperations.ZeroMemory(protectedPkcs8);
                }
            }

            WindowsAcl.ProtectServiceFile(identityPath, serviceSid);
            var configuration = new BootstrapConfiguration(
                SchemaVersion: 1,
                NodeId: nodeId,
                WorkerName: $"HCH Worker - {SanitizeMachineName(machineName)}",
                KeyId: identity.Fingerprint,
                OwnerSid: ownerSid.Value,
                RootKeyId: rootTrust?.RootKeyId,
                RootPublicKeyFingerprint: rootTrust?.RootPublicKeyFingerprint,
                RootPublicKeyPath: rootTrust?.RootPublicKeyPath,
                OrchestratorBaseUri: new Uri("https://hubtech.online/"),
                OllamaBaseUri: new Uri("http://127.0.0.1:11434/"),
                LastNonZeroMaxConcurrentJobs: 1,
                ClaimBatchSize: 1,
                ManifestCapacityLimit: 64,
                LocalResourceLimit: 64,
                StateRoot: stateRoot);
            await WriteConfigurationAsync(configPath, configuration).ConfigureAwait(false);
            ProtectConfigurationFile(configPath, ownerSid, serviceSid);
            return 0;
        }
        catch
        {
            if (legacyMigrationAttempted && legacyMigrator is not null)
            {
                try
                {
                    await RollbackLegacyMigrationIfPresentAsync(
                        root,
                        legacyMigrator,
                        legacyMigrationId).ConfigureAwait(false);
                    DeleteFile(markerPath);
                }
                catch (Exception error) when (error is LegacyMigrationException or JsonException
                    or IOException or UnauthorizedAccessException)
                {
                    throw new InvalidOperationException("installer-legacy-migration-rollback-incomplete");
                }
            }
            else
            {
                DeleteBootstrapArtifacts(configPath, identityPath, markerPath, ReadCreatedRootTrustPath(markerPath));
            }

            throw;
        }
    }

    private static async Task<int> RollbackAsync(string productRoot)
    {
        string root = ValidateLocalFixedPath(productRoot);
        string markerPath = Path.Combine(root, MarkerFileName);
        if (!File.Exists(markerPath))
        {
            return 0;
        }

        BootstrapMarker? marker = ReadBootstrapMarker(markerPath);
        string stateRoot = Path.Combine(root, "state");
        string journalPath = Path.Combine(
            stateRoot,
            LegacyWindowsWorkerPaths.TargetMigrationJournalRelativePath.Replace(
                '/',
                Path.DirectorySeparatorChar));
        if (marker?.LegacyMigrationAttempted == true || File.Exists(journalPath))
        {
            var migrator = new LegacyWindowsWorkerMigrator(
                new MachineSecretProtector(),
                new WindowsLegacyWorkerRuntimePreflight());
            await RollbackLegacyMigrationIfPresentAsync(
                root,
                migrator,
                marker?.LegacyMigrationId).ConfigureAwait(false);
            DeleteFile(markerPath);
            return 0;
        }

        string configPath = Path.Combine(root, ConfigFileName);
        string identityPath = Path.Combine(
            root,
            "state",
            IdentityRelativePath.Replace('/', Path.DirectorySeparatorChar));
        DeleteBootstrapArtifacts(configPath, identityPath, markerPath, ReadCreatedRootTrustPath(markerPath));
        return 0;
    }

    private static int Commit(string productRoot)
    {
        string root = ValidateLocalFixedPath(productRoot);
        string markerPath = Path.Combine(root, MarkerFileName);
        if (File.Exists(markerPath))
        {
            RejectReparsePoints(markerPath);
            File.Delete(markerPath);
        }

        return 0;
    }

    private static async Task<int> SelfTestAsync()
    {
        string root = Path.Combine(Path.GetTempPath(), "hch-worker-installer-test-" + Guid.NewGuid().ToString("N"));
        var currentSid = WindowsServiceIdentity.GetCurrentUserSid();
        try
        {
            int first = await BootstrapAsync(
                root, currentSid.Value, Environment.MachineName, currentSid, probeInstalledTrust: false)
                .ConfigureAwait(false);
            if (first != 0)
            {
                throw new InvalidOperationException("installer-self-test-bootstrap-failed");
            }

            string configPath = Path.Combine(root, ConfigFileName);
            byte[] firstHash = SHA256.HashData(await File.ReadAllBytesAsync(configPath).ConfigureAwait(false));
            var config = JsonSerializer.Deserialize<BootstrapConfiguration>(
                await File.ReadAllBytesAsync(configPath).ConfigureAwait(false),
                JsonOptions) ?? throw new InvalidOperationException("installer-self-test-config-empty");
            string identityPath = Path.Combine(root, "state", IdentityRelativePath.Replace('/', Path.DirectorySeparatorChar));
            byte[] protectedPkcs8 = await File.ReadAllBytesAsync(identityPath).ConfigureAwait(false);
            byte[]? pkcs8 = null;
            try
            {
                pkcs8 = new MachineSecretProtector().Unprotect(protectedPkcs8, IdentityPurpose(config.NodeId));
                using var identity = Ed25519Identity.ImportPkcs8(pkcs8);
                if (!CryptographicOperations.FixedTimeEquals(
                        System.Text.Encoding.ASCII.GetBytes(config.KeyId),
                        System.Text.Encoding.ASCII.GetBytes(identity.Fingerprint)))
                {
                    throw new InvalidOperationException("installer-self-test-key-id-mismatch");
                }
            }
            finally
            {
                CryptographicOperations.ZeroMemory(protectedPkcs8);
                if (pkcs8 is not null)
                {
                    CryptographicOperations.ZeroMemory(pkcs8);
                }
            }

            _ = Commit(root);
            _ = await BootstrapAsync(
                root,
                currentSid.Value,
                "must-not-overwrite",
                currentSid,
                probeInstalledTrust: false,
                installMode: InstallerInstallMode.Upgrade)
                .ConfigureAwait(false);
            byte[] secondHash = SHA256.HashData(await File.ReadAllBytesAsync(configPath).ConfigureAwait(false));
            if (!CryptographicOperations.FixedTimeEquals(firstHash, secondHash))
            {
                throw new InvalidOperationException("installer-self-test-upgrade-overwrote-config");
            }

            _ = await RollbackAsync(root).ConfigureAwait(false);
            if (!File.Exists(configPath) || !File.Exists(identityPath))
            {
                throw new InvalidOperationException("installer-self-test-rollback-removed-preserved-state");
            }

            string rollbackRoot = root + "-rollback";
            _ = await BootstrapAsync(
                rollbackRoot, currentSid.Value, Environment.MachineName, currentSid, probeInstalledTrust: false)
                .ConfigureAwait(false);
            _ = await RollbackAsync(rollbackRoot).ConfigureAwait(false);
            if (File.Exists(Path.Combine(rollbackRoot, ConfigFileName)) ||
                File.Exists(Path.Combine(rollbackRoot, "state", IdentityRelativePath.Replace('/', Path.DirectorySeparatorChar))))
            {
                throw new InvalidOperationException("installer-self-test-selective-rollback-failed");
            }

            TryDeleteTree(rollbackRoot);

            string trustRoot = root + "-trust";
            string rootPublicKeyPath = Path.Combine(root, "test-root.pem");
            using (var rootIdentity = Ed25519Identity.Generate())
            {
                await File.WriteAllTextAsync(rootPublicKeyPath, rootIdentity.ExportSubjectPublicKeyInfoPem())
                    .ConfigureAwait(false);
                _ = await BootstrapAsync(
                    trustRoot,
                    currentSid.Value,
                    Environment.MachineName,
                    currentSid,
                    "hch-root-self-test",
                    rootIdentity.Fingerprint,
                    rootPublicKeyPath,
                    probeInstalledTrust: false).ConfigureAwait(false);
            }

            var trustConfig = JsonSerializer.Deserialize<BootstrapConfiguration>(
                await File.ReadAllBytesAsync(Path.Combine(trustRoot, ConfigFileName)).ConfigureAwait(false),
                JsonOptions) ?? throw new InvalidOperationException("installer-self-test-trust-config-empty");
            if (trustConfig.RootKeyId != "hch-root-self-test"
                || trustConfig.RootPublicKeyPath is null
                || !File.Exists(trustConfig.RootPublicKeyPath))
            {
                throw new InvalidOperationException("installer-self-test-root-trust-not-pinned");
            }

            _ = await RollbackAsync(trustRoot).ConfigureAwait(false);
            if (File.Exists(trustConfig.RootPublicKeyPath))
            {
                throw new InvalidOperationException("installer-self-test-root-trust-rollback-failed");
            }

            TryDeleteTree(trustRoot);
            DeleteFile(rootPublicKeyPath);

            string squattedRoot = root + "-squatted";
            Directory.CreateDirectory(squattedRoot);
            await File.WriteAllTextAsync(
                Path.Combine(squattedRoot, ConfigFileName),
                "{\"schemaVersion\":1}").ConfigureAwait(false);
            InvalidOperationException squatting = await AssertBootstrapFailureAsync(
                () => BootstrapAsync(
                    squattedRoot,
                    currentSid.Value,
                    Environment.MachineName,
                    currentSid,
                    probeInstalledTrust: false));
            if (squatting.Message != "installer-target-preinitialized-refused")
            {
                throw new InvalidOperationException("installer-self-test-squatting-not-refused");
            }

            TryDeleteTree(squattedRoot);
            return 0;
        }
        finally
        {
            TryDeleteTree(root);
        }
    }

    private static async Task<InvalidOperationException> AssertBootstrapFailureAsync(
        Func<Task<int>> action)
    {
        try
        {
            _ = await action().ConfigureAwait(false);
        }
        catch (InvalidOperationException error)
        {
            return error;
        }

        throw new InvalidOperationException("installer-self-test-expected-failure-missing");
    }

    private static async Task<BootstrapConfiguration> ValidateExistingInstallationAsync(
        string productRoot,
        SecurityIdentifier serviceSid)
    {
        if (!Directory.Exists(productRoot))
        {
            throw new InvalidOperationException("installer-upgrade-state-missing");
        }

        RejectReparsePoints(productRoot);
        string markerPath = Path.Combine(productRoot, MarkerFileName);
        if (File.Exists(markerPath) || Directory.Exists(markerPath))
        {
            throw new InvalidOperationException("installer-upgrade-bootstrap-pending");
        }

        BootstrapConfiguration configuration = await ValidateExistingInstallationStateAsync(
            productRoot,
            serviceSid,
            validateProductRootAcl: false).ConfigureAwait(false);
        var ownerSid = ValidateOwnerSid(configuration.OwnerSid);

        // Existing V4 candidates may predate the protected root ACL. The
        // cryptographic identity and protected state are validated first;
        // only then is the root hardened, followed by a second full read.
        WindowsAcl.ProtectProductDirectory(productRoot, serviceSid, ownerSid);
        return await ValidateExistingInstallationStateAsync(
            productRoot,
            serviceSid,
            validateProductRootAcl: true).ConfigureAwait(false);
    }

    private static async Task<BootstrapConfiguration> ValidateExistingInstallationStateAsync(
        string productRoot,
        SecurityIdentifier serviceSid,
        bool validateProductRootAcl)
    {
        string configPath = Path.Combine(productRoot, ConfigFileName);
        string stateRoot = Path.Combine(productRoot, "state");
        string identityPath = Path.Combine(
            stateRoot,
            IdentityRelativePath.Replace('/', Path.DirectorySeparatorChar));
        if (!File.Exists(configPath) || !File.Exists(identityPath))
        {
            throw new InvalidOperationException("installer-upgrade-state-incomplete");
        }

        RejectReparsePoints(configPath);
        RejectReparsePoints(identityPath);
        byte[] configurationBytes = ReadLimitedFile(
            configPath,
            MaximumConfigurationLength,
            "installer-upgrade-configuration-length-invalid");
        BootstrapConfiguration configuration;
        try
        {
            configuration = JsonSerializer.Deserialize<BootstrapConfiguration>(
                configurationBytes,
                JsonOptions) ?? throw new InvalidOperationException("installer-upgrade-configuration-empty");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(configurationBytes);
        }

        ValidateBootstrapConfiguration(configuration, productRoot);
        var ownerSid = ValidateOwnerSid(configuration.OwnerSid);
        WindowsAcl.ValidateServiceDirectory(stateRoot, serviceSid);
        WindowsAcl.ValidateServiceFile(configPath, serviceSid, ownerSid);
        WindowsAcl.ValidateServiceFile(identityPath, serviceSid);
        if (validateProductRootAcl)
        {
            WindowsAcl.ValidateProductDirectory(productRoot, serviceSid, ownerSid);
        }

        byte[] protectedPkcs8 = ReadLimitedFile(
            identityPath,
            MaximumConfigurationLength,
            "installer-upgrade-identity-length-invalid");
        byte[]? pkcs8 = null;
        try
        {
            pkcs8 = new MachineSecretProtector().Unprotect(
                protectedPkcs8,
                IdentityPurpose(configuration.NodeId));
            using var identity = Ed25519Identity.ImportPkcs8(pkcs8);
            if (!FixedTimeTextEquals(identity.Fingerprint, configuration.KeyId))
            {
                throw new CryptographicException("installer-upgrade-identity-mismatch");
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(protectedPkcs8);
            if (pkcs8 is not null)
            {
                CryptographicOperations.ZeroMemory(pkcs8);
            }
        }

        if (configuration.RootPublicKeyPath is not null)
        {
            string trustPath = Path.Combine(
                productRoot,
                RootTrustRelativePath.Replace('/', Path.DirectorySeparatorChar));
            if (!Path.GetFullPath(configuration.RootPublicKeyPath).Equals(
                    Path.GetFullPath(trustPath),
                    StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidOperationException("installer-upgrade-root-trust-path-invalid");
            }

            _ = ValidateTrustCandidate(
                configuration.RootKeyId!,
                configuration.RootPublicKeyFingerprint!,
                trustPath);
            WindowsAcl.ValidateServiceDirectory(Path.GetDirectoryName(trustPath)!, serviceSid);
            WindowsAcl.ValidateServiceFile(trustPath, serviceSid, ownerSid);
        }

        await Task.CompletedTask.ConfigureAwait(false);
        return configuration;
    }

    private static void ValidateBootstrapConfiguration(
        BootstrapConfiguration configuration,
        string productRoot)
    {
        int trustPins = (configuration.RootKeyId is null ? 0 : 1)
            + (configuration.RootPublicKeyFingerprint is null ? 0 : 1)
            + (configuration.RootPublicKeyPath is null ? 0 : 1);
        string expectedStateRoot = Path.GetFullPath(Path.Combine(productRoot, "state"));
        if (configuration.SchemaVersion != 1
            || !WorkerNodeIdPattern().IsMatch(configuration.NodeId)
            || !RootFingerprintPattern().IsMatch(configuration.KeyId)
            || string.IsNullOrWhiteSpace(configuration.WorkerName)
            || configuration.WorkerName.Length > 160
            || configuration.WorkerName.Any(char.IsControl)
            || trustPins is not (0 or 3)
            || !IsHttpsOrigin(configuration.OrchestratorBaseUri)
            || !IsLoopbackHttpOrigin(configuration.OllamaBaseUri)
            || !IsCapacity(configuration.LastNonZeroMaxConcurrentJobs)
            || !IsCapacity(configuration.ClaimBatchSize)
            || !IsCapacity(configuration.ManifestCapacityLimit)
            || !IsCapacity(configuration.LocalResourceLimit)
            || !Path.GetFullPath(configuration.StateRoot).Equals(
                expectedStateRoot,
                StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException("installer-upgrade-configuration-invalid");
        }

        if (trustPins == 3
            && (!RootKeyIdPattern().IsMatch(configuration.RootKeyId!)
                || !RootFingerprintPattern().IsMatch(configuration.RootPublicKeyFingerprint!)))
        {
            throw new InvalidOperationException("installer-upgrade-root-trust-invalid");
        }
    }

    private static bool IsHttpsOrigin(Uri value) =>
        value.IsAbsoluteUri
        && value.Scheme == Uri.UriSchemeHttps
        && value.UserInfo.Length == 0
        && value.AbsolutePath == "/"
        && value.Query.Length == 0
        && value.Fragment.Length == 0;

    private static bool IsLoopbackHttpOrigin(Uri value) =>
        value.IsAbsoluteUri
        && value.Scheme == Uri.UriSchemeHttp
        && (value.Host.Equals("localhost", StringComparison.OrdinalIgnoreCase)
            || value.Host == "127.0.0.1"
            || value.Host == "::1")
        && value.UserInfo.Length == 0
        && value.AbsolutePath == "/"
        && value.Query.Length == 0
        && value.Fragment.Length == 0;

    private static bool IsCapacity(int value) => value is >= 1 and <= 64;

    private static byte[] ReadLimitedFile(string path, int maximumLength, string errorCode)
    {
        var info = new FileInfo(path);
        if (info.Length is <= 0 || info.Length > maximumLength)
        {
            throw new InvalidOperationException(errorCode);
        }

        return File.ReadAllBytes(path);
    }

    private static async Task<int> MaintenancePreflightAsync(string productRoot)
    {
        string root = ValidateLocalFixedPath(productRoot);
        SecurityIdentifier serviceSid = WindowsServiceIdentity.ResolveServiceSid(ServiceName);
        BootstrapConfiguration configuration = await ValidateExistingInstallationAsync(root, serviceSid)
            .ConfigureAwait(false);

        WorkerSnapshotPayload snapshot = await PrepareMaintenanceThroughServiceAsync(
            configuration.NodeId).ConfigureAwait(false);
        if (!string.Equals(snapshot.NodeId, configuration.NodeId, StringComparison.Ordinal)
            || snapshot.AcceptingClaims
            || snapshot.MaxConcurrentJobs != 0
            || snapshot.ActiveJobs != 0
            || snapshot.ReservedJobs != 0
            || snapshot.OperationalState is not ("Paused" or "Stopped"))
        {
            throw new InvalidOperationException("installer-maintenance-drain-required");
        }

        await ValidateNoPendingEditorialOperationsAsync(configuration.StateRoot)
            .ConfigureAwait(false);
        return 0;
    }

    private static async Task<WorkerSnapshotPayload> PrepareMaintenanceThroughServiceAsync(
        string nodeId)
    {
        await using NamedPipeClientStream pipe = LocalNamedPipe.CreateClient(IpcProtocol.PipeName(nodeId));
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        try
        {
            await pipe.ConnectAsync(TimeSpan.FromSeconds(5), timeout.Token).ConfigureAwait(false);
            new WindowsServicePipeServerAuthenticator(ServiceName).Authenticate(pipe);
            IpcRequest request = IpcRequest.Create(
                IpcCommand.PrepareMaintenance,
                EmptyPayload.Value);
            await IpcFraming.WriteAsync(pipe, request, timeout.Token).ConfigureAwait(false);
            IpcResponse response = await IpcFraming.ReadAsync<IpcResponse>(pipe, timeout.Token)
                .ConfigureAwait(false);
            if (response.Version != IpcProtocol.Version || response.RequestId != request.RequestId)
            {
                throw new InvalidOperationException("installer-maintenance-ipc-correlation-invalid");
            }

            if (!response.Success)
            {
                throw new InvalidOperationException(
                    response.ErrorCode ?? "installer-maintenance-service-refused");
            }

            return IpcValidation.Payload<WorkerSnapshotPayload>(response.Payload);
        }
        catch (TimeoutException error)
        {
            throw new InvalidOperationException("installer-maintenance-service-unavailable", error);
        }
        catch (OperationCanceledException error) when (timeout.IsCancellationRequested)
        {
            throw new InvalidOperationException("installer-maintenance-service-unavailable", error);
        }
    }

    private static async Task ValidateNoPendingEditorialOperationsAsync(string stateRoot)
    {
        var files = new AtomicFileStore(stateRoot);
        string pendingClaim = files.Resolve("journals/pending-claim.json");
        if (File.Exists(pendingClaim) || Directory.Exists(pendingClaim))
        {
            RejectReparsePoints(pendingClaim);
            throw new InvalidOperationException("installer-maintenance-pending-claim");
        }

        var journals = new EditorialJournalStore(files);
        foreach (string assignmentId in journals.ListAssignmentIds())
        {
            EditorialJobJournal journal = await journals.ReadAsync(assignmentId).ConfigureAwait(false)
                ?? throw new InvalidOperationException("installer-maintenance-journal-missing");
            if (journal.SchemaVersion != EditorialJobJournal.CurrentSchemaVersion
                || !string.Equals(journal.AssignmentId, assignmentId, StringComparison.Ordinal)
                || journal.IsActive
                || journal.RequiresReconciliation
                || journal.Phase is not (EditorialJournalPhase.Completed
                    or EditorialJournalPhase.Failed))
            {
                throw new InvalidOperationException("installer-maintenance-journal-unreconciled");
            }
        }

        string recoveryDirectory = files.Resolve("journals/recovery");
        if (Directory.Exists(recoveryDirectory))
        {
            RejectReparsePoints(recoveryDirectory);
            if (Directory.EnumerateFileSystemEntries(recoveryDirectory).Any())
            {
                throw new InvalidOperationException("installer-maintenance-recovery-pending");
            }
        }
    }

    private static async Task WriteConfigurationAsync(string path, BootstrapConfiguration configuration)
    {
        byte[] bytes = JsonSerializer.SerializeToUtf8Bytes(configuration, JsonOptions);
        string temporary = path + "." + Guid.NewGuid().ToString("N") + ".tmp";
        try
        {
            await using (var stream = new FileStream(
                temporary,
                FileMode.CreateNew,
                FileAccess.Write,
                FileShare.None,
                64 * 1024,
                FileOptions.Asynchronous | FileOptions.WriteThrough))
            {
                await stream.WriteAsync(bytes).ConfigureAwait(false);
                await stream.FlushAsync().ConfigureAwait(false);
                stream.Flush(flushToDisk: true);
            }

            File.Move(temporary, path, overwrite: false);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(bytes);
            if (File.Exists(temporary))
            {
                File.Delete(temporary);
            }
        }
    }

    private static async Task<RootTrustPins?> ResolveRootTrustAsync(
        string productRoot,
        string markerPath,
        SecurityIdentifier ownerSid,
        SecurityIdentifier serviceSid,
        string? declaredRootKeyId,
        string? declaredRootFingerprint,
        string? declaredRootPublicKeyPath,
        bool probeInstalledTrust)
    {
        int declaredCount = (declaredRootKeyId is null ? 0 : 1)
            + (declaredRootFingerprint is null ? 0 : 1)
            + (declaredRootPublicKeyPath is null ? 0 : 1);
        if (declaredCount is not (0 or 3))
        {
            throw new ArgumentException("installer-root-trust-options-incomplete");
        }

        TrustCandidate? candidate = probeInstalledTrust ? ReadLegacyRootTrustCandidate() : null;
        candidate ??= declaredCount == 3
            ? ValidateTrustCandidate(
                declaredRootKeyId!,
                declaredRootFingerprint!,
                declaredRootPublicKeyPath!)
            : null;
        candidate ??= probeInstalledTrust ? ReadPackagedRootTrustCandidate() : null;
        if (candidate is null)
        {
            return null;
        }

        string trustDirectory = Path.Combine(productRoot, "trust");
        string target = Path.Combine(
            productRoot,
            RootTrustRelativePath.Replace('/', Path.DirectorySeparatorChar));
        WindowsAcl.CreatePrivateServiceDirectory(trustDirectory, serviceSid);
        bool created = !File.Exists(target);
        if (created)
        {
            await WriteMarkerAsync(markerPath, target).ConfigureAwait(false);
            await CopyPublicTrustAtomicallyAsync(candidate.SourcePath, target).ConfigureAwait(false);
            ProtectConfigurationFile(target, ownerSid, serviceSid);
        }
        else
        {
            TrustCandidate existing = ValidateTrustCandidate(
                candidate.RootKeyId,
                candidate.RootPublicKeyFingerprint,
                target);
            if (!FixedTimeTextEquals(existing.RootPublicKeyFingerprint, candidate.RootPublicKeyFingerprint))
            {
                throw new CryptographicException("installer-root-trust-target-mismatch");
            }
        }

        return new RootTrustPins(candidate.RootKeyId, candidate.RootPublicKeyFingerprint, target);
    }

    private static TrustCandidate? ReadLegacyRootTrustCandidate()
    {
        string publicKeyPath = Path.Combine(LegacyProductRoot, "trust", "orchestrator-root.pem");
        string trustStatePath = Path.Combine(LegacyProductRoot, "state", "trust-state.json");
        bool publicKeyExists = File.Exists(publicKeyPath);
        bool trustStateExists = File.Exists(trustStatePath);
        if (!publicKeyExists && !trustStateExists)
        {
            return null;
        }

        if (!publicKeyExists || !trustStateExists)
        {
            throw new InvalidOperationException("installer-legacy-root-trust-incomplete");
        }

        RejectReparsePoints(trustStatePath);
        var info = new FileInfo(trustStatePath);
        if (info.Length is <= 0 or > MaximumTrustStateLength)
        {
            throw new InvalidOperationException("installer-legacy-trust-state-length-invalid");
        }

        using JsonDocument document = JsonDocument.Parse(
            File.ReadAllBytes(trustStatePath),
            new JsonDocumentOptions { AllowTrailingCommas = false, CommentHandling = JsonCommentHandling.Disallow, MaxDepth = 32 });
        JsonElement root = document.RootElement;
        if (RequiredJsonString(root, "schema") != "hch.worker-trust-state/v1"
            || !root.TryGetProperty("schemaVersion", out JsonElement schemaVersion)
            || schemaVersion.ValueKind != JsonValueKind.Number
            || !schemaVersion.TryGetInt32(out int version)
            || version != 1)
        {
            throw new InvalidOperationException("installer-legacy-trust-state-invalid");
        }
        string rootKeyId = RequiredJsonString(root, "rootKeyId");
        string rootFingerprint = RequiredJsonString(root, "rootFingerprint");
        return ValidateTrustCandidate(rootKeyId, rootFingerprint, publicKeyPath);
    }

    private static TrustCandidate? ReadPackagedRootTrustCandidate()
    {
        string trustPayloadDirectory = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
            "HubTech",
            "HCH Worker",
            "4",
            "Trust");
        string metadataPath = Path.Combine(trustPayloadDirectory, PackagedTrustMetadataFileName);
        string publicKeyPath = Path.Combine(trustPayloadDirectory, PackagedTrustPublicKeyFileName);
        bool metadataExists = File.Exists(metadataPath);
        bool publicKeyExists = File.Exists(publicKeyPath);
        if (!metadataExists && !publicKeyExists)
        {
            return null;
        }

        if (!metadataExists || !publicKeyExists)
        {
            throw new InvalidOperationException("installer-packaged-root-trust-incomplete");
        }

        RejectReparsePoints(metadataPath);
        var info = new FileInfo(metadataPath);
        if (info.Length is <= 0 or > MaximumTrustStateLength)
        {
            throw new InvalidOperationException("installer-packaged-root-trust-metadata-length-invalid");
        }

        var metadata = JsonSerializer.Deserialize<PackagedRootTrustMetadata>(
            File.ReadAllBytes(metadataPath),
            JsonOptions) ?? throw new InvalidOperationException("installer-packaged-root-trust-metadata-invalid");
        if (metadata.Schema != "hch.worker-root-trust/v1"
            || metadata.PublicKeyFileName != PackagedTrustPublicKeyFileName)
        {
            throw new InvalidOperationException("installer-packaged-root-trust-metadata-invalid");
        }

        return ValidateTrustCandidate(
            metadata.RootKeyId,
            metadata.RootPublicKeyFingerprint,
            publicKeyPath);
    }

    private static TrustCandidate ValidateTrustCandidate(
        string rootKeyId,
        string expectedFingerprint,
        string sourcePath)
    {
        if (!RootKeyIdPattern().IsMatch(rootKeyId))
        {
            throw new ArgumentException("installer-root-key-id-invalid");
        }

        if (!RootFingerprintPattern().IsMatch(expectedFingerprint))
        {
            throw new ArgumentException("installer-root-fingerprint-invalid");
        }

        string absoluteSource = ValidateLocalFixedPath(sourcePath);
        if (!File.Exists(absoluteSource))
        {
            throw new FileNotFoundException("installer-root-public-key-missing", absoluteSource);
        }

        var info = new FileInfo(absoluteSource);
        if (info.Length is <= 0 or > MaximumPublicTrustFileLength)
        {
            throw new CryptographicException("installer-root-public-key-length-invalid");
        }

        string pem = new System.Text.UTF8Encoding(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true)
            .GetString(File.ReadAllBytes(absoluteSource));
        byte[] subjectPublicKeyInfo = Ed25519KeyEncoding.DecodePublicKeyPem(pem);
        string calculatedFingerprint = Ed25519KeyEncoding.Fingerprint(subjectPublicKeyInfo);
        if (!FixedTimeTextEquals(calculatedFingerprint, expectedFingerprint))
        {
            throw new CryptographicException("installer-root-public-key-fingerprint-mismatch");
        }

        return new TrustCandidate(rootKeyId, calculatedFingerprint, absoluteSource);
    }

    private static async Task CopyPublicTrustAtomicallyAsync(string sourcePath, string targetPath)
    {
        byte[] bytes = await File.ReadAllBytesAsync(sourcePath).ConfigureAwait(false);
        string temporary = targetPath + "." + Guid.NewGuid().ToString("N") + ".tmp";
        try
        {
            await using (var stream = new FileStream(
                temporary,
                FileMode.CreateNew,
                FileAccess.Write,
                FileShare.None,
                64 * 1024,
                FileOptions.Asynchronous | FileOptions.WriteThrough))
            {
                await stream.WriteAsync(bytes).ConfigureAwait(false);
                await stream.FlushAsync().ConfigureAwait(false);
                stream.Flush(flushToDisk: true);
            }

            File.Move(temporary, targetPath, overwrite: false);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(bytes);
            if (File.Exists(temporary))
            {
                File.Delete(temporary);
            }
        }
    }

    private static async Task WriteMarkerAsync(
        string markerPath,
        string? createdRootTrustPath,
        string? legacyMigrationId = null,
        bool legacyMigrationAttempted = false)
    {
        string directory = Path.GetDirectoryName(markerPath)
            ?? throw new InvalidOperationException("installer-marker-path-invalid");
        var store = new AtomicFileStore(directory);
        await store.WriteJsonAsync(
            Path.GetFileName(markerPath),
            new BootstrapMarker(
                createdRootTrustPath,
                legacyMigrationId,
                legacyMigrationAttempted)).ConfigureAwait(false);
    }

    private static async Task RollbackLegacyMigrationIfPresentAsync(
        string productRoot,
        LegacyWindowsWorkerMigrator migrator,
        string? migrationId)
    {
        if (string.IsNullOrWhiteSpace(migrationId))
        {
            var state = new AtomicFileStore(Path.Combine(productRoot, "state"));
            LegacyWindowsMigrationJournal? journal = await state
                .ReadJsonAsync<LegacyWindowsMigrationJournal>(
                    LegacyWindowsWorkerPaths.TargetMigrationJournalRelativePath)
                .ConfigureAwait(false);
            migrationId = journal?.MigrationId;
        }

        if (!string.IsNullOrWhiteSpace(migrationId))
        {
            await migrator.RollbackAsync(productRoot, migrationId).ConfigureAwait(false);
        }
    }

    private static string? ReadCreatedRootTrustPath(string markerPath)
    {
        try
        {
            if (!File.Exists(markerPath) || new FileInfo(markerPath).Length == 0)
            {
                return null;
            }

            return ReadBootstrapMarker(markerPath)?.CreatedRootTrustPath;
        }
        catch (JsonException)
        {
            return null;
        }
    }

    private static BootstrapMarker? ReadBootstrapMarker(string markerPath)
    {
        try
        {
            if (!File.Exists(markerPath) || new FileInfo(markerPath).Length == 0)
            {
                return null;
            }

            return JsonSerializer.Deserialize<BootstrapMarker>(
                File.ReadAllBytes(markerPath),
                JsonOptions);
        }
        catch (JsonException)
        {
            return null;
        }
    }

    private static string RequiredJsonString(JsonElement value, string propertyName) =>
        value.ValueKind == JsonValueKind.Object
        && value.TryGetProperty(propertyName, out JsonElement property)
        && property.ValueKind == JsonValueKind.String
        && !string.IsNullOrWhiteSpace(property.GetString())
            ? property.GetString()!
            : throw new InvalidOperationException("installer-legacy-trust-state-invalid");

    private static bool FixedTimeTextEquals(string left, string right)
    {
        byte[] leftBytes = System.Text.Encoding.ASCII.GetBytes(left);
        byte[] rightBytes = System.Text.Encoding.ASCII.GetBytes(right);
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

    private static void ProtectConfigurationFile(
        string path,
        SecurityIdentifier ownerSid,
        SecurityIdentifier serviceSid)
    {
        var security = new FileSecurity();
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        security.SetOwner(serviceSid);
        AddFileRule(security, serviceSid, FileSystemRights.FullControl);
        AddFileRule(security, SystemSid, FileSystemRights.FullControl);
        AddFileRule(security, AdministratorsSid, FileSystemRights.FullControl);
        AddFileRule(security, ownerSid, FileSystemRights.ReadAndExecute | FileSystemRights.ReadPermissions);
        new FileInfo(path).SetAccessControl(security);
    }

    private static void GrantOwnerReadProductRoot(string path, SecurityIdentifier ownerSid)
    {
        var directory = new DirectoryInfo(path);
        DirectorySecurity security = directory.GetAccessControl();
        security.AddAccessRule(new FileSystemAccessRule(
            ownerSid,
            FileSystemRights.ReadAndExecute | FileSystemRights.ListDirectory | FileSystemRights.ReadPermissions,
            InheritanceFlags.None,
            PropagationFlags.None,
            AccessControlType.Allow));
        directory.SetAccessControl(security);
    }

    private static void AddFileRule(
        FileSecurity security,
        SecurityIdentifier sid,
        FileSystemRights rights) =>
        security.AddAccessRule(new FileSystemAccessRule(sid, rights, AccessControlType.Allow));

    private static SecurityIdentifier ValidateOwnerSid(string value)
    {
        if (!SidPattern().IsMatch(value))
        {
            throw new ArgumentException("installer-owner-sid-invalid", nameof(value));
        }

        var sid = new SecurityIdentifier(value);
        if (RefusedOwnerSids.Contains(sid.Value))
        {
            throw new ArgumentException("installer-owner-sid-service-account-refused", nameof(value));
        }

        return sid;
    }

    private static string ValidateLocalFixedPath(string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        if (!Path.IsPathFullyQualified(path) || path.StartsWith("\\\\", StringComparison.Ordinal))
        {
            throw new ArgumentException("installer-product-root-invalid", nameof(path));
        }

        string fullPath = Path.GetFullPath(path);
        string root = Path.GetPathRoot(fullPath)
            ?? throw new ArgumentException("installer-product-root-invalid", nameof(path));
        if (new DriveInfo(root).DriveType != DriveType.Fixed)
        {
            throw new ArgumentException("installer-product-root-volume-invalid", nameof(path));
        }

        RejectReparsePoints(fullPath);
        return fullPath;
    }

    private static void RejectReparsePoints(string path)
    {
        for (string? current = path; !string.IsNullOrEmpty(current); current = Path.GetDirectoryName(current))
        {
            if ((File.Exists(current) || Directory.Exists(current)) &&
                (File.GetAttributes(current) & FileAttributes.ReparsePoint) != 0)
            {
                throw new IOException("installer-reparse-point-refused");
            }

            string? parent = Path.GetDirectoryName(current);
            if (string.Equals(parent, current, StringComparison.OrdinalIgnoreCase))
            {
                break;
            }
        }
    }

    private static string CreateNodeId(string machineName) =>
        $"windows-{SanitizeMachineName(machineName).ToLowerInvariant()}-{Guid.NewGuid():N}";

    private static string SanitizeMachineName(string value)
    {
        string sanitized = MachineNameCharacters().Replace(value, "-").Trim('-');
        return string.IsNullOrWhiteSpace(sanitized) ? "device" : sanitized[..Math.Min(64, sanitized.Length)];
    }

    private static string IdentityPurpose(string nodeId) => $"operational-identity:{nodeId}";

    private static void DeleteBootstrapArtifacts(
        string configPath,
        string identityPath,
        string markerPath,
        string? createdRootTrustPath)
    {
        DeleteFile(configPath);
        DeleteFile(identityPath);
        if (createdRootTrustPath is not null)
        {
            DeleteFile(createdRootTrustPath);
            DeleteIfEmpty(Path.GetDirectoryName(createdRootTrustPath));
        }
        DeleteFile(markerPath);
        DeleteIfEmpty(Path.GetDirectoryName(identityPath));
        DeleteIfEmpty(Path.GetDirectoryName(Path.GetDirectoryName(identityPath)));
    }

    private static void DeleteFile(string path)
    {
        if (!File.Exists(path))
        {
            return;
        }

        RejectReparsePoints(path);
        File.Delete(path);
    }

    private static void DeleteIfEmpty(string? path)
    {
        if (!string.IsNullOrEmpty(path) && Directory.Exists(path) && !Directory.EnumerateFileSystemEntries(path).Any())
        {
            Directory.Delete(path);
        }
    }

    private static void TryDeleteTree(string path)
    {
        try
        {
            if (Directory.Exists(path))
            {
                Directory.Delete(path, recursive: true);
            }
        }
        catch (IOException)
        {
        }
        catch (UnauthorizedAccessException)
        {
        }
    }

    private static InstallerOptions ParseOptions(string[] args)
    {
        if (args.Length < 3 || args.Length % 2 == 0)
        {
            throw new ArgumentException("installer-arguments-invalid");
        }

        string command = args[0];
        var values = new Dictionary<string, string>(StringComparer.Ordinal);
        for (int index = 1; index < args.Length; index += 2)
        {
            if (!args[index].StartsWith("--", StringComparison.Ordinal) ||
                !values.TryAdd(args[index][2..], args[index + 1]))
            {
                throw new ArgumentException("installer-arguments-invalid");
            }
        }

        string productRoot = Required(values, "product-root");
        if (command is "rollback" or "commit" or "maintenance-preflight")
        {
            if (values.Count != 1)
            {
                throw new ArgumentException("installer-arguments-invalid");
            }

            return new InstallerOptions(command, productRoot, string.Empty, string.Empty);
        }

        if (command != "bootstrap")
        {
            throw new ArgumentException("installer-arguments-invalid");
        }

        string? rootKeyId = Optional(values, "root-key-id");
        string? rootFingerprint = Optional(values, "root-public-key-fingerprint");
        string? rootPublicKeyPath = Optional(values, "root-public-key-path");
        int trustOptionCount = (rootKeyId is null ? 0 : 1)
            + (rootFingerprint is null ? 0 : 1)
            + (rootPublicKeyPath is null ? 0 : 1);
        if (values.Count != 4 + trustOptionCount || trustOptionCount is not (0 or 3))
        {
            throw new ArgumentException("installer-root-trust-options-incomplete");
        }

        InstallerInstallMode installMode = Required(values, "install-mode") switch
        {
            "fresh" => InstallerInstallMode.Fresh,
            "upgrade" => InstallerInstallMode.Upgrade,
            _ => throw new ArgumentException("installer-install-mode-invalid"),
        };

        return new InstallerOptions(
            command,
            productRoot,
            Required(values, "owner-sid"),
            Required(values, "machine-name"),
            installMode,
            rootKeyId,
            rootFingerprint,
            rootPublicKeyPath);
    }

    private static string Required(IReadOnlyDictionary<string, string> values, string key) =>
        values.TryGetValue(key, out string? value) && !string.IsNullOrWhiteSpace(value)
            ? value
            : throw new ArgumentException("installer-arguments-invalid");

    private static string? Optional(IReadOnlyDictionary<string, string> values, string key) =>
        values.TryGetValue(key, out string? value) && !string.IsNullOrWhiteSpace(value) ? value : null;

    private static int Fail(string code)
    {
        Console.Error.WriteLine(code);
        return 2;
    }

    private sealed record InstallerOptions(
        string Command,
        string ProductRoot,
        string OwnerSid,
        string MachineName,
        InstallerInstallMode InstallMode = InstallerInstallMode.Fresh,
        string? RootKeyId = null,
        string? RootPublicKeyFingerprint = null,
        string? RootPublicKeyPath = null);

    private enum InstallerInstallMode
    {
        Fresh,
        Upgrade,
    }

    private sealed record BootstrapConfiguration(
        int SchemaVersion,
        string NodeId,
        string WorkerName,
        string KeyId,
        string OwnerSid,
        string? RootKeyId,
        string? RootPublicKeyFingerprint,
        string? RootPublicKeyPath,
        Uri OrchestratorBaseUri,
        Uri OllamaBaseUri,
        int LastNonZeroMaxConcurrentJobs,
        int ClaimBatchSize,
        int ManifestCapacityLimit,
        int LocalResourceLimit,
        string StateRoot);

    private sealed record RootTrustPins(
        string RootKeyId,
        string RootPublicKeyFingerprint,
        string RootPublicKeyPath);

    private sealed record TrustCandidate(
        string RootKeyId,
        string RootPublicKeyFingerprint,
        string SourcePath);

    private sealed record BootstrapMarker(
        string? CreatedRootTrustPath,
        string? LegacyMigrationId,
        bool LegacyMigrationAttempted);

    private sealed record PackagedRootTrustMetadata(
        string Schema,
        string RootKeyId,
        string RootPublicKeyFingerprint,
        string PublicKeyFileName);

    private static JsonSerializerOptions JsonOptions { get; } = new(JsonSerializerDefaults.Web)
    {
        AllowTrailingCommas = false,
        MaxDepth = 32,
        PropertyNameCaseInsensitive = false,
        ReadCommentHandling = JsonCommentHandling.Disallow,
        UnmappedMemberHandling = System.Text.Json.Serialization.JsonUnmappedMemberHandling.Disallow,
        WriteIndented = true,
    };

    [GeneratedRegex("^S-1-(?:[0-9]+-){1,14}[0-9]+$", RegexOptions.CultureInvariant)]
    private static partial Regex SidPattern();

    [GeneratedRegex("[^A-Za-z0-9_.-]+", RegexOptions.CultureInvariant)]
    private static partial Regex MachineNameCharacters();

    [GeneratedRegex("^[A-Za-z0-9][A-Za-z0-9._:/-]{0,159}$", RegexOptions.CultureInvariant)]
    private static partial Regex RootKeyIdPattern();

    [GeneratedRegex("^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$", RegexOptions.CultureInvariant)]
    private static partial Regex WorkerNodeIdPattern();

    [GeneratedRegex("^SHA256:[A-Za-z0-9_-]{43}$", RegexOptions.CultureInvariant)]
    private static partial Regex RootFingerprintPattern();
}
