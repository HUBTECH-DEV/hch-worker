using System.IO.Pipes;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using Hch.Worker.Windows;

namespace Hch.Worker.Tests;

public sealed class WindowsPlatformTests
{
    [Fact]
    public void PipeAclContainsOnlyTheAuthorizedOwnerAndServiceGroups()
    {
        SecurityIdentifier owner = WindowsServiceIdentity.GetCurrentUserSid();
        var service = new SecurityIdentifier("S-1-5-80-1-2-3-4-5");
        var system = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
        var administrators = new SecurityIdentifier(
            WellKnownSidType.BuiltinAdministratorsSid,
            null);

        PipeSecurity security = WindowsAcl.CreateLocalPipeSecurity(owner, service);
        AuthorizationRuleCollection accessRules = security.GetAccessRules(
            includeExplicit: true,
            includeInherited: false,
            typeof(SecurityIdentifier));
        var rules = accessRules.Cast<PipeAccessRule>().ToArray();

        Assert.True(security.AreAccessRulesProtected);
        Assert.Equal(service, security.GetOwner(typeof(SecurityIdentifier)));
        Assert.Equal(4, rules.Length);
        Assert.Contains(rules, rule => Allows(rule, owner, PipeAccessRights.ReadWrite));
        Assert.Contains(rules, rule => Allows(rule, service, PipeAccessRights.FullControl));
        Assert.Contains(rules, rule => Allows(rule, system, PipeAccessRights.FullControl));
        Assert.Contains(rules, rule => Allows(rule, administrators, PipeAccessRights.FullControl));
        Assert.DoesNotContain(rules, rule => rule.AccessControlType == AccessControlType.Deny);
    }

    [Fact]
    public void DuplicateOwnerAndServiceSidIsPromotedToFullControl()
    {
        SecurityIdentifier current = WindowsServiceIdentity.GetCurrentUserSid();
        PipeSecurity security = WindowsAcl.CreateLocalPipeSecurity(current, current);
        AuthorizationRuleCollection accessRules = security.GetAccessRules(
            includeExplicit: true,
            includeInherited: false,
            typeof(SecurityIdentifier));

        PipeAccessRule currentRule = Assert.Single(
            accessRules.Cast<PipeAccessRule>(),
            rule => rule.IdentityReference.Equals(current));
        Assert.Equal(PipeAccessRights.FullControl, currentRule.PipeAccessRights);
    }

    [Fact]
    public async Task LocalNamedPipeAuthenticatesTheConnectedClientSid()
    {
        SecurityIdentifier current = WindowsServiceIdentity.GetCurrentUserSid();
        string pipeName = $"hch-worker-test-{Guid.NewGuid():N}";
        await using NamedPipeServerStream server = LocalNamedPipe.CreateServer(
            pipeName,
            current,
            current);
        await using NamedPipeClientStream client = LocalNamedPipe.CreateClient(pipeName);
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));

        Task waitForConnection = server.WaitForConnectionAsync(timeout.Token);
        Task connect = client.ConnectAsync(timeout.Token);
        await Task.WhenAll(waitForConnection, connect);

        NamedPipePeerIdentity peer = LocalNamedPipe.GetClientIdentity(server);
        Assert.Equal(current, peer.Sid);
        Assert.NotNull(peer.ProcessId);
        Assert.Equal(Environment.ProcessId, checked((int)peer.ProcessId.GetValueOrDefault()));
        LocalNamedPipe.EnsureOwner(server, current);

        NamedPipeServerIdentity serverIdentity = LocalNamedPipe.GetServerIdentity(client);
        Assert.Equal(Environment.ProcessId, checked((int)serverIdentity.ProcessId));
        Assert.NotNull(serverIdentity.SessionId);
    }

    [Fact]
    public void PipeServerPolicyRequiresStableScmPidSystemIdentityImageAclAndSignature()
    {
        var system = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
        var service = new SecurityIdentifier("S-1-5-80-1-2-3-4-5");
        const string image = @"C:\Program Files\HubTech\HCH Worker\Hch.Worker.Service.exe";
        var valid = new WindowsPipeServerEvidence(
            "HchWorker",
            4242,
            4242,
            0,
            4242,
            4242,
            4,
            0x10,
            "LocalSystem",
            system,
            service,
            image,
            image,
            ImageDaclSafe: true,
            AuthenticodeTrusted: true);

        WindowsPipeServerSecurityPolicy.Validate(valid);
        WindowsPipeServerSecurityPolicy.Validate(valid with
        {
            ServiceStartName = @"NT SERVICE\HchWorker",
            ProcessUserSid = service,
        });
        Assert.Throws<UnauthorizedAccessException>(() =>
            WindowsPipeServerSecurityPolicy.Validate(valid with { PipeProcessIdAfter = 4243 }));
        Assert.Throws<UnauthorizedAccessException>(() =>
            WindowsPipeServerSecurityPolicy.Validate(valid with { ServiceProcessIdBefore = 4243 }));
        Assert.Throws<UnauthorizedAccessException>(() =>
            WindowsPipeServerSecurityPolicy.Validate(valid with
            {
                ProcessUserSid = new SecurityIdentifier(WellKnownSidType.WorldSid, null),
            }));
        Assert.Throws<UnauthorizedAccessException>(() =>
            WindowsPipeServerSecurityPolicy.Validate(valid with { PipeSessionId = 1 }));
        Assert.Throws<UnauthorizedAccessException>(() =>
            WindowsPipeServerSecurityPolicy.Validate(valid with
            {
                ServiceStartName = @"NT SERVICE\AnotherService",
                ProcessUserSid = service,
            }));
        Assert.Throws<UnauthorizedAccessException>(() =>
            WindowsPipeServerSecurityPolicy.Validate(valid with
            {
                ProcessImagePath = @"C:\Temp\Hch.Worker.Service.exe",
            }));
        Assert.Throws<UnauthorizedAccessException>(() =>
            WindowsPipeServerSecurityPolicy.Validate(valid with { ImageDaclSafe = false }));
        Assert.Throws<UnauthorizedAccessException>(() =>
            WindowsPipeServerSecurityPolicy.Validate(valid with { AuthenticodeTrusted = false }));
    }

    [Fact]
    public void TelemetryUsesNullForUnavailableOrInvalidMeasurements()
    {
        using var collector = new WindowsTelemetryCollector(
            gpuProvider: new InvalidGpuTelemetryProvider());

        WindowsTelemetrySnapshot first = collector.Collect();
        WindowsTelemetrySnapshot second = collector.Collect();

        Assert.Equal(Environment.ProcessId, first.ProcessId);
        Assert.Null(first.ProcessCpuPercent);
        Assert.Null(first.SystemCpuPercent);
        Assert.Null(first.GpuPercent);
        Assert.Equal(512UL, first.VramUsedBytes);
        Assert.True(first.ProcessWorkingSetBytes is null or > 0);
        Assert.True(first.TotalMemoryBytes is null or > 0);
        Assert.True(first.NetworkReceivedBytes is null or >= 0);
        Assert.True(first.NetworkSentBytes is null or >= 0);
        Assert.True(second.ProcessCpuPercent is null or >= 0 and <= 100);
        Assert.True(second.SystemCpuPercent is null or >= 0 and <= 100);
    }

    [Fact]
    public void CredentialTargetsAreNamespacedAndRejectArbitraryNames()
    {
        Assert.Equal(
            "HubTech/HCH/Worker/token/enrollment-01",
            RevocableCredentialTokenStore.CreateTarget("enrollment-01"));
        Assert.Throws<ArgumentException>(() =>
            RevocableCredentialTokenStore.CreateTarget("../another-target"));
        Assert.Throws<ArgumentException>(() =>
            RevocableCredentialTokenStore.CreateTarget("password:account"));
    }

    [Fact]
    public void CredentialManagerRoundTripIsExplicitlyOptInAndRevocable()
    {
        if (!string.Equals(
                Environment.GetEnvironmentVariable("HCH_TEST_CREDENTIAL_MANAGER"),
                "1",
                StringComparison.Ordinal))
        {
            return;
        }

        var store = new RevocableCredentialTokenStore();
        string tokenId = $"test-{Guid.NewGuid():N}";
        byte[] expected = RandomNumberGenerator.GetBytes(32);
        byte[]? copy = null;
        try
        {
            store.Store(tokenId, expected);
            using RevocableTokenSecret secret = Assert.IsType<RevocableTokenSecret>(
                store.Read(tokenId));
            copy = secret.CopySecret();

            Assert.Equal(expected, copy);
            Assert.Equal(expected.Length, secret.Length);
            Assert.Equal("[REDACTED]", secret.ToString());
            Assert.True(store.Revoke(tokenId));
            Assert.Null(store.Read(tokenId));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(expected);
            if (copy is not null)
            {
                CryptographicOperations.ZeroMemory(copy);
            }

            _ = store.Revoke(tokenId);
        }
    }

    private static bool Allows(
        PipeAccessRule rule,
        SecurityIdentifier sid,
        PipeAccessRights expected) =>
        rule.AccessControlType == AccessControlType.Allow
        && rule.IdentityReference.Equals(sid)
        && (rule.PipeAccessRights & expected) == expected;

    private sealed class InvalidGpuTelemetryProvider : IGpuTelemetryProvider
    {
        public GpuTelemetry Collect() => new(double.NaN, 512);
    }
}
