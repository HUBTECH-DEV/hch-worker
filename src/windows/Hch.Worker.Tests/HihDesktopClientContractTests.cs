using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Hch.Worker.Tray;

namespace Hch.Worker.Tests;

public sealed class HihDesktopClientContractTests
{
    [Fact]
    public void DiscoveryV11RequiresTheHchAudienceAndTenantBinding()
    {
        byte[] payload = DiscoveryPayload();

        HihDesktopClient.ValidateDiscoveryContract(payload);
    }

    [Theory]
    [InlineData("\"schemaVersion\":\"1.1\"", "\"schemaVersion\":\"1.0\"")]
    [InlineData("\"audience\":\"hch\"", "\"audience\":\"other\"")]
    [InlineData("\"membershipRequired\":true", "\"membershipRequired\":false")]
    public void DiscoveryRejectsDowngradeOrResourceSubstitution(string expected, string replacement)
    {
        string tampered = Encoding.UTF8.GetString(DiscoveryPayload())
            .Replace(expected, replacement, StringComparison.Ordinal);

        Assert.Throws<HihDesktopAuthenticationException>(() =>
            HihDesktopClient.ValidateDiscoveryContract(Encoding.UTF8.GetBytes(tampered)));
    }

    [Fact]
    public void DiscoveryRejectsUnknownFields()
    {
        string tampered = Encoding.UTF8.GetString(DiscoveryPayload())
            .Replace("\"issuer\":", "\"unexpected\":true,\"issuer\":", StringComparison.Ordinal);

        Assert.Throws<JsonException>(() =>
            HihDesktopClient.ValidateDiscoveryContract(Encoding.UTF8.GetBytes(tampered)));
    }

    [Fact]
    public void DiscoveryRejectsMissingRequiredObjectsWithoutNullDereference()
    {
        JsonObject document = JsonNode.Parse(DiscoveryPayload())!.AsObject();
        document["resource"] = null;

        Assert.Throws<HihDesktopAuthenticationException>(() =>
            HihDesktopClient.ValidateDiscoveryContract(
                Encoding.UTF8.GetBytes(document.ToJsonString())));
    }

    private static byte[] DiscoveryPayload() => Encoding.UTF8.GetBytes("""
        {
          "schemaVersion":"1.1",
          "issuer":"https://hah.hubtech.online/api/v1",
          "resource":{
            "audience":"hch",
            "tenantId":"376e89e2-8fa2-4d50-bd52-a7deb40f7ff2",
            "tenantName":"Hubtech Community Hub",
            "tenantSlug":"hubtech-community-hub",
            "membershipRequired":true
          },
          "client":{
            "clientId":"hch-worker-windows",
            "clientType":"public",
            "clientSecretRequired":false,
            "redirectUriPattern":"http://127.0.0.1:{dynamicPort}/callback"
          },
          "capabilities":{
            "authorizationCodePkce":true,
            "pkceCodeChallengeMethods":["S256"],
            "deviceCode":false,
            "nativePassword":true,
            "mfaVerification":false,
            "mfaRequiredPolicy":"fail-closed"
          },
          "endpoints":{
            "authorization":"https://hah.hubtech.online/api/v1/native-auth/authorize",
            "token":"https://hah.hubtech.online/api/v1/native-auth/token",
            "revoke":"https://hah.hubtech.online/api/v1/native-auth/revoke",
            "session":"https://hah.hubtech.online/api/v1/native-auth/session",
            "nativePassword":"https://hah.hubtech.online/api/v1/native-auth/password",
            "deviceAuthorization":null,
            "workerSshKeyChallenge":"https://hah.hubtech.online/api/v1/hch/worker-ssh-keys/challenges",
            "workerSshKeyRegistration":"https://hah.hubtech.online/api/v1/hch/worker-ssh-keys",
            "login":"https://hah.hubtech.online/login",
            "passwordRecovery":"https://hah.hubtech.online/forgot-password",
            "createAccount":"https://hah.hubtech.online/create-account"
          },
          "token":{
            "type":"Bearer",
            "format":"opaque",
            "ttlSeconds":600,
            "audience":"hch",
            "scope":"hch.worker.enroll.self",
            "refreshTokenIssued":false
          },
          "proofOfPossession":{
            "algorithm":"Ed25519",
            "canonicalization":"RFC8785",
            "signatureEncoding":"base64url-no-padding",
            "challengeTtlSeconds":120
          }
        }
        """);
}
