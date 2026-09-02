[CmdletBinding()]
param(
    [uri]$HihDiscoveryUri = 'https://hah.hubtech.online/api/v1/native-auth/discovery',
    [uri]$HchBaseUri = 'https://hubtech.online/'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$maximumResponseBytes = 256KB

function Assert-HttpsUri([uri]$Value, [string]$Label) {
    if (-not $Value.IsAbsoluteUri -or $Value.Scheme -cne 'https' -or
        -not [string]::IsNullOrEmpty($Value.UserInfo) -or
        -not [string]::IsNullOrEmpty($Value.Fragment)) {
        throw "$Label must be an absolute HTTPS URI without user-info or fragment."
    }
}

function Assert-ExactProperties($Value, [string[]]$Expected, [string]$Path) {
    if ($null -eq $Value) { throw "$Path must be an object." }
    $actual = @($Value.PSObject.Properties.Name | Sort-Object)
    $expectedNames = @($Expected | Sort-Object)
    if (($actual -join "`n") -cne ($expectedNames -join "`n")) {
        throw "$Path has unexpected or missing properties."
    }
}

function Read-BoundedResponse(
    [Net.Http.HttpClient]$Client,
    [Net.Http.HttpMethod]$Method,
    [uri]$Uri
) {
    $request = [Net.Http.HttpRequestMessage]::new($Method, $Uri)
    try {
        $response = $Client.SendAsync(
            $request,
            [Net.Http.HttpCompletionOption]::ResponseHeadersRead).GetAwaiter().GetResult()
        try {
            if ($response.Headers.Location) {
                throw "Redirects are forbidden while probing $Uri."
            }
            if ($response.Content.Headers.ContentLength -gt $maximumResponseBytes) {
                throw "Response from $Uri exceeds the bounded size."
            }

            $stream = $response.Content.ReadAsStream()
            try {
                $output = [IO.MemoryStream]::new()
                try {
                    $buffer = [byte[]]::new(8192)
                    while (($read = $stream.Read($buffer, 0, $buffer.Length)) -gt 0) {
                        if ($output.Length + $read -gt $maximumResponseBytes) {
                            throw "Response from $Uri exceeds the bounded size."
                        }
                        $output.Write($buffer, 0, $read)
                    }
                    $contentType = $response.Content.Headers.ContentType
                    return [pscustomobject]@{
                        Status = [int]$response.StatusCode
                        ContentType = if ($null -eq $contentType) { '' } else { [string]$contentType.MediaType }
                        Bytes = $output.ToArray()
                    }
                } finally {
                    $output.Dispose()
                }
            } finally {
                $stream.Dispose()
            }
        } finally {
            $response.Dispose()
        }
    } finally {
        $request.Dispose()
    }
}

Assert-HttpsUri $HihDiscoveryUri 'HIH discovery URI'
Assert-HttpsUri $HchBaseUri 'HCH base URI'
if ($HihDiscoveryUri.AbsolutePath -cne '/api/v1/native-auth/discovery' -or
    $HihDiscoveryUri.Query.Length -ne 0 -or $HchBaseUri.Query.Length -ne 0) {
    throw 'Onboarding probe paths must be canonical and query-free.'
}

$handler = [Net.Http.HttpClientHandler]::new()
$handler.AllowAutoRedirect = $false
$handler.AutomaticDecompression = [Net.DecompressionMethods]::None
$handler.UseCookies = $false
$client = [Net.Http.HttpClient]::new($handler)
$client.Timeout = [TimeSpan]::FromSeconds(15)
$client.DefaultRequestHeaders.UserAgent.ParseAdd('HCH-Worker-Readiness/4.0.0')

try {
    $discoveryResponse = Read-BoundedResponse $client ([Net.Http.HttpMethod]::Get) $HihDiscoveryUri
    if ($discoveryResponse.Status -ne 200 -or
        $discoveryResponse.ContentType -cne 'application/json' -or
        $discoveryResponse.Bytes.Length -eq 0) {
        throw "HIH native discovery is unavailable (HTTP $($discoveryResponse.Status))."
    }

    $utf8 = [Text.UTF8Encoding]::new($false, $true)
    $raw = $utf8.GetString($discoveryResponse.Bytes)
    if ($raw[0] -eq [char]0xFEFF) { throw 'HIH discovery must be UTF-8 without BOM.' }
    $discovery = $raw | ConvertFrom-Json -Depth 30
    Assert-ExactProperties $discovery @(
        'schemaVersion', 'issuer', 'resource', 'client', 'capabilities',
        'endpoints', 'token', 'proofOfPossession') '$'
    Assert-ExactProperties $discovery.resource @(
        'audience', 'tenantId', 'tenantName', 'tenantSlug', 'membershipRequired') '$.resource'
    Assert-ExactProperties $discovery.client @(
        'clientId', 'clientType', 'clientSecretRequired', 'redirectUriPattern') '$.client'
    Assert-ExactProperties $discovery.capabilities @(
        'authorizationCodePkce', 'pkceCodeChallengeMethods', 'deviceCode',
        'nativePassword', 'mfaVerification', 'mfaRequiredPolicy') '$.capabilities'
    Assert-ExactProperties $discovery.endpoints @(
        'authorization', 'token', 'revoke', 'session', 'nativePassword',
        'deviceAuthorization', 'workerSshKeyChallenge', 'workerSshKeyRegistration',
        'login', 'passwordRecovery', 'createAccount') '$.endpoints'
    Assert-ExactProperties $discovery.token @(
        'type', 'format', 'ttlSeconds', 'audience', 'scope', 'refreshTokenIssued') '$.token'
    Assert-ExactProperties $discovery.proofOfPossession @(
        'algorithm', 'canonicalization', 'signatureEncoding', 'challengeTtlSeconds') '$.proofOfPossession'

    $issuer = [uri]'https://hah.hubtech.online/api/v1'
    $tenantId = [guid]::Empty
    $expectedEndpoints = [ordered]@{
        authorization = "$issuer/native-auth/authorize"
        token = "$issuer/native-auth/token"
        revoke = "$issuer/native-auth/revoke"
        session = "$issuer/native-auth/session"
        nativePassword = "$issuer/native-auth/password"
        workerSshKeyChallenge = "$issuer/hch/worker-ssh-keys/challenges"
        workerSshKeyRegistration = "$issuer/hch/worker-ssh-keys"
    }
    $contractValid =
        [string]$discovery.schemaVersion -ceq '1.1' -and
        [string]$discovery.issuer -ceq $issuer.AbsoluteUri.TrimEnd('/') -and
        [string]$discovery.resource.audience -ceq 'hch' -and
        [guid]::TryParseExact([string]$discovery.resource.tenantId, 'D', [ref]$tenantId) -and
        $tenantId -ne [guid]::Empty -and
        $discovery.resource.membershipRequired -eq $true -and
        [string]$discovery.client.clientId -ceq 'hch-worker-windows' -and
        [string]$discovery.client.clientType -ceq 'public' -and
        $discovery.client.clientSecretRequired -eq $false -and
        [string]$discovery.client.redirectUriPattern -ceq 'http://127.0.0.1:{dynamicPort}/callback' -and
        $discovery.capabilities.authorizationCodePkce -eq $true -and
        @($discovery.capabilities.pkceCodeChallengeMethods).Count -eq 1 -and
        [string]$discovery.capabilities.pkceCodeChallengeMethods[0] -ceq 'S256' -and
        $discovery.capabilities.deviceCode -eq $false -and
        $discovery.capabilities.nativePassword -eq $true -and
        $discovery.capabilities.mfaVerification -eq $false -and
        [string]$discovery.capabilities.mfaRequiredPolicy -ceq 'fail-closed' -and
        $null -eq $discovery.endpoints.deviceAuthorization -and
        [string]$discovery.token.type -ceq 'Bearer' -and
        [string]$discovery.token.format -ceq 'opaque' -and
        [int]$discovery.token.ttlSeconds -ge 60 -and [int]$discovery.token.ttlSeconds -le 3600 -and
        [string]$discovery.token.audience -ceq 'hch' -and
        [string]$discovery.token.scope -ceq 'hch.worker.enroll.self' -and
        $discovery.token.refreshTokenIssued -eq $false -and
        [string]$discovery.proofOfPossession.algorithm -ceq 'Ed25519' -and
        [string]$discovery.proofOfPossession.canonicalization -ceq 'RFC8785' -and
        [string]$discovery.proofOfPossession.signatureEncoding -ceq 'base64url-no-padding' -and
        [int]$discovery.proofOfPossession.challengeTtlSeconds -ge 30 -and
        [int]$discovery.proofOfPossession.challengeTtlSeconds -le 600
    if (-not $contractValid) { throw 'HIH native discovery contract is incompatible with Worker 4.0.0.' }
    foreach ($name in $expectedEndpoints.Keys) {
        if ([string]$discovery.endpoints.$name -cne [string]$expectedEndpoints[$name]) {
            throw "HIH discovery endpoint $name is not canonical."
        }
    }
    foreach ($name in 'login', 'passwordRecovery', 'createAccount') {
        $page = [uri][string]$discovery.endpoints.$name
        if (-not $page.IsAbsoluteUri -or $page.Scheme -cne 'https' -or
            $page.Host -cne 'hah.hubtech.online') {
            throw "HIH discovery page $name is outside the approved HAH origin."
        }
    }

    $routeStatuses = [ordered]@{}
    foreach ($relativePath in @(
            'api/editorial/orchestrator/enrollment/challenge',
            'api/editorial/orchestrator/enrollment/self-token')) {
        $uri = [uri]::new($HchBaseUri, $relativePath)
        $probe = Read-BoundedResponse $client ([Net.Http.HttpMethod]::Get) $uri
        if ($probe.Status -notin 401, 403, 405) {
            throw "Protected HCH onboarding route $relativePath is unavailable (HTTP $($probe.Status))."
        }
        $routeStatuses[$relativePath] = $probe.Status
    }

    [pscustomobject]@{
        schema = 'hch.worker-onboarding-readiness/v1'
        status = 'ready'
        discovery = $HihDiscoveryUri.AbsoluteUri
        tenantId = $tenantId.ToString('D')
        hchProtectedRouteStatuses = $routeStatuses
        checkedAtUtc = [DateTimeOffset]::UtcNow.ToString('O')
    } | ConvertTo-Json -Depth 5 -Compress
} finally {
    $client.Dispose()
    $handler.Dispose()
}
