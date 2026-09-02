[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidatePattern('^\d+\.\d+\.\d+$')]
    [string]$Version,

    [Parameter(Mandatory)]
    [ValidatePattern('^[A-Fa-f0-9]{40}$')]
    [string]$ExpectedSignerThumbprint,

    [Parameter(Mandatory)]
    [ValidatePattern('^[A-Fa-f0-9]{64}$')]
    [string]$ExpectedSignerCertificateSha256,

    [ValidateSet('Candidate')]
    [string]$ReleaseIntent = 'Candidate',

    [string]$TimestampUrl = 'http://timestamp.digicert.com',
    [string]$MsiE2eEvidencePath,
    [switch]$RequireDefender
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$repositoryRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\..')).Path
$windowsRoot = Join-Path $repositoryRoot 'src\windows'
$artifactRoot = Join-Path $repositoryRoot 'artifacts\windows-v4'
$workRoot = Join-Path $artifactRoot 'work'
$releaseRoot = Join-Path $artifactRoot 'release'
$securityWork = Join-Path $workRoot 'security'
$securityRelease = Join-Path $releaseRoot 'security'
$preparationPath = Join-Path $workRoot 'package-preparation.json'
$payloadReceiptPath = Join-Path $workRoot 'signed-payloads.json'
$unsignedMsiReceiptPath = Join-Path $workRoot 'unsigned-msi.json'
$signedMsiReceiptPath = Join-Path $workRoot 'signed-msi.json'
$msiName = "HCH-Worker-$Version-win-x64.msi"
$msiPath = Join-Path $releaseRoot $msiName
$expectedSignerThumbprint = $ExpectedSignerThumbprint.ToUpperInvariant()
$expectedSignerCertificateSha256 = $ExpectedSignerCertificateSha256.ToUpperInvariant()

function Invoke-Checked {
    param([Parameter(Mandatory)][string]$FilePath, [Parameter(Mandatory)][string[]]$ArgumentList)

    & $FilePath @ArgumentList
    if ($LASTEXITCODE -ne 0) {
        throw "Command failed with exit code ${LASTEXITCODE}: $FilePath"
    }
}

function Read-RequiredJson {
    param([Parameter(Mandatory)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Required release receipt is missing: $Path"
    }
    return Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json -Depth 100
}

function Resolve-PreparedPath {
    param([Parameter(Mandatory)][string]$RelativePath)

    if ($RelativePath -notmatch '^(?:publish|trust)/[A-Za-z0-9_. /+-]+$' -or $RelativePath.Contains('..')) {
        throw "Unsafe prepared path: $RelativePath"
    }
    $candidate = [IO.Path]::GetFullPath((Join-Path $workRoot $RelativePath.Replace('/', '\')))
    $boundary = [IO.Path]::GetFullPath($workRoot).TrimEnd('\') + '\'
    if (-not $candidate.StartsWith($boundary, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Prepared path escaped the work root: $RelativePath"
    }
    return $candidate
}

function Add-TemporarySignerTrust {
    param([Parameter(Mandatory)][Security.Cryptography.X509Certificates.X509Certificate2]$Certificate)

    $added = [System.Collections.Generic.List[string]]::new()
    foreach ($storeName in 'Root', 'TrustedPublisher') {
        $path = "Cert:\CurrentUser\$storeName\$($Certificate.Thumbprint)"
        if (-not (Test-Path -LiteralPath $path)) {
            $publicCopy = [Security.Cryptography.X509Certificates.X509Certificate2]::new($Certificate.Export(
                [Security.Cryptography.X509Certificates.X509ContentType]::Cert))
            $store = [Security.Cryptography.X509Certificates.X509Store]::new(
                $storeName,
                [Security.Cryptography.X509Certificates.StoreLocation]::CurrentUser)
            try {
                $store.Open([Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
                $store.Add($publicCopy)
                $added.Add($path)
            } finally {
                $store.Dispose()
                $publicCopy.Dispose()
            }
        }
    }
    return @($added)
}

function Assert-SignerPolicy {
    param([Parameter(Mandatory)][string]$Path)

    $signature = Get-AuthenticodeSignature -LiteralPath $Path
    if ($signature.Status -ne 'Valid' `
        -or $null -eq $signature.SignerCertificate `
        -or $signature.SignerCertificate.Thumbprint -ne $expectedSignerThumbprint `
        -or $signature.SignerCertificate.GetCertHashString([Security.Cryptography.HashAlgorithmName]::SHA256) -ne $expectedSignerCertificateSha256 `
        -or $null -eq $signature.TimeStamperCertificate) {
        throw "Authenticode signer or timestamp policy failed for ${Path}: $($signature.Status)"
    }
}

foreach ($secretName in 'HCH_SIGN_PFX_BASE64', 'HCH_SIGN_PFX_PASSWORD', 'HCH_SIGN_PFX_PATH') {
    if (-not [string]::IsNullOrWhiteSpace([Environment]::GetEnvironmentVariable($secretName))) {
        throw 'Release evidence must be generated outside the signing-secret boundary.'
    }
}

$preparation = Read-RequiredJson $preparationPath
$payloadReceipt = Read-RequiredJson $payloadReceiptPath
$unsignedMsiReceipt = Read-RequiredJson $unsignedMsiReceiptPath
$signedMsiReceipt = Read-RequiredJson $signedMsiReceiptPath

if ($preparation.schema -ne 'hch.worker-windows-package-preparation/v1' `
    -or $preparation.version -ne $Version `
    -or $preparation.expectedMsi -ne $msiName `
    -or $preparation.releaseIntent -ne $ReleaseIntent.ToLowerInvariant() `
    -or $payloadReceipt.schema -ne 'hch.worker-windows-signed-payloads/v1' `
    -or $unsignedMsiReceipt.schema -ne 'hch.worker-windows-unsigned-msi/v1' `
    -or $signedMsiReceipt.schema -ne 'hch.worker-windows-signed-msi/v1') {
    throw 'Release receipts do not describe the requested product, version and intent.'
}

$preparationSha256 = (Get-FileHash -LiteralPath $preparationPath -Algorithm SHA256).Hash.ToLowerInvariant()
if ($payloadReceipt.version -ne $Version `
    -or $payloadReceipt.sourceCommit -ne $preparation.sourceCommit `
    -or $payloadReceipt.preparationSha256 -ne $preparationSha256 `
    -or $unsignedMsiReceipt.version -ne $Version `
    -or $unsignedMsiReceipt.sourceCommit -ne $preparation.sourceCommit `
    -or $unsignedMsiReceipt.preparationSha256 -ne $preparationSha256 `
    -or $signedMsiReceipt.version -ne $Version `
    -or $signedMsiReceipt.sourceCommit -ne $preparation.sourceCommit `
    -or $signedMsiReceipt.msi -ne $msiName `
    -or $signedMsiReceipt.unsignedSha256 -ne $unsignedMsiReceipt.msiSha256) {
    throw 'Release receipts are not a single, continuous preparation/sign/repack chain.'
}
foreach ($receipt in $payloadReceipt, $signedMsiReceipt) {
    if ($receipt.signerThumbprint -ne $expectedSignerThumbprint `
        -or $receipt.signerCertificateSha256 -ne $expectedSignerCertificateSha256 `
        -or $receipt.timestampUrl -ne $TimestampUrl) {
        throw 'Release receipt does not match the reviewed signer and timestamp policy.'
    }
}

$head = (& git -C $repositoryRoot rev-parse HEAD).Trim()
$dirty = -not [string]::IsNullOrWhiteSpace((& git -C $repositoryRoot status --porcelain=v1 --untracked-files=all))
if ($LASTEXITCODE -ne 0 -or $head -ne $preparation.sourceCommit) {
    throw 'Current source commit does not match release preparation.'
}
if (-not (Test-Path -LiteralPath $msiPath -PathType Leaf)) {
    throw "Signed MSI is missing: $msiPath"
}
$signedMsiSha256 = (Get-FileHash -LiteralPath $msiPath -Algorithm SHA256).Hash.ToLowerInvariant()
if ($signedMsiSha256 -ne $signedMsiReceipt.signedSha256) {
    throw 'Signed MSI hash does not match its signing receipt.'
}

$unexpectedReleaseInputs = @(Get-ChildItem -LiteralPath $releaseRoot -Force |
    Where-Object { $_.Name -ne $msiName })
if ($unexpectedReleaseInputs.Count -ne 0) {
    throw "Release directory contained unexpected input before evidence generation: $($unexpectedReleaseInputs.Name -join ', ')"
}

$embeddedSigner = (Get-AuthenticodeSignature -LiteralPath $msiPath).SignerCertificate
if ($null -eq $embeddedSigner `
    -or $embeddedSigner.Thumbprint -ne $expectedSignerThumbprint `
    -or $embeddedSigner.GetCertHashString([Security.Cryptography.HashAlgorithmName]::SHA256) -ne $expectedSignerCertificateSha256) {
    throw 'Signed MSI does not embed the reviewed signer certificate.'
}

$temporaryTrust = @()
try {
    $temporaryTrust = Add-TemporarySignerTrust $embeddedSigner
    Assert-SignerPolicy $msiPath

    $signedPayloadByPath = @{}
    foreach ($entry in @($payloadReceipt.files)) {
        $signedPayloadByPath[[string]$entry.path] = $entry
    }
    foreach ($entry in @($preparation.files | Where-Object signable)) {
        $path = Resolve-PreparedPath ([string]$entry.path)
        $signedEntry = $signedPayloadByPath[[string]$entry.path]
        if ($null -eq $signedEntry `
            -or $signedEntry.unsignedSha256 -ne $entry.sha256 `
            -or $signedEntry.signedSha256 -ne (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash) {
            throw "Signed payload evidence mismatch: $path"
        }
        Assert-SignerPolicy $path
    }
} finally {
    foreach ($path in $temporaryTrust) {
        Remove-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue
    }
}

$dependencyEvidencePath = Join-Path $securityWork 'dependency-vulnerability-scan.json'
$dependencyEvidence = Read-RequiredJson $dependencyEvidencePath
if ($dependencyEvidence.schema -ne 'hch.worker-dependency-vulnerability-scan/v1' `
    -or $dependencyEvidence.status -ne 'passed') {
    throw 'Dependency vulnerability evidence is missing or failed.'
}

$defenderEvidencePath = Join-Path $securityWork 'defender-signed-release-scan.json'
& (Join-Path $PSScriptRoot 'Test-HchWorkerDefender.ps1') `
    -ScanPath $msiPath `
    -EvidencePath $defenderEvidencePath `
    -RequireAvailable:$RequireDefender
$defenderEvidence = Read-RequiredJson $defenderEvidencePath

$e2eEvidence = $null
if (-not [string]::IsNullOrWhiteSpace($MsiE2eEvidencePath)) {
    $resolvedE2ePath = (Resolve-Path -LiteralPath $MsiE2eEvidencePath).Path
    $e2eEvidence = Read-RequiredJson $resolvedE2ePath
    if ($e2eEvidence.schema -ne 'hch.worker-windows-msi-e2e/v1' `
        -or $e2eEvidence.status -ne 'passed' `
        -or $e2eEvidence.version -ne $Version `
        -or $e2eEvidence.msiSha256 -ne $signedMsiSha256) {
        throw 'Disposable MSI E2E evidence does not match the signed MSI.'
    }
}
if ($null -eq $e2eEvidence) {
    throw 'Every signed candidate requires successful evidence from the disposable MSI lifecycle harness.'
}

$candidateReady = -not $dirty `
    -and -not $preparation.sourceTreeDirty `
    -and -not $preparation.immutableVersionRef `
    -and $preparation.testsRun `
    -and $preparation.rootTrustPinned `
    -and $dependencyEvidence.status -eq 'passed' `
    -and $defenderEvidence.status -eq 'passed' `
    -and $null -ne $e2eEvidence
if (-not $candidateReady) {
    throw 'Signed candidate policy is not satisfied.'
}

New-Item -ItemType Directory -Path $securityRelease -Force | Out-Null
Copy-Item -LiteralPath $dependencyEvidencePath -Destination (Join-Path $securityRelease 'dependency-vulnerability-scan.json')
Copy-Item -LiteralPath $defenderEvidencePath -Destination (Join-Path $securityRelease 'defender-signed-release-scan.json')
if ($null -ne $e2eEvidence) {
    $e2eEvidence | ConvertTo-Json -Depth 100 |
        Set-Content -LiteralPath (Join-Path $securityRelease 'msi-disposable-e2e.json') -Encoding utf8NoBOM
}

$provenance = [ordered]@{
    schema = 'hch.worker-windows-provenance/v3'
    product = 'HCH Worker'
    version = $Version
    releaseIntent = $ReleaseIntent.ToLowerInvariant()
    runtimeIdentifier = 'win-x64'
    source = [ordered]@{
        repository = 'https://github.com/HUBTECH-DEV/hch-worker'
        commit = $preparation.sourceCommit
        ref = $preparation.sourceRef
        clean = -not $dirty
        immutableVersionRef = [bool]$preparation.immutableVersionRef
    }
    build = [ordered]@{
        dotnetSdk = (& dotnet --version).Trim()
        wixSdk = '7.0.0'
        runnerName = $env:RUNNER_NAME
        runnerEnvironment = $env:RUNNER_ENVIRONMENT
        runnerImage = $env:ImageOS
        os = [Environment]::OSVersion.VersionString
        architecture = [Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString()
        testsRun = [bool]$preparation.testsRun
    }
    trust = [ordered]@{
        rootKeyId = $preparation.rootKeyId
        rootPublicKeyFingerprint = $preparation.rootPublicKeyFingerprint
        signerThumbprint = $expectedSignerThumbprint
        signerCertificateSha256 = $expectedSignerCertificateSha256
        timestampUrl = $TimestampUrl
    }
    gates = [ordered]@{
        dependencyVulnerabilityScan = $dependencyEvidence.status
        microsoftDefender = $defenderEvidence.status
        disposableMsiLifecycle = if ($null -eq $e2eEvidence) { 'not-run' } else { $e2eEvidence.status }
        detachedChecksumSignature = 'required-after-this-step'
        githubArtifactAttestation = 'required-by-candidate-workflow-before-canary'
    }
    subject = [ordered]@{
        name = $msiName
        sha256 = $signedMsiSha256
    }
    generatedAtUtc = [DateTimeOffset]::UtcNow.ToString('O')
}
$provenance | ConvertTo-Json -Depth 12 |
    Set-Content -LiteralPath (Join-Path $releaseRoot 'build-provenance.json') -Encoding utf8NoBOM

[ordered]@{
    schema = 'hch.worker-windows-signing-status/v2'
    releaseIntent = $ReleaseIntent.ToLowerInvariant()
    signed = $true
    signerThumbprint = $expectedSignerThumbprint
    signerCertificateSha256 = $expectedSignerCertificateSha256
    timestampUrl = $TimestampUrl
    rootTrustPinned = [bool]$preparation.rootTrustPinned
    testsRun = [bool]$preparation.testsRun
    sourceTreeClean = -not $dirty
    immutableVersionRef = [bool]$preparation.immutableVersionRef
    dependencyScan = $dependencyEvidence.status
    defenderScan = $defenderEvidence.status
    disposableMsiLifecycle = if ($null -eq $e2eEvidence) { 'not-run' } else { $e2eEvidence.status }
    detachedChecksumSignature = 'required-companion-SHA256SUMS.p7s'
    githubArtifactAttestation = 'workflow-required-before-canary'
    releasable = $false
} | ConvertTo-Json -Depth 8 |
    Set-Content -LiteralPath (Join-Path $releaseRoot 'signing-status.json') -Encoding utf8NoBOM

Invoke-Checked -FilePath dotnet -ArgumentList @(
    'tool', 'run', 'sbom-tool', '--', 'generate',
    '-b', $releaseRoot,
        '-bc', $windowsRoot,
    '-pn', 'HCH Worker',
    '-pv', $Version,
    '-ps', 'HubTech',
    '-nsb', 'https://hubtech.online/sbom/hch-worker',
    '-D', 'true',
    '-mi', 'SPDX:2.2')
Invoke-Checked -FilePath dotnet -ArgumentList @(
    'tool', 'run', 'sbom-tool', '--', 'validate',
    '-b', $releaseRoot,
    '-o', (Join-Path $releaseRoot 'sbom-validation.json'),
    '-mi', 'SPDX:2.2')

$hashLines = Get-ChildItem -LiteralPath $releaseRoot -File -Recurse |
    Where-Object { $_.Name -notin 'SHA256SUMS.txt', 'SHA256SUMS.p7s' } |
    Sort-Object FullName |
    ForEach-Object {
        $relative = [IO.Path]::GetRelativePath($releaseRoot, $_.FullName).Replace('\', '/')
        '{0}  {1}' -f (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant(), $relative
    }
$hashLines | Set-Content -LiteralPath (Join-Path $releaseRoot 'SHA256SUMS.txt') -Encoding ascii

Write-Host "Final release evidence prepared for detached signing: $releaseRoot"
