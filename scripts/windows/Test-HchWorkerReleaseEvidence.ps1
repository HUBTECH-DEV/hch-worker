[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$ReleasePath,

    [Parameter(Mandatory)]
    [ValidatePattern('^\d+\.\d+\.\d+$')]
    [string]$Version,

    [Parameter(Mandatory)]
    [ValidatePattern('^[A-Fa-f0-9]{40}$')]
    [string]$ExpectedSignerThumbprint,

    [Parameter(Mandatory)]
    [ValidatePattern('^[A-Fa-f0-9]{64}$')]
    [string]$ExpectedSignerCertificateSha256,

    [switch]$RequireCandidate
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$releaseRoot = (Resolve-Path -LiteralPath $ReleasePath).Path
$expectedSignerThumbprint = $ExpectedSignerThumbprint.ToUpperInvariant()
$expectedSignerCertificateSha256 = $ExpectedSignerCertificateSha256.ToUpperInvariant()
$msiName = "HCH-Worker-$Version-win-x64.msi"
$msiPath = Join-Path $releaseRoot $msiName
$checksumPath = Join-Path $releaseRoot 'SHA256SUMS.txt'
$signaturePath = Join-Path $releaseRoot 'SHA256SUMS.p7s'

function Read-RequiredJson {
    param([Parameter(Mandatory)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Required release evidence is missing: $Path"
    }
    return Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json -Depth 100
}

function Resolve-ReleaseRelativePath {
    param([Parameter(Mandatory)][string]$RelativePath)

    if ($RelativePath -notmatch '^[A-Za-z0-9_. /+-]+$' `
        -or $RelativePath.Contains('..') `
        -or [IO.Path]::IsPathRooted($RelativePath)) {
        throw "Unsafe checksum path: $RelativePath"
    }
    $candidate = [IO.Path]::GetFullPath((Join-Path $releaseRoot $RelativePath.Replace('/', '\')))
    $boundary = [IO.Path]::GetFullPath($releaseRoot).TrimEnd('\') + '\'
    if (-not $candidate.StartsWith($boundary, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Checksum path escaped release root: $RelativePath"
    }
    return $candidate
}

function Add-TemporarySignerTrust {
    param([Parameter(Mandatory)][Security.Cryptography.X509Certificates.X509Certificate2]$Certificate)

    $added = [System.Collections.Generic.List[string]]::new()
    foreach ($storeName in 'Root', 'TrustedPublisher') {
        $path = "Cert:\CurrentUser\$storeName\$($Certificate.Thumbprint)"
        if (-not (Test-Path -LiteralPath $path)) {
            $copy = [Security.Cryptography.X509Certificates.X509Certificate2]::new($Certificate.Export(
                [Security.Cryptography.X509Certificates.X509ContentType]::Cert))
            $store = [Security.Cryptography.X509Certificates.X509Store]::new(
                $storeName,
                [Security.Cryptography.X509Certificates.StoreLocation]::CurrentUser)
            try {
                $store.Open([Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
                $store.Add($copy)
                $added.Add($path)
            } finally {
                $store.Dispose()
                $copy.Dispose()
            }
        }
    }
    return @($added)
}

foreach ($path in $msiPath, $checksumPath, $signaturePath) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "Final release file is missing: $path"
    }
}
if (Get-ChildItem -LiteralPath $releaseRoot -File -Recurse |
    Where-Object { $_.Extension -in '.pfx', '.p12', '.key', '.snk' }) {
    throw 'Release directory contains private-key-shaped material.'
}

$declared = [System.Collections.Generic.Dictionary[string, string]]::new([StringComparer]::Ordinal)
foreach ($line in Get-Content -LiteralPath $checksumPath) {
    if ($line -notmatch '^(?<hash>[0-9a-f]{64})  (?<path>.+)$') {
        throw "Malformed SHA256SUMS line: $line"
    }
    $relative = [string]$Matches.path
    $declaredHash = [string]$Matches.hash
    if (-not $declared.TryAdd($relative, $declaredHash)) {
        throw "Duplicate SHA256SUMS path: $relative"
    }
    $resolved = Resolve-ReleaseRelativePath $relative
    if (-not (Test-Path -LiteralPath $resolved -PathType Leaf)) {
        throw "Checksummed release file is missing: $relative"
    }
    $actual = (Get-FileHash -LiteralPath $resolved -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actual -cne $declaredHash) {
        throw "Release checksum mismatch: $relative"
    }
}

$expectedChecksummedPaths = @(Get-ChildItem -LiteralPath $releaseRoot -File -Recurse |
    Where-Object { $_.Name -notin 'SHA256SUMS.txt', 'SHA256SUMS.p7s' } |
    ForEach-Object { [IO.Path]::GetRelativePath($releaseRoot, $_.FullName).Replace('\', '/') })
if ($declared.Count -ne $expectedChecksummedPaths.Count) {
    throw 'SHA256SUMS does not cover exactly the expected release files.'
}
foreach ($relative in $expectedChecksummedPaths) {
    if (-not $declared.ContainsKey($relative)) {
        throw "Release file is not covered by SHA256SUMS: $relative"
    }
}

Add-Type -AssemblyName System.Security.Cryptography.Pkcs
$content = [Security.Cryptography.Pkcs.ContentInfo]::new([IO.File]::ReadAllBytes($checksumPath))
$cms = [Security.Cryptography.Pkcs.SignedCms]::new($content, $true)
$cms.Decode([IO.File]::ReadAllBytes($signaturePath))
$cms.CheckSignature($true)
if ($cms.SignerInfos.Count -ne 1) {
    throw 'Detached checksum evidence must contain exactly one signer.'
}
$evidenceSigner = $cms.SignerInfos[0].Certificate
if ($null -eq $evidenceSigner `
    -or $evidenceSigner.Thumbprint -ne $expectedSignerThumbprint `
    -or $evidenceSigner.GetCertHashString([Security.Cryptography.HashAlgorithmName]::SHA256) -ne $expectedSignerCertificateSha256) {
    throw 'Detached checksum evidence signer does not match policy.'
}

$embeddedMsiSigner = (Get-AuthenticodeSignature -LiteralPath $msiPath).SignerCertificate
if ($null -eq $embeddedMsiSigner `
    -or $embeddedMsiSigner.Thumbprint -ne $expectedSignerThumbprint `
    -or $embeddedMsiSigner.GetCertHashString([Security.Cryptography.HashAlgorithmName]::SHA256) -ne $expectedSignerCertificateSha256) {
    throw 'MSI signer does not match policy.'
}
$temporaryTrust = @()
try {
    $temporaryTrust = Add-TemporarySignerTrust $embeddedMsiSigner
    $msiSignature = Get-AuthenticodeSignature -LiteralPath $msiPath
    if ($msiSignature.Status -ne 'Valid' -or $null -eq $msiSignature.TimeStamperCertificate) {
        throw "MSI Authenticode trust/timestamp verification failed: $($msiSignature.Status)"
    }
} finally {
    foreach ($path in $temporaryTrust) {
        Remove-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue
    }
}

$provenance = Read-RequiredJson (Join-Path $releaseRoot 'build-provenance.json')
$signingStatus = Read-RequiredJson (Join-Path $releaseRoot 'signing-status.json')
$dependency = Read-RequiredJson (Join-Path $releaseRoot 'security\dependency-vulnerability-scan.json')
$defender = Read-RequiredJson (Join-Path $releaseRoot 'security\defender-signed-release-scan.json')
$msiSha256 = (Get-FileHash -LiteralPath $msiPath -Algorithm SHA256).Hash.ToLowerInvariant()
if ($provenance.schema -ne 'hch.worker-windows-provenance/v3' `
    -or $provenance.version -ne $Version `
    -or $provenance.subject.name -ne $msiName `
    -or $provenance.subject.sha256 -ne $msiSha256 `
    -or $provenance.trust.signerThumbprint -ne $expectedSignerThumbprint `
    -or $provenance.trust.signerCertificateSha256 -ne $expectedSignerCertificateSha256) {
    throw 'Build provenance does not match final MSI and signer policy.'
}
if ($signingStatus.schema -ne 'hch.worker-windows-signing-status/v2' `
    -or -not $signingStatus.signed `
    -or $signingStatus.signerThumbprint -ne $expectedSignerThumbprint `
    -or $signingStatus.signerCertificateSha256 -ne $expectedSignerCertificateSha256 `
    -or $dependency.status -ne 'passed') {
    throw 'Signing or dependency policy evidence is invalid.'
}

if ($RequireCandidate) {
    $e2e = Read-RequiredJson (Join-Path $releaseRoot 'security\msi-disposable-e2e.json')
    if ($signingStatus.releaseIntent -ne 'candidate' `
        -or $signingStatus.releasable `
        -or -not $signingStatus.rootTrustPinned `
        -or -not $signingStatus.testsRun `
        -or -not $signingStatus.sourceTreeClean `
        -or $signingStatus.immutableVersionRef `
        -or $signingStatus.defenderScan -ne 'passed' `
        -or $defender.status -ne 'passed' `
        -or $signingStatus.disposableMsiLifecycle -ne 'passed' `
        -or $e2e.status -ne 'passed' `
        -or $e2e.version -ne $Version `
        -or $e2e.msiSha256 -ne $msiSha256 `
        -or $provenance.releaseIntent -ne 'candidate' `
        -or $provenance.source.ref -ne 'refs/heads/main' `
        -or -not $provenance.source.clean `
        -or $provenance.source.immutableVersionRef `
        -or $provenance.source.commit -notmatch '^[0-9a-f]{40}$' `
        -or $provenance.gates.dependencyVulnerabilityScan -ne 'passed' `
        -or $provenance.gates.microsoftDefender -ne 'passed' `
        -or $provenance.gates.disposableMsiLifecycle -ne 'passed') {
        throw 'Signed candidate gates are not all proven by the immutable evidence set.'
    }
}

Write-Host 'Final Windows release evidence verification passed.'
