[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$PackageDirectory,
    [ValidatePattern('^\d+\.\d+\.\d+$')][string]$Version = '3.1.1',
    [Parameter(Mandatory)][ValidatePattern('^[0-9A-Fa-f]{40}$')][string]$SignerThumbprint,
    [Parameter(Mandatory)][ValidatePattern('^[0-9A-Fa-f]{64}$')][string]$SignerCertificateSha256,
    [ValidateSet('CurrentUser', 'LocalMachine')][string]$CertificateStoreLocation = 'CurrentUser'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ($Version -cne '3.1.1') { throw 'bridge-package-version-not-approved' }

function Assert-RegularFile([string]$Path, [long]$MaximumBytes) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { throw "bridge-package-file-missing:$Path" }
    $item = Get-Item -LiteralPath $Path -Force
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
        $item.Length -le 0 -or $item.Length -gt $MaximumBytes) {
        throw "bridge-package-file-invalid:$Path"
    }
    return $item
}

$directory = (Resolve-Path -LiteralPath $PackageDirectory).Path
$directoryItem = Get-Item -LiteralPath $directory -Force
if (-not $directoryItem.PSIsContainer -or
    ($directoryItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
    throw 'bridge-package-directory-invalid'
}
$packages = @(
    "HCH-Worker-Setup-$Version-x64.exe",
    "HCH-Worker-$Version-linux-x64.tar.gz",
    "HCH-Worker-$Version-macos-universal.tar.gz")
foreach ($name in $packages) { $null = Assert-RegularFile (Join-Path $directory $name) 512MB }

$checksumPath = Join-Path $directory 'SHA256SUMS.txt'
$signaturePath = Join-Path $directory 'SHA256SUMS.p7s'
if (Test-Path -LiteralPath $checksumPath -or Test-Path -LiteralPath $signaturePath) {
    throw 'bridge-package-evidence-already-exists'
}
$lines = foreach ($name in $packages) {
    $hash = (Get-FileHash -LiteralPath (Join-Path $directory $name) -Algorithm SHA256).Hash.ToLowerInvariant()
    "$hash  $name"
}
$checksumBytes = [Text.UTF8Encoding]::new($false).GetBytes(($lines -join "`n") + "`n")
if ($checksumBytes.Length -le 0 -or $checksumBytes.Length -gt 64KB) { throw 'bridge-package-checksum-size-invalid' }

$store = [Security.Cryptography.X509Certificates.X509Store]::new(
    'My', [Security.Cryptography.X509Certificates.StoreLocation]::$CertificateStoreLocation)
try {
    $store.Open([Security.Cryptography.X509Certificates.OpenFlags]::ReadOnly)
    $pin = $SignerThumbprint.Replace(' ', '').ToUpperInvariant()
    $matches = @($store.Certificates | Where-Object {
        $_.Thumbprint.Replace(' ', '').ToUpperInvariant() -ceq $pin
    })
    if ($matches.Count -ne 1 -or -not $matches[0].HasPrivateKey) {
        throw 'bridge-package-signer-not-found'
    }
    $certificate = $matches[0]
    $sha256 = [Convert]::ToHexString($certificate.GetCertHash(
        [Security.Cryptography.HashAlgorithmName]::SHA256))
    if ($sha256 -cne $SignerCertificateSha256.ToUpperInvariant()) {
        throw 'bridge-package-signer-sha256-mismatch'
    }
    $ekuExtensions = @($certificate.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.37' })
    if ($ekuExtensions.Count -ne 1) { throw 'bridge-package-signer-eku-invalid' }
    $eku = if ($ekuExtensions[0] -is [Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]) {
        $ekuExtensions[0]
    } else {
        [Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]::new(
            $ekuExtensions[0], $ekuExtensions[0].Critical)
    }
    if ($eku.EnhancedKeyUsages.Count -ne 1 -or
        $eku.EnhancedKeyUsages[0].Value -cne '1.3.6.1.5.5.7.3.3') {
        throw 'bridge-package-signer-eku-invalid'
    }
    $now = [DateTime]::UtcNow
    $signingTime = [DateTime]::new($now.Year, $now.Month, $now.Day, $now.Hour, $now.Minute, $now.Second,
        [DateTimeKind]::Utc)
    if ($signingTime -lt $certificate.NotBefore.ToUniversalTime() -or
        $signingTime -gt $certificate.NotAfter.ToUniversalTime()) {
        throw 'bridge-package-signer-expired'
    }
    Add-Type -AssemblyName System.Security.Cryptography.Pkcs
    $cms = [Security.Cryptography.Pkcs.SignedCms]::new(
        [Security.Cryptography.Pkcs.ContentInfo]::new($checksumBytes), $true)
    $signer = [Security.Cryptography.Pkcs.CmsSigner]::new(
        [Security.Cryptography.Pkcs.SubjectIdentifierType]::IssuerAndSerialNumber, $certificate)
    $signer.IncludeOption = [Security.Cryptography.X509Certificates.X509IncludeOption]::EndCertOnly
    $signer.DigestAlgorithm = [Security.Cryptography.Oid]::new('2.16.840.1.101.3.4.2.1')
    $signer.SignedAttributes.Add([Security.Cryptography.Pkcs.Pkcs9SigningTime]::new($signingTime))
    $cms.ComputeSignature($signer, $true)

    $checksumTemp = "$checksumPath.$([Guid]::NewGuid().ToString('N')).tmp"
    $signatureTemp = "$signaturePath.$([Guid]::NewGuid().ToString('N')).tmp"
    try {
        [IO.File]::WriteAllBytes($checksumTemp, $checksumBytes)
        [IO.File]::WriteAllBytes($signatureTemp, $cms.Encode())
        [IO.File]::Move($checksumTemp, $checksumPath)
        [IO.File]::Move($signatureTemp, $signaturePath)
    } finally {
        Remove-Item -LiteralPath $checksumTemp -Force -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath $signatureTemp -Force -ErrorAction SilentlyContinue
    }
} finally {
    $store.Dispose()
}

[pscustomobject]@{
    schema = 'hch.worker-bridge-package/v1'
    version = $Version
    packages = $packages
    checksum = $checksumPath
    signature = $signaturePath
    signerThumbprint = $SignerThumbprint.Replace(' ', '').ToUpperInvariant()
}
