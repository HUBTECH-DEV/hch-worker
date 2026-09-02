[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$EvidencePath,

    [Parameter(Mandatory)]
    [string]$EvidenceSignaturePath,

    [Parameter(Mandatory)]
    [ValidatePattern('^[0-9A-Fa-f]{40}$')]
    [string]$AttesterThumbprint,

    [Parameter(Mandatory)]
    [ValidatePattern('^[0-9A-Fa-f]{64}$')]
    [string]$ExpectedAttesterCertificateSha256,

    [ValidateSet('CurrentUser', 'LocalMachine')]
    [string]$CertificateStoreLocation = 'CurrentUser'
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$codeSigningEkuOid = '1.3.6.1.5.5.7.3.3'
$resolvedEvidence = (Resolve-Path -LiteralPath $EvidencePath).Path
$signatureParent = Split-Path -Parent ([IO.Path]::GetFullPath($EvidenceSignaturePath))
if (-not (Test-Path -LiteralPath $signatureParent -PathType Container)) {
    throw "Detached-signature parent directory does not exist: $signatureParent"
}
$resolvedSignature = [IO.Path]::GetFullPath($EvidenceSignaturePath)
if (Test-Path -LiteralPath $resolvedSignature) {
    throw "Refusing to overwrite existing detached signature: $resolvedSignature"
}

$evidenceBytes = [IO.File]::ReadAllBytes($resolvedEvidence)
if ($evidenceBytes.Length -eq 0) {
    throw 'Canary evidence must not be empty.'
}
$strictUtf8 = [Text.UTF8Encoding]::new($false, $true)
$raw = $strictUtf8.GetString($evidenceBytes)
if ($raw.Length -eq 0 -or $raw[0] -eq [char]0xFEFF) {
    throw 'Canary evidence must be UTF-8 without BOM.'
}
if ($raw -match '(?i)-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----|Authorization\s*:|Bearer\s+[A-Za-z0-9._~-]+') {
    throw 'Canary evidence contains secret-shaped material and will not be signed.'
}
$evidence = $raw | ConvertFrom-Json -Depth 100
if ($evidence.schema -cne 'hch.worker-windows-canary/v2' `
    -or $evidence.status -cne 'passed' `
    -or $evidence.sanitized -isnot [bool] `
    -or -not $evidence.sanitized) {
    throw 'Only passed, sanitized hch.worker-windows-canary/v2 evidence may be signed.'
}
$completedAt = [DateTimeOffset]::MinValue
if ($evidence.completedAtUtc -is [DateTime]) {
    $completedAt = [DateTimeOffset]$evidence.completedAtUtc.ToUniversalTime()
} elseif ($evidence.completedAtUtc -is [DateTimeOffset]) {
    $completedAt = $evidence.completedAtUtc.ToUniversalTime()
} elseif ($evidence.completedAtUtc -is [string]) {
    if (-not [DateTimeOffset]::TryParse(
            $evidence.completedAtUtc,
            [Globalization.CultureInfo]::InvariantCulture,
            [Globalization.DateTimeStyles]::RoundtripKind,
            [ref]$completedAt)) {
        throw 'Canary completedAtUtc must be a valid UTC timestamp.'
    }
    $completedAt = $completedAt.ToUniversalTime()
} else {
    throw 'Canary completedAtUtc must be a valid UTC timestamp.'
}
$currentUtc = [DateTime]::UtcNow
$signingTimeUtc = [DateTime]::new(
    $currentUtc.Year,
    $currentUtc.Month,
    $currentUtc.Day,
    $currentUtc.Hour,
    $currentUtc.Minute,
    $currentUtc.Second,
    [DateTimeKind]::Utc)
$signingTime = [DateTimeOffset]$signingTimeUtc
if ($signingTime -le $completedAt -or $signingTime -gt $completedAt.AddHours(24)) {
    throw 'Controlled signing must occur after canary completion and within 24 hours.'
}

$storeLocation = [Security.Cryptography.X509Certificates.StoreLocation]::$CertificateStoreLocation
$store = [Security.Cryptography.X509Certificates.X509Store]::new(
    [Security.Cryptography.X509Certificates.StoreName]::My,
    $storeLocation)
try {
    $store.Open([Security.Cryptography.X509Certificates.OpenFlags]::ReadOnly)
    $normalizedThumbprint = $AttesterThumbprint.ToUpperInvariant()
    $certificates = @($store.Certificates | Where-Object {
        $_.Thumbprint.Replace(' ', '').ToUpperInvariant() -ceq $normalizedThumbprint
    })
    if ($certificates.Count -ne 1) {
        throw "Expected exactly one attester certificate in $CertificateStoreLocation/My."
    }
    $certificate = $certificates[0]
    if (-not $certificate.HasPrivateKey) {
        throw 'Canary attester certificate has no locally protected private key.'
    }
    $actualCertificateSha256 = [Convert]::ToHexString(
        $certificate.GetCertHash([Security.Cryptography.HashAlgorithmName]::SHA256))
    if ($actualCertificateSha256 -cne $ExpectedAttesterCertificateSha256.ToUpperInvariant()) {
        throw 'Canary attester certificate does not match the expected SHA-256 certificate pin.'
    }

    $ekuExtensions = @($certificate.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.37' })
    if ($ekuExtensions.Count -ne 1) {
        throw 'Canary attester certificate must contain exactly one EKU extension.'
    }
    if ($ekuExtensions[0] -is [Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]) {
        $decodedEku = $ekuExtensions[0]
    } else {
        $decodedEku = [Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]::new(
            $ekuExtensions[0],
            $ekuExtensions[0].Critical)
    }
    if ($decodedEku.EnhancedKeyUsages.Count -ne 1 `
        -or $decodedEku.EnhancedKeyUsages[0].Value -cne $codeSigningEkuOid) {
        throw 'Canary attester certificate is not constrained to code-signing use.'
    }
    $keyUsageExtensions = @($certificate.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.15' })
    if ($keyUsageExtensions.Count -gt 1) {
        throw 'Canary attester certificate has ambiguous key-usage extensions.'
    }
    if ($keyUsageExtensions.Count -eq 1) {
        if ($keyUsageExtensions[0] -is [Security.Cryptography.X509Certificates.X509KeyUsageExtension]) {
            $decodedKeyUsage = $keyUsageExtensions[0]
        } else {
            $decodedKeyUsage = [Security.Cryptography.X509Certificates.X509KeyUsageExtension]::new(
                $keyUsageExtensions[0],
                $keyUsageExtensions[0].Critical)
        }
        if (($decodedKeyUsage.KeyUsages -band `
            [Security.Cryptography.X509Certificates.X509KeyUsageFlags]::DigitalSignature) -eq 0) {
            throw 'Canary attester certificate key usage does not allow digital signatures.'
        }
    }
    $certificateNotBefore = [DateTimeOffset]$certificate.NotBefore.ToUniversalTime()
    $certificateNotAfter = [DateTimeOffset]$certificate.NotAfter.ToUniversalTime()
    if ($signingTime -lt $certificateNotBefore -or $signingTime -gt $certificateNotAfter) {
        throw 'Canary attester certificate is not valid at signing time.'
    }

    $contentInfo = [Security.Cryptography.Pkcs.ContentInfo]::new($evidenceBytes)
    $signedCms = [Security.Cryptography.Pkcs.SignedCms]::new($contentInfo, $true)
    $cmsSigner = [Security.Cryptography.Pkcs.CmsSigner]::new(
        [Security.Cryptography.Pkcs.SubjectIdentifierType]::IssuerAndSerialNumber,
        $certificate)
    $cmsSigner.IncludeOption = [Security.Cryptography.X509Certificates.X509IncludeOption]::EndCertOnly
    $cmsSigner.DigestAlgorithm = [Security.Cryptography.Oid]::new('2.16.840.1.101.3.4.2.1')
    $cmsSigner.SignedAttributes.Add(
        [Security.Cryptography.Pkcs.Pkcs9SigningTime]::new($signingTimeUtc))
    $signedCms.ComputeSignature($cmsSigner, $true)
    $signatureBytes = $signedCms.Encode()
    if ($signatureBytes.Length -eq 0) {
        throw 'CMS provider returned an empty detached signature.'
    }

    $temporarySignature = "$resolvedSignature.$([Guid]::NewGuid().ToString('N')).tmp"
    try {
        [IO.File]::WriteAllBytes($temporarySignature, $signatureBytes)
        [IO.File]::Move($temporarySignature, $resolvedSignature)
    } finally {
        if (Test-Path -LiteralPath $temporarySignature) {
            Remove-Item -LiteralPath $temporarySignature -Force
        }
    }
} finally {
    $store.Dispose()
}

Write-Host "Detached CMS canary signature created without exporting private key: $resolvedSignature"
