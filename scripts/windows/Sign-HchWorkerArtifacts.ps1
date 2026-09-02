[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateSet('Payloads', 'Msi', 'Evidence')]
    [string]$Stage,

    [Parameter(Mandatory)]
    [ValidatePattern('^\d+\.\d+\.\d+$')]
    [string]$Version,

    [Parameter(Mandatory)]
    [ValidatePattern('^[A-Fa-f0-9]{40}$')]
    [string]$ExpectedSignerThumbprint,

    [Parameter(Mandatory)]
    [ValidatePattern('^[A-Fa-f0-9]{64}$')]
    [string]$ExpectedSignerCertificateSha256,

    [string]$TimestampUrl = 'http://timestamp.digicert.com'
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$repositoryRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\..')).Path
$artifactRoot = Join-Path $repositoryRoot 'artifacts\windows-v4'
$workRoot = Join-Path $artifactRoot 'work'
$releaseRoot = Join-Path $artifactRoot 'release'
$preparationPath = Join-Path $workRoot 'package-preparation.json'
$expectedMsiName = "HCH-Worker-$Version-win-x64.msi"
$expectedSignerThumbprint = $ExpectedSignerThumbprint.ToUpperInvariant()
$expectedSignerCertificateSha256 = $ExpectedSignerCertificateSha256.ToUpperInvariant()

function Find-SignTool {
    $kitsRoot = ${env:ProgramFiles(x86)}
    if ([string]::IsNullOrWhiteSpace($kitsRoot)) { return $null }
    return Get-ChildItem -LiteralPath (Join-Path $kitsRoot 'Windows Kits\10\bin') `
        -Filter signtool.exe -File -Recurse -ErrorAction SilentlyContinue |
        Where-Object FullName -Match '\\x64\\signtool\.exe$' |
        Sort-Object FullName -Descending |
        Select-Object -First 1 -ExpandProperty FullName
}

function Invoke-NativeChecked {
    param([Parameter(Mandatory)][string]$FilePath, [Parameter(Mandatory)][string[]]$ArgumentList)

    & $FilePath @ArgumentList
    if ($LASTEXITCODE -ne 0) {
        throw "Command failed with exit code ${LASTEXITCODE}: $FilePath"
    }
}

function Assert-Preparation {
    if (-not (Test-Path -LiteralPath $preparationPath -PathType Leaf)) {
        throw 'Package preparation manifest is missing.'
    }
    $preparation = Get-Content -LiteralPath $preparationPath -Raw | ConvertFrom-Json -Depth 100
    if ($preparation.schema -ne 'hch.worker-windows-package-preparation/v1' `
        -or $preparation.version -ne $Version `
        -or $preparation.expectedMsi -ne $expectedMsiName `
        -or $preparation.sourceTreeDirty `
        -or -not $preparation.testsRun `
        -or -not $preparation.rootTrustPinned) {
        throw 'Only a clean, tested and root-pinned preparation can enter the signing boundary.'
    }
    $head = (& git -C $repositoryRoot rev-parse HEAD).Trim()
    if ($LASTEXITCODE -ne 0 -or $head -ne $preparation.sourceCommit) {
        throw 'Current source commit does not match the package preparation.'
    }
    if (-not [string]::IsNullOrWhiteSpace((& git -C $repositoryRoot status --porcelain=v1 --untracked-files=all))) {
        throw 'Signing requires a clean Git worktree.'
    }
    return $preparation
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

function Assert-FileHash {
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$ExpectedSha256)

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Expected file is missing: $Path"
    }
    $actual = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash
    if ($actual -ne $ExpectedSha256) {
        throw "File hash mismatch at the signing boundary: $Path"
    }
}

function Read-RequiredJson {
    param([Parameter(Mandatory)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Required signing-boundary receipt is missing: $Path"
    }
    return Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json -Depth 100
}

function Assert-StageInputs {
    param([Parameter(Mandatory)]$Preparation)

    if ($Stage -eq 'Payloads') {
        $seen = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
        $signableCount = 0
        foreach ($entry in @($Preparation.files)) {
            $relative = [string]$entry.path
            if (-not $seen.Add($relative)) {
                throw "Preparation contains a duplicate path: $relative"
            }
            $path = Resolve-PreparedPath $relative
            Assert-FileHash $path ([string]$entry.sha256)
            if ($entry.signable) {
                $signableCount++
                $leaf = [IO.Path]::GetFileName($path)
                if ($relative -notmatch '^publish/(?:service|tray|installer)/' `
                    -or $leaf -notmatch '^Hch\.Worker\.[A-Za-z0-9_.-]+\.(?:exe|dll)$') {
                    throw "Preparation attempted to place an unexpected file in the signing allowlist: $relative"
                }
                if ($null -ne (Get-AuthenticodeSignature -LiteralPath $path).SignerCertificate) {
                    throw "Payload is already Authenticode signed before its isolated signing stage: $relative"
                }
            }
        }
        if ($signableCount -lt 3) {
            throw 'Signing allowlist does not contain the required first-party Worker payloads.'
        }
        if (Test-Path -LiteralPath (Join-Path $workRoot 'signed-payloads.json')) {
            throw 'Payload signing receipt already exists; signing stages are single-use.'
        }
        return
    }

    if ($Stage -eq 'Msi') {
        $unsignedReceiptPath = Join-Path $workRoot 'unsigned-msi.json'
        $payloadReceiptPath = Join-Path $workRoot 'signed-payloads.json'
        $unsignedReceipt = Read-RequiredJson $unsignedReceiptPath
        $payloadReceipt = Read-RequiredJson $payloadReceiptPath
        $preparationHash = (Get-FileHash -LiteralPath $preparationPath -Algorithm SHA256).Hash.ToLowerInvariant()
        $payloadReceiptHash = (Get-FileHash -LiteralPath $payloadReceiptPath -Algorithm SHA256).Hash.ToLowerInvariant()
        $msiPath = Join-Path $releaseRoot $expectedMsiName
        if ($unsignedReceipt.schema -ne 'hch.worker-windows-unsigned-msi/v1' `
            -or $unsignedReceipt.version -ne $Version `
            -or $unsignedReceipt.sourceCommit -ne $Preparation.sourceCommit `
            -or $unsignedReceipt.preparationSha256 -ne $preparationHash `
            -or $unsignedReceipt.signedPayloadReceiptSha256 -ne $payloadReceiptHash `
            -or $unsignedReceipt.msi -ne $expectedMsiName `
            -or $payloadReceipt.schema -ne 'hch.worker-windows-signed-payloads/v1' `
            -or $payloadReceipt.signerThumbprint -ne $expectedSignerThumbprint `
            -or $payloadReceipt.signerCertificateSha256 -ne $expectedSignerCertificateSha256) {
            throw 'Repacked MSI and payload receipts do not form the reviewed signing chain.'
        }
        Assert-FileHash $msiPath ([string]$unsignedReceipt.msiSha256)
        if ($null -ne (Get-AuthenticodeSignature -LiteralPath $msiPath).SignerCertificate) {
            throw 'MSI already contains an Authenticode signature before its isolated signing stage.'
        }
        if (Test-Path -LiteralPath (Join-Path $workRoot 'signed-msi.json')) {
            throw 'MSI signing receipt already exists; signing stages are single-use.'
        }
        return
    }

    $checksumPath = Join-Path $releaseRoot 'SHA256SUMS.txt'
    $signaturePath = Join-Path $releaseRoot 'SHA256SUMS.p7s'
    $signingStatus = Read-RequiredJson (Join-Path $releaseRoot 'signing-status.json')
    $provenance = Read-RequiredJson (Join-Path $releaseRoot 'build-provenance.json')
    if (-not $signingStatus.signed `
        -or $signingStatus.signerThumbprint -ne $expectedSignerThumbprint `
        -or $signingStatus.signerCertificateSha256 -ne $expectedSignerCertificateSha256 `
        -or $provenance.trust.signerThumbprint -ne $expectedSignerThumbprint `
        -or $provenance.trust.signerCertificateSha256 -ne $expectedSignerCertificateSha256) {
        throw 'Final release evidence does not match the reviewed signer policy.'
    }
    if (Test-Path -LiteralPath $signaturePath) {
        throw 'Detached evidence signature already exists; signing stages are single-use.'
    }
    if (-not (Test-Path -LiteralPath $checksumPath -PathType Leaf)) {
        throw 'Final release checksums are missing.'
    }
    $boundary = [IO.Path]::GetFullPath($releaseRoot).TrimEnd('\') + '\'
    $count = 0
    foreach ($line in Get-Content -LiteralPath $checksumPath) {
        if ($line -notmatch '^(?<hash>[0-9a-f]{64})  (?<path>[A-Za-z0-9_. /+-]+)$') {
            throw "Malformed release checksum line: $line"
        }
        $expectedHash = [string]$Matches.hash
        $relative = [string]$Matches.path
        if ($relative.Contains('..') -or [IO.Path]::IsPathRooted($relative)) {
            throw "Unsafe release checksum path: $relative"
        }
        $path = [IO.Path]::GetFullPath((Join-Path $releaseRoot $relative.Replace('/', '\')))
        if (-not $path.StartsWith($boundary, [StringComparison]::OrdinalIgnoreCase)) {
            throw "Release checksum path escaped its boundary: $relative"
        }
        Assert-FileHash $path $expectedHash
        $count++
    }
    if ($count -lt 5) {
        throw 'Final release checksum set is unexpectedly small.'
    }
}

function Import-PolicySigner {
    $temporaryPfxPath = $null
    $newStorePaths = [System.Collections.Generic.List[string]]::new()
    try {
        $certificate = $null
        if (-not [string]::IsNullOrWhiteSpace($env:HCH_SIGN_PFX_BASE64)) {
            if ([string]::IsNullOrWhiteSpace($env:HCH_SIGN_PFX_PASSWORD)) {
                throw 'HCH_SIGN_PFX_PASSWORD is required with HCH_SIGN_PFX_BASE64.'
            }
            $temporaryPfxPath = Join-Path ([IO.Path]::GetTempPath()) ("hch-signing-{0}.pfx" -f [Guid]::NewGuid().ToString('N'))
            $pfxBytes = [Convert]::FromBase64String($env:HCH_SIGN_PFX_BASE64)
            try {
                [IO.File]::WriteAllBytes($temporaryPfxPath, $pfxBytes)
            } finally {
                [Security.Cryptography.CryptographicOperations]::ZeroMemory($pfxBytes)
            }
            $password = ConvertTo-SecureString $env:HCH_SIGN_PFX_PASSWORD -AsPlainText -Force
            try {
                $before = @(Get-ChildItem Cert:\CurrentUser\My | Select-Object -ExpandProperty Thumbprint)
                $imported = @(Import-PfxCertificate -FilePath $temporaryPfxPath `
                    -CertStoreLocation Cert:\CurrentUser\My -Password $password -Exportable:$false)
                foreach ($item in $imported) {
                    if ($before -notcontains $item.Thumbprint) {
                        $newStorePaths.Add("Cert:\CurrentUser\My\$($item.Thumbprint)")
                    }
                }
                $candidates = @($imported | Where-Object {
                    $_.HasPrivateKey -and
                    ($_.EnhancedKeyUsageList.ObjectId.Value -contains '1.3.6.1.5.5.7.3.3')
                })
                if ($candidates.Count -ne 1) {
                    throw 'PFX must contain exactly one private code-signing certificate.'
                }
                $certificate = $candidates[0]
            } finally {
                $password.Dispose()
            }
        } elseif (-not [string]::IsNullOrWhiteSpace($env:HCH_SIGN_CERT_THUMBPRINT)) {
            $certificate = Get-Item -LiteralPath "Cert:\CurrentUser\My\$($env:HCH_SIGN_CERT_THUMBPRINT)" -ErrorAction SilentlyContinue
            if ($null -eq $certificate) {
                $certificate = Get-Item -LiteralPath "Cert:\LocalMachine\My\$($env:HCH_SIGN_CERT_THUMBPRINT)" -ErrorAction SilentlyContinue
            }
        } else {
            throw 'An isolated signing step requires HCH_SIGN_PFX_BASE64/password or HCH_SIGN_CERT_THUMBPRINT.'
        }

        if ($null -eq $certificate -or -not $certificate.HasPrivateKey) {
            throw 'Configured code-signing certificate is unavailable.'
        }
        if ($certificate.Thumbprint -ne $expectedSignerThumbprint `
            -or $certificate.GetCertHashString([Security.Cryptography.HashAlgorithmName]::SHA256) -ne $expectedSignerCertificateSha256) {
            throw 'Code-signing certificate does not match the reviewed signer policy.'
        }

        foreach ($storeName in 'Root', 'TrustedPublisher') {
            $storePath = "Cert:\CurrentUser\$storeName\$($certificate.Thumbprint)"
            if (-not (Test-Path -LiteralPath $storePath)) {
                $publicCopy = [Security.Cryptography.X509Certificates.X509Certificate2]::new($certificate.Export(
                    [Security.Cryptography.X509Certificates.X509ContentType]::Cert))
                $store = [Security.Cryptography.X509Certificates.X509Store]::new(
                    $storeName,
                    [Security.Cryptography.X509Certificates.StoreLocation]::CurrentUser)
                try {
                    $store.Open([Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
                    $store.Add($publicCopy)
                    $newStorePaths.Add($storePath)
                } finally {
                    $store.Dispose()
                    $publicCopy.Dispose()
                }
            }
        }

        return [pscustomobject]@{
            Certificate = $certificate
            TemporaryPfxPath = $temporaryPfxPath
            NewStorePaths = @($newStorePaths)
        }
    } catch {
        if ($temporaryPfxPath -and (Test-Path -LiteralPath $temporaryPfxPath)) {
            Remove-Item -LiteralPath $temporaryPfxPath -Force -ErrorAction SilentlyContinue
        }
        foreach ($path in $newStorePaths) {
            Remove-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue
        }
        throw
    } finally {
        foreach ($name in 'HCH_SIGN_PFX_BASE64', 'HCH_SIGN_PFX_PASSWORD', 'HCH_SIGN_PFX_PATH', 'HCH_SIGN_CERT_THUMBPRINT') {
            Remove-Item "Env:$name" -ErrorAction SilentlyContinue
        }
    }
}

function Invoke-AuthenticodeSign {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,
        [string]$SignTool
    )

    if ($SignTool) {
        Invoke-NativeChecked -FilePath $SignTool -ArgumentList @(
            'sign', '/fd', 'SHA256', '/td', 'SHA256', '/tr', $TimestampUrl,
            '/sha1', $Certificate.Thumbprint, $Path)
    } else {
        $result = Set-AuthenticodeSignature -LiteralPath $Path -Certificate $Certificate `
            -HashAlgorithm SHA256 -TimestampServer $TimestampUrl -IncludeChain All
        if ($result.Status -ne 'Valid') {
            throw "Authenticode signing failed for ${Path}: $($result.Status)"
        }
    }

    $signature = Get-AuthenticodeSignature -LiteralPath $Path
    if ($signature.Status -ne 'Valid' `
        -or $null -eq $signature.SignerCertificate `
        -or $signature.SignerCertificate.Thumbprint -ne $expectedSignerThumbprint `
        -or $signature.SignerCertificate.GetCertHashString([Security.Cryptography.HashAlgorithmName]::SHA256) -ne $expectedSignerCertificateSha256 `
        -or $null -eq $signature.TimeStamperCertificate) {
        throw "Authenticode policy verification failed for ${Path}: $($signature.Status)"
    }
}

$preparation = Assert-Preparation
Assert-StageInputs $preparation
$signerContext = Import-PolicySigner
try {
    $signTool = Find-SignTool
    if ($Stage -eq 'Payloads') {
        $records = @()
        foreach ($entry in @($preparation.files)) {
            $path = Resolve-PreparedPath $entry.path
            Assert-FileHash $path $entry.sha256
            if ($entry.signable) {
                Invoke-AuthenticodeSign -Path $path -Certificate $signerContext.Certificate -SignTool $signTool
                $records += [ordered]@{
                    path = $entry.path
                    unsignedSha256 = $entry.sha256
                    signedSha256 = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
                }
            }
        }
        if ($records.Count -lt 3) {
            throw 'Signing allowlist did not contain the required Worker payloads.'
        }
        [ordered]@{
            schema = 'hch.worker-windows-signed-payloads/v1'
            version = $Version
            sourceCommit = $preparation.sourceCommit
            preparationSha256 = (Get-FileHash -LiteralPath $preparationPath -Algorithm SHA256).Hash.ToLowerInvariant()
            signerThumbprint = $expectedSignerThumbprint
            signerCertificateSha256 = $expectedSignerCertificateSha256
            timestampUrl = $TimestampUrl
            signedAtUtc = [DateTimeOffset]::UtcNow.ToString('O')
            files = @($records)
        } | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $workRoot 'signed-payloads.json') -Encoding utf8NoBOM
    } elseif ($Stage -eq 'Msi') {
        $unsignedReceiptPath = Join-Path $workRoot 'unsigned-msi.json'
        $payloadReceiptPath = Join-Path $workRoot 'signed-payloads.json'
        if (-not (Test-Path -LiteralPath $unsignedReceiptPath) -or -not (Test-Path -LiteralPath $payloadReceiptPath)) {
            throw 'Repacked MSI and signed payload receipts are required before MSI signing.'
        }
        $receipt = Get-Content -LiteralPath $unsignedReceiptPath -Raw | ConvertFrom-Json
        $msiPath = Join-Path $releaseRoot $expectedMsiName
        Assert-FileHash $msiPath $receipt.msiSha256
        $unsignedHash = $receipt.msiSha256
        Invoke-AuthenticodeSign -Path $msiPath -Certificate $signerContext.Certificate -SignTool $signTool
        [ordered]@{
            schema = 'hch.worker-windows-signed-msi/v1'
            version = $Version
            sourceCommit = $preparation.sourceCommit
            msi = $expectedMsiName
            unsignedSha256 = $unsignedHash
            signedSha256 = (Get-FileHash -LiteralPath $msiPath -Algorithm SHA256).Hash.ToLowerInvariant()
            signerThumbprint = $expectedSignerThumbprint
            signerCertificateSha256 = $expectedSignerCertificateSha256
            timestampUrl = $TimestampUrl
            signedAtUtc = [DateTimeOffset]::UtcNow.ToString('O')
        } | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $workRoot 'signed-msi.json') -Encoding utf8NoBOM
    } else {
        $checksumPath = Join-Path $releaseRoot 'SHA256SUMS.txt'
        if (-not (Test-Path -LiteralPath $checksumPath -PathType Leaf)) {
            throw 'Release checksums must exist before evidence signing.'
        }
        Add-Type -AssemblyName System.Security.Cryptography.Pkcs
        $content = [Security.Cryptography.Pkcs.ContentInfo]::new([IO.File]::ReadAllBytes($checksumPath))
        $cms = [Security.Cryptography.Pkcs.SignedCms]::new($content, $true)
        $cmsSigner = [Security.Cryptography.Pkcs.CmsSigner]::new($signerContext.Certificate)
        $cmsSigner.IncludeOption = [Security.Cryptography.X509Certificates.X509IncludeOption]::EndCertOnly
        $cmsSigner.SignedAttributes.Add(
            [Security.Cryptography.Pkcs.Pkcs9SigningTime]::new([DateTime]::UtcNow))
        $cms.ComputeSignature($cmsSigner, $true)
        $encoded = $cms.Encode()
        try {
            [IO.File]::WriteAllBytes((Join-Path $releaseRoot 'SHA256SUMS.p7s'), $encoded)
        } finally {
            [Security.Cryptography.CryptographicOperations]::ZeroMemory($encoded)
        }
        $verification = [Security.Cryptography.Pkcs.SignedCms]::new($content, $true)
        $verification.Decode([IO.File]::ReadAllBytes((Join-Path $releaseRoot 'SHA256SUMS.p7s')))
        $verification.CheckSignature($true)
        $actualSigner = $verification.SignerInfos[0].Certificate
        if ($actualSigner.Thumbprint -ne $expectedSignerThumbprint `
            -or $actualSigner.GetCertHashString([Security.Cryptography.HashAlgorithmName]::SHA256) -ne $expectedSignerCertificateSha256) {
            throw 'Detached evidence signature does not match signer policy.'
        }
    }
} finally {
    if ($signerContext.TemporaryPfxPath -and (Test-Path -LiteralPath $signerContext.TemporaryPfxPath)) {
        Remove-Item -LiteralPath $signerContext.TemporaryPfxPath -Force -ErrorAction SilentlyContinue
    }
    foreach ($path in $signerContext.NewStorePaths) {
        Remove-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue
    }
}

Write-Host "Isolated signing stage completed: $Stage"
