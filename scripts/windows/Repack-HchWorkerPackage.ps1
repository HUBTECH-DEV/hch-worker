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

    [switch]$AcceptWixEula,
    [switch]$RequireDefender
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$repositoryRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\..')).Path
$windowsRoot = Join-Path $repositoryRoot 'src\windows'
$artifactRoot = Join-Path $repositoryRoot 'artifacts\windows-v4'
$workRoot = Join-Path $artifactRoot 'work'
$releaseRoot = Join-Path $artifactRoot 'release'
$wixOutput = Join-Path $workRoot 'wix-signed-payloads'
$servicePublish = Join-Path $workRoot 'publish\service'
$trayPublish = Join-Path $workRoot 'publish\tray'
$bootstrapPublish = Join-Path $workRoot 'publish\installer'
$trustWork = Join-Path $workRoot 'trust'
$preparationPath = Join-Path $workRoot 'package-preparation.json'
$payloadReceiptPath = Join-Path $workRoot 'signed-payloads.json'
$msiName = "HCH-Worker-$Version-win-x64.msi"
$msiPath = Join-Path $releaseRoot $msiName
$expectedSignerThumbprint = $ExpectedSignerThumbprint.ToUpperInvariant()
$expectedSignerCertificateSha256 = $ExpectedSignerCertificateSha256.ToUpperInvariant()

function Invoke-Checked {
    param([Parameter(Mandatory)][string]$FilePath, [Parameter(Mandatory)][string[]]$ArgumentList)
    & $FilePath @ArgumentList
    if ($LASTEXITCODE -ne 0) { throw "Command failed with exit code ${LASTEXITCODE}: $FilePath" }
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

if (-not $AcceptWixEula) { throw 'WiX 7 EULA acceptance is required.' }
if (-not (Test-Path -LiteralPath $preparationPath) -or -not (Test-Path -LiteralPath $payloadReceiptPath)) {
    throw 'Preparation and signed-payload receipts are required.'
}
$preparation = Get-Content -LiteralPath $preparationPath -Raw | ConvertFrom-Json -Depth 100
$receipt = Get-Content -LiteralPath $payloadReceiptPath -Raw | ConvertFrom-Json -Depth 100
if ($preparation.version -ne $Version `
    -or $preparation.sourceTreeDirty `
    -or -not $preparation.testsRun `
    -or -not $preparation.rootTrustPinned `
    -or $receipt.version -ne $Version `
    -or $receipt.sourceCommit -ne $preparation.sourceCommit `
    -or $receipt.preparationSha256 -ne (Get-FileHash -LiteralPath $preparationPath -Algorithm SHA256).Hash `
    -or $receipt.signerThumbprint -ne $expectedSignerThumbprint `
    -or $receipt.signerCertificateSha256 -ne $expectedSignerCertificateSha256) {
    throw 'Signed payload receipt does not match the reviewed preparation and signer policy.'
}

$head = (& git -C $repositoryRoot rev-parse HEAD).Trim()
if ($LASTEXITCODE -ne 0 -or $head -ne $preparation.sourceCommit `
    -or -not [string]::IsNullOrWhiteSpace((& git -C $repositoryRoot status --porcelain=v1 --untracked-files=all))) {
    throw 'Repackaging requires the exact clean source commit used for preparation.'
}

$signedByPath = @{}
foreach ($entry in @($receipt.files)) { $signedByPath[[string]$entry.path] = $entry }
$expectedPaths = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
$temporaryTrust = @()
try {
    $firstSignedPath = Resolve-PreparedPath ([string]$receipt.files[0].path)
    $initialSignature = Get-AuthenticodeSignature -LiteralPath $firstSignedPath
    if ($null -eq $initialSignature.SignerCertificate `
        -or $initialSignature.SignerCertificate.Thumbprint -ne $expectedSignerThumbprint `
        -or $initialSignature.SignerCertificate.GetCertHashString([Security.Cryptography.HashAlgorithmName]::SHA256) -ne $expectedSignerCertificateSha256) {
        throw 'Signed payload does not embed the reviewed signer certificate.'
    }
    $temporaryTrust = Add-TemporarySignerTrust $initialSignature.SignerCertificate

    foreach ($entry in @($preparation.files)) {
        [void]$expectedPaths.Add([string]$entry.path)
        $path = Resolve-PreparedPath ([string]$entry.path)
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "Prepared file is missing: $path" }
        $hash = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($entry.signable) {
            $signed = $signedByPath[[string]$entry.path]
            if ($null -eq $signed -or $signed.unsignedSha256 -ne $entry.sha256 -or $signed.signedSha256 -ne $hash) {
                throw "Signed payload hash receipt mismatch: $path"
            }
            $signature = Get-AuthenticodeSignature -LiteralPath $path
            if ($signature.Status -ne 'Valid' `
                -or $null -eq $signature.SignerCertificate `
                -or $signature.SignerCertificate.Thumbprint -ne $expectedSignerThumbprint `
                -or $signature.SignerCertificate.GetCertHashString([Security.Cryptography.HashAlgorithmName]::SHA256) -ne $expectedSignerCertificateSha256 `
                -or $null -eq $signature.TimeStamperCertificate) {
                throw "Signed payload failed Authenticode policy: $path"
            }
        } elseif ($hash -ne $entry.sha256) {
            throw "Non-signable package input changed after preparation: $path"
        }
    }
} finally {
    foreach ($path in $temporaryTrust) {
        Remove-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue
    }
}

$actualPaths = Get-ChildItem -Path (Join-Path $workRoot 'publish'), $trustWork -File -Recurse |
    ForEach-Object { [IO.Path]::GetRelativePath($workRoot, $_.FullName).Replace('\', '/') }
foreach ($path in $actualPaths) {
    if (-not $expectedPaths.Contains($path)) { throw "Unexpected package input appeared after preparation: $path" }
}

if (Test-Path -LiteralPath $wixOutput) { Remove-Item -LiteralPath $wixOutput -Recurse -Force }
if (Test-Path -LiteralPath $releaseRoot) { Remove-Item -LiteralPath $releaseRoot -Recurse -Force }
New-Item -ItemType Directory -Path $wixOutput, $releaseRoot -Force | Out-Null

$wixArguments = @(
    'build', (Join-Path $windowsRoot 'Hch.Worker.Installer\Hch.Worker.Installer.wixproj'),
    '--no-restore',
    '--configuration', 'Release',
    '-p:AcceptEula=wix7',
    "-p:ProductVersion=$Version",
    "-p:ServicePublishDir=$servicePublish",
    "-p:TrayPublishDir=$trayPublish",
    "-p:BootstrapPublishDir=$bootstrapPublish",
    "-p:OutputPath=$wixOutput",
    '-p:IncludeRootTrustPayload=true',
    "-p:RootPublicKeySource=$(Join-Path $trustWork 'orchestrator-root.pem')",
    "-p:RootTrustMetadataSource=$(Join-Path $trustWork 'root-trust.json')")
Invoke-Checked -FilePath dotnet -ArgumentList $wixArguments

$builtMsi = Join-Path $wixOutput $msiName
if (-not (Test-Path -LiteralPath $builtMsi -PathType Leaf)) { throw "WiX did not produce expected MSI: $builtMsi" }
Copy-Item -LiteralPath $builtMsi -Destination $msiPath
if ($null -ne (Get-AuthenticodeSignature -LiteralPath $msiPath).SignerCertificate) {
    throw 'Repackaging unexpectedly produced an Authenticode-signed MSI.'
}
& (Join-Path $PSScriptRoot 'Test-HchWorkerPackage.ps1') `
    -MsiPath $msiPath `
    -ExpectedVersion $Version

& (Join-Path $PSScriptRoot 'Test-HchWorkerDefender.ps1') `
    -ScanPath $releaseRoot `
    -EvidencePath (Join-Path $workRoot 'security\defender-unsigned-msi-scan.json') `
    -RequireAvailable:$RequireDefender

[ordered]@{
    schema = 'hch.worker-windows-unsigned-msi/v1'
    version = $Version
    sourceCommit = $preparation.sourceCommit
    preparationSha256 = (Get-FileHash -LiteralPath $preparationPath -Algorithm SHA256).Hash.ToLowerInvariant()
    signedPayloadReceiptSha256 = (Get-FileHash -LiteralPath $payloadReceiptPath -Algorithm SHA256).Hash.ToLowerInvariant()
    msi = $msiName
    msiSha256 = (Get-FileHash -LiteralPath $msiPath -Algorithm SHA256).Hash.ToLowerInvariant()
    generatedAtUtc = [DateTimeOffset]::UtcNow.ToString('O')
} | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $workRoot 'unsigned-msi.json') -Encoding utf8NoBOM

Write-Host "MSI rebuilt from policy-signed payloads: $msiPath"
