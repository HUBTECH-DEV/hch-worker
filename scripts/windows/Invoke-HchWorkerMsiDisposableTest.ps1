[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$MsiPath,

    [Parameter(Mandatory)]
    [ValidatePattern('^\d+\.\d+\.\d+$')]
    [string]$Version,

    [Parameter(Mandatory)]
    [ValidatePattern('^[A-Fa-f0-9]{40}$')]
    [string]$ExpectedSignerThumbprint,

    [Parameter(Mandatory)]
    [ValidatePattern('^[A-Fa-f0-9]{64}$')]
    [string]$ExpectedSignerCertificateSha256,

    [Parameter(Mandatory)]
    [ValidateSet('GitHubHosted', 'MarkedDisposableVm')]
    [string]$EnvironmentKind,

    [string]$DisposableMarkerPath,

    [Parameter(Mandatory)]
    [ValidateSet('I_UNDERSTAND_THIS_INSTALLS_AND_REMOVES_HCH_WORKER_ON_A_DISPOSABLE_MACHINE')]
    [string]$ConfirmDisposableExecution,

    [Parameter(Mandatory)]
    [string]$EvidencePath
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$expectedSignerThumbprint = $ExpectedSignerThumbprint.ToUpperInvariant()
$expectedSignerCertificateSha256 = $ExpectedSignerCertificateSha256.ToUpperInvariant()
$resolvedMsi = (Resolve-Path -LiteralPath $MsiPath).Path
$resolvedEvidence = [IO.Path]::GetFullPath($EvidencePath)
$evidenceDirectory = Split-Path -Parent $resolvedEvidence
$programDataRoot = [IO.Path]::GetFullPath((Join-Path $env:ProgramData 'HubTech\HCH Worker'))
$legacyProductRoot = [IO.Path]::GetFullPath((Join-Path $env:ProgramData 'HCH\EditorialWorker'))
$programFilesRoot = [IO.Path]::GetFullPath((Join-Path $env:ProgramFiles 'HubTech\HCH Worker'))
$rollbackSentinel = 'I_UNDERSTAND_THIS_IS_A_DISPOSABLE_ROLLBACK_TEST'
$ownerSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$testRoot = Join-Path ([IO.Path]::GetTempPath()) ('hch-worker-msi-e2e-' + [Guid]::NewGuid().ToString('N'))
$extractRoot = Join-Path $testRoot 'administrative-image'
$logsRoot = Join-Path $testRoot 'logs'
$temporaryTrust = @()
$installedByHarness = $false
$createdProductData = $false

if ($resolvedEvidence.StartsWith(
        ([IO.Path]::GetFullPath($testRoot).TrimEnd('\') + '\'),
        [StringComparison]::OrdinalIgnoreCase)) {
    throw 'EvidencePath must be outside the disposable scratch directory.'
}

function Assert-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'The disposable MSI lifecycle test requires an elevated administrator session.'
    }
}

function Assert-DisposableEnvironment {
    if ($EnvironmentKind -eq 'GitHubHosted') {
        if ($env:CI -ne 'true' `
            -or $env:GITHUB_ACTIONS -ne 'true' `
            -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted') {
            throw 'GitHubHosted mode is allowed only on a GitHub-hosted Actions runner.'
        }
        return
    }

    if ([string]::IsNullOrWhiteSpace($DisposableMarkerPath)) {
        throw 'MarkedDisposableVm mode requires an expiring authorization marker.'
    }
    $markerPath = (Resolve-Path -LiteralPath $DisposableMarkerPath).Path
    $markerItem = Get-Item -LiteralPath $markerPath -Force
    if (($markerItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw 'Disposable authorization marker cannot be a reparse point.'
    }
    $marker = Get-Content -LiteralPath $markerPath -Raw | ConvertFrom-Json -Depth 20
    $expiresAt = [DateTimeOffset]::ParseExact(
        [string]$marker.expiresAtUtc,
        'O',
        [Globalization.CultureInfo]::InvariantCulture)
    if ($marker.schema -ne 'hch.disposable-windows-msi-test/v1' `
        -or $marker.machineName -cne [Environment]::MachineName `
        -or $marker.purpose -cne 'HCH Worker MSI lifecycle test' `
        -or $expiresAt -le [DateTimeOffset]::UtcNow `
        -or $expiresAt -gt [DateTimeOffset]::UtcNow.AddHours(24)) {
        throw 'Disposable authorization marker is invalid, expired or too long-lived.'
    }
}

function Get-MsiProperty {
    param([Parameter(Mandatory)][string]$Name)

    $installer = New-Object -ComObject WindowsInstaller.Installer
    $database = $installer.OpenDatabase($resolvedMsi, 0)
    $view = $database.OpenView("SELECT ``Value`` FROM ``Property`` WHERE ``Property``='$Name'")
    try {
        [void]$view.Execute()
        $record = $view.Fetch()
        if ($null -eq $record) { throw "MSI property is missing: $Name" }
        return [string]$record.StringData(1)
    } finally {
        [void]$view.Close()
    }
}

function Test-ProductRegistered {
    param([Parameter(Mandatory)][string]$ProductCode)

    foreach ($path in @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\$ProductCode",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\$ProductCode")) {
        if (Test-Path -LiteralPath $path) { return $true }
    }
    return $false
}

function Invoke-MsiExec {
    param(
        [Parameter(Mandatory)][string[]]$Arguments,
        [Parameter(Mandatory)][int[]]$ExpectedExitCodes
    )

    $startInfo = [Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = (Get-Command msiexec.exe -ErrorAction Stop).Source
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    foreach ($argument in $Arguments) {
        [void]$startInfo.ArgumentList.Add($argument)
    }
    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $startInfo
    try {
        if (-not $process.Start()) { throw 'msiexec.exe did not start.' }
        if (-not $process.WaitForExit(600000)) {
            $process.Kill($true)
            throw 'msiexec.exe exceeded the ten-minute disposable-test timeout.'
        }
        if ($ExpectedExitCodes -notcontains $process.ExitCode) {
            throw "msiexec.exe returned unexpected exit code $($process.ExitCode)."
        }
        return $process.ExitCode
    } finally {
        $process.Dispose()
    }
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

function Assert-SignedFile {
    param([Parameter(Mandatory)][string]$Path)

    $signature = Get-AuthenticodeSignature -LiteralPath $Path
    if ($signature.Status -ne 'Valid' `
        -or $null -eq $signature.SignerCertificate `
        -or $signature.SignerCertificate.Thumbprint -ne $expectedSignerThumbprint `
        -or $signature.SignerCertificate.GetCertHashString([Security.Cryptography.HashAlgorithmName]::SHA256) -ne $expectedSignerCertificateSha256 `
        -or $null -eq $signature.TimeStamperCertificate) {
        throw "Extracted file failed signer/timestamp policy: $Path"
    }
}

function Assert-NoInstalledProduct {
    param([Parameter(Mandatory)][string]$ProductCode)

    if (Get-Service -Name HchWorker -ErrorAction SilentlyContinue) {
        throw 'HchWorker service already exists; the machine is not clean.'
    }
    if (Test-ProductRegistered $ProductCode) {
        throw 'The MSI product is already registered; the machine is not clean.'
    }
    foreach ($path in $programDataRoot, $legacyProductRoot, $programFilesRoot) {
        if (Test-Path -LiteralPath $path) {
            throw "Existing Worker state or binaries make this machine unsafe for a destructive lifecycle test: $path"
        }
    }
}

function Assert-BootstrapArtifactsAbsent {
    foreach ($path in @(
        (Join-Path $programDataRoot 'config.json'),
        (Join-Path $programDataRoot '.bootstrap-v4.pending'),
        (Join-Path $programDataRoot 'state\identity\worker-ed25519.pkcs8.dpapi'),
        (Join-Path $programDataRoot 'trust\orchestrator-root.pem'))) {
        if (Test-Path -LiteralPath $path) {
            throw "MSI rollback left a bootstrap artifact behind: $path"
        }
    }
}

function Assert-Uninstalled {
    param([Parameter(Mandatory)][string]$ProductCode)

    if (Get-Service -Name HchWorker -ErrorAction SilentlyContinue) {
        throw 'HchWorker service remains after uninstall/rollback.'
    }
    if (Test-ProductRegistered $ProductCode) {
        throw 'MSI product registration remains after uninstall/rollback.'
    }
    foreach ($path in @(
        (Join-Path $programFilesRoot '4\Service\Hch.Worker.Service.exe'),
        (Join-Path $programFilesRoot '4\Tray\Hch.Worker.Tray.exe'),
        (Join-Path $programFilesRoot '4\Installer\Hch.Worker.Installer.exe'))) {
        if (Test-Path -LiteralPath $path) {
            throw "Installed executable remains after uninstall/rollback: $path"
        }
    }
}

function Get-RequiredHash {
    param([Parameter(Mandatory)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Required installed state is missing: $Path"
    }
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

Assert-Administrator
Assert-DisposableEnvironment
New-Item -ItemType Directory -Path $testRoot, $extractRoot, $logsRoot, $evidenceDirectory -Force | Out-Null

$productCode = Get-MsiProperty 'ProductCode'
$productVersion = Get-MsiProperty 'ProductVersion'
$productName = Get-MsiProperty 'ProductName'
$manufacturer = Get-MsiProperty 'Manufacturer'
if ($productCode -notmatch '^\{[A-Fa-f0-9-]{36}\}$' `
    -or $productVersion -ne $Version `
    -or $productName -ne 'HCH Worker' `
    -or $manufacturer -ne 'HubTech') {
    throw 'MSI identity does not match the expected HCH Worker product and version.'
}
Assert-NoInstalledProduct $productCode

$msiHash = (Get-FileHash -LiteralPath $resolvedMsi -Algorithm SHA256).Hash.ToLowerInvariant()
$msiSignature = Get-AuthenticodeSignature -LiteralPath $resolvedMsi
if ($null -eq $msiSignature.SignerCertificate `
    -or $msiSignature.SignerCertificate.Thumbprint -ne $expectedSignerThumbprint `
    -or $msiSignature.SignerCertificate.GetCertHashString([Security.Cryptography.HashAlgorithmName]::SHA256) -ne $expectedSignerCertificateSha256) {
    throw 'MSI does not embed the reviewed signer certificate.'
}

try {
    $temporaryTrust = Add-TemporarySignerTrust $msiSignature.SignerCertificate
    Assert-SignedFile $resolvedMsi

    $extractLog = Join-Path $logsRoot 'administrative-extract.log'
    [void](Invoke-MsiExec @(
        '/a', $resolvedMsi,
        "TARGETDIR=$extractRoot",
        "HCH_OWNER_SID=$ownerSid",
        '/qn', '/norestart', '/l*v', $extractLog) @(0))
    Assert-Uninstalled $productCode
    Assert-BootstrapArtifactsAbsent

    $extractedSignables = @(Get-ChildItem -LiteralPath $extractRoot -File -Recurse |
        Where-Object { $_.Name -like 'Hch.Worker.*' -and $_.Extension -in '.exe', '.dll' } |
        Sort-Object FullName)
    if ($extractedSignables.Count -lt 3) {
        throw 'Administrative image did not contain the expected first-party signed payloads.'
    }
    foreach ($file in $extractedSignables) { Assert-SignedFile $file.FullName }

    $rollbackLog = Join-Path $logsRoot 'forced-rollback.log'
    [void](Invoke-MsiExec @(
        '/i', $resolvedMsi,
        "HCH_OWNER_SID=$ownerSid",
        "HCH_TEST_ROLLBACK=$rollbackSentinel",
        '/qn', '/norestart', '/l*v', $rollbackLog) @(1603))
    Assert-Uninstalled $productCode
    Assert-BootstrapArtifactsAbsent

    $installLog = Join-Path $logsRoot 'clean-install.log'
    [void](Invoke-MsiExec @(
        '/i', $resolvedMsi,
        "HCH_OWNER_SID=$ownerSid",
        '/qn', '/norestart', '/l*v', $installLog) @(0))
    $installedByHarness = $true
    $createdProductData = Test-Path -LiteralPath $programDataRoot
    if (-not (Test-ProductRegistered $productCode)) { throw 'Clean install did not register the MSI product.' }
    if (-not (Get-Service -Name HchWorker -ErrorAction SilentlyContinue)) { throw 'Clean install did not create HchWorker service.' }

    $configPath = Join-Path $programDataRoot 'config.json'
    $identityPath = Join-Path $programDataRoot 'state\identity\worker-ed25519.pkcs8.dpapi'
    $rootTrustPath = Join-Path $programDataRoot 'trust\orchestrator-root.pem'
    $configHash = Get-RequiredHash $configPath
    $identityHash = Get-RequiredHash $identityPath
    $rootTrustHash = Get-RequiredHash $rootTrustPath
    if (Test-Path -LiteralPath (Join-Path $programDataRoot '.bootstrap-v4.pending')) {
        throw 'Bootstrap commit marker remains after a successful installation.'
    }

    $configuration = Get-Content -LiteralPath $configPath -Raw | ConvertFrom-Json -Depth 50
    $lastParallelismProperty = $configuration.PSObject.Properties |
        Where-Object { $_.Name -eq 'lastNonZeroMaxConcurrentJobs' -or $_.Name -eq 'LastNonZeroMaxConcurrentJobs' } |
        Select-Object -First 1
    if ($null -eq $lastParallelismProperty -or [int]$lastParallelismProperty.Value -ne 1) {
        throw 'Fresh Worker configuration did not retain the safe parallelism default.'
    }
    $readyPath = Join-Path $programDataRoot 'state\ready.json'
    $pausedDrainEvidence = 'not-ready-no-capacity-state'
    if (Test-Path -LiteralPath $readyPath) {
        $ready = Get-Content -LiteralPath $readyPath -Raw | ConvertFrom-Json -Depth 50
        if ([int]$ready.requestedCapacity -ne 0 -or [int]$ready.grantedCapacity -ne 0) {
            throw 'Fresh installation exposed non-zero capacity before an explicit Start.'
        }
        $pausedDrainEvidence = 'ready-state-requested-and-granted-capacity-zero'
    }

    $repairLog = Join-Path $logsRoot 'repair.log'
    [void](Invoke-MsiExec @('/fa', $productCode, '/qn', '/norestart', '/l*v', $repairLog) @(0))
    if ((Get-RequiredHash $configPath) -ne $configHash `
        -or (Get-RequiredHash $identityPath) -ne $identityHash `
        -or (Get-RequiredHash $rootTrustPath) -ne $rootTrustHash) {
        throw 'MSI repair changed preserved Worker configuration, identity or root trust.'
    }

    $uninstallLog = Join-Path $logsRoot 'uninstall.log'
    [void](Invoke-MsiExec @('/x', $productCode, '/qn', '/norestart', '/l*v', $uninstallLog) @(0))
    $installedByHarness = $false
    Assert-Uninstalled $productCode
    if ((Get-RequiredHash $configPath) -ne $configHash `
        -or (Get-RequiredHash $identityPath) -ne $identityHash `
        -or (Get-RequiredHash $rootTrustPath) -ne $rootTrustHash) {
        throw 'MSI uninstall did not preserve Worker configuration, identity and root trust exactly.'
    }

    $logEvidence = foreach ($log in Get-ChildItem -LiteralPath $logsRoot -File | Sort-Object Name) {
        [ordered]@{
            name = $log.Name
            sha256 = (Get-FileHash -LiteralPath $log.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
        }
    }
    [ordered]@{
        schema = 'hch.worker-windows-msi-e2e/v1'
        status = 'passed'
        version = $Version
        productCode = $productCode
        msiSha256 = $msiHash
        signerThumbprint = $expectedSignerThumbprint
        signerCertificateSha256 = $expectedSignerCertificateSha256
        environmentKind = $EnvironmentKind
        machineName = [Environment]::MachineName
        rollbackExitCode = 1603
        extractedFirstPartySignedFiles = $extractedSignables.Count
        pausedDrainEvidence = $pausedDrainEvidence
        repairPreservedState = $true
        uninstallPreservedState = $true
        logs = @($logEvidence)
        completedAtUtc = [DateTimeOffset]::UtcNow.ToString('O')
    } | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $resolvedEvidence -Encoding utf8NoBOM
} finally {
    if ($installedByHarness -and (Test-ProductRegistered $productCode)) {
        try {
            [void](Invoke-MsiExec @('/x', $productCode, '/qn', '/norestart') @(0, 1605, 1614))
        } catch {
            Write-Warning "Emergency MSI cleanup failed: $($_.Exception.Message)"
        }
    }
    foreach ($path in $temporaryTrust) {
        Remove-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue
    }
    if (Test-Path -LiteralPath $testRoot) {
        Remove-Item -LiteralPath $testRoot -Recurse -Force
    }
    if ($createdProductData -and -not (Test-ProductRegistered $productCode) -and (Test-Path -LiteralPath $programDataRoot)) {
        $resolvedCleanup = (Resolve-Path -LiteralPath $programDataRoot).Path
        if ($resolvedCleanup -cne $programDataRoot) {
            throw "Refusing to clean an unexpected product-data path: $resolvedCleanup"
        }
        Remove-Item -LiteralPath $resolvedCleanup -Recurse -Force
    }
}

Write-Host "Disposable MSI lifecycle test passed: $resolvedEvidence"
