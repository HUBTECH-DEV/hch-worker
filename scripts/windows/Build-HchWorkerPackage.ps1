[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidatePattern('^\d+\.\d+\.\d+$')]
    [string]$Version,

    [ValidateSet('Release')]
    [string]$Configuration = 'Release',

    [switch]$AllowUnsigned,
    [switch]$AllowUnpinnedCandidate,
    [switch]$AcceptWixEula,
    [switch]$SkipTests,
    [switch]$RequireDefender,

    [ValidateSet('Candidate')]
    [string]$ReleaseIntent = 'Candidate',

    [string]$SourceRef,

    [string]$RootPublicKeyPath,
    [string]$RootPublicKeyFingerprint,
    [string]$RootKeyId
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$repositoryRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\..')).Path
$windowsRoot = Join-Path $repositoryRoot 'src\windows'
$artifactRoot = Join-Path $repositoryRoot 'artifacts\windows-v4'
$workRoot = Join-Path $artifactRoot 'work'
$releaseRoot = Join-Path $artifactRoot 'release'
$servicePublish = Join-Path $workRoot 'publish\service'
$trayPublish = Join-Path $workRoot 'publish\tray'
$bootstrapPublish = Join-Path $workRoot 'publish\installer'
$bootstrapSelfTestAssembly = Join-Path $windowsRoot (
    "Hch.Worker.Installer\bin\$Configuration\net10.0-windows\win-x64\Hch.Worker.Installer.dll")
$trustWork = Join-Path $workRoot 'trust'
$wixOutput = Join-Path $workRoot 'wix'
$msiName = "HCH-Worker-$Version-win-x64.msi"
$msiPath = Join-Path $releaseRoot $msiName

function Invoke-Checked {
    param([Parameter(Mandatory)][string]$FilePath, [Parameter(Mandatory)][string[]]$ArgumentList)

    & $FilePath @ArgumentList
    if ($LASTEXITCODE -ne 0) {
        throw "Command failed with exit code ${LASTEXITCODE}: $FilePath"
    }
}

function Assert-UnsignedPayload {
    param([Parameter(Mandatory)][string]$Path)

    $signature = Get-AuthenticodeSignature -LiteralPath $Path
    if ($null -ne $signature.SignerCertificate) {
        throw "Unsigned preparation unexpectedly contains an Authenticode signature: $Path"
    }
}

function Invoke-GitText {
    param([Parameter(Mandatory)][string[]]$ArgumentList)

    $output = & git @ArgumentList 2>$null
    if ($LASTEXITCODE -ne 0) {
        throw "Git command failed: git $($ArgumentList -join ' ')"
    }
    return (@($output) -join "`n").Trim()
}

function Get-SourceState {
    param([Parameter(Mandatory)][string]$Version, [string]$DeclaredRef)

    $commit = Invoke-GitText @('rev-parse', 'HEAD')
    $status = Invoke-GitText @('status', '--porcelain=v1', '--untracked-files=all')
    $resolvedRef = $DeclaredRef
    if ([string]::IsNullOrWhiteSpace($resolvedRef)) {
        $resolvedRef = (& git symbolic-ref -q HEAD 2>$null)
        if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($resolvedRef)) {
            $resolvedRef = 'detached:' + $commit
        } else {
            $resolvedRef = $resolvedRef.Trim()
        }
    }

    $tagRef = "refs/tags/windows-v$Version"
    $immutableTag = $false
    if ($resolvedRef -eq $tagRef) {
        $tagType = Invoke-GitText @('cat-file', '-t', $tagRef)
        if ($tagType -ne 'tag') {
            throw "Windows version tag must be annotated: $tagRef"
        }
        $tagCommit = Invoke-GitText @('rev-parse', "$tagRef^{commit}")
        $immutableTag = $tagCommit -eq $commit
    }

    return [pscustomobject]@{
        Commit = $commit
        Ref = $resolvedRef
        Dirty = -not [string]::IsNullOrWhiteSpace($status)
        ImmutableTag = $immutableTag
    }
}

function Assert-VersionConsistency {
    param([Parameter(Mandatory)][string]$ExpectedVersion)

    [xml]$props = Get-Content -LiteralPath (Join-Path $windowsRoot 'Directory.Build.props') -Raw
    $declaredVersion = [string]$props.Project.PropertyGroup.Version
    $declaredAssemblyVersion = [string]$props.Project.PropertyGroup.AssemblyVersion
    $declaredFileVersion = [string]$props.Project.PropertyGroup.FileVersion
    if ($declaredVersion -ne $ExpectedVersion `
        -or $declaredAssemblyVersion -ne "$ExpectedVersion.0" `
        -or $declaredFileVersion -ne "$ExpectedVersion.0") {
        throw 'Version mismatch between the requested package and Directory.Build.props.'
    }

    $enrollmentSource = [IO.File]::ReadAllText(
        (Join-Path $windowsRoot 'Hch.Worker.Protocol\EnrollmentContracts.cs'))
    if ($enrollmentSource -notmatch 'RuntimeVersion\s*=\s*"(?<version>\d+\.\d+\.\d+)"' `
        -or $Matches.version -ne $ExpectedVersion) {
        throw 'Operational enrollment runtime version does not match the package version.'
    }

    foreach ($manifestPath in @(
        (Join-Path $windowsRoot 'Hch.Worker.Installer\app.manifest'),
        (Join-Path $windowsRoot 'Hch.Worker.Tray\app.manifest'))) {
        [xml]$manifest = Get-Content -LiteralPath $manifestPath -Raw
        $identity = $manifest.assembly.assemblyIdentity
        if ([string]$identity.version -ne "$ExpectedVersion.0") {
            throw "Application manifest version mismatch: $manifestPath"
        }
    }
}

function Assert-PublishedVersions {
    param([Parameter(Mandatory)][string]$ExpectedVersion)

    foreach ($path in @(
        (Join-Path $servicePublish 'Hch.Worker.Service.exe'),
        (Join-Path $trayPublish 'Hch.Worker.Tray.exe'),
        (Join-Path $bootstrapPublish 'Hch.Worker.Installer.exe'))) {
        $version = [Diagnostics.FileVersionInfo]::GetVersionInfo($path)
        if ($version.ProductVersion -notlike "$ExpectedVersion*" -or $version.FileVersion -ne "$ExpectedVersion.0") {
            throw "Published binary version mismatch: $path"
        }
    }
}

function Assert-RootTrustPayload {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$ExpectedFingerprint,
        [Parameter(Mandatory)][string]$KeyId
    )

    if ($KeyId -notmatch '^[A-Za-z0-9][A-Za-z0-9._:/-]{0,159}$') {
        throw 'RootKeyId has an invalid HCH identifier.'
    }
    if ($ExpectedFingerprint -notmatch '^SHA256:[A-Za-z0-9_-]{43}$') {
        throw 'RootPublicKeyFingerprint must use the HCH SHA256 base64url format.'
    }

    $resolved = (Resolve-Path -LiteralPath $Path).Path
    $pem = [IO.File]::ReadAllText($resolved, [Text.UTF8Encoding]::new($false, $true)).Trim()
    if ($pem -notmatch '(?s)\A-----BEGIN PUBLIC KEY-----\s+([A-Za-z0-9+/=\r\n]+)\s+-----END PUBLIC KEY-----\z') {
        throw 'RootPublicKeyPath must contain exactly one PEM PUBLIC KEY block.'
    }
    $spki = [Convert]::FromBase64String(($Matches[1] -replace '\s', ''))
    $ed25519PrefixHex = '302A300506032B6570032100'
    if ($spki.Length -ne 44 -or [Convert]::ToHexString([byte[]]$spki[0..11]) -cne $ed25519PrefixHex) {
        throw 'RootPublicKeyPath is not a parameter-free RFC 8410 Ed25519 public key.'
    }
    $digest = [Security.Cryptography.SHA256]::HashData($spki)
    $calculated = 'SHA256:' + [Convert]::ToBase64String($digest).TrimEnd('=').Replace('+', '-').Replace('/', '_')
    if ($calculated -cne $ExpectedFingerprint) {
        throw 'RootPublicKeyFingerprint does not match RootPublicKeyPath.'
    }
    return $resolved
}

Push-Location $repositoryRoot
try {
    foreach ($secretName in @(
        'HCH_SIGN_CERT_THUMBPRINT',
        'HCH_SIGN_PFX_PATH',
        'HCH_SIGN_PFX_BASE64',
        'HCH_SIGN_PFX_PASSWORD')) {
        if (-not [string]::IsNullOrWhiteSpace([Environment]::GetEnvironmentVariable($secretName))) {
            throw 'Signing material must never be present while product restore, test or publish executes. Use Sign-HchWorkerArtifacts.ps1 after this preparation step.'
        }
    }
    if (-not $AllowUnsigned) {
        throw 'This script prepares an unsigned candidate only. Pass -AllowUnsigned, then use the isolated signing and repackaging scripts.'
    }
    if (-not $AcceptWixEula) {
        throw 'WiX 7 requires explicit EULA acceptance. Review OSMF terms, then pass -AcceptWixEula.'
    }

    Assert-VersionConsistency -ExpectedVersion $Version
    $sourceState = Get-SourceState -Version $Version -DeclaredRef $SourceRef
    & (Join-Path $PSScriptRoot 'Test-HchWorkerInstallerSource.ps1')

    if (Test-Path -LiteralPath $workRoot) {
        Remove-Item -LiteralPath $workRoot -Recurse -Force
    }
    if (Test-Path -LiteralPath $releaseRoot) {
        Remove-Item -LiteralPath $releaseRoot -Recurse -Force
    }
    New-Item -ItemType Directory -Path $servicePublish, $trayPublish, $bootstrapPublish, $trustWork, $wixOutput, $releaseRoot -Force | Out-Null

    $rootTrustInputs = @(
        @($RootPublicKeyPath, $RootPublicKeyFingerprint, $RootKeyId) |
            Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
    )
    if ($rootTrustInputs.Count -notin 0, 3) {
        throw 'RootPublicKeyPath, RootPublicKeyFingerprint and RootKeyId are all-or-none.'
    }
    $hasRootTrustPayload = $rootTrustInputs.Count -eq 3
    if (-not $hasRootTrustPayload -and -not $AllowUnpinnedCandidate) {
        throw 'Signed candidates require an out-of-band root PEM, fingerprint and key id. Pass -AllowUnpinnedCandidate only for a non-releasable NotReady engineering candidate.'
    }
    if ($hasRootTrustPayload) {
        $RootPublicKeyPath = Assert-RootTrustPayload `
            -Path $RootPublicKeyPath `
            -ExpectedFingerprint $RootPublicKeyFingerprint `
            -KeyId $RootKeyId
        $packagedRootPublicKeyPath = Join-Path $trustWork 'orchestrator-root.pem'
        Copy-Item -LiteralPath $RootPublicKeyPath -Destination $packagedRootPublicKeyPath
        $rootTrustMetadataPath = Join-Path $trustWork 'root-trust.json'
        [ordered]@{
            schema = 'hch.worker-root-trust/v1'
            rootKeyId = $RootKeyId
            rootPublicKeyFingerprint = $RootPublicKeyFingerprint
            publicKeyFileName = 'orchestrator-root.pem'
        } | ConvertTo-Json | Set-Content -LiteralPath $rootTrustMetadataPath -Encoding utf8NoBOM
    }

    Invoke-Checked -FilePath dotnet -ArgumentList @('tool', 'restore')
    Invoke-Checked -FilePath dotnet -ArgumentList @(
        'restore', (Join-Path $windowsRoot 'Hch.Worker.sln'),
        '--locked-mode', '--runtime', 'win-x64', '-p:PublishReadyToRun=true')
    Invoke-Checked -FilePath dotnet -ArgumentList @(
        'restore', (Join-Path $windowsRoot 'Hch.Worker.Installer\Hch.Worker.Installer.wixproj'),
        '--locked-mode', '-p:AcceptEula=wix7')
    Invoke-Checked -FilePath dotnet -ArgumentList @('format', (Join-Path $windowsRoot 'Hch.Worker.sln'), '--verify-no-changes', '--no-restore')

    $securityEvidenceRoot = Join-Path $workRoot 'security'
    New-Item -ItemType Directory -Path $securityEvidenceRoot -Force | Out-Null
    & (Join-Path $PSScriptRoot 'Test-HchWorkerDependencies.ps1') `
        -SolutionPath (Join-Path $windowsRoot 'Hch.Worker.sln') `
        -EvidencePath (Join-Path $securityEvidenceRoot 'dependency-vulnerability-scan.json')

    if (-not $SkipTests) {
        Invoke-Checked -FilePath dotnet -ArgumentList @(
            'test', (Join-Path $windowsRoot 'Hch.Worker.Tests\Hch.Worker.Tests.csproj'),
            '--configuration', $Configuration, '--no-restore', '--runtime', 'win-x64',
            "-p:Version=$Version", "-p:AssemblyVersion=$Version.0", "-p:FileVersion=$Version.0"
        )
    }

    $informationalVersion = "$Version+$($sourceState.Commit)"
    $commonPublish = @(
        '--configuration', $Configuration,
        '--runtime', 'win-x64',
        '--self-contained', 'true',
        '--no-restore',
        '-p:ContinuousIntegrationBuild=true',
        '-p:PublishSingleFile=false',
        '-p:PublishTrimmed=false',
        '-p:PublishReadyToRun=true',
        '-p:DebugType=None',
        '-p:DebugSymbols=false',
        "-p:Version=$Version",
        "-p:AssemblyVersion=$Version.0",
        "-p:FileVersion=$Version.0",
        "-p:InformationalVersion=$informationalVersion"
    )
    Invoke-Checked -FilePath dotnet -ArgumentList (@('publish', (Join-Path $windowsRoot 'Hch.Worker.Service\Hch.Worker.Service.csproj')) + $commonPublish + @('--output', $servicePublish))
    Invoke-Checked -FilePath dotnet -ArgumentList (@('publish', (Join-Path $windowsRoot 'Hch.Worker.Tray\Hch.Worker.Tray.csproj')) + $commonPublish + @('--output', $trayPublish))
    Invoke-Checked -FilePath dotnet -ArgumentList @(
        'publish', (Join-Path $windowsRoot 'Hch.Worker.Installer\Hch.Worker.Installer.csproj'),
        '--configuration', $Configuration,
        '--runtime', 'win-x64',
        '--self-contained', 'true',
        '--no-restore',
        '-p:ContinuousIntegrationBuild=true',
        '-p:PublishSingleFile=true',
        '-p:PublishTrimmed=false',
        '-p:DebugType=None',
        '-p:DebugSymbols=false',
        "-p:Version=$Version",
        "-p:AssemblyVersion=$Version.0",
        "-p:FileVersion=$Version.0",
        "-p:InformationalVersion=$informationalVersion",
        '--output', $bootstrapPublish
    )

    # The single-file bootstrap intentionally requests elevation and contains
    # no loose DLL. Execute the managed assembly produced by the same publish
    # build for this non-mutating gate so CI does not display a UAC prompt.
    Invoke-Checked -FilePath dotnet -ArgumentList @($bootstrapSelfTestAssembly, 'self-test')
    Assert-PublishedVersions -ExpectedVersion $Version

    $signablePayloads = Get-ChildItem -Path $servicePublish, $trayPublish, $bootstrapPublish -File -Recurse |
        Where-Object { $_.Extension -in '.exe', '.dll' -and $_.Name -like 'Hch.Worker.*' } |
        Sort-Object FullName
    foreach ($payload in $signablePayloads) {
        Assert-UnsignedPayload -Path $payload.FullName
    }

    & (Join-Path $PSScriptRoot 'Test-HchWorkerDefender.ps1') `
        -ScanPath (Join-Path $workRoot 'publish') `
        -EvidencePath (Join-Path $securityEvidenceRoot 'defender-publish-scan.json') `
        -RequireAvailable:$RequireDefender

    $preparedFiles = Get-ChildItem -Path (Join-Path $workRoot 'publish'), $trustWork -File -Recurse |
        Sort-Object FullName |
        ForEach-Object {
            [ordered]@{
                path = [IO.Path]::GetRelativePath($workRoot, $_.FullName).Replace('\', '/')
                length = $_.Length
                sha256 = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
                signable = $signablePayloads.FullName -contains $_.FullName
            }
        }
    $preparation = [ordered]@{
        schema = 'hch.worker-windows-package-preparation/v1'
        version = $Version
        releaseIntent = $ReleaseIntent.ToLowerInvariant()
        sourceCommit = $sourceState.Commit
        sourceRef = $sourceState.Ref
        sourceTreeDirty = $sourceState.Dirty
        immutableVersionRef = $sourceState.ImmutableTag
        testsRun = -not $SkipTests
        dependencyScan = 'passed'
        defenderRequired = [bool]$RequireDefender
        rootTrustPinned = $hasRootTrustPayload
        rootKeyId = if ($hasRootTrustPayload) { $RootKeyId } else { $null }
        rootPublicKeyFingerprint = if ($hasRootTrustPayload) { $RootPublicKeyFingerprint } else { $null }
        expectedMsi = $msiName
        preparedAtUtc = [DateTimeOffset]::UtcNow.ToString('O')
        files = @($preparedFiles)
    }
    $preparationPath = Join-Path $workRoot 'package-preparation.json'
    $preparation | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $preparationPath -Encoding utf8NoBOM

    $wixArguments = @(
        'build', (Join-Path $windowsRoot 'Hch.Worker.Installer\Hch.Worker.Installer.wixproj'),
        '--no-restore',
        '--configuration', $Configuration,
        '-p:AcceptEula=wix7',
        "-p:ProductVersion=$Version",
        "-p:ServicePublishDir=$servicePublish",
        "-p:TrayPublishDir=$trayPublish",
        "-p:BootstrapPublishDir=$bootstrapPublish",
        "-p:OutputPath=$wixOutput"
    )
    if ($hasRootTrustPayload) {
        $wixArguments += @(
            '-p:IncludeRootTrustPayload=true',
            "-p:RootPublicKeySource=$packagedRootPublicKeyPath",
            "-p:RootTrustMetadataSource=$rootTrustMetadataPath"
        )
    }
    Invoke-Checked -FilePath dotnet -ArgumentList $wixArguments

    $builtMsi = Join-Path $wixOutput $msiName
    if (-not (Test-Path -LiteralPath $builtMsi -PathType Leaf)) {
        throw "WiX did not produce the expected MSI: $builtMsi"
    }
    Copy-Item -LiteralPath $builtMsi -Destination $msiPath
    Assert-UnsignedPayload -Path $msiPath

    & (Join-Path $PSScriptRoot 'Test-HchWorkerPackage.ps1') `
        -MsiPath $msiPath `
        -ExpectedVersion $Version

    [ordered]@{
        schema = 'hch.worker-windows-unsigned-msi/v1'
        version = $Version
        sourceCommit = $sourceState.Commit
        preparationSha256 = (Get-FileHash -LiteralPath $preparationPath -Algorithm SHA256).Hash.ToLowerInvariant()
        msi = $msiName
        msiSha256 = (Get-FileHash -LiteralPath $msiPath -Algorithm SHA256).Hash.ToLowerInvariant()
        generatedAtUtc = [DateTimeOffset]::UtcNow.ToString('O')
    } | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $workRoot 'unsigned-msi.json') -Encoding utf8NoBOM

    $provenance = [ordered]@{
        schemaVersion = 2
        product = 'HCH Worker'
        version = $Version
        releaseIntent = $ReleaseIntent.ToLowerInvariant()
        runtimeIdentifier = 'win-x64'
        sourceCommit = $sourceState.Commit
        sourceRef = $sourceState.Ref
        sourceTreeDirty = $sourceState.Dirty
        immutableVersionRef = $sourceState.ImmutableTag
        testsRun = -not $SkipTests
        dotnetSdk = (& dotnet --version).Trim()
        wixSdk = '7.0.0'
        signed = $false
        signingMode = 'external-isolated-required'
        rootTrustPinned = $hasRootTrustPayload
        rootKeyId = if ($hasRootTrustPayload) { $RootKeyId } else { $null }
        rootPublicKeyFingerprint = if ($hasRootTrustPayload) { $RootPublicKeyFingerprint } else { $null }
        generatedAtUtc = [DateTimeOffset]::UtcNow.ToString('O')
        msi = $msiName
    }
    $provenance | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $releaseRoot 'build-provenance.json') -Encoding utf8NoBOM

    Invoke-Checked -FilePath dotnet -ArgumentList @(
        'tool', 'run', 'sbom-tool', '--', 'generate',
        '-b', $releaseRoot,
        '-bc', $windowsRoot,
        '-pn', 'HCH Worker',
        '-pv', $Version,
        '-ps', 'HubTech',
        '-nsb', 'https://hubtech.online/sbom/hch-worker',
        '-D', 'true',
        '-mi', 'SPDX:2.2'
    )
    Invoke-Checked -FilePath dotnet -ArgumentList @(
        'tool', 'run', 'sbom-tool', '--', 'validate',
        '-b', $releaseRoot,
        '-o', (Join-Path $releaseRoot 'sbom-validation.json'),
        '-mi', 'SPDX:2.2'
    )

    [ordered]@{
        schemaVersion = 1
        releaseIntent = $ReleaseIntent.ToLowerInvariant()
        signed = $false
        rootTrustPinned = $hasRootTrustPayload
        testsRun = -not $SkipTests
        sourceTreeClean = -not $sourceState.Dirty
        immutableVersionRef = $sourceState.ImmutableTag
        releasable = $false
        nextStep = 'Sign-HchWorkerArtifacts.ps1 -Stage Payloads; Repack-HchWorkerPackage.ps1; Sign-HchWorkerArtifacts.ps1 -Stage Msi; Complete-HchWorkerReleaseEvidence.ps1'
    } | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $releaseRoot 'signing-status.json') -Encoding utf8NoBOM

    $hashLines = Get-ChildItem -LiteralPath $releaseRoot -File -Recurse |
        Where-Object Name -ne 'SHA256SUMS.txt' |
        Sort-Object FullName |
        ForEach-Object {
            $relative = [IO.Path]::GetRelativePath($releaseRoot, $_.FullName).Replace('\', '/')
            '{0}  {1}' -f (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant(), $relative
        }
    $hashLines | Set-Content -LiteralPath (Join-Path $releaseRoot 'SHA256SUMS.txt') -Encoding ascii

    Write-Host "Unsigned package candidate ready: $msiPath"
    Write-Host "Release evidence: $releaseRoot"
} finally {
    Pop-Location
}
