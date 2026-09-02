[CmdletBinding()]
param(
    [ValidatePattern('^\d+\.\d+\.\d+$')][string]$Version = '3.1.1',
    [ValidatePattern('^[0-9a-f]{40}$')][string]$SourceCommit,
    [string]$OutputDirectory = 'artifacts/bridge',
    [switch]$Force
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Invoke-CheckedNative {
    param([Parameter(Mandatory)][string]$Command, [Parameter(Mandatory)][string[]]$Arguments)
    $output = @(& $Command @Arguments)
    $exitCode = $LASTEXITCODE
    if ($exitCode -ne 0) { throw "bridge-archive-command-failed:$Command" }
    $output
}

function Copy-BridgePath {
    param([Parameter(Mandatory)][string]$Source, [Parameter(Mandatory)][string]$Destination)
    if (-not (Test-Path -LiteralPath $Source)) { throw "bridge-archive-source-missing:$Source" }
    $sourceItem = Get-Item -LiteralPath $Source -Force
    if (($sourceItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "bridge-archive-source-link-rejected:$Source"
    }
    if ($sourceItem.PSIsContainer) {
        $links = @(Get-ChildItem -LiteralPath $Source -Force -Recurse | Where-Object {
            ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0
        })
        if ($links.Count -ne 0) { throw "bridge-archive-source-link-rejected:$($links[0].FullName)" }
    }
    $parent = Split-Path -Parent $Destination
    if (-not (Test-Path -LiteralPath $parent -PathType Container)) {
        New-Item -ItemType Directory -Path $parent -Force | Out-Null
    }
    Copy-Item -LiteralPath $Source -Destination $Destination -Recurse -Force
}

if ($Version -cne '3.1.1') { throw 'bridge-archive-version-not-approved' }
if (-not [Runtime.InteropServices.RuntimeInformation]::IsOSPlatform(
        [Runtime.InteropServices.OSPlatform]::Linux)) {
    throw 'bridge-archive-reproducible-build-requires-linux'
}

$repositoryRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
if ([string]::IsNullOrWhiteSpace($SourceCommit)) {
    $sourceCommitOutput = @(Invoke-CheckedNative 'git' @('-C', $repositoryRoot, 'rev-parse', 'HEAD'))
    if ($sourceCommitOutput.Count -ne 1) { throw 'bridge-archive-source-commit-invalid' }
    $SourceCommit = ([string]$sourceCommitOutput[0]).Trim().ToLowerInvariant()
}
if ($SourceCommit -notmatch '^[0-9a-f]{40}$') {
    throw 'bridge-archive-source-commit-invalid'
}
$headOutput = @(Invoke-CheckedNative 'git' @('-C', $repositoryRoot, 'rev-parse', 'HEAD'))
if ($headOutput.Count -ne 1) { throw 'bridge-archive-source-commit-mismatch' }
$head = ([string]$headOutput[0]).Trim().ToLowerInvariant()
if ($head -cne $SourceCommit) { throw 'bridge-archive-source-commit-mismatch' }
$sourceEpochOutput = @(Invoke-CheckedNative 'git' @('-C', $repositoryRoot, 'show', '-s', '--format=%ct', $SourceCommit))
if ($sourceEpochOutput.Count -ne 1) { throw 'bridge-archive-source-epoch-invalid' }
$sourceEpochText = ([string]$sourceEpochOutput[0]).Trim()
$sourceEpoch = 0L
if (-not [Int64]::TryParse($sourceEpochText, [ref]$sourceEpoch) -or $sourceEpoch -le 0) {
    throw 'bridge-archive-source-epoch-invalid'
}

$tarVersionOutput = @(Invoke-CheckedNative 'tar' @('--version'))
$tarVersion = if ($tarVersionOutput.Count -gt 0) { [string]$tarVersionOutput[0] } else { '' }
if ($tarVersion -notmatch 'GNU tar') {
    throw 'bridge-archive-gnu-tar-required'
}

$outputRoot = if ([IO.Path]::IsPathRooted($OutputDirectory)) {
    [IO.Path]::GetFullPath($OutputDirectory)
} else {
    [IO.Path]::GetFullPath((Join-Path $repositoryRoot $OutputDirectory))
}
New-Item -ItemType Directory -Path $outputRoot -Force | Out-Null
$temporaryRoot = Join-Path ([IO.Path]::GetTempPath()) ('hch-worker-bridge-' + [Guid]::NewGuid().ToString('N'))

try {
    New-Item -ItemType Directory -Path $temporaryRoot | Out-Null
    foreach ($platform in @('linux', 'macos')) {
        $stageRoot = Join-Path $temporaryRoot $platform
        $productRoot = Join-Path $stageRoot 'hch-worker'
        New-Item -ItemType Directory -Path $productRoot -Force | Out-Null
        [IO.File]::WriteAllText((Join-Path $productRoot 'VERSION'), "$Version`n", [Text.ASCIIEncoding]::new())

        foreach ($relative in @(
                'lib',
                'ops/linux/editorial-worker',
                'ops/worker-dashboard')) {
            Copy-BridgePath (Join-Path $repositoryRoot $relative) (Join-Path $productRoot $relative)
        }
        $linuxPackagePath = Join-Path $productRoot 'ops/linux/editorial-worker/package.json'
        $linuxPackage = Get-Content -Raw -LiteralPath $linuxPackagePath | ConvertFrom-Json
        $linuxPackage.version = $Version
        $linuxPackageJson = $linuxPackage | ConvertTo-Json -Depth 20
        [IO.File]::WriteAllText($linuxPackagePath, "$linuxPackageJson`n", [Text.UTF8Encoding]::new($false))

        if ($platform -ceq 'linux') {
            foreach ($relative in @('ops/systemd', 'scripts/hch-editorial-workerctl',
                    'scripts/run-editorial-republication.sh', 'scripts/run-editorial-enrollment.sh')) {
                Copy-BridgePath (Join-Path $repositoryRoot $relative) (Join-Path $productRoot $relative)
            }
            $executables = @(
                'ops/linux/editorial-worker/worker.mjs',
                'scripts/hch-editorial-workerctl',
                'scripts/run-editorial-republication.sh',
                'scripts/run-editorial-enrollment.sh')
        } else {
            Copy-BridgePath (Join-Path $repositoryRoot 'ops/macos/editorial-worker') `
                (Join-Path $productRoot 'ops/macos/editorial-worker')
            [IO.File]::WriteAllText(
                (Join-Path $productRoot 'ops/macos/editorial-worker/VERSION'),
                "$Version`n",
                [Text.ASCIIEncoding]::new())
            $executables = @(
                'ops/linux/editorial-worker/worker.mjs',
                'ops/macos/editorial-worker/hch-editorial-workerctl',
                'ops/macos/editorial-worker/install-launch-agents.sh')
        }

        foreach ($relative in $executables) {
            Invoke-CheckedNative 'chmod' @('0755', (Join-Path $productRoot $relative))
        }
        $files = @(Get-ChildItem -LiteralPath $productRoot -File -Force -Recurse)
        if ($files.Count -eq 0 -or $files.Count -gt 4096) { throw 'bridge-archive-entry-count-invalid' }
        $expandedBytes = ($files | Measure-Object -Property Length -Sum).Sum
        if ($null -eq $expandedBytes -or [Int64]$expandedBytes -le 0 -or [Int64]$expandedBytes -gt 768MB) {
            throw 'bridge-archive-expanded-size-limit-exceeded'
        }

        $archiveName = "HCH-Worker-$Version-$($platform -eq 'linux' ? 'linux-x64' : 'macos-universal').tar.gz"
        $archivePath = Join-Path $outputRoot $archiveName
        if (Test-Path -LiteralPath $archivePath) {
            if (-not $Force) { throw "bridge-archive-output-exists:$archiveName" }
            Remove-Item -LiteralPath $archivePath -Force
        }
        Invoke-CheckedNative 'tar' @(
            '--sort=name',
            "--mtime=@$sourceEpoch",
            '--owner=0',
            '--group=0',
            '--numeric-owner',
            '--format=pax',
            '--pax-option=delete=atime,delete=ctime',
            '-czf', $archivePath,
            '-C', $stageRoot,
            'hch-worker')
        $archive = Get-Item -LiteralPath $archivePath
        if ($archive.Length -le 0 -or $archive.Length -gt 512MB) { throw 'bridge-archive-size-limit-exceeded' }
    }

    $result = foreach ($file in @(Get-ChildItem -LiteralPath $outputRoot -Filter "HCH-Worker-$Version-*.tar.gz" -File | Sort-Object Name)) {
        [pscustomobject]@{
            file = $file.FullName
            bytes = $file.Length
            sha256 = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
            sourceCommit = $SourceCommit
        }
    }
    $result
} finally {
    if (Test-Path -LiteralPath $temporaryRoot) {
        Remove-Item -LiteralPath $temporaryRoot -Recurse -Force
    }
}
