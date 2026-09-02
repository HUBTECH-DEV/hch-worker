[CmdletBinding()]
param(
  [string]$NodePath = 'C:\Program Files\HCH\EditorialWorker\versions\3.1.0\runtime\node.exe',
  [string]$RootPublicKeyPath = 'C:\ProgramData\HCH\EditorialWorker\trust\orchestrator-root.pem',
  [string]$OutputDirectory = (Join-Path $PSScriptRoot 'artifacts'),
  [string]$ReleaseBaseUrl = 'https://github.com/HUBTECH-DEV/hch-worker/releases/download',
  [ValidatePattern('^\d+\.\d+\.\d+$')][string]$Version,
  [string]$SigningThumbprint = $env:HCH_WINDOWS_PUBLISHER_THUMBPRINT,
  [string]$TimestampUrl = 'http://timestamp.digicert.com'
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$repositoryRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..\..'))
$kitRoot = Join-Path $repositoryRoot 'ops\windows\editorial-worker'
$dashboardRoot = Join-Path $repositoryRoot 'ops\worker-dashboard'
$version = if ([string]::IsNullOrWhiteSpace($Version)) {
  (Get-Content -Raw -LiteralPath (Join-Path $kitRoot 'VERSION')).Trim()
} else {
  $Version
}
if ($version -notmatch '^\d+\.\d+\.\d+$') { throw 'hch-setup-version-invalid' }
foreach ($required in @($NodePath, $RootPublicKeyPath, (Join-Path $kitRoot 'service\bin\HchEditorialWorkerService.exe'))) {
  if (-not (Test-Path -LiteralPath $required -PathType Leaf)) { throw 'hch-setup-build-input-missing' }
}
$nodeSignature = Get-AuthenticodeSignature -LiteralPath $NodePath
if ([string]$nodeSignature.Status -ne 'Valid') { throw 'hch-setup-node-signature-invalid' }
$csc = Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
if (-not (Test-Path -LiteralPath $csc -PathType Leaf)) { throw 'hch-setup-csharp-compiler-missing' }

$buildRoot = Join-Path ([IO.Path]::GetTempPath()) ('hch-setup-build-' + [guid]::NewGuid().ToString('n'))
$stage = Join-Path $buildRoot 'payload'
$artifactName = "HCH-Worker-Setup-$version-x64.exe"
$outputRoot = [IO.Path]::GetFullPath($OutputDirectory)
$outputPath = Join-Path $outputRoot $artifactName
try {
  New-Item -ItemType Directory -Path $stage -Force | Out-Null
  $stageKit = Join-Path $stage 'ops\windows\editorial-worker'
  $stageInstaller = Join-Path $stage 'ops\windows\installer'
  $stageDashboard = Join-Path $stage 'ops\worker-dashboard'
  $stageLib = Join-Path $stage 'lib'
  foreach ($directory in @($stageKit, $stageInstaller, $stageDashboard, $stageLib,
      (Join-Path $stage 'runtime'), (Join-Path $stage 'trust'))) {
    New-Item -ItemType Directory -Path $directory -Force | Out-Null
  }
  Get-ChildItem -LiteralPath $kitRoot -Force | Where-Object {
    $_.Name -notin @('WorkerConfig.psd1', 'tests')
  } | ForEach-Object { Copy-Item -LiteralPath $_.FullName -Destination $stageKit -Recurse -Force }
  [IO.File]::WriteAllText((Join-Path $stageKit 'VERSION'), "$version`n", [Text.ASCIIEncoding]::new())
  Get-ChildItem -LiteralPath $dashboardRoot -Force | ForEach-Object {
    Copy-Item -LiteralPath $_.FullName -Destination $stageDashboard -Recurse -Force
  }
  foreach ($name in @('canonical-text.mjs','editorial-normalization.mjs','editorial-model-catalog.mjs',
      'editorial-policy.mjs','editorial-worker-signatures.mjs')) {
    Copy-Item -LiteralPath (Join-Path $repositoryRoot ('lib\' + $name)) -Destination $stageLib -Force
  }
  Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'Install-HchWorkerPackage.ps1') -Destination $stageInstaller
  Copy-Item -LiteralPath $NodePath -Destination (Join-Path $stage 'runtime\node.exe')
  Copy-Item -LiteralPath $RootPublicKeyPath -Destination (Join-Path $stage 'trust\orchestrator-root.pem')
  $payloadZip = Join-Path $buildRoot 'payload.zip'
  Compress-Archive -Path (Join-Path $stage '*') -DestinationPath $payloadZip -CompressionLevel Optimal
  New-Item -ItemType Directory -Path $outputRoot -Force | Out-Null
  $versionedSetupSource = Join-Path $buildRoot 'HchWorkerSetup.cs'
  $versionedSetupManifest = Join-Path $buildRoot 'HchWorkerSetup.exe.manifest'
  $assemblyVersion = "$version.0"
  $setupSource = Get-Content -Raw -LiteralPath (Join-Path $PSScriptRoot 'HchWorkerSetup.cs')
  $setupSource = [Regex]::Replace($setupSource, '(?m)^\[assembly: AssemblyVersion\("[^"]+"\)\]\r?$', "[assembly: AssemblyVersion(`"$assemblyVersion`")]", 1)
  $setupSource = [Regex]::Replace($setupSource, '(?m)^\[assembly: AssemblyFileVersion\("[^"]+"\)\]\r?$', "[assembly: AssemblyFileVersion(`"$assemblyVersion`")]", 1)
  if ($setupSource -notmatch [Regex]::Escape("[assembly: AssemblyVersion(`"$assemblyVersion`")]" ) -or
      $setupSource -notmatch [Regex]::Escape("[assembly: AssemblyFileVersion(`"$assemblyVersion`")]")) {
    throw 'hch-setup-version-stamp-failed'
  }
  [IO.File]::WriteAllText($versionedSetupSource, $setupSource, [Text.UTF8Encoding]::new($false))
  $setupManifest = Get-Content -Raw -LiteralPath (Join-Path $PSScriptRoot 'HchWorkerSetup.exe.manifest')
  $setupManifest = [Regex]::Replace(
    $setupManifest,
    '(<assemblyIdentity\s+version=")[^"]+("\s+name="Hubtech\.HchWorker\.Setup")',
    "`${1}$assemblyVersion`${2}",
    1)
  if ($setupManifest -notmatch ('assemblyIdentity\s+version="' + [Regex]::Escape($assemblyVersion) + '"')) {
    throw 'hch-setup-manifest-version-stamp-failed'
  }
  [IO.File]::WriteAllText($versionedSetupManifest, $setupManifest, [Text.UTF8Encoding]::new($false))
  $compilerArguments = @(
    '/nologo', '/target:winexe', '/platform:x64', '/optimize+', ('/out:' + $outputPath),
    ('/win32manifest:' + $versionedSetupManifest),
    ('/resource:' + $payloadZip + ',HchWorkerPayload'),
    '/reference:System.Windows.Forms.dll', '/reference:System.Drawing.dll',
    '/reference:System.Web.Extensions.dll', '/reference:System.IO.Compression.dll',
    '/reference:System.IO.Compression.FileSystem.dll', $versionedSetupSource
  )
  $compilerOutput = @(& $csc @compilerArguments 2>&1)
  if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $outputPath -PathType Leaf)) {
    $safeCompilerCode = if ($compilerOutput.Count -gt 0 -and
        [string]$compilerOutput[0] -match 'error CS\d+') { $Matches[0].Replace(' ', '-').ToLowerInvariant() } `
      else { 'unknown' }
    throw ('hch-setup-compile-failed:' + $safeCompilerCode)
  }
  if (-not [string]::IsNullOrWhiteSpace($SigningThumbprint)) {
    & (Join-Path $kitRoot 'Sign-HchWorkerReleaseArtifact.ps1') -BinaryPath $outputPath `
      -CertificateThumbprint $SigningThumbprint -TimestampUrl $TimestampUrl | Out-Null
  }
  $evidencePath = $outputPath + '.release.json'
  [void](& (Join-Path $kitRoot 'New-HchWorkerReleaseEvidence.ps1') `
    -BinaryPath $outputPath -OutputPath $evidencePath)
  $sha256 = (Get-FileHash -LiteralPath $outputPath -Algorithm SHA256).Hash.ToUpperInvariant()
  $wingetRoot = Join-Path $outputRoot 'winget'
  New-Item -ItemType Directory -Path $wingetRoot -Force | Out-Null
  $releaseUrl = $ReleaseBaseUrl.TrimEnd('/') + "/v$version/$artifactName"
  $manifest = @"
PackageIdentifier: Hubtech.HCHWorker
PackageVersion: $version
InstallerType: exe
Scope: machine
InstallModes:
- interactive
UpgradeBehavior: install
ReleaseDate: $([DateTimeOffset]::UtcNow.ToString('yyyy-MM-dd'))
Installers:
- Architecture: x64
  InstallerUrl: $releaseUrl
  InstallerSha256: $sha256
ManifestType: installer
ManifestVersion: 1.10.0
"@
  [IO.File]::WriteAllText((Join-Path $wingetRoot 'Hubtech.HCHWorker.installer.yaml'), $manifest,
    [Text.UTF8Encoding]::new($false))
  $versionManifest = @"
PackageIdentifier: Hubtech.HCHWorker
PackageVersion: $version
DefaultLocale: pt-BR
ManifestType: version
ManifestVersion: 1.10.0
"@
  $localeManifest = @"
PackageIdentifier: Hubtech.HCHWorker
PackageVersion: $version
PackageLocale: pt-BR
Publisher: HUBTECH CONSULTORIA E DESENVOLVIMENTO LTDA
PublisherUrl: https://hubtech.online
PackageName: HCH Editorial Worker
PackageUrl: https://github.com/HUBTECH-DEV/hch-worker
License: Proprietary
ShortDescription: Worker editorial distribuído do Hubtech Community Hub.
Description: Instala o serviço Windows, painel local e identidade Ed25519 do HCH Worker.
Tags:
- hch
- worker
- editorial
- hubtech
ManifestType: defaultLocale
ManifestVersion: 1.10.0
"@
  [IO.File]::WriteAllText((Join-Path $wingetRoot 'Hubtech.HCHWorker.yaml'), $versionManifest,
    [Text.UTF8Encoding]::new($false))
  [IO.File]::WriteAllText((Join-Path $wingetRoot 'Hubtech.HCHWorker.locale.pt-BR.yaml'), $localeManifest,
    [Text.UTF8Encoding]::new($false))
  [pscustomobject]@{
    artifact = $outputPath
    evidence = $evidencePath
    version = $version
    sha256 = $sha256
    winget = $wingetRoot
  }
} finally {
  Remove-Item -LiteralPath $buildRoot -Recurse -Force -ErrorAction SilentlyContinue
}
