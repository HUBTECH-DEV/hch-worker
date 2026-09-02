[CmdletBinding()]
param(
  [string]$OutputPath,
  [ValidatePattern('^\d+\.\d+\.\d+$')][string]$Version,
  [string]$CompilerPath = (Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe')
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
  $OutputPath = Join-Path $PSScriptRoot 'service\bin\HchEditorialWorkerService.exe'
}
$frameworkRelease = [int](Get-ItemPropertyValue `
  -LiteralPath 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full' `
  -Name Release -ErrorAction Stop)
if ($frameworkRelease -lt 528040) { throw 'worker-service-net-framework-4.8-required' }

$sourcePath = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot 'service\HchEditorialWorkerService.cs'))
$manifestPath = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot 'service\HchEditorialWorkerService.exe.manifest'))
$sourceVersionPath = Join-Path $PSScriptRoot 'VERSION'
if ([string]::IsNullOrWhiteSpace($Version)) {
  $Version = (Get-Content -Raw -LiteralPath $sourceVersionPath).Trim()
}
if ($Version -notmatch '^\d+\.\d+\.\d+$') { throw 'worker-service-version-invalid' }
$compilerFullPath = [IO.Path]::GetFullPath($CompilerPath)
$outputFullPath = [IO.Path]::GetFullPath($OutputPath)
if (-not (Test-Path -LiteralPath $sourcePath -PathType Leaf)) { throw 'worker-service-source-not-found' }
if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) { throw 'worker-service-manifest-not-found' }
if (-not (Test-Path -LiteralPath $compilerFullPath -PathType Leaf)) { throw 'worker-service-csc-not-found' }
$outputDirectory = Split-Path -Parent $outputFullPath
if (-not (Test-Path -LiteralPath $outputDirectory -PathType Container)) {
  New-Item -ItemType Directory -Path $outputDirectory -Force | Out-Null
}

$temporaryRoot = Join-Path ([IO.Path]::GetTempPath()) ('hch-worker-service-build-' + [Guid]::NewGuid().ToString('N'))
try {
  New-Item -ItemType Directory -Path $temporaryRoot | Out-Null
  $versionedSourcePath = Join-Path $temporaryRoot 'HchEditorialWorkerService.cs'
  $versionedManifestPath = Join-Path $temporaryRoot 'HchEditorialWorkerService.exe.manifest'
  $assemblyVersion = "$Version.0"
  $source = Get-Content -Raw -LiteralPath $sourcePath
  $source = [Regex]::Replace($source, '(?m)^\[assembly: AssemblyVersion\("[^"]+"\)\]\r?$', "[assembly: AssemblyVersion(`"$assemblyVersion`")]", 1)
  $source = [Regex]::Replace($source, '(?m)^\[assembly: AssemblyFileVersion\("[^"]+"\)\]\r?$', "[assembly: AssemblyFileVersion(`"$assemblyVersion`")]", 1)
  $source = [Regex]::Replace($source, '(?m)^\[assembly: AssemblyInformationalVersion\("[^"]+"\)\]\r?$', "[assembly: AssemblyInformationalVersion(`"$Version`")]", 1)
  if ($source -notmatch [Regex]::Escape("[assembly: AssemblyVersion(`"$assemblyVersion`")]" ) -or
      $source -notmatch [Regex]::Escape("[assembly: AssemblyFileVersion(`"$assemblyVersion`")]" ) -or
      $source -notmatch [Regex]::Escape("[assembly: AssemblyInformationalVersion(`"$Version`")]")) {
    throw 'worker-service-version-stamp-failed'
  }
  [IO.File]::WriteAllText($versionedSourcePath, $source, [Text.UTF8Encoding]::new($false))
  $manifest = Get-Content -Raw -LiteralPath $manifestPath
  $manifest = [Regex]::Replace($manifest, '(<assemblyIdentity\s+version=")[^"]+("\s+processorArchitecture=)', "`${1}$assemblyVersion`${2}", 1)
  if ($manifest -notmatch ('assemblyIdentity\s+version="' + [Regex]::Escape($assemblyVersion) + '"')) {
    throw 'worker-service-manifest-version-stamp-failed'
  }
  [IO.File]::WriteAllText($versionedManifestPath, $manifest, [Text.UTF8Encoding]::new($false))

  $arguments = @(
    '/nologo',
    '/target:winexe',
    '/optimize+',
    '/checked+',
    '/platform:anycpu',
    '/reference:System.dll',
    '/reference:System.Core.dll',
    '/reference:System.ServiceProcess.dll',
    ('/win32manifest:' + $versionedManifestPath),
    ('/out:' + $outputFullPath),
    $versionedSourcePath
  )
  & $compilerFullPath @arguments
  if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $outputFullPath -PathType Leaf)) {
    throw "worker-service-build-failed:$LASTEXITCODE"
  }
} finally {
  Remove-Item -LiteralPath $temporaryRoot -Recurse -Force -ErrorAction SilentlyContinue
}
$hash = (Get-FileHash -LiteralPath $outputFullPath -Algorithm SHA256).Hash.ToLowerInvariant()
[void](& (Join-Path $PSScriptRoot 'New-HchWorkerReleaseEvidence.ps1') -BinaryPath $outputFullPath)
[pscustomobject]@{
  built = $true
  version = $Version
  framework = [Runtime.InteropServices.RuntimeEnvironment]::GetSystemVersion()
  frameworkRelease = $frameworkRelease
  compilerPath = $compilerFullPath
  outputPath = $outputFullPath
  sha256 = $hash
}
