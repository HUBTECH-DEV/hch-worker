[CmdletBinding()]
param(
  [string]$OutputPath,
  [string]$CompilerPath = (Join-Path ([Runtime.InteropServices.RuntimeEnvironment]::GetRuntimeDirectory()) 'csc.exe')
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
$compilerFullPath = [IO.Path]::GetFullPath($CompilerPath)
$outputFullPath = [IO.Path]::GetFullPath($OutputPath)
if (-not (Test-Path -LiteralPath $sourcePath -PathType Leaf)) { throw 'worker-service-source-not-found' }
if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) { throw 'worker-service-manifest-not-found' }
if (-not (Test-Path -LiteralPath $compilerFullPath -PathType Leaf)) { throw 'worker-service-csc-not-found' }
$outputDirectory = Split-Path -Parent $outputFullPath
if (-not (Test-Path -LiteralPath $outputDirectory -PathType Container)) {
  New-Item -ItemType Directory -Path $outputDirectory -Force | Out-Null
}

$arguments = @(
  '/nologo',
  '/target:winexe',
  '/optimize+',
  '/checked+',
  '/platform:anycpu',
  '/reference:System.dll',
  '/reference:System.Core.dll',
  '/reference:System.ServiceProcess.dll',
  ('/win32manifest:' + $manifestPath),
  ('/out:' + $outputFullPath),
  $sourcePath
)
& $compilerFullPath @arguments
if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $outputFullPath -PathType Leaf)) {
  throw "worker-service-build-failed:$LASTEXITCODE"
}
$hash = (Get-FileHash -LiteralPath $outputFullPath -Algorithm SHA256).Hash.ToLowerInvariant()
[void](& (Join-Path $PSScriptRoot 'New-HchWorkerReleaseEvidence.ps1') -BinaryPath $outputFullPath)
[pscustomobject]@{
  built = $true
  framework = [Runtime.InteropServices.RuntimeEnvironment]::GetSystemVersion()
  frameworkRelease = $frameworkRelease
  compilerPath = $compilerFullPath
  outputPath = $outputFullPath
  sha256 = $hash
}
