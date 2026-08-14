[CmdletBinding()]
param(
  [string]$ConfigPath = '',
  [string]$DashboardRoot = '',
  [ValidateRange(1, 65535)][int]$Port = 4319
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

foreach ($requiredEnvironmentVariable in @('ProgramFiles', 'ProgramData', 'SystemRoot')) {
  if ([string]::IsNullOrWhiteSpace([Environment]::GetEnvironmentVariable($requiredEnvironmentVariable))) {
    throw 'worker-dashboard-machine-root-unavailable'
  }
}

# The dashboard can control only the installed, version-pinned worker kit. The
# configuration intentionally lives outside Program Files at one machine-wide
# canonical path; neither location is inferred from a browser request.
$trustedVersionsRoot = [IO.Path]::GetFullPath((Join-Path $env:ProgramFiles 'HCH\EditorialWorker\versions'))
$workerCliRootPath = [IO.Path]::GetFullPath($PSScriptRoot).TrimEnd('\', '/')
$trustedVersionsPrefix = $trustedVersionsRoot.TrimEnd('\', '/') + [IO.Path]::DirectorySeparatorChar
if (-not $workerCliRootPath.StartsWith($trustedVersionsPrefix, [StringComparison]::OrdinalIgnoreCase)) {
  throw 'worker-dashboard-worker-kit-outside-program-files'
}
$relativeKitRoot = $workerCliRootPath.Substring($trustedVersionsPrefix.Length)
if ($relativeKitRoot -notmatch '^\d+\.\d+\.\d+\\ops\\windows\\editorial-worker$') {
  throw 'worker-dashboard-worker-kit-layout-invalid'
}

$workerConfigRootPath = [IO.Path]::GetFullPath((Join-Path $env:ProgramData 'HCH\EditorialWorker\config'))
$canonicalConfigPath = [IO.Path]::GetFullPath((Join-Path $workerConfigRootPath 'WorkerConfig.psd1'))
if ([string]::IsNullOrWhiteSpace($ConfigPath)) { $ConfigPath = $canonicalConfigPath }
$configFullPath = [IO.Path]::GetFullPath($ConfigPath)
if (-not $configFullPath.Equals($canonicalConfigPath, [StringComparison]::OrdinalIgnoreCase)) {
  throw 'worker-dashboard-config-outside-program-data'
}

$powershellRootPath = [IO.Path]::GetFullPath((Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0'))
$powershellPath = [IO.Path]::GetFullPath((Join-Path $powershellRootPath 'powershell.exe'))
Import-Module (Join-Path $PSScriptRoot 'Hch.EditorialWorker.psm1') -Force
$config = Import-HchWorkerConfig -Path $configFullPath
$nodePath = Assert-HchNodeRuntime -Config $config

if ([string]::IsNullOrWhiteSpace($DashboardRoot)) {
  if ($config.ContainsKey('DashboardRoot')) { $DashboardRoot = [string]$config.DashboardRoot }
  else { $DashboardRoot = Join-Path $PSScriptRoot '..\..\worker-dashboard' }
}
if ($config.ContainsKey('DashboardPort') -and -not $PSBoundParameters.ContainsKey('Port')) {
  $Port = [int]$config.DashboardPort
}
$dashboardPath = [IO.Path]::GetFullPath($DashboardRoot)
$serverPath = Join-Path $dashboardPath 'server.mjs'
if (-not (Test-Path -LiteralPath $serverPath -PathType Leaf)) { throw 'worker-dashboard-server-not-found' }
$workerCliPath = [IO.Path]::GetFullPath((Join-Path $workerCliRootPath 'Hch-Worker.ps1'))
foreach ($requiredPath in @(
  $workerCliRootPath,
  $workerConfigRootPath,
  $powershellRootPath,
  $workerCliPath,
  $configFullPath,
  $powershellPath
)) {
  if (-not (Test-Path -LiteralPath $requiredPath -PathType Leaf)) {
    if (-not (Test-Path -LiteralPath $requiredPath -PathType Container)) {
      throw 'worker-dashboard-control-path-not-found'
    }
  }
}

# These values are fixed locally. In particular, callers cannot request a LAN
# bind through this wrapper or inherit an unsafe host from the machine.
$env:HCH_WORKER_DASHBOARD_HOST = '127.0.0.1'
$env:HCH_WORKER_DASHBOARD_PORT = [string]$Port
$env:HCH_WORKER_DASHBOARD_DATA_DIR = [IO.Path]::GetFullPath([string]$config.StateRoot)

& $nodePath $serverPath `
  '--host' '127.0.0.1' `
  '--port' ([string]$Port) `
  '--data-dir' ([string]$env:HCH_WORKER_DASHBOARD_DATA_DIR) `
  '--worker-cli' $workerCliPath `
  '--worker-cli-root' $workerCliRootPath `
  '--worker-config' $configFullPath `
  '--worker-config-root' $workerConfigRootPath `
  '--powershell' $powershellPath `
  '--powershell-root' $powershellRootPath `
  '--control-timeout-ms' '75000' `
  '--control-plane-timeout-seconds' '15'
if ($LASTEXITCODE -ne 0) { throw "worker-dashboard-exited:$LASTEXITCODE" }
