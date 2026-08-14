[CmdletBinding(SupportsShouldProcess = $true)]
param(
  [string]$ConfigPath = '',
  [string]$DashboardRoot = '',
  [ValidateRange(1, 65535)][int]$Port = 4319,
  [switch]$NoStart
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
foreach ($requiredEnvironmentVariable in @('ProgramFiles', 'ProgramData', 'SystemRoot')) {
  if ([string]::IsNullOrWhiteSpace([Environment]::GetEnvironmentVariable($requiredEnvironmentVariable))) {
    throw 'worker-dashboard-machine-root-unavailable'
  }
}
$canonicalConfigRoot = [IO.Path]::GetFullPath((Join-Path $env:ProgramData 'HCH\EditorialWorker\config'))
$canonicalConfigPath = [IO.Path]::GetFullPath((Join-Path $canonicalConfigRoot 'WorkerConfig.psd1'))
if ([string]::IsNullOrWhiteSpace($ConfigPath)) { $ConfigPath = $canonicalConfigPath }
$configFullPath = [IO.Path]::GetFullPath($ConfigPath)
if (-not $configFullPath.Equals($canonicalConfigPath, [StringComparison]::OrdinalIgnoreCase)) {
  throw 'worker-dashboard-config-outside-program-data'
}
Import-Module (Join-Path $PSScriptRoot 'Hch.EditorialWorker.psm1') -Force
$config = Import-HchWorkerConfig -Path $configFullPath
[void](Assert-HchNodeRuntime -Config $config)
if ($null -eq (Get-Command 'Register-ScheduledTask' -ErrorAction SilentlyContinue)) {
  throw 'scheduled-tasks-module-unavailable'
}

if ([string]::IsNullOrWhiteSpace($DashboardRoot)) {
  if ($config.ContainsKey('DashboardRoot')) { $DashboardRoot = [string]$config.DashboardRoot }
  else { $DashboardRoot = Join-Path $PSScriptRoot '..\..\worker-dashboard' }
}
if ($config.ContainsKey('DashboardPort') -and -not $PSBoundParameters.ContainsKey('Port')) {
  $Port = [int]$config.DashboardPort
}
$dashboardFullPath = [IO.Path]::GetFullPath($DashboardRoot)
if (-not (Test-Path -LiteralPath (Join-Path $dashboardFullPath 'server.mjs') -PathType Leaf)) {
  throw 'worker-dashboard-server-not-found'
}

$version = (Get-Content -Raw -LiteralPath (Join-Path $PSScriptRoot 'VERSION')).Trim()
if ($version -notmatch '^\d+\.\d+\.\d+$') { throw 'worker-kit-version-invalid' }
$installedKitRoot = [IO.Path]::GetFullPath((Join-Path $env:ProgramFiles (
  'HCH\EditorialWorker\versions\' + $version + '\ops\windows\editorial-worker'
)))
$launcherPath = [IO.Path]::GetFullPath((Join-Path $installedKitRoot 'Start-WorkerDashboard.ps1'))
if (-not (Test-Path -LiteralPath $launcherPath -PathType Leaf)) {
  throw 'worker-dashboard-installed-launcher-not-found'
}
$taskName = 'HCH Editorial Dashboard - ' + [string]$config.NodeId
$currentUser = [Security.Principal.WindowsIdentity]::GetCurrent().Name
$powershellPath = [IO.Path]::GetFullPath((Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'))
$arguments = '-NoLogo -NoProfile -NonInteractive -ExecutionPolicy RemoteSigned -File "' + $launcherPath +
  '" -ConfigPath "' + $configFullPath + '" -DashboardRoot "' + $dashboardFullPath +
  '" -Port ' + [string]$Port
$action = New-ScheduledTaskAction -Execute $powershellPath -Argument $arguments
$trigger = New-ScheduledTaskTrigger -AtLogOn -User $currentUser
$principal = New-ScheduledTaskPrincipal -UserId $currentUser -LogonType Interactive -RunLevel Limited
$settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -RestartCount 5 `
  -RestartInterval ([TimeSpan]::FromMinutes(1)) -ExecutionTimeLimit ([TimeSpan]::Zero)

$registered = $false
$started = $false
$previousInstanceStopped = $false
if ($PSCmdlet.ShouldProcess($taskName, 'register loopback-only worker dashboard task')) {
  $existingTask = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
  if ($null -ne $existingTask -and [string]$existingTask.State -eq 'Running') {
    Stop-ScheduledTask -TaskName $taskName
    $previousInstanceStopped = $true
  }
  Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger `
    -Principal $principal -Settings $settings -Description `
    'HCH loopback worker dashboard; fixed start/stop controls call the trusted local worker CLI.' `
    -Force | Out-Null
  $registered = $true
  if (-not $NoStart) { Start-ScheduledTask -TaskName $taskName; $started = $true }
}

[pscustomobject]@{
  taskName = $taskName
  principal = $currentUser
  runLevel = 'Limited'
  bind = '127.0.0.1'
  dataDirectory = [IO.Path]::GetFullPath([string]$config.StateRoot)
  url = 'http://127.0.0.1:' + [string]$Port
  registered = $registered
  started = $started
  previousInstanceStopped = $previousInstanceStopped
}
