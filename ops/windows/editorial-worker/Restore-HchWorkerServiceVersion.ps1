[CmdletBinding(SupportsShouldProcess = $true)]
param(
  [Parameter(Mandatory = $true)][ValidatePattern('^\d+\.\d+\.\d+$')][string]$Version,
  [string]$ConfigPath,
  [string]$DestinationRoot = (Join-Path $env:ProgramFiles 'HCH\EditorialWorker')
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
if ([string]::IsNullOrWhiteSpace($ConfigPath)) { $ConfigPath = Join-Path $PSScriptRoot 'WorkerConfig.psd1' }
$principal = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  throw 'worker-service-restore-requires-administrator'
}
Import-Module (Join-Path $PSScriptRoot 'Hch.EditorialWorker.psm1') -Force
$config = Import-HchWorkerConfig -Path $ConfigPath
$serviceName = Get-HchWorkerServiceName -Config $config
$versionRoot = [IO.Path]::GetFullPath((Join-Path $DestinationRoot ('versions\' + $Version)))
$kit = Join-Path $versionRoot 'ops\windows\editorial-worker'
$binary = Join-Path $kit 'service\bin\HchEditorialWorkerService.exe'
$installedConfig = Join-Path $env:ProgramData 'HCH\EditorialWorker\config\WorkerConfig.psd1'
foreach ($path in @($binary, (Join-Path $kit 'Run-WorkerCycle.ps1'),
    (Join-Path $kit 'Send-WorkerNodeHeartbeat.ps1'), (Join-Path $kit 'Hch-Worker.ps1'), $installedConfig)) {
  if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw ('worker-service-restore-file-missing:' + $path) }
}
$q = { param([string]$value) '"' + $value.Replace('"', '\"') + '"' }
$imagePath = (& $q $binary) +
  ' --service-name ' + (& $q $serviceName) +
  ' --powershell ' + (& $q (Join-Path $PSHOME 'powershell.exe')) +
  ' --runner ' + (& $q (Join-Path $kit 'Run-WorkerCycle.ps1')) +
  ' --heartbeat-runner ' + (& $q (Join-Path $kit 'Send-WorkerNodeHeartbeat.ps1')) +
  ' --control-cli ' + (& $q (Join-Path $kit 'Hch-Worker.ps1')) +
  ' --config ' + (& $q $installedConfig) +
  ' --temp-root ' + (& $q (Join-Path ([string]$config.StateRoot) 'service-temp')) +
  ' --poll-seconds 15 --stop-timeout-seconds 3600'
if ($PSCmdlet.ShouldProcess($serviceName, ('restore installed version ' + $Version))) {
  $service = Get-Service -Name $serviceName -ErrorAction Stop
  if ([string]$service.Status -ne 'Stopped') { Stop-Service -Name $serviceName -ErrorAction Stop }
  Set-ItemProperty -LiteralPath ('HKLM:\SYSTEM\CurrentControlSet\Services\' + $serviceName) `
    -Name ImagePath -Value $imagePath -Type ExpandString
  & (Join-Path $env:SystemRoot 'System32\sc.exe') config $serviceName start= delayed-auto | Out-Null
  if ($LASTEXITCODE -ne 0) { throw 'worker-service-restore-startup-config-failed' }
  Start-Service -Name $serviceName
  (Get-Service -Name $serviceName).WaitForStatus(
    [System.ServiceProcess.ServiceControllerStatus]::Running, [TimeSpan]::FromSeconds(30))
}
[pscustomobject]@{ restored = $true; serviceName = $serviceName; version = $Version; imagePath = $imagePath }
