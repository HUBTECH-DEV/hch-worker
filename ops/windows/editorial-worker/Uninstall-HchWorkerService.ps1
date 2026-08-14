[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
  [string]$ConfigPath,
  [ValidateRange(30, 86400)][int]$StopTimeoutSeconds = 3600
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
if ([string]::IsNullOrWhiteSpace($ConfigPath)) { $ConfigPath = Join-Path $PSScriptRoot 'WorkerConfig.psd1' }
Import-Module (Join-Path $PSScriptRoot 'Hch.EditorialWorker.psm1') -Force
$principal = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  throw 'worker-service-uninstall-requires-administrator'
}
$config = Import-HchWorkerConfig -Path $ConfigPath
$serviceName = Get-HchWorkerServiceName -Config $config
$service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
if ($null -eq $service) {
  [pscustomobject]@{ serviceName = $serviceName; removed = $false; reason = 'not-installed'; statePreserved = $true }
  return
}

if ($PSCmdlet.ShouldProcess($serviceName, 'stop and unregister HCH Windows Service; preserve state and identity')) {
  [void](Set-HchWorkerControl -Config $config -Parallelism 0 -AcceptingClaims $false -UpdatedBy 'service-uninstall')
  if ([string]$service.Status -ne 'Stopped') {
    Stop-Service -Name $serviceName
    $service.WaitForStatus([System.ServiceProcess.ServiceControllerStatus]::Stopped,
      [TimeSpan]::FromSeconds($StopTimeoutSeconds + 30))
  }
  $output = @(& (Join-Path $env:SystemRoot 'System32\sc.exe') 'delete' $serviceName 2>&1)
  if ($LASTEXITCODE -ne 0) { throw 'worker-service-delete-failed' }
  [pscustomobject]@{
    serviceName = $serviceName
    removed = $true
    statePreserved = $true
    identityPreserved = $true
    binariesPreserved = $true
  }
}
