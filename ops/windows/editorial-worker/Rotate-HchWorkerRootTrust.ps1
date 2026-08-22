[CmdletBinding()]
param(
  [string]$ConfigPath = (Join-Path $PSScriptRoot 'WorkerConfig.psd1')
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$principal = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  throw 'worker-root-rotation-requires-administrator'
}

Import-Module (Join-Path $PSScriptRoot 'Hch.EditorialWorker.psm1') -Force
$config = Import-HchWorkerConfig -Path $ConfigPath
$serviceName = Get-HchWorkerServiceName -Config $config
$sourceRoot = Join-Path $PSScriptRoot 'trust\hch-windows-root-rotation.pem'
$targetRoot = [IO.Path]::GetFullPath([string]$config.RootPublicKeyPath)
if (-not (Test-Path -LiteralPath $sourceRoot -PathType Leaf)) { throw 'worker-new-root-public-key-not-found' }
$stateRoot = [IO.Path]::GetFullPath([string]$config.StateRoot)
$backupRoot = Join-Path $stateRoot ('backups\root-rotation-' + [DateTimeOffset]::UtcNow.ToString('yyyyMMddTHHmmssZ'))
New-Item -ItemType Directory -Path $backupRoot -Force | Out-Null
$service = Get-Service -Name $serviceName -ErrorAction Stop
if ($service.Status -ne 'Stopped') {
  Stop-Service -Name $serviceName -Force
  $service.WaitForStatus('Stopped', [TimeSpan]::FromMinutes(2))
}
$acl = Get-Acl -LiteralPath $targetRoot
Copy-Item -LiteralPath $targetRoot -Destination (Join-Path $backupRoot 'root-public.pem') -Force
$trustState = Join-Path $stateRoot 'trust-state.json'
if (Test-Path -LiteralPath $trustState -PathType Leaf) {
  Move-Item -LiteralPath $trustState -Destination (Join-Path $backupRoot 'trust-state.json') -Force
}
$temporaryRoot = $targetRoot + '.rotation-next'
Copy-Item -LiteralPath $sourceRoot -Destination $temporaryRoot -Force
Set-Acl -LiteralPath $temporaryRoot -AclObject $acl
Move-Item -LiteralPath $temporaryRoot -Destination $targetRoot -Force
Start-Service -Name $serviceName
(Get-Service -Name $serviceName).WaitForStatus('Running', [TimeSpan]::FromMinutes(1))
[pscustomobject]@{
  serviceName = $serviceName
  state = 'Running'
  rootFingerprint = 'verified-by-next-bootstrap'
  backupRoot = $backupRoot
}
