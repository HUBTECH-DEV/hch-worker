[CmdletBinding(ConfirmImpact = 'High', SupportsShouldProcess = $true)]
param(
  [string]$ConfigPath = (Join-Path $PSScriptRoot 'WorkerConfig.psd1'),
  [Parameter(Mandatory = $true)]
  [ValidatePattern('^[a-z0-9][a-z0-9._-]{2,159}$')]
  [string]$OperationKey,
  [Parameter(Mandatory = $true)][switch]$ConfirmLeaseExpiredOrReclaimed
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'Hch.EditorialWorker.psm1') -Force
$config = Import-HchWorkerConfig -Path $ConfigPath

if ($PSCmdlet.ShouldProcess($OperationKey, 'archive expired idempotency record and permit a new request id')) {
  Move-HchExpiredOperationRequest -Config $config -OperationKey $OperationKey `
    -ConfirmLeaseExpiredOrReclaimed:$ConfirmLeaseExpiredOrReclaimed
}
