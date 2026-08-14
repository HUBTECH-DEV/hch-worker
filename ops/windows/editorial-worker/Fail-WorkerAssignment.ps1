[CmdletBinding()]
param(
  [string]$ConfigPath = (Join-Path $PSScriptRoot 'WorkerConfig.psd1'),
  [Parameter(Mandatory = $true)][string]$AssignmentPath,
  [Parameter(Mandatory = $true)][ValidatePattern('^[a-z0-9][a-z0-9._-]{0,119}$')][string]$ErrorCode
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'Hch.EditorialWorker.psm1') -Force
$config = Import-HchWorkerConfig -Path $ConfigPath
$assignment = Read-HchJsonFile -Path $AssignmentPath
Invoke-HchWorkerFail -Config $config -Assignment $assignment -ErrorCode $ErrorCode
