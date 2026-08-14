[CmdletBinding()]
param(
  [string]$ConfigPath = (Join-Path $PSScriptRoot 'WorkerConfig.psd1'),
  [Parameter(Mandatory = $true)][string]$AssignmentPath,
  [Parameter(Mandatory = $true)][string]$ProgressPath
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'Hch.EditorialWorker.psm1') -Force
$config = Import-HchWorkerConfig -Path $ConfigPath
$assignment = Read-HchJsonFile -Path $AssignmentPath
$progress = Read-HchJsonFile -Path $ProgressPath
Invoke-HchWorkerHeartbeat -Config $config -Assignment $assignment -Progress $progress
