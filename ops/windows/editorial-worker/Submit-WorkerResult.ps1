[CmdletBinding()]
param(
  [string]$ConfigPath = (Join-Path $PSScriptRoot 'WorkerConfig.psd1'),
  [Parameter(Mandatory = $true)][string]$AssignmentPath,
  [Parameter(Mandatory = $true)][string]$DraftPath
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'Hch.EditorialWorker.psm1') -Force
$config = Import-HchWorkerConfig -Path $ConfigPath
$assignment = Read-HchJsonFile -Path $AssignmentPath
$draft = Read-HchJsonFile -Path $DraftPath

# The module first recomputes entry/inputSnapshotHash and runtimeProfileHash,
# then repeats the canonical policy/manifest/input snapshot at completion. Any
# divergence discards the local result before it can be committed.
Invoke-HchWorkerComplete -Config $config -Assignment $assignment -Draft $draft
