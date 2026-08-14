[CmdletBinding()]
param(
  [string]$ConfigPath = (Join-Path $PSScriptRoot 'WorkerConfig.psd1'),
  [Parameter(Mandatory = $true)][string]$AssignmentPath
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'Hch.EditorialWorker.psm1') -Force
$config = Import-HchWorkerConfig -Path $ConfigPath
[void](Assert-HchClaimGate -Config $config)
$assignment = Read-HchJsonFile -Path $AssignmentPath

# This gate must be called immediately before the generator reads entry or the
# runtime profile. It does not generate content and never exposes the lease.
Assert-HchAssignmentIntegrity -Config $config -Assignment $assignment
