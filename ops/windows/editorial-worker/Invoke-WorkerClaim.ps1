[CmdletBinding()]
param(
  [string]$ConfigPath = (Join-Path $PSScriptRoot 'WorkerConfig.psd1'),
  [ValidateRange(0, 64)][int]$Requested = 1,
  [Parameter(Mandatory = $true)][string]$OutputPath
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'Hch.EditorialWorker.psm1') -Force
$config = Import-HchWorkerConfig -Path $ConfigPath
$response = Invoke-HchWorkerClaim -Config $config -RequestedCapacity $Requested

$fullOutput = [IO.Path]::GetFullPath($OutputPath)
$parent = Split-Path -Parent $fullOutput
if (-not (Test-Path -LiteralPath $parent)) { New-Item -ItemType Directory -Path $parent -Force | Out-Null }
[IO.File]::WriteAllText(
  $fullOutput,
  ($response | ConvertTo-Json -Depth 100),
  [Text.UTF8Encoding]::new($false)
)

[pscustomobject]@{
  nodeId = [string]$config.NodeId
  assignments = @($response.assignments).Count
  requestedCapacity = [int]$response.capacity.requestedCapacity
  grantedCapacity = [int]$response.capacity.grantedCapacity
  availableSlots = [int]$response.capacity.availableSlots
  capacityReason = [string]$response.capacity.reason
  capacityValidUntil = [string]$response.capacity.grantedUntil
  outputPath = $fullOutput
  generationStarted = $false
}
