[CmdletBinding()]
param(
  [string]$ConfigPath = (Join-Path $PSScriptRoot 'WorkerConfig.psd1'),
  [ValidateRange(-1, 64)][int]$RequestedCapacity = -1,
  [ValidateRange(-1, 100)][double]$CpuPercent = -1,
  [ValidateRange(-1, 100)][double]$MemoryPercent = -1,
  [ValidateRange(-1, 100)][double]$GpuPercent = -1
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'Hch.EditorialWorker.psm1') -Force
$config = Import-HchWorkerConfig -Path $ConfigPath
$control = Get-HchWorkerControl -Config $config
$capacity = if ($RequestedCapacity -ge 0) {
  $RequestedCapacity
} elseif ([bool]$control.acceptingClaims) {
  [int]$control.requestedParallelism
} else { 0 }
$pressure = @{}
if ($CpuPercent -ge 0) { $pressure.cpuPercent = $CpuPercent }
if ($MemoryPercent -ge 0) { $pressure.memoryPercent = $MemoryPercent }
if ($GpuPercent -ge 0) { $pressure.gpuPercent = $GpuPercent }

# Presence and capacity only: this command never claims or starts generation.
Invoke-HchWorkerNodeHeartbeat -Config $config -RequestedCapacity $capacity -Pressure $pressure
