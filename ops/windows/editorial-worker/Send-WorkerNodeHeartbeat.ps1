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
$ready = $null
try { $ready = Assert-HchClaimGate -Config $config } catch { }
$refreshBefore = if ($config.ContainsKey('ReadyRefreshBeforeSeconds')) {
  [int]$config.ReadyRefreshBeforeSeconds
} else { 3000 }
if ($null -eq $ready -or
    ([DateTimeOffset]::Parse([string]$ready.readyUntil) - [DateTimeOffset]::UtcNow).TotalSeconds -le $refreshBefore) {
  # This runner belongs to the service heartbeat loop. Renewal does not claim.
  try { [void](Invoke-HchWorkerBootstrap -Config $config) } catch { }
  try { $ready = Assert-HchClaimGate -Config $config } catch { $ready = $null }
}
$control = Get-HchWorkerControl -Config $config
$capacity = if ($null -eq $ready) {
  0
} elseif ($RequestedCapacity -ge 0) {
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
