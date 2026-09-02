[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$ScanPath,

    [Parameter(Mandatory)]
    [string]$EvidencePath,

    [switch]$RequireAvailable
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$resolvedScanPath = (Resolve-Path -LiteralPath $ScanPath).Path
$evidenceDirectory = Split-Path -Parent ([IO.Path]::GetFullPath($EvidencePath))
New-Item -ItemType Directory -Path $evidenceDirectory -Force | Out-Null

$statusCommand = Get-Command Get-MpComputerStatus -ErrorAction SilentlyContinue
$scanCommand = Get-Command Start-MpScan -ErrorAction SilentlyContinue
$available = $null -ne $statusCommand -and $null -ne $scanCommand
$enabled = $false
$statusReason = $null
$startedAt = [DateTimeOffset]::UtcNow

if ($available) {
    try {
        $defender = Get-MpComputerStatus
        $enabled = [bool]$defender.AntivirusEnabled -and [bool]$defender.RealTimeProtectionEnabled
        if (-not $enabled) {
            $statusReason = 'defender-disabled'
        }
    } catch {
        $available = $false
        $statusReason = 'defender-status-unavailable'
    }
} else {
    $statusReason = 'defender-cmdlets-unavailable'
}

if ($available -and $enabled) {
    Start-MpScan -ScanType CustomScan -ScanPath $resolvedScanPath
}

$detections = @()
if ($available -and $enabled -and (Get-Command Get-MpThreatDetection -ErrorAction SilentlyContinue)) {
    $detections = @(Get-MpThreatDetection -ErrorAction SilentlyContinue | Where-Object {
        $_.InitialDetectionTime -ge $startedAt.UtcDateTime -and
        (@($_.Resources) | Where-Object { $_ -like "*$resolvedScanPath*" }).Count -gt 0
    } | ForEach-Object {
        [pscustomobject]@{
            threatId = $_.ThreatID
            processName = $_.ProcessName
            actionSuccess = $_.ActionSuccess
            resources = @($_.Resources)
        }
    })
}

$passed = $available -and $enabled -and $detections.Count -eq 0
[ordered]@{
    schema = 'hch.worker-defender-scan/v1'
    generatedAtUtc = [DateTimeOffset]::UtcNow.ToString('O')
    scanPath = $resolvedScanPath
    available = $available
    enabled = $enabled
    status = if ($passed) { 'passed' } elseif (-not $available -or -not $enabled) { 'unavailable' } else { 'failed' }
    reason = $statusReason
    detections = @($detections)
} | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $EvidencePath -Encoding utf8NoBOM

if ($detections.Count -ne 0) {
    throw "Microsoft Defender detected $($detections.Count) threat occurrence(s) in the package inputs."
}
if ($RequireAvailable -and -not $passed) {
    throw "Microsoft Defender is required for this build but is not available and enabled: $statusReason"
}

if ($passed) {
    Write-Host 'Microsoft Defender scan passed.'
} else {
    Write-Warning "Microsoft Defender scan could not be enforced: $statusReason"
}
