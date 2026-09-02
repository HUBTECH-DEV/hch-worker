[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$EvidencePath,

    [Parameter(Mandatory)]
    [ValidatePattern('^\d+\.\d+\.\d+$')]
    [string]$Version,

    [Parameter(Mandatory)]
    [ValidatePattern('^[0-9a-f]{40}$')]
    [string]$SourceCommit,

    [Parameter(Mandatory)]
    [string]$MsiPath
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$resolvedEvidence = (Resolve-Path -LiteralPath $EvidencePath).Path
$resolvedMsi = (Resolve-Path -LiteralPath $MsiPath).Path
$raw = Get-Content -LiteralPath $resolvedEvidence -Raw
if ($raw -match '(?i)-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----|Authorization\s*:|Bearer\s+[A-Za-z0-9._~-]+') {
    throw 'Canary evidence contains secret-shaped material.'
}
$jsonDocument = [Text.Json.JsonDocument]::Parse($raw)
try {
    $startedAtText = $jsonDocument.RootElement.GetProperty('startedAtUtc').GetString()
    $completedAtText = $jsonDocument.RootElement.GetProperty('completedAtUtc').GetString()
} finally {
    $jsonDocument.Dispose()
}
$evidence = $raw | ConvertFrom-Json -Depth 100

function Assert-NoSensitivePropertyNames {
    param([AllowNull()][object]$Value, [string]$Path = '$')

    if ($null -eq $Value -or $Value -is [string] -or $Value -is [ValueType]) {
        return
    }
    if ($Value -is [Collections.IEnumerable] -and $Value -isnot [Management.Automation.PSCustomObject]) {
        $index = 0
        foreach ($item in $Value) {
            Assert-NoSensitivePropertyNames $item "$Path[$index]"
            $index++
        }
        return
    }
    foreach ($property in $Value.PSObject.Properties) {
        if ($property.Name -match '(?i)password|private.?key|lease.?token|authorization|bearer|secret|enrollment.?token') {
            throw "Canary evidence contains a prohibited property: $Path.$($property.Name)"
        }
        Assert-NoSensitivePropertyNames $property.Value "$Path.$($property.Name)"
    }
}

function Assert-TrueGate {
    param([Parameter(Mandatory)][string]$Name)

    $property = $evidence.gates.PSObject.Properties[$Name]
    if ($null -eq $property -or $property.Value -isnot [bool] -or -not $property.Value) {
        throw "Canary gate is not proven: $Name"
    }
}

Assert-NoSensitivePropertyNames $evidence
$msiSha256 = (Get-FileHash -LiteralPath $resolvedMsi -Algorithm SHA256).Hash.ToLowerInvariant()
if ($evidence.schema -ne 'hch.worker-windows-canary/v1' `
    -or $evidence.status -ne 'passed' `
    -or $evidence.sanitized -isnot [bool] `
    -or -not $evidence.sanitized `
    -or $evidence.version -ne $Version `
    -or $evidence.sourceCommit -cne $SourceCommit `
    -or $evidence.msiSha256 -cne $msiSha256) {
    throw 'Canary evidence does not bind the exact signed candidate.'
}

$startedAt = [DateTimeOffset]::ParseExact(
    $startedAtText,
    'O',
    [Globalization.CultureInfo]::InvariantCulture,
    [Globalization.DateTimeStyles]::AssumeUniversal -bor [Globalization.DateTimeStyles]::AdjustToUniversal)
$completedAt = [DateTimeOffset]::ParseExact(
    $completedAtText,
    'O',
    [Globalization.CultureInfo]::InvariantCulture,
    [Globalization.DateTimeStyles]::AssumeUniversal -bor [Globalization.DateTimeStyles]::AdjustToUniversal)
if ($completedAt -le $startedAt -or ($completedAt - $startedAt) -gt [TimeSpan]::FromHours(24)) {
    throw 'Canary timestamps do not describe one bounded validation session.'
}

foreach ($gate in @(
    'installedPausedDrain',
    'legacyServiceStoppedDisabled',
    'enrollment',
    'bootstrap',
    'heartbeat',
    'claim',
    'progress',
    'completedPendingEditorialReview',
    'restartPausedDrain',
    'rollbackTo310',
    'rollbackHeartbeat')) {
    Assert-TrueGate $gate
}

if ([int]$evidence.heartbeats.count -lt 2 `
    -or [int]$evidence.capacity.requested -ne 1 `
    -or [int]$evidence.capacity.granted -ne 1 `
    -or [int]$evidence.capacity.maxActiveObserved -gt 1 `
    -or [int]$evidence.capacity.maxActiveObserved -lt 1 `
    -or [int]$evidence.progress.samples -lt 2 `
    -or [double]$evidence.progress.firstPercent -lt 0 `
    -or [double]$evidence.progress.lastPercent -gt 100 `
    -or [double]$evidence.progress.lastPercent -le [double]$evidence.progress.firstPercent `
    -or $evidence.progress.stalled -isnot [bool] `
    -or $evidence.progress.stalled `
    -or $evidence.rollback.targetVersion -ne '3.1.0' `
    -or $evidence.rollback.v4ServiceDisabled -isnot [bool] `
    -or -not $evidence.rollback.v4ServiceDisabled `
    -or $evidence.rollback.legacyServiceStartMode -ne 'AutomaticDelayed') {
    throw 'Canary capacity, progress or rollback evidence is invalid.'
}

Write-Host "Windows canary evidence passed for exact MSI $msiSha256."
