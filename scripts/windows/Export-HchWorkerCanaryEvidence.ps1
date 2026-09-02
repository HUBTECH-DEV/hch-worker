[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$CaptureDirectory,

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

<#
.SYNOPSIS
Exports deterministic, unsigned HCH Worker Windows canary evidence from a
frozen bundle of real captures.

.DESCRIPTION
The exporter never runs a canary, probes a live service, signs evidence, or
creates observations. It projects only already-validated response captures,
real SCM probes, durable runtime state, assignment journals, and a rollback
backup receipt from CaptureDirectory. Receipt digests are recomputed from the
sanitized projections. Output is UTF-8 without BOM, LF terminated, and
published atomically without overwriting an existing file.

Current runtime limitation: the C# runtime durably persists enrollment,
readiness/trust, migration backup receipts, and assignment journals, but it
does not yet persist accepted node-heartbeat, assignment-heartbeat,
complete/fail response captures or SCM/restart/rollback probes. Consequently a
real export remains blocked until the canary harness or a future runtime sink
materializes the complete frozen bundle below. Missing sources fail closed;
this script never manufactures a sample or gate.

Minimum frozen capture bundle (all files are strict JSON and no other files are
allowed):

  probes/installed-state.json
  probes/legacy-before-start.json
  probes/msi-disposable-e2e.json
  probes/restart-state.json
  runtime/enrollment/operational-key.json
  runtime/ready.json
  runtime/trust-state.json
  runtime/journals/assignments/<assignment-id>.json
  accepted/node-heartbeats/*.json
  accepted/assignment-heartbeats/*.json
  accepted/completions/*.json
  accepted/failures/*.json
  rollback/rollback.json
  <legacyBackupReceiptRelativePath from rollback/rollback.json>

The accepted capture envelopes must be written only after the existing C#
contract validators accept the corresponding response. They intentionally omit
lease tokens, request bodies, drafts, editorial content, credentials, and HTTP
headers. The MSI lifecycle receipt must come from
Invoke-HchWorkerMsiDisposableTest.ps1 for the exact candidate. State probes
carry independent SCM and process observations and bind ProductCode,
PackageCode, ImagePath and installed payload hashes to that receipt. The
rollback producer records an SCM observation and references the actual legacy
backup receipt; this exporter hashes that file and both sanitized service
definitions instead of trusting supplied aggregate hashes.
#>

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$maximumSourceFileBytes = 4 * 1024 * 1024
$maximumTotalSourceBytes = 64 * 1024 * 1024
$maximumClockSkew = [TimeSpan]::FromMinutes(5)
$maximumHeartbeatServerSkew = [TimeSpan]::FromSeconds(5)
$minimumHeartbeatSpan = [TimeSpan]::FromMinutes(15)
$maximumHeartbeatGap = [TimeSpan]::FromSeconds(120)
$maximumSessionDuration = [TimeSpan]::FromHours(24)
$sourceBytesRead = [int64]0
$pathComparison = if ($IsWindows) { [StringComparison]::OrdinalIgnoreCase } else { [StringComparison]::Ordinal }
$pathComparer = if ($IsWindows) { [StringComparer]::OrdinalIgnoreCase } else { [StringComparer]::Ordinal }
$sourceDigests = [Collections.Generic.Dictionary[string, string]]::new($pathComparer)
$requestIds = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
$receiptHashes = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)

function Get-Sha256Bytes {
    param([Parameter(Mandatory)][byte[]]$Bytes)

    $hasher = [Security.Cryptography.SHA256]::Create()
    try {
        return [Convert]::ToHexString($hasher.ComputeHash($Bytes)).ToLowerInvariant()
    } finally {
        $hasher.Dispose()
    }
}

function Get-Sha256Text {
    param([Parameter(Mandatory)][string]$Value)

    return Get-Sha256Bytes ([Text.UTF8Encoding]::new($false).GetBytes($Value))
}

function Get-RequiredProperty {
    param(
        [Parameter(Mandatory)][object]$Value,
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$Path
    )

    $property = $Value.PSObject.Properties[$Name]
    if ($null -eq $property) {
        throw "Required canary source property is missing: $Path.$Name."
    }
    return $property.Value
}

function Assert-ExactPropertyNames {
    param(
        [Parameter(Mandatory)][object]$Value,
        [Parameter(Mandatory)][string[]]$Names,
        [Parameter(Mandatory)][string]$Path
    )

    $properties = @($Value.PSObject.Properties)
    if ($properties.Count -ne $Names.Count) {
        throw "Canary source $Path does not have the exact permitted property set."
    }
    $actual = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($property in $properties) {
        [void]$actual.Add($property.Name)
    }
    foreach ($name in $Names) {
        if (-not $actual.Contains($name)) {
            throw "Canary source $Path is missing required property $name."
        }
    }
}

function Assert-NoDuplicateJsonPropertyNames {
    param(
        [Parameter(Mandatory)][Text.Json.JsonElement]$Element,
        [Parameter(Mandatory)][string]$Path
    )

    if ($Element.ValueKind -eq [Text.Json.JsonValueKind]::Object) {
        $names = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
        foreach ($property in $Element.EnumerateObject()) {
            if (-not $names.Add($property.Name)) {
                throw "Canary source contains duplicate JSON property $Path.$($property.Name)."
            }
            Assert-NoDuplicateJsonPropertyNames $property.Value "$Path.$($property.Name)"
        }
    } elseif ($Element.ValueKind -eq [Text.Json.JsonValueKind]::Array) {
        $index = 0
        foreach ($item in $Element.EnumerateArray()) {
            Assert-NoDuplicateJsonPropertyNames $item "$Path[$index]"
            $index++
        }
    }
}

function Assert-NoSecretShapedMaterial {
    param(
        [Parameter(Mandatory)][string]$Raw,
        [Parameter(Mandatory)][string]$Path
    )

    if ($Raw -match '(?i)-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----|Bearer\s+[A-Za-z0-9._~-]+' `
        -or $Raw -match '(?i)"(?:password|passwd|privateKey|leaseToken|authorization|secret|clientSecret|enrollmentToken|cookie)"\s*:') {
        throw "Canary source contains prohibited secret-shaped material: $Path."
    }
}

function Assert-NoReparsePoint {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Boundary
    )

    $current = $Path
    while (-not [string]::IsNullOrEmpty($current)) {
        if (Test-Path -LiteralPath $current) {
            $attributes = [IO.File]::GetAttributes($current)
            if (($attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw "Canary source paths cannot traverse a reparse point."
            }
        }
        if ([string]::Equals($current, $Boundary, $pathComparison)) {
            return
        }
        $parent = [IO.Path]::GetDirectoryName($current)
        if ([string]::Equals($parent, $current, $pathComparison)) {
            break
        }
        $current = $parent
    }
    throw 'Canary source path escaped the capture boundary.'
}

function Resolve-CaptureFile {
    param([Parameter(Mandatory)][string]$RelativePath)

    if ([IO.Path]::IsPathFullyQualified($RelativePath) -or [string]::IsNullOrWhiteSpace($RelativePath)) {
        throw 'Canary source paths must be non-empty relative paths.'
    }
    $full = [IO.Path]::GetFullPath([IO.Path]::Combine($resolvedCaptureDirectory, $RelativePath))
    if (-not $full.StartsWith($capturePrefix, $pathComparison)) {
        throw 'Canary source path escaped the capture boundary.'
    }
    if (-not (Test-Path -LiteralPath $full -PathType Leaf)) {
        throw "Required canary capture is missing: $RelativePath."
    }
    Assert-NoReparsePoint $full $resolvedCaptureDirectory
    return $full
}

function Read-SourceJson {
    param([Parameter(Mandatory)][string]$RelativePath)

    $full = Resolve-CaptureFile $RelativePath
    if ($sourceDigests.ContainsKey($full)) {
        throw "Canary source was referenced more than once: $RelativePath."
    }
    $info = Get-Item -LiteralPath $full -Force
    if ($info.Length -lt 2 -or $info.Length -gt $maximumSourceFileBytes) {
        throw "Canary source size is outside the permitted bound: $RelativePath."
    }
    $script:sourceBytesRead += $info.Length
    if ($script:sourceBytesRead -gt $maximumTotalSourceBytes) {
        throw 'Canary source bundle exceeds the total permitted size.'
    }

    $bytes = [IO.File]::ReadAllBytes($full)
    $strictUtf8 = [Text.UTF8Encoding]::new($false, $true)
    $raw = $strictUtf8.GetString($bytes)
    if ($raw.Length -eq 0 -or $raw[0] -eq [char]0xFEFF) {
        throw "Canary source must be UTF-8 without BOM: $RelativePath."
    }
    Assert-NoSecretShapedMaterial $raw $RelativePath

    $document = [Text.Json.JsonDocument]::Parse($raw)
    try {
        if ($document.RootElement.ValueKind -ne [Text.Json.JsonValueKind]::Object) {
            throw "Canary source root must be a JSON object: $RelativePath."
        }
        Assert-NoDuplicateJsonPropertyNames $document.RootElement '$'
    } finally {
        $document.Dispose()
    }

    $value = $raw | ConvertFrom-Json -Depth 100
    $digest = Get-Sha256Bytes $bytes
    $sourceDigests.Add($full, $digest)
    return [pscustomobject]@{
        RelativePath = $RelativePath
        FullPath = $full
        Value = $value
        Raw = $raw
        Sha256 = $digest
    }
}

function Get-ExactInteger {
    param(
        [AllowNull()][object]$Value,
        [Parameter(Mandatory)][string]$Path
    )

    if ($Value -isnot [byte] -and $Value -isnot [int16] -and $Value -isnot [int32] -and $Value -isnot [int64]) {
        throw "Canary source integer must be encoded exactly as JSON integer: $Path."
    }
    return [int64]$Value
}

function Get-ExactBoolean {
    param(
        [AllowNull()][object]$Value,
        [Parameter(Mandatory)][string]$Path
    )

    if ($Value -isnot [bool]) {
        throw "Canary source boolean must be encoded exactly as JSON boolean: $Path."
    }
    return [bool]$Value
}

function ConvertTo-UtcTimestamp {
    param(
        [AllowNull()][object]$Value,
        [Parameter(Mandatory)][string]$Path
    )

    if ($Value -is [DateTime]) {
        return [DateTimeOffset]$Value.ToUniversalTime()
    }
    if ($Value -is [DateTimeOffset]) {
        return $Value.ToUniversalTime()
    }
    if ($Value -isnot [string] -or $Value -notmatch '(?:Z|\+00:00)$') {
        throw "Canary source timestamp must be an ISO-8601 UTC string: $Path."
    }
    $parsed = [DateTimeOffset]::MinValue
    if (-not [DateTimeOffset]::TryParse(
            $Value,
            [Globalization.CultureInfo]::InvariantCulture,
            [Globalization.DateTimeStyles]::RoundtripKind,
            [ref]$parsed) -or $parsed.Offset -ne [TimeSpan]::Zero) {
        throw "Canary source timestamp is invalid: $Path."
    }
    return $parsed.ToUniversalTime()
}

function Format-UtcTimestamp {
    param([Parameter(Mandatory)][DateTimeOffset]$Value)

    return $Value.ToUniversalTime().ToString(
        'yyyy-MM-ddTHH:mm:ss.fffZ',
        [Globalization.CultureInfo]::InvariantCulture)
}

function Get-UnixMilliseconds {
    param([Parameter(Mandatory)][DateTimeOffset]$Value)

    return $Value.ToUnixTimeMilliseconds().ToString([Globalization.CultureInfo]::InvariantCulture)
}

function Format-Boolean {
    param([Parameter(Mandatory)][bool]$Value)

    if ($Value) { return 'true' }
    return 'false'
}

function Assert-Sha256 {
    param(
        [AllowNull()][object]$Value,
        [Parameter(Mandatory)][string]$Path
    )

    if ($Value -isnot [string] -or $Value -cnotmatch '^[0-9a-f]{64}$') {
        throw "Canary SHA-256 value is invalid: $Path."
    }
}

function Assert-CanonicalUuid {
    param(
        [AllowNull()][object]$Value,
        [Parameter(Mandatory)][string]$Path
    )

    $parsed = [Guid]::Empty
    if ($Value -isnot [string] -or -not [Guid]::TryParseExact($Value, 'D', [ref]$parsed) `
        -or $parsed -eq [Guid]::Empty) {
        throw "Canary UUID is invalid: $Path."
    }
}

function Assert-Identifier {
    param(
        [AllowNull()][object]$Value,
        [Parameter(Mandatory)][string]$Path
    )

    if ($Value -isnot [string] -or $Value -notmatch '^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$') {
        throw "Canary identifier is invalid: $Path."
    }
}

function Assert-SafeToken {
    param(
        [AllowNull()][object]$Value,
        [Parameter(Mandatory)][string]$Path
    )

    if ($Value -isnot [string] -or $Value -notmatch '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$') {
        throw "Canary sanitized token is invalid: $Path."
    }
}

function Add-Unique {
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][Collections.Generic.HashSet[string]]$Set,
        [Parameter(Mandatory)][string]$Value,
        [Parameter(Mandatory)][string]$Path
    )

    if (-not $Set.Add($Value)) {
        throw "Canary source repeats a value that must be unique: $Path."
    }
}

function New-ReceiptSha256 {
    param(
        [Parameter(Mandatory)][string]$Kind,
        [Parameter(Mandatory)][string[]]$Fields
    )

    $canonical = [string]::Join("`n", @('schema=hch.worker-canary-receipt/v1', "kind=$Kind") + $Fields) + "`n"
    $digest = Get-Sha256Text $canonical
    Add-Unique $receiptHashes $digest "receipt:$Kind"
    return $digest
}

function Assert-ValidatedAt {
    param(
        [Parameter(Mandatory)][DateTimeOffset]$ValidatedAt,
        [Parameter(Mandatory)][DateTimeOffset]$ServerTime,
        [Parameter(Mandatory)][string]$Path
    )

    if ($ValidatedAt -lt $ServerTime.Subtract($maximumClockSkew) `
        -or $ValidatedAt -gt $ServerTime.Add($maximumClockSkew)) {
        throw "Canary capture was not validated near its server timestamp: $Path."
    }
}

function Get-CaptureFiles {
    param(
        [Parameter(Mandatory)][string]$RelativeDirectory,
        [Parameter(Mandatory)][int]$Minimum,
        [Parameter(Mandatory)][int]$Maximum
    )

    $directory = [IO.Path]::GetFullPath([IO.Path]::Combine($resolvedCaptureDirectory, $RelativeDirectory))
    if (-not $directory.StartsWith($capturePrefix, $pathComparison) `
        -or -not (Test-Path -LiteralPath $directory -PathType Container)) {
        throw "Required canary capture directory is missing: $RelativeDirectory."
    }
    Assert-NoReparsePoint $directory $resolvedCaptureDirectory
    $files = @(Get-ChildItem -LiteralPath $directory -Filter '*.json' -File -Force | Sort-Object Name)
    if ($files.Count -lt $Minimum -or $files.Count -gt $Maximum) {
        throw "Canary capture count is outside the permitted bound: $RelativeDirectory."
    }
    return @($files | ForEach-Object {
        [IO.Path]::GetRelativePath($resolvedCaptureDirectory, $_.FullName)
    })
}

function Convert-HeartbeatValue {
    param(
        [Parameter(Mandatory)][object]$Value,
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][ValidateSet('node-heartbeat', 'legacy-node-heartbeat')][string]$Kind
    )

    $isLegacy = $Kind -eq 'legacy-node-heartbeat'
    $names = if ($isLegacy) {
        @('workerVersion', 'requestId', 'nodeId', 'heartbeatAt', 'nextHeartbeatSeconds', 'capacity', 'serverTime')
    } else {
        @('requestId', 'nodeId', 'heartbeatAt', 'nextHeartbeatSeconds', 'capacity', 'serverTime')
    }
    Assert-ExactPropertyNames $Value $names $Path

    $requestId = Get-RequiredProperty $Value 'requestId' $Path
    $nodeId = Get-RequiredProperty $Value 'nodeId' $Path
    Assert-CanonicalUuid $requestId "$Path.requestId"
    Assert-Identifier $nodeId "$Path.nodeId"
    Add-Unique $requestIds $requestId "$Path.requestId"
    $heartbeatAt = ConvertTo-UtcTimestamp (Get-RequiredProperty $Value 'heartbeatAt' $Path) "$Path.heartbeatAt"
    $serverTime = ConvertTo-UtcTimestamp (Get-RequiredProperty $Value 'serverTime' $Path) "$Path.serverTime"
    $nextHeartbeatSeconds = Get-ExactInteger (
        Get-RequiredProperty $Value 'nextHeartbeatSeconds' $Path) "$Path.nextHeartbeatSeconds"
    if ($heartbeatAt -gt $serverTime -or ($serverTime - $heartbeatAt) -gt $maximumHeartbeatServerSkew `
        -or $nextHeartbeatSeconds -ne 60) {
        throw "Canary heartbeat timing is invalid: $Path."
    }

    $capacity = Get-RequiredProperty $Value 'capacity' $Path
    Assert-ExactPropertyNames $capacity @(
        'configuredCapacity',
        'requestedCapacity',
        'grantedCapacity',
        'activeAssignments',
        'availableSlots',
        'capacityClass',
        'reason',
        'grantedUntil') "$Path.capacity"
    $configured = Get-ExactInteger (Get-RequiredProperty $capacity 'configuredCapacity' "$Path.capacity") "$Path.capacity.configuredCapacity"
    $requested = Get-ExactInteger (Get-RequiredProperty $capacity 'requestedCapacity' "$Path.capacity") "$Path.capacity.requestedCapacity"
    $granted = Get-ExactInteger (Get-RequiredProperty $capacity 'grantedCapacity' "$Path.capacity") "$Path.capacity.grantedCapacity"
    $active = Get-ExactInteger (Get-RequiredProperty $capacity 'activeAssignments' "$Path.capacity") "$Path.capacity.activeAssignments"
    $available = Get-ExactInteger (Get-RequiredProperty $capacity 'availableSlots' "$Path.capacity") "$Path.capacity.availableSlots"
    $capacityClass = Get-RequiredProperty $capacity 'capacityClass' "$Path.capacity"
    $reason = Get-RequiredProperty $capacity 'reason' "$Path.capacity"
    Assert-SafeToken $capacityClass "$Path.capacity.capacityClass"
    Assert-SafeToken $reason "$Path.capacity.reason"
    $grantedUntilRaw = Get-RequiredProperty $capacity 'grantedUntil' "$Path.capacity"
    $grantedUntil = $null
    $grantedUntilText = $null
    $grantedUntilCanonical = '~'
    if ($null -ne $grantedUntilRaw) {
        $grantedUntil = ConvertTo-UtcTimestamp $grantedUntilRaw "$Path.capacity.grantedUntil"
        $grantedUntilText = Format-UtcTimestamp $grantedUntil
        $grantedUntilCanonical = Get-UnixMilliseconds $grantedUntil
        if ($grantedUntil -le $serverTime) {
            throw "Canary capacity grant is expired: $Path."
        }
    }
    if ($configured -lt 1 -or $configured -gt 64) {
        throw "Canary configured capacity is invalid: $Path."
    }
    if ($isLegacy) {
        if ((Get-RequiredProperty $Value 'workerVersion' $Path) -cne '3.1.1' `
            -or $requested -lt 0 -or $requested -gt 64 `
            -or $granted -lt 0 -or $granted -gt $requested `
            -or $active -lt 0 -or $active -gt $granted `
            -or $available -ne ($granted - $active)) {
            throw "Canary legacy heartbeat capacity is invalid: $Path."
        }
    } elseif ($requested -ne 1 -or $granted -ne 1 -or $active -lt 0 -or $active -gt 1 `
        -or $available -lt 0 -or $available -gt 1 -or ($active + $available) -ne 1) {
        throw "Canary v4 heartbeat capacity is invalid: $Path."
    }

    $outputCapacity = [ordered]@{
        configuredCapacity = $configured
        requestedCapacity = $requested
        grantedCapacity = $granted
        activeAssignments = $active
        availableSlots = $available
        capacityClass = [string]$capacityClass
        reason = [string]$reason
        grantedUntil = $grantedUntilText
    }
    $fields = @()
    if ($isLegacy) { $fields += 'workerVersion=3.1.1' }
    $fields += @(
        "requestId=$requestId",
        "nodeId=$nodeId",
        "heartbeatAtUnixMs=$(Get-UnixMilliseconds $heartbeatAt)",
        "nextHeartbeatSeconds=$($nextHeartbeatSeconds.ToString([Globalization.CultureInfo]::InvariantCulture))",
        "capacity.configuredCapacity=$($configured.ToString([Globalization.CultureInfo]::InvariantCulture))",
        "capacity.requestedCapacity=$($requested.ToString([Globalization.CultureInfo]::InvariantCulture))",
        "capacity.grantedCapacity=$($granted.ToString([Globalization.CultureInfo]::InvariantCulture))",
        "capacity.activeAssignments=$($active.ToString([Globalization.CultureInfo]::InvariantCulture))",
        "capacity.availableSlots=$($available.ToString([Globalization.CultureInfo]::InvariantCulture))",
        "capacity.capacityClass=$capacityClass",
        "capacity.reason=$reason",
        "capacity.grantedUntilUnixMs=$grantedUntilCanonical",
        "serverTimeUnixMs=$(Get-UnixMilliseconds $serverTime)"
    )
    $receipt = New-ReceiptSha256 $Kind $fields
    $output = if ($isLegacy) {
        [ordered]@{
            workerVersion = '3.1.1'
            requestId = [string]$requestId
            nodeId = [string]$nodeId
            heartbeatAt = Format-UtcTimestamp $heartbeatAt
            nextHeartbeatSeconds = $nextHeartbeatSeconds
            capacity = $outputCapacity
            serverTime = Format-UtcTimestamp $serverTime
            receiptSha256 = $receipt
        }
    } else {
        [ordered]@{
            requestId = [string]$requestId
            nodeId = [string]$nodeId
            heartbeatAt = Format-UtcTimestamp $heartbeatAt
            nextHeartbeatSeconds = $nextHeartbeatSeconds
            capacity = $outputCapacity
            serverTime = Format-UtcTimestamp $serverTime
            receiptSha256 = $receipt
        }
    }
    return [pscustomobject]@{
        Output = $output
        RequestId = [string]$requestId
        NodeId = [string]$nodeId
        ServerTime = $serverTime
        HeartbeatAt = $heartbeatAt
        ActiveAssignments = $active
    }
}

function Read-StateProbe {
    param(
        [Parameter(Mandatory)][string]$RelativePath,
        [Parameter(Mandatory)][string]$CaptureName
    )

    $source = Read-SourceJson $RelativePath
    $value = $source.Value
    $sourcePath = "source:$RelativePath"
    Assert-ExactPropertyNames $value @(
        'schema',
        'collector',
        'capture',
        'workerVersion',
        'sourceCommit',
        'msiSha256',
        'msiLifecycleEvidenceSha256',
        'productCode',
        'packageCode',
        'serviceName',
        'scmState',
        'scmStartMode',
        'scmDelayedAutomaticStart',
        'scmAccountName',
        'scmImagePath',
        'scmProcessId',
        'processId',
        'processImagePath',
        'processStartedAtUtc',
        'bootStartedAtUtc',
        'serviceExecutableSha256',
        'trayExecutablePath',
        'trayExecutableSha256',
        'operationalState',
        'acceptingClaims',
        'maxConcurrentJobs',
        'grantedCapacity',
        'activeAssignments',
        'observedAtUtc') $sourcePath

    $productCode = Get-RequiredProperty $value 'productCode' $sourcePath
    $packageCode = Get-RequiredProperty $value 'packageCode' $sourcePath
    $serviceName = Get-RequiredProperty $value 'serviceName' $sourcePath
    $scmImagePath = Get-RequiredProperty $value 'scmImagePath' $sourcePath
    $processImagePath = Get-RequiredProperty $value 'processImagePath' $sourcePath
    $trayExecutablePath = Get-RequiredProperty $value 'trayExecutablePath' $sourcePath
    $serviceExecutableSha256 = Get-RequiredProperty $value 'serviceExecutableSha256' $sourcePath
    $trayExecutableSha256 = Get-RequiredProperty $value 'trayExecutableSha256' $sourcePath
    $scmProcessId = Get-ExactInteger (Get-RequiredProperty $value 'scmProcessId' $sourcePath) "$sourcePath.scmProcessId"
    $processId = Get-ExactInteger (Get-RequiredProperty $value 'processId' $sourcePath) "$sourcePath.processId"
    $processStartedAt = ConvertTo-UtcTimestamp (
        Get-RequiredProperty $value 'processStartedAtUtc' $sourcePath) "$sourcePath.processStartedAtUtc"
    $bootStartedAt = ConvertTo-UtcTimestamp (
        Get-RequiredProperty $value 'bootStartedAtUtc' $sourcePath) "$sourcePath.bootStartedAtUtc"
    $observedAt = ConvertTo-UtcTimestamp (
        Get-RequiredProperty $value 'observedAtUtc' $sourcePath) "$sourcePath.observedAtUtc"

    foreach ($pathValue in @($scmImagePath, $processImagePath, $trayExecutablePath)) {
        if ($pathValue -isnot [string] -or [string]::IsNullOrWhiteSpace($pathValue) `
            -or -not [IO.Path]::IsPathFullyQualified($pathValue) `
            -or $pathValue.IndexOfAny([char[]]"`r`n") -ge 0) {
            throw "Canary executable path is invalid: $RelativePath."
        }
    }
    if (-not [string]::Equals($scmImagePath, $processImagePath, [StringComparison]::OrdinalIgnoreCase) `
        -or -not $scmImagePath.EndsWith('\HubTech\HCH Worker\4\Service\Hch.Worker.Service.exe', [StringComparison]::OrdinalIgnoreCase) `
        -or -not $trayExecutablePath.EndsWith('\HubTech\HCH Worker\4\Tray\Hch.Worker.Tray.exe', [StringComparison]::OrdinalIgnoreCase)) {
        throw "Canary SCM/process ImagePath or tray path is not the installed v4 payload: $RelativePath."
    }
    Assert-Sha256 $serviceExecutableSha256 "$sourcePath.serviceExecutableSha256"
    Assert-Sha256 $trayExecutableSha256 "$sourcePath.trayExecutableSha256"
    if ((Get-RequiredProperty $value 'schema' $sourcePath) -cne 'hch.worker-windows-state-capture/v2' `
        -or (Get-RequiredProperty $value 'collector' $sourcePath) -cne 'windows-scm-cim-process/v1' `
        -or (Get-RequiredProperty $value 'capture' "source:$RelativePath") -cne $CaptureName `
        -or (Get-RequiredProperty $value 'workerVersion' "source:$RelativePath") -cne $Version `
        -or (Get-RequiredProperty $value 'sourceCommit' "source:$RelativePath") -cne $SourceCommit `
        -or (Get-RequiredProperty $value 'msiSha256' "source:$RelativePath") -cne $msiSha256 `
        -or (Get-RequiredProperty $value 'msiLifecycleEvidenceSha256' $sourcePath) -cne $msiLifecycleEvidenceSha256 `
        -or $productCode -cne $msiIdentity.ProductCode `
        -or $packageCode -cne $msiIdentity.PackageCode `
        -or $serviceName -cne 'HchWorker' `
        -or (Get-RequiredProperty $value 'scmState' $sourcePath) -cne 'Running' `
        -or (Get-RequiredProperty $value 'scmStartMode' $sourcePath) -cne 'Automatic' `
        -or -not (Get-ExactBoolean (Get-RequiredProperty $value 'scmDelayedAutomaticStart' $sourcePath) "$sourcePath.scmDelayedAutomaticStart") `
        -or (Get-RequiredProperty $value 'scmAccountName' $sourcePath) -cne 'LocalSystem' `
        -or $scmProcessId -le 0 `
        -or $processId -ne $scmProcessId `
        -or $bootStartedAt -ge $processStartedAt `
        -or $processStartedAt -gt $observedAt `
        -or $serviceExecutableSha256 -cne $msiLifecycleServiceSha256 `
        -or $trayExecutableSha256 -cne $msiLifecycleTraySha256 `
        -or (Get-RequiredProperty $value 'operationalState' "source:$RelativePath") -cne 'Paused' `
        -or (Get-ExactBoolean (Get-RequiredProperty $value 'acceptingClaims' "source:$RelativePath") "source:$RelativePath.acceptingClaims") `
        -or (Get-ExactInteger (Get-RequiredProperty $value 'maxConcurrentJobs' "source:$RelativePath") "source:$RelativePath.maxConcurrentJobs") -ne 0 `
        -or (Get-ExactInteger (Get-RequiredProperty $value 'grantedCapacity' "source:$RelativePath") "source:$RelativePath.grantedCapacity") -ne 0 `
        -or (Get-ExactInteger (Get-RequiredProperty $value 'activeAssignments' "source:$RelativePath") "source:$RelativePath.activeAssignments") -ne 0) {
        throw "Canary Paused/Drain state probe does not bind the candidate identity or state: $RelativePath."
    }
    return [pscustomobject]@{
        ObservedAt = $observedAt
        BootStartedAt = $bootStartedAt
        ProcessStartedAt = $processStartedAt
        ProcessId = $processId
        ServiceImagePath = [string]$scmImagePath
        ServiceExecutableSha256 = [string]$serviceExecutableSha256
        TrayExecutablePath = [string]$trayExecutablePath
        TrayExecutableSha256 = [string]$trayExecutableSha256
    }
}

function Get-ServiceDefinitionHash {
    param(
        [Parameter(Mandatory)][object]$Definition,
        [Parameter(Mandatory)][string]$Path
    )

    Assert-ExactPropertyNames $Definition @(
        'serviceName',
        'imagePath',
        'accountName',
        'startMode',
        'serviceType',
        'delayedAutomaticStart',
        'failureActionsSha256',
        'securityDescriptorSddl') $Path
    $serviceName = Get-RequiredProperty $Definition 'serviceName' $Path
    $imagePath = Get-RequiredProperty $Definition 'imagePath' $Path
    $accountName = Get-RequiredProperty $Definition 'accountName' $Path
    $startMode = Get-ExactInteger (Get-RequiredProperty $Definition 'startMode' $Path) "$Path.startMode"
    $serviceType = Get-ExactInteger (Get-RequiredProperty $Definition 'serviceType' $Path) "$Path.serviceType"
    $delayed = Get-ExactBoolean (Get-RequiredProperty $Definition 'delayedAutomaticStart' $Path) "$Path.delayedAutomaticStart"
    $failureActions = Get-RequiredProperty $Definition 'failureActionsSha256' $Path
    $sddl = Get-RequiredProperty $Definition 'securityDescriptorSddl' $Path
    foreach ($entry in @($serviceName, $imagePath, $accountName, $sddl)) {
        if ($entry -isnot [string] -or [string]::IsNullOrWhiteSpace($entry) -or $entry.Length -gt 4096 `
            -or $entry.IndexOfAny([char[]]"`r`n") -ge 0) {
            throw "Canary service-definition field is invalid: $Path."
        }
    }
    Assert-Sha256 $failureActions "$Path.failureActionsSha256"
    $canonical = [string]::Join("`n", @(
        'schema=hch.worker-legacy-service-definition/v1',
        "serviceName=$serviceName",
        "imagePath=$imagePath",
        "accountName=$accountName",
        "startMode=$($startMode.ToString([Globalization.CultureInfo]::InvariantCulture))",
        "serviceType=$($serviceType.ToString([Globalization.CultureInfo]::InvariantCulture))",
        "delayedAutomaticStart=$(Format-Boolean $delayed)",
        "failureActionsSha256=$failureActions",
        "securityDescriptorSddl=$sddl"
    )) + "`n"
    return Get-Sha256Text $canonical
}

function ConvertTo-LimitedJcs {
    param([Parameter(Mandatory)][Text.Json.JsonElement]$Element)

    switch ($Element.ValueKind) {
        ([Text.Json.JsonValueKind]::Object) {
            $names = [string[]]@($Element.EnumerateObject() | ForEach-Object { $_.Name })
            [Array]::Sort($names, [StringComparer]::Ordinal)
            $members = foreach ($name in $names) {
                $quotedName = [Text.Json.JsonSerializer]::Serialize([string]$name, $jcsJsonOptions)
                "$quotedName`:$(ConvertTo-LimitedJcs ($Element.GetProperty($name)))"
            }
            return '{' + [string]::Join(',', [string[]]@($members)) + '}'
        }
        ([Text.Json.JsonValueKind]::Array) {
            $items = @(foreach ($item in $Element.EnumerateArray()) { ConvertTo-LimitedJcs $item })
            return '[' + [string]::Join(',', [string[]]$items) + ']'
        }
        ([Text.Json.JsonValueKind]::String) {
            return [Text.Json.JsonSerializer]::Serialize([string]$Element.GetString(), $jcsJsonOptions)
        }
        ([Text.Json.JsonValueKind]::Number) {
            $rawNumber = $Element.GetRawText()
            if ($rawNumber -notmatch '^-?(?:0|[1-9][0-9]*)$') {
                throw 'Legacy backup receipt contains a non-integer number unsupported by the bounded verifier.'
            }
            return $rawNumber
        }
        ([Text.Json.JsonValueKind]::True) { return 'true' }
        ([Text.Json.JsonValueKind]::False) { return 'false' }
        ([Text.Json.JsonValueKind]::Null) { return 'null' }
        default { throw 'Legacy backup receipt contains an unsupported JSON value.' }
    }
}

function Get-MsiIdentity {
    param([Parameter(Mandatory)][string]$Path)

    if (-not $IsWindows) {
        throw 'Canary MSI identity verification requires Windows Installer on Windows.'
    }
    if ([IO.Path]::GetExtension($Path) -cne '.msi') {
        throw 'MsiPath must have the exact .msi extension.'
    }
    $stream = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    try {
        if ($stream.Length -lt 4096) {
            throw 'MsiPath is too small to be a Windows Installer database.'
        }
        $header = [byte[]]::new(8)
        if ($stream.Read($header, 0, $header.Length) -ne $header.Length `
            -or [Convert]::ToHexString($header) -cne 'D0CF11E0A1B11AE1') {
            throw 'MsiPath is not an OLE compound Windows Installer database.'
        }
    } finally {
        $stream.Dispose()
    }

    $installer = $null
    $database = $null
    $summary = $null
    try {
        $installer = New-Object -ComObject WindowsInstaller.Installer
        $database = $installer.OpenDatabase($Path, 0)
        $properties = [ordered]@{}
        foreach ($name in 'ProductCode', 'ProductVersion', 'ProductName', 'Manufacturer') {
            $view = $null
            try {
                $view = $database.OpenView("SELECT ``Value`` FROM ``Property`` WHERE ``Property``='$name'")
                [void]$view.Execute()
                $record = $view.Fetch()
                if ($null -eq $record) { throw "MSI property is missing: $name." }
                $properties[$name] = [string]$record.StringData(1)
            } finally {
                if ($null -ne $view) { [void]$view.Close() }
            }
        }
        $summary = $database.SummaryInformation(0)
        $packageCode = [string]$summary.Property(9)
    } catch {
        throw "MsiPath is not a readable Windows Installer database: $($_.Exception.Message)"
    } finally {
        if ($null -ne $summary) { [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($summary) }
        if ($null -ne $database) { [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($database) }
        if ($null -ne $installer) { [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($installer) }
    }

    $productGuid = [Guid]::Empty
    $packageGuid = [Guid]::Empty
    if (-not [Guid]::TryParseExact($properties.ProductCode, 'B', [ref]$productGuid) `
        -or -not [Guid]::TryParseExact($packageCode, 'B', [ref]$packageGuid) `
        -or $productGuid -eq [Guid]::Empty -or $packageGuid -eq [Guid]::Empty `
        -or $properties.ProductVersion -cne $Version `
        -or $properties.ProductName -cne 'HCH Worker' `
        -or $properties.Manufacturer -cne 'HubTech') {
        throw 'MSI identity does not match the expected HCH Worker candidate.'
    }
    return [pscustomobject]@{
        ProductCode = $productGuid.ToString('B').ToUpperInvariant()
        PackageCode = $packageGuid.ToString('B').ToUpperInvariant()
    }
}

$captureItem = Get-Item -LiteralPath (Resolve-Path -LiteralPath $CaptureDirectory).Path -Force
if (-not $captureItem.PSIsContainer `
    -or ($captureItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
    throw 'CaptureDirectory must be a real, non-reparse directory.'
}
$resolvedCaptureDirectory = [IO.Path]::GetFullPath($captureItem.FullName).TrimEnd(
    [IO.Path]::DirectorySeparatorChar,
    [IO.Path]::AltDirectorySeparatorChar)
$capturePrefix = $resolvedCaptureDirectory + [IO.Path]::DirectorySeparatorChar

$resolvedMsi = (Resolve-Path -LiteralPath $MsiPath).Path
if (-not (Test-Path -LiteralPath $resolvedMsi -PathType Leaf) `
    -or ((Get-Item -LiteralPath $resolvedMsi -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
    throw 'MsiPath must identify a real, non-reparse file.'
}
$msiSha256 = (Get-FileHash -LiteralPath $resolvedMsi -Algorithm SHA256).Hash.ToLowerInvariant()
$msiIdentity = Get-MsiIdentity $resolvedMsi

$msiLifecycleSource = Read-SourceJson 'probes/msi-disposable-e2e.json'
$msiLifecycle = $msiLifecycleSource.Value
$msiLifecycleEvidenceSha256 = $msiLifecycleSource.Sha256
Assert-ExactPropertyNames $msiLifecycle @(
    'schema',
    'status',
    'version',
    'productCode',
    'packageCode',
    'msiSha256',
    'msiLengthBytes',
    'signerThumbprint',
    'signerCertificateSha256',
    'environmentKind',
    'machineName',
    'rollbackExitCode',
    'extractedFirstPartySignedFiles',
    'extractedPayloads',
    'installedService',
    'pausedDrainEvidence',
    'repairPreservedState',
    'uninstallPreservedState',
    'logs',
    'completedAtUtc') 'source:probes/msi-disposable-e2e.json'
$msiLengthBytes = Get-ExactInteger (
    Get-RequiredProperty $msiLifecycle 'msiLengthBytes' 'source:msi-lifecycle') 'source:msi-lifecycle.msiLengthBytes'
$rollbackExitCode = Get-ExactInteger (
    Get-RequiredProperty $msiLifecycle 'rollbackExitCode' 'source:msi-lifecycle') 'source:msi-lifecycle.rollbackExitCode'
$extractedFileCount = Get-ExactInteger (
    Get-RequiredProperty $msiLifecycle 'extractedFirstPartySignedFiles' 'source:msi-lifecycle') `
    'source:msi-lifecycle.extractedFirstPartySignedFiles'
$lifecycleCompletedAt = ConvertTo-UtcTimestamp (
    Get-RequiredProperty $msiLifecycle 'completedAtUtc' 'source:msi-lifecycle') 'source:msi-lifecycle.completedAtUtc'
$signerThumbprint = Get-RequiredProperty $msiLifecycle 'signerThumbprint' 'source:msi-lifecycle'
$signerCertificateSha256 = Get-RequiredProperty $msiLifecycle 'signerCertificateSha256' 'source:msi-lifecycle'
if ((Get-RequiredProperty $msiLifecycle 'schema' 'source:msi-lifecycle') -cne 'hch.worker-windows-msi-e2e/v1' `
    -or (Get-RequiredProperty $msiLifecycle 'status' 'source:msi-lifecycle') -cne 'passed' `
    -or (Get-RequiredProperty $msiLifecycle 'version' 'source:msi-lifecycle') -cne $Version `
    -or (Get-RequiredProperty $msiLifecycle 'productCode' 'source:msi-lifecycle') -cne $msiIdentity.ProductCode `
    -or (Get-RequiredProperty $msiLifecycle 'packageCode' 'source:msi-lifecycle') -cne $msiIdentity.PackageCode `
    -or (Get-RequiredProperty $msiLifecycle 'msiSha256' 'source:msi-lifecycle') -cne $msiSha256 `
    -or $msiLengthBytes -ne (Get-Item -LiteralPath $resolvedMsi).Length `
    -or $signerThumbprint -isnot [string] -or $signerThumbprint -cnotmatch '^[A-F0-9]{40}$' `
    -or $signerCertificateSha256 -isnot [string] -or $signerCertificateSha256 -cnotmatch '^[A-F0-9]{64}$' `
    -or (Get-RequiredProperty $msiLifecycle 'environmentKind' 'source:msi-lifecycle') -notin @('GitHubHosted', 'MarkedDisposableVm') `
    -or $rollbackExitCode -ne 1603 `
    -or $extractedFileCount -lt 3 `
    -or -not (Get-ExactBoolean (Get-RequiredProperty $msiLifecycle 'repairPreservedState' 'source:msi-lifecycle') 'source:msi-lifecycle.repairPreservedState') `
    -or -not (Get-ExactBoolean (Get-RequiredProperty $msiLifecycle 'uninstallPreservedState' 'source:msi-lifecycle') 'source:msi-lifecycle.uninstallPreservedState')) {
    throw 'Disposable MSI lifecycle evidence does not bind the exact candidate and successful lifecycle.'
}
Assert-SafeToken (Get-RequiredProperty $msiLifecycle 'machineName' 'source:msi-lifecycle') 'source:msi-lifecycle.machineName'
if ((Get-RequiredProperty $msiLifecycle 'pausedDrainEvidence' 'source:msi-lifecycle') -notin @(
        'not-ready-no-capacity-state',
        'ready-state-requested-and-granted-capacity-zero')) {
    throw 'Disposable MSI lifecycle evidence did not prove the safe initial Paused/Drain state.'
}
$lifecycleLogs = @(Get-RequiredProperty $msiLifecycle 'logs' 'source:msi-lifecycle')
if ($lifecycleLogs.Count -lt 5) {
    throw 'Disposable MSI lifecycle evidence is missing lifecycle log digests.'
}

$extractedPayloads = Get-RequiredProperty $msiLifecycle 'extractedPayloads' 'source:msi-lifecycle'
Assert-ExactPropertyNames $extractedPayloads @('service', 'tray', 'installer') 'source:msi-lifecycle.extractedPayloads'
foreach ($payloadName in 'service', 'tray', 'installer') {
    $payload = Get-RequiredProperty $extractedPayloads $payloadName 'source:msi-lifecycle.extractedPayloads'
    Assert-ExactPropertyNames $payload @('relativePath', 'sha256', 'sizeBytes') "source:msi-lifecycle.extractedPayloads.$payloadName"
    Assert-Sha256 (Get-RequiredProperty $payload 'sha256' "source:msi-lifecycle.extractedPayloads.$payloadName") `
        "source:msi-lifecycle.extractedPayloads.$payloadName.sha256"
    $payloadSize = Get-ExactInteger (
        Get-RequiredProperty $payload 'sizeBytes' "source:msi-lifecycle.extractedPayloads.$payloadName") `
        "source:msi-lifecycle.extractedPayloads.$payloadName.sizeBytes"
    if ($payloadSize -lt 4096) { throw "Disposable MSI payload is implausibly small: $payloadName." }
}
$msiLifecycleServiceSha256 = [string](Get-RequiredProperty $extractedPayloads.service 'sha256' 'source:msi-lifecycle.extractedPayloads.service')
$msiLifecycleTraySha256 = [string](Get-RequiredProperty $extractedPayloads.tray 'sha256' 'source:msi-lifecycle.extractedPayloads.tray')

$lifecycleInstalledService = Get-RequiredProperty $msiLifecycle 'installedService' 'source:msi-lifecycle'
Assert-ExactPropertyNames $lifecycleInstalledService @(
    'serviceName',
    'displayName',
    'scmState',
    'scmStartMode',
    'scmDelayedAutomaticStart',
    'scmAccountName',
    'scmImagePath',
    'scmProcessId',
    'processImagePath',
    'processStartedAtUtc',
    'bootStartedAtUtc',
    'serviceExecutableSha256',
    'trayExecutablePath',
    'trayExecutableSha256',
    'observedAtUtc') 'source:msi-lifecycle.installedService'
$lifecycleScmImagePath = Get-RequiredProperty $lifecycleInstalledService 'scmImagePath' 'source:msi-lifecycle.installedService'
$lifecycleProcessImagePath = Get-RequiredProperty $lifecycleInstalledService 'processImagePath' 'source:msi-lifecycle.installedService'
$lifecycleTrayPath = Get-RequiredProperty $lifecycleInstalledService 'trayExecutablePath' 'source:msi-lifecycle.installedService'
$lifecycleProcessId = Get-ExactInteger (
    Get-RequiredProperty $lifecycleInstalledService 'scmProcessId' 'source:msi-lifecycle.installedService') `
    'source:msi-lifecycle.installedService.scmProcessId'
$lifecycleProcessStartedAt = ConvertTo-UtcTimestamp (
    Get-RequiredProperty $lifecycleInstalledService 'processStartedAtUtc' 'source:msi-lifecycle.installedService') `
    'source:msi-lifecycle.installedService.processStartedAtUtc'
$lifecycleBootStartedAt = ConvertTo-UtcTimestamp (
    Get-RequiredProperty $lifecycleInstalledService 'bootStartedAtUtc' 'source:msi-lifecycle.installedService') `
    'source:msi-lifecycle.installedService.bootStartedAtUtc'
$lifecycleObservedAt = ConvertTo-UtcTimestamp (
    Get-RequiredProperty $lifecycleInstalledService 'observedAtUtc' 'source:msi-lifecycle.installedService') `
    'source:msi-lifecycle.installedService.observedAtUtc'
if ((Get-RequiredProperty $lifecycleInstalledService 'serviceName' 'source:msi-lifecycle.installedService') -cne 'HchWorker' `
    -or (Get-RequiredProperty $lifecycleInstalledService 'displayName' 'source:msi-lifecycle.installedService') -cne 'HCH Worker' `
    -or (Get-RequiredProperty $lifecycleInstalledService 'scmState' 'source:msi-lifecycle.installedService') -cne 'Running' `
    -or (Get-RequiredProperty $lifecycleInstalledService 'scmStartMode' 'source:msi-lifecycle.installedService') -cne 'Automatic' `
    -or -not (Get-ExactBoolean (
        Get-RequiredProperty $lifecycleInstalledService 'scmDelayedAutomaticStart' 'source:msi-lifecycle.installedService') `
        'source:msi-lifecycle.installedService.scmDelayedAutomaticStart') `
    -or (Get-RequiredProperty $lifecycleInstalledService 'scmAccountName' 'source:msi-lifecycle.installedService') -cne 'LocalSystem' `
    -or $lifecycleProcessId -le 0 `
    -or -not [string]::Equals($lifecycleScmImagePath, $lifecycleProcessImagePath, [StringComparison]::OrdinalIgnoreCase) `
    -or -not $lifecycleScmImagePath.EndsWith('\HubTech\HCH Worker\4\Service\Hch.Worker.Service.exe', [StringComparison]::OrdinalIgnoreCase) `
    -or -not $lifecycleTrayPath.EndsWith('\HubTech\HCH Worker\4\Tray\Hch.Worker.Tray.exe', [StringComparison]::OrdinalIgnoreCase) `
    -or (Get-RequiredProperty $lifecycleInstalledService 'serviceExecutableSha256' 'source:msi-lifecycle.installedService') -cne $msiLifecycleServiceSha256 `
    -or (Get-RequiredProperty $lifecycleInstalledService 'trayExecutableSha256' 'source:msi-lifecycle.installedService') -cne $msiLifecycleTraySha256 `
    -or $lifecycleBootStartedAt -ge $lifecycleProcessStartedAt `
    -or $lifecycleProcessStartedAt -gt $lifecycleObservedAt `
    -or $lifecycleObservedAt -gt $lifecycleCompletedAt) {
    throw 'Disposable MSI lifecycle service snapshot is inconsistent with the extracted candidate payloads.'
}

$resolvedEvidence = [IO.Path]::GetFullPath($EvidencePath)
if ($resolvedEvidence.StartsWith($capturePrefix, $pathComparison) `
    -or [string]::Equals($resolvedEvidence, $resolvedCaptureDirectory, $pathComparison)) {
    throw 'EvidencePath must be outside the immutable capture directory.'
}
$evidenceParent = [IO.Path]::GetDirectoryName($resolvedEvidence)
if ([string]::IsNullOrWhiteSpace($evidenceParent) `
    -or -not (Test-Path -LiteralPath $evidenceParent -PathType Container)) {
    throw 'EvidencePath parent directory does not exist.'
}
if (((Get-Item -LiteralPath $evidenceParent -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
    throw 'EvidencePath parent cannot be a reparse point.'
}
if (Test-Path -LiteralPath $resolvedEvidence) {
    throw 'Refusing to overwrite existing canary evidence.'
}

$jcsJsonOptions = [Text.Json.JsonSerializerOptions]::new()
$jcsJsonOptions.Encoder = [Text.Encodings.Web.JavaScriptEncoder]::UnsafeRelaxedJsonEscaping

# Accepted v4 node heartbeats are sanitized response projections written only
# after OrchestratorContractValidator.Validate succeeds.
$heartbeatItems = [Collections.Generic.List[object]]::new()
foreach ($relative in Get-CaptureFiles 'accepted/node-heartbeats' 10 2048) {
    $source = Read-SourceJson $relative
    $capture = $source.Value
    Assert-ExactPropertyNames $capture @('schema', 'validatedAtUtc', 'response') "source:$relative"
    if ((Get-RequiredProperty $capture 'schema' "source:$relative") -cne 'hch.worker-canary-node-heartbeat-capture/v1') {
        throw "Canary node-heartbeat capture schema is invalid: $relative."
    }
    $converted = Convert-HeartbeatValue (
        Get-RequiredProperty $capture 'response' "source:$relative") "source:$relative.response" 'node-heartbeat'
    $validatedAt = ConvertTo-UtcTimestamp (
        Get-RequiredProperty $capture 'validatedAtUtc' "source:$relative") "source:$relative.validatedAtUtc"
    Assert-ValidatedAt $validatedAt $converted.ServerTime "source:$relative.validatedAtUtc"
    $heartbeatItems.Add($converted)
}
$heartbeatItems = @($heartbeatItems | Sort-Object ServerTime, RequestId)
$canaryNodeId = $heartbeatItems[0].NodeId
$firstHeartbeatTime = $heartbeatItems[0].ServerTime
$previousHeartbeatTime = $null
$observedActiveJob = $false
foreach ($item in $heartbeatItems) {
    if ($item.NodeId -cne $canaryNodeId) {
        throw 'All node-heartbeat captures must bind the same nodeId.'
    }
    if ($null -ne $previousHeartbeatTime) {
        $gap = $item.ServerTime - $previousHeartbeatTime
        if ($gap -le [TimeSpan]::Zero -or $gap -gt $maximumHeartbeatGap) {
            throw 'Canary node-heartbeat captures contain an invalid or stale gap.'
        }
    }
    if ($item.ActiveAssignments -eq 1) { $observedActiveJob = $true }
    $previousHeartbeatTime = $item.ServerTime
}
if (($previousHeartbeatTime - $firstHeartbeatTime) -lt $minimumHeartbeatSpan) {
    throw 'Canary accepted heartbeat span is shorter than 15 minutes.'
}
if (-not $observedActiveJob) {
    throw 'Canary node-heartbeat captures never observed the single active slot.'
}

# Durable enrollment/readiness/trust records are consumed but projected only to
# booleans, so owner identity and public key material never enter the evidence.
$enrollmentSource = Read-SourceJson 'runtime/enrollment/operational-key.json'
$enrollment = $enrollmentSource.Value
Assert-ExactPropertyNames $enrollment @(
    'schemaVersion', 'protocol', 'requestId', 'tokenId', 'nodeId', 'workerKeyId',
    'workerPublicKeyPem', 'workerPublicKeyFingerprint', 'ownerUserId', 'ownerEmail',
    'ownerSshKeyId', 'ownerSshKeyFingerprint', 'status', 'enrolledAt') 'source:runtime/enrollment/operational-key.json'
$enrollmentSchemaVersion = Get-ExactInteger (
    Get-RequiredProperty $enrollment 'schemaVersion' 'source:enrollment') 'source:enrollment.schemaVersion'
$enrolledAt = ConvertTo-UtcTimestamp (
    Get-RequiredProperty $enrollment 'enrolledAt' 'source:enrollment') 'source:enrollment.enrolledAt'
if ($enrollmentSchemaVersion -ne 1 `
    -or (Get-RequiredProperty $enrollment 'protocol' 'source:enrollment') -cne 'operational-key-proof-v1' `
    -or (Get-RequiredProperty $enrollment 'status' 'source:enrollment') -cne 'active' `
    -or (Get-RequiredProperty $enrollment 'nodeId' 'source:enrollment') -cne $canaryNodeId) {
    throw 'Durable operational enrollment receipt is not active for the canary node.'
}
$workerKeyId = Get-RequiredProperty $enrollment 'workerKeyId' 'source:enrollment'
Assert-Identifier $workerKeyId 'source:enrollment.workerKeyId'

$readySource = Read-SourceJson 'runtime/ready.json'
$ready = $readySource.Value
Assert-ExactPropertyNames $ready @(
    'schemaVersion', 'ready', 'nodeId', 'keyId', 'manifestSequence', 'manifestHash',
    'contentContractHash', 'policyHash', 'provider', 'engineAdapter', 'engineAdapterVersion',
    'workerRuntimeVersion', 'runtimeProfileHash', 'capacityPolicyHash',
    'adaptiveWorkPolicyHash', 'requestedCapacity', 'grantedCapacity', 'capacityClass',
    'capacityReason', 'capacityGrantedUntil', 'bootstrapSessionId', 'readyUntil',
    'attestedAt', 'trustVerifiedAt') 'source:runtime/ready.json'
$attestedAt = ConvertTo-UtcTimestamp (Get-RequiredProperty $ready 'attestedAt' 'source:ready') 'source:ready.attestedAt'
$trustVerifiedAt = ConvertTo-UtcTimestamp (
    Get-RequiredProperty $ready 'trustVerifiedAt' 'source:ready') 'source:ready.trustVerifiedAt'
$readyUntil = ConvertTo-UtcTimestamp (Get-RequiredProperty $ready 'readyUntil' 'source:ready') 'source:ready.readyUntil'
if ((Get-ExactInteger (Get-RequiredProperty $ready 'schemaVersion' 'source:ready') 'source:ready.schemaVersion') -ne 1 `
    -or -not (Get-ExactBoolean (Get-RequiredProperty $ready 'ready' 'source:ready') 'source:ready.ready') `
    -or (Get-RequiredProperty $ready 'nodeId' 'source:ready') -cne $canaryNodeId `
    -or (Get-RequiredProperty $ready 'keyId' 'source:ready') -cne $workerKeyId `
    -or (Get-RequiredProperty $ready 'workerRuntimeVersion' 'source:ready') -cne $Version `
    -or (Get-ExactInteger (Get-RequiredProperty $ready 'requestedCapacity' 'source:ready') 'source:ready.requestedCapacity') -ne 0 `
    -or (Get-ExactInteger (Get-RequiredProperty $ready 'grantedCapacity' 'source:ready') 'source:ready.grantedCapacity') -ne 0 `
    -or $readyUntil -le $firstHeartbeatTime) {
    throw 'Durable readiness record does not prove paused bootstrap for this candidate.'
}

$trustSource = Read-SourceJson 'runtime/trust-state.json'
$trust = $trustSource.Value
Assert-ExactPropertyNames $trust @(
    'schema', 'schemaVersion', 'rootKeyId', 'rootFingerprint', 'releaseKeyId',
    'delegationSequence', 'delegationHash', 'manifestSequence', 'manifestHash',
    'contentContractHash', 'policyHash', 'verifiedAt') 'source:runtime/trust-state.json'
$trustObservedAt = ConvertTo-UtcTimestamp (Get-RequiredProperty $trust 'verifiedAt' 'source:trust') 'source:trust.verifiedAt'
if ((Get-RequiredProperty $trust 'schema' 'source:trust') -cne 'hch.worker-trust-state/v1' `
    -or (Get-ExactInteger (Get-RequiredProperty $trust 'schemaVersion' 'source:trust') 'source:trust.schemaVersion') -ne 1 `
    -or (Get-RequiredProperty $trust 'manifestHash' 'source:trust') -cne (Get-RequiredProperty $ready 'manifestHash' 'source:ready') `
    -or (Get-RequiredProperty $trust 'contentContractHash' 'source:trust') -cne (Get-RequiredProperty $ready 'contentContractHash' 'source:ready') `
    -or (Get-RequiredProperty $trust 'policyHash' 'source:trust') -cne (Get-RequiredProperty $ready 'policyHash' 'source:ready') `
    -or $trustObservedAt -ne $trustVerifiedAt -or $trustVerifiedAt -gt $attestedAt) {
    throw 'Durable trust and readiness records are not mutually consistent.'
}

$installedProbe = Read-StateProbe 'probes/installed-state.json' 'installed-paused-drain'
$restartProbe = Read-StateProbe 'probes/restart-state.json' 'restart-paused-drain'
$installedAt = $installedProbe.ObservedAt
$restartAt = $restartProbe.ObservedAt
if (-not [string]::Equals(
        $installedProbe.ServiceImagePath,
        $restartProbe.ServiceImagePath,
        [StringComparison]::OrdinalIgnoreCase) `
    -or -not [string]::Equals(
        $installedProbe.TrayExecutablePath,
        $restartProbe.TrayExecutablePath,
        [StringComparison]::OrdinalIgnoreCase) `
    -or $installedProbe.ServiceExecutableSha256 -cne $restartProbe.ServiceExecutableSha256 `
    -or $installedProbe.TrayExecutableSha256 -cne $restartProbe.TrayExecutableSha256 `
    -or $installedProbe.ProcessId -eq $restartProbe.ProcessId `
    -or $restartProbe.BootStartedAt -le $installedProbe.ObservedAt `
    -or $restartProbe.ProcessStartedAt -le $restartProbe.BootStartedAt `
    -or $restartProbe.ProcessStartedAt -le $installedProbe.ObservedAt) {
    throw 'Canary restart probe does not prove a new boot and a new SCM process for the same installed payload.'
}
$legacyProbeSource = Read-SourceJson 'probes/legacy-before-start.json'
$legacyProbe = $legacyProbeSource.Value
Assert-ExactPropertyNames $legacyProbe @(
    'schema', 'capture', 'serviceName', 'serviceState', 'startMode', 'processId', 'observedAtUtc') `
    'source:probes/legacy-before-start.json'
$legacyBeforeAt = ConvertTo-UtcTimestamp (
    Get-RequiredProperty $legacyProbe 'observedAtUtc' 'source:legacy-before') 'source:legacy-before.observedAtUtc'
$legacyProcessId = Get-ExactInteger (
    Get-RequiredProperty $legacyProbe 'processId' 'source:legacy-before') 'source:legacy-before.processId'
Assert-SafeToken (Get-RequiredProperty $legacyProbe 'serviceName' 'source:legacy-before') 'source:legacy-before.serviceName'
if ((Get-RequiredProperty $legacyProbe 'schema' 'source:legacy-before') -cne 'hch.worker-windows-scm-capture/v1' `
    -or (Get-RequiredProperty $legacyProbe 'capture' 'source:legacy-before') -cne 'legacy-before-start' `
    -or (Get-RequiredProperty $legacyProbe 'serviceState' 'source:legacy-before') -cne 'Stopped' `
    -or (Get-RequiredProperty $legacyProbe 'startMode' 'source:legacy-before') -cne 'Disabled' `
    -or $legacyProcessId -ne 0) {
    throw 'Legacy service was not captured stopped and disabled before Start.'
}
foreach ($prestartTimestamp in @($installedAt, $legacyBeforeAt, $enrolledAt, $attestedAt, $trustObservedAt)) {
    if ($prestartTimestamp -gt $firstHeartbeatTime `
        -or $prestartTimestamp -lt $firstHeartbeatTime.Subtract($maximumSessionDuration)) {
        throw 'A prerequisite capture is outside the bounded canary preparation window.'
    }
}

# Assignment-heartbeat captures contain only the sanitized progress projection
# and the SHA-256 of the exact signed request body; lease material is prohibited.
$progressItems = [Collections.Generic.List[object]]::new()
foreach ($relative in Get-CaptureFiles 'accepted/assignment-heartbeats' 2 4096) {
    $source = Read-SourceJson $relative
    $capture = $source.Value
    Assert-ExactPropertyNames $capture @(
        'schema', 'validatedAtUtc', 'observedPercent', 'requestBodySha256',
        'requestProgress', 'response') "source:$relative"
    if ((Get-RequiredProperty $capture 'schema' "source:$relative") -cne 'hch.worker-canary-assignment-heartbeat-capture/v1') {
        throw "Canary assignment-heartbeat capture schema is invalid: $relative."
    }
    $percent = Get-ExactInteger (Get-RequiredProperty $capture 'observedPercent' "source:$relative") "source:$relative.observedPercent"
    $requestBodySha256 = Get-RequiredProperty $capture 'requestBodySha256' "source:$relative"
    Assert-Sha256 $requestBodySha256 "source:$relative.requestBodySha256"
    $requestProgress = Get-RequiredProperty $capture 'requestProgress' "source:$relative"
    Assert-ExactPropertyNames $requestProgress @('phase', 'attempt', 'sequence', 'contentBytes') "source:$relative.requestProgress"
    $phase = Get-RequiredProperty $requestProgress 'phase' "source:$relative.requestProgress"
    $attempt = Get-ExactInteger (Get-RequiredProperty $requestProgress 'attempt' "source:$relative.requestProgress") "source:$relative.requestProgress.attempt"
    $sequence = Get-ExactInteger (Get-RequiredProperty $requestProgress 'sequence' "source:$relative.requestProgress") "source:$relative.requestProgress.sequence"
    $contentBytes = Get-ExactInteger (Get-RequiredProperty $requestProgress 'contentBytes' "source:$relative.requestProgress") "source:$relative.requestProgress.contentBytes"
    Assert-SafeToken $phase "source:$relative.requestProgress.phase"

    $response = Get-RequiredProperty $capture 'response' "source:$relative"
    Assert-ExactPropertyNames $response @(
        'assignmentId', 'generationPlanHash', 'leaseExpiresAt', 'liveness', 'workSizing', 'serverTime') `
        "source:$relative.response"
    $assignmentId = Get-RequiredProperty $response 'assignmentId' "source:$relative.response"
    $planHash = Get-RequiredProperty $response 'generationPlanHash' "source:$relative.response"
    Assert-CanonicalUuid $assignmentId "source:$relative.response.assignmentId"
    Assert-Sha256 $planHash "source:$relative.response.generationPlanHash"
    $serverTime = ConvertTo-UtcTimestamp (Get-RequiredProperty $response 'serverTime' "source:$relative.response") "source:$relative.response.serverTime"
    $validatedAt = ConvertTo-UtcTimestamp (Get-RequiredProperty $capture 'validatedAtUtc' "source:$relative") "source:$relative.validatedAtUtc"
    Assert-ValidatedAt $validatedAt $serverTime "source:$relative.validatedAtUtc"
    $observedAt = $validatedAt
    $leaseExpiresAt = ConvertTo-UtcTimestamp (Get-RequiredProperty $response 'leaseExpiresAt' "source:$relative.response") "source:$relative.response.leaseExpiresAt"
    $liveness = Get-RequiredProperty $response 'liveness' "source:$relative.response"
    Assert-ExactPropertyNames $liveness @('state', 'lastProgressAt', 'staleAfterSeconds') "source:$relative.response.liveness"
    $livenessState = Get-RequiredProperty $liveness 'state' "source:$relative.response.liveness"
    $lastProgressAt = ConvertTo-UtcTimestamp (Get-RequiredProperty $liveness 'lastProgressAt' "source:$relative.response.liveness") "source:$relative.response.liveness.lastProgressAt"
    $staleAfter = Get-ExactInteger (Get-RequiredProperty $liveness 'staleAfterSeconds' "source:$relative.response.liveness") "source:$relative.response.liveness.staleAfterSeconds"
    Assert-SafeToken $livenessState "source:$relative.response.liveness.state"
    $workSizing = Get-RequiredProperty $response 'workSizing' "source:$relative.response"
    Assert-ExactPropertyNames $workSizing @('currentTier', 'currentRank', 'reason') "source:$relative.response.workSizing"
    $tier = Get-RequiredProperty $workSizing 'currentTier' "source:$relative.response.workSizing"
    $rank = Get-ExactInteger (Get-RequiredProperty $workSizing 'currentRank' "source:$relative.response.workSizing") "source:$relative.response.workSizing.currentRank"
    $sizingReason = Get-RequiredProperty $workSizing 'reason' "source:$relative.response.workSizing"
    Assert-SafeToken $tier "source:$relative.response.workSizing.currentTier"
    Assert-SafeToken $sizingReason "source:$relative.response.workSizing.reason"
    if ($phase -cnotin @('responding', 'finalizing') -or $livenessState -cne $phase `
        -or $attempt -lt 1 -or $attempt -gt 8 -or $sequence -lt 1 -or $sequence -gt 4000000 `
        -or $contentBytes -lt 1 -or $contentBytes -gt 4000000 -or $percent -lt 0 -or $percent -gt 100 `
        -or $leaseExpiresAt -le $serverTime -or $lastProgressAt -gt $serverTime `
        -or $staleAfter -lt 1 -or $staleAfter -gt 86400 -or $rank -lt 0 -or $rank -gt 15 `
        -or $sizingReason -cnotin @('minimum-unit-window-ignored', 'within-window', 'near-window-downshift', 'already-downshifted')) {
        throw "Canary assignment-heartbeat capture is semantically invalid: $relative."
    }
    $outputRequestProgress = [ordered]@{
        phase = [string]$phase
        attempt = $attempt
        sequence = $sequence
        contentBytes = $contentBytes
    }
    $outputResponse = [ordered]@{
        assignmentId = [string]$assignmentId
        generationPlanHash = [string]$planHash
        leaseExpiresAt = Format-UtcTimestamp $leaseExpiresAt
        liveness = [ordered]@{
            state = [string]$livenessState
            lastProgressAt = Format-UtcTimestamp $lastProgressAt
            staleAfterSeconds = $staleAfter
        }
        workSizing = [ordered]@{
            currentTier = [string]$tier
            currentRank = $rank
            reason = [string]$sizingReason
        }
        serverTime = Format-UtcTimestamp $serverTime
    }
    $receipt = New-ReceiptSha256 'assignment-heartbeat' @(
        "assignmentId=$assignmentId",
        "observedPercent=$($percent.ToString([Globalization.CultureInfo]::InvariantCulture))",
        "observedAtUnixMs=$(Get-UnixMilliseconds $observedAt)",
        "requestBodySha256=$requestBodySha256",
        "requestProgress.phase=$phase",
        "requestProgress.attempt=$($attempt.ToString([Globalization.CultureInfo]::InvariantCulture))",
        "requestProgress.sequence=$($sequence.ToString([Globalization.CultureInfo]::InvariantCulture))",
        "requestProgress.contentBytes=$($contentBytes.ToString([Globalization.CultureInfo]::InvariantCulture))",
        "response.assignmentId=$assignmentId",
        "response.generationPlanHash=$planHash",
        "response.leaseExpiresAtUnixMs=$(Get-UnixMilliseconds $leaseExpiresAt)",
        "response.liveness.state=$livenessState",
        "response.liveness.lastProgressAtUnixMs=$(Get-UnixMilliseconds $lastProgressAt)",
        "response.liveness.staleAfterSeconds=$($staleAfter.ToString([Globalization.CultureInfo]::InvariantCulture))",
        "response.workSizing.currentTier=$tier",
        "response.workSizing.currentRank=$($rank.ToString([Globalization.CultureInfo]::InvariantCulture))",
        "response.workSizing.reason=$sizingReason",
        "response.serverTimeUnixMs=$(Get-UnixMilliseconds $serverTime)"
    )
    $progressItems.Add([pscustomobject]@{
        AssignmentId = [string]$assignmentId
        GenerationPlanHash = [string]$planHash
        ServerTime = $serverTime
        Sequence = $sequence
        Percent = $percent
        ContentBytes = $contentBytes
        Output = [ordered]@{
            assignmentId = [string]$assignmentId
            observedPercent = $percent
            observedAtUtc = Format-UtcTimestamp $observedAt
            requestBodySha256 = [string]$requestBodySha256
            requestProgress = $outputRequestProgress
            response = $outputResponse
            receiptSha256 = $receipt
        }
    })
}
$progressItems = @($progressItems | Sort-Object ServerTime, Sequence)
$progressAssignmentId = $progressItems[0].AssignmentId
$progressPlanHash = $progressItems[0].GenerationPlanHash
$previousProgress = $null
foreach ($item in $progressItems) {
    if ($item.AssignmentId -cne $progressAssignmentId -or $item.GenerationPlanHash -cne $progressPlanHash) {
        throw 'Progress captures must bind one assignment and immutable generationPlanHash.'
    }
    if ($null -ne $previousProgress `
        -and ($item.ServerTime -le $previousProgress.ServerTime `
            -or $item.Sequence -le $previousProgress.Sequence `
            -or $item.Percent -le $previousProgress.Percent `
            -or $item.ContentBytes -le $previousProgress.ContentBytes)) {
        throw 'Progress captures must increase in time, sequence, percent, and content bytes.'
    }
    $previousProgress = $item
}

function Read-RuntimeJournal {
    param(
        [Parameter(Mandatory)][string]$AssignmentId,
        [Parameter(Mandatory)][ValidateSet('completed', 'failed')][string]$ExpectedPhase,
        [AllowNull()][object]$ExpectedErrorCode,
        [Parameter(Mandatory)][string]$ExpectedPlanHash
    )

    $relative = "runtime/journals/assignments/$AssignmentId.json"
    $source = Read-SourceJson $relative
    $journal = $source.Value
    Assert-ExactPropertyNames $journal @(
        'schemaVersion', 'assignmentId', 'generationPlanHash', 'leaseTokenHash',
        'leaseExpiresAt', 'phase', 'requestId', 'requestBodyDigest', 'draftHash',
        'lastErrorCode', 'updatedAt') "source:$relative"
    $schemaVersion = Get-ExactInteger (Get-RequiredProperty $journal 'schemaVersion' "source:$relative") "source:$relative.schemaVersion"
    $phaseNumber = Get-ExactInteger (Get-RequiredProperty $journal 'phase' "source:$relative") "source:$relative.phase"
    $requestId = Get-RequiredProperty $journal 'requestId' "source:$relative"
    $requestDigest = Get-RequiredProperty $journal 'requestBodyDigest' "source:$relative"
    $draftHash = Get-RequiredProperty $journal 'draftHash' "source:$relative"
    $lastError = Get-RequiredProperty $journal 'lastErrorCode' "source:$relative"
    $updatedAt = ConvertTo-UtcTimestamp (Get-RequiredProperty $journal 'updatedAt' "source:$relative") "source:$relative.updatedAt"
    Assert-CanonicalUuid $requestId "source:$relative.requestId"
    Add-Unique $requestIds $requestId "source:$relative.requestId"
    Assert-Sha256 (Get-RequiredProperty $journal 'leaseTokenHash' "source:$relative") "source:$relative.leaseTokenHash"
    [void](ConvertTo-UtcTimestamp (Get-RequiredProperty $journal 'leaseExpiresAt' "source:$relative") "source:$relative.leaseExpiresAt")
    Assert-Sha256 $requestDigest "source:$relative.requestBodyDigest"
    if ($null -ne $draftHash) { Assert-Sha256 $draftHash "source:$relative.draftHash" }
    $expectedPhaseNumber = if ($ExpectedPhase -eq 'completed') { 6 } else { 7 }
    if ($schemaVersion -ne 1 -or $phaseNumber -ne $expectedPhaseNumber `
        -or (Get-RequiredProperty $journal 'assignmentId' "source:$relative") -cne $AssignmentId `
        -or (Get-RequiredProperty $journal 'generationPlanHash' "source:$relative") -cne $ExpectedPlanHash `
        -or $lastError -cne $ExpectedErrorCode `
        -or ($ExpectedPhase -eq 'completed' -and $null -eq $draftHash)) {
        throw "Durable runtime journal does not reconcile the accepted outcome: $relative."
    }
    return [pscustomobject]@{
        SchemaVersion = $schemaVersion
        AssignmentId = $AssignmentId
        GenerationPlanHash = $ExpectedPlanHash
        Phase = $ExpectedPhase
        RequestId = [string]$requestId
        RequestBodySha256 = [string]$requestDigest
        DraftSha256 = if ($null -eq $draftHash) { $null } else { [string]$draftHash }
        LastErrorCode = if ($null -eq $lastError) { $null } else { [string]$lastError }
        UpdatedAt = $updatedAt
        Output = [ordered]@{
            schemaVersion = $schemaVersion
            assignmentId = $AssignmentId
            generationPlanHash = $ExpectedPlanHash
            phase = $ExpectedPhase
            requestId = [string]$requestId
            requestBodySha256 = [string]$requestDigest
            draftSha256 = if ($null -eq $draftHash) { $null } else { [string]$draftHash }
            lastErrorCode = if ($null -eq $lastError) { $null } else { [string]$lastError }
            updatedAtUtc = Format-UtcTimestamp $updatedAt
        }
    }
}

$completionItems = [Collections.Generic.List[object]]::new()
$outcomeAssignments = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
foreach ($relative in Get-CaptureFiles 'accepted/completions' 1 128) {
    $source = Read-SourceJson $relative
    $capture = $source.Value
    Assert-ExactPropertyNames $capture @('schema', 'validatedAtUtc', 'response') "source:$relative"
    if ((Get-RequiredProperty $capture 'schema' "source:$relative") -cne 'hch.worker-canary-complete-capture/v1') {
        throw "Canary completion capture schema is invalid: $relative."
    }
    $response = Get-RequiredProperty $capture 'response' "source:$relative"
    Assert-ExactPropertyNames $response @(
        'assignmentId', 'generationPlanHash', 'commitAccepted', 'status',
        'automaticApproval', 'automaticPublication', 'replayed', 'serverTime') "source:$relative.response"
    $assignmentId = Get-RequiredProperty $response 'assignmentId' "source:$relative.response"
    $planHash = Get-RequiredProperty $response 'generationPlanHash' "source:$relative.response"
    Assert-CanonicalUuid $assignmentId "source:$relative.response.assignmentId"
    Assert-Sha256 $planHash "source:$relative.response.generationPlanHash"
    Add-Unique $outcomeAssignments $assignmentId "source:$relative.response.assignmentId"
    $commitAccepted = Get-ExactBoolean (Get-RequiredProperty $response 'commitAccepted' "source:$relative.response") "source:$relative.response.commitAccepted"
    $automaticApproval = Get-ExactBoolean (Get-RequiredProperty $response 'automaticApproval' "source:$relative.response") "source:$relative.response.automaticApproval"
    $automaticPublication = Get-ExactBoolean (Get-RequiredProperty $response 'automaticPublication' "source:$relative.response") "source:$relative.response.automaticPublication"
    $replayed = Get-ExactBoolean (Get-RequiredProperty $response 'replayed' "source:$relative.response") "source:$relative.response.replayed"
    $status = Get-RequiredProperty $response 'status' "source:$relative.response"
    $serverTime = ConvertTo-UtcTimestamp (Get-RequiredProperty $response 'serverTime' "source:$relative.response") "source:$relative.response.serverTime"
    $validatedAt = ConvertTo-UtcTimestamp (Get-RequiredProperty $capture 'validatedAtUtc' "source:$relative") "source:$relative.validatedAtUtc"
    Assert-ValidatedAt $validatedAt $serverTime "source:$relative.validatedAtUtc"
    if (-not $commitAccepted -or $automaticApproval -or $automaticPublication -or $status -cne 'pending-review') {
        throw "Accepted completion capture is not pending editorial review: $relative."
    }
    $journal = Read-RuntimeJournal $assignmentId 'completed' $null $planHash
    if ($journal.UpdatedAt -lt $serverTime.Subtract($maximumClockSkew)) {
        throw "Completion journal was not durably reconciled near the accepted response: $relative."
    }
    $receipt = New-ReceiptSha256 'complete' @(
        "assignmentId=$assignmentId",
        "generationPlanHash=$planHash",
        "commitAccepted=$(Format-Boolean $commitAccepted)",
        "status=$status",
        "automaticApproval=$(Format-Boolean $automaticApproval)",
        "automaticPublication=$(Format-Boolean $automaticPublication)",
        "replayed=$(Format-Boolean $replayed)",
        "serverTimeUnixMs=$(Get-UnixMilliseconds $serverTime)",
        "journal.schemaVersion=$($journal.SchemaVersion.ToString([Globalization.CultureInfo]::InvariantCulture))",
        "journal.assignmentId=$($journal.AssignmentId)",
        "journal.generationPlanHash=$($journal.GenerationPlanHash)",
        'journal.phase=completed',
        "journal.requestId=$($journal.RequestId)",
        "journal.requestBodySha256=$($journal.RequestBodySha256)",
        "journal.draftSha256=$($journal.DraftSha256)",
        'journal.lastErrorCode=~',
        "journal.updatedAtUnixMs=$(Get-UnixMilliseconds $journal.UpdatedAt)"
    )
    $completionItems.Add([pscustomobject]@{
        AssignmentId = [string]$assignmentId
        GenerationPlanHash = [string]$planHash
        ServerTime = $serverTime
        Output = [ordered]@{
            assignmentId = [string]$assignmentId
            generationPlanHash = [string]$planHash
            commitAccepted = $commitAccepted
            status = [string]$status
            automaticApproval = $automaticApproval
            automaticPublication = $automaticPublication
            replayed = $replayed
            serverTime = Format-UtcTimestamp $serverTime
            journal = $journal.Output
            receiptSha256 = $receipt
        }
    })
}
$completionItems = @($completionItems | Sort-Object ServerTime, AssignmentId)
if (-not ($completionItems.AssignmentId -ccontains $progressAssignmentId)) {
    throw 'Progress captures are not linked to an accepted completed assignment.'
}
$linkedCompletion = @($completionItems | Where-Object AssignmentId -CEQ $progressAssignmentId)[0]
if ($linkedCompletion.GenerationPlanHash -cne $progressPlanHash `
    -or $linkedCompletion.ServerTime -le $previousProgress.ServerTime) {
    throw 'Progress and completion captures do not preserve one immutable plan in order.'
}

$failureItems = [Collections.Generic.List[object]]::new()
foreach ($relative in Get-CaptureFiles 'accepted/failures' 1 128) {
    $source = Read-SourceJson $relative
    $capture = $source.Value
    Assert-ExactPropertyNames $capture @('schema', 'validatedAtUtc', 'requestErrorCode', 'response') "source:$relative"
    if ((Get-RequiredProperty $capture 'schema' "source:$relative") -cne 'hch.worker-canary-fail-capture/v1') {
        throw "Canary failure capture schema is invalid: $relative."
    }
    $errorCode = Get-RequiredProperty $capture 'requestErrorCode' "source:$relative"
    if ($errorCode -isnot [string] -or $errorCode -notmatch '^[a-z0-9][a-z0-9.-]{0,63}$') {
        throw "Failure capture has an unsafe error code: $relative."
    }
    $response = Get-RequiredProperty $capture 'response' "source:$relative"
    Assert-ExactPropertyNames $response @(
        'assignmentId', 'generationPlanHash', 'status', 'replayed', 'serverTime') "source:$relative.response"
    $assignmentId = Get-RequiredProperty $response 'assignmentId' "source:$relative.response"
    $planHash = Get-RequiredProperty $response 'generationPlanHash' "source:$relative.response"
    Assert-CanonicalUuid $assignmentId "source:$relative.response.assignmentId"
    Assert-Sha256 $planHash "source:$relative.response.generationPlanHash"
    Add-Unique $outcomeAssignments $assignmentId "source:$relative.response.assignmentId"
    $status = Get-RequiredProperty $response 'status' "source:$relative.response"
    $replayed = Get-ExactBoolean (Get-RequiredProperty $response 'replayed' "source:$relative.response") "source:$relative.response.replayed"
    $serverTime = ConvertTo-UtcTimestamp (Get-RequiredProperty $response 'serverTime' "source:$relative.response") "source:$relative.response.serverTime"
    $validatedAt = ConvertTo-UtcTimestamp (Get-RequiredProperty $capture 'validatedAtUtc' "source:$relative") "source:$relative.validatedAtUtc"
    Assert-ValidatedAt $validatedAt $serverTime "source:$relative.validatedAtUtc"
    if ($status -cne 'failed-attempt') {
        throw "Accepted failure capture is not reconciled as failed-attempt: $relative."
    }
    $journal = Read-RuntimeJournal $assignmentId 'failed' $errorCode $planHash
    if ($journal.UpdatedAt -lt $serverTime.Subtract($maximumClockSkew)) {
        throw "Failure journal was not durably reconciled near the accepted response: $relative."
    }
    $draftCanonical = if ($null -eq $journal.DraftSha256) { '~' } else { $journal.DraftSha256 }
    $receipt = New-ReceiptSha256 'fail' @(
        "assignmentId=$assignmentId",
        "generationPlanHash=$planHash",
        "status=$status",
        "replayed=$(Format-Boolean $replayed)",
        "serverTimeUnixMs=$(Get-UnixMilliseconds $serverTime)",
        "requestErrorCode=$errorCode",
        "journal.schemaVersion=$($journal.SchemaVersion.ToString([Globalization.CultureInfo]::InvariantCulture))",
        "journal.assignmentId=$($journal.AssignmentId)",
        "journal.generationPlanHash=$($journal.GenerationPlanHash)",
        'journal.phase=failed',
        "journal.requestId=$($journal.RequestId)",
        "journal.requestBodySha256=$($journal.RequestBodySha256)",
        "journal.draftSha256=$draftCanonical",
        "journal.lastErrorCode=$($journal.LastErrorCode)",
        "journal.updatedAtUnixMs=$(Get-UnixMilliseconds $journal.UpdatedAt)"
    )
    $failureItems.Add([pscustomobject]@{
        AssignmentId = [string]$assignmentId
        ServerTime = $serverTime
        Output = [ordered]@{
            assignmentId = [string]$assignmentId
            generationPlanHash = [string]$planHash
            status = [string]$status
            replayed = $replayed
            serverTime = Format-UtcTimestamp $serverTime
            requestErrorCode = [string]$errorCode
            journal = $journal.Output
            receiptSha256 = $receipt
        }
    })
}
$failureItems = @($failureItems | Sort-Object ServerTime, AssignmentId)
$outcomeTimes = @(
    @($completionItems | ForEach-Object { $_.ServerTime })
    @($failureItems | ForEach-Object { $_.ServerTime })
)
$latestOutcomeTime = @($outcomeTimes | Sort-Object -Descending)[0]

# Rollback consumes a real backup receipt. No backup or service-definition hash
# is accepted from the rollback capture itself.
$rollbackSource = Read-SourceJson 'rollback/rollback.json'
$rollbackCapture = $rollbackSource.Value
Assert-ExactPropertyNames $rollbackCapture @(
    'schema', 'validatedAtUtc', 'receiptId', 'serverTime', 'targetVersion',
    'v4ServiceDisabled', 'legacyServiceStartMode', 'legacyBackupReceiptRelativePath',
    'restoredServiceDefinition', 'legacyHeartbeat') 'source:rollback/rollback.json'
if ((Get-RequiredProperty $rollbackCapture 'schema' 'source:rollback') -cne 'hch.worker-canary-rollback-capture/v1') {
    throw 'Canary rollback capture schema is invalid.'
}
$rollbackReceiptId = Get-RequiredProperty $rollbackCapture 'receiptId' 'source:rollback'
Assert-CanonicalUuid $rollbackReceiptId 'source:rollback.receiptId'
$rollbackServerTime = ConvertTo-UtcTimestamp (
    Get-RequiredProperty $rollbackCapture 'serverTime' 'source:rollback') 'source:rollback.serverTime'
$rollbackValidatedAt = ConvertTo-UtcTimestamp (
    Get-RequiredProperty $rollbackCapture 'validatedAtUtc' 'source:rollback') 'source:rollback.validatedAtUtc'
Assert-ValidatedAt $rollbackValidatedAt $rollbackServerTime 'source:rollback.validatedAtUtc'
$v4Disabled = Get-ExactBoolean (
    Get-RequiredProperty $rollbackCapture 'v4ServiceDisabled' 'source:rollback') 'source:rollback.v4ServiceDisabled'
if ((Get-RequiredProperty $rollbackCapture 'targetVersion' 'source:rollback') -cne '3.1.1' `
    -or -not $v4Disabled `
    -or (Get-RequiredProperty $rollbackCapture 'legacyServiceStartMode' 'source:rollback') -cne 'AutomaticDelayed') {
    throw 'Rollback capture does not prove disabled v4 and restored 3.1.1 service mode.'
}

$backupRelativePath = Get-RequiredProperty $rollbackCapture 'legacyBackupReceiptRelativePath' 'source:rollback'
if ($backupRelativePath -isnot [string]) { throw 'Rollback backup receipt path must be a string.' }
$backupSource = Read-SourceJson $backupRelativePath
$backupReceipt = $backupSource.Value
Assert-ExactPropertyNames $backupReceipt @('payload', 'receiptSha256') "source:$backupRelativePath"
Assert-Sha256 (Get-RequiredProperty $backupReceipt 'receiptSha256' "source:$backupRelativePath") "source:$backupRelativePath.receiptSha256"
$backupPayload = Get-RequiredProperty $backupReceipt 'payload' "source:$backupRelativePath"
Assert-ExactPropertyNames $backupPayload @(
    'schemaVersion', 'migrationId', 'sourceVersion', 'sourceProductRoot',
    'sourceSnapshotSha256', 'nodeId', 'keyId', 'files', 'aclReceipts',
    'serviceDefinition', 'capturedAt') "source:$backupRelativePath.payload"
if ((Get-ExactInteger (Get-RequiredProperty $backupPayload 'schemaVersion' "source:$backupRelativePath.payload") "source:$backupRelativePath.payload.schemaVersion") -ne 1 `
    -or (Get-RequiredProperty $backupPayload 'sourceVersion' "source:$backupRelativePath.payload") -cne '3.1.1' `
    -or (Get-RequiredProperty $backupPayload 'nodeId' "source:$backupRelativePath.payload") -cne $canaryNodeId) {
    throw 'Referenced legacy backup receipt does not bind 3.1.1 and the canary node.'
}

$backupDocument = [Text.Json.JsonDocument]::Parse($backupSource.Raw)
try {
    $canonicalPayload = ConvertTo-LimitedJcs $backupDocument.RootElement.GetProperty('payload')
} finally {
    $backupDocument.Dispose()
}
if ((Get-Sha256Text $canonicalPayload) -cne (Get-RequiredProperty $backupReceipt 'receiptSha256' "source:$backupRelativePath")) {
    throw 'Referenced legacy backup receipt has an invalid canonical payload digest.'
}
$backupSha256 = $backupSource.Sha256
$previousDefinition = Get-RequiredProperty $backupPayload 'serviceDefinition' "source:$backupRelativePath.payload"
$restoredDefinition = Get-RequiredProperty $rollbackCapture 'restoredServiceDefinition' 'source:rollback'
$previousDefinitionSha256 = Get-ServiceDefinitionHash $previousDefinition "source:$backupRelativePath.payload.serviceDefinition"
$restoredDefinitionSha256 = Get-ServiceDefinitionHash $restoredDefinition 'source:rollback.restoredServiceDefinition'
if ($previousDefinitionSha256 -cne $restoredDefinitionSha256) {
    throw 'Rollback capture did not restore the exact sanitized legacy service definition.'
}

$legacyHeartbeat = Convert-HeartbeatValue (
    Get-RequiredProperty $rollbackCapture 'legacyHeartbeat' 'source:rollback') `
    'source:rollback.legacyHeartbeat' 'legacy-node-heartbeat'
if ($legacyHeartbeat.NodeId -cne $canaryNodeId `
    -or $legacyHeartbeat.ServerTime -le $rollbackServerTime) {
    throw 'Rollback legacy heartbeat does not bind the same node strictly after restoration.'
}
$completedAt = $legacyHeartbeat.ServerTime
$startedAt = $firstHeartbeatTime
if ($completedAt -le $startedAt -or ($completedAt - $startedAt) -gt $maximumSessionDuration `
    -or ($completedAt - $previousHeartbeatTime) -gt $maximumHeartbeatGap `
    -or $rollbackServerTime -lt $previousHeartbeatTime `
    -or $rollbackServerTime -lt $latestOutcomeTime `
    -or $rollbackServerTime -gt $completedAt `
    -or $restartProbe.BootStartedAt -le $previousHeartbeatTime `
    -or $restartProbe.ProcessStartedAt -le $restartProbe.BootStartedAt `
    -or $restartAt -le $latestOutcomeTime `
    -or $restartAt -gt $rollbackServerTime `
    -or $rollbackValidatedAt -lt $rollbackServerTime `
    -or $restartAt -gt $rollbackValidatedAt `
    -or $rollbackValidatedAt -ge $legacyHeartbeat.ServerTime) {
    throw 'Canary rollback and session boundaries are not chronologically valid.'
}

$rollbackReceiptSha256 = New-ReceiptSha256 'rollback' @(
    "receiptId=$rollbackReceiptId",
    "serverTimeUnixMs=$(Get-UnixMilliseconds $rollbackServerTime)",
    'targetVersion=3.1.1',
    'v4ServiceDisabled=true',
    'legacyServiceStartMode=AutomaticDelayed',
    "backupSha256=$backupSha256",
    "previousServiceDefinitionSha256=$previousDefinitionSha256",
    "restoredServiceDefinitionSha256=$restoredDefinitionSha256",
    "legacyHeartbeatReceiptSha256=$($legacyHeartbeat.Output.receiptSha256)"
)
$rollbackOutput = [ordered]@{
    receiptId = [string]$rollbackReceiptId
    serverTime = Format-UtcTimestamp $rollbackServerTime
    targetVersion = '3.1.1'
    v4ServiceDisabled = $true
    legacyServiceStartMode = 'AutomaticDelayed'
    backupSha256 = $backupSha256
    previousServiceDefinitionSha256 = $previousDefinitionSha256
    restoredServiceDefinitionSha256 = $restoredDefinitionSha256
    legacyHeartbeat = $legacyHeartbeat.Output
    receiptSha256 = $rollbackReceiptSha256
}

$installationReceiptSha256 = New-ReceiptSha256 'install-restart' @(
    "msiSha256=$msiSha256",
    "msiLifecycleEvidenceSha256=$msiLifecycleEvidenceSha256",
    "productCode=$($msiIdentity.ProductCode)",
    "packageCode=$($msiIdentity.PackageCode)",
    'serviceName=HchWorker',
    "serviceImagePath=$($installedProbe.ServiceImagePath)",
    "serviceExecutableSha256=$($installedProbe.ServiceExecutableSha256)",
    "trayExecutablePath=$($installedProbe.TrayExecutablePath)",
    "trayExecutableSha256=$($installedProbe.TrayExecutableSha256)",
    "installed.bootStartedAtUnixMs=$(Get-UnixMilliseconds $installedProbe.BootStartedAt)",
    "installed.processStartedAtUnixMs=$(Get-UnixMilliseconds $installedProbe.ProcessStartedAt)",
    "installed.observedAtUnixMs=$(Get-UnixMilliseconds $installedProbe.ObservedAt)",
    "installed.processId=$($installedProbe.ProcessId.ToString([Globalization.CultureInfo]::InvariantCulture))",
    "restart.bootStartedAtUnixMs=$(Get-UnixMilliseconds $restartProbe.BootStartedAt)",
    "restart.processStartedAtUnixMs=$(Get-UnixMilliseconds $restartProbe.ProcessStartedAt)",
    "restart.observedAtUnixMs=$(Get-UnixMilliseconds $restartProbe.ObservedAt)",
    "restart.processId=$($restartProbe.ProcessId.ToString([Globalization.CultureInfo]::InvariantCulture))"
)
$installationOutput = [ordered]@{
    msiLifecycleEvidenceSha256 = $msiLifecycleEvidenceSha256
    productCode = $msiIdentity.ProductCode
    packageCode = $msiIdentity.PackageCode
    serviceName = 'HchWorker'
    serviceImagePath = $installedProbe.ServiceImagePath
    serviceExecutableSha256 = $installedProbe.ServiceExecutableSha256
    trayExecutablePath = $installedProbe.TrayExecutablePath
    trayExecutableSha256 = $installedProbe.TrayExecutableSha256
    installed = [ordered]@{
        bootStartedAtUtc = Format-UtcTimestamp $installedProbe.BootStartedAt
        processStartedAtUtc = Format-UtcTimestamp $installedProbe.ProcessStartedAt
        observedAtUtc = Format-UtcTimestamp $installedProbe.ObservedAt
        processId = $installedProbe.ProcessId
    }
    restart = [ordered]@{
        bootStartedAtUtc = Format-UtcTimestamp $restartProbe.BootStartedAt
        processStartedAtUtc = Format-UtcTimestamp $restartProbe.ProcessStartedAt
        observedAtUtc = Format-UtcTimestamp $restartProbe.ObservedAt
        processId = $restartProbe.ProcessId
    }
    receiptSha256 = $installationReceiptSha256
}

# The dedicated bundle is exact. Unknown or unreferenced files are rejected so
# an operator cannot accidentally sign a partial selection from a larger,
# potentially sensitive runtime directory.
foreach ($directory in Get-ChildItem -LiteralPath $resolvedCaptureDirectory -Directory -Recurse -Force) {
    if (($directory.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw 'Canary source bundle contains a reparse directory.'
    }
}
$allFiles = @(Get-ChildItem -LiteralPath $resolvedCaptureDirectory -File -Recurse -Force)
if ($allFiles.Count -ne $sourceDigests.Count) {
    throw 'Canary source bundle contains an unsupported or unreferenced file.'
}
foreach ($file in $allFiles) {
    if (-not $sourceDigests.ContainsKey([IO.Path]::GetFullPath($file.FullName))) {
        throw 'Canary source bundle contains an unsupported or unreferenced file.'
    }
}

$evidence = [ordered]@{
    schema = 'hch.worker-windows-canary/v2'
    status = 'passed'
    sanitized = $true
    version = $Version
    sourceCommit = $SourceCommit
    msiSha256 = $msiSha256
    installationReceipt = $installationOutput
    startedAtUtc = Format-UtcTimestamp $startedAt
    completedAtUtc = Format-UtcTimestamp $completedAt
    gates = [ordered]@{
        installedPausedDrain = $true
        legacyServiceStoppedDisabled = $true
        enrollment = $true
        bootstrap = $true
        claim = ($outcomeAssignments.Count -gt 0)
        restartPausedDrain = $true
    }
    heartbeatSamples = @($heartbeatItems | ForEach-Object { $_.Output })
    progressSamples = @($progressItems | ForEach-Object { $_.Output })
    completions = @($completionItems | ForEach-Object { $_.Output })
    failures = @($failureItems | ForEach-Object { $_.Output })
    rollbackReceipt = $rollbackOutput
}

$json = ($evidence | ConvertTo-Json -Depth 100 -Compress) -replace "`r`n", "`n"
$json += "`n"
Assert-NoSecretShapedMaterial $json 'canary-evidence.json'
if ($json -match '(?i)ownerEmail|workerPublicKey|leaseTokenHash|sourceProductRoot|securityDescriptorSddl|draftHash|requestBodyDigest') {
    throw 'Sanitized evidence projection retained a prohibited source-only field.'
}

# Revalidate every source after building the projection. A producer modifying a
# capture concurrently causes a failure before publication.
foreach ($entry in $sourceDigests.GetEnumerator()) {
    Assert-NoReparsePoint $entry.Key $resolvedCaptureDirectory
    $actual = Get-Sha256Bytes ([IO.File]::ReadAllBytes($entry.Key))
    if ($actual -cne $entry.Value) {
        throw 'Canary source bundle changed during export.'
    }
}

# Re-enumerate after digest verification. This narrows the publication race and
# fails closed if another process adds an unsupported file during projection.
$finalFiles = @(Get-ChildItem -LiteralPath $resolvedCaptureDirectory -File -Recurse -Force)
if ($finalFiles.Count -ne $sourceDigests.Count) {
    throw 'Canary source bundle changed during export.'
}
foreach ($file in $finalFiles) {
    $full = [IO.Path]::GetFullPath($file.FullName)
    Assert-NoReparsePoint $full $resolvedCaptureDirectory
    if (-not $sourceDigests.ContainsKey($full)) {
        throw 'Canary source bundle changed during export.'
    }
}

$bytes = [Text.UTF8Encoding]::new($false).GetBytes($json)
$temporary = [IO.Path]::Combine(
    $evidenceParent,
    ".canary-evidence.$([Guid]::NewGuid().ToString('N')).tmp")
try {
    $stream = [IO.FileStream]::new(
        $temporary,
        [IO.FileMode]::CreateNew,
        [IO.FileAccess]::Write,
        [IO.FileShare]::None,
        65536,
        [IO.FileOptions]::WriteThrough)
    try {
        $stream.Write($bytes, 0, $bytes.Length)
        $stream.Flush($true)
    } finally {
        $stream.Dispose()
    }
    [IO.File]::Move($temporary, $resolvedEvidence)
} finally {
    if (Test-Path -LiteralPath $temporary) {
        Remove-Item -LiteralPath $temporary -Force
    }
}

Write-Host (
    'Unsigned deterministic canary evidence exported from {0} real source files: {1}' -f `
    $sourceDigests.Count,
    $resolvedEvidence)
