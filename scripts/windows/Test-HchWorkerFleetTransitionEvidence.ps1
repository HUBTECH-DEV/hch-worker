[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$EvidencePath,
    [Parameter(Mandatory)][string]$EvidenceSignaturePath,
    [Parameter(Mandatory)][ValidatePattern('^[0-9A-Fa-f]{40}$')][string]$ExpectedTelemetryAuthorityThumbprint,
    [Parameter(Mandatory)][ValidatePattern('^[0-9A-Fa-f]{64}$')][string]$ExpectedTelemetryAuthorityCertificateSha256,
    [string]$ExpectedRepository = 'HUBTECH-DEV/hch-worker',
    [string]$ExpectedBridgeTag = 'v3.1.1',
    [Parameter(Mandatory)][ValidatePattern('^[1-9][0-9]*$')][string]$ExpectedBridgeReleaseId,
    [Parameter(Mandatory)][ValidatePattern('^[0-9a-f]{40}$')][string]$ExpectedBridgeSourceCommit
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$maximumHeartbeatGapSeconds = 120
$maximumEvidenceBytes = 128MB
$maximumSignatureBytes = 1MB
$maximumNodes = 64
$maximumHeartbeatSamplesPerNode = 20000
$maximumHeartbeatSamplesTotal = 500000
$utf8 = [Text.UTF8Encoding]::new($false, $true)

function Read-BoundedRegularFile(
    [string]$Path,
    [long]$MaximumBytes,
    [string]$Label
) {
    $resolvedPath = (Resolve-Path -LiteralPath $Path).Path
    $item = Get-Item -LiteralPath $resolvedPath -Force
    if ($item.PSIsContainer) {
        throw "$Label must be a regular file."
    }
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "$Label must not be a reparse point."
    }

    # Size and bytes are read through the same handle. FileShare.Read excludes
    # new writers and delete/rename access while the handle is held, removing
    # the ordinary path-check/path-read TOCTOU window on the Windows runner.
    $stream = [IO.FileStream]::new(
        $resolvedPath,
        [IO.FileMode]::Open,
        [IO.FileAccess]::Read,
        [IO.FileShare]::Read
    )
    try {
        $openedItem = Get-Item -LiteralPath $resolvedPath -Force
        if (($openedItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "$Label became a reparse point while it was opened."
        }
        $length = $stream.Length
        if ($length -le 0 -or $length -gt $MaximumBytes) {
            throw "$Label must be between 1 byte and $MaximumBytes bytes."
        }
        $buffer = [byte[]]::new([int]$length)
        $offset = 0
        while ($offset -lt $buffer.Length) {
            $read = $stream.Read($buffer, $offset, $buffer.Length - $offset)
            if ($read -le 0) {
                throw "$Label ended before its declared length."
            }
            $offset += $read
        }
        if ($stream.Length -ne $length) {
            throw "$Label changed while it was read."
        }
        return [pscustomobject]@{
            Path = $resolvedPath
            Bytes = $buffer
        }
    }
    finally {
        $stream.Dispose()
    }
}

$evidenceFile = Read-BoundedRegularFile $EvidencePath $maximumEvidenceBytes 'Fleet evidence'
$signatureFile = Read-BoundedRegularFile $EvidenceSignaturePath $maximumSignatureBytes 'Detached signature'
$bytes = $evidenceFile.Bytes
$signatureBytes = $signatureFile.Bytes
$raw = $utf8.GetString($bytes)

if ($bytes.Length -eq 0 -or $signatureBytes.Length -eq 0 -or $raw[0] -eq [char]0xFEFF) {
    throw 'Evidence and detached signature must be non-empty; evidence must be UTF-8 without BOM.'
}
if ($raw -match '(?i)private.?key|password|secret|token|authorization|bearer') {
    throw 'Evidence contains a prohibited sensitive name or value.'
}

$jsonOptions = [Text.Json.JsonDocumentOptions]::new()
$jsonOptions.AllowTrailingCommas = $false
$jsonOptions.CommentHandling = [Text.Json.JsonCommentHandling]::Disallow
$root = [Text.Json.JsonDocument]::Parse($raw, $jsonOptions)

function Test-DuplicateProperties([Text.Json.JsonElement]$Element, [string]$Path) {
    if ($Element.ValueKind -eq [Text.Json.JsonValueKind]::Object) {
        $seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
        foreach ($property in $Element.EnumerateObject()) {
            if (-not $seen.Add($property.Name)) {
                throw "Duplicate JSON property: $Path.$($property.Name)"
            }
            Test-DuplicateProperties $property.Value "$Path.$($property.Name)"
        }
    }
    elseif ($Element.ValueKind -eq [Text.Json.JsonValueKind]::Array) {
        $index = 0
        foreach ($value in $Element.EnumerateArray()) {
            Test-DuplicateProperties $value "$Path[$index]"
            $index++
        }
    }
}

function Get-ExactPositiveJsonInteger(
    [Text.Json.JsonElement]$Object,
    [string]$Name,
    [bool]$AllowZero
) {
    $property = $Object.GetProperty($Name)
    $value = [long]0
    if (
        $property.ValueKind -ne [Text.Json.JsonValueKind]::Number -or
        -not $property.TryGetInt64([ref]$value) -or
        ($AllowZero -and $value -lt 0) -or
        (-not $AllowZero -and $value -le 0)
    ) {
        throw "$Name must be an exact JSON integer in the permitted positive range."
    }
    return $value
}

function Assert-CanonicalUtcJsonProperty(
    [Text.Json.JsonElement]$Object,
    [string]$Name,
    [string]$Path
) {
    $property = [Text.Json.JsonElement]::new()
    # Missing or differently-cased names are diagnosed later by the exact
    # shape check. When the exact name exists, validate the original JSON token
    # before ConvertFrom-Json can normalize it into DateTime.
    if (-not $Object.TryGetProperty($Name, [ref]$property)) {
        return
    }
    $value = if ($property.ValueKind -eq [Text.Json.JsonValueKind]::String) {
        $property.GetString()
    }
    else {
        $null
    }
    $parsed = [DateTimeOffset]::MinValue
    $styles = (
        [Globalization.DateTimeStyles]::AssumeUniversal -bor
        [Globalization.DateTimeStyles]::AdjustToUniversal
    )
    if (
        $null -eq $value -or
        -not [DateTimeOffset]::TryParseExact(
            $value,
            'yyyy-MM-ddTHH:mm:ss.fffZ',
            [Globalization.CultureInfo]::InvariantCulture,
            $styles,
            [ref]$parsed
        ) -or
        $parsed.ToString(
            'yyyy-MM-ddTHH:mm:ss.fffZ',
            [Globalization.CultureInfo]::InvariantCulture
        ) -cne $value
    ) {
        throw "$Path must be a JSON string exactly yyyy-MM-ddTHH:mm:ss.fffZ."
    }
}

Test-DuplicateProperties $root.RootElement '$'
if ($root.RootElement.ValueKind -ne [Text.Json.JsonValueKind]::Object) {
    throw 'Fleet evidence root must be a JSON object.'
}
Assert-CanonicalUtcJsonProperty `
    $root.RootElement `
    'windowStartedAtUtc' `
    '$.windowStartedAtUtc'
Assert-CanonicalUtcJsonProperty `
    $root.RootElement `
    'windowCompletedAtUtc' `
    '$.windowCompletedAtUtc'

$jsonBridgeReleaseId = Get-ExactPositiveJsonInteger $root.RootElement 'bridgeReleaseId' $false
$jsonEligibleWorkerCount = Get-ExactPositiveJsonInteger $root.RootElement 'eligibleWorkerCount' $false
$jsonObservedWorkerCount = Get-ExactPositiveJsonInteger $root.RootElement 'observedWorkerCount' $false
$jsonLegacyLatestOnlyWorkerCount = Get-ExactPositiveJsonInteger $root.RootElement 'legacyLatestOnlyWorkerCount' $true
$nodesElement = $root.RootElement.GetProperty('nodes')
if ($nodesElement.ValueKind -ne [Text.Json.JsonValueKind]::Array) {
    throw 'nodes must be a JSON array even when it contains one element.'
}
$nodeCount = $nodesElement.GetArrayLength()
if ($nodeCount -gt $maximumNodes) {
    throw "nodes exceeds the maximum of $maximumNodes entries."
}
$jsonInventoryMemberIndexes = [Collections.Generic.List[long]]::new()
$jsonHeartbeatSampleCount = [long]0
$nodeElementIndex = 0
foreach ($nodeElement in $nodesElement.EnumerateArray()) {
    if ($nodeElement.ValueKind -ne [Text.Json.JsonValueKind]::Object) {
        throw 'Every nodes entry must be a JSON object.'
    }
    $memberIndex = Get-ExactPositiveJsonInteger $nodeElement 'inventoryMemberIndex' $true
    [void]$jsonInventoryMemberIndexes.Add($memberIndex)
    $heartbeatSamplesElement = $nodeElement.GetProperty('heartbeatSamples')
    if ($heartbeatSamplesElement.ValueKind -ne [Text.Json.JsonValueKind]::Array) {
        throw 'heartbeatSamples must be a JSON array.'
    }
    $sampleCount = $heartbeatSamplesElement.GetArrayLength()
    if ($sampleCount -lt 2 -or $sampleCount -gt $maximumHeartbeatSamplesPerNode) {
        throw "Each node must contain between 2 and $maximumHeartbeatSamplesPerNode heartbeat samples."
    }
    $heartbeatElementIndex = 0
    foreach ($heartbeatElement in $heartbeatSamplesElement.EnumerateArray()) {
        if ($heartbeatElement.ValueKind -eq [Text.Json.JsonValueKind]::Object) {
            Assert-CanonicalUtcJsonProperty `
                $heartbeatElement `
                'serverTime' `
                "$.nodes[$nodeElementIndex].heartbeatSamples[$heartbeatElementIndex].serverTime"
        }
        $heartbeatElementIndex++
    }
    $jsonHeartbeatSampleCount += $sampleCount
    if ($jsonHeartbeatSampleCount -gt $maximumHeartbeatSamplesTotal) {
        throw "Fleet evidence exceeds the maximum of $maximumHeartbeatSamplesTotal heartbeat samples."
    }
    $nodeElementIndex++
}
$root.Dispose()

$evidence = $raw | ConvertFrom-Json -Depth 100

function Assert-ExactProperties($Object, [string[]]$Names, [string]$Path) {
    $actual = @($Object.PSObject.Properties.Name)
    if ($actual.Count -ne $Names.Count) {
        throw "Unexpected or missing property at $Path"
    }
    $actualSet = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($name in $actual) {
        [void]$actualSet.Add($name)
    }
    foreach ($name in $Names) {
        if (-not $actualSet.Contains($name)) {
            throw "Unexpected or missing property at $Path"
        }
    }
}

function Convert-CanonicalUtc($Value, [string]$Path) {
    $text = if ($Value -is [DateTime]) {
        $Value.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ', [Globalization.CultureInfo]::InvariantCulture)
    }
    else {
        [string]$Value
    }
    $result = [DateTimeOffset]::MinValue
    if (-not [DateTimeOffset]::TryParseExact(
        $text,
        'yyyy-MM-ddTHH:mm:ss.fffZ',
        [Globalization.CultureInfo]::InvariantCulture,
        [Globalization.DateTimeStyles]::AssumeUniversal,
        [ref]$result
    )) {
        throw "$Path must be canonical UTC"
    }
    return $result.ToUniversalTime()
}

function Assert-Sha256($Value, [string]$Path) {
    if ($Value -isnot [string] -or $Value -notmatch '^[0-9a-f]{64}$') {
        throw "$Path must be lowercase SHA-256"
    }
    return $Value
}

function Assert-CanonicalUuid($Value, [string]$Path) {
    $guid = [Guid]::Empty
    if (
        $Value -isnot [string] -or
        -not [Guid]::TryParseExact($Value, 'D', [ref]$guid) -or
        $guid -eq [Guid]::Empty -or
        $guid.ToString('D') -cne $Value
    ) {
        throw "$Path must be canonical UUID"
    }
    return $Value
}

function Get-Sha256([string]$Value) {
    return [Convert]::ToHexString(
        [Security.Cryptography.SHA256]::HashData($utf8.GetBytes($Value))
    ).ToLowerInvariant()
}

function Get-DerivedInventorySnapshotId([string]$InventorySnapshotSha256) {
    $canonical = @(
        'schema=hch.worker-fleet-inventory-snapshot-id/v1',
        "inventorySnapshotSha256=$InventorySnapshotSha256"
    ) -join "`n"
    $canonical += "`n"
    $digest = Get-Sha256 $canonical
    # RFC 9562 UUIDv8: retain 122 digest bits while fixing the version and
    # variant nibbles. Formatting from hex avoids Guid byte-order ambiguity.
    $uuidHex = (
        $digest.Substring(0, 12) +
        '8' +
        $digest.Substring(13, 3) +
        '8' +
        $digest.Substring(17, 15)
    )
    return '{0}-{1}-{2}-{3}-{4}' -f `
        $uuidHex.Substring(0, 8),
        $uuidHex.Substring(8, 4),
        $uuidHex.Substring(12, 4),
        $uuidHex.Substring(16, 4),
        $uuidHex.Substring(20, 12)
}

Assert-ExactProperties $evidence @(
    'schema',
    'status',
    'sanitized',
    'repository',
    'bridgeTag',
    'bridgeReleaseId',
    'bridgeSourceCommit',
    'windowStartedAtUtc',
    'windowCompletedAtUtc',
    'inventorySnapshotId',
    'inventorySnapshotSha256',
    'inventoryProjectionSha256',
    'eligibleWorkerCount',
    'observedWorkerCount',
    'legacyLatestOnlyWorkerCount',
    'nodes'
) '$'

if (
    $evidence.schema -cne 'hch.worker-fleet-transition/v1' -or
    $evidence.status -cne 'passed' -or
    $evidence.sanitized -isnot [bool] -or
    -not $evidence.sanitized -or
    $evidence.repository -cne $ExpectedRepository -or
    $evidence.bridgeTag -cne $ExpectedBridgeTag -or
    [string]$jsonBridgeReleaseId -cne $ExpectedBridgeReleaseId -or
    $evidence.bridgeSourceCommit -cne $ExpectedBridgeSourceCommit
) {
    throw 'Fleet evidence does not bind the expected bridge.'
}

$declaredWindowStart = Convert-CanonicalUtc $evidence.windowStartedAtUtc '$.windowStartedAtUtc'
$declaredWindowEnd = Convert-CanonicalUtc $evidence.windowCompletedAtUtc '$.windowCompletedAtUtc'
$inventorySnapshotSha256 = Assert-Sha256 $evidence.inventorySnapshotSha256 '$.inventorySnapshotSha256'
$inventorySnapshotId = Assert-CanonicalUuid $evidence.inventorySnapshotId '$.inventorySnapshotId'
if ($inventorySnapshotId -cne (Get-DerivedInventorySnapshotId $inventorySnapshotSha256)) {
    throw 'inventorySnapshotId must be the UUIDv8 derived from inventorySnapshotSha256.'
}
$inventoryProjectionSha256 = Assert-Sha256 $evidence.inventoryProjectionSha256 '$.inventoryProjectionSha256'

if ($evidence.nodes -isnot [Object[]] -or $evidence.nodes.Count -lt 3) {
    throw 'nodes must be a non-empty JSON array covering all platforms.'
}

$nodeIds = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
$inventoryMemberIndexes = [Collections.Generic.HashSet[long]]::new()
$requestIds = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
$heartbeatReceipts = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
$membershipReceipts = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
$platforms = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
$nodeWindowStarts = [Collections.Generic.List[DateTimeOffset]]::new()
$nodeWindowEnds = [Collections.Generic.List[DateTimeOffset]]::new()
$inventoryMembers = [Collections.Generic.List[string]]::new()
$now = [DateTimeOffset]::UtcNow
$nodeOrdinal = 0

foreach ($node in $evidence.nodes) {
    Assert-ExactProperties $node @(
        'inventoryMemberIndex',
        'nodeIdHash',
        'inventoryMembershipReceiptSha256',
        'platform',
        'version',
        'releaseDiscoveryProtocol',
        'heartbeatSamples'
    ) '$.nodes[]'

    $inventoryMemberIndex = $jsonInventoryMemberIndexes[$nodeOrdinal]
    if ([long]$node.inventoryMemberIndex -ne $inventoryMemberIndex) {
        throw 'inventoryMemberIndex must be an exact JSON integer.'
    }
    if (-not $inventoryMemberIndexes.Add($inventoryMemberIndex)) {
        throw 'Duplicate inventoryMemberIndex.'
    }
    $nodeIdHash = Assert-Sha256 $node.nodeIdHash 'nodeIdHash'
    $nodeIdCanonical = @(
        'schema=hch.worker-fleet-node-pseudonym/v1',
        "inventorySnapshotId=$inventorySnapshotId",
        "inventorySnapshotSha256=$inventorySnapshotSha256",
        "inventoryMemberIndex=$inventoryMemberIndex"
    ) -join "`n"
    $nodeIdCanonical += "`n"
    if ($nodeIdHash -cne (Get-Sha256 $nodeIdCanonical)) {
        throw 'nodeIdHash must be derived from the inventory snapshot and member index.'
    }
    if (-not $nodeIds.Add($nodeIdHash)) {
        throw 'Duplicate nodeIdHash.'
    }
    if ($node.platform -notin @('windows', 'linux', 'macos')) {
        throw 'Invalid platform.'
    }
    [void]$platforms.Add($node.platform)
    if (
        $node.version -cne '3.1.1' -or
        $node.releaseDiscoveryProtocol -cne 'platform-release-list/v1'
    ) {
        throw 'Node did not prove bridge discovery.'
    }

    $membershipReceipt = Assert-Sha256 `
        $node.inventoryMembershipReceiptSha256 `
        'inventoryMembershipReceiptSha256'
    if (-not $membershipReceipts.Add($membershipReceipt)) {
        throw 'Duplicate inventoryMembershipReceiptSha256.'
    }
    $membershipCanonical = @(
        'schema=hch.worker-fleet-inventory-membership/v1',
        "inventorySnapshotId=$inventorySnapshotId",
        "inventorySnapshotSha256=$inventorySnapshotSha256",
        "inventoryMemberIndex=$inventoryMemberIndex",
        "nodeIdHash=$nodeIdHash",
        "platform=$($node.platform)"
    ) -join "`n"
    $membershipCanonical += "`n"
    if ($membershipReceipt -cne (Get-Sha256 $membershipCanonical)) {
        throw 'Inventory membership receipt digest mismatch.'
    }
    [void]$inventoryMembers.Add(
        "$inventoryMemberIndex|$nodeIdHash|$($node.platform)|$membershipReceipt"
    )

    if ($node.heartbeatSamples -isnot [Object[]] -or $node.heartbeatSamples.Count -lt 2) {
        throw 'Each node must contain an ordered heartbeatSamples JSON array with at least two samples.'
    }

    $previousHeartbeat = [DateTimeOffset]::MinValue
    $firstHeartbeat = [DateTimeOffset]::MinValue
    $lastHeartbeat = [DateTimeOffset]::MinValue
    $sampleIndex = 0

    foreach ($heartbeat in $node.heartbeatSamples) {
        Assert-ExactProperties $heartbeat @(
            'requestId',
            'serverTime',
            'receiptSha256'
        ) '$.nodes[].heartbeatSamples[]'

        $requestId = Assert-CanonicalUuid $heartbeat.requestId 'heartbeatSamples[].requestId'
        if (-not $requestIds.Add($requestId)) {
            throw 'Duplicate heartbeat requestId.'
        }
        $receipt = Assert-Sha256 $heartbeat.receiptSha256 'heartbeatSamples[].receiptSha256'
        if (-not $heartbeatReceipts.Add($receipt)) {
            throw 'Duplicate heartbeat receiptSha256.'
        }
        $serverTime = Convert-CanonicalUtc $heartbeat.serverTime 'heartbeatSamples[].serverTime'
        if ($serverTime -gt $now.AddMinutes(5)) {
            throw 'Heartbeat sample is future-dated.'
        }

        if ($sampleIndex -eq 0) {
            $firstHeartbeat = $serverTime
        }
        else {
            if ($serverTime -le $previousHeartbeat) {
                throw 'Heartbeat samples must be strictly ordered and unique by serverTime.'
            }
            if (($serverTime - $previousHeartbeat).TotalSeconds -gt $maximumHeartbeatGapSeconds) {
                throw "Heartbeat samples contain a stale gap greater than $maximumHeartbeatGapSeconds seconds."
            }
        }

        $heartbeatCanonical = @(
            'schema=hch.worker-fleet-receipt/v1',
            'kind=accepted-bridge-heartbeat',
            "nodeIdHash=$nodeIdHash",
            "platform=$($node.platform)",
            "version=$($node.version)",
            "releaseDiscoveryProtocol=$($node.releaseDiscoveryProtocol)",
            "heartbeatRequestId=$requestId",
            "heartbeatServerTime=$($serverTime.ToUnixTimeMilliseconds())"
        ) -join "`n"
        $heartbeatCanonical += "`n"
        if ($receipt -cne (Get-Sha256 $heartbeatCanonical)) {
            throw 'Heartbeat receipt digest mismatch.'
        }

        $previousHeartbeat = $serverTime
        $lastHeartbeat = $serverTime
        $sampleIndex++
    }

    if (($lastHeartbeat - $firstHeartbeat) -lt [TimeSpan]::FromDays(7)) {
        throw 'Every node must prove a sustained heartbeat window of at least seven days.'
    }
    [void]$nodeWindowStarts.Add($firstHeartbeat)
    [void]$nodeWindowEnds.Add($lastHeartbeat)
    $nodeOrdinal++
}

for ($expectedMemberIndex = 0; $expectedMemberIndex -lt $evidence.nodes.Count; $expectedMemberIndex++) {
    if (-not $inventoryMemberIndexes.Contains([long]$expectedMemberIndex)) {
        throw 'inventoryMemberIndex values must exactly cover the zero-based inventory projection.'
    }
}

foreach ($platform in @('windows', 'linux', 'macos')) {
    if (-not $platforms.Contains($platform)) {
        throw "Missing platform coverage: $platform"
    }
}

if (
    $jsonEligibleWorkerCount -ne $evidence.nodes.Count -or
    $jsonObservedWorkerCount -ne $evidence.nodes.Count -or
    $jsonLegacyLatestOnlyWorkerCount -ne 0
) {
    throw 'Fleet counts must be derived, equal and contain no latest-only worker.'
}

$sortedInventoryMembers = [string[]]$inventoryMembers.ToArray()
[Array]::Sort($sortedInventoryMembers, [StringComparer]::Ordinal)
$inventoryProjectionCanonical = @(
    'schema=hch.worker-fleet-inventory-projection/v1',
    "inventorySnapshotId=$inventorySnapshotId",
    "inventorySnapshotSha256=$inventorySnapshotSha256"
) -join "`n"
$inventoryProjectionCanonical += "`n"
foreach ($member in $sortedInventoryMembers) {
    $inventoryProjectionCanonical += "member=$member`n"
}
if ($inventoryProjectionSha256 -cne (Get-Sha256 $inventoryProjectionCanonical)) {
    throw 'Inventory projection digest mismatch.'
}

# The common sustained window is the intersection of all per-node windows:
# the latest first heartbeat through the earliest last heartbeat. Using a
# union would let a late or intermittently observed node inherit another
# node's seven-day history.
$derivedWindowStart = $nodeWindowStarts[0]
foreach ($nodeStart in $nodeWindowStarts) {
    if ($nodeStart -gt $derivedWindowStart) {
        $derivedWindowStart = $nodeStart
    }
}
$derivedWindowEnd = $nodeWindowEnds[0]
foreach ($nodeEnd in $nodeWindowEnds) {
    if ($nodeEnd -lt $derivedWindowEnd) {
        $derivedWindowEnd = $nodeEnd
    }
}
if (($derivedWindowEnd - $derivedWindowStart) -lt [TimeSpan]::FromDays(7)) {
    throw 'The derived common fleet window must be sustained for at least seven days.'
}
if (
    $declaredWindowStart -ne $derivedWindowStart -or
    $declaredWindowEnd -ne $derivedWindowEnd
) {
    throw 'Declared fleet window must exactly equal the window derived from per-node heartbeats.'
}
if ($derivedWindowEnd -gt $now.AddMinutes(5) -or $derivedWindowEnd -lt $now.AddDays(-7)) {
    throw 'Fleet evidence is future-dated or older than seven days.'
}

$cms = [Security.Cryptography.Pkcs.SignedCms]::new(
    [Security.Cryptography.Pkcs.ContentInfo]::new($bytes),
    $true
)
try {
    $cms.Decode($signatureBytes)
    $cms.CheckSignature($true)
}
catch {
    throw "Detached CMS does not authenticate exact evidence bytes: $($_.Exception.Message)"
}
if ($cms.SignerInfos.Count -ne 1) {
    throw 'Fleet evidence must have exactly one CMS signer.'
}

$signerInfo = $cms.SignerInfos[0]
$certificate = $signerInfo.Certificate
if ($null -eq $certificate) {
    throw 'CMS signer certificate is missing.'
}
if (
    $certificate.Thumbprint.Replace(' ', '').ToUpperInvariant() -cne $ExpectedTelemetryAuthorityThumbprint.ToUpperInvariant() -or
    [Convert]::ToHexString($certificate.GetCertHash([Security.Cryptography.HashAlgorithmName]::SHA256)) -cne $ExpectedTelemetryAuthorityCertificateSha256.ToUpperInvariant()
) {
    throw 'Telemetry authority does not match both pins.'
}
if ($signerInfo.DigestAlgorithm.Value -notin @(
    '2.16.840.1.101.3.4.2.1',
    '2.16.840.1.101.3.4.2.2',
    '2.16.840.1.101.3.4.2.3'
)) {
    throw 'CMS digest must be SHA-256 or stronger.'
}

# This validator can authenticate only the telemetry pins supplied to it. The
# promotion workflow must compare those pins with the canary/artifact signer
# pins and fail when an authority is reused.
$ekuExtensions = @($certificate.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.37' })
if ($ekuExtensions.Count -ne 1) {
    throw 'Exactly one EKU extension is required.'
}
$eku = if ($ekuExtensions[0] -is [Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]) {
    $ekuExtensions[0]
}
else {
    [Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]::new(
        $ekuExtensions[0],
        $ekuExtensions[0].Critical
    )
}
if (
    $eku.EnhancedKeyUsages.Count -ne 1 -or
    $eku.EnhancedKeyUsages[0].Value -cne '1.3.6.1.5.5.7.3.3'
) {
    throw 'Telemetry authority must be code-signing-only.'
}

$keyUsageExtensions = @($certificate.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.15' })
if ($keyUsageExtensions.Count -gt 1) {
    throw 'Telemetry authority has multiple Key Usage extensions.'
}
if ($keyUsageExtensions.Count -eq 1) {
    $keyUsage = if ($keyUsageExtensions[0] -is [Security.Cryptography.X509Certificates.X509KeyUsageExtension]) {
        $keyUsageExtensions[0]
    }
    else {
        [Security.Cryptography.X509Certificates.X509KeyUsageExtension]::new(
            $keyUsageExtensions[0],
            $keyUsageExtensions[0].Critical
        )
    }
    if (
        ($keyUsage.KeyUsages -band [Security.Cryptography.X509Certificates.X509KeyUsageFlags]::DigitalSignature) -eq 0
    ) {
        throw 'Telemetry authority Key Usage does not allow digital signatures.'
    }
}

$signingTimeAttributes = @(
    $signerInfo.SignedAttributes |
        Where-Object { $_.Oid.Value -eq '1.2.840.113549.1.9.5' }
)
if (
    $signingTimeAttributes.Count -ne 1 -or
    $signingTimeAttributes[0].Values.Count -ne 1
) {
    throw 'CMS must have exactly one signingTime.'
}
$signingTime = [DateTimeOffset](
    [Security.Cryptography.Pkcs.Pkcs9SigningTime]::new(
        $signingTimeAttributes[0].Values[0].RawData
    ).SigningTime.ToUniversalTime()
)
if (
    $signingTime -le $derivedWindowEnd -or
    $signingTime -gt $derivedWindowEnd.AddHours(24) -or
    $signingTime -gt $now.AddMinutes(5) -or
    $signingTime -lt $now.AddDays(-7)
) {
    throw 'CMS signingTime violates ordering or freshness.'
}
if (
    $signingTime -lt ([DateTimeOffset]$certificate.NotBefore.ToUniversalTime()) -or
    $signingTime -gt ([DateTimeOffset]$certificate.NotAfter.ToUniversalTime())
) {
    throw 'Certificate was not valid at signingTime.'
}

$heartbeatCount = 0
foreach ($node in $evidence.nodes) {
    $heartbeatCount += $node.heartbeatSamples.Count
}
Write-Host (
    'Fleet transition evidence passed for {0} derived workers across Windows, Linux and macOS; {1} accepted heartbeats; common sustained window {2:N2} days.' -f `
        $evidence.nodes.Count,
        $heartbeatCount,
        ($derivedWindowEnd - $derivedWindowStart).TotalDays
)
