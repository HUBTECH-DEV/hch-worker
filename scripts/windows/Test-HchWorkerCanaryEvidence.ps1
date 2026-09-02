[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$EvidencePath,

    [Parameter(Mandatory)]
    [string]$EvidenceSignaturePath,

    [Parameter(Mandatory)]
    [ValidatePattern('^[0-9A-Fa-f]{40}$')]
    [string]$ExpectedAttesterThumbprint,

    [Parameter(Mandatory)]
    [ValidatePattern('^[0-9A-Fa-f]{64}$')]
    [string]$ExpectedAttesterCertificateSha256,

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

$minimumSustainedDuration = [TimeSpan]::FromMinutes(15)
$maximumValidationDuration = [TimeSpan]::FromHours(24)
$minimumHeartbeatCount = 10
$maximumHeartbeatGapSeconds = 120
$maximumClockSkew = [TimeSpan]::FromMinutes(5)
$maximumHeartbeatServerSkew = [TimeSpan]::FromSeconds(5)
$maximumPromotionEvidenceAge = [TimeSpan]::FromDays(7)
$codeSigningEkuOid = '1.3.6.1.5.5.7.3.3'
$signingTimeOid = '1.2.840.113549.1.9.5'
$sha256DigestOids = @(
    '2.16.840.1.101.3.4.2.1',
    '2.16.840.1.101.3.4.2.2',
    '2.16.840.1.101.3.4.2.3'
)
$assignmentLivenessStates = @('starting', 'responding', 'finalizing')
$assignmentWorkSizingReasons = @(
    'minimum-unit-window-ignored',
    'within-window',
    'near-window-downshift',
    'already-downshifted'
)

function Get-RequiredProperty {
    param(
        [Parameter(Mandatory)][object]$Value,
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$Path
    )

    $property = $Value.PSObject.Properties[$Name]
    if ($null -eq $property) {
        throw "Canary evidence is missing required property $Path.$Name."
    }
    return $property.Value
}

function Assert-JsonArrayProperty {
    param(
        [Parameter(Mandatory)][Text.Json.JsonElement]$Root,
        [Parameter(Mandatory)][string]$Name
    )

    try {
        $element = $Root.GetProperty($Name)
    } catch {
        throw "Canary evidence is missing required array $Name."
    }
    if ($element.ValueKind -ne [Text.Json.JsonValueKind]::Array) {
        throw "Canary evidence property $Name must be a JSON array."
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
                throw "Canary evidence contains duplicate JSON property $Path.$($property.Name)."
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

function ConvertTo-UtcTimestamp {
    param(
        [Parameter(Mandatory)][object]$Value,
        [Parameter(Mandatory)][string]$Path
    )

    if ($Value -is [DateTime]) {
        return [DateTimeOffset]$Value.ToUniversalTime()
    }
    if ($Value -is [DateTimeOffset]) {
        return $Value.ToUniversalTime()
    }
    if ($Value -isnot [string] -or $Value -notmatch '(?:Z|\+00:00)$') {
        throw "Canary timestamp $Path must be an ISO-8601 UTC string."
    }
    $parsed = [DateTimeOffset]::MinValue
    if (-not [DateTimeOffset]::TryParse(
            $Value,
            [Globalization.CultureInfo]::InvariantCulture,
            [Globalization.DateTimeStyles]::RoundtripKind,
            [ref]$parsed) -or $parsed.Offset -ne [TimeSpan]::Zero) {
        throw "Canary timestamp $Path is invalid."
    }
    return $parsed.ToUniversalTime()
}

function Assert-TimestampInSession {
    param(
        [Parameter(Mandatory)][DateTimeOffset]$Value,
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][DateTimeOffset]$StartedAt,
        [Parameter(Mandatory)][DateTimeOffset]$CompletedAt
    )

    if ($Value -lt $StartedAt -or $Value -gt $CompletedAt) {
        throw "Canary timestamp $Path is outside the bounded validation session."
    }
}

function Assert-Identifier {
    param(
        [Parameter(Mandatory)][object]$Value,
        [Parameter(Mandatory)][string]$Path
    )

    if ($Value -isnot [string] -or $Value -notmatch '^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$') {
        throw "Canary identifier $Path is invalid."
    }
}

function Assert-CanonicalUuid {
    param(
        [Parameter(Mandatory)][object]$Value,
        [Parameter(Mandatory)][string]$Path
    )

    $parsed = [Guid]::Empty
    if ($Value -isnot [string] -or -not [Guid]::TryParseExact($Value, 'D', [ref]$parsed) `
        -or $parsed -eq [Guid]::Empty) {
        throw "Canary UUID $Path must be a non-empty canonical D-format UUID."
    }
}

function Assert-Sha256 {
    param(
        [Parameter(Mandatory)][object]$Value,
        [Parameter(Mandatory)][string]$Path
    )

    if ($Value -isnot [string] -or $Value -cnotmatch '^[0-9a-f]{64}$') {
        throw "Canary SHA-256 $Path is invalid."
    }
}

function Get-ExactInteger {
    param(
        [Parameter(Mandatory)][object]$Value,
        [Parameter(Mandatory)][string]$Path
    )

    if ($Value -isnot [byte] -and $Value -isnot [int16] -and $Value -isnot [int32] -and $Value -isnot [int64]) {
        throw "Canary integer $Path must be encoded as a JSON integer."
    }
    return [int64]$Value
}

function Get-ExactBoolean {
    param(
        [Parameter(Mandatory)][object]$Value,
        [Parameter(Mandatory)][string]$Path
    )

    if ($Value -isnot [bool]) {
        throw "Canary boolean $Path must be encoded as a JSON boolean."
    }
    return [bool]$Value
}

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

    $gates = Get-RequiredProperty $evidence 'gates' '$'
    $value = Get-RequiredProperty $gates $Name '$.gates'
    if (-not (Get-ExactBoolean $value "$.gates.$Name")) {
        throw "Canary gate is not proven: $Name"
    }
}

function Add-UniqueValue {
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][Collections.Generic.HashSet[string]]$Set,
        [Parameter(Mandatory)][string]$Value,
        [Parameter(Mandatory)][string]$Path
    )

    if (-not $Set.Add($Value)) {
        throw "Canary evidence repeats a value that must be unique: $Path."
    }
}

function Assert-ExactPropertyNames {
    param(
        [Parameter(Mandatory)][object]$Value,
        [Parameter(Mandatory)][string[]]$Names,
        [Parameter(Mandatory)][string]$Path
    )

    $properties = @($Value.PSObject.Properties)
    if ($properties.Count -ne $Names.Count) {
        throw "Canary receipt $Path must contain exactly: $($Names -join ', ')."
    }
    $actual = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($property in $properties) {
        [void]$actual.Add($property.Name)
    }
    foreach ($name in $Names) {
        if (-not $actual.Contains($name)) {
            throw "Canary receipt $Path is missing exact property $name."
        }
    }
}

function Assert-SafeReceiptToken {
    param(
        [Parameter(Mandatory)][object]$Value,
        [Parameter(Mandatory)][string]$Path
    )

    if ($Value -isnot [string] -or $Value -notmatch '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$') {
        throw "Canary receipt token $Path is invalid."
    }
}

function Get-CanonicalTimestampValue {
    param([Parameter(Mandatory)][DateTimeOffset]$Value)

    return $Value.ToUnixTimeMilliseconds().ToString([Globalization.CultureInfo]::InvariantCulture)
}

function Get-CanonicalBooleanValue {
    param([Parameter(Mandatory)][bool]$Value)

    if ($Value) { return 'true' }
    return 'false'
}

function Assert-ReceiptSha256 {
    param(
        [Parameter(Mandatory)][object]$Value,
        [Parameter(Mandatory)][string]$Kind,
        [Parameter(Mandatory)][string[]]$Fields,
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][AllowEmptyCollection()][Collections.Generic.HashSet[string]]$ReceiptHashes
    )

    Assert-Sha256 $Value $Path
    $canonical = [string]::Join("`n", @('schema=hch.worker-canary-receipt/v1', "kind=$Kind") + $Fields) + "`n"
    $hasher = [Security.Cryptography.SHA256]::Create()
    try {
        $actual = [Convert]::ToHexString(
            $hasher.ComputeHash([Text.UTF8Encoding]::new($false).GetBytes($canonical))).ToLowerInvariant()
    } finally {
        $hasher.Dispose()
    }
    if ($Value -cne $actual) {
        throw "Canary receipt digest does not match its canonical sanitized fields: $Path."
    }
    Add-UniqueValue $ReceiptHashes $Value $Path
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
        if ($stream.Length -lt 4096) { throw 'MsiPath is too small to be a Windows Installer database.' }
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

$resolvedEvidence = (Resolve-Path -LiteralPath $EvidencePath).Path
$resolvedSignature = (Resolve-Path -LiteralPath $EvidenceSignaturePath).Path
$resolvedMsi = (Resolve-Path -LiteralPath $MsiPath).Path
$evidenceBytes = [IO.File]::ReadAllBytes($resolvedEvidence)
$signatureBytes = [IO.File]::ReadAllBytes($resolvedSignature)
if ($evidenceBytes.Length -eq 0 -or $signatureBytes.Length -eq 0) {
    throw 'Canary evidence and detached CMS signature must both be non-empty.'
}

$strictUtf8 = [Text.UTF8Encoding]::new($false, $true)
$raw = $strictUtf8.GetString($evidenceBytes)
if ($raw.Length -eq 0 -or $raw[0] -eq [char]0xFEFF) {
    throw 'Canary evidence must be UTF-8 without BOM.'
}
if ($raw -match '(?i)-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----|Authorization\s*:|Bearer\s+[A-Za-z0-9._~-]+') {
    throw 'Canary evidence contains secret-shaped material.'
}

$jsonDocument = [Text.Json.JsonDocument]::Parse($raw)
try {
    if ($jsonDocument.RootElement.ValueKind -ne [Text.Json.JsonValueKind]::Object) {
        throw 'Canary evidence root must be a JSON object.'
    }
    Assert-NoDuplicateJsonPropertyNames $jsonDocument.RootElement '$'
    foreach ($arrayName in 'heartbeatSamples', 'progressSamples', 'completions', 'failures') {
        Assert-JsonArrayProperty $jsonDocument.RootElement $arrayName
    }
} finally {
    $jsonDocument.Dispose()
}
$evidence = $raw | ConvertFrom-Json -Depth 100
Assert-NoSensitivePropertyNames $evidence
foreach ($legacyAggregate in 'heartbeats', 'capacity', 'progress', 'completion', 'failure', 'rollback') {
    if ($null -ne $evidence.PSObject.Properties[$legacyAggregate]) {
        throw "Canary schema v2 forbids legacy self-declared aggregate: $legacyAggregate."
    }
}

# Verify the detached CMS over the exact evidence bytes before trusting any gate.
$contentInfo = [Security.Cryptography.Pkcs.ContentInfo]::new($evidenceBytes)
$signedCms = [Security.Cryptography.Pkcs.SignedCms]::new($contentInfo, $true)
try {
    $signedCms.Decode($signatureBytes)
    if ($signedCms.SignerInfos.Count -ne 1) {
        throw 'Canary evidence must have exactly one CMS attester.'
    }
    $signedCms.CheckSignature($true)
} catch {
    throw "Detached CMS signature does not authenticate the exact canary evidence bytes: $($_.Exception.Message)"
}

$signerInfo = $signedCms.SignerInfos[0]
$attesterCertificate = $signerInfo.Certificate
if ($null -eq $attesterCertificate) {
    throw 'Detached CMS signature does not contain the attester certificate.'
}
$expectedThumbprint = $ExpectedAttesterThumbprint.ToUpperInvariant()
$actualThumbprint = $attesterCertificate.Thumbprint.Replace(' ', '').ToUpperInvariant()
$expectedCertificateSha256 = $ExpectedAttesterCertificateSha256.ToUpperInvariant()
$actualCertificateSha256 = [Convert]::ToHexString(
    $attesterCertificate.GetCertHash([Security.Cryptography.HashAlgorithmName]::SHA256))
if ($actualThumbprint -cne $expectedThumbprint -or $actualCertificateSha256 -cne $expectedCertificateSha256) {
    throw 'Canary evidence attester certificate does not match both protected certificate pins.'
}
if ($sha256DigestOids -cnotcontains $signerInfo.DigestAlgorithm.Value) {
    throw 'Canary evidence CMS must use SHA-256 or stronger digest.'
}

$ekuExtension = @($attesterCertificate.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.37' })
if ($ekuExtension.Count -ne 1) {
    throw 'Canary attester certificate must contain exactly one EKU extension.'
}
if ($ekuExtension[0] -is [Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]) {
    $decodedEku = $ekuExtension[0]
} else {
    $decodedEku = [Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]::new(
        $ekuExtension[0],
        $ekuExtension[0].Critical)
}
if ($decodedEku.EnhancedKeyUsages.Count -ne 1 `
    -or $decodedEku.EnhancedKeyUsages[0].Value -cne $codeSigningEkuOid) {
    throw 'Canary attester certificate is not constrained to code-signing use.'
}
$keyUsageExtensions = @($attesterCertificate.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.15' })
if ($keyUsageExtensions.Count -gt 1) {
    throw 'Canary attester certificate has ambiguous key-usage extensions.'
}
if ($keyUsageExtensions.Count -eq 1) {
    if ($keyUsageExtensions[0] -is [Security.Cryptography.X509Certificates.X509KeyUsageExtension]) {
        $decodedKeyUsage = $keyUsageExtensions[0]
    } else {
        $decodedKeyUsage = [Security.Cryptography.X509Certificates.X509KeyUsageExtension]::new(
            $keyUsageExtensions[0],
            $keyUsageExtensions[0].Critical)
    }
    if (($decodedKeyUsage.KeyUsages -band `
        [Security.Cryptography.X509Certificates.X509KeyUsageFlags]::DigitalSignature) -eq 0) {
        throw 'Canary attester certificate key usage does not allow digital signatures.'
    }
}

$signingTimeAttributes = @($signerInfo.SignedAttributes | Where-Object { $_.Oid.Value -eq $signingTimeOid })
if ($signingTimeAttributes.Count -ne 1 -or $signingTimeAttributes[0].Values.Count -ne 1) {
    throw 'Canary evidence CMS must contain exactly one signed signingTime attribute.'
}
$pkcs9SigningTime = [Security.Cryptography.Pkcs.Pkcs9SigningTime]::new(
    $signingTimeAttributes[0].Values[0].RawData)
$signingTime = [DateTimeOffset]$pkcs9SigningTime.SigningTime.ToUniversalTime()

$msiSha256 = (Get-FileHash -LiteralPath $resolvedMsi -Algorithm SHA256).Hash.ToLowerInvariant()
$msiIdentity = Get-MsiIdentity $resolvedMsi
$msiLifecyclePath = Join-Path (Split-Path -Parent $resolvedMsi) 'msi-disposable-e2e.json'
if (-not (Test-Path -LiteralPath $msiLifecyclePath -PathType Leaf) `
    -or ((Get-Item -LiteralPath $msiLifecyclePath -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
    throw 'The exact candidate is missing non-reparse disposable MSI lifecycle evidence.'
}
$msiLifecycleBytes = [IO.File]::ReadAllBytes($msiLifecyclePath)
$msiLifecycleRaw = $strictUtf8.GetString($msiLifecycleBytes)
if ($msiLifecycleRaw.Length -eq 0 -or $msiLifecycleRaw[0] -eq [char]0xFEFF) {
    throw 'Disposable MSI lifecycle evidence must be UTF-8 without BOM.'
}
$msiLifecycleDocument = [Text.Json.JsonDocument]::Parse($msiLifecycleRaw)
try {
    if ($msiLifecycleDocument.RootElement.ValueKind -ne [Text.Json.JsonValueKind]::Object) {
        throw 'Disposable MSI lifecycle evidence root must be a JSON object.'
    }
    Assert-NoDuplicateJsonPropertyNames $msiLifecycleDocument.RootElement '$.msiLifecycle'
} finally {
    $msiLifecycleDocument.Dispose()
}
$msiLifecycle = $msiLifecycleRaw | ConvertFrom-Json -Depth 50
Assert-NoSensitivePropertyNames $msiLifecycle '$.msiLifecycle'
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
    'completedAtUtc') '$.msiLifecycle'
if ((Get-RequiredProperty $msiLifecycle 'schema' '$.msiLifecycle') -cne 'hch.worker-windows-msi-e2e/v1' `
    -or (Get-RequiredProperty $msiLifecycle 'status' '$.msiLifecycle') -cne 'passed' `
    -or (Get-RequiredProperty $msiLifecycle 'version' '$.msiLifecycle') -cne $Version `
    -or (Get-RequiredProperty $msiLifecycle 'productCode' '$.msiLifecycle') -cne $msiIdentity.ProductCode `
    -or (Get-RequiredProperty $msiLifecycle 'packageCode' '$.msiLifecycle') -cne $msiIdentity.PackageCode `
    -or (Get-RequiredProperty $msiLifecycle 'msiSha256' '$.msiLifecycle') -cne $msiSha256 `
    -or (Get-ExactInteger (Get-RequiredProperty $msiLifecycle 'msiLengthBytes' '$.msiLifecycle') '$.msiLifecycle.msiLengthBytes') -ne (Get-Item -LiteralPath $resolvedMsi).Length `
    -or (Get-ExactInteger (Get-RequiredProperty $msiLifecycle 'rollbackExitCode' '$.msiLifecycle') '$.msiLifecycle.rollbackExitCode') -ne 1603 `
    -or -not (Get-ExactBoolean (Get-RequiredProperty $msiLifecycle 'repairPreservedState' '$.msiLifecycle') '$.msiLifecycle.repairPreservedState') `
    -or -not (Get-ExactBoolean (Get-RequiredProperty $msiLifecycle 'uninstallPreservedState' '$.msiLifecycle') '$.msiLifecycle.uninstallPreservedState')) {
    throw 'Disposable MSI lifecycle evidence does not match the exact candidate.'
}
$msiLifecycleSha256 = [Convert]::ToHexString(
    [Security.Cryptography.SHA256]::HashData($msiLifecycleBytes)).ToLowerInvariant()
$lifecyclePayloads = Get-RequiredProperty $msiLifecycle 'extractedPayloads' '$.msiLifecycle'
Assert-ExactPropertyNames $lifecyclePayloads @('service', 'tray', 'installer') '$.msiLifecycle.extractedPayloads'
foreach ($payloadName in 'service', 'tray', 'installer') {
    $payload = Get-RequiredProperty $lifecyclePayloads $payloadName '$.msiLifecycle.extractedPayloads'
    Assert-ExactPropertyNames $payload @('relativePath', 'sha256', 'sizeBytes') "$.msiLifecycle.extractedPayloads.$payloadName"
    Assert-Sha256 (Get-RequiredProperty $payload 'sha256' "$.msiLifecycle.extractedPayloads.$payloadName") `
        "$.msiLifecycle.extractedPayloads.$payloadName.sha256"
}
$lifecycleInstalledService = Get-RequiredProperty $msiLifecycle 'installedService' '$.msiLifecycle'
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
    'observedAtUtc') '$.msiLifecycle.installedService'
$lifecycleServiceSha256 = Get-RequiredProperty $lifecyclePayloads.service 'sha256' '$.msiLifecycle.extractedPayloads.service'
$lifecycleTraySha256 = Get-RequiredProperty $lifecyclePayloads.tray 'sha256' '$.msiLifecycle.extractedPayloads.tray'
if ((Get-RequiredProperty $lifecycleInstalledService 'serviceName' '$.msiLifecycle.installedService') -cne 'HchWorker' `
    -or (Get-RequiredProperty $lifecycleInstalledService 'scmState' '$.msiLifecycle.installedService') -cne 'Running' `
    -or (Get-RequiredProperty $lifecycleInstalledService 'serviceExecutableSha256' '$.msiLifecycle.installedService') -cne $lifecycleServiceSha256 `
    -or (Get-RequiredProperty $lifecycleInstalledService 'trayExecutableSha256' '$.msiLifecycle.installedService') -cne $lifecycleTraySha256) {
    throw 'Disposable MSI lifecycle payload correlation is invalid.'
}
Assert-ExactPropertyNames $evidence @(
    'schema',
    'status',
    'sanitized',
    'version',
    'sourceCommit',
    'msiSha256',
    'installationReceipt',
    'startedAtUtc',
    'completedAtUtc',
    'gates',
    'heartbeatSamples',
    'progressSamples',
    'completions',
    'failures',
    'rollbackReceipt') '$'
if ((Get-RequiredProperty $evidence 'schema' '$') -cne 'hch.worker-windows-canary/v2' `
    -or (Get-RequiredProperty $evidence 'status' '$') -cne 'passed' `
    -or -not (Get-ExactBoolean (Get-RequiredProperty $evidence 'sanitized' '$') '$.sanitized') `
    -or (Get-RequiredProperty $evidence 'version' '$') -cne $Version `
    -or (Get-RequiredProperty $evidence 'sourceCommit' '$') -cne $SourceCommit `
    -or (Get-RequiredProperty $evidence 'msiSha256' '$') -cne $msiSha256) {
    throw 'Canary evidence does not bind the exact signed candidate.'
}
$gates = Get-RequiredProperty $evidence 'gates' '$'
Assert-ExactPropertyNames $gates @(
    'installedPausedDrain',
    'legacyServiceStoppedDisabled',
    'enrollment',
    'bootstrap',
    'claim',
    'restartPausedDrain') '$.gates'

$startedAt = ConvertTo-UtcTimestamp (Get-RequiredProperty $evidence 'startedAtUtc' '$') '$.startedAtUtc'
$completedAt = ConvertTo-UtcTimestamp (Get-RequiredProperty $evidence 'completedAtUtc' '$') '$.completedAtUtc'
$validationNow = [DateTimeOffset]::UtcNow
$duration = $completedAt - $startedAt
if ($completedAt -le $startedAt -or $duration -gt $maximumValidationDuration) {
    throw 'Canary timestamps do not describe one bounded validation session.'
}
if ($duration -lt $minimumSustainedDuration) {
    throw 'Canary validation must remain healthy for at least 15 minutes.'
}
if ($signingTime -le $completedAt -or $signingTime -gt $completedAt.AddHours(24)) {
    throw 'Canary evidence signingTime must be after completion and no more than 24 hours later.'
}
if ($completedAt -gt $validationNow.Add($maximumClockSkew) `
    -or $signingTime -gt $validationNow.Add($maximumClockSkew)) {
    throw 'Canary evidence or signingTime is beyond the permitted five-minute UTC clock skew.'
}
if ($completedAt -lt $validationNow.Subtract($maximumPromotionEvidenceAge) `
    -or $signingTime -lt $validationNow.Subtract($maximumPromotionEvidenceAge)) {
    throw 'Canary evidence completion or signingTime is older than the seven-day promotion freshness window.'
}
$certificateNotBefore = [DateTimeOffset]$attesterCertificate.NotBefore.ToUniversalTime()
$certificateNotAfter = [DateTimeOffset]$attesterCertificate.NotAfter.ToUniversalTime()
if ($signingTime -lt $certificateNotBefore -or $signingTime -gt $certificateNotAfter) {
    throw 'Canary attester certificate was not valid at signingTime.'
}

foreach ($gate in @(
    'installedPausedDrain',
    'legacyServiceStoppedDisabled',
    'enrollment',
    'bootstrap',
    'claim',
    'restartPausedDrain')) {
    Assert-TrueGate $gate
}
foreach ($legacyGate in @(
    'heartbeat',
    'progress',
    'completedPendingEditorialReview',
    'failedAssignmentReported',
    'rollbackTo310',
    'rollbackTo311',
    'rollbackHeartbeat')) {
    if ($null -ne $evidence.gates.PSObject.Properties[$legacyGate]) {
        throw "Canary schema v2 forbids legacy self-declared gate: $legacyGate."
    }
}

$requestIds = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
$receiptHashes = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
$assignmentIds = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
$installation = Get-RequiredProperty $evidence 'installationReceipt' '$'
Assert-ExactPropertyNames $installation @(
    'msiLifecycleEvidenceSha256',
    'productCode',
    'packageCode',
    'serviceName',
    'serviceImagePath',
    'serviceExecutableSha256',
    'trayExecutablePath',
    'trayExecutableSha256',
    'installed',
    'restart',
    'receiptSha256') '$.installationReceipt'
$installationLifecycleSha256 = Get-RequiredProperty $installation 'msiLifecycleEvidenceSha256' '$.installationReceipt'
$installationProductCode = Get-RequiredProperty $installation 'productCode' '$.installationReceipt'
$installationPackageCode = Get-RequiredProperty $installation 'packageCode' '$.installationReceipt'
$installationServiceName = Get-RequiredProperty $installation 'serviceName' '$.installationReceipt'
$installationServiceImagePath = Get-RequiredProperty $installation 'serviceImagePath' '$.installationReceipt'
$installationServiceSha256 = Get-RequiredProperty $installation 'serviceExecutableSha256' '$.installationReceipt'
$installationTrayPath = Get-RequiredProperty $installation 'trayExecutablePath' '$.installationReceipt'
$installationTraySha256 = Get-RequiredProperty $installation 'trayExecutableSha256' '$.installationReceipt'
Assert-Sha256 $installationLifecycleSha256 '$.installationReceipt.msiLifecycleEvidenceSha256'
Assert-Sha256 $installationServiceSha256 '$.installationReceipt.serviceExecutableSha256'
Assert-Sha256 $installationTraySha256 '$.installationReceipt.trayExecutableSha256'
if ($installationLifecycleSha256 -cne $msiLifecycleSha256 `
    -or $installationProductCode -cne $msiIdentity.ProductCode `
    -or $installationPackageCode -cne $msiIdentity.PackageCode `
    -or $installationServiceName -cne 'HchWorker' `
    -or $installationServiceSha256 -cne $lifecycleServiceSha256 `
    -or $installationTraySha256 -cne $lifecycleTraySha256 `
    -or $installationServiceImagePath -isnot [string] `
    -or $installationTrayPath -isnot [string] `
    -or -not [string]::Equals(
        $installationServiceImagePath,
        (Get-RequiredProperty $lifecycleInstalledService 'scmImagePath' '$.msiLifecycle.installedService'),
        [StringComparison]::OrdinalIgnoreCase) `
    -or -not [string]::Equals(
        $installationTrayPath,
        (Get-RequiredProperty $lifecycleInstalledService 'trayExecutablePath' '$.msiLifecycle.installedService'),
        [StringComparison]::OrdinalIgnoreCase)) {
    throw 'Canary installation receipt does not bind the MSI lifecycle ProductCode, PackageCode, ImagePath and payload hashes.'
}
$installedTransition = Get-RequiredProperty $installation 'installed' '$.installationReceipt'
$restartTransition = Get-RequiredProperty $installation 'restart' '$.installationReceipt'
foreach ($entry in @(
        [pscustomobject]@{ Value = $installedTransition; Path = '$.installationReceipt.installed' },
        [pscustomobject]@{ Value = $restartTransition; Path = '$.installationReceipt.restart' })) {
    Assert-ExactPropertyNames $entry.Value @(
        'bootStartedAtUtc',
        'processStartedAtUtc',
        'observedAtUtc',
        'processId') $entry.Path
}
$installedBootStartedAt = ConvertTo-UtcTimestamp (
    Get-RequiredProperty $installedTransition 'bootStartedAtUtc' '$.installationReceipt.installed') `
    '$.installationReceipt.installed.bootStartedAtUtc'
$installedProcessStartedAt = ConvertTo-UtcTimestamp (
    Get-RequiredProperty $installedTransition 'processStartedAtUtc' '$.installationReceipt.installed') `
    '$.installationReceipt.installed.processStartedAtUtc'
$installedObservedAt = ConvertTo-UtcTimestamp (
    Get-RequiredProperty $installedTransition 'observedAtUtc' '$.installationReceipt.installed') `
    '$.installationReceipt.installed.observedAtUtc'
$installedProcessId = Get-ExactInteger (
    Get-RequiredProperty $installedTransition 'processId' '$.installationReceipt.installed') `
    '$.installationReceipt.installed.processId'
$restartBootStartedAt = ConvertTo-UtcTimestamp (
    Get-RequiredProperty $restartTransition 'bootStartedAtUtc' '$.installationReceipt.restart') `
    '$.installationReceipt.restart.bootStartedAtUtc'
$restartProcessStartedAt = ConvertTo-UtcTimestamp (
    Get-RequiredProperty $restartTransition 'processStartedAtUtc' '$.installationReceipt.restart') `
    '$.installationReceipt.restart.processStartedAtUtc'
$restartObservedAt = ConvertTo-UtcTimestamp (
    Get-RequiredProperty $restartTransition 'observedAtUtc' '$.installationReceipt.restart') `
    '$.installationReceipt.restart.observedAtUtc'
$restartProcessId = Get-ExactInteger (
    Get-RequiredProperty $restartTransition 'processId' '$.installationReceipt.restart') `
    '$.installationReceipt.restart.processId'
if ($installedProcessId -le 0 -or $restartProcessId -le 0 -or $installedProcessId -eq $restartProcessId `
    -or $installedBootStartedAt -ge $installedProcessStartedAt `
    -or $installedProcessStartedAt -gt $installedObservedAt `
    -or $restartBootStartedAt -le $installedObservedAt `
    -or $restartBootStartedAt -ge $restartProcessStartedAt `
    -or $restartProcessStartedAt -gt $restartObservedAt) {
    throw 'Canary installation receipt does not prove a new boot and a distinct SCM process.'
}
Assert-ReceiptSha256 (
    Get-RequiredProperty $installation 'receiptSha256' '$.installationReceipt') 'install-restart' @(
        "msiSha256=$msiSha256",
        "msiLifecycleEvidenceSha256=$installationLifecycleSha256",
        "productCode=$installationProductCode",
        "packageCode=$installationPackageCode",
        "serviceName=$installationServiceName",
        "serviceImagePath=$installationServiceImagePath",
        "serviceExecutableSha256=$installationServiceSha256",
        "trayExecutablePath=$installationTrayPath",
        "trayExecutableSha256=$installationTraySha256",
        "installed.bootStartedAtUnixMs=$(Get-CanonicalTimestampValue $installedBootStartedAt)",
        "installed.processStartedAtUnixMs=$(Get-CanonicalTimestampValue $installedProcessStartedAt)",
        "installed.observedAtUnixMs=$(Get-CanonicalTimestampValue $installedObservedAt)",
        "installed.processId=$($installedProcessId.ToString([Globalization.CultureInfo]::InvariantCulture))",
        "restart.bootStartedAtUnixMs=$(Get-CanonicalTimestampValue $restartBootStartedAt)",
        "restart.processStartedAtUnixMs=$(Get-CanonicalTimestampValue $restartProcessStartedAt)",
        "restart.observedAtUnixMs=$(Get-CanonicalTimestampValue $restartObservedAt)",
        "restart.processId=$($restartProcessId.ToString([Globalization.CultureInfo]::InvariantCulture))") `
    '$.installationReceipt.receiptSha256' $receiptHashes
$heartbeatSamples = @(Get-RequiredProperty $evidence 'heartbeatSamples' '$')
if ($heartbeatSamples.Count -lt $minimumHeartbeatCount) {
    throw "Canary evidence must contain at least $minimumHeartbeatCount unique heartbeat samples."
}

$canaryNodeId = $null
$firstHeartbeatTime = $null
$previousHeartbeatTime = $null
$maximumDerivedHeartbeatGap = [TimeSpan]::Zero
$observedActiveJob = $false
for ($index = 0; $index -lt $heartbeatSamples.Count; $index++) {
    $sample = $heartbeatSamples[$index]
    $path = "$.heartbeatSamples[$index]"
    Assert-ExactPropertyNames $sample @(
        'requestId',
        'nodeId',
        'heartbeatAt',
        'nextHeartbeatSeconds',
        'capacity',
        'serverTime',
        'receiptSha256') $path
    $serverTime = ConvertTo-UtcTimestamp (Get-RequiredProperty $sample 'serverTime' $path) "$path.serverTime"
    Assert-TimestampInSession $serverTime "$path.serverTime" $startedAt $completedAt
    $requestId = Get-RequiredProperty $sample 'requestId' $path
    Assert-CanonicalUuid $requestId "$path.requestId"
    Add-UniqueValue $requestIds $requestId "$path.requestId"
    $nodeId = Get-RequiredProperty $sample 'nodeId' $path
    Assert-Identifier $nodeId "$path.nodeId"
    if ($null -eq $canaryNodeId) {
        $canaryNodeId = $nodeId
    } elseif ($nodeId -cne $canaryNodeId) {
        throw 'All canary heartbeat samples must bind the same nodeId.'
    }

    $heartbeatAt = ConvertTo-UtcTimestamp (Get-RequiredProperty $sample 'heartbeatAt' $path) "$path.heartbeatAt"
    Assert-TimestampInSession $heartbeatAt "$path.heartbeatAt" $startedAt $completedAt
    $nextHeartbeatSeconds = Get-ExactInteger (
        Get-RequiredProperty $sample 'nextHeartbeatSeconds' $path) "$path.nextHeartbeatSeconds"
    if ($heartbeatAt -gt $serverTime -or ($serverTime - $heartbeatAt) -gt $maximumHeartbeatServerSkew `
        -or $nextHeartbeatSeconds -ne 60) {
        throw "Canary heartbeat response timing is invalid at $path."
    }

    $capacity = Get-RequiredProperty $sample 'capacity' $path
    Assert-ExactPropertyNames $capacity @(
        'configuredCapacity',
        'requestedCapacity',
        'grantedCapacity',
        'activeAssignments',
        'availableSlots',
        'capacityClass',
        'reason',
        'grantedUntil') "$path.capacity"
    $configured = Get-ExactInteger (
        Get-RequiredProperty $capacity 'configuredCapacity' "$path.capacity") "$path.capacity.configuredCapacity"
    $requested = Get-ExactInteger (
        Get-RequiredProperty $capacity 'requestedCapacity' "$path.capacity") "$path.capacity.requestedCapacity"
    $granted = Get-ExactInteger (
        Get-RequiredProperty $capacity 'grantedCapacity' "$path.capacity") "$path.capacity.grantedCapacity"
    $active = Get-ExactInteger (
        Get-RequiredProperty $capacity 'activeAssignments' "$path.capacity") "$path.capacity.activeAssignments"
    $available = Get-ExactInteger (
        Get-RequiredProperty $capacity 'availableSlots' "$path.capacity") "$path.capacity.availableSlots"
    $capacityClass = Get-RequiredProperty $capacity 'capacityClass' "$path.capacity"
    $capacityReason = Get-RequiredProperty $capacity 'reason' "$path.capacity"
    Assert-SafeReceiptToken $capacityClass "$path.capacity.capacityClass"
    Assert-SafeReceiptToken $capacityReason "$path.capacity.reason"
    $grantedUntilRaw = $capacity.PSObject.Properties['grantedUntil'].Value
    $grantedUntil = $null
    $grantedUntilCanonical = '~'
    if ($null -ne $grantedUntilRaw) {
        $grantedUntil = ConvertTo-UtcTimestamp $grantedUntilRaw "$path.capacity.grantedUntil"
        $grantedUntilCanonical = Get-CanonicalTimestampValue $grantedUntil
    }
    if ($configured -lt 1 -or $configured -gt 64 -or $requested -ne 1 -or $granted -ne 1 `
        -or $active -lt 0 -or $active -gt 1 `
        -or $available -lt 0 -or $available -gt 1 -or ($active + $available) -ne $granted) {
        throw "Canary heartbeat capacity is invalid at $path."
    }
    if ($null -ne $grantedUntil -and $grantedUntil -le $serverTime) {
        throw "Canary heartbeat capacity grant is already expired at $path."
    }
    if ($active -eq 1) {
        $observedActiveJob = $true
    }

    Assert-ReceiptSha256 (
        Get-RequiredProperty $sample 'receiptSha256' $path) 'node-heartbeat' @(
            "requestId=$requestId",
            "nodeId=$nodeId",
            "heartbeatAtUnixMs=$(Get-CanonicalTimestampValue $heartbeatAt)",
            "nextHeartbeatSeconds=$($nextHeartbeatSeconds.ToString([Globalization.CultureInfo]::InvariantCulture))",
            "capacity.configuredCapacity=$($configured.ToString([Globalization.CultureInfo]::InvariantCulture))",
            "capacity.requestedCapacity=$($requested.ToString([Globalization.CultureInfo]::InvariantCulture))",
            "capacity.grantedCapacity=$($granted.ToString([Globalization.CultureInfo]::InvariantCulture))",
            "capacity.activeAssignments=$($active.ToString([Globalization.CultureInfo]::InvariantCulture))",
            "capacity.availableSlots=$($available.ToString([Globalization.CultureInfo]::InvariantCulture))",
            "capacity.capacityClass=$capacityClass",
            "capacity.reason=$capacityReason",
            "capacity.grantedUntilUnixMs=$grantedUntilCanonical",
            "serverTimeUnixMs=$(Get-CanonicalTimestampValue $serverTime)") `
        "$path.receiptSha256" $receiptHashes

    $gap = if ($null -eq $previousHeartbeatTime) {
        $serverTime - $startedAt
    } else {
        $serverTime - $previousHeartbeatTime
    }
    if (($null -eq $previousHeartbeatTime -and $gap -lt [TimeSpan]::Zero) `
        -or ($null -ne $previousHeartbeatTime -and $gap -le [TimeSpan]::Zero)) {
        throw 'Canary heartbeat samples must be ordered by strictly increasing serverTime.'
    }
    if ($gap -gt $maximumDerivedHeartbeatGap) {
        $maximumDerivedHeartbeatGap = $gap
    }
    if ($null -eq $firstHeartbeatTime) {
        $firstHeartbeatTime = $serverTime
    }
    $previousHeartbeatTime = $serverTime
}
$finalHeartbeatGap = $completedAt - $previousHeartbeatTime
if ($finalHeartbeatGap -gt $maximumDerivedHeartbeatGap) {
    $maximumDerivedHeartbeatGap = $finalHeartbeatGap
}
if ($maximumDerivedHeartbeatGap.TotalSeconds -gt $maximumHeartbeatGapSeconds) {
    throw "Canary heartbeat gap derived from samples exceeds $maximumHeartbeatGapSeconds seconds."
}
if (($previousHeartbeatTime - $firstHeartbeatTime) -lt $minimumSustainedDuration) {
    throw 'Canary accepted heartbeat span must remain healthy for at least 15 minutes.'
}
if (-not $observedActiveJob) {
    throw 'Canary heartbeat samples never observed the single active worker slot.'
}

$progressSamples = @(Get-RequiredProperty $evidence 'progressSamples' '$')
if ($progressSamples.Count -lt 2) {
    throw 'Canary evidence must contain at least two linked progress samples.'
}
$progressAssignmentId = $null
$progressGenerationPlanHash = $null
$previousSequence = [int64]-1
$previousPercent = [int64]-1
$previousContentBytes = [int64]-1
$previousProgressTime = $null
for ($index = 0; $index -lt $progressSamples.Count; $index++) {
    $sample = $progressSamples[$index]
    $path = "$.progressSamples[$index]"
    Assert-ExactPropertyNames $sample @(
        'assignmentId',
        'observedPercent',
        'observedAtUtc',
        'requestBodySha256',
        'requestProgress',
        'response',
        'receiptSha256') $path
    $assignmentId = Get-RequiredProperty $sample 'assignmentId' $path
    Assert-CanonicalUuid $assignmentId "$path.assignmentId"
    if ($null -eq $progressAssignmentId) {
        $progressAssignmentId = $assignmentId
    } elseif ($assignmentId -cne $progressAssignmentId) {
        throw 'Canary progress samples must belong to one completed assignment.'
    }
    $percent = Get-ExactInteger (
        Get-RequiredProperty $sample 'observedPercent' $path) "$path.observedPercent"
    $observedAt = ConvertTo-UtcTimestamp (
        Get-RequiredProperty $sample 'observedAtUtc' $path) "$path.observedAtUtc"
    Assert-TimestampInSession $observedAt "$path.observedAtUtc" $startedAt $completedAt
    $requestBodySha256 = Get-RequiredProperty $sample 'requestBodySha256' $path
    Assert-Sha256 $requestBodySha256 "$path.requestBodySha256"

    $requestProgress = Get-RequiredProperty $sample 'requestProgress' $path
    Assert-ExactPropertyNames $requestProgress @('phase', 'attempt', 'sequence', 'contentBytes') "$path.requestProgress"
    $phase = Get-RequiredProperty $requestProgress 'phase' "$path.requestProgress"
    Assert-SafeReceiptToken $phase "$path.requestProgress.phase"
    $attempt = Get-ExactInteger (
        Get-RequiredProperty $requestProgress 'attempt' "$path.requestProgress") "$path.requestProgress.attempt"
    $sequence = Get-ExactInteger (
        Get-RequiredProperty $requestProgress 'sequence' "$path.requestProgress") "$path.requestProgress.sequence"
    $contentBytes = Get-ExactInteger (
        Get-RequiredProperty $requestProgress 'contentBytes' "$path.requestProgress") "$path.requestProgress.contentBytes"

    $response = Get-RequiredProperty $sample 'response' $path
    Assert-ExactPropertyNames $response @(
        'assignmentId',
        'generationPlanHash',
        'leaseExpiresAt',
        'liveness',
        'workSizing',
        'serverTime') "$path.response"
    $responseAssignmentId = Get-RequiredProperty $response 'assignmentId' "$path.response"
    $generationPlanHash = Get-RequiredProperty $response 'generationPlanHash' "$path.response"
    Assert-CanonicalUuid $responseAssignmentId "$path.response.assignmentId"
    Assert-Sha256 $generationPlanHash "$path.response.generationPlanHash"
    if ($null -eq $progressGenerationPlanHash) {
        $progressGenerationPlanHash = $generationPlanHash
    } elseif ($generationPlanHash -cne $progressGenerationPlanHash) {
        throw 'Canary progress samples must bind one immutable generationPlanHash.'
    }
    $serverTime = ConvertTo-UtcTimestamp (
        Get-RequiredProperty $response 'serverTime' "$path.response") "$path.response.serverTime"
    Assert-TimestampInSession $serverTime "$path.response.serverTime" $startedAt $completedAt
    $leaseExpiresAt = ConvertTo-UtcTimestamp (
        Get-RequiredProperty $response 'leaseExpiresAt' "$path.response") "$path.response.leaseExpiresAt"

    $liveness = Get-RequiredProperty $response 'liveness' "$path.response"
    Assert-ExactPropertyNames $liveness @('state', 'lastProgressAt', 'staleAfterSeconds') "$path.response.liveness"
    $livenessState = Get-RequiredProperty $liveness 'state' "$path.response.liveness"
    Assert-SafeReceiptToken $livenessState "$path.response.liveness.state"
    $lastProgressAt = ConvertTo-UtcTimestamp (
        Get-RequiredProperty $liveness 'lastProgressAt' "$path.response.liveness") `
        "$path.response.liveness.lastProgressAt"
    $staleAfterSeconds = Get-ExactInteger (
        Get-RequiredProperty $liveness 'staleAfterSeconds' "$path.response.liveness") `
        "$path.response.liveness.staleAfterSeconds"

    $workSizing = Get-RequiredProperty $response 'workSizing' "$path.response"
    Assert-ExactPropertyNames $workSizing @('currentTier', 'currentRank', 'reason') "$path.response.workSizing"
    $currentTier = Get-RequiredProperty $workSizing 'currentTier' "$path.response.workSizing"
    $currentRank = Get-ExactInteger (
        Get-RequiredProperty $workSizing 'currentRank' "$path.response.workSizing") "$path.response.workSizing.currentRank"
    $workSizingReason = Get-RequiredProperty $workSizing 'reason' "$path.response.workSizing"
    Assert-SafeReceiptToken $currentTier "$path.response.workSizing.currentTier"
    Assert-SafeReceiptToken $workSizingReason "$path.response.workSizing.reason"

    if ($responseAssignmentId -cne $assignmentId `
        -or $observedAt -gt $serverTime.Add($maximumClockSkew) `
        -or $observedAt -lt $serverTime.Subtract($maximumClockSkew) `
        -or $leaseExpiresAt -le $serverTime -or $lastProgressAt -gt $serverTime `
        -or $assignmentLivenessStates -cnotcontains $livenessState -or $livenessState -cne $phase `
        -or $phase -cnotin @('responding', 'finalizing') `
        -or $attempt -lt 1 -or $attempt -gt 8 -or $sequence -le $previousSequence `
        -or $sequence -gt 4000000 -or $contentBytes -lt 1 -or $contentBytes -gt 4000000 `
        -or ($previousContentBytes -ge 0 -and $contentBytes -le $previousContentBytes) `
        -or $percent -le $previousPercent `
        -or $percent -lt 0 -or $percent -gt 100 -or $staleAfterSeconds -lt 1 `
        -or $staleAfterSeconds -gt 86400 -or $currentRank -lt 0 -or $currentRank -gt 15 `
        -or $assignmentWorkSizingReasons -cnotcontains $workSizingReason `
        -or ($null -ne $previousProgressTime -and $serverTime -le $previousProgressTime)) {
        throw 'Canary progress must have strictly increasing sequence, content bytes, percent and serverTime.'
    }

    Assert-ReceiptSha256 (
        Get-RequiredProperty $sample 'receiptSha256' $path) 'assignment-heartbeat' @(
            "assignmentId=$assignmentId",
            "observedPercent=$($percent.ToString([Globalization.CultureInfo]::InvariantCulture))",
            "observedAtUnixMs=$(Get-CanonicalTimestampValue $observedAt)",
            "requestBodySha256=$requestBodySha256",
            "requestProgress.phase=$phase",
            "requestProgress.attempt=$($attempt.ToString([Globalization.CultureInfo]::InvariantCulture))",
            "requestProgress.sequence=$($sequence.ToString([Globalization.CultureInfo]::InvariantCulture))",
            "requestProgress.contentBytes=$($contentBytes.ToString([Globalization.CultureInfo]::InvariantCulture))",
            "response.assignmentId=$responseAssignmentId",
            "response.generationPlanHash=$generationPlanHash",
            "response.leaseExpiresAtUnixMs=$(Get-CanonicalTimestampValue $leaseExpiresAt)",
            "response.liveness.state=$livenessState",
            "response.liveness.lastProgressAtUnixMs=$(Get-CanonicalTimestampValue $lastProgressAt)",
            "response.liveness.staleAfterSeconds=$($staleAfterSeconds.ToString([Globalization.CultureInfo]::InvariantCulture))",
            "response.workSizing.currentTier=$currentTier",
            "response.workSizing.currentRank=$($currentRank.ToString([Globalization.CultureInfo]::InvariantCulture))",
            "response.workSizing.reason=$workSizingReason",
            "response.serverTimeUnixMs=$(Get-CanonicalTimestampValue $serverTime)") `
        "$path.receiptSha256" $receiptHashes
    $previousSequence = $sequence
    $previousPercent = $percent
    $previousContentBytes = $contentBytes
    $previousProgressTime = $serverTime
}

$completionAssignmentIds = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
$latestOutcomeTime = $startedAt
$completions = @(Get-RequiredProperty $evidence 'completions' '$')
if ($completions.Count -lt 1) {
    throw 'Canary evidence must contain at least one completion sample.'
}
for ($index = 0; $index -lt $completions.Count; $index++) {
    $sample = $completions[$index]
    $path = "$.completions[$index]"
    Assert-ExactPropertyNames $sample @(
        'assignmentId',
        'generationPlanHash',
        'commitAccepted',
        'status',
        'automaticApproval',
        'automaticPublication',
        'replayed',
        'serverTime',
        'journal',
        'receiptSha256') $path
    $assignmentId = Get-RequiredProperty $sample 'assignmentId' $path
    Assert-CanonicalUuid $assignmentId "$path.assignmentId"
    Add-UniqueValue $completionAssignmentIds $assignmentId "$path.assignmentId"
    Add-UniqueValue $assignmentIds $assignmentId "$path.assignmentId"
    $generationPlanHash = Get-RequiredProperty $sample 'generationPlanHash' $path
    Assert-Sha256 $generationPlanHash "$path.generationPlanHash"
    if ($assignmentId -ceq $progressAssignmentId -and $generationPlanHash -cne $progressGenerationPlanHash) {
        throw 'Canary completion generationPlanHash does not match the linked progress samples.'
    }
    $serverTime = ConvertTo-UtcTimestamp (Get-RequiredProperty $sample 'serverTime' $path) "$path.serverTime"
    Assert-TimestampInSession $serverTime "$path.serverTime" $startedAt $completedAt
    if ($assignmentId -ceq $progressAssignmentId -and $serverTime -le $previousProgressTime) {
        throw 'Canary completion must occur after the final linked progress sample.'
    }
    if ($serverTime -gt $latestOutcomeTime) {
        $latestOutcomeTime = $serverTime
    }
    $commitAccepted = Get-ExactBoolean (
        Get-RequiredProperty $sample 'commitAccepted' $path) "$path.commitAccepted"
    $automaticApproval = Get-ExactBoolean (
        Get-RequiredProperty $sample 'automaticApproval' $path) "$path.automaticApproval"
    $automaticPublication = Get-ExactBoolean (
        Get-RequiredProperty $sample 'automaticPublication' $path) "$path.automaticPublication"
    $replayed = Get-ExactBoolean (Get-RequiredProperty $sample 'replayed' $path) "$path.replayed"
    $status = Get-RequiredProperty $sample 'status' $path
    if (-not $commitAccepted -or $automaticApproval -or $automaticPublication -or $status -cne 'pending-review') {
        throw "Canary completion sample is invalid or unreconciled at $path."
    }

    $journal = Get-RequiredProperty $sample 'journal' $path
    Assert-ExactPropertyNames $journal @(
        'schemaVersion',
        'assignmentId',
        'generationPlanHash',
        'phase',
        'requestId',
        'requestBodySha256',
        'draftSha256',
        'lastErrorCode',
        'updatedAtUtc') "$path.journal"
    $journalSchemaVersion = Get-ExactInteger (
        Get-RequiredProperty $journal 'schemaVersion' "$path.journal") "$path.journal.schemaVersion"
    $journalAssignmentId = Get-RequiredProperty $journal 'assignmentId' "$path.journal"
    $journalGenerationPlanHash = Get-RequiredProperty $journal 'generationPlanHash' "$path.journal"
    $journalPhase = Get-RequiredProperty $journal 'phase' "$path.journal"
    $requestId = Get-RequiredProperty $journal 'requestId' "$path.journal"
    $requestBodySha256 = Get-RequiredProperty $journal 'requestBodySha256' "$path.journal"
    $draftSha256 = Get-RequiredProperty $journal 'draftSha256' "$path.journal"
    $lastErrorCode = $journal.PSObject.Properties['lastErrorCode'].Value
    $journalUpdatedAt = ConvertTo-UtcTimestamp (
        Get-RequiredProperty $journal 'updatedAtUtc' "$path.journal") "$path.journal.updatedAtUtc"
    Assert-CanonicalUuid $journalAssignmentId "$path.journal.assignmentId"
    Assert-Sha256 $journalGenerationPlanHash "$path.journal.generationPlanHash"
    Assert-CanonicalUuid $requestId "$path.journal.requestId"
    Assert-Sha256 $requestBodySha256 "$path.journal.requestBodySha256"
    Assert-Sha256 $draftSha256 "$path.journal.draftSha256"
    Add-UniqueValue $requestIds $requestId "$path.journal.requestId"
    Assert-TimestampInSession $journalUpdatedAt "$path.journal.updatedAtUtc" $startedAt $completedAt
    if ($journalSchemaVersion -ne 1 -or $journalAssignmentId -cne $assignmentId `
        -or $journalGenerationPlanHash -cne $generationPlanHash -or $journalPhase -cne 'completed' `
        -or $null -ne $lastErrorCode `
        -or $journalUpdatedAt -lt $serverTime.Subtract($maximumClockSkew)) {
        throw "Canary completion journal is not durably reconciled at $path."
    }

    Assert-ReceiptSha256 (
        Get-RequiredProperty $sample 'receiptSha256' $path) 'complete' @(
            "assignmentId=$assignmentId",
            "generationPlanHash=$generationPlanHash",
            "commitAccepted=$(Get-CanonicalBooleanValue $commitAccepted)",
            "status=$status",
            "automaticApproval=$(Get-CanonicalBooleanValue $automaticApproval)",
            "automaticPublication=$(Get-CanonicalBooleanValue $automaticPublication)",
            "replayed=$(Get-CanonicalBooleanValue $replayed)",
            "serverTimeUnixMs=$(Get-CanonicalTimestampValue $serverTime)",
            "journal.schemaVersion=$($journalSchemaVersion.ToString([Globalization.CultureInfo]::InvariantCulture))",
            "journal.assignmentId=$journalAssignmentId",
            "journal.generationPlanHash=$journalGenerationPlanHash",
            "journal.phase=$journalPhase",
            "journal.requestId=$requestId",
            "journal.requestBodySha256=$requestBodySha256",
            "journal.draftSha256=$draftSha256",
            'journal.lastErrorCode=~',
            "journal.updatedAtUnixMs=$(Get-CanonicalTimestampValue $journalUpdatedAt)") `
        "$path.receiptSha256" $receiptHashes
}
if (-not $completionAssignmentIds.Contains($progressAssignmentId)) {
    throw 'Canary progress samples are not linked to a completed assignment.'
}

$failures = @(Get-RequiredProperty $evidence 'failures' '$')
if ($failures.Count -lt 1) {
    throw 'Canary evidence must contain at least one failure sample.'
}
for ($index = 0; $index -lt $failures.Count; $index++) {
    $sample = $failures[$index]
    $path = "$.failures[$index]"
    Assert-ExactPropertyNames $sample @(
        'assignmentId',
        'generationPlanHash',
        'status',
        'replayed',
        'serverTime',
        'requestErrorCode',
        'journal',
        'receiptSha256') $path
    $assignmentId = Get-RequiredProperty $sample 'assignmentId' $path
    Assert-CanonicalUuid $assignmentId "$path.assignmentId"
    if ($assignmentIds.Contains($assignmentId)) {
        throw 'Canary completion and failure must use distinct assignments.'
    }
    Add-UniqueValue $assignmentIds $assignmentId "$path.assignmentId"
    $generationPlanHash = Get-RequiredProperty $sample 'generationPlanHash' $path
    Assert-Sha256 $generationPlanHash "$path.generationPlanHash"
    $serverTime = ConvertTo-UtcTimestamp (Get-RequiredProperty $sample 'serverTime' $path) "$path.serverTime"
    Assert-TimestampInSession $serverTime "$path.serverTime" $startedAt $completedAt
    if ($serverTime -gt $latestOutcomeTime) {
        $latestOutcomeTime = $serverTime
    }
    $errorCode = Get-RequiredProperty $sample 'requestErrorCode' $path
    $status = Get-RequiredProperty $sample 'status' $path
    $replayed = Get-ExactBoolean (Get-RequiredProperty $sample 'replayed' $path) "$path.replayed"
    if ($errorCode -isnot [string] -or $errorCode -notmatch '^[a-z0-9][a-z0-9.-]{0,63}$' `
        -or $status -cne 'failed-attempt') {
        throw "Canary failure sample is invalid or unreconciled at $path."
    }

    $journal = Get-RequiredProperty $sample 'journal' $path
    Assert-ExactPropertyNames $journal @(
        'schemaVersion',
        'assignmentId',
        'generationPlanHash',
        'phase',
        'requestId',
        'requestBodySha256',
        'draftSha256',
        'lastErrorCode',
        'updatedAtUtc') "$path.journal"
    $journalSchemaVersion = Get-ExactInteger (
        Get-RequiredProperty $journal 'schemaVersion' "$path.journal") "$path.journal.schemaVersion"
    $journalAssignmentId = Get-RequiredProperty $journal 'assignmentId' "$path.journal"
    $journalGenerationPlanHash = Get-RequiredProperty $journal 'generationPlanHash' "$path.journal"
    $journalPhase = Get-RequiredProperty $journal 'phase' "$path.journal"
    $requestId = Get-RequiredProperty $journal 'requestId' "$path.journal"
    $requestBodySha256 = Get-RequiredProperty $journal 'requestBodySha256' "$path.journal"
    $draftSha256 = $journal.PSObject.Properties['draftSha256'].Value
    $lastErrorCode = Get-RequiredProperty $journal 'lastErrorCode' "$path.journal"
    $journalUpdatedAt = ConvertTo-UtcTimestamp (
        Get-RequiredProperty $journal 'updatedAtUtc' "$path.journal") "$path.journal.updatedAtUtc"
    Assert-CanonicalUuid $journalAssignmentId "$path.journal.assignmentId"
    Assert-Sha256 $journalGenerationPlanHash "$path.journal.generationPlanHash"
    Assert-CanonicalUuid $requestId "$path.journal.requestId"
    Assert-Sha256 $requestBodySha256 "$path.journal.requestBodySha256"
    if ($null -ne $draftSha256) {
        Assert-Sha256 $draftSha256 "$path.journal.draftSha256"
    }
    Add-UniqueValue $requestIds $requestId "$path.journal.requestId"
    Assert-TimestampInSession $journalUpdatedAt "$path.journal.updatedAtUtc" $startedAt $completedAt
    if ($journalSchemaVersion -ne 1 -or $journalAssignmentId -cne $assignmentId `
        -or $journalGenerationPlanHash -cne $generationPlanHash -or $journalPhase -cne 'failed' `
        -or $lastErrorCode -cne $errorCode `
        -or $journalUpdatedAt -lt $serverTime.Subtract($maximumClockSkew)) {
        throw "Canary failure journal is not durably reconciled at $path."
    }
    $draftSha256Canonical = if ($null -eq $draftSha256) { '~' } else { [string]$draftSha256 }

    Assert-ReceiptSha256 (
        Get-RequiredProperty $sample 'receiptSha256' $path) 'fail' @(
            "assignmentId=$assignmentId",
            "generationPlanHash=$generationPlanHash",
            "status=$status",
            "replayed=$(Get-CanonicalBooleanValue $replayed)",
            "serverTimeUnixMs=$(Get-CanonicalTimestampValue $serverTime)",
            "requestErrorCode=$errorCode",
            "journal.schemaVersion=$($journalSchemaVersion.ToString([Globalization.CultureInfo]::InvariantCulture))",
            "journal.assignmentId=$journalAssignmentId",
            "journal.generationPlanHash=$journalGenerationPlanHash",
            "journal.phase=$journalPhase",
            "journal.requestId=$requestId",
            "journal.requestBodySha256=$requestBodySha256",
            "journal.draftSha256=$draftSha256Canonical",
            "journal.lastErrorCode=$lastErrorCode",
            "journal.updatedAtUnixMs=$(Get-CanonicalTimestampValue $journalUpdatedAt)") `
        "$path.receiptSha256" $receiptHashes
}

$rollback = Get-RequiredProperty $evidence 'rollbackReceipt' '$'
Assert-ExactPropertyNames $rollback @(
    'receiptId',
    'serverTime',
    'targetVersion',
    'v4ServiceDisabled',
    'legacyServiceStartMode',
    'backupSha256',
    'previousServiceDefinitionSha256',
    'restoredServiceDefinitionSha256',
    'legacyHeartbeat',
    'receiptSha256') '$.rollbackReceipt'
$rollbackReceiptId = Get-RequiredProperty $rollback 'receiptId' '$.rollbackReceipt'
Assert-CanonicalUuid $rollbackReceiptId '$.rollbackReceipt.receiptId'
$rollbackServerTime = ConvertTo-UtcTimestamp (
    Get-RequiredProperty $rollback 'serverTime' '$.rollbackReceipt') '$.rollbackReceipt.serverTime'
Assert-TimestampInSession $rollbackServerTime '$.rollbackReceipt.serverTime' $startedAt $completedAt
if ($installedObservedAt -ge $firstHeartbeatTime `
    -or $restartBootStartedAt -le $previousHeartbeatTime `
    -or $restartObservedAt -le $latestOutcomeTime `
    -or $restartObservedAt -gt $rollbackServerTime `
    -or $rollbackServerTime -lt $previousHeartbeatTime `
    -or $rollbackServerTime -lt $latestOutcomeTime `
    -or (Get-RequiredProperty $rollback 'targetVersion' '$.rollbackReceipt') -cne '3.1.1' `
    -or -not (Get-ExactBoolean (
        Get-RequiredProperty $rollback 'v4ServiceDisabled' '$.rollbackReceipt') '$.rollbackReceipt.v4ServiceDisabled') `
    -or (Get-RequiredProperty $rollback 'legacyServiceStartMode' '$.rollbackReceipt') -cne 'AutomaticDelayed') {
    throw 'Canary rollback receipt does not prove a completed recovery to 3.1.1.'
}
foreach ($hashName in 'backupSha256', 'previousServiceDefinitionSha256', 'restoredServiceDefinitionSha256') {
    Assert-Sha256 (Get-RequiredProperty $rollback $hashName '$.rollbackReceipt') "$.rollbackReceipt.$hashName"
}
if ((Get-RequiredProperty $rollback 'previousServiceDefinitionSha256' '$.rollbackReceipt') -cne `
    (Get-RequiredProperty $rollback 'restoredServiceDefinitionSha256' '$.rollbackReceipt')) {
    throw 'Canary rollback did not restore the exact legacy service definition hash.'
}

$legacyHeartbeat = Get-RequiredProperty $rollback 'legacyHeartbeat' '$.rollbackReceipt'
Assert-ExactPropertyNames $legacyHeartbeat @(
    'workerVersion',
    'requestId',
    'nodeId',
    'heartbeatAt',
    'nextHeartbeatSeconds',
    'capacity',
    'serverTime',
    'receiptSha256') '$.rollbackReceipt.legacyHeartbeat'
$legacyHeartbeatTime = ConvertTo-UtcTimestamp (
    Get-RequiredProperty $legacyHeartbeat 'serverTime' '$.rollbackReceipt.legacyHeartbeat') `
    '$.rollbackReceipt.legacyHeartbeat.serverTime'
Assert-TimestampInSession $legacyHeartbeatTime '$.rollbackReceipt.legacyHeartbeat.serverTime' $startedAt $completedAt
$legacyRequestId = Get-RequiredProperty $legacyHeartbeat 'requestId' '$.rollbackReceipt.legacyHeartbeat'
Assert-CanonicalUuid $legacyRequestId '$.rollbackReceipt.legacyHeartbeat.requestId'
Add-UniqueValue $requestIds $legacyRequestId '$.rollbackReceipt.legacyHeartbeat.requestId'
$legacyNodeId = Get-RequiredProperty $legacyHeartbeat 'nodeId' '$.rollbackReceipt.legacyHeartbeat'
Assert-Identifier $legacyNodeId '$.rollbackReceipt.legacyHeartbeat.nodeId'
$legacyHeartbeatAt = ConvertTo-UtcTimestamp (
    Get-RequiredProperty $legacyHeartbeat 'heartbeatAt' '$.rollbackReceipt.legacyHeartbeat') `
    '$.rollbackReceipt.legacyHeartbeat.heartbeatAt'
$legacyNextHeartbeatSeconds = Get-ExactInteger (
    Get-RequiredProperty $legacyHeartbeat 'nextHeartbeatSeconds' '$.rollbackReceipt.legacyHeartbeat') `
    '$.rollbackReceipt.legacyHeartbeat.nextHeartbeatSeconds'
$legacyCapacity = Get-RequiredProperty $legacyHeartbeat 'capacity' '$.rollbackReceipt.legacyHeartbeat'
Assert-ExactPropertyNames $legacyCapacity @(
    'configuredCapacity',
    'requestedCapacity',
    'grantedCapacity',
    'activeAssignments',
    'availableSlots',
    'capacityClass',
    'reason',
    'grantedUntil') '$.rollbackReceipt.legacyHeartbeat.capacity'
$legacyConfigured = Get-ExactInteger (
    Get-RequiredProperty $legacyCapacity 'configuredCapacity' '$.rollbackReceipt.legacyHeartbeat.capacity') `
    '$.rollbackReceipt.legacyHeartbeat.capacity.configuredCapacity'
$legacyRequested = Get-ExactInteger (
    Get-RequiredProperty $legacyCapacity 'requestedCapacity' '$.rollbackReceipt.legacyHeartbeat.capacity') `
    '$.rollbackReceipt.legacyHeartbeat.capacity.requestedCapacity'
$legacyGranted = Get-ExactInteger (
    Get-RequiredProperty $legacyCapacity 'grantedCapacity' '$.rollbackReceipt.legacyHeartbeat.capacity') `
    '$.rollbackReceipt.legacyHeartbeat.capacity.grantedCapacity'
$legacyActive = Get-ExactInteger (
    Get-RequiredProperty $legacyCapacity 'activeAssignments' '$.rollbackReceipt.legacyHeartbeat.capacity') `
    '$.rollbackReceipt.legacyHeartbeat.capacity.activeAssignments'
$legacyAvailable = Get-ExactInteger (
    Get-RequiredProperty $legacyCapacity 'availableSlots' '$.rollbackReceipt.legacyHeartbeat.capacity') `
    '$.rollbackReceipt.legacyHeartbeat.capacity.availableSlots'
$legacyCapacityClass = Get-RequiredProperty $legacyCapacity 'capacityClass' '$.rollbackReceipt.legacyHeartbeat.capacity'
$legacyCapacityReason = Get-RequiredProperty $legacyCapacity 'reason' '$.rollbackReceipt.legacyHeartbeat.capacity'
Assert-SafeReceiptToken $legacyCapacityClass '$.rollbackReceipt.legacyHeartbeat.capacity.capacityClass'
Assert-SafeReceiptToken $legacyCapacityReason '$.rollbackReceipt.legacyHeartbeat.capacity.reason'
$legacyGrantedUntilRaw = $legacyCapacity.PSObject.Properties['grantedUntil'].Value
$legacyGrantedUntil = $null
$legacyGrantedUntilCanonical = '~'
if ($null -ne $legacyGrantedUntilRaw) {
    $legacyGrantedUntil = ConvertTo-UtcTimestamp $legacyGrantedUntilRaw `
        '$.rollbackReceipt.legacyHeartbeat.capacity.grantedUntil'
    $legacyGrantedUntilCanonical = Get-CanonicalTimestampValue $legacyGrantedUntil
}
if ($legacyHeartbeatTime -le $rollbackServerTime `
    -or $legacyHeartbeatAt -gt $legacyHeartbeatTime `
    -or ($legacyHeartbeatTime - $legacyHeartbeatAt) -gt $maximumHeartbeatServerSkew `
    -or $legacyNodeId -cne $canaryNodeId `
    -or (Get-RequiredProperty $legacyHeartbeat 'workerVersion' '$.rollbackReceipt.legacyHeartbeat') -cne '3.1.1' `
    -or $legacyNextHeartbeatSeconds -ne 60 `
    -or $legacyConfigured -lt 1 -or $legacyConfigured -gt 64 `
    -or $legacyRequested -lt 0 -or $legacyRequested -gt 64 `
    -or $legacyGranted -lt 0 -or $legacyGranted -gt $legacyRequested `
    -or $legacyActive -lt 0 -or $legacyActive -gt $legacyGranted `
    -or $legacyAvailable -ne ($legacyGranted - $legacyActive) `
    -or ($null -ne $legacyGrantedUntil -and $legacyGrantedUntil -le $legacyHeartbeatTime)) {
    throw 'Canary rollback receipt does not contain an accepted legacy heartbeat for the same node.'
}

Assert-ReceiptSha256 (
    Get-RequiredProperty $legacyHeartbeat 'receiptSha256' '$.rollbackReceipt.legacyHeartbeat') `
    'legacy-node-heartbeat' @(
        'workerVersion=3.1.1',
        "requestId=$legacyRequestId",
        "nodeId=$legacyNodeId",
        "heartbeatAtUnixMs=$(Get-CanonicalTimestampValue $legacyHeartbeatAt)",
        "nextHeartbeatSeconds=$($legacyNextHeartbeatSeconds.ToString([Globalization.CultureInfo]::InvariantCulture))",
        "capacity.configuredCapacity=$($legacyConfigured.ToString([Globalization.CultureInfo]::InvariantCulture))",
        "capacity.requestedCapacity=$($legacyRequested.ToString([Globalization.CultureInfo]::InvariantCulture))",
        "capacity.grantedCapacity=$($legacyGranted.ToString([Globalization.CultureInfo]::InvariantCulture))",
        "capacity.activeAssignments=$($legacyActive.ToString([Globalization.CultureInfo]::InvariantCulture))",
        "capacity.availableSlots=$($legacyAvailable.ToString([Globalization.CultureInfo]::InvariantCulture))",
        "capacity.capacityClass=$legacyCapacityClass",
        "capacity.reason=$legacyCapacityReason",
        "capacity.grantedUntilUnixMs=$legacyGrantedUntilCanonical",
        "serverTimeUnixMs=$(Get-CanonicalTimestampValue $legacyHeartbeatTime)") `
    '$.rollbackReceipt.legacyHeartbeat.receiptSha256' $receiptHashes

$rollbackBackupSha256 = Get-RequiredProperty $rollback 'backupSha256' '$.rollbackReceipt'
$rollbackPreviousDefinitionSha256 = Get-RequiredProperty (
    $rollback) 'previousServiceDefinitionSha256' '$.rollbackReceipt'
$rollbackRestoredDefinitionSha256 = Get-RequiredProperty (
    $rollback) 'restoredServiceDefinitionSha256' '$.rollbackReceipt'
$legacyHeartbeatReceiptSha256 = Get-RequiredProperty (
    $legacyHeartbeat) 'receiptSha256' '$.rollbackReceipt.legacyHeartbeat'
Assert-ReceiptSha256 (
    Get-RequiredProperty $rollback 'receiptSha256' '$.rollbackReceipt') 'rollback' @(
        "receiptId=$rollbackReceiptId",
        "serverTimeUnixMs=$(Get-CanonicalTimestampValue $rollbackServerTime)",
        'targetVersion=3.1.1',
        'v4ServiceDisabled=true',
        'legacyServiceStartMode=AutomaticDelayed',
        "backupSha256=$rollbackBackupSha256",
        "previousServiceDefinitionSha256=$rollbackPreviousDefinitionSha256",
        "restoredServiceDefinitionSha256=$rollbackRestoredDefinitionSha256",
        "legacyHeartbeatReceiptSha256=$legacyHeartbeatReceiptSha256") `
    '$.rollbackReceipt.receiptSha256' $receiptHashes

Write-Host (
    "Windows canary evidence passed for exact MSI {0}; CMS attester {1}; {2} heartbeats; max derived gap {3:N1}s." -f `
    $msiSha256,
    $actualThumbprint,
    $heartbeatSamples.Count,
    $maximumDerivedHeartbeatGap.TotalSeconds)
