[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$repositoryRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\..')).Path
$ciPath = Join-Path $repositoryRoot '.github\workflows\ci.yml'
$candidatePath = Join-Path $repositoryRoot '.github\workflows\windows-package.yml'
$promotionPath = Join-Path $repositoryRoot '.github\workflows\windows-release.yml'
$canaryValidator = Join-Path $repositoryRoot 'scripts\windows\Test-HchWorkerCanaryEvidence.ps1'
$canaryExporter = Join-Path $repositoryRoot 'scripts\windows\Export-HchWorkerCanaryEvidence.ps1'
$canarySigner = Join-Path $repositoryRoot 'scripts\windows\Sign-HchWorkerCanaryEvidence.ps1'
$bridgeReleaseValidator = Join-Path $repositoryRoot 'scripts\windows\Test-HchWorkerBridgeRelease.ps1'
$fleetValidator = Join-Path $repositoryRoot 'scripts\windows\Test-HchWorkerFleetTransitionEvidence.ps1'
$fleetSigner = Join-Path $repositoryRoot 'scripts\windows\Sign-HchWorkerFleetTransitionEvidence.ps1'
$releaseMonitorPath = Join-Path $repositoryRoot 'ops\worker-dashboard\lib\releases.mjs'
$buildScript = Join-Path $repositoryRoot 'scripts\windows\Build-HchWorkerPackage.ps1'
$completeScript = Join-Path $repositoryRoot 'scripts\windows\Complete-HchWorkerReleaseEvidence.ps1'
$releaseEvidenceScript = Join-Path $repositoryRoot 'scripts\windows\Test-HchWorkerReleaseEvidence.ps1'
foreach ($path in $ciPath, $candidatePath, $promotionPath, $canaryValidator, $canaryExporter, $canarySigner, $bridgeReleaseValidator, $fleetValidator, $fleetSigner, $releaseMonitorPath, $buildScript, $completeScript, $releaseEvidenceScript) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "Windows release gate file is missing: $path"
    }
}

$ci = Get-Content -LiteralPath $ciPath -Raw
$candidate = Get-Content -LiteralPath $candidatePath -Raw
$promotion = Get-Content -LiteralPath $promotionPath -Raw
$canary = Get-Content -LiteralPath $canaryValidator -Raw
$canaryExport = Get-Content -LiteralPath $canaryExporter -Raw
$canarySigning = Get-Content -LiteralPath $canarySigner -Raw
$bridgeRelease = Get-Content -LiteralPath $bridgeReleaseValidator -Raw
$fleet = Get-Content -LiteralPath $fleetValidator -Raw
$fleetSigning = Get-Content -LiteralPath $fleetSigner -Raw
$releaseMonitor = Get-Content -LiteralPath $releaseMonitorPath -Raw
$releaseMonitorRuntimeShape = $releaseMonitor.Replace('${RELEASE_PAGE_SIZE}', '100').Replace('${page}', '')

function Assert-CanaryExactPropertyShape {
    param(
        [Parameter(Mandatory)][string]$Text,
        [Parameter(Mandatory)][string[]]$Names,
        [Parameter(Mandatory)][string]$Label,
        [int]$MinimumMatches = 1
    )

    $fieldPattern = [string]::Join(
        '\s*,?\s*',
        @($Names | ForEach-Object { "'$( [Regex]::Escape($_) )'" }))
    $pattern = "Assert-ExactPropertyNames\s+\S+\s+@\(\s*$fieldPattern\s*\)"
    $matches = [Regex]::Matches(
        $Text,
        $pattern,
        [Text.RegularExpressions.RegexOptions]::Singleline)
    if ($matches.Count -lt $MinimumMatches) {
        throw "Canary evidence exact property shape is missing: $Label"
    }
}

if ($candidate -match '(?m)^\s*publish-official-release:' `
    -or $candidate -match '\bgh\s+release\s+create\b' `
    -or $candidate -match '\brelease_intent\b') {
    throw 'Candidate workflow must not contain an official publication path.'
}
$buildScriptText = Get-Content -LiteralPath $buildScript -Raw
$completeScriptText = Get-Content -LiteralPath $completeScript -Raw
$buildAndComplete = $buildScriptText +
    $completeScriptText +
    (Get-Content -LiteralPath $releaseEvidenceScript -Raw)
if ($buildAndComplete -match "ValidateSet\([^\r\n]*'Official'" `
    -or $buildAndComplete -match '\bRequireReleasable\b' `
    -or $buildAndComplete -match '\breleasable\s*=\s*\[bool\]\$officialReady') {
    throw 'Build/sign completion may produce candidates only; official status belongs to post-canary promotion.'
}
foreach ($scriptText in $buildScriptText, $completeScriptText) {
    if (-not $scriptText.Contains("'-bc', `$windowsRoot", [StringComparison]::Ordinal) `
        -or -not $scriptText.Contains("'-D', 'true'", [StringComparison]::Ordinal) `
        -or $scriptText.Contains("'-bc', `$repositoryRoot", [StringComparison]::Ordinal)) {
        throw 'Windows candidate SBOM must be rebuilt from src/windows without retaining a prior manifest.'
    }
}
foreach ($required in @(
    "WIX_EULA_ACCEPTED -ne 'wix7'",
    'Set WIX_EULA_ACCEPTED=wix7 only after organizational review',
    "if: env.WIX_EULA_ACCEPTED == 'wix7'",
    "if: env.WIX_EULA_ACCEPTED != 'wix7'",
    'Report unsigned package as unavailable without organizational WiX acceptance',
    'Signed workflow dispatch remains fail-closed',
    '-AcceptWixEula',
    'inputs.run_disposable_msi_e2e != true',
    "ReleaseIntent = 'Candidate'",
    'RequireDefender = $true',
    'RequireCandidate = $true',
    'retention-days: 90',
    'actions/attest-build-provenance@')) {
    if (-not $candidate.Contains($required, [StringComparison]::Ordinal)) {
        throw "Signed-candidate workflow gate is missing: $required"
    }
}
if ($canarySigning -match '(?i)Export-PfxCertificate|Export-Certificate|\.Export\s*\(') {
    throw 'Controlled canary signing must never export certificate or private-key material.'
}
foreach ($required in @(
    'Current runtime limitation:',
    'Missing sources fail closed',
    "'workerVersion'",
    "'sourceCommit'",
    "'msiSha256'",
    'Refusing to overwrite existing canary evidence.',
    'Canary source bundle changed during export.',
    'Canary source bundle contains an unsupported or unreferenced file.',
    '$restartAt -gt $rollbackServerTime',
    '$rollbackValidatedAt -ge $legacyHeartbeat.ServerTime')) {
    if (-not $canaryExport.Contains($required, [StringComparison]::Ordinal)) {
        throw "Deterministic canary evidence exporter gate is missing: $required"
    }
}
if ($canaryExport -match '(?i)SignedCms|CmsSigner|Export-PfxCertificate|Export-Certificate') {
    throw 'Canary evidence export must remain separate from signing and private-key handling.'
}

foreach ($required in @(
    'native-windows-v4:',
    'Restore exact locked .NET dependencies',
    "if: vars.WIX_EULA_ACCEPTED == 'wix7'",
    'Record deferred WiX binary gate',
    "if: vars.WIX_EULA_ACCEPTED != 'wix7'",
    'dotnet test src/windows/Hch.Worker.Tests/Hch.Worker.Tests.csproj')) {
    if (-not $ci.Contains($required, [StringComparison]::Ordinal)) {
        throw "Native Windows CI strategy is missing: $required"
    }
}
foreach ($required in @(
    'dotnet build src/windows/Hch.Worker.sln',
    "throw 'Native solution build failed.'")) {
    if (-not $ci.Contains($required, [StringComparison]::Ordinal)) {
        throw "Native Windows full-solution build gate is missing: $required"
    }
}
if ($ci.Contains('Set WIX_EULA_ACCEPTED=wix7 only after organizational review', [StringComparison]::Ordinal)) {
    throw 'Native source/test CI must not fail merely because organizational WiX acceptance is absent.'
}

foreach ($required in @(
    'environment: windows-release-promotion',
    'WINDOWS_RELEASE_TAG_RULESET_ENFORCED',
    'refs/tags/v3.1.1',
    'No active immutable ruleset protects the compatibility bridge',
    '$detail.conditions.ref_name.exclude',
    '$detail.bypass_actors',
    '$ruleTypes -ccontains',
    'git merge-base --is-ancestor',
    'git cat-file -t',
    'actions/download-artifact@',
    'run-id: ${{ inputs.candidate_run_id }}',
    'Test-HchWorkerReleaseEvidence.ps1',
    '-RequireCandidate',
    'gh attestation verify',
    '--signer-workflow',
    '--source-digest $sourceCommit',
    '--source-ref refs/heads/main',
    '--deny-self-hosted-runners',
    'Test-HchWorkerCanaryEvidence.ps1',
    '-EvidenceSignaturePath $canarySignaturePath',
    '-ExpectedAttesterThumbprint $env:HCH_CANARY_ATTESTER_THUMBPRINT',
    '-ExpectedAttesterCertificateSha256 $env:HCH_CANARY_ATTESTER_CERTIFICATE_SHA256',
    'Verify immutable 3.1.1 bridge and independently attested fleet transition',
    "'.github/workflows/bridge-package.yml'",
    'The reviewed 3.1.1 bridge producer workflow is not implemented on protected main.',
    'Test-HchWorkerBridgeRelease.ps1',
    '-BridgeSourceCommit $bridgeSourceCommit',
    '-CmsSignerSha1 $env:HCH_SIGNER_THUMBPRINT',
    '-CmsSignerSha256 $env:HCH_SIGNER_CERTIFICATE_SHA256',
    'Test-HchWorkerFleetTransitionEvidence.ps1',
    'release-evidence/fleet/3.1.1/fleet-transition-evidence.json',
    'release-evidence/fleet/3.1.1/fleet-transition-evidence.p7s',
    'HCH_FLEET_ATTESTER_THUMBPRINT',
    'HCH_FLEET_ATTESTER_CERTIFICATE_SHA256',
    ".Replace(' ', '').ToUpperInvariant()",
    'Fleet telemetry authority must be distinct from artifact and canary signers.',
    'Fleet transition window cannot begin before the verified bridge was published.',
    'canary-evidence.p7s',
    'type: choice',
    'RELEASE_COMPATIBILITY: ${{ inputs.compatibility }}',
    'RELEASE_CONTENT_IMPACT: ${{ inputs.content_impact }}',
    'Compatibility and content-impact declarations are not an allowed exact pair.',
    'HCH-Worker-Compatibility: $env:RELEASE_COMPATIBILITY',
    'HCH-Worker-Content-Impact: $env:RELEASE_CONTENT_IMPACT',
    'Official Windows tag changed after validation; publication is refused.',
    '--latest=false',
    'gh release create')) {
    if (-not $promotion.Contains($required, [StringComparison]::Ordinal)) {
        throw "Official promotion workflow gate is missing: $required"
    }
}
if ($promotion -match 'Build-HchWorkerPackage|Repack-HchWorkerPackage|Sign-HchWorkerArtifacts') {
    throw 'Promotion workflow must never rebuild, repack or resign the candidate.'
}
if ($promotion.Contains("`$ruleTypes -ccontains 'creation'", [StringComparison]::Ordinal)) {
    throw 'Immutable tag verification must not require a no-bypass creation restriction that makes tag creation impossible.'
}
if ($promotion -match 'Compress-Archive|evidenceZip') {
    throw 'Promotion must not create and publish a post-validation unsigned evidence archive.'
}
if ($promotion -match '(?i)skip.?bridge|skip.?fleet|continue-on-error|\bTestMode\b') {
    throw 'Official promotion must not expose a bridge/fleet bypass.'
}

foreach ($required in @(
    'AddDays(-7)',
    '3.1.1',
    "Get-ReleaseOnline ''",
    'Get-ReleaseOnline $tag',
    'HCH-Worker-Compatibility',
    'HCH-Worker-Content-Impact',
    'isImmutable',
    'bridge-release-not-immutable',
    'SHA256SUMS.txt',
    'SHA256SUMS.p7s',
    'Assert-AssetMetadataLimits',
    'bridge-release-asset-size-zero',
    'bridge-release-asset-total-size-limit-exceeded',
    'Assert-GzipTarPackage',
    'bridge-release-archive-entry-count-limit-exceeded',
    'bridge-release-archive-link-or-special-entry',
    'bridge-release-archive-entrypoint-not-executable',
    'bridge-release-archive-version-invalid',
    'Assert-WindowsPackageAuthenticode',
    'TimeStamperCertificate',
    'bridge-release-windows-authenticode-sha256-pin-mismatch',
    '[Security.Cryptography.Pkcs.SignedCms]',
    '[Security.Cryptography.Pkcs.Pkcs9SigningTime]',
    "'attestation', 'verify'",
    '--signer-workflow',
    '--deny-self-hosted-runners')) {
    if (-not $bridgeRelease.Contains($required, [StringComparison]::Ordinal)) {
        throw "Compatibility bridge release gate is missing: $required"
    }
}

foreach ($required in @(
    "'hch.worker-fleet-transition/v1'",
    'hch.worker-fleet-receipt/v1',
    '[TimeSpan]::FromDays(7)',
    'AddMinutes(5)',
    '[Security.Cryptography.Pkcs.SignedCms]',
    '$cms.CheckSignature($true)',
    'ExpectedTelemetryAuthorityThumbprint',
    'ExpectedTelemetryAuthorityCertificateSha256',
    '[StringComparer]::Ordinal',
    '[Security.Cryptography.X509Certificates.X509KeyUsageFlags]::DigitalSignature',
    'platform-release-list/v1',
    'legacyLatestOnlyWorkerCount',
    'eligibleWorkerCount',
    'observedWorkerCount')) {
    if (-not $fleet.Contains($required, [StringComparison]::Ordinal)) {
        throw "Fleet transition evidence gate is missing: $required"
    }
}

foreach ($required in @(
    '[Security.Cryptography.Pkcs.SignedCms]',
    '[Security.Cryptography.Pkcs.Pkcs9SigningTime]',
    '$cert.HasPrivateKey',
    '[Security.Cryptography.X509Certificates.X509KeyUsageFlags]::DigitalSignature',
    '$cms.ComputeSignature($signer,$true)',
    'without exporting private key')) {
    if (-not $fleetSigning.Contains($required, [StringComparison]::Ordinal)) {
        throw "Controlled fleet evidence signing gate is missing: $required"
    }
}

foreach ($required in @(
    '[TimeSpan]::FromMinutes(15)',
    '[TimeSpan]::FromMinutes(5)',
    '[TimeSpan]::FromSeconds(5)',
    '[TimeSpan]::FromDays(7)',
    '$minimumHeartbeatCount = 10',
    '$maximumHeartbeatGapSeconds = 120',
    "'hch.worker-windows-canary/v2'",
    "'schema=hch.worker-canary-receipt/v1'",
    'function Assert-ReceiptSha256',
    'Get-CanonicalTimestampValue',
    'Get-CanonicalBooleanValue',
    '[Security.Cryptography.Pkcs.SignedCms]',
    '$signedCms.CheckSignature($true)',
    '$signingTime -le $completedAt',
    '$validationNow = [DateTimeOffset]::UtcNow',
    '$completedAt -gt $validationNow.Add($maximumClockSkew)',
    '$completedAt -lt $validationNow.Subtract($maximumPromotionEvidenceAge)',
    "'heartbeatSamples'",
    "'progressSamples'",
    "'completions'",
    "'failures'",
    "'rollbackReceipt'")) {
    if (-not $canary.Contains($required, [StringComparison]::Ordinal)) {
        throw "Sustained complete/fail canary gate is missing: $required"
    }
}

Assert-CanaryExactPropertyShape $canary @(
    'schema',
    'status',
    'sanitized',
    'version',
    'sourceCommit',
    'msiSha256',
    'startedAtUtc',
    'completedAtUtc',
    'gates',
    'heartbeatSamples',
    'progressSamples',
    'completions',
    'failures',
    'rollbackReceipt') 'canary evidence root'
Assert-CanaryExactPropertyShape $canary @(
    'installedPausedDrain',
    'legacyServiceStoppedDisabled',
    'enrollment',
    'bootstrap',
    'claim',
    'restartPausedDrain') 'canary evidence gates'
Assert-CanaryExactPropertyShape $canary @(
    'requestId',
    'nodeId',
    'heartbeatAt',
    'nextHeartbeatSeconds',
    'capacity',
    'serverTime',
    'receiptSha256') 'node heartbeat response receipt'
Assert-CanaryExactPropertyShape $canary @(
    'configuredCapacity',
    'requestedCapacity',
    'grantedCapacity',
    'activeAssignments',
    'availableSlots',
    'capacityClass',
    'reason',
    'grantedUntil') 'heartbeat capacity contract' -MinimumMatches 2
Assert-CanaryExactPropertyShape $canary @(
    'assignmentId',
    'observedPercent',
    'observedAtUtc',
    'requestBodySha256',
    'requestProgress',
    'response',
    'receiptSha256') 'assignment heartbeat observation receipt'
Assert-CanaryExactPropertyShape $canary @(
    'phase',
    'attempt',
    'sequence',
    'contentBytes') 'assignment heartbeat request progress'
Assert-CanaryExactPropertyShape $canary @(
    'assignmentId',
    'generationPlanHash',
    'leaseExpiresAt',
    'liveness',
    'workSizing',
    'serverTime') 'assignment heartbeat response'
Assert-CanaryExactPropertyShape $canary @(
    'state',
    'lastProgressAt',
    'staleAfterSeconds') 'assignment heartbeat liveness'
Assert-CanaryExactPropertyShape $canary @(
    'currentTier',
    'currentRank',
    'reason') 'assignment heartbeat work sizing'
Assert-CanaryExactPropertyShape $canary @(
    'assignmentId',
    'generationPlanHash',
    'commitAccepted',
    'status',
    'automaticApproval',
    'automaticPublication',
    'replayed',
    'serverTime',
    'journal',
    'receiptSha256') 'complete response plus local journal'
Assert-CanaryExactPropertyShape $canary @(
    'assignmentId',
    'generationPlanHash',
    'status',
    'replayed',
    'serverTime',
    'requestErrorCode',
    'journal',
    'receiptSha256') 'fail response plus request error and local journal'
Assert-CanaryExactPropertyShape $canary @(
    'schemaVersion',
    'assignmentId',
    'generationPlanHash',
    'phase',
    'requestId',
    'requestBodySha256',
    'draftSha256',
    'lastErrorCode',
    'updatedAtUtc') 'durable local journal' -MinimumMatches 2

foreach ($required in @(
    '[Security.Cryptography.Pkcs.SignedCms]',
    '[Security.Cryptography.Pkcs.Pkcs9SigningTime]',
    '$certificate.HasPrivateKey',
    '$signedCms.ComputeSignature($cmsSigner, $true)',
    'without exporting private key')) {
    if (-not $canarySigning.Contains($required, [StringComparison]::Ordinal)) {
        throw "Controlled canary signing gate is missing: $required"
    }
}

foreach ($required in @(
    'releases?per_page=100&page=',
    'RELEASE_PAGE_SIZE = 100',
    'MAX_RELEASE_PAGES = 10',
    'release-list-limit-exceeded',
    'RELEASE_PLATFORMS',
    'HCH-Worker-Compatibility',
    'HCH-Worker-Content-Impact')) {
    if (-not $releaseMonitorRuntimeShape.Contains($required, [StringComparison]::Ordinal)) {
        throw "Platform release discovery gate is missing: $required"
    }
}

Write-Host 'Windows candidate/canary/rollback/promotion workflow separation passed static verification.'
