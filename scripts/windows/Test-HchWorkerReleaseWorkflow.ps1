[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$repositoryRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\..')).Path
$ciPath = Join-Path $repositoryRoot '.github\workflows\ci.yml'
$candidatePath = Join-Path $repositoryRoot '.github\workflows\windows-package.yml'
$promotionPath = Join-Path $repositoryRoot '.github\workflows\windows-release.yml'
$bridgeWorkflowPath = Join-Path $repositoryRoot '.github\workflows\bridge-package.yml'
$canaryValidator = Join-Path $repositoryRoot 'scripts\windows\Test-HchWorkerCanaryEvidence.ps1'
$canaryExporter = Join-Path $repositoryRoot 'scripts\windows\Export-HchWorkerCanaryEvidence.ps1'
$canarySigner = Join-Path $repositoryRoot 'scripts\windows\Sign-HchWorkerCanaryEvidence.ps1'
$bridgeReleaseValidator = Join-Path $repositoryRoot 'scripts\windows\Test-HchWorkerBridgeRelease.ps1'
$bridgeArchiveBuilder = Join-Path $repositoryRoot 'scripts\windows\Build-HchWorkerBridgeArchives.ps1'
$bridgeCompleteScript = Join-Path $repositoryRoot 'scripts\windows\Complete-HchWorkerBridgePackage.ps1'
$fleetValidator = Join-Path $repositoryRoot 'scripts\windows\Test-HchWorkerFleetTransitionEvidence.ps1'
$fleetSigner = Join-Path $repositoryRoot 'scripts\windows\Sign-HchWorkerFleetTransitionEvidence.ps1'
$releaseMonitorPath = Join-Path $repositoryRoot 'ops\worker-dashboard\lib\releases.mjs'
$buildScript = Join-Path $repositoryRoot 'scripts\windows\Build-HchWorkerPackage.ps1'
$completeScript = Join-Path $repositoryRoot 'scripts\windows\Complete-HchWorkerReleaseEvidence.ps1'
$releaseEvidenceScript = Join-Path $repositoryRoot 'scripts\windows\Test-HchWorkerReleaseEvidence.ps1'
$onboardingProbe = Join-Path $repositoryRoot 'scripts\windows\Test-HchWorkerOnboardingEndpoints.ps1'
foreach ($path in $ciPath, $candidatePath, $promotionPath, $bridgeWorkflowPath, $canaryValidator, $canaryExporter, $canarySigner, $bridgeReleaseValidator, $bridgeArchiveBuilder, $bridgeCompleteScript, $fleetValidator, $fleetSigner, $releaseMonitorPath, $buildScript, $completeScript, $releaseEvidenceScript, $onboardingProbe) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "Windows release gate file is missing: $path"
    }
}

$ci = Get-Content -LiteralPath $ciPath -Raw
$candidate = Get-Content -LiteralPath $candidatePath -Raw
$promotion = Get-Content -LiteralPath $promotionPath -Raw
$bridgeWorkflow = Get-Content -LiteralPath $bridgeWorkflowPath -Raw
$canary = Get-Content -LiteralPath $canaryValidator -Raw
$canaryExport = Get-Content -LiteralPath $canaryExporter -Raw
$canarySigning = Get-Content -LiteralPath $canarySigner -Raw
$bridgeRelease = Get-Content -LiteralPath $bridgeReleaseValidator -Raw
$bridgeArchive = Get-Content -LiteralPath $bridgeArchiveBuilder -Raw
$bridgeComplete = Get-Content -LiteralPath $bridgeCompleteScript -Raw
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
    'Verify production onboarding contracts',
    './scripts/windows/Test-HchWorkerOnboardingEndpoints.ps1',
    "'.github/workflows/bridge-package.yml'",
    'The reviewed 3.1.1 bridge producer workflow is unavailable on protected main.',
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
    'release-compatibility.json',
    'hch.worker-windows-release-compatibility/v1',
    'Signed candidate compatibility declaration is invalid.',
    'RELEASE_COMPATIBILITY=$($compatibility.compatibility)',
    'RELEASE_CONTENT_IMPACT=$($compatibility.contentImpact)',
    'HCH-Worker-Compatibility: $env:RELEASE_COMPATIBILITY',
    'HCH-Worker-Content-Impact: $env:RELEASE_CONTENT_IMPACT',
    '$releaseAssets = @(Get-ChildItem -LiteralPath $releaseRoot -File',
    'Final public release inventory is incomplete.',
    'gh release create $tag @releaseAssets',
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
if ($promotion -match 'inputs\.compatibility|inputs\.content_impact') {
    throw 'Official promotion must derive compatibility from checksummed candidate evidence, not operator inputs.'
}

foreach ($required in @(
    'workflow_dispatch:',
    'inputs.publish == true',
    "BRIDGE_VERSION: '3.1.1'",
    'environment: bridge-release-signing',
    'environment: bridge-release-promotion',
    'Build-HchWorkerBridgeArchives.ps1',
    'Build-HchWorkerService.ps1',
    'Build-HchWorkerSetup.ps1',
    'Complete-HchWorkerBridgePackage.ps1',
    'Test-HchWorkerBridgeRelease.ps1',
    '-CandidateMode',
    'actions/attest-build-provenance@',
    'gh attestation verify',
    'RELEASE_IMMUTABILITY_ENFORCED',
    'gh release create v3.1.1',
    'HCH-Worker-Compatibility: compatible',
    'HCH-Worker-Content-Impact: none')) {
    if (-not $bridgeWorkflow.Contains($required, [StringComparison]::Ordinal)) {
        throw "Compatibility bridge producer gate is missing: $required"
    }
}

foreach ($required in @(
    'release-compatibility.json',
    'hch.worker-windows-release-compatibility/v1',
    'releaseCompatibilitySha256',
    'previousSupportedVersion',
    'ExpectedInformationalVersion',
    'ProductVersion -cne $ExpectedInformationalVersion',
    'sbom.spdx.json',
    'dependency-vulnerability-scan.json',
    'msi-disposable-e2e.json')) {
    if (-not $buildAndComplete.Contains($required, [StringComparison]::Ordinal)) {
        throw "Windows compatibility preparation gate is missing: $required"
    }
}
if ([regex]::Matches($buildAndComplete, [regex]::Escape('-p:IncludeSourceRevisionInInformationalVersion=false')).Count -lt 2) {
    throw 'Every native Windows publish must suppress the SDK source-revision suffix after setting the exact informational version.'
}
foreach ($required in @(
    'release-compatibility.json',
    'Release compatibility evidence is invalid or detached from provenance.',
    'releaseCompatibility',
    'releaseContentImpact',
    'Final public release inventory must be flat')) {
    if (-not (Get-Content -LiteralPath $releaseEvidenceScript -Raw).Contains($required, [StringComparison]::Ordinal)) {
        throw "Windows compatibility verification gate is missing: $required"
    }
}
if ($bridgeWorkflow -match 'pull_request_target|continue-on-error|--clobber' -or
    $bridgeWorkflow -notmatch "(?s)publish-immutable-bridge:.*inputs\.publish") {
    throw 'Compatibility bridge producer exposes an unsafe publication path.'
}
foreach ($required in @(
    "if (`$Version -cne '3.1.1')",
    'bridge-archive-reproducible-build-requires-linux',
    'GNU tar',
    '--sort=name',
    '--mtime=@$sourceEpoch',
    'bridge-archive-expanded-size-limit-exceeded',
    'sourceCommit = $SourceCommit')) {
    if (-not $bridgeArchive.Contains($required, [StringComparison]::Ordinal)) {
        throw "Compatibility bridge archive builder gate is missing: $required"
    }
}
foreach ($required in @(
    'SHA256SUMS.txt',
    'SHA256SUMS.p7s',
    '[Security.Cryptography.Pkcs.SignedCms]',
    '[Security.Cryptography.Pkcs.Pkcs9SigningTime]',
    'bridge-package-signer-sha256-mismatch',
    'HasPrivateKey')) {
    if (-not $bridgeComplete.Contains($required, [StringComparison]::Ordinal)) {
        throw "Compatibility bridge signing gate is missing: $required"
    }
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
    '[switch]$CandidateMode',
    'bridge-release-candidate-input-invalid',
    'bridge-release-candidate-actions-source-invalid',
    'Assert-WindowsPackageAuthenticode',
    'Assert-CmsSignature')) {
    if (-not $bridgeRelease.Contains($required, [StringComparison]::Ordinal)) {
        throw "Compatibility bridge candidate gate is missing: $required"
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
    'installationReceipt',
    'startedAtUtc',
    'completedAtUtc',
    'gates',
    'heartbeatSamples',
    'progressSamples',
    'completions',
    'failures',
    'rollbackReceipt') 'canary evidence root'
Assert-CanaryExactPropertyShape $canary @(
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
    'receiptSha256') 'canary installation receipt'
Assert-CanaryExactPropertyShape $canary @(
    'bootStartedAtUtc',
    'processStartedAtUtc',
    'observedAtUtc',
    'processId') 'canary installation transition'
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
