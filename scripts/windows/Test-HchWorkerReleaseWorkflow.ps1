[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$repositoryRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\..')).Path
$candidatePath = Join-Path $repositoryRoot '.github\workflows\windows-package.yml'
$promotionPath = Join-Path $repositoryRoot '.github\workflows\windows-release.yml'
$canaryValidator = Join-Path $repositoryRoot 'scripts\windows\Test-HchWorkerCanaryEvidence.ps1'
$buildScript = Join-Path $repositoryRoot 'scripts\windows\Build-HchWorkerPackage.ps1'
$completeScript = Join-Path $repositoryRoot 'scripts\windows\Complete-HchWorkerReleaseEvidence.ps1'
$releaseEvidenceScript = Join-Path $repositoryRoot 'scripts\windows\Test-HchWorkerReleaseEvidence.ps1'
foreach ($path in $candidatePath, $promotionPath, $canaryValidator, $buildScript, $completeScript, $releaseEvidenceScript) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "Windows release gate file is missing: $path"
    }
}

$candidate = Get-Content -LiteralPath $candidatePath -Raw
$promotion = Get-Content -LiteralPath $promotionPath -Raw
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

foreach ($required in @(
    'environment: windows-release-promotion',
    'WINDOWS_RELEASE_TAG_RULESET_ENFORCED',
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
    'gh release create')) {
    if (-not $promotion.Contains($required, [StringComparison]::Ordinal)) {
        throw "Official promotion workflow gate is missing: $required"
    }
}
if ($promotion -match 'Build-HchWorkerPackage|Repack-HchWorkerPackage|Sign-HchWorkerArtifacts') {
    throw 'Promotion workflow must never rebuild, repack or resign the candidate.'
}

Write-Host 'Windows candidate/canary/rollback/promotion workflow separation passed static verification.'
