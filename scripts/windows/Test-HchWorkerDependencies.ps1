[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$SolutionPath,

    [Parameter(Mandatory)]
    [string]$EvidencePath
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$resolvedSolution = (Resolve-Path -LiteralPath $SolutionPath).Path
$evidenceDirectory = Split-Path -Parent ([IO.Path]::GetFullPath($EvidencePath))
New-Item -ItemType Directory -Path $evidenceDirectory -Force | Out-Null

$raw = & dotnet list $resolvedSolution package `
    --vulnerable `
    --include-transitive `
    --format json `
    --output-version 1 `
    --no-restore
if ($LASTEXITCODE -ne 0) {
    throw "NuGet vulnerability scan failed with exit code $LASTEXITCODE."
}

$jsonText = (@($raw) -join "`n").Trim()
$report = $jsonText | ConvertFrom-Json -Depth 100
$vulnerabilities = @()
function Get-OptionalProperty {
    param([Parameter(Mandatory)]$InputObject, [Parameter(Mandatory)][string]$Name)

    $property = $InputObject.PSObject.Properties[$Name]
    if ($null -eq $property) {
        return $null
    }
    return $property.Value
}
foreach ($project in @($report.projects)) {
    $frameworks = Get-OptionalProperty $project 'frameworks'
    if ($null -eq $frameworks) { continue }
    foreach ($framework in @($frameworks)) {
        $packages = @()
        $topLevelPackages = Get-OptionalProperty $framework 'topLevelPackages'
        $transitivePackages = Get-OptionalProperty $framework 'transitivePackages'
        if ($null -ne $topLevelPackages) { $packages += @($topLevelPackages) }
        if ($null -ne $transitivePackages) { $packages += @($transitivePackages) }
        foreach ($package in $packages) {
            $packageVulnerabilities = Get-OptionalProperty $package 'vulnerabilities'
            if ($null -eq $packageVulnerabilities) { continue }
            foreach ($vulnerability in @($packageVulnerabilities)) {
                $vulnerabilities += [pscustomobject]@{
                    project = $project.path
                    framework = $framework.framework
                    package = $package.id
                    resolvedVersion = $package.resolvedVersion
                    severity = $vulnerability.severity
                    advisoryUrl = $vulnerability.advisoryUrl
                }
            }
        }
    }
}

[ordered]@{
    schema = 'hch.worker-dependency-vulnerability-scan/v1'
    generatedAtUtc = [DateTimeOffset]::UtcNow.ToString('O')
    solution = $resolvedSolution
    sources = @($report.sources)
    status = if ($vulnerabilities.Count -eq 0) { 'passed' } else { 'failed' }
    vulnerabilities = @($vulnerabilities)
} | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $EvidencePath -Encoding utf8NoBOM

if ($vulnerabilities.Count -ne 0) {
    throw "NuGet vulnerability scan found $($vulnerabilities.Count) vulnerable package occurrence(s)."
}

Write-Host 'NuGet vulnerability scan passed.'
