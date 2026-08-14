[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)][string]$BinaryPath,
  [string]$EvidencePath,
  [string]$ExpectedPublisherThumbprint,
  [switch]$AllowUnsignedDevelopmentBuild
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$binary = [IO.Path]::GetFullPath($BinaryPath)
if ([string]::IsNullOrWhiteSpace($EvidencePath)) { $EvidencePath = $binary + '.release.json' }
$evidenceFile = [IO.Path]::GetFullPath($EvidencePath)
if (-not (Test-Path -LiteralPath $binary -PathType Leaf)) { throw 'worker-release-binary-not-found' }
if (-not (Test-Path -LiteralPath $evidenceFile -PathType Leaf)) { throw 'worker-release-evidence-not-found' }
$evidence = Get-Content -Raw -LiteralPath $evidenceFile | ConvertFrom-Json
if ([string]$evidence.schema -ne 'hch.windows-worker-artifact/v1') { throw 'worker-release-evidence-schema-invalid' }
$actualHash = (Get-FileHash -LiteralPath $binary -Algorithm SHA256).Hash.ToLowerInvariant()
if ([string]$evidence.sha256 -cne $actualHash) { throw 'worker-release-artifact-hash-mismatch' }
$version = [Diagnostics.FileVersionInfo]::GetVersionInfo($binary)
if ([string]$version.ProductName -ne 'HCH Editorial Worker' -or
    [string]$version.CompanyName -ne 'HUBTECH CONSULTORIA E DESENVOLVIMENTO LTDA') {
  throw 'worker-release-version-resource-invalid'
}
$signature = Get-AuthenticodeSignature -LiteralPath $binary
if (-not $AllowUnsignedDevelopmentBuild) {
  if ([string]$signature.Status -ne 'Valid' -or $null -eq $signature.SignerCertificate) {
    throw 'worker-release-authenticode-required'
  }
  if ($null -eq $signature.TimeStamperCertificate) { throw 'worker-release-timestamp-required' }
  if ([string]::IsNullOrWhiteSpace($ExpectedPublisherThumbprint)) {
    throw 'worker-release-publisher-thumbprint-required'
  }
  $expected = $ExpectedPublisherThumbprint.Replace(' ', '').ToUpperInvariant()
  if ([string]$signature.SignerCertificate.Thumbprint -ne $expected) {
    throw 'worker-release-publisher-mismatch'
  }
}
[pscustomobject]@{
  valid = $true
  sha256 = $actualHash
  signatureStatus = [string]$signature.Status
  publisherThumbprint = if ($null -ne $signature.SignerCertificate) { [string]$signature.SignerCertificate.Thumbprint } else { $null }
  developmentBuild = [bool]$AllowUnsignedDevelopmentBuild
}
