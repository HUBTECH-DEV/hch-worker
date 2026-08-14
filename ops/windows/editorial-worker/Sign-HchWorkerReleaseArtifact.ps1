[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)][string]$CertificateThumbprint,
  [string]$BinaryPath,
  [string]$SignToolPath,
  [string]$TimestampUrl = 'http://timestamp.digicert.com'
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
if ([string]::IsNullOrWhiteSpace($BinaryPath)) {
  $BinaryPath = Join-Path $PSScriptRoot 'service\bin\HchEditorialWorkerService.exe'
}
if ([string]::IsNullOrWhiteSpace($SignToolPath)) {
  $candidate = Get-ChildItem 'C:\Program Files (x86)\Windows Kits\10\bin' -Recurse -Filter signtool.exe -ErrorAction SilentlyContinue |
    Where-Object { $_.FullName -match '\\x64\\signtool\.exe$' } | Sort-Object FullName -Descending | Select-Object -First 1
  if ($null -ne $candidate) { $SignToolPath = $candidate.FullName }
}
$binary = [IO.Path]::GetFullPath($BinaryPath)
$thumbprint = $CertificateThumbprint.Replace(' ', '').ToUpperInvariant()
$certificate = Get-ChildItem ('Cert:\CurrentUser\My\' + $thumbprint) -ErrorAction SilentlyContinue
if ($null -eq $certificate) { $certificate = Get-ChildItem ('Cert:\LocalMachine\My\' + $thumbprint) -ErrorAction SilentlyContinue }
if ($null -eq $certificate -or -not $certificate.HasPrivateKey) { throw 'worker-release-signing-certificate-not-found' }
if (-not [string]::IsNullOrWhiteSpace($SignToolPath)) {
  & $SignToolPath sign /sha1 $thumbprint /fd SHA256 /tr $TimestampUrl /td SHA256 /d 'HCH Editorial Worker' $binary
  if ($LASTEXITCODE -ne 0) { throw 'worker-release-signing-failed' }
  & $SignToolPath verify /pa /all /v $binary
  if ($LASTEXITCODE -ne 0) { throw 'worker-release-signature-verification-failed' }
} else {
  $signed = Set-AuthenticodeSignature -FilePath $binary -Certificate $certificate `
    -HashAlgorithm SHA256 -TimestampServer $TimestampUrl -IncludeChain All
  if ([string]$signed.Status -notin @('Valid', 'UnknownError', 'NotTrusted')) {
    throw ('worker-release-signing-failed:' + [string]$signed.Status)
  }
}
[void](& (Join-Path $PSScriptRoot 'New-HchWorkerReleaseEvidence.ps1') -BinaryPath $binary)
$finalSignature = Get-AuthenticodeSignature -LiteralPath $binary
if ($null -eq $finalSignature.SignerCertificate -or
    [string]$finalSignature.SignerCertificate.Thumbprint -ne $thumbprint) {
  throw 'worker-release-signer-identity-mismatch'
}
if ($null -eq $finalSignature.TimeStamperCertificate) { throw 'worker-release-timestamp-required' }
if ([string]$finalSignature.Status -eq 'Valid') {
  & (Join-Path $PSScriptRoot 'Test-HchWorkerReleaseArtifact.ps1') -BinaryPath $binary -ExpectedPublisherThumbprint $thumbprint
} else {
  [pscustomobject]@{
    signed = $true
    signatureStatus = [string]$finalSignature.Status
    publisherThumbprint = $thumbprint
    awaitingLocalPublisherTrust = $true
  }
}
