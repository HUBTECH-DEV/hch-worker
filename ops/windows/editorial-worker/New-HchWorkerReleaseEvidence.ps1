[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)][string]$BinaryPath,
  [string]$OutputPath
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$binary = [IO.Path]::GetFullPath($BinaryPath)
if (-not (Test-Path -LiteralPath $binary -PathType Leaf)) { throw 'worker-release-binary-not-found' }
if ([string]::IsNullOrWhiteSpace($OutputPath)) { $OutputPath = $binary + '.release.json' }
$output = [IO.Path]::GetFullPath($OutputPath)
$signature = Get-AuthenticodeSignature -LiteralPath $binary
$version = [Diagnostics.FileVersionInfo]::GetVersionInfo($binary)
$evidence = [ordered]@{
  schema = 'hch.windows-worker-artifact/v1'
  fileName = [IO.Path]::GetFileName($binary)
  sha256 = (Get-FileHash -LiteralPath $binary -Algorithm SHA256).Hash.ToLowerInvariant()
  productName = [string]$version.ProductName
  fileVersion = [string]$version.FileVersion
  companyName = [string]$version.CompanyName
  signatureStatus = [string]$signature.Status
  publisherSubject = if ($null -ne $signature.SignerCertificate) { [string]$signature.SignerCertificate.Subject } else { $null }
  publisherThumbprint = if ($null -ne $signature.SignerCertificate) { [string]$signature.SignerCertificate.Thumbprint } else { $null }
  timestampSubject = if ($null -ne $signature.TimeStamperCertificate) { [string]$signature.TimeStamperCertificate.Subject } else { $null }
}
$json = $evidence | ConvertTo-Json -Depth 4
[IO.File]::WriteAllText($output, $json + [Environment]::NewLine, [Text.UTF8Encoding]::new($false))
$evidence
