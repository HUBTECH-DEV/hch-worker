[CmdletBinding()]
param([string]$CertificatePath = (Join-Path $PSScriptRoot 'trust\hch-windows-publisher.cer'))
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$certificate = [Security.Cryptography.X509Certificates.X509Certificate2]::new([IO.Path]::GetFullPath($CertificatePath))
function Test-Store([string]$name, [string]$thumbprint) {
  $store = [Security.Cryptography.X509Certificates.X509Store]::new($name, 'LocalMachine')
  try {
    $store.Open('ReadOnly')
    return $store.Certificates.Find('FindByThumbprint', $thumbprint, $false).Count -gt 0
  } finally { $store.Close() }
}
$root = Test-Store 'Root' $certificate.Thumbprint
$publisher = Test-Store 'TrustedPublisher' $certificate.Thumbprint
[pscustomobject]@{ trusted=($root -and $publisher); root=$root; trustedPublisher=$publisher; subject=$certificate.Subject; thumbprint=$certificate.Thumbprint }
if (-not ($root -and $publisher)) { exit 1 }
