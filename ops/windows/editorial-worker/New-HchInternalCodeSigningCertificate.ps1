[CmdletBinding(SupportsShouldProcess = $true)]
param(
  [string]$PublicCertificatePath = (Join-Path $PSScriptRoot 'trust\hch-windows-publisher.cer'),
  [ValidateRange(1, 5)][int]$ValidityYears = 2
)
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$subject = 'CN=HUBTECH CONSULTORIA E DESENVOLVIMENTO LTDA, O=HUBTECH CONSULTORIA E DESENVOLVIMENTO LTDA, C=BR'
$destination = [IO.Path]::GetFullPath($PublicCertificatePath)
if ($PSCmdlet.ShouldProcess($subject, 'create non-exportable internal code-signing identity')) {
  $certificate = New-SelfSignedCertificate `
    -Type CodeSigningCert `
    -Subject $subject `
    -FriendlyName 'HUBTECH Internal Code Signing' `
    -CertStoreLocation 'Cert:\CurrentUser\My' `
    -KeyAlgorithm RSA `
    -KeyLength 3072 `
    -HashAlgorithm SHA256 `
    -KeyExportPolicy NonExportable `
    -NotAfter (Get-Date).AddYears($ValidityYears)
  $directory = Split-Path -Parent $destination
  if (-not (Test-Path -LiteralPath $directory)) { New-Item -ItemType Directory -Path $directory -Force | Out-Null }
  Export-Certificate -Cert $certificate -FilePath $destination -Type CERT | Out-Null
  [pscustomobject]@{
    created = $true
    subject = $certificate.Subject
    thumbprint = $certificate.Thumbprint
    publicCertificatePath = $destination
    privateKeyExportable = $false
    expiresAt = $certificate.NotAfter.ToUniversalTime().ToString('o')
  }
}
