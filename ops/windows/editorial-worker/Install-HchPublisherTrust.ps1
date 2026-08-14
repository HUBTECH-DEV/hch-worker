[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
  [string]$CertificatePath = (Join-Path $PSScriptRoot 'trust\hch-windows-publisher.cer'),
  [switch]$Force
)
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$principal = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  throw 'publisher-trust-install-requires-administrator'
}
$path = [IO.Path]::GetFullPath($CertificatePath)
if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw 'publisher-certificate-not-found' }
$certificate = [Security.Cryptography.X509Certificates.X509Certificate2]::new($path)
if ($certificate.Subject -ne 'CN=HUBTECH CONSULTORIA E DESENVOLVIMENTO LTDA, O=HUBTECH CONSULTORIA E DESENVOLVIMENTO LTDA, C=BR') {
  throw 'publisher-certificate-subject-invalid'
}
if ($certificate.NotAfter.ToUniversalTime() -le [DateTime]::UtcNow) { throw 'publisher-certificate-expired' }
$eku = @($certificate.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.37' } | ForEach-Object { $_.Format($false) }) -join ' '
if ($eku -notmatch '1\.3\.6\.1\.5\.5\.7\.3\.3|Code Signing|Assinatura de Código') {
  throw 'publisher-certificate-code-signing-eku-required'
}
$message = @"
Publicador: $($certificate.Subject)
Thumbprint SHA-1: $($certificate.Thumbprint)
Validade: $($certificate.NotBefore.ToString('u')) até $($certificate.NotAfter.ToString('u'))

Esta ação confiará em programas assinados por esta chave HUBTECH nesta máquina.
Confirme o thumbprint por um canal separado antes de continuar.
"@
Write-Host $message
if (-not $Force -and -not $PSCmdlet.ShouldContinue($message, 'Confiar no publicador HUBTECH?')) {
  throw 'publisher-trust-declined'
}
foreach ($storeName in @('Root', 'TrustedPublisher')) {
  if ($PSCmdlet.ShouldProcess(('LocalMachine\' + $storeName), ('import ' + $certificate.Thumbprint))) {
    $store = [Security.Cryptography.X509Certificates.X509Store]::new($storeName, 'LocalMachine')
    try { $store.Open('ReadWrite'); $store.Add($certificate) } finally { $store.Close() }
  }
}
[pscustomobject]@{ trusted=$true; subject=$certificate.Subject; thumbprint=$certificate.Thumbprint; scope='LocalMachine' }
