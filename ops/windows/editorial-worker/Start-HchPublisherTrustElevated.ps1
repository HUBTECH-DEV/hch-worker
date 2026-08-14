[CmdletBinding()]
param()
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$installer = Join-Path $PSScriptRoot 'Install-HchPublisherTrust.ps1'
$certificate = Join-Path $PSScriptRoot 'trust\hch-windows-publisher.cer'
function Quote-HchArgument([string]$value) { '"' + $value.Replace('"', '\"') + '"' }
$arguments = @(
  '-NoLogo','-NoProfile','-ExecutionPolicy','RemoteSigned','-File',
  (Quote-HchArgument $installer),'-CertificatePath',(Quote-HchArgument $certificate)
) -join ' '
$process = Start-Process -FilePath (Join-Path $PSHOME 'powershell.exe') -Verb RunAs `
  -ArgumentList $arguments -PassThru
[pscustomobject]@{ launcherProcessId=$process.Id; certificatePath=$certificate }
