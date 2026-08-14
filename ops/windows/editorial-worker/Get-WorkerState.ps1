[CmdletBinding()]
param(
  [string]$ConfigPath = (Join-Path $PSScriptRoot 'WorkerConfig.psd1')
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'Hch.EditorialWorker.psm1') -Force
$config = Import-HchWorkerConfig -Path $ConfigPath
Get-HchWorkerKitStatus -Config $config
