[CmdletBinding()]
param(
  [string]$ConfigPath = (Join-Path $PSScriptRoot 'WorkerConfig.psd1')
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'Hch.EditorialWorker.psm1') -Force
$config = Import-HchWorkerConfig -Path $ConfigPath
$identity = Initialize-HchWorkerIdentity -Config $config

[pscustomobject]@{
  nodeId = [string]$identity.nodeId
  keyId = [string]$identity.keyId
  algorithm = [string]$identity.algorithm
  publicKeyPath = [string]$identity.publicKeyPath
  privateKeyExported = $false
  nextAction = 'Invoke-WorkerBootstrap.ps1'
}
