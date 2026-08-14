[CmdletBinding()]
param()

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$wrapper = Join-Path $PSScriptRoot 'Invoke-HchWorkerServiceInstallDiagnostic.ps1'
$installer = Join-Path $PSScriptRoot 'Install-HchWorkerService.ps1'
$config = Join-Path $PSScriptRoot 'WorkerConfig.psd1'
$result = Join-Path $env:ProgramData 'HCH\EditorialWorker\service-install-result.json'
Remove-Item -LiteralPath $result -Force -ErrorAction SilentlyContinue

function Quote-HchProcessArgument {
  param([Parameter(Mandatory = $true)][string]$Value)
  return '"' + $Value.Replace('"', '\"') + '"'
}

$arguments = @(
  '-NoLogo',
  '-NoProfile',
  '-NonInteractive',
  '-ExecutionPolicy',
  'RemoteSigned',
  '-File',
  (Quote-HchProcessArgument $wrapper),
  '-InstallerPath',
  (Quote-HchProcessArgument $installer),
  '-ConfigPath',
  (Quote-HchProcessArgument $config),
  '-ResultPath',
  (Quote-HchProcessArgument $result)
) -join ' '

$process = Start-Process -FilePath (Join-Path $PSHOME 'powershell.exe') `
  -Verb RunAs -ArgumentList $arguments -WindowStyle Hidden -PassThru
[pscustomobject]@{
  launcherProcessId = $process.Id
  resultPath = $result
}
