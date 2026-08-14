[CmdletBinding()]
param([string]$Version = '3.0.0')
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$wrapper = Join-Path $PSScriptRoot 'Invoke-HchWorkerServiceRestoreDiagnostic.ps1'
$restore = Join-Path $PSScriptRoot 'Restore-HchWorkerServiceVersion.ps1'
$config = Join-Path $PSScriptRoot 'WorkerConfig.psd1'
$result = Join-Path $env:ProgramData 'HCH\EditorialWorker\service-restore-result.json'
Remove-Item -LiteralPath $result -Force -ErrorAction SilentlyContinue
function Quote-HchArgument([string]$value) { '"' + $value.Replace('"', '\"') + '"' }
$arguments = @(
  '-NoLogo','-NoProfile','-NonInteractive','-ExecutionPolicy','RemoteSigned','-File',
  (Quote-HchArgument $wrapper),'-RestoreScriptPath',(Quote-HchArgument $restore),
  '-ConfigPath',(Quote-HchArgument $config),'-ResultPath',(Quote-HchArgument $result),
  '-Version',(Quote-HchArgument $Version)
) -join ' '
$process = Start-Process -FilePath (Join-Path $PSHOME 'powershell.exe') -Verb RunAs `
  -ArgumentList $arguments -WindowStyle Hidden -PassThru
[pscustomobject]@{ launcherProcessId=$process.Id; resultPath=$result }
