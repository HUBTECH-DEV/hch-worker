[CmdletBinding()]
param()

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$wrapper = Join-Path $PSScriptRoot 'Invoke-HchWorkerServiceInstallDiagnostic.ps1'
$rotation = Join-Path $PSScriptRoot 'Rotate-HchWorkerRootTrust.ps1'
$config = Join-Path $env:ProgramData 'HCH\EditorialWorker\config\WorkerConfig.psd1'
$result = Join-Path $env:ProgramData 'HCH\EditorialWorker\root-rotation-result.json'
Remove-Item -LiteralPath $result -Force -ErrorAction SilentlyContinue
function Quote-HchArgument([string]$Value) { return '"' + $Value.Replace('"', '\"') + '"' }
$arguments = @(
  '-NoLogo','-NoProfile','-NonInteractive','-ExecutionPolicy','RemoteSigned','-File',
  (Quote-HchArgument $wrapper),'-InstallerPath',(Quote-HchArgument $rotation),
  '-ConfigPath',(Quote-HchArgument $config),'-ResultPath',(Quote-HchArgument $result)
) -join ' '
$process = Start-Process -FilePath (Join-Path $PSHOME 'powershell.exe') -Verb RunAs `
  -ArgumentList $arguments -WindowStyle Hidden -PassThru
[pscustomobject]@{ launcherProcessId = $process.Id; resultPath = $result }
