[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)][string]$RestoreScriptPath,
  [Parameter(Mandatory = $true)][string]$ConfigPath,
  [Parameter(Mandatory = $true)][string]$ResultPath,
  [Parameter(Mandatory = $true)][string]$Version
)
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
try {
  $result = & $RestoreScriptPath -Version $Version -ConfigPath $ConfigPath
  $payload = [ordered]@{ succeeded=$true; observedAt=[DateTimeOffset]::UtcNow.ToString('o'); result=$result }
} catch {
  $payload = [ordered]@{ succeeded=$false; observedAt=[DateTimeOffset]::UtcNow.ToString('o'); errorCode=$_.Exception.Message; errorLine=$_.InvocationInfo.ScriptLineNumber }
}
$directory = Split-Path -Parent $ResultPath
if (-not (Test-Path -LiteralPath $directory)) { New-Item -ItemType Directory -Path $directory -Force | Out-Null }
[IO.File]::WriteAllText($ResultPath, (($payload | ConvertTo-Json -Depth 6 -Compress) + [Environment]::NewLine), [Text.UTF8Encoding]::new($false))
if (-not $payload.succeeded) { exit 1 }
