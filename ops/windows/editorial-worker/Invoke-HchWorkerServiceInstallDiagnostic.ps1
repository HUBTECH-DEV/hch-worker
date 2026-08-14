[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)][string]$InstallerPath,
  [Parameter(Mandatory = $true)][string]$ConfigPath,
  [Parameter(Mandatory = $true)][string]$ResultPath
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$record = $null
$exitCode = 0
try {
  $result = & ([IO.Path]::GetFullPath($InstallerPath)) `
    -ConfigPath ([IO.Path]::GetFullPath($ConfigPath))
  $record = [ordered]@{
    succeeded = $true
    observedAt = [DateTimeOffset]::UtcNow.ToString('o')
    serviceName = [string]$result.serviceName
    state = [string]$result.state
    errorCode = $null
    errorLine = $null
  }
} catch {
  $message = ([string]$_.Exception.Message).ToLowerInvariant() -replace '[^a-z0-9._:-]', '-'
  $message = $message.Trim('-')
  if ([string]::IsNullOrWhiteSpace($message) -or $message.Length -gt 180) {
    $message = 'worker-service-install-failed'
  }
  $record = [ordered]@{
    succeeded = $false
    observedAt = [DateTimeOffset]::UtcNow.ToString('o')
    serviceName = $null
    state = $null
    errorCode = $message
    errorLine = [int]$_.InvocationInfo.ScriptLineNumber
    errorId = ([string]$_.FullyQualifiedErrorId -replace '[^A-Za-z0-9._:-]', '-').Trim('-')
  }
  $exitCode = 1
}

$parent = Split-Path -Parent ([IO.Path]::GetFullPath($ResultPath))
if (-not (Test-Path -LiteralPath $parent -PathType Container)) {
  New-Item -ItemType Directory -Path $parent -Force | Out-Null
}
[IO.File]::WriteAllText(
  [IO.Path]::GetFullPath($ResultPath),
  ($record | ConvertTo-Json -Compress),
  [Text.UTF8Encoding]::new($false)
)
exit $exitCode
