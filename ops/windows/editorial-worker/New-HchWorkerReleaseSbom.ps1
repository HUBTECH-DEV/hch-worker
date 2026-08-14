[CmdletBinding()]
param(
  [string]$RepositoryRoot = (Join-Path $PSScriptRoot '..\..\..'),
  [string]$OutputPath = (Join-Path $PSScriptRoot 'service\bin\hch-worker-windows.cdx.json')
)
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$root = [IO.Path]::GetFullPath($RepositoryRoot)
$output = [IO.Path]::GetFullPath($OutputPath)
$version = (Get-Content -Raw -LiteralPath (Join-Path $PSScriptRoot 'VERSION')).Trim()
$includedRoots = @(
  (Join-Path $root 'ops\windows\editorial-worker'),
  (Join-Path $root 'ops\worker-dashboard'),
  (Join-Path $root 'lib\editorial-policy.mjs')
)
$files = foreach ($included in $includedRoots) {
  if (Test-Path -LiteralPath $included -PathType Leaf) { Get-Item -LiteralPath $included }
  elseif (Test-Path -LiteralPath $included -PathType Container) {
    Get-ChildItem -LiteralPath $included -File -Recurse | Where-Object {
      $_.FullName -notmatch '[\\/]tests?[\\/]' -and
      $_.Name -notin @('WorkerConfig.psd1', 'hch-worker-windows.cdx.json')
    }
  }
}
$components = @($files | Sort-Object FullName -Unique | ForEach-Object {
  $relative = $_.FullName.Substring($root.Length).TrimStart('\','/').Replace('\','/')
  [ordered]@{
    type = 'file'
    name = $relative
    'bom-ref' = 'file:' + $relative
    hashes = @([ordered]@{ alg='SHA-256'; content=(Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant() })
  }
})
$bom = [ordered]@{
  bomFormat = 'CycloneDX'
  specVersion = '1.5'
  serialNumber = 'urn:uuid:' + [guid]::NewGuid().ToString()
  version = 1
  metadata = [ordered]@{
    timestamp = [DateTimeOffset]::UtcNow.ToString('o')
    component = [ordered]@{ type='application'; name='HCH Editorial Worker for Windows'; version=$version }
  }
  components = $components
}
$directory = Split-Path -Parent $output
if (-not (Test-Path -LiteralPath $directory)) { New-Item -ItemType Directory -Path $directory -Force | Out-Null }
[IO.File]::WriteAllText($output, (($bom | ConvertTo-Json -Depth 8) + [Environment]::NewLine), [Text.UTF8Encoding]::new($false))
[pscustomobject]@{ generated=$true; outputPath=$output; componentCount=$components.Count }
