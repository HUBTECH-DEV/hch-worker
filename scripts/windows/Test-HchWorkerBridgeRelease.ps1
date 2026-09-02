[CmdletBinding()]
param(
  [string]$Repository = 'HUBTECH-DEV/hch-worker',
  [string]$Version = '3.1.1',
  [Parameter(Mandatory = $true)]
  [ValidatePattern('^[0-9a-f]{40}$')]
  [string]$BridgeSourceCommit,
  [Parameter(Mandatory = $true)]
  [ValidatePattern('^[0-9A-Fa-f]{40}$')]
  [string]$CmsSignerSha1,
  [Parameter(Mandatory = $true)]
  [ValidatePattern('^[0-9A-Fa-f]{64}$')]
  [string]$CmsSignerSha256,
  [switch]$TestMode,
  [string]$LatestReleaseJsonPath,
  [string]$TaggedReleaseJsonPath,
  [string]$AssetDirectory,
  [ValidateSet('tag', 'commit')]
  [string]$OfflineTagObjectType = 'tag',
  [string]$OfflineTagCommit,
  [ValidateSet('true', 'false')]
  [string]$OfflineCommitIsMainAncestor = 'true',
  [switch]$SkipAuthenticodeVerification,
  [switch]$SkipCmsVerification,
  [switch]$SkipAttestationVerification
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Stop-BridgeReleaseGate {
  param([Parameter(Mandatory = $true)][string]$Code)
  throw $Code
}

function Assert-RegularFile {
  param([Parameter(Mandatory = $true)][string]$Path)
  if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
    Stop-BridgeReleaseGate 'bridge-release-file-missing'
  }
  $item = Get-Item -LiteralPath $Path -Force
  if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
    Stop-BridgeReleaseGate 'bridge-release-reparse-point-rejected'
  }
  return $item
}

function Invoke-CheckedNative {
  param(
    [Parameter(Mandatory = $true)][string]$Command,
    [Parameter(Mandatory = $true)][string[]]$Arguments
  )
  try {
    $output = & $Command @Arguments 2>&1
  } catch {
    Stop-BridgeReleaseGate ("bridge-release-native-command-failed:{0}" -f $Command)
  }
  if ($LASTEXITCODE -ne 0) {
    Stop-BridgeReleaseGate ("bridge-release-native-command-failed:{0}" -f $Command)
  }
  return ($output -join "`n")
}

function Get-Sha256Hex {
  param([Parameter(Mandatory = $true)][string]$Path)
  $stream = [IO.File]::OpenRead($Path)
  try {
    $algorithm = [Security.Cryptography.SHA256]::Create()
    try {
      return ([BitConverter]::ToString($algorithm.ComputeHash($stream))).Replace('-', '').ToLowerInvariant()
    } finally {
      $algorithm.Dispose()
    }
  } finally {
    $stream.Dispose()
  }
}

function Read-ReleaseJson {
  param([Parameter(Mandatory = $true)][string]$Path)
  $null = Assert-RegularFile $Path
  try {
    return (Get-Content -Raw -LiteralPath $Path | ConvertFrom-Json)
  } catch {
    Stop-BridgeReleaseGate 'bridge-release-json-invalid'
  }
}

function Get-ReleaseOnline {
  param([string]$Tag)
  $arguments = @('release', 'view')
  if ($Tag) { $arguments += $Tag }
  $arguments += @('--repo', $Repository, '--json', 'databaseId,id,tagName,isDraft,isPrerelease,isImmutable,publishedAt,body,assets')
  $json = Invoke-CheckedNative 'gh' $arguments
  try { return ($json | ConvertFrom-Json) } catch { Stop-BridgeReleaseGate 'bridge-release-gh-json-invalid' }
}

function Get-AssetMap {
  param([Parameter(Mandatory = $true)]$Release)
  $map = @{}
  foreach ($asset in @($Release.assets)) {
    $name = [string]$asset.name
    $id = [string]$asset.id
    $size = 0L
    $sizeText = [string]$asset.size
    if ($sizeText -cnotmatch '^(0|[1-9][0-9]*)$' -or
        -not [Int64]::TryParse($sizeText, [ref]$size)) {
      Stop-BridgeReleaseGate 'bridge-release-asset-size-invalid'
    }
    if ([string]::IsNullOrWhiteSpace($name) -or [string]::IsNullOrWhiteSpace($id) -or $map.ContainsKey($name)) {
      Stop-BridgeReleaseGate 'bridge-release-asset-identity-invalid'
    }
    $map[$name] = [pscustomobject]@{ id = $id; name = $name; size = $size }
  }
  return $map
}

function Assert-ReleaseMetadata {
  param($Latest, $Tagged, [string]$ExpectedTag)
  if ([string]::IsNullOrWhiteSpace([string]$Latest.databaseId) -or
      [string]::IsNullOrWhiteSpace([string]$Latest.id) -or
      [string]$Latest.databaseId -ne [string]$Tagged.databaseId -or
      [string]$Latest.id -ne [string]$Tagged.id -or
      [string]$Latest.tagName -ne $ExpectedTag -or
      [string]$Tagged.tagName -ne $ExpectedTag -or
      [string]$Latest.publishedAt -ne [string]$Tagged.publishedAt -or
      [string]$Latest.body -cne [string]$Tagged.body) {
    Stop-BridgeReleaseGate 'bridge-release-latest-tag-identity-mismatch'
  }
  if ([bool]$Latest.isDraft -or [bool]$Tagged.isDraft -or
      [bool]$Latest.isPrerelease -or [bool]$Tagged.isPrerelease) {
    Stop-BridgeReleaseGate 'bridge-release-not-stable'
  }
  $latestImmutable = $Latest.PSObject.Properties['isImmutable']
  $taggedImmutable = $Tagged.PSObject.Properties['isImmutable']
  if ($null -eq $latestImmutable -or $null -eq $taggedImmutable -or
      $latestImmutable.Value -isnot [bool] -or $taggedImmutable.Value -isnot [bool] -or
      -not [bool]$latestImmutable.Value -or -not [bool]$taggedImmutable.Value) {
    Stop-BridgeReleaseGate 'bridge-release-not-immutable'
  }
  $published = [DateTimeOffset]::MinValue
  if (-not [DateTimeOffset]::TryParse([string]$Tagged.publishedAt, [Globalization.CultureInfo]::InvariantCulture,
      [Globalization.DateTimeStyles]::AssumeUniversal, [ref]$published)) {
    Stop-BridgeReleaseGate 'bridge-release-published-at-invalid'
  }
  if ($published.ToUniversalTime() -gt [DateTimeOffset]::UtcNow.AddDays(-7)) {
    Stop-BridgeReleaseGate 'bridge-release-too-recent'
  }

  $compatibilityMarkers = @([Regex]::Matches(
      [string]$Tagged.body,
      '^[ \t]*HCH-Worker-Compatibility:[ \t]*([a-z-]+)[ \t]*$',
      [Text.RegularExpressions.RegexOptions]::IgnoreCase -bor [Text.RegularExpressions.RegexOptions]::Multiline))
  $impactMarkers = @([Regex]::Matches(
      [string]$Tagged.body,
      '^[ \t]*HCH-Worker-Content-Impact:[ \t]*([a-z-]+)[ \t]*$',
      [Text.RegularExpressions.RegexOptions]::IgnoreCase -bor [Text.RegularExpressions.RegexOptions]::Multiline))
  if ($compatibilityMarkers.Count -gt 1 -or $impactMarkers.Count -gt 1) {
    Stop-BridgeReleaseGate 'bridge-release-notes-contract-duplicated'
  }
  if ($compatibilityMarkers.Count -ne 1 -or $impactMarkers.Count -ne 1 -or
      $compatibilityMarkers[0].Groups[1].Value.ToLowerInvariant() -cne 'compatible' -or
      $impactMarkers[0].Groups[1].Value.ToLowerInvariant() -cne 'none') {
    Stop-BridgeReleaseGate 'bridge-release-notes-contract-invalid'
  }
}

function Assert-AssetInventory {
  param($Latest, $Tagged, [string[]]$ExpectedNames)
  $latestMap = Get-AssetMap $Latest
  $taggedMap = Get-AssetMap $Tagged
  $actual = @($taggedMap.Keys | Sort-Object)
  $expected = @($ExpectedNames | Sort-Object)
  if (($actual -join "`n") -cne ($expected -join "`n") -or
      (@($latestMap.Keys | Sort-Object) -join "`n") -cne ($expected -join "`n")) {
    Stop-BridgeReleaseGate 'bridge-release-asset-inventory-invalid'
  }
  foreach ($name in $expected) {
    if ($latestMap[$name].id -ne $taggedMap[$name].id -or
        $latestMap[$name].name -cne $taggedMap[$name].name -or
        $latestMap[$name].size -ne $taggedMap[$name].size) {
      Stop-BridgeReleaseGate 'bridge-release-asset-metadata-mismatch'
    }
  }
  return $taggedMap
}

function Assert-AssetMetadataLimits {
  param(
    [Parameter(Mandatory = $true)][hashtable]$AssetMap,
    [Parameter(Mandatory = $true)][string[]]$PackageNames
  )

  $maximumBytesByName = [Collections.Generic.Dictionary[string, Int64]]::new([StringComparer]::Ordinal)
  $maximumBytesByName[$PackageNames[0]] = 512MB
  $maximumBytesByName[$PackageNames[1]] = 512MB
  $maximumBytesByName[$PackageNames[2]] = 512MB
  $maximumBytesByName['SHA256SUMS.txt'] = 64KB
  $maximumBytesByName['SHA256SUMS.p7s'] = 2MB
  $maximumTotalBytes = 1280MB
  $totalBytes = 0L

  foreach ($entry in $maximumBytesByName.GetEnumerator()) {
    if (-not $AssetMap.ContainsKey($entry.Key)) {
      Stop-BridgeReleaseGate 'bridge-release-asset-inventory-invalid'
    }
    $size = [Int64]$AssetMap[$entry.Key].size
    if ($size -le 0) {
      Stop-BridgeReleaseGate 'bridge-release-asset-size-zero'
    }
    if ($size -gt $entry.Value) {
      Stop-BridgeReleaseGate 'bridge-release-asset-size-limit-exceeded'
    }
    if ($totalBytes -gt ([Int64]::MaxValue - $size)) {
      Stop-BridgeReleaseGate 'bridge-release-asset-total-size-invalid'
    }
    $totalBytes += $size
  }
  if ($totalBytes -gt $maximumTotalBytes) {
    Stop-BridgeReleaseGate 'bridge-release-asset-total-size-limit-exceeded'
  }
  return $totalBytes
}

function Assert-TagContractOnline {
  param([string]$Tag, [string]$ExpectedCommit, [string]$Directory)
  Invoke-CheckedNative 'git' @('-C', $Directory, 'init', '--quiet') | Out-Null
  Invoke-CheckedNative 'git' @('-C', $Directory, '-c', 'core.hooksPath=NUL', 'remote', 'add', 'origin', "https://github.com/$Repository.git") | Out-Null
  Invoke-CheckedNative 'git' @('-C', $Directory, '-c', 'core.hooksPath=NUL', '-c', 'protocol.file.allow=never', 'fetch', '--quiet', '--no-tags', 'origin', "refs/tags/$Tag`:refs/tags/$Tag") | Out-Null
  $type = (Invoke-CheckedNative 'git' @('-C', $Directory, 'cat-file', '-t', "refs/tags/$Tag")).Trim()
  if ($type -cne 'tag') { Stop-BridgeReleaseGate 'bridge-release-tag-not-annotated' }
  $commit = (Invoke-CheckedNative 'git' @('-C', $Directory, 'rev-parse', "refs/tags/$Tag`^{commit}")).Trim().ToLowerInvariant()
  if ($commit -cne $ExpectedCommit) { Stop-BridgeReleaseGate 'bridge-release-tag-commit-mismatch' }
  Invoke-CheckedNative 'git' @('-C', $Directory, '-c', 'core.hooksPath=NUL', '-c', 'protocol.file.allow=never', 'fetch', '--quiet', '--no-tags', 'origin', '+refs/heads/main:refs/remotes/origin/main') | Out-Null
  & git -C $Directory merge-base --is-ancestor $ExpectedCommit refs/remotes/origin/main
  if ($LASTEXITCODE -ne 0) { Stop-BridgeReleaseGate 'bridge-release-commit-not-main-ancestor' }
}

function Assert-TagContractOffline {
  param([string]$ExpectedCommit)
  if ($OfflineTagObjectType -cne 'tag') { Stop-BridgeReleaseGate 'bridge-release-tag-not-annotated' }
  if ($OfflineTagCommit -notmatch '^[0-9a-f]{40}$' -or $OfflineTagCommit -cne $ExpectedCommit) {
    Stop-BridgeReleaseGate 'bridge-release-tag-commit-mismatch'
  }
  if ($OfflineCommitIsMainAncestor -cne 'true') {
    Stop-BridgeReleaseGate 'bridge-release-commit-not-main-ancestor'
  }
}

function Assert-DownloadedAssets {
  param([string]$Directory, [hashtable]$AssetMap, [string[]]$ExpectedNames)
  $entries = @(Get-ChildItem -LiteralPath $Directory -Force)
  if (@($entries | Where-Object { $_.PSIsContainer }).Count -ne 0) {
    Stop-BridgeReleaseGate 'bridge-release-downloaded-inventory-invalid'
  }
  $files = @($entries | Where-Object { -not $_.PSIsContainer })
  $actual = @($files.Name | Sort-Object)
  $expected = @($ExpectedNames | Sort-Object)
  if (($actual -join "`n") -cne ($expected -join "`n")) {
    Stop-BridgeReleaseGate 'bridge-release-downloaded-inventory-invalid'
  }
  foreach ($file in $files) {
    if ([Int64]$file.Length -ne [Int64]$AssetMap[$file.Name].size) {
      Stop-BridgeReleaseGate 'bridge-release-downloaded-size-mismatch'
    }
  }
}

function Assert-Checksums {
  param([string]$Directory, [string[]]$Packages)
  $checksumPath = Join-Path $Directory 'SHA256SUMS.txt'
  $null = Assert-RegularFile $checksumPath
  $raw = Get-Content -Raw -LiteralPath $checksumPath
  $normalized = $raw.Replace("`r`n", "`n")
  if ($normalized.Contains("`r") -or -not $normalized.EndsWith("`n")) {
    Stop-BridgeReleaseGate 'bridge-release-checksum-format-invalid'
  }
  $payload = $normalized.Substring(0, $normalized.Length - 1)
  if ($payload.EndsWith("`n") -or $payload.Length -eq 0) {
    Stop-BridgeReleaseGate 'bridge-release-checksum-format-invalid'
  }
  $lines = @($payload -split "`n")
  if ($lines.Count -ne $Packages.Count) { Stop-BridgeReleaseGate 'bridge-release-checksum-count-invalid' }
  $packageSet = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
  foreach ($package in $Packages) { [void]$packageSet.Add($package) }
  $seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
  foreach ($line in $lines) {
    if ($line -cnotmatch '^([0-9A-Fa-f]{64})  ([A-Za-z0-9][A-Za-z0-9._-]*)$') {
      Stop-BridgeReleaseGate 'bridge-release-checksum-format-invalid'
    }
    $hash = $Matches[1].ToLowerInvariant()
    $name = $Matches[2]
    if (-not $packageSet.Contains($name) -or -not $seen.Add($name)) {
      Stop-BridgeReleaseGate 'bridge-release-checksum-inventory-invalid'
    }
    $path = Join-Path $Directory $name
    $null = Assert-RegularFile $path
    if ((Get-Sha256Hex $path) -cne $hash) {
      Stop-BridgeReleaseGate 'bridge-release-checksum-mismatch'
    }
  }
  foreach ($name in $Packages) {
    if (-not $seen.Contains($name)) { Stop-BridgeReleaseGate 'bridge-release-checksum-missing' }
  }
}

function Get-TarCommand {
  foreach ($name in @('bsdtar', 'tar')) {
    $command = Get-Command $name -CommandType Application -ErrorAction SilentlyContinue |
      Select-Object -First 1
    if ($null -ne $command -and -not [string]::IsNullOrWhiteSpace([string]$command.Source)) {
      return [string]$command.Source
    }
  }
  Stop-BridgeReleaseGate 'bridge-release-archive-tool-missing'
}

function Convert-ArchiveListingToLines {
  param([AllowEmptyString()][string]$Listing)
  if ([string]::IsNullOrEmpty($Listing)) { return @() }
  return @($Listing -split "`n")
}

function Assert-SafeArchiveEntryName {
  param([Parameter(Mandatory = $true)][string]$Name)

  if ([string]::IsNullOrWhiteSpace($Name) -or $Name.Length -gt 512 -or
      $Name -match '[\x00-\x1f\x7f]' -or $Name.Contains('\') -or
      $Name.StartsWith('/') -or $Name.StartsWith('~') -or
      $Name -match '^[A-Za-z]:' -or $Name.Contains('//')) {
    Stop-BridgeReleaseGate 'bridge-release-archive-entry-name-unsafe'
  }
  $canonical = $Name.TrimEnd([char]'/')
  if ([string]::IsNullOrWhiteSpace($canonical) -or
      ($canonical -cne 'hch-worker' -and -not $canonical.StartsWith('hch-worker/', [StringComparison]::Ordinal))) {
    Stop-BridgeReleaseGate 'bridge-release-archive-entry-name-unsafe'
  }
  foreach ($segment in @($canonical -split '/')) {
    if ($segment.Length -eq 0 -or $segment.Length -gt 128 -or
        $segment -ceq '.' -or $segment -ceq '..' -or
        $segment.EndsWith('.') -or
        $segment -imatch '^(?:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\.|$)' -or
        $segment -cnotmatch '^[A-Za-z0-9][A-Za-z0-9._-]*$') {
      Stop-BridgeReleaseGate 'bridge-release-archive-entry-name-unsafe'
    }
  }
  return $canonical
}

function Get-BridgeArchiveContract {
  param([Parameter(Mandatory = $true)][ValidateSet('linux', 'macos')][string]$Platform)

  $requiredFiles = @(
    'hch-worker/VERSION',
    'hch-worker/ops/linux/editorial-worker/worker.mjs',
    'hch-worker/ops/worker-dashboard/server.mjs'
  )
  $executableFiles = @('hch-worker/ops/linux/editorial-worker/worker.mjs')
  if ($Platform -ceq 'linux') {
    $requiredFiles += @(
      'hch-worker/scripts/hch-editorial-workerctl',
      'hch-worker/ops/systemd/hch-editorial-worker.service'
    )
    $executableFiles += 'hch-worker/scripts/hch-editorial-workerctl'
  } else {
    $requiredFiles += @(
      'hch-worker/ops/macos/editorial-worker/hch-editorial-workerctl',
      'hch-worker/ops/macos/editorial-worker/install-launch-agents.sh',
      'hch-worker/ops/macos/editorial-worker/launchd/online.hubtech.hch.editorial-worker.cycle.plist.in'
    )
    $executableFiles += @(
      'hch-worker/ops/macos/editorial-worker/hch-editorial-workerctl',
      'hch-worker/ops/macos/editorial-worker/install-launch-agents.sh'
    )
  }
  return [pscustomobject]@{
    requiredFiles = [string[]]$requiredFiles
    executableFiles = [string[]]$executableFiles
  }
}

function Assert-GzipTarPackage {
  param(
    [Parameter(Mandatory = $true)][string]$Path,
    [Parameter(Mandatory = $true)][ValidateSet('linux', 'macos')][string]$Platform,
    [Parameter(Mandatory = $true)][string]$ExpectedVersion,
    [Parameter(Mandatory = $true)][string]$TarCommand
  )

  $archiveItem = Assert-RegularFile $Path
  if ($archiveItem.Length -le 0) {
    Stop-BridgeReleaseGate 'bridge-release-archive-empty'
  }
  $header = [byte[]]::new(2)
  $stream = [IO.File]::OpenRead($archiveItem.FullName)
  try {
    if ($stream.Read($header, 0, $header.Length) -ne $header.Length -or
        $header[0] -ne 0x1f -or $header[1] -ne 0x8b) {
      Stop-BridgeReleaseGate 'bridge-release-archive-gzip-invalid'
    }
  } finally {
    $stream.Dispose()
  }

  $archiveHashBefore = Get-Sha256Hex $archiveItem.FullName
  $names = @(Convert-ArchiveListingToLines (
      Invoke-CheckedNative $TarCommand @('-tzf', $archiveItem.FullName)))
  if ($names.Count -eq 0) {
    Stop-BridgeReleaseGate 'bridge-release-archive-empty'
  }
  if ($names.Count -gt 4096) {
    Stop-BridgeReleaseGate 'bridge-release-archive-entry-count-limit-exceeded'
  }
  $verboseLines = @(Convert-ArchiveListingToLines (
      Invoke-CheckedNative $TarCommand @('-tvzf', $archiveItem.FullName)))
  if ($verboseLines.Count -ne $names.Count) {
    Stop-BridgeReleaseGate 'bridge-release-archive-listing-ambiguous'
  }

  $entryModes = [Collections.Generic.Dictionary[string, string]]::new([StringComparer]::Ordinal)
  $caseFoldedNames = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
  foreach ($index in 0..($names.Count - 1)) {
    $canonical = Assert-SafeArchiveEntryName $names[$index]
    if ($entryModes.ContainsKey($canonical) -or -not $caseFoldedNames.Add($canonical)) {
      Stop-BridgeReleaseGate 'bridge-release-archive-entry-duplicate'
    }
    $verbose = [string]$verboseLines[$index]
    if ($verbose.Length -lt 11) {
      Stop-BridgeReleaseGate 'bridge-release-archive-listing-ambiguous'
    }
    $mode = $verbose.Substring(0, 10)
    if ($mode[0] -ne '-' -and $mode[0] -ne 'd') {
      Stop-BridgeReleaseGate 'bridge-release-archive-link-or-special-entry'
    }
    if ($mode.Substring(1) -cnotmatch '^[r-][w-][xsS-][r-][w-][xsS-][r-][w-][xtT-]$') {
      Stop-BridgeReleaseGate 'bridge-release-archive-listing-ambiguous'
    }
    if ($canonical -ceq 'hch-worker' -and $mode[0] -ne 'd') {
      Stop-BridgeReleaseGate 'bridge-release-archive-entry-name-unsafe'
    }
    $entryModes.Add($canonical, $mode)
  }

  $contract = Get-BridgeArchiveContract $Platform
  foreach ($required in $contract.requiredFiles) {
    if (-not $entryModes.ContainsKey($required) -or $entryModes[$required][0] -ne '-') {
      Stop-BridgeReleaseGate 'bridge-release-archive-layout-invalid'
    }
  }
  foreach ($executable in $contract.executableFiles) {
    $ownerExecute = $entryModes[$executable][3]
    if ($ownerExecute -ne 'x' -and $ownerExecute -ne 's') {
      Stop-BridgeReleaseGate 'bridge-release-archive-entrypoint-not-executable'
    }
  }

  $inspectionRoot = Join-Path ([IO.Path]::GetTempPath()) (
    'hch-worker-bridge-archive-{0}' -f [Guid]::NewGuid().ToString('N'))
  try {
    $null = New-Item -ItemType Directory -Path $inspectionRoot
    $extractArguments = @('-xzf', $archiveItem.FullName, '-C', $inspectionRoot, '--') +
      [string[]]$contract.requiredFiles
    Invoke-CheckedNative $TarCommand $extractArguments | Out-Null
    foreach ($item in @(Get-ChildItem -LiteralPath $inspectionRoot -Force -Recurse)) {
      if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        Stop-BridgeReleaseGate 'bridge-release-archive-extracted-reparse-point'
      }
    }
    foreach ($required in $contract.requiredFiles) {
      $nativeRelative = $required.Replace([char]'/', [IO.Path]::DirectorySeparatorChar)
      $extractedPath = Join-Path $inspectionRoot $nativeRelative
      $extracted = Assert-RegularFile $extractedPath
      if ($extracted.Length -le 0) {
        Stop-BridgeReleaseGate 'bridge-release-archive-required-file-empty'
      }
    }
    $versionPath = Join-Path $inspectionRoot (
      'hch-worker/VERSION'.Replace([char]'/', [IO.Path]::DirectorySeparatorChar))
    $actualVersionBytes = [IO.File]::ReadAllBytes($versionPath)
    $expectedVersionBytes = [Text.Encoding]::ASCII.GetBytes("$ExpectedVersion`n")
    if ($actualVersionBytes.Length -ne $expectedVersionBytes.Length) {
      Stop-BridgeReleaseGate 'bridge-release-archive-version-invalid'
    }
    for ($index = 0; $index -lt $expectedVersionBytes.Length; $index++) {
      if ($actualVersionBytes[$index] -ne $expectedVersionBytes[$index]) {
        Stop-BridgeReleaseGate 'bridge-release-archive-version-invalid'
      }
    }
  } finally {
    if (Test-Path -LiteralPath $inspectionRoot) {
      Remove-Item -LiteralPath $inspectionRoot -Recurse -Force
    }
  }
  if ((Get-Sha256Hex $archiveItem.FullName) -cne $archiveHashBefore) {
    Stop-BridgeReleaseGate 'bridge-release-archive-mutated-during-validation'
  }
}

function Assert-WindowsPackageAuthenticode {
  param([Parameter(Mandatory = $true)][string]$Path)

  $null = Assert-RegularFile $Path
  $signature = Get-AuthenticodeSignature -LiteralPath $Path
  if ([string]$signature.Status -cne 'Valid' -or $null -eq $signature.SignerCertificate) {
    Stop-BridgeReleaseGate 'bridge-release-windows-authenticode-invalid'
  }
  $certificate = $signature.SignerCertificate
  if ($certificate.Thumbprint.Replace(' ', '').ToUpperInvariant() -cne $CmsSignerSha1.ToUpperInvariant()) {
    Stop-BridgeReleaseGate 'bridge-release-windows-authenticode-sha1-pin-mismatch'
  }
  $certificateSha256 = [Convert]::ToHexString(
    $certificate.GetCertHash([Security.Cryptography.HashAlgorithmName]::SHA256))
  if ($certificateSha256 -cne $CmsSignerSha256.ToUpperInvariant()) {
    Stop-BridgeReleaseGate 'bridge-release-windows-authenticode-sha256-pin-mismatch'
  }
  if ($null -eq $signature.TimeStamperCertificate) {
    Stop-BridgeReleaseGate 'bridge-release-windows-authenticode-timestamp-missing'
  }
  $ekuExtensions = @($certificate.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.37' })
  if ($ekuExtensions.Count -ne 1) {
    Stop-BridgeReleaseGate 'bridge-release-windows-authenticode-code-signing-eku-invalid'
  }
  $eku = if ($ekuExtensions[0] -is [Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]) {
    $ekuExtensions[0]
  } else {
    [Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]::new(
      $ekuExtensions[0],
      $ekuExtensions[0].Critical)
  }
  if ($eku.EnhancedKeyUsages.Count -ne 1 -or
      $eku.EnhancedKeyUsages[0].Value -cne '1.3.6.1.5.5.7.3.3') {
    Stop-BridgeReleaseGate 'bridge-release-windows-authenticode-code-signing-eku-invalid'
  }
  $keyUsageExtensions = @($certificate.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.15' })
  if ($keyUsageExtensions.Count -gt 1) {
    Stop-BridgeReleaseGate 'bridge-release-windows-authenticode-key-usage-invalid'
  }
  if ($keyUsageExtensions.Count -eq 1) {
    $keyUsage = if ($keyUsageExtensions[0] -is [Security.Cryptography.X509Certificates.X509KeyUsageExtension]) {
      $keyUsageExtensions[0]
    } else {
      [Security.Cryptography.X509Certificates.X509KeyUsageExtension]::new(
        $keyUsageExtensions[0],
        $keyUsageExtensions[0].Critical)
    }
    if (($keyUsage.KeyUsages -band
        [Security.Cryptography.X509Certificates.X509KeyUsageFlags]::DigitalSignature) -eq 0) {
      Stop-BridgeReleaseGate 'bridge-release-windows-authenticode-key-usage-invalid'
    }
  }
}

function Assert-CmsSignature {
  param([string]$Directory)
  Add-Type -AssemblyName System.Security.Cryptography.Pkcs
  $checksumPath = Join-Path $Directory 'SHA256SUMS.txt'
  $signaturePath = Join-Path $Directory 'SHA256SUMS.p7s'
  $null = Assert-RegularFile $checksumPath
  $null = Assert-RegularFile $signaturePath
  $content = [IO.File]::ReadAllBytes($checksumPath)
  $signature = [IO.File]::ReadAllBytes($signaturePath)
  $contentInfo = [Security.Cryptography.Pkcs.ContentInfo]::new($content)
  $cms = [Security.Cryptography.Pkcs.SignedCms]::new($contentInfo, $true)
  try {
    $cms.Decode($signature)
    if (-not $cms.Detached) { Stop-BridgeReleaseGate 'bridge-release-cms-not-detached' }
    $cms.CheckSignature($true)
  } catch {
    Stop-BridgeReleaseGate 'bridge-release-cms-signature-invalid'
  }
  if ($cms.SignerInfos.Count -ne 1) { Stop-BridgeReleaseGate 'bridge-release-cms-signer-count-invalid' }
  $signer = $cms.SignerInfos[0]
  if ($null -eq $signer.Certificate) { Stop-BridgeReleaseGate 'bridge-release-cms-certificate-missing' }
  $allowedDigests = @('2.16.840.1.101.3.4.2.1', '2.16.840.1.101.3.4.2.2', '2.16.840.1.101.3.4.2.3')
  if ([string]$signer.DigestAlgorithm.Value -notin $allowedDigests) {
    Stop-BridgeReleaseGate 'bridge-release-cms-digest-too-weak'
  }
  $certificate = $signer.Certificate
  if ($certificate.Thumbprint.ToUpperInvariant() -cne $CmsSignerSha1.ToUpperInvariant()) {
    Stop-BridgeReleaseGate 'bridge-release-cms-sha1-pin-mismatch'
  }
  $certificateSha256 = ([BitConverter]::ToString($certificate.GetCertHash([Security.Cryptography.HashAlgorithmName]::SHA256))).Replace('-', '')
  if ($certificateSha256.ToUpperInvariant() -cne $CmsSignerSha256.ToUpperInvariant()) {
    Stop-BridgeReleaseGate 'bridge-release-cms-sha256-pin-mismatch'
  }
  $ekuExtension = @($certificate.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.37' })
  if ($ekuExtension.Count -ne 1) { Stop-BridgeReleaseGate 'bridge-release-cms-code-signing-eku-missing' }
  $decodedEku = New-Object Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension
  $decodedEku.CopyFrom($ekuExtension[0])
  if ($decodedEku.EnhancedKeyUsages.Count -ne 1 -or
      $decodedEku.EnhancedKeyUsages[0].Value -cne '1.3.6.1.5.5.7.3.3') {
    Stop-BridgeReleaseGate 'bridge-release-cms-code-signing-eku-missing'
  }
  $keyUsageExtensions = @($certificate.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.15' })
  if ($keyUsageExtensions.Count -gt 1) {
    Stop-BridgeReleaseGate 'bridge-release-cms-key-usage-invalid'
  }
  if ($keyUsageExtensions.Count -eq 1) {
    $decodedKeyUsage = New-Object Security.Cryptography.X509Certificates.X509KeyUsageExtension
    $decodedKeyUsage.CopyFrom($keyUsageExtensions[0])
    if (($decodedKeyUsage.KeyUsages -band
        [Security.Cryptography.X509Certificates.X509KeyUsageFlags]::DigitalSignature) -eq 0) {
      Stop-BridgeReleaseGate 'bridge-release-cms-key-usage-invalid'
    }
  }
  $signingTimeAttributes = @($signer.SignedAttributes | Where-Object {
      $_.Oid.Value -eq '1.2.840.113549.1.9.5'
    })
  if ($signingTimeAttributes.Count -ne 1 -or $signingTimeAttributes[0].Values.Count -ne 1) {
    Stop-BridgeReleaseGate 'bridge-release-cms-signing-time-invalid'
  }
  $signingTime = [DateTimeOffset]([Security.Cryptography.Pkcs.Pkcs9SigningTime]::new(
      $signingTimeAttributes[0].Values[0].RawData).SigningTime.ToUniversalTime())
  if ($signingTime -lt ([DateTimeOffset]$certificate.NotBefore.ToUniversalTime()) -or
      $signingTime -gt ([DateTimeOffset]$certificate.NotAfter.ToUniversalTime()) -or
      $signingTime -gt [DateTimeOffset]::UtcNow.AddMinutes(5)) {
    Stop-BridgeReleaseGate 'bridge-release-cms-signing-time-invalid'
  }
}

function Assert-AttestationsOnline {
  param([string]$Directory, [string[]]$Packages, [string]$ExpectedCommit)
  foreach ($name in $Packages) {
    $arguments = @(
      'attestation', 'verify', (Join-Path $Directory $name),
      '--repo', $Repository,
      '--signer-repo', $Repository,
      '--signer-workflow', "$Repository/.github/workflows/bridge-package.yml",
      '--source-digest', $ExpectedCommit,
      '--source-ref', 'refs/heads/main',
      '--deny-self-hosted-runners'
    )
    Invoke-CheckedNative 'gh' $arguments | Out-Null
  }
}

if ($Repository -cne 'HUBTECH-DEV/hch-worker' -or $Version -cne '3.1.1') {
  Stop-BridgeReleaseGate 'bridge-release-target-not-approved'
}
$tag = "v$Version"
$packageNames = @(
  "HCH-Worker-Setup-$Version-x64.exe",
  "HCH-Worker-$Version-linux-x64.tar.gz",
  "HCH-Worker-$Version-macos-universal.tar.gz"
)
$assetNames = @($packageNames + @('SHA256SUMS.txt', 'SHA256SUMS.p7s'))

if ($TestMode) {
  if ([string]$env:GITHUB_ACTIONS -ieq 'true') { Stop-BridgeReleaseGate 'bridge-release-test-mode-forbidden-in-actions' }
  if (-not $LatestReleaseJsonPath -or -not $TaggedReleaseJsonPath -or -not $AssetDirectory) {
    Stop-BridgeReleaseGate 'bridge-release-test-mode-input-missing'
  }
} elseif ($LatestReleaseJsonPath -or $TaggedReleaseJsonPath -or $AssetDirectory -or
          $SkipAuthenticodeVerification -or $SkipCmsVerification -or
          $SkipAttestationVerification -or $OfflineTagCommit) {
  Stop-BridgeReleaseGate 'bridge-release-test-bypass-forbidden-online'
}
if (($SkipAuthenticodeVerification -or $SkipCmsVerification -or $SkipAttestationVerification) -and -not $TestMode) {
  Stop-BridgeReleaseGate 'bridge-release-test-bypass-forbidden-online'
}

$temporaryRoot = $null
try {
  if ($TestMode) {
    $latest = Read-ReleaseJson $LatestReleaseJsonPath
    $tagged = Read-ReleaseJson $TaggedReleaseJsonPath
    $downloadDirectory = (Resolve-Path -LiteralPath $AssetDirectory).Path
  } else {
    foreach ($command in @('gh', 'git')) {
      if (-not (Get-Command $command -ErrorAction SilentlyContinue)) {
        Stop-BridgeReleaseGate ("bridge-release-command-missing:{0}" -f $command)
      }
    }
    $latest = Get-ReleaseOnline ''
    $tagged = Get-ReleaseOnline $tag
  }

  Assert-ReleaseMetadata $latest $tagged $tag
  $assetMap = Assert-AssetInventory $latest $tagged $assetNames
  $assetTotalBytes = Assert-AssetMetadataLimits $assetMap $packageNames
  $tarCommand = Get-TarCommand
  if ($TestMode) {
    Assert-TagContractOffline $BridgeSourceCommit
  } else {
    $temporaryRoot = Join-Path ([IO.Path]::GetTempPath()) ("hch-worker-bridge-release-{0}" -f [Guid]::NewGuid().ToString('N'))
    $gitDirectory = Join-Path $temporaryRoot 'git'
    $downloadDirectory = Join-Path $temporaryRoot 'assets'
    $null = New-Item -ItemType Directory -Path $gitDirectory, $downloadDirectory
    Assert-TagContractOnline $tag $BridgeSourceCommit $gitDirectory
    Invoke-CheckedNative 'gh' @('release', 'download', $tag, '--repo', $Repository, '--dir', $downloadDirectory, '--pattern', '*') | Out-Null
  }
  Assert-DownloadedAssets $downloadDirectory $assetMap $assetNames
  Assert-Checksums $downloadDirectory $packageNames
  Assert-GzipTarPackage `
    -Path (Join-Path $downloadDirectory $packageNames[1]) `
    -Platform linux `
    -ExpectedVersion $Version `
    -TarCommand $tarCommand
  Assert-GzipTarPackage `
    -Path (Join-Path $downloadDirectory $packageNames[2]) `
    -Platform macos `
    -ExpectedVersion $Version `
    -TarCommand $tarCommand
  if (-not $SkipAuthenticodeVerification) {
    Assert-WindowsPackageAuthenticode (Join-Path $downloadDirectory $packageNames[0])
  }
  if (-not $SkipCmsVerification) { Assert-CmsSignature $downloadDirectory }
  if (-not $SkipAttestationVerification) { Assert-AttestationsOnline $downloadDirectory $packageNames $BridgeSourceCommit }

  [pscustomobject]@{
    repository = $Repository
    version = $Version
    tag = $tag
    sourceCommit = $BridgeSourceCommit
    releaseId = [string]$tagged.id
    releaseDatabaseId = [string]$tagged.databaseId
    assetCount = $assetNames.Count
    assetTotalBytes = $assetTotalBytes
    testMode = [bool]$TestMode
    status = 'verified'
  } | ConvertTo-Json -Compress
} finally {
  if ($temporaryRoot -and (Test-Path -LiteralPath $temporaryRoot)) {
    Remove-Item -LiteralPath $temporaryRoot -Recurse -Force
  }
}
