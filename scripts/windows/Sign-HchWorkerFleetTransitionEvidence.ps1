[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$EvidencePath,
    [Parameter(Mandatory)][string]$EvidenceSignaturePath,
    [Parameter(Mandatory)][ValidatePattern('^[0-9A-Fa-f]{40}$')][string]$TelemetryAuthorityThumbprint,
    [Parameter(Mandatory)][ValidatePattern('^[0-9A-Fa-f]{64}$')][string]$ExpectedTelemetryAuthorityCertificateSha256,
    [ValidateSet('CurrentUser', 'LocalMachine')][string]$CertificateStoreLocation = 'CurrentUser'
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$codeSigningEkuOid = '1.3.6.1.5.5.7.3.3'
$maximumEvidenceBytes = 128MB
$maximumNodes = 64
$maximumHeartbeatSamplesPerNode = 20000
$maximumHeartbeatSamplesTotal = 500000

function Read-BoundedRegularFile([string]$Path, [long]$MaximumBytes, [string]$Label) {
  $resolvedPath = (Resolve-Path -LiteralPath $Path).Path
  $item = Get-Item -LiteralPath $resolvedPath -Force
  if ($item.PSIsContainer) { throw "$Label must be a regular file." }
  if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw "$Label must not be a reparse point." }
  $stream = [IO.FileStream]::new($resolvedPath,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
  try {
    $openedItem = Get-Item -LiteralPath $resolvedPath -Force
    if (($openedItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw "$Label became a reparse point while it was opened." }
    $length = $stream.Length
    if ($length -le 0 -or $length -gt $MaximumBytes) { throw "$Label must be between 1 byte and $MaximumBytes bytes." }
    $buffer = [byte[]]::new([int]$length)
    $offset = 0
    while ($offset -lt $buffer.Length) {
      $read = $stream.Read($buffer,$offset,$buffer.Length-$offset)
      if ($read -le 0) { throw "$Label ended before its declared length." }
      $offset += $read
    }
    if ($stream.Length -ne $length) { throw "$Label changed while it was read." }
    return [pscustomobject]@{ Path=$resolvedPath; Bytes=$buffer }
  } finally { $stream.Dispose() }
}

$evidenceFile = Read-BoundedRegularFile $EvidencePath $maximumEvidenceBytes 'Fleet evidence'
$evidence = $evidenceFile.Path
$bytes = $evidenceFile.Bytes
$signature = [IO.Path]::GetFullPath($EvidenceSignaturePath)
$signatureParent = Split-Path -Parent $signature
if (-not (Test-Path -LiteralPath $signatureParent -PathType Container)) { throw 'Detached-signature parent directory does not exist.' }
$signatureParentItem = Get-Item -LiteralPath $signatureParent -Force
if (($signatureParentItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Detached-signature parent directory must not be a reparse point.' }
if (Test-Path -LiteralPath $signature) { throw 'Refusing to overwrite existing detached signature.' }
$utf8 = [Text.UTF8Encoding]::new($false, $true)
$raw = $utf8.GetString($bytes)
if ($bytes.Length -eq 0 -or $raw[0] -eq [char]0xFEFF) { throw 'Fleet evidence must be non-empty UTF-8 without BOM.' }
if ($raw -match '(?i)private.?key|password|secret|authorization\s*:|bearer\s+') { throw 'Fleet evidence contains secret-shaped material.' }
$document = $raw | ConvertFrom-Json -Depth 100
if ($document.schema -cne 'hch.worker-fleet-transition/v1' -or $document.status -cne 'passed' -or $document.sanitized -isnot [bool] -or -not $document.sanitized) { throw 'Only passed, sanitized hch.worker-fleet-transition/v1 evidence may be signed.' }
$nodes = @($document.nodes)
if ($nodes.Count -gt $maximumNodes) { throw "nodes exceeds the maximum of $maximumNodes entries." }
$heartbeatSampleCount = [long]0
foreach ($node in $nodes) {
  $nodeHeartbeatSampleCount = @($node.heartbeatSamples).Count
  if ($nodeHeartbeatSampleCount -gt $maximumHeartbeatSamplesPerNode) { throw "A node exceeds the maximum of $maximumHeartbeatSamplesPerNode heartbeat samples." }
  $heartbeatSampleCount += $nodeHeartbeatSampleCount
  if ($heartbeatSampleCount -gt $maximumHeartbeatSamplesTotal) { throw "Fleet evidence exceeds the maximum of $maximumHeartbeatSamplesTotal heartbeat samples." }
}
$completed = [DateTimeOffset]::MinValue
if ($document.windowCompletedAtUtc -is [DateTime]) {
  $completed = [DateTimeOffset]$document.windowCompletedAtUtc.ToUniversalTime()
} elseif ($document.windowCompletedAtUtc -is [DateTimeOffset]) {
  $completed = $document.windowCompletedAtUtc.ToUniversalTime()
} elseif ($document.windowCompletedAtUtc -isnot [string] -or -not [DateTimeOffset]::TryParse($document.windowCompletedAtUtc, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::RoundtripKind, [ref]$completed)) {
  throw 'windowCompletedAtUtc is invalid.'
}
$completed = $completed.ToUniversalTime()
$now = [DateTime]::UtcNow
$signingUtc = [DateTime]::new($now.Year,$now.Month,$now.Day,$now.Hour,$now.Minute,$now.Second,[DateTimeKind]::Utc)
$signing = [DateTimeOffset]$signingUtc
if ($signing -le $completed -or $signing -gt $completed.AddHours(24)) { throw 'Signing must occur after completion and within 24 hours.' }
$store = [Security.Cryptography.X509Certificates.X509Store]::new('My',[Security.Cryptography.X509Certificates.StoreLocation]::$CertificateStoreLocation)
try {
  $store.Open([Security.Cryptography.X509Certificates.OpenFlags]::ReadOnly)
  $pin = $TelemetryAuthorityThumbprint.Replace(' ','').ToUpperInvariant()
  $matches = @($store.Certificates | Where-Object { $_.Thumbprint.Replace(' ','').ToUpperInvariant() -ceq $pin })
  if ($matches.Count -ne 1) { throw 'Expected exactly one telemetry-authority certificate.' }
  $cert = $matches[0]
  if (-not $cert.HasPrivateKey) { throw 'Telemetry-authority certificate has no protected private key.' }
  if ([Convert]::ToHexString($cert.GetCertHash([Security.Cryptography.HashAlgorithmName]::SHA256)) -cne $ExpectedTelemetryAuthorityCertificateSha256.ToUpperInvariant()) { throw 'Telemetry-authority SHA-256 pin mismatch.' }
  $ekus = @($cert.Extensions | Where-Object {$_.Oid.Value -eq '2.5.29.37'})
  if ($ekus.Count -ne 1) { throw 'Telemetry authority must contain exactly one EKU extension.' }
  $eku = if ($ekus[0] -is [Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]) {$ekus[0]} else {[Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]::new($ekus[0],$ekus[0].Critical)}
  if ($eku.EnhancedKeyUsages.Count -ne 1 -or $eku.EnhancedKeyUsages[0].Value -cne $codeSigningEkuOid) { throw 'Telemetry authority must be constrained to code signing.' }
  $keyUsages = @($cert.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.15' })
  if ($keyUsages.Count -gt 1) { throw 'Telemetry authority contains multiple Key Usage extensions.' }
  if ($keyUsages.Count -eq 1) {
    $keyUsage = if ($keyUsages[0] -is [Security.Cryptography.X509Certificates.X509KeyUsageExtension]) {$keyUsages[0]} else {[Security.Cryptography.X509Certificates.X509KeyUsageExtension]::new($keyUsages[0],$keyUsages[0].Critical)}
    if (($keyUsage.KeyUsages -band [Security.Cryptography.X509Certificates.X509KeyUsageFlags]::DigitalSignature) -eq 0) {
      throw 'Telemetry authority Key Usage does not allow digital signatures.'
    }
  }
  if ($signing -lt ([DateTimeOffset]$cert.NotBefore.ToUniversalTime()) -or $signing -gt ([DateTimeOffset]$cert.NotAfter.ToUniversalTime())) { throw 'Telemetry-authority certificate is not valid at signing time.' }
  $cms = [Security.Cryptography.Pkcs.SignedCms]::new([Security.Cryptography.Pkcs.ContentInfo]::new($bytes),$true)
  $signer = [Security.Cryptography.Pkcs.CmsSigner]::new([Security.Cryptography.Pkcs.SubjectIdentifierType]::IssuerAndSerialNumber,$cert)
  $signer.IncludeOption = [Security.Cryptography.X509Certificates.X509IncludeOption]::EndCertOnly
  $signer.DigestAlgorithm = [Security.Cryptography.Oid]::new('2.16.840.1.101.3.4.2.1')
  $signer.SignedAttributes.Add([Security.Cryptography.Pkcs.Pkcs9SigningTime]::new($signingUtc))
  $cms.ComputeSignature($signer,$true)
  $tmp = "$signature.$([Guid]::NewGuid().ToString('N')).tmp"
  try {
    $currentSignatureParent = Get-Item -LiteralPath $signatureParent -Force
    if (($currentSignatureParent.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Detached-signature parent directory became a reparse point.' }
    $encodedSignature = $cms.Encode()
    $temporaryStream = [IO.FileStream]::new($tmp,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
    try {
      $temporaryStream.Write($encodedSignature,0,$encodedSignature.Length)
      $temporaryStream.Flush($true)
    } finally { $temporaryStream.Dispose() }
    [IO.File]::Move($tmp,$signature)
  } finally { if (Test-Path $tmp) { Remove-Item -LiteralPath $tmp -Force } }
} finally { $store.Dispose() }
Write-Host "Detached CMS fleet-transition signature created without exporting private key: $signature"
