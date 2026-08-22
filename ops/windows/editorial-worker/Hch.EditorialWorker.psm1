Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$script:KitRoot = Split-Path -Parent $PSCommandPath
$script:CryptoHelper = Join-Path $script:KitRoot 'crypto\hch-ed25519.mjs'
$script:KitVersion = (Get-Content -Raw -LiteralPath (Join-Path $script:KitRoot 'VERSION')).Trim()
$script:LastHttpTelemetry = [ordered]@{ requestBytes = 0L; responseBytes = 0L; durationMilliseconds = 0L }
$script:LastTransportObservation = $null
$script:LastTrustObservation = $null
$script:AllowedActionTypes = @(
  'verify-artifact',
  'configure-engine',
  'pull-model-by-digest',
  'apply-editorial-policy',
  'self-test'
)

function Import-HchWorkerConfig {
  [CmdletBinding()]
  param([Parameter(Mandatory = $true)][string]$Path)

  if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { throw 'worker-config-not-found' }
  $config = Import-PowerShellDataFile -LiteralPath $Path
  foreach ($name in @('NodeId', 'ControlPlaneBaseUri', 'RootPublicKeyPath', 'StateRoot', 'InstallRoot')) {
    if (-not $config.ContainsKey($name) -or [string]::IsNullOrWhiteSpace([string]$config[$name])) {
      throw "worker-config-missing:$name"
    }
  }
  if ([int](Get-HchConfigValue $config 'SchemaVersion' 0) -ne 2) { throw 'worker-config-schema-unsupported' }
  if ([string]$config.NodeId -notmatch '^[a-z0-9][a-z0-9._-]{2,63}$') { throw 'worker-node-id-invalid' }
  $controlPlane = [Uri]$config.ControlPlaneBaseUri
  if (-not $controlPlane.IsAbsoluteUri -or $controlPlane.Scheme -ne 'https') {
    throw 'control-plane-must-use-https'
  }
  $localParallelismLimit = [int](Get-HchConfigValue $config 'LocalParallelismLimit' 8)
  if ($localParallelismLimit -lt 1 -or $localParallelismLimit -gt 64) {
    throw 'local-parallelism-limit-out-of-range'
  }
  $requestedCapacity = [int](Get-HchConfigValue $config 'RequestedCapacity' 1)
  if ($requestedCapacity -lt 1 -or $requestedCapacity -gt $localParallelismLimit) {
    throw 'requested-capacity-out-of-range'
  }
  if ([int](Get-HchConfigValue $config 'NodeHeartbeatIntervalSeconds' 60) -ne 60) {
    throw 'node-heartbeat-interval-must-be-60'
  }
  $nodeHeartbeatTimeout = [int](Get-HchConfigValue $config 'NodeHeartbeatRequestTimeoutSeconds' 10)
  if ($nodeHeartbeatTimeout -lt 3 -or $nodeHeartbeatTimeout -gt 15) {
    throw 'node-heartbeat-request-timeout-out-of-range'
  }
  return $config
}

function Get-HchConfigValue {
  param([hashtable]$Config, [string]$Name, $Default)
  if ($Config.ContainsKey($Name)) { return $Config[$Name] }
  return $Default
}

function Get-HchWorkerControl {
  [CmdletBinding()]
  param([Parameter(Mandatory = $true)][hashtable]$Config)
  $controlPath = Join-Path ([string]$Config.StateRoot) 'worker-control.json'
  if (-not (Test-Path -LiteralPath $controlPath -PathType Leaf)) {
    return [pscustomobject][ordered]@{
      schema = 'hch.worker-control/v1'
      schemaVersion = 1
      nodeId = [string]$Config.NodeId
      acceptingClaims = $false
      requestedParallelism = 1
      lastNonZeroParallelism = 1
      drainRequested = $true
      updatedAt = $null
      updatedBy = 'default'
    }
  }
  try { $control = Read-HchJsonFile -Path $controlPath }
  catch { throw 'worker-control-state-invalid' }
  if ([string]$control.schema -ne 'hch.worker-control/v1' -or
      [int]$control.schemaVersion -ne 1 -or
      [string]$control.nodeId -ne [string]$Config.NodeId) {
    throw 'worker-control-state-invalid'
  }
  $localLimit = [int](Get-HchConfigValue $Config 'LocalParallelismLimit' 8)
  $requested = [int]$control.requestedParallelism
  $lastNonZero = [int]$control.lastNonZeroParallelism
  if ($requested -lt 0 -or $requested -gt $localLimit -or
      $lastNonZero -lt 1 -or $lastNonZero -gt $localLimit) {
    throw 'worker-control-parallelism-invalid'
  }
  if ([bool]$control.acceptingClaims -and ($requested -eq 0 -or [bool]$control.drainRequested)) {
    throw 'worker-control-state-inconsistent'
  }
  return $control
}

function Set-HchWorkerControl {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory = $true)][hashtable]$Config,
    [Parameter(Mandatory = $true)][ValidateRange(0, 64)][int]$Parallelism,
    [Parameter(Mandatory = $true)][bool]$AcceptingClaims,
    [string]$UpdatedBy = 'operator-cli'
  )
  $localLimit = [int](Get-HchConfigValue $Config 'LocalParallelismLimit' 8)
  if ($Parallelism -gt $localLimit) { throw 'worker-parallelism-exceeds-local-limit' }
  if ($AcceptingClaims -and $Parallelism -eq 0) { throw 'worker-cannot-accept-claims-at-zero-parallelism' }
  $previous = Get-HchWorkerControl -Config $Config
  $lastNonZero = if ($Parallelism -gt 0) {
    $Parallelism
  } else {
    [Math]::Max(1, [int]$previous.lastNonZeroParallelism)
  }
  $record = [ordered]@{
    schema = 'hch.worker-control/v1'
    schemaVersion = 1
    nodeId = [string]$Config.NodeId
    acceptingClaims = $AcceptingClaims
    requestedParallelism = $Parallelism
    lastNonZeroParallelism = $lastNonZero
    drainRequested = -not $AcceptingClaims
    updatedAt = [DateTimeOffset]::UtcNow.ToString('o')
    updatedBy = $UpdatedBy
  }
  Write-HchJsonAtomic -Path (Join-Path ([string]$Config.StateRoot) 'worker-control.json') -Value $record
  [void](Set-HchWorkerCapacitySnapshot -Config $Config -RequestedCapacity $Parallelism `
    -CapacityReason $(if ($AcceptingClaims) { 'pending-server-negotiation' } else { 'drain-requested' }))
  return [pscustomobject]$record
}

function Set-HchWorkerCapacitySnapshot {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory = $true)][hashtable]$Config,
    [ValidateRange(-1, 64)][int]$RequestedCapacity = -1,
    [ValidateRange(-1, 64)][int]$GrantedCapacity = -1,
    [ValidateRange(-1, 1000000)][int]$ActiveAssignments = -1,
    [string]$CapacityReason = '',
    [AllowNull()][string]$ValidUntil = $null,
    [switch]$ClearValidUntil
  )
  $path = Join-Path ([string]$Config.StateRoot) 'capacity.json'
  $previous = $null
  if (Test-Path -LiteralPath $path -PathType Leaf) {
    try { $previous = Read-HchJsonFile -Path $path } catch { $previous = $null }
  }
  $requested = if ($RequestedCapacity -ge 0) {
    $RequestedCapacity
  } elseif ($null -ne $previous) { [int]$previous.requestedCapacity } else { 0 }
  $granted = if ($GrantedCapacity -ge 0) {
    $GrantedCapacity
  } elseif ($null -ne $previous) { [int]$previous.grantedCapacity } else { 0 }
  $active = if ($ActiveAssignments -ge 0) {
    $ActiveAssignments
  } elseif ($null -ne $previous) { [int]$previous.activeAssignments } else { 0 }
  $reason = if (-not [string]::IsNullOrWhiteSpace($CapacityReason)) {
    $CapacityReason
  } elseif ($null -ne $previous) { [string]$previous.capacityReason } else { 'not-negotiated' }
  if ([string]::IsNullOrWhiteSpace([string]$reason) -or [string]$reason -match '[\x00-\x1f\x7f]' -or
      ([string]$reason).Length -gt 256) { throw 'worker-capacity-reason-invalid' }
  $expires = if ($ClearValidUntil) {
    $null
  } elseif (-not [string]::IsNullOrWhiteSpace($ValidUntil)) {
    [DateTimeOffset]::Parse($ValidUntil).ToString('o')
  } elseif ($null -ne $previous) { $previous.validUntil } else { $null }
  $record = [ordered]@{
    schema = 'hch.worker-capacity/v1'
    schemaVersion = 1
    observedAt = [DateTimeOffset]::UtcNow.ToString('o')
    nodeId = [string]$Config.NodeId
    requestedCapacity = $requested
    grantedCapacity = $granted
    activeAssignments = $active
    capacityReason = $reason
    validUntil = $expires
  }
  Write-HchJsonAtomic -Path $path -Value $record
  return [pscustomobject]$record
}

function Update-HchWorkerActiveAssignmentCount {
  param(
    [Parameter(Mandatory = $true)][hashtable]$Config,
    [Parameter(Mandatory = $true)][ValidateRange(-64, 64)][int]$Delta
  )
  $path = Join-Path ([string]$Config.StateRoot) 'capacity.json'
  $current = 0
  if (Test-Path -LiteralPath $path -PathType Leaf) {
    try { $current = [int](Read-HchJsonFile -Path $path).activeAssignments }
    catch { throw 'worker-capacity-state-invalid' }
  }
  return Set-HchWorkerCapacitySnapshot -Config $Config `
    -ActiveAssignments ([Math]::Max(0, $current + $Delta))
}

function Get-HchWorkerCycleTaskName {
  [CmdletBinding()]
  param([Parameter(Mandatory = $true)][hashtable]$Config)
  return 'HCH Editorial Worker - ' + [string]$Config.NodeId
}

function Get-HchWorkerServiceName {
  [CmdletBinding()]
  param([Parameter(Mandatory = $true)][hashtable]$Config)
  $nodeId = [string]$Config.NodeId
  if ([string]::IsNullOrWhiteSpace($nodeId)) { throw 'worker-node-id-invalid' }
  $slug = ($nodeId.ToLowerInvariant() -replace '[^a-z0-9]+', '-').Trim('-')
  if ([string]::IsNullOrWhiteSpace($slug)) { $slug = 'node' }
  if ($slug.Length -gt 40) { $slug = $slug.Substring(0, 40).TrimEnd('-') }
  $sha = [Security.Cryptography.SHA256]::Create()
  try {
    $hash = ([BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($nodeId)))).Replace('-', '').ToLowerInvariant()
  } finally { $sha.Dispose() }
  return 'HchEditorialWorker-' + $slug + '-' + $hash.Substring(0, 12)
}

function Get-HchWorkerServiceDisplayName {
  [CmdletBinding()]
  param([Parameter(Mandatory = $true)][hashtable]$Config)
  return 'HCH Editorial Worker - ' + [string]$Config.NodeId
}

function Assert-HchNodeRuntime {
  [CmdletBinding()]
  param([Parameter(Mandatory = $true)][hashtable]$Config)

  $nodePath = [string](Get-HchConfigValue $Config 'NodePath' 'node.exe')
  $command = Get-Command $nodePath -ErrorAction SilentlyContinue
  if (-not $command) { throw 'node-runtime-not-found' }
  $versionText = (& $command.Source --version 2>$null).Trim()
  if ($LASTEXITCODE -ne 0 -or $versionText -notmatch '^v(?<major>\d+)\.') { throw 'node-runtime-version-unreadable' }
  $minimumMajor = [int](Get-HchConfigValue $Config 'MinimumNodeMajor' 22)
  if ([int]$Matches.major -lt $minimumMajor) { throw "node-runtime-too-old:$versionText" }
  if (-not (Test-Path -LiteralPath $script:CryptoHelper -PathType Leaf)) { throw 'crypto-helper-not-found' }
  return $command.Source
}

function Invoke-HchCrypto {
  param(
    [Parameter(Mandatory = $true)][hashtable]$Config,
    [Parameter(Mandatory = $true)][string[]]$Arguments
  )
  $nodePath = Assert-HchNodeRuntime -Config $Config
  $output = & $nodePath $script:CryptoHelper @Arguments
  $exitCode = $LASTEXITCODE
  if ($exitCode -ne 0) { throw "crypto-helper-failed:$exitCode" }
  if ([string]::IsNullOrWhiteSpace(($output -join ''))) { return $null }
  return (($output -join "`n") | ConvertFrom-Json)
}

function Write-HchUtf8File {
  param([Parameter(Mandatory = $true)][string]$Path, [Parameter(Mandatory = $true)][string]$Content)
  $parent = Split-Path -Parent $Path
  if (-not (Test-Path -LiteralPath $parent)) { New-Item -ItemType Directory -Path $parent -Force | Out-Null }
  [IO.File]::WriteAllText($Path, $Content, [Text.UTF8Encoding]::new($false))
}

function Write-HchJsonAtomic {
  param([Parameter(Mandatory = $true)][string]$Path, [Parameter(Mandatory = $true)]$Value)
  $parent = Split-Path -Parent $Path
  if (-not (Test-Path -LiteralPath $parent)) { New-Item -ItemType Directory -Path $parent -Force | Out-Null }
  $temporary = Join-Path $parent ('.hch-' + [guid]::NewGuid().ToString('n') + '.tmp')
  $replaceBackup = Join-Path $parent ('.hch-' + [guid]::NewGuid().ToString('n') + '.bak')
  try {
    Write-HchUtf8File -Path $temporary -Content ($Value | ConvertTo-Json -Depth 100 -Compress)
    if (Test-Path -LiteralPath $Path) {
      [IO.File]::Replace($temporary, $Path, $replaceBackup, $true)
      Remove-Item -LiteralPath $replaceBackup -Force -ErrorAction SilentlyContinue
    } else {
      [IO.File]::Move($temporary, $Path)
    }
  } finally {
    Remove-Item -LiteralPath $temporary -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $replaceBackup -Force -ErrorAction SilentlyContinue
  }
}

function Read-HchJsonFile {
  param([Parameter(Mandatory = $true)][string]$Path)
  if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { throw "json-file-not-found:$Path" }
  return (Get-Content -Raw -LiteralPath $Path | ConvertFrom-Json)
}

function Set-HchRestrictedAcl {
  param([Parameter(Mandatory = $true)][string]$Path, [switch]$Container)
  if ($env:OS -ne 'Windows_NT') { return }
  $currentSid = [Security.Principal.WindowsIdentity]::GetCurrent().User
  $systemSid = [Security.Principal.SecurityIdentifier]::new('S-1-5-18')
  if ($Container) {
    $acl = [Security.AccessControl.DirectorySecurity]::new()
    $inheritance = [Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit'
  } else {
    $acl = [Security.AccessControl.FileSecurity]::new()
    $inheritance = [Security.AccessControl.InheritanceFlags]::None
  }
  $acl.SetAccessRuleProtection($true, $false)
  $acl.SetOwner($currentSid)
  foreach ($sid in @($currentSid, $systemSid)) {
    $rule = [Security.AccessControl.FileSystemAccessRule]::new(
      $sid,
      [Security.AccessControl.FileSystemRights]::FullControl,
      $inheritance,
      [Security.AccessControl.PropagationFlags]::None,
      [Security.AccessControl.AccessControlType]::Allow
    )
    [void]$acl.AddAccessRule($rule)
  }
  try {
    if ($Container) {
      [IO.DirectoryInfo]::new($Path).SetAccessControl($acl)
    } else {
      [IO.FileInfo]::new($Path).SetAccessControl($acl)
    }
  } catch [UnauthorizedAccessException] {
    # The Windows service intentionally has Modify, not WRITE_DAC, on the
    # protected StateRoot. A child created there may safely retain inheritance
    # because the installer validates and protects that parent. The service
    # also lacks READ_CONTROL, so it must not attempt to inspect or rewrite the
    # descriptor at runtime.
    return
  }
}

function Initialize-HchWorkerIdentity {
  [CmdletBinding()]
  param([Parameter(Mandatory = $true)][hashtable]$Config)

  [void](Assert-HchNodeRuntime -Config $Config)
  $identityDirectory = Join-Path ([string]$Config.StateRoot) 'identity'
  $privatePath = Join-Path $identityDirectory 'worker-private.pk8.pem'
  $publicPath = Join-Path $identityDirectory 'worker-public.spki.pem'
  $metadataPath = Join-Path $identityDirectory 'identity.json'

  # An installed Windows service deliberately shares StateRoot with the
  # limited interactive dashboard account, while the private key itself has a
  # protected service-only ACL. Reapplying a current-principal-only ACL during
  # every bootstrap would remove the dashboard operator from StateRoot when
  # this function runs as NT SERVICE\<worker>. Existing identities were already
  # hardened at creation and are explicitly re-ACL'd by the service installer.
  if (Test-Path -LiteralPath $metadataPath -PathType Leaf) {
    return Get-HchWorkerIdentity -Config $Config
  }
  if (-not (Test-Path -LiteralPath ([string]$Config.StateRoot))) {
    New-Item -ItemType Directory -Path ([string]$Config.StateRoot) -Force | Out-Null
  }
  Set-HchRestrictedAcl -Path ([string]$Config.StateRoot) -Container
  if (-not (Test-Path -LiteralPath ([string]$Config.InstallRoot))) {
    New-Item -ItemType Directory -Path ([string]$Config.InstallRoot) -Force | Out-Null
  }
  Set-HchRestrictedAcl -Path ([string]$Config.InstallRoot) -Container
  if (-not (Test-Path -LiteralPath $identityDirectory)) {
    New-Item -ItemType Directory -Path $identityDirectory -Force | Out-Null
  }
  Set-HchRestrictedAcl -Path $identityDirectory -Container
  try {
    $generated = Invoke-HchCrypto -Config $Config -Arguments @(
      'generate', '--private', $privatePath, '--public', $publicPath
    )
    Set-HchRestrictedAcl -Path $privatePath
    $metadata = [ordered]@{
      schemaVersion = 2
      nodeId = [string]$Config.NodeId
      keyId = [string]$generated.keyId
      algorithm = 'Ed25519'
      privateKeyFormat = 'PKCS8-PEM'
      publicKeyFormat = 'SPKI-PEM'
      privateKeyPath = $privatePath
      publicKeyPath = $publicPath
      createdAt = [DateTimeOffset]::UtcNow.ToString('o')
    }
    Write-HchJsonAtomic -Path $metadataPath -Value $metadata
    Set-HchRestrictedAcl -Path $metadataPath
  } catch {
    Remove-Item -LiteralPath $privatePath -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $publicPath -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $metadataPath -Force -ErrorAction SilentlyContinue
    throw
  }
  return Get-HchWorkerIdentity -Config $Config
}

function Get-HchWorkerIdentity {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory = $true)][hashtable]$Config,
    [switch]$PublicOnly
  )

  $metadataPath = Join-Path (Join-Path ([string]$Config.StateRoot) 'identity') 'identity.json'
  $identity = Read-HchJsonFile -Path $metadataPath
  if ([string]$identity.nodeId -ne [string]$Config.NodeId) { throw 'identity-node-mismatch' }
  if ([string]$identity.algorithm -ne 'Ed25519') { throw 'identity-algorithm-invalid' }
  $requiredKeyPaths = if ($PublicOnly) {
    @([string]$identity.publicKeyPath)
  } else {
    @([string]$identity.privateKeyPath, [string]$identity.publicKeyPath)
  }
  foreach ($keyPath in $requiredKeyPaths) {
    if (-not (Test-Path -LiteralPath $keyPath -PathType Leaf)) { throw 'identity-key-file-missing' }
  }
  $fingerprint = Invoke-HchCrypto -Config $Config -Arguments @(
    'fingerprint', '--public', [string]$identity.publicKeyPath
  )
  if ([string]$fingerprint.keyId -ne [string]$identity.keyId) { throw 'identity-public-key-mismatch' }
  return $identity
}

function Get-HchWorkerPublicKeyId {
  [CmdletBinding()]
  param([Parameter(Mandatory = $true)][hashtable]$Config)
  $identity = Get-HchWorkerIdentity -Config $Config -PublicOnly
  $fingerprint = Invoke-HchCrypto -Config $Config -Arguments @(
    'fingerprint', '--public', [string]$identity.publicKeyPath
  )
  if ([string]$fingerprint.keyId -ne [string]$identity.keyId) {
    throw 'identity-public-key-mismatch'
  }
  return [string]$identity.keyId
}

function Get-HchCanonicalFile {
  param(
    [Parameter(Mandatory = $true)][hashtable]$Config,
    [Parameter(Mandatory = $true)]$Value
  )
  $inputPath = Join-Path ([IO.Path]::GetTempPath()) ('hch-json-' + [guid]::NewGuid().ToString('n') + '.json')
  $outputPath = Join-Path ([IO.Path]::GetTempPath()) ('hch-jcs-' + [guid]::NewGuid().ToString('n') + '.json')
  try {
    Write-HchUtf8File -Path $inputPath -Content ($Value | ConvertTo-Json -Depth 100 -Compress)
    [void](Invoke-HchCrypto -Config $Config -Arguments @(
      'canonicalize', '--input', $inputPath, '--output', $outputPath
    ))
    return $outputPath
  } catch {
    Remove-Item -LiteralPath $outputPath -Force -ErrorAction SilentlyContinue
    throw
  } finally {
    Remove-Item -LiteralPath $inputPath -Force -ErrorAction SilentlyContinue
  }
}

function Get-HchSha256File {
  param([Parameter(Mandatory = $true)][string]$Path)
  $stream = [IO.File]::OpenRead($Path)
  $sha = [Security.Cryptography.SHA256]::Create()
  try {
    return (($sha.ComputeHash($stream) | ForEach-Object { $_.ToString('x2') }) -join '')
  } finally {
    $sha.Dispose()
    $stream.Dispose()
  }
}

function Get-HchNormalizedHash {
  param([Parameter(Mandatory = $true)][string]$Value)
  $normalized = $Value.Trim().ToLowerInvariant() -replace '^sha256:', ''
  if ($normalized -notmatch '^[a-f0-9]{64}$') { throw 'sha256-value-invalid' }
  return $normalized
}

function Get-HchCanonicalSha256 {
  param(
    [Parameter(Mandatory = $true)][hashtable]$Config,
    [Parameter(Mandatory = $true)]$Value
  )
  $canonicalPath = Get-HchCanonicalFile -Config $Config -Value $Value
  try { return Get-HchSha256File -Path $canonicalPath }
  finally { Remove-Item -LiteralPath $canonicalPath -Force -ErrorAction SilentlyContinue }
}

function Get-HchOperationRequestId {
  param(
    [Parameter(Mandatory = $true)][hashtable]$Config,
    [Parameter(Mandatory = $true)][ValidatePattern('^[a-z0-9][a-z0-9._-]{2,159}$')][string]$OperationKey,
    [Parameter(Mandatory = $true)][string]$Target,
    [Parameter(Mandatory = $true)]$Body,
    [AllowNull()]$SafeContext = $null
  )
  $directory = Join-Path ([string]$Config.StateRoot) 'pending-operations'
  if (-not (Test-Path -LiteralPath $directory)) { New-Item -ItemType Directory -Path $directory -Force | Out-Null }
  Set-HchRestrictedAcl -Path $directory -Container
  $path = Join-Path $directory ($OperationKey + '.json')
  $digest = Get-HchCanonicalSha256 -Config $Config -Value $Body
  $now = [DateTimeOffset]::UtcNow
  if (Test-Path -LiteralPath $path) {
    $pending = Read-HchJsonFile -Path $path
    if ([DateTimeOffset]::Parse([string]$pending.expiresAt) -le $now) {
      throw "idempotency-window-expired-recovery-required:$OperationKey"
    }
    if ([string]$pending.target -ne $Target -or [string]$pending.bodyDigest -ne $digest) {
      throw "idempotency-operation-conflict:$OperationKey"
    }
    if ($null -ne $SafeContext) {
      if (-not ($pending.PSObject.Properties.Name -contains 'safeContext') -or
          (Get-HchCanonicalSha256 -Config $Config -Value $pending.safeContext) -ne
          (Get-HchCanonicalSha256 -Config $Config -Value $SafeContext)) {
        throw "idempotency-operation-safe-context-conflict:$OperationKey"
      }
    }
    return [string]$pending.requestId
  }
  $record = [ordered]@{
    schema = 'hch.pending-operation/v1'
    operationKey = $OperationKey
    requestId = [guid]::NewGuid().ToString('n')
    target = $Target
    bodyDigest = $digest
    createdAt = $now.ToString('o')
    expiresAt = $now.AddHours(24).ToString('o')
  }
  if ($null -ne $SafeContext) { $record.safeContext = $SafeContext }
  try { Write-HchJsonAtomic -Path $path -Value $record }
  catch {
    if (-not (Test-Path -LiteralPath $path)) { throw }
    $pending = Read-HchJsonFile -Path $path
    if ([string]$pending.target -ne $Target -or [string]$pending.bodyDigest -ne $digest) {
      throw "idempotency-operation-conflict:$OperationKey"
    }
    if ($null -ne $SafeContext -and (
        -not ($pending.PSObject.Properties.Name -contains 'safeContext') -or
        (Get-HchCanonicalSha256 -Config $Config -Value $pending.safeContext) -ne
        (Get-HchCanonicalSha256 -Config $Config -Value $SafeContext)
      )) {
      throw "idempotency-operation-safe-context-conflict:$OperationKey"
    }
    return [string]$pending.requestId
  }
  return [string]$record.requestId
}

function Get-HchPendingOperationSafeContext {
  param(
    [Parameter(Mandatory = $true)][hashtable]$Config,
    [Parameter(Mandatory = $true)][string]$OperationKey
  )
  $path = Join-Path (Join-Path ([string]$Config.StateRoot) 'pending-operations') ($OperationKey + '.json')
  if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { return $null }
  $pending = Read-HchJsonFile -Path $path
  if ([string]$pending.schema -ne 'hch.pending-operation/v1' -or
      [string]$pending.operationKey -ne $OperationKey) {
    throw "idempotency-operation-state-invalid:$OperationKey"
  }
  if (-not ($pending.PSObject.Properties.Name -contains 'safeContext')) { return $null }
  return $pending.safeContext
}

function Complete-HchOperationRequest {
  param(
    [Parameter(Mandatory = $true)][hashtable]$Config,
    [Parameter(Mandatory = $true)][string]$OperationKey,
    [Parameter(Mandatory = $true)][string]$RequestId
  )
  $path = Join-Path (Join-Path ([string]$Config.StateRoot) 'pending-operations') ($OperationKey + '.json')
  if (-not (Test-Path -LiteralPath $path)) { return }
  $pending = Read-HchJsonFile -Path $path
  if ([string]$pending.requestId -ne $RequestId) { throw 'idempotency-operation-resolution-mismatch' }
  Remove-Item -LiteralPath $path -Force
}

function Move-HchExpiredOperationRequest {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory = $true)][hashtable]$Config,
    [Parameter(Mandatory = $true)][ValidatePattern('^[a-z0-9][a-z0-9._-]{2,159}$')][string]$OperationKey,
    [Parameter(Mandatory = $true)][switch]$ConfirmLeaseExpiredOrReclaimed
  )
  if (-not $ConfirmLeaseExpiredOrReclaimed) { throw 'lease-expiration-or-reclaim-confirmation-required' }
  $pendingDirectory = Join-Path ([string]$Config.StateRoot) 'pending-operations'
  $path = Join-Path $pendingDirectory ($OperationKey + '.json')
  if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw 'pending-operation-not-found' }
  $pending = Read-HchJsonFile -Path $path
  if ([DateTimeOffset]::Parse([string]$pending.expiresAt) -gt [DateTimeOffset]::UtcNow) {
    throw 'idempotency-window-still-active'
  }
  $archiveDirectory = Join-Path ([string]$Config.StateRoot) 'expired-operations'
  if (-not (Test-Path -LiteralPath $archiveDirectory)) {
    New-Item -ItemType Directory -Path $archiveDirectory -Force | Out-Null
  }
  Set-HchRestrictedAcl -Path $archiveDirectory -Container
  $archivePath = Join-Path $archiveDirectory `
    ([DateTimeOffset]::UtcNow.ToString('yyyyMMddTHHmmssfffZ') + '-' + $OperationKey + '.json')
  Move-Item -LiteralPath $path -Destination $archivePath
  return [pscustomobject]@{
    operationKey = $OperationKey
    previousRequestId = [string]$pending.requestId
    archivedAt = [DateTimeOffset]::UtcNow.ToString('o')
    nextRequestMustBeNew = $true
  }
}

function Get-HchNestedValue {
  param($InputObject, [string[]]$Path, $Default = $null)
  $current = $InputObject
  foreach ($segment in $Path) {
    if ($null -eq $current) { return $Default }
    if ($current -is [Collections.IDictionary]) {
      if (-not $current.Contains($segment)) { return $Default }
      $current = $current[$segment]
      continue
    }
    $property = $current.PSObject.Properties[$segment]
    if ($null -eq $property) { return $Default }
    $current = $property.Value
  }
  if ($null -eq $current) { return $Default }
  return $current
}

function Test-HchIntegerInRange {
  param($Value, [long]$Minimum, [long]$Maximum)
  if ($null -eq $Value) { return $false }
  try { $number = [double]$Value } catch { return $false }
  if ([double]::IsNaN($number) -or [double]::IsInfinity($number) -or
      $number -ne [Math]::Truncate($number)) { return $false }
  return $number -ge $Minimum -and $number -le $Maximum
}

function Assert-HchCapacityPressure {
  param($Pressure)
  if ($null -eq $Pressure) { return [ordered]@{} }
  $result = [ordered]@{}
  foreach ($property in @($Pressure.PSObject.Properties)) {
    if ([string]$property.Name -notin @('cpuPercent', 'memoryPercent', 'gpuPercent')) {
      throw "capacity-pressure-field-invalid:$($property.Name)"
    }
    try { $number = [double]$property.Value } catch { throw "capacity-pressure-value-invalid:$($property.Name)" }
    if ([double]::IsNaN($number) -or [double]::IsInfinity($number) -or
        $number -lt 0 -or $number -gt 100) {
      throw "capacity-pressure-value-invalid:$($property.Name)"
    }
    $result[[string]$property.Name] = [Math]::Round($number, 2)
  }
  return $result
}

function Assert-HchCapacityPolicy {
  param([Parameter(Mandatory = $true)]$Policy)
  $required = @(
    'algorithmVersion', 'absoluteRequestedMaximum', 'defaultNodeCeiling',
    'globalAssignmentCeiling', 'grantTtlSeconds', 'telemetryMayOnlyReduce',
    'classCeilings', 'platformClasses', 'nodeClasses', 'nodeCeilings', 'pressure'
  )
  foreach ($field in $required) {
    if (-not ($Policy.PSObject.Properties.Name -contains $field)) {
      throw "capacity-policy-field-missing:$field"
    }
  }
  foreach ($field in $Policy.PSObject.Properties.Name) {
    if ([string]$field -notin $required) { throw "capacity-policy-field-unsupported:$field" }
  }
  if ([string]$Policy.algorithmVersion -ne 'hch-adaptive-capacity-v1') {
    throw 'capacity-policy-algorithm-unsupported'
  }
  if (-not (Test-HchIntegerInRange $Policy.absoluteRequestedMaximum 1 64)) {
    throw 'capacity-policy-absolute-maximum-invalid'
  }
  $absoluteMaximum = [int]$Policy.absoluteRequestedMaximum
  if (-not (Test-HchIntegerInRange $Policy.defaultNodeCeiling 1 $absoluteMaximum)) {
    throw 'capacity-policy-default-node-ceiling-invalid'
  }
  if (-not (Test-HchIntegerInRange $Policy.globalAssignmentCeiling 1 4096)) {
    throw 'capacity-policy-global-ceiling-invalid'
  }
  if (-not (Test-HchIntegerInRange $Policy.grantTtlSeconds 30 3600)) {
    throw 'capacity-policy-grant-ttl-invalid'
  }
  if ([bool]$Policy.telemetryMayOnlyReduce -ne $true) {
    throw 'capacity-policy-telemetry-boundary-invalid'
  }

  foreach ($capacityClass in @('constrained', 'standard', 'accelerated')) {
    $ceiling = Get-HchNestedValue -InputObject $Policy -Path @('classCeilings', $capacityClass) -Default $null
    if (-not (Test-HchIntegerInRange $ceiling 0 $absoluteMaximum)) {
      throw "capacity-policy-class-ceiling-invalid:$capacityClass"
    }
  }
  foreach ($property in @($Policy.classCeilings.PSObject.Properties)) {
    if ([string]$property.Name -notin @('constrained', 'standard', 'accelerated') -or
        -not (Test-HchIntegerInRange $property.Value 0 $absoluteMaximum)) {
      throw "capacity-policy-class-ceiling-invalid:$($property.Name)"
    }
  }
  foreach ($platform in @('linux', 'macos', 'windows')) {
    $className = [string](Get-HchNestedValue -InputObject $Policy -Path @('platformClasses', $platform) -Default '')
    if ($className -notin @('constrained', 'standard', 'accelerated')) {
      throw "capacity-policy-platform-class-invalid:$platform"
    }
  }
  foreach ($property in @($Policy.platformClasses.PSObject.Properties)) {
    if ([string]$property.Value -notin @('constrained', 'standard', 'accelerated')) {
      throw "capacity-policy-platform-class-invalid:$($property.Name)"
    }
  }
  foreach ($property in @($Policy.nodeClasses.PSObject.Properties)) {
    if ([string]$property.Name -notmatch '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$' -or
        [string]$property.Value -notin @('constrained', 'standard', 'accelerated')) {
      throw "capacity-policy-node-class-invalid:$($property.Name)"
    }
  }
  foreach ($property in @($Policy.nodeCeilings.PSObject.Properties)) {
    if ([string]$property.Name -notmatch '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$' -or
        -not (Test-HchIntegerInRange $property.Value 0 $absoluteMaximum)) {
      throw "capacity-policy-node-ceiling-invalid:$($property.Name)"
    }
  }

  foreach ($field in @('softLimitPercent', 'hardLimitPercent', 'softReductionFactor')) {
    if (-not ($Policy.pressure.PSObject.Properties.Name -contains $field)) {
      throw "capacity-policy-pressure-field-missing:$field"
    }
  }
  foreach ($field in $Policy.pressure.PSObject.Properties.Name) {
    if ([string]$field -notin @('softLimitPercent', 'hardLimitPercent', 'softReductionFactor')) {
      throw "capacity-policy-pressure-field-unsupported:$field"
    }
  }
  try {
    $softLimit = [double]$Policy.pressure.softLimitPercent
    $hardLimit = [double]$Policy.pressure.hardLimitPercent
    $reductionFactor = [double]$Policy.pressure.softReductionFactor
  } catch { throw 'capacity-policy-pressure-invalid' }
  if ([double]::IsNaN($softLimit) -or [double]::IsInfinity($softLimit) -or
      [double]::IsNaN($hardLimit) -or [double]::IsInfinity($hardLimit) -or
      [double]::IsNaN($reductionFactor) -or [double]::IsInfinity($reductionFactor) -or
      $softLimit -lt 0 -or $hardLimit -gt 100 -or $softLimit -ge $hardLimit -or
      $reductionFactor -lt 0 -or $reductionFactor -gt 1) {
    throw 'capacity-policy-pressure-invalid'
  }
  return $Policy
}

function Assert-HchAdaptiveWorkPolicy {
  param([Parameter(Mandatory = $true)]$Policy)
  $required = @(
    'algorithmVersion', 'processingWindowSeconds', 'nearWindowRatio',
    'firstProgressGraceSeconds', 'stallAfterSeconds', 'finalizationGraceSeconds',
    'windowMode', 'minimumTierIgnoresWindow', 'livenessBasis', 'tiers'
  )
  foreach ($field in $required) {
    if (-not ($Policy.PSObject.Properties.Name -contains $field)) {
      throw "adaptive-work-policy-field-missing:$field"
    }
  }
  foreach ($field in $Policy.PSObject.Properties.Name) {
    if ([string]$field -notin $required) { throw "adaptive-work-policy-field-unsupported:$field" }
  }
  if ([string]$Policy.algorithmVersion -ne 'hch-adaptive-work-v1' -or
      [string]$Policy.windowMode -ne 'advisory' -or
      [bool]$Policy.minimumTierIgnoresWindow -ne $true -or
      [string]$Policy.livenessBasis -ne 'progress') {
    throw 'adaptive-work-policy-semantics-invalid'
  }
  if (-not (Test-HchIntegerInRange $Policy.processingWindowSeconds 60 86400) -or
      -not (Test-HchIntegerInRange $Policy.firstProgressGraceSeconds 30 86400) -or
      -not (Test-HchIntegerInRange $Policy.stallAfterSeconds 30 86400) -or
      -not (Test-HchIntegerInRange $Policy.finalizationGraceSeconds 30 86400)) {
    throw 'adaptive-work-policy-grace-invalid'
  }
  try { $nearWindowRatio = [double]$Policy.nearWindowRatio }
  catch { throw 'adaptive-work-policy-near-window-invalid' }
  if ([double]::IsNaN($nearWindowRatio) -or [double]::IsInfinity($nearWindowRatio) -or
      $nearWindowRatio -le 0 -or $nearWindowRatio -gt 1) {
    throw 'adaptive-work-policy-near-window-invalid'
  }
  $tiers = @($Policy.tiers)
  if ($tiers.Count -lt 1 -or $tiers.Count -gt 16) { throw 'adaptive-work-policy-tiers-invalid' }
  $seenIds = @{}
  $seenRanks = @{}
  $minimumCount = 0
  foreach ($tier in $tiers) {
    $tierRequired = @('id', 'rank', 'minimumUnit', 'maxOutputTokens', 'editorialProfile')
    foreach ($field in $tierRequired) {
      if (-not ($tier.PSObject.Properties.Name -contains $field)) {
        throw "adaptive-work-tier-field-missing:$field"
      }
    }
    foreach ($field in $tier.PSObject.Properties.Name) {
      if ([string]$field -notin $tierRequired) { throw "adaptive-work-tier-field-unsupported:$field" }
    }
    $tierId = [string]$tier.id
    $rank = [int]$tier.rank
    if ($tierId -notmatch '^[a-z][a-z0-9-]{0,31}$' -or
        -not (Test-HchIntegerInRange $tier.rank 0 15) -or
        -not (Test-HchIntegerInRange $tier.maxOutputTokens 1 32768) -or
        [string]$tier.editorialProfile -notin @(
          'EDITORIAL_LONG_FORM', 'EDITORIAL_COMPACT', 'EDITORIAL_MINIMUM'
        )) {
      throw "adaptive-work-tier-invalid:$tierId"
    }
    if ($seenIds.ContainsKey($tierId) -or $seenRanks.ContainsKey([string]$rank)) {
      throw 'adaptive-work-tier-duplicate'
    }
    $seenIds[$tierId] = $true
    $seenRanks[[string]$rank] = $true
    if ([bool]$tier.minimumUnit) {
      $minimumCount++
      if ($rank -ne 0) { throw 'adaptive-work-minimum-tier-rank-invalid' }
    }
  }
  if ($minimumCount -ne 1) { throw 'adaptive-work-minimum-tier-invalid' }
  $orderedTiers = @($tiers | Sort-Object -Property rank)
  for ($index = 0; $index -lt $orderedTiers.Count; $index++) {
    $tier = $orderedTiers[$index]
    if ([int]$tier.rank -ne $index -or
        ($index -gt 0 -and
          [int]$tier.maxOutputTokens -le [int]$orderedTiers[$index - 1].maxOutputTokens)) {
      throw 'adaptive-work-tier-order-invalid'
    }
  }
  return $Policy
}

function Get-HchInstalledAdaptiveWorkPolicy {
  param([Parameter(Mandatory = $true)][hashtable]$Config)
  $enginePath = Get-HchSafeInstallPath -Config $Config -RelativePath 'config\engine.json'
  $appliedPath = Join-Path ([string]$Config.StateRoot) 'applied-manifest.json'
  $readyPath = Join-Path ([string]$Config.StateRoot) 'ready.json'
  if (-not (Test-Path -LiteralPath $enginePath -PathType Leaf) -or
      -not (Test-Path -LiteralPath $appliedPath -PathType Leaf) -or
      -not (Test-Path -LiteralPath $readyPath -PathType Leaf)) {
    throw 'installed-adaptive-work-policy-missing'
  }
  try {
    $engine = Read-HchJsonFile -Path $enginePath
    $applied = Read-HchJsonFile -Path $appliedPath
    $ready = Read-HchJsonFile -Path $readyPath
  } catch { throw 'installed-adaptive-work-policy-invalid' }
  if (-not ($engine.PSObject.Properties.Name -contains 'adaptiveWorkPolicy') -or
      -not ($engine.PSObject.Properties.Name -contains 'adaptiveWorkPolicyHash') -or
      -not ($applied.PSObject.Properties.Name -contains 'adaptiveWorkPolicyHash') -or
      -not ($ready.PSObject.Properties.Name -contains 'adaptiveWorkPolicyHash')) {
    throw 'installed-adaptive-work-policy-missing'
  }
  [void](Assert-HchAdaptiveWorkPolicy -Policy $engine.adaptiveWorkPolicy)
  $actualHash = Get-HchCanonicalSha256 -Config $Config -Value $engine.adaptiveWorkPolicy
  if ([string]$engine.adaptiveWorkPolicyHash -ne $actualHash -or
      [string]$applied.adaptiveWorkPolicyHash -ne $actualHash -or
      [string]$ready.adaptiveWorkPolicyHash -ne $actualHash) {
    throw 'installed-adaptive-work-policy-hash-mismatch'
  }
  return [pscustomobject]@{
    Policy = $engine.adaptiveWorkPolicy
    Hash = $actualHash
    GenerationMaximum = [int]$engine.generation.maxOutputTokens
  }
}

function Assert-HchGenerationPlan {
  param(
    [Parameter(Mandatory = $true)][hashtable]$Config,
    [Parameter(Mandatory = $true)]$Plan,
    [Parameter(Mandatory = $true)]$Entry,
    [Parameter(Mandatory = $true)][string]$PlanHash
  )
  $required = @(
    'algorithmVersion', 'tierId', 'tierRank', 'maxOutputTokens', 'editorialProfile',
    'minimumUnit', 'processingWindowSeconds', 'nearWindowSeconds',
    'firstProgressGraceSeconds', 'stallAfterSeconds', 'finalizationGraceSeconds', 'policyHash'
  )
  foreach ($field in $required) {
    if (-not ($Plan.PSObject.Properties.Name -contains $field)) {
      throw "assignment-generation-plan-field-missing:$field"
    }
  }
  foreach ($field in $Plan.PSObject.Properties.Name) {
    if ([string]$field -notin $required) { throw "assignment-generation-plan-field-unsupported:$field" }
  }
  $expectedHash = Get-HchNormalizedHash -Value $PlanHash
  if ((Get-HchCanonicalSha256 -Config $Config -Value $Plan) -ne $expectedHash) {
    throw 'assignment-generation-plan-hash-mismatch'
  }
  $installed = Get-HchInstalledAdaptiveWorkPolicy -Config $Config
  $policy = $installed.Policy
  $tier = @($policy.tiers | Where-Object {
    [string]$_.id -eq [string]$Plan.tierId -and [int]$_.rank -eq [int]$Plan.tierRank
  }) | Select-Object -First 1
  if ($null -eq $tier) { throw 'assignment-generation-plan-tier-invalid' }
  $nearWindowSeconds = [int][Math]::Floor(
    [double]$policy.processingWindowSeconds * [double]$policy.nearWindowRatio
  )
  $expected = [ordered]@{
    algorithmVersion = [string]$policy.algorithmVersion
    maxOutputTokens = [int]$tier.maxOutputTokens
    minimumUnit = [bool]$tier.minimumUnit
    processingWindowSeconds = [int]$policy.processingWindowSeconds
    nearWindowSeconds = $nearWindowSeconds
    firstProgressGraceSeconds = [int]$policy.firstProgressGraceSeconds
    stallAfterSeconds = [int]$policy.stallAfterSeconds
    finalizationGraceSeconds = [int]$policy.finalizationGraceSeconds
    policyHash = [string]$installed.Hash
  }
  foreach ($field in $expected.Keys) {
    if ([string]$Plan.$field -ne [string]$expected[$field]) {
      throw "assignment-generation-plan-policy-mismatch:$field"
    }
  }
  if ([string]$Plan.editorialProfile -notin @(
      [string]$tier.editorialProfile, 'CATALOG_SUMMARY', 'EVENT_LISTING'
    )) {
    throw 'assignment-generation-plan-profile-invalid'
  }
  if ([int]$Plan.maxOutputTokens -gt [int]$installed.GenerationMaximum) {
    throw 'assignment-generation-plan-exceeds-engine-limit'
  }
  $expectedProfile = if ([string]$Entry.kind -eq 'event') {
    'EVENT_LISTING'
  } elseif ([string]$Entry.kind -eq 'radar') {
    'CATALOG_SUMMARY'
  } else { [string]$tier.editorialProfile }
  if ([string]$Plan.editorialProfile -ne $expectedProfile) {
    throw 'assignment-generation-plan-entry-profile-mismatch'
  }
  return [pscustomobject]@{
    valid = $true
    generationPlanHash = $expectedHash
    policyHash = [string]$installed.Hash
  }
}

function Get-HchExpectedCapacityClass {
  param([hashtable]$Config, $Policy)
  [void](Assert-HchCapacityPolicy -Policy $Policy)
  $capacityClass = [string](Get-HchNestedValue -InputObject $Policy `
    -Path @('nodeClasses', [string]$Config.NodeId) -Default '')
  if ([string]::IsNullOrWhiteSpace($capacityClass)) {
    $capacityClass = [string](Get-HchNestedValue -InputObject $Policy `
      -Path @('platformClasses', 'windows') -Default 'standard')
  }
  if ($capacityClass -notin @('constrained', 'standard', 'accelerated')) {
    throw 'capacity-policy-effective-class-invalid'
  }
  return $capacityClass
}

function Get-HchExpectedNodeCeiling {
  param([hashtable]$Config, $Policy)
  $capacityClass = Get-HchExpectedCapacityClass -Config $Config -Policy $Policy
  $nodeCeiling = Get-HchNestedValue -InputObject $Policy `
    -Path @('nodeCeilings', [string]$Config.NodeId) -Default $null
  if ($null -eq $nodeCeiling) {
    $nodeCeiling = Get-HchNestedValue -InputObject $Policy `
      -Path @('classCeilings', $capacityClass) -Default $Policy.defaultNodeCeiling
  }
  return [int][Math]::Max(0, [Math]::Min([int]$Policy.absoluteRequestedMaximum, [int]$nodeCeiling))
}

function Assert-HchAssignmentIntegrity {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory = $true)][hashtable]$Config,
    [Parameter(Mandatory = $true)]$Assignment
  )
  foreach ($field in @(
    'assignmentId', 'leaseToken', 'leaseExpiresAt', 'inputSnapshotHash', 'entry',
    'runtimeProfile', 'generationPlan', 'generationPlanHash'
  )) {
    if (-not ($Assignment.PSObject.Properties.Name -contains $field)) {
      throw "assignment-integrity-field-missing:$field"
    }
  }
  if ([string]::IsNullOrWhiteSpace([string]$Assignment.assignmentId) -or
      [string]::IsNullOrWhiteSpace([string]$Assignment.leaseToken)) {
    throw 'assignment-integrity-identity-invalid'
  }
  try { $leaseExpiresAt = [DateTimeOffset]::Parse([string]$Assignment.leaseExpiresAt) }
  catch { throw 'assignment-integrity-lease-expiration-invalid' }
  if ($leaseExpiresAt -le [DateTimeOffset]::UtcNow) { throw 'assignment-integrity-lease-expired' }
  $expectedInputHash = Get-HchNormalizedHash -Value ([string]$Assignment.inputSnapshotHash)
  $calculatedInputHash = Get-HchCanonicalSha256 -Config $Config -Value $Assignment.entry
  if ($calculatedInputHash -ne $expectedInputHash) { throw 'assignment-input-snapshot-hash-mismatch' }

  $runtimeProfile = $Assignment.runtimeProfile
  foreach ($field in @('provider', 'engineAdapter', 'engineAdapterVersion')) {
    if (-not ($runtimeProfile.PSObject.Properties.Name -contains $field)) {
      throw "assignment-runtime-profile-field-missing:$field"
    }
    $value = [string]$runtimeProfile.$field
    if ([string]::IsNullOrWhiteSpace($value) -or
        $value -notmatch '^[A-Za-z0-9][A-Za-z0-9._:+/-]{0,159}$') {
      throw "assignment-runtime-profile-field-invalid:$field"
    }
  }
  if (-not ($runtimeProfile.PSObject.Properties.Name -contains 'runtimeProfileHash')) {
    throw 'assignment-runtime-profile-hash-missing'
  }
  $expectedProfileHash = Get-HchNormalizedHash -Value ([string]$runtimeProfile.runtimeProfileHash)
  $profileCore = [ordered]@{}
  foreach ($property in $runtimeProfile.PSObject.Properties) {
    if ([string]$property.Name -ne 'runtimeProfileHash') {
      $profileCore[[string]$property.Name] = $property.Value
    }
  }
  $calculatedProfileHash = Get-HchCanonicalSha256 -Config $Config -Value $profileCore
  if ($calculatedProfileHash -ne $expectedProfileHash) { throw 'assignment-runtime-profile-hash-mismatch' }

  $engineConfigPath = Get-HchSafeInstallPath -Config $Config -RelativePath 'config\engine.json'
  if (-not (Test-Path -LiteralPath $engineConfigPath -PathType Leaf)) {
    throw 'assignment-runtime-profile-engine-config-missing'
  }
  try { $engineConfig = Read-HchJsonFile -Path $engineConfigPath }
  catch { throw 'assignment-runtime-profile-engine-config-invalid' }
  $engineBindings = [ordered]@{
    provider = 'provider'
    engineAdapter = 'adapter'
    engineAdapterVersion = 'adapterVersion'
  }
  foreach ($profileField in $engineBindings.Keys) {
    $engineField = [string]$engineBindings[$profileField]
    $configured = [string](Get-HchNestedValue -InputObject $engineConfig -Path @('engine', $engineField) -Default '')
    if ([string]::IsNullOrWhiteSpace($configured)) {
      throw "assignment-runtime-profile-engine-config-invalid:$engineField"
    }
    if (-not [string]::Equals(
        [string]$runtimeProfile.$profileField,
        $configured,
        [StringComparison]::Ordinal)) {
      throw "assignment-runtime-profile-engine-mismatch:$profileField"
    }
  }
  $planIntegrity = Assert-HchGenerationPlan -Config $Config -Plan $Assignment.generationPlan `
    -Entry $Assignment.entry `
    -PlanHash ([string]$Assignment.generationPlanHash)
  return [pscustomobject]@{
    valid = $true
    assignmentId = [string]$Assignment.assignmentId
    inputSnapshotHash = $expectedInputHash
    runtimeProfileHash = $expectedProfileHash
    generationPlanHash = [string]$planIntegrity.generationPlanHash
  }
}

function Assert-HchDelegationContinuity {
  param(
    [Parameter(Mandatory = $true)][hashtable]$Config,
    [Parameter(Mandatory = $true)][long]$DelegationSequence,
    [Parameter(Mandatory = $true)][string]$DelegationHash
  )
  if ($DelegationSequence -lt 1) { throw 'delegation-sequence-invalid' }
  $normalizedHash = Get-HchNormalizedHash -Value $DelegationHash
  $trustStatePath = Join-Path ([string]$Config.StateRoot) 'trust-state.json'
  if (-not (Test-Path -LiteralPath $trustStatePath -PathType Leaf)) { return }
  try {
    $trustState = Read-HchJsonFile -Path $trustStatePath
    if ([int]$trustState.schemaVersion -ne 1 -or
        [string]$trustState.delegationSequence -notmatch '^[1-9][0-9]*$') {
      throw 'invalid'
    }
    $currentSequence = [long]$trustState.delegationSequence
    $currentHash = Get-HchNormalizedHash -Value ([string]$trustState.delegationHash)
  } catch {
    throw 'delegation-trust-state-invalid'
  }
  if ($DelegationSequence -lt $currentSequence) { throw 'delegation-rollback-detected' }
  if ($DelegationSequence -eq $currentSequence -and $normalizedHash -ne $currentHash) {
    throw 'delegation-equivocation-detected'
  }
}

function Save-HchVerifiedTrustState {
  param(
    [Parameter(Mandatory = $true)][hashtable]$Config,
    [Parameter(Mandatory = $true)]$Verified,
    [Parameter(Mandatory = $true)]$Payload,
    [Parameter(Mandatory = $true)][string]$ManifestHash,
    [Parameter(Mandatory = $true)][string]$PolicyHash,
    [Parameter(Mandatory = $true)][string]$VerifiedAt
  )
  $delegationSequence = [long]$Verified.delegationSequence
  $delegationHash = Get-HchNormalizedHash -Value ([string]$Verified.delegationHash)
  Assert-HchDelegationContinuity -Config $Config -DelegationSequence $delegationSequence `
    -DelegationHash $delegationHash
  $trustState = [ordered]@{
    schema = 'hch.worker-trust-state/v1'
    schemaVersion = 1
    rootKeyId = [string]$Verified.rootKeyId
    rootFingerprint = [string]$Verified.rootFingerprint
    releaseKeyId = [string]$Verified.releaseKeyId
    delegationSequence = $delegationSequence
    delegationHash = $delegationHash
    manifestSequence = [long]$Payload.sequence
    manifestHash = $ManifestHash
    policyHash = $PolicyHash
    verifiedAt = $VerifiedAt
  }
  Write-HchJsonAtomic -Path (Join-Path ([string]$Config.StateRoot) 'trust-state.json') -Value $trustState
  return [pscustomobject]$trustState
}

function Test-HchRawSignature {
  param(
    [Parameter(Mandatory = $true)][hashtable]$Config,
    [Parameter(Mandatory = $true)]$Payload,
    [Parameter(Mandatory = $true)][string]$PublicKeyPath,
    [Parameter(Mandatory = $true)][string]$Signature
  )
  $canonicalPath = Get-HchCanonicalFile -Config $Config -Value $Payload
  try {
    $result = Invoke-HchCrypto -Config $Config -Arguments @(
      'verify', '--public', $PublicKeyPath, '--input', $canonicalPath, '--signature', $Signature
    )
    return [bool]$result.valid
  } finally {
    Remove-Item -LiteralPath $canonicalPath -Force -ErrorAction SilentlyContinue
  }
}

function Test-HchSignedManifest {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory = $true)][hashtable]$Config,
    [Parameter(Mandatory = $true)]$Envelope
  )

  $rootPath = [string]$Config.RootPublicKeyPath
  if (-not (Test-Path -LiteralPath $rootPath -PathType Leaf)) { throw 'pinned-root-public-key-not-found' }
  $envelopePath = Join-Path ([IO.Path]::GetTempPath()) ('hch-manifest-envelope-' + [guid]::NewGuid().ToString('n') + '.json')
  $payloadPath = Join-Path ([IO.Path]::GetTempPath()) ('hch-manifest-payload-' + [guid]::NewGuid().ToString('n') + '.json')
  try {
    Write-HchUtf8File -Path $envelopePath -Content ($Envelope | ConvertTo-Json -Depth 100 -Compress)
    $verifyArguments = @(
      'verify-chain', '--root', $rootPath, '--envelope', $envelopePath,
      '--output', $payloadPath, '--clock-skew', [string](Get-HchConfigValue $Config 'ClockSkewSeconds' 60)
    )
    $appliedPath = Join-Path ([string]$Config.StateRoot) 'applied-manifest.json'
    if (Test-Path -LiteralPath $appliedPath -PathType Leaf) {
      try {
        $applied = Read-HchJsonFile -Path $appliedPath
        $appliedHash = Get-HchNormalizedHash -Value ([string]$applied.manifestHash)
        $verifyArguments += @('--allow-expired-hash', $appliedHash)
      } catch { throw 'worker-applied-manifest-invalid' }
    }
    $verified = Invoke-HchCrypto -Config $Config -Arguments $verifyArguments
    $payload = Read-HchJsonFile -Path $payloadPath
  } catch {
    $script:LastTrustObservation = [ordered]@{
      status = 'error'; rootKeyId = $null; releaseKeyId = $null
      manifestSequence = $null; manifestHash = $null; policyHash = $null
      lastVerifiedAt = $null; errorCode = 'manifest-signature-verification-failed'
    }
    throw
  } finally {
    Remove-Item -LiteralPath $envelopePath -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $payloadPath -Force -ErrorAction SilentlyContinue
  }
  if ([string]$payload.schemaVersion -ne '2.0') { throw 'manifest-schema-unsupported' }
  $sequence = [long]$payload.sequence
  if ($sequence -lt 1) { throw 'manifest-sequence-invalid' }
  if (-not ($verified.PSObject.Properties.Name -contains 'delegationSequence') -or
      -not ($verified.PSObject.Properties.Name -contains 'delegationHash') -or
      [string]$verified.delegationSequence -notmatch '^[1-9][0-9]*$') {
    throw 'delegation-verification-metadata-invalid'
  }
  $delegationSequence = [long]$verified.delegationSequence
  $delegationHash = Get-HchNormalizedHash -Value ([string]$verified.delegationHash)
  Assert-HchDelegationContinuity -Config $Config -DelegationSequence $delegationSequence `
    -DelegationHash $delegationHash
  $manifestHash = Get-HchNormalizedHash -Value ([string]$payload.hash)
  if ($manifestHash -ne (Get-HchNormalizedHash -Value ([string]$verified.manifestHash))) {
    throw 'manifest-helper-hash-mismatch'
  }
  foreach ($field in @('provider', 'adapter', 'adapterVersion')) {
    $value = [string](Get-HchNestedValue -InputObject $payload -Path @('engine', $field) -Default '')
    if ([string]::IsNullOrWhiteSpace($value) -or
        $value -notmatch '^[A-Za-z0-9][A-Za-z0-9._:+/-]{0,159}$') {
      throw "manifest-engine-field-invalid:$field"
    }
  }
  if (-not ($payload.PSObject.Properties.Name -contains 'capacityPolicy') -or
      -not ($payload.PSObject.Properties.Name -contains 'adaptiveWorkPolicy')) {
    throw 'manifest-signed-worker-policy-missing'
  }
  [void](Assert-HchCapacityPolicy -Policy $payload.capacityPolicy)
  [void](Assert-HchAdaptiveWorkPolicy -Policy $payload.adaptiveWorkPolicy)
  $verifiedAt = [DateTimeOffset]::UtcNow.ToString('o')
  $policyHash = if ($payload.PSObject.Properties.Name -contains 'editorial') {
    [string]$payload.editorial.policyHash
  } else { $null }
  $seenActions = @{}
  foreach ($action in @($payload.actions)) {
    if ([string]$action.authorizationClass -eq 'root-required' -or
        [string]$action.type -in @('install-runtime-artifact', 'install-engine-adapter')) {
      Set-HchWorkerStatus -Config $Config -State 'update-failed' `
        -Code ('root-action-refused-no-canonical-authorization:' + [string]$action.type)
      throw "root-action-refused-no-canonical-authorization:$($action.type)"
    }
    if ([string]$action.authorizationClass -ne 'release') { throw 'manifest-action-authorization-invalid' }
    if (-not ($script:AllowedActionTypes -contains [string]$action.type)) {
      throw "manifest-action-not-allowed:$($action.type)"
    }
    foreach ($field in $action.PSObject.Properties.Name) {
      if ([string]$field -notin @('type', 'authorizationClass')) {
        throw "manifest-action-forbidden-field:$field"
      }
    }
    if ($seenActions.ContainsKey([string]$action.type)) { throw "manifest-action-duplicate:$($action.type)" }
    $seenActions[[string]$action.type] = $true
  }
  if (-not ($payload.PSObject.Properties.Name -contains 'rootActionCapabilities')) {
    throw 'manifest-root-action-capabilities-missing'
  }
  $seenCapabilities = @{}
  foreach ($capability in @($payload.rootActionCapabilities)) {
    foreach ($field in $capability.PSObject.Properties.Name) {
      if ([string]$field -notin @('type', 'status')) {
        throw "manifest-root-capability-forbidden-field:$field"
      }
    }
    if ([string]$capability.type -notin @('install-runtime-artifact', 'install-engine-adapter') -or
        [string]$capability.status -ne 'requires-separate-root-envelope') {
      throw 'manifest-root-capability-invalid'
    }
    if ($seenCapabilities.ContainsKey([string]$capability.type)) {
      throw "manifest-root-capability-duplicate:$($capability.type)"
    }
    $seenCapabilities[[string]$capability.type] = $true
  }
  foreach ($artifact in @($payload.artifacts)) {
    if ([string]$artifact.authorizationClass -ne 'release') { throw 'root-artifact-refused' }
  }
  if ([bool]$payload.security.authorizationByIp -or [bool]$payload.security.arbitraryRemoteCommands) {
    throw 'manifest-security-boundary-invalid'
  }
  Assert-HchManifestContinuity -Config $Config -Payload $payload -ManifestHash $manifestHash
  [void](Save-HchVerifiedTrustState -Config $Config -Verified $verified -Payload $payload `
    -ManifestHash $manifestHash -PolicyHash $policyHash -VerifiedAt $verifiedAt)
  $script:LastTrustObservation = [ordered]@{
    status = 'verified'
    rootKeyId = [string]$verified.rootKeyId
    releaseKeyId = [string]$verified.releaseKeyId
    manifestSequence = [long]$payload.sequence
    manifestHash = $manifestHash
    policyHash = $policyHash
    lastVerifiedAt = $verifiedAt
    errorCode = $null
  }
  return [pscustomobject]@{
    Payload = $payload
    Envelope = $Envelope
    ManifestHash = $manifestHash
    RootKeyId = [string]$verified.rootKeyId
    ReleaseKeyId = [string]$verified.releaseKeyId
    DelegationSequence = $delegationSequence
    DelegationHash = $delegationHash
    VerifiedAt = $verifiedAt
  }
}

function Assert-HchManifestContinuity {
  param(
    [Parameter(Mandatory = $true)][hashtable]$Config,
    [Parameter(Mandatory = $true)]$Payload,
    [Parameter(Mandatory = $true)][string]$ManifestHash
  )
  $appliedPath = Join-Path ([string]$Config.StateRoot) 'applied-manifest.json'
  if (-not (Test-Path -LiteralPath $appliedPath)) { return }
  $applied = Read-HchJsonFile -Path $appliedPath
  $currentSequence = [long]$applied.sequence
  $newSequence = [long]$Payload.sequence
  if ($newSequence -lt $currentSequence) { throw 'manifest-rollback-detected' }
  if ($newSequence -eq $currentSequence) {
    if ([string]$applied.manifestHash -ne $ManifestHash) { throw 'manifest-equivocation-detected' }
    return
  }
  $previousHash = Get-HchNormalizedHash -Value ([string]$Payload.previousManifestHash)
  if ($previousHash -ne (Get-HchNormalizedHash -Value ([string]$applied.manifestHash))) {
    throw 'manifest-chain-discontinuity'
  }
  if ($Payload.PSObject.Properties.Name -contains 'minimumAcceptedSequence') {
    if ([long]$Payload.minimumAcceptedSequence -gt $newSequence) { throw 'manifest-minimum-sequence-invalid' }
  }
}

function Get-HchRequestSignatureBase {
  param(
    [string]$Method,
    [Uri]$Uri,
    [hashtable]$Headers,
    [long]$Created,
    [long]$Expires,
    [string]$KeyId
  )
  $components = @(
    '@method', '@authority', '@path', 'content-digest', 'content-type',
    'x-hch-node-id', 'x-hch-key-id', 'x-hch-request-id',
    'x-hch-created', 'x-hch-expires', 'x-hch-nonce'
  )
  $componentList = ($components | ForEach-Object { '"' + $_ + '"' }) -join ' '
  $signatureParameters = "($componentList);created=$Created;expires=$Expires;keyid=`"$KeyId`";alg=`"ed25519`";tag=`"hch-editorial-worker-request/v1`""
  $lines = @(
    '"@method": ' + $Method.ToUpperInvariant()
    '"@authority": ' + $Uri.Authority.ToLowerInvariant()
    '"@path": ' + $Uri.AbsolutePath
    '"content-digest": ' + $Headers['content-digest']
    '"content-type": ' + $Headers['content-type']
    '"x-hch-node-id": ' + $Headers['x-hch-node-id']
    '"x-hch-key-id": ' + $Headers['x-hch-key-id']
    '"x-hch-request-id": ' + $Headers['x-hch-request-id']
    '"x-hch-created": ' + $Headers['x-hch-created']
    '"x-hch-expires": ' + $Headers['x-hch-expires']
    '"x-hch-nonce": ' + $Headers['x-hch-nonce']
    '"@signature-params": ' + $signatureParameters
  )
  return [pscustomobject]@{ Base = ($lines -join "`n"); Parameters = $signatureParameters }
}

function Resolve-HchControlPlaneUri {
  param([hashtable]$Config, [string]$Path)
  $controlPlane = [Uri]$Config.ControlPlaneBaseUri
  $uri = [Uri]::new($controlPlane, $Path)
  if ($uri.Scheme -ne $controlPlane.Scheme -or
      -not [string]::Equals($uri.Host, $controlPlane.Host, [StringComparison]::OrdinalIgnoreCase) -or
      $uri.Port -ne $controlPlane.Port) {
    throw 'control-plane-request-origin-mismatch'
  }
  if (-not [string]::IsNullOrEmpty($uri.Query) -or -not [string]::IsNullOrEmpty($uri.Fragment)) {
    throw 'signed-control-plane-query-or-fragment-refused'
  }
  return $uri
}

function Wait-HchTaskWithinDeadline {
  param(
    [Parameter(Mandatory = $true)][Threading.Tasks.Task]$Task,
    [Parameter(Mandatory = $true)][Diagnostics.Stopwatch]$Stopwatch,
    [Parameter(Mandatory = $true)][ValidateRange(1, 7200000)][long]$TimeoutMilliseconds,
    [Parameter(Mandatory = $true)][string]$TimeoutCode,
    [AllowNull()][Threading.CancellationTokenSource]$CancellationSource = $null
  )
  $remaining = [long]$TimeoutMilliseconds - [long]$Stopwatch.ElapsedMilliseconds
  if ($remaining -le 0) {
    if ($null -ne $CancellationSource) {
      try { $CancellationSource.Cancel() } catch { }
    }
    throw [TimeoutException]::new($TimeoutCode)
  }
  $waitMilliseconds = [int][Math]::Min([long][int]::MaxValue, $remaining)
  try {
    $completed = $Task.Wait($waitMilliseconds)
  } catch {
    if ($Task.IsCanceled -or
        ($null -ne $CancellationSource -and $CancellationSource.IsCancellationRequested) -or
        [long]$Stopwatch.ElapsedMilliseconds -ge $TimeoutMilliseconds) {
      throw [TimeoutException]::new($TimeoutCode, $_.Exception)
    }
    $taskError = $_.Exception
    if ($taskError.InnerException -is [AggregateException]) {
      $taskError = $taskError.InnerException.Flatten().InnerExceptions[0]
    } elseif ($taskError -is [AggregateException]) {
      $taskError = $taskError.Flatten().InnerExceptions[0]
    }
    throw $taskError
  }
  if (-not $completed) {
    if ($null -ne $CancellationSource) {
      try { $CancellationSource.Cancel() } catch { }
    }
    throw [TimeoutException]::new($TimeoutCode)
  }
  try {
    return $Task.GetAwaiter().GetResult()
  } catch {
    if ($Task.IsCanceled -or
        ($null -ne $CancellationSource -and $CancellationSource.IsCancellationRequested) -or
        [long]$Stopwatch.ElapsedMilliseconds -ge $TimeoutMilliseconds) {
      throw [TimeoutException]::new($TimeoutCode, $_.Exception)
    }
    throw
  }
}

function Invoke-HchSignedJsonRequest {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory = $true)][hashtable]$Config,
    [Parameter(Mandatory = $true)]$Identity,
    [Parameter(Mandatory = $true)][ValidateSet('GET', 'POST')][string]$Method,
    [Parameter(Mandatory = $true)][string]$Path,
    [Parameter(Mandatory = $true)][string]$Nonce,
    [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$')][string]$RequestId = '',
    [ValidateRange(1, 7200)][int]$TimeoutSeconds = 120,
    $Body = $null
  )
  if ($Nonce -notmatch '^[A-Za-z0-9._~+\/=:-]{16,512}$') { throw 'request-nonce-invalid' }
  $uri = Resolve-HchControlPlaneUri -Config $Config -Path $Path
  $bodyBytes = [byte[]]@()
  if ($null -ne $Body) {
    $canonicalBody = Get-HchCanonicalFile -Config $Config -Value $Body
    try { $bodyBytes = [IO.File]::ReadAllBytes($canonicalBody) }
    finally { Remove-Item -LiteralPath $canonicalBody -Force -ErrorAction SilentlyContinue }
  }
  $sha = [Security.Cryptography.SHA256]::Create()
  try { $digest = [Convert]::ToBase64String($sha.ComputeHash($bodyBytes)) }
  finally { $sha.Dispose() }
  $created = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
  $expires = $created + [int](Get-HchConfigValue $Config 'RequestLifetimeSeconds' 120)
  if ([string]::IsNullOrWhiteSpace($RequestId)) { $RequestId = [guid]::NewGuid().ToString('n') }
  $headers = @{
    'content-digest' = "sha-256=:${digest}:"
    'content-type' = 'application/json'
    'x-hch-node-id' = [string]$Config.NodeId
    'x-hch-key-id' = [string]$Identity.keyId
    'x-hch-request-id' = $RequestId
    'x-hch-created' = [string]$created
    'x-hch-expires' = [string]$expires
    'x-hch-nonce' = $Nonce
  }
  $signatureBase = Get-HchRequestSignatureBase -Method $Method -Uri $uri -Headers $headers `
    -Created $created -Expires $expires -KeyId ([string]$Identity.keyId)
  $basePath = Join-Path ([IO.Path]::GetTempPath()) ('hch-http-signature-' + [guid]::NewGuid().ToString('n'))
  try {
    Write-HchUtf8File -Path $basePath -Content $signatureBase.Base
    $signature = Invoke-HchCrypto -Config $Config -Arguments @(
      'sign', '--private', [string]$Identity.privateKeyPath, '--input', $basePath
    )
  } finally {
    Remove-Item -LiteralPath $basePath -Force -ErrorAction SilentlyContinue
  }
  $headers['signature-input'] = 'hch=' + $signatureBase.Parameters
  $headers['signature'] = 'hch=:' + [string]$signature.value + ':'
  return Invoke-HchHttpJson -Method $Method -Uri $uri -Headers $headers -BodyBytes $bodyBytes `
    -TimeoutSeconds $TimeoutSeconds -ControlPlaneTransport
}

function Get-HchTlsObservation {
  param(
    [Parameter(Mandatory = $true)][Uri]$Uri,
    [ValidateRange(1, 120)][int]$TimeoutSeconds = 15,
    [ValidateRange(0, 120000)][int]$TimeoutMilliseconds = 0
  )
  $observedAt = [DateTimeOffset]::UtcNow.ToString('o')
  if ($Uri.Scheme -ne 'https') {
    return [ordered]@{
      tlsStatus = 'unavailable'
      certificateStatus = 'unverified'
      certificateExpiresAt = $null
      certificateFingerprint = $null
      errorCode = 'transport-not-https'
      observedAt = $observedAt
    }
  }
  $tcp = $null
  $ssl = $null
  $certificate = $null
  $timer = [Diagnostics.Stopwatch]::StartNew()
  $totalTimeoutMilliseconds = if ($TimeoutMilliseconds -gt 0) {
    [long]$TimeoutMilliseconds
  } else {
    [long]$TimeoutSeconds * 1000L
  }
  try {
    $tcp = [Net.Sockets.TcpClient]::new()
    $connectTask = $tcp.ConnectAsync($Uri.DnsSafeHost, $Uri.Port)
    [void](Wait-HchTaskWithinDeadline -Task $connectTask -Stopwatch $timer `
      -TimeoutMilliseconds $totalTimeoutMilliseconds -TimeoutCode 'tls-connect-timeout')
    if (-not $tcp.Connected) { throw 'tls-connect-failed' }
    $ssl = [Net.Security.SslStream]::new($tcp.GetStream(), $false)
    $authenticateTask = $ssl.AuthenticateAsClientAsync(
      $Uri.DnsSafeHost,
      $null,
      [Security.Authentication.SslProtocols]::None,
      $false
    )
    [void](Wait-HchTaskWithinDeadline -Task $authenticateTask -Stopwatch $timer `
      -TimeoutMilliseconds $totalTimeoutMilliseconds -TimeoutCode 'tls-handshake-timeout')
    if (-not $ssl.IsAuthenticated -or -not $ssl.IsEncrypted -or $null -eq $ssl.RemoteCertificate) {
      throw 'tls-session-not-authenticated'
    }
    $certificate = [Security.Cryptography.X509Certificates.X509Certificate2]::new($ssl.RemoteCertificate)
    $sha = [Security.Cryptography.SHA256]::Create()
    try { $fingerprint = (($sha.ComputeHash($certificate.RawData) | ForEach-Object { $_.ToString('x2') }) -join '') }
    finally { $sha.Dispose() }
    $expires = [DateTimeOffset]::new($certificate.NotAfter.ToUniversalTime())
    $remaining = $expires - [DateTimeOffset]::UtcNow
    $certificateStatus = if ($remaining.TotalSeconds -le 0) { 'expired' }
      elseif ($remaining.TotalDays -le 7) { 'expiring' }
      else { 'valid' }
    if ($certificateStatus -eq 'expired') { throw 'tls-certificate-expired' }
    return [ordered]@{
      tlsStatus = 'verified'
      certificateStatus = $certificateStatus
      certificateExpiresAt = $expires.ToString('o')
      certificateFingerprint = 'sha256:' + $fingerprint
      errorCode = $null
      observedAt = $observedAt
    }
  } catch {
    $errorCode = if ([string]$_.Exception.Message -eq 'tls-connect-timeout') { 'tls-connect-timeout' }
      elseif ([string]$_.Exception.Message -eq 'tls-handshake-timeout') { 'tls-handshake-timeout' }
      elseif ([string]$_.Exception.Message -eq 'tls-certificate-expired') { 'tls-certificate-expired' }
      elseif ([string]$_.Exception.Message -eq 'tls-session-not-authenticated') { 'tls-session-not-authenticated' }
      else { 'tls-certificate-validation-failed' }
    return [ordered]@{
      tlsStatus = 'error'
      certificateStatus = if ($errorCode -eq 'tls-certificate-expired') { 'expired' } else { 'invalid' }
      certificateExpiresAt = if ($null -ne $certificate) {
        [DateTimeOffset]::new($certificate.NotAfter.ToUniversalTime()).ToString('o')
      } else { $null }
      certificateFingerprint = $null
      errorCode = $errorCode
      observedAt = $observedAt
    }
  } finally {
    $timer.Stop()
    if ($null -ne $certificate) { $certificate.Dispose() }
    if ($null -ne $ssl) { $ssl.Dispose() }
    if ($null -ne $tcp) { $tcp.Dispose() }
  }
}

function Invoke-HchHttpJson {
  param(
    [Parameter(Mandatory = $true)][ValidateSet('GET', 'POST')][string]$Method,
    [Parameter(Mandatory = $true)][Uri]$Uri,
    [hashtable]$Headers = @{},
    [byte[]]$BodyBytes = [byte[]]@(),
    [ValidateRange(1, 7200)][int]$TimeoutSeconds = 120,
    [switch]$ControlPlaneTransport
  )
  $httpTimer = [Diagnostics.Stopwatch]::StartNew()
  $totalTimeoutMilliseconds = [long]$TimeoutSeconds * 1000L
  $timeoutCode = if ($ControlPlaneTransport) { 'control-plane-request-timeout' } else { 'http-request-timeout' }
  if ($ControlPlaneTransport) {
    $tlsTimeoutMilliseconds = [long][Math]::Min(15000L,
      $totalTimeoutMilliseconds - [long]$httpTimer.ElapsedMilliseconds)
    if ($tlsTimeoutMilliseconds -le 0) { throw [TimeoutException]::new($timeoutCode) }
    $script:LastTransportObservation = Get-HchTlsObservation -Uri $Uri `
      -TimeoutMilliseconds ([int]$tlsTimeoutMilliseconds)
    if ([string]$script:LastTransportObservation.tlsStatus -ne 'verified' -or
        [string]$script:LastTransportObservation.certificateStatus -notin @('valid', 'expiring')) {
      throw "control-plane-tls-validation-failed:$($script:LastTransportObservation.errorCode)"
    }
  }
  Add-Type -AssemblyName System.Net.Http
  $handler = [Net.Http.HttpClientHandler]::new()
  $handler.AllowAutoRedirect = $false
  $client = [Net.Http.HttpClient]::new($handler)
  $client.Timeout = [Threading.Timeout]::InfiniteTimeSpan
  $cancellation = [Threading.CancellationTokenSource]::new()
  $request = [Net.Http.HttpRequestMessage]::new([Net.Http.HttpMethod]::new($Method), $Uri)
  $response = $null
  $text = ''
  try {
    if ($Method -eq 'GET' -and $BodyBytes.Length -ne 0) {
      throw 'http-get-body-refused'
    }
    if ($Method -eq 'POST') {
      $request.Content = [Net.Http.ByteArrayContent]::new($BodyBytes)
      $request.Content.Headers.ContentType = [Net.Http.Headers.MediaTypeHeaderValue]::Parse('application/json')
    }
    foreach ($name in $Headers.Keys) {
      if ($name -eq 'content-type') { continue }
      if (-not $request.Headers.TryAddWithoutValidation($name, [string]$Headers[$name])) {
        if ($null -eq $request.Content) { throw "http-request-header-refused:$name" }
        [void]$request.Content.Headers.TryAddWithoutValidation($name, [string]$Headers[$name])
      }
    }
    $remainingMilliseconds = $totalTimeoutMilliseconds - [long]$httpTimer.ElapsedMilliseconds
    if ($remainingMilliseconds -le 0) { throw [TimeoutException]::new($timeoutCode) }
    $cancellation.CancelAfter([int][Math]::Min([long][int]::MaxValue, $remainingMilliseconds))
    $sendTask = $client.SendAsync(
      $request,
      [Net.Http.HttpCompletionOption]::ResponseContentRead,
      $cancellation.Token
    )
    $response = Wait-HchTaskWithinDeadline -Task $sendTask -Stopwatch $httpTimer `
      -TimeoutMilliseconds $totalTimeoutMilliseconds -TimeoutCode $timeoutCode `
      -CancellationSource $cancellation
    $readTask = $response.Content.ReadAsStringAsync()
    $text = Wait-HchTaskWithinDeadline -Task $readTask -Stopwatch $httpTimer `
      -TimeoutMilliseconds $totalTimeoutMilliseconds -TimeoutCode $timeoutCode `
      -CancellationSource $cancellation
    if (-not $response.IsSuccessStatusCode) {
      $exception = [InvalidOperationException]::new("orchestrator-request-rejected:$([int]$response.StatusCode):$($text.Substring(0, [Math]::Min(2048, $text.Length)))")
      $exception.Data['HchStatusCode'] = [int]$response.StatusCode
      throw $exception
    }
    if ([string]::IsNullOrWhiteSpace($text)) { return $null }
    return ($text | ConvertFrom-Json)
  } finally {
    $httpTimer.Stop()
    $script:LastHttpTelemetry = [ordered]@{
      requestBytes = [long]$BodyBytes.Length
      responseBytes = [long][Text.Encoding]::UTF8.GetByteCount([string]$text)
      durationMilliseconds = [long]$httpTimer.ElapsedMilliseconds
    }
    if ($null -ne $response) { $response.Dispose() }
    $request.Dispose()
    $cancellation.Dispose()
    $client.Dispose()
    $handler.Dispose()
  }
}

function Invoke-HchUnsignedJsonRequest {
  param(
    [Parameter(Mandatory = $true)][hashtable]$Config,
    [Parameter(Mandatory = $true)][ValidateSet('GET', 'POST')][string]$Method,
    [Parameter(Mandatory = $true)][string]$Path,
    $Body = $null,
    [string]$BearerToken = '',
    [ValidateRange(1, 7200)][int]$TimeoutSeconds = 120
  )
  $uri = Resolve-HchControlPlaneUri -Config $Config -Path $Path
  $headers = @{}
  if (-not [string]::IsNullOrWhiteSpace($BearerToken)) { $headers.authorization = 'Bearer ' + $BearerToken }
  $bytes = [byte[]]@()
  if ($null -ne $Body) {
    $jsonPath = Get-HchCanonicalFile -Config $Config -Value $Body
    try { $bytes = [IO.File]::ReadAllBytes($jsonPath) }
    finally { Remove-Item -LiteralPath $jsonPath -Force -ErrorAction SilentlyContinue }
  }
  return Invoke-HchHttpJson -Method $Method -Uri $uri -Headers $headers -BodyBytes $bytes `
    -TimeoutSeconds $TimeoutSeconds -ControlPlaneTransport
}

function Get-HchChallenge {
  param(
    [hashtable]$Config,
    $Identity,
    [ValidateRange(1, 7200)][int]$TimeoutSeconds = 120,
    [Parameter(Mandatory = $true)][ValidateSet('bootstrap', 'attest', 'claim', 'complete', 'heartbeat', 'node-heartbeat', 'fail')][string]$Purpose
  )
  $clientNonce = 'client-' + [guid]::NewGuid().ToString('n') + [guid]::NewGuid().ToString('n')
  $response = Invoke-HchSignedJsonRequest -Config $Config -Identity $Identity -Method POST `
    -Path '/api/editorial/orchestrator/challenge' -Nonce $clientNonce -Body ([ordered]@{
      nodeId = [string]$Config.NodeId
      keyId = [string]$Identity.keyId
      purpose = $Purpose
    }) -TimeoutSeconds $TimeoutSeconds
  if ([string]$response.nodeId -ne [string]$Config.NodeId -or
      [string]$response.keyId -ne [string]$Identity.keyId -or
      [string]$response.purpose -ne $Purpose) {
    throw 'orchestrator-challenge-response-mismatch'
  }
  if (-not ($response.PSObject.Properties.Name -contains 'nonce')) { throw 'orchestrator-challenge-missing-nonce' }
  if ($response.PSObject.Properties.Name -contains 'expiresAt') {
    if ([DateTimeOffset]::Parse([string]$response.expiresAt) -le [DateTimeOffset]::UtcNow) {
      throw 'orchestrator-challenge-expired'
    }
  }
  return [string]$response.nonce
}

function Invoke-HchWorkerEnrollment {
  [CmdletBinding()]
  param([Parameter(Mandatory = $true)][hashtable]$Config, [Parameter(Mandatory = $true)]$Identity)

  $enrollmentPath = Join-Path ([string]$Config.StateRoot) 'enrolled.json'
  if (Test-Path -LiteralPath $enrollmentPath) {
    $enrolled = Read-HchJsonFile -Path $enrollmentPath
    if ([string]$enrolled.nodeId -eq [string]$Config.NodeId -and [string]$enrolled.keyId -eq [string]$Identity.keyId) {
      return $enrolled
    }
    throw 'enrollment-state-identity-mismatch'
  }
  $publicKey = Get-Content -Raw -LiteralPath ([string]$Identity.publicKeyPath)
  $body = [ordered]@{
    nodeId = [string]$Config.NodeId
    keyId = [string]$Identity.keyId
    publicKeyPem = $publicKey
  }
  $token = [Environment]::GetEnvironmentVariable('HCH_EDITORIAL_ENROLLMENT_TOKEN', 'Process')
  if ([string]::IsNullOrWhiteSpace($token)) {
    $token = [Environment]::GetEnvironmentVariable('HCH_EDITORIAL_ENROLLMENT_TOKEN', 'Machine')
  }
  if ([string]::IsNullOrWhiteSpace($token)) {
    $token = [Environment]::GetEnvironmentVariable('HCH_EDITORIAL_ENROLLMENT_TOKEN', 'User')
  }
  if ([string]::IsNullOrWhiteSpace($token)) { throw 'enrollment-token-not-configured' }
  $response = Invoke-HchUnsignedJsonRequest -Config $Config -Method POST `
    -Path '/api/editorial/orchestrator/enrollment' -Body $body -BearerToken $token
  if ([string]$response.nodeId -ne [string]$Config.NodeId -or [string]$response.keyId -ne [string]$Identity.keyId) {
    throw 'enrollment-response-identity-mismatch'
  }
  if ([string]$response.fingerprint -ne [string]$Identity.keyId) { throw 'enrollment-fingerprint-mismatch' }
  $record = [ordered]@{
    schemaVersion = 2
    nodeId = [string]$Config.NodeId
    keyId = [string]$Identity.keyId
    enrolledAt = [DateTimeOffset]::UtcNow.ToString('o')
    serverState = [string]$response.state
  }
  Write-HchJsonAtomic -Path $enrollmentPath -Value $record
  return [pscustomobject]$record
}

function Get-HchBootUptimeSeconds {
  try {
    $operatingSystem = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
    return [Math]::Max(0, [long]([DateTimeOffset]::UtcNow - [DateTimeOffset]$operatingSystem.LastBootUpTime).TotalSeconds)
  } catch { return $null }
}

function Get-HchPublicKeyId {
  param([hashtable]$Config)
  try { return [string](Get-HchWorkerIdentity -Config $Config).keyId }
  catch { return $null }
}

function Set-HchWorkerStatus {
  param(
    [hashtable]$Config,
    [string]$State,
    [string]$Code = '',
    [string]$ConnectionState = '',
    $CurrentBatch = $null,
    $AssignmentProgress = $null,
    [switch]$ClearAssignmentProgress,
    [switch]$ClearCurrentBatch
  )
  $statusPath = Join-Path ([string]$Config.StateRoot) 'status.json'
  $previous = $null
  if (Test-Path -LiteralPath $statusPath) {
    try { $previous = Read-HchJsonFile -Path $statusPath } catch { $previous = $null }
  }
  $now = [DateTimeOffset]::UtcNow.ToString('o')
  $readyPath = Join-Path ([string]$Config.StateRoot) 'ready.json'
  $ready = $null
  if (Test-Path -LiteralPath $readyPath) {
    try { $ready = Read-HchJsonFile -Path $readyPath } catch { $ready = $null }
  }
  $lastSuccess = if ($null -ne $previous) { $previous.connection.lastSuccessAt } else { $null }
  $lastFailure = if ($null -ne $previous) { $previous.connection.lastFailureAt } else { $null }
  $lastError = if ($null -ne $previous) { $previous.connection.lastErrorCode } else { $null }
  $apiState = if ($null -ne $previous) { [string]$previous.connection.api } else { 'unknown' }
  if ($ConnectionState -eq 'connected') {
    $apiState = 'connected'; $lastSuccess = $now; $lastError = $null
  } elseif ($ConnectionState -eq 'error') {
    $apiState = 'error'; $lastFailure = $now; $lastError = $Code
  }
  if ($ClearCurrentBatch) { $CurrentBatch = $null; $AssignmentProgress = $null }
  elseif ($null -eq $CurrentBatch -and $null -ne $previous) { $CurrentBatch = $previous.currentBatch }
  if ($ClearCurrentBatch -or $ClearAssignmentProgress) { $AssignmentProgress = $null }
  elseif ($null -eq $AssignmentProgress -and $null -ne $previous -and
      $null -ne $previous.PSObject.Properties['progress']) {
    $AssignmentProgress = $previous.progress
  }
  if ($null -ne $AssignmentProgress) {
    $allowedProgressFields = @(
      'assignmentId', 'generationPlanHash', 'phase', 'attempt', 'sequence',
      'contentBytes', 'updatedAt'
    )
    $progressFields = if ($AssignmentProgress -is [Collections.IDictionary]) {
      @($AssignmentProgress.Keys)
    } else { @($AssignmentProgress.PSObject.Properties.Name) }
    foreach ($field in $progressFields) {
      if ([string]$field -notin $allowedProgressFields) {
        throw 'worker-status-progress-field-invalid'
      }
    }
    foreach ($field in $allowedProgressFields) {
      if ([string]$field -notin $progressFields) { throw 'worker-status-progress-field-missing' }
    }
    $assignmentId = [guid]::Empty
    if (-not [guid]::TryParse([string]$AssignmentProgress.assignmentId, [ref]$assignmentId)) {
      throw 'worker-status-progress-assignment-invalid'
    }
    $progressCore = Assert-HchAssignmentProgress -Progress ([pscustomobject][ordered]@{
      phase = [string]$AssignmentProgress.phase
      attempt = [int]$AssignmentProgress.attempt
      sequence = [long]$AssignmentProgress.sequence
      contentBytes = [long]$AssignmentProgress.contentBytes
      updatedAt = [string]$AssignmentProgress.updatedAt
    })
    $AssignmentProgress = [ordered]@{
      assignmentId = $assignmentId.ToString()
      generationPlanHash = Get-HchNormalizedHash `
        -Value ([string]$AssignmentProgress.generationPlanHash)
      phase = [string]$progressCore.phase
      attempt = [int]$progressCore.attempt
      sequence = [long]$progressCore.sequence
      contentBytes = [long]$progressCore.contentBytes
      updatedAt = [string]$progressCore.updatedAt
    }
  }
  $isReady = $null -ne $ready -and [DateTimeOffset]::Parse([string]$ready.readyUntil) -gt [DateTimeOffset]::UtcNow
  $transport = if ($null -ne $script:LastTransportObservation) {
    $script:LastTransportObservation
  } elseif ($null -ne $previous -and $null -ne $previous.PSObject.Properties['transport']) {
    $previous.transport
  } else {
    [ordered]@{
      tlsStatus = 'unknown'; certificateStatus = 'unverified'; certificateExpiresAt = $null
      certificateFingerprint = $null; errorCode = $null
    }
  }
  $trust = if ($null -ne $script:LastTrustObservation) {
    $script:LastTrustObservation
  } elseif ($null -ne $ready) {
    [ordered]@{
      # The renewable ready lease can expire without invalidating the verified
      # root/release/manifest signature chain.
      status = 'verified'
      rootKeyId = Get-HchNestedValue -InputObject $ready -Path @('rootKeyId') -Default $null
      releaseKeyId = Get-HchNestedValue -InputObject $ready -Path @('releaseKeyId') -Default $null
      manifestSequence = [long]$ready.manifestSequence
      manifestHash = [string]$ready.manifestHash
      policyHash = [string]$ready.policyHash
      lastVerifiedAt = Get-HchNestedValue -InputObject $ready -Path @('trustVerifiedAt') -Default $null
      errorCode = if ($isReady) { $null } else { 'ready-attestation-expired' }
    }
  } elseif ($null -ne $previous -and $null -ne $previous.PSObject.Properties['trust']) {
    $previous.trust
  } else {
    [ordered]@{
      status = 'pending'; rootKeyId = $null; releaseKeyId = $null
      manifestSequence = $null; manifestHash = $null; policyHash = $null
      lastVerifiedAt = $null; errorCode = $null
    }
  }
  $record = [ordered]@{
    schema = 'hch.worker-status/v1'
    schemaVersion = 1
    observedAt = $now
    nodeId = [string]$Config.NodeId
    workerKeyId = Get-HchPublicKeyId -Config $Config
    platform = 'windows'
    kitVersion = $script:KitVersion
    state = $State
    running = $State -eq 'processing'
    standby = $State -in @('idle', 'ready', 'standby')
    ready = [bool]$isReady
    readyUntil = if ($isReady) { [string]$ready.readyUntil } else { $null }
    manifestSequence = if ($isReady) { [long]$ready.manifestSequence } else { $null }
    manifestHash = if ($isReady) { [string]$ready.manifestHash } else { $null }
    connection = [ordered]@{
      api = $apiState
      tls = if ([string]$transport.tlsStatus -eq 'verified') { 'verified' }
        elseif ([string]$transport.tlsStatus -eq 'error') { 'error' }
        else { 'unknown' }
      auth = if ($apiState -eq 'connected') { 'ed25519' } else { 'pending' }
      ed25519 = $apiState -eq 'connected'
      lastSuccessAt = $lastSuccess
      lastFailureAt = $lastFailure
      lastErrorCode = $lastError
    }
    transport = [ordered]@{
      tlsStatus = [string]$transport.tlsStatus
      certificateStatus = [string]$transport.certificateStatus
      certificateExpiresAt = Get-HchNestedValue -InputObject $transport -Path @('certificateExpiresAt') -Default $null
      certificateFingerprint = Get-HchNestedValue -InputObject $transport -Path @('certificateFingerprint') -Default $null
      errorCode = Get-HchNestedValue -InputObject $transport -Path @('errorCode') -Default $null
    }
    trust = [ordered]@{
      status = [string]$trust.status
      rootKeyId = Get-HchNestedValue -InputObject $trust -Path @('rootKeyId') -Default $null
      releaseKeyId = Get-HchNestedValue -InputObject $trust -Path @('releaseKeyId') -Default $null
      manifestSequence = Get-HchNestedValue -InputObject $trust -Path @('manifestSequence') -Default $null
      manifestHash = Get-HchNestedValue -InputObject $trust -Path @('manifestHash') -Default $null
      policyHash = Get-HchNestedValue -InputObject $trust -Path @('policyHash') -Default $null
      lastVerifiedAt = Get-HchNestedValue -InputObject $trust -Path @('lastVerifiedAt') -Default $null
      errorCode = Get-HchNestedValue -InputObject $trust -Path @('errorCode') -Default $null
    }
    capacity = if (Test-Path -LiteralPath (Join-Path ([string]$Config.StateRoot) 'capacity.json') -PathType Leaf) {
      $capacity = Read-HchJsonFile -Path (Join-Path ([string]$Config.StateRoot) 'capacity.json')
      [ordered]@{
        requestedCapacity = [int]$capacity.requestedCapacity
        grantedCapacity = [int]$capacity.grantedCapacity
        activeAssignments = [int]$capacity.activeAssignments
        capacityReason = [string]$capacity.capacityReason
        validUntil = $capacity.validUntil
      }
    } else {
      [ordered]@{
        requestedCapacity = 0; grantedCapacity = 0; activeAssignments = 0
        capacityReason = 'not-negotiated'; validUntil = $null
      }
    }
    uptimeSeconds = Get-HchBootUptimeSeconds
    currentBatch = $CurrentBatch
    progress = $AssignmentProgress
    code = $Code
  }
  Write-HchJsonAtomic -Path $statusPath -Value $record
}

function Get-HchResourceMetrics {
  $cpuLoad = $null
  $logicalProcessors = [Environment]::ProcessorCount
  $totalMemory = $null
  $availableMemory = $null
  $gpuStatus = 'unavailable'
  $gpuUtilization = $null
  $gpuErrorCode = 'gpu-metrics-provider-unavailable'
  $receiveBytesPerSecond = $null
  $sendBytesPerSecond = $null
  $rxBytes = $null
  $txBytes = $null
  try {
    $processors = @(Get-CimInstance Win32_Processor -ErrorAction Stop)
    if ($processors.Count -gt 0) {
      $cpuLoad = [Math]::Round((($processors | Measure-Object -Property LoadPercentage -Average).Average), 2)
    }
  } catch { }
  try {
    $operatingSystem = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
    $totalMemory = [long]$operatingSystem.TotalVisibleMemorySize * 1024
    $availableMemory = [long]$operatingSystem.FreePhysicalMemory * 1024
  } catch { }
  $nvidiaCommand = Get-Command 'nvidia-smi.exe' -ErrorAction SilentlyContinue | Select-Object -First 1
  if ($null -ne $nvidiaCommand) {
    try {
      $nvidiaPath = [string]$nvidiaCommand.Source
      $gpuLines = @(& $nvidiaPath '--query-gpu=utilization.gpu' '--format=csv,noheader,nounits' 2>$null)
      $gpuExitCode = $LASTEXITCODE
      $gpuValues = @()
      if ($gpuExitCode -eq 0) {
        foreach ($line in $gpuLines) {
          $parsed = 0.0
          if ([double]::TryParse(
            ([string]$line).Trim(),
            [Globalization.NumberStyles]::Float,
            [Globalization.CultureInfo]::InvariantCulture,
            [ref]$parsed
          )) { $gpuValues += $parsed }
        }
      }
      if ($gpuExitCode -ne 0) {
        $gpuStatus = 'unavailable'; $gpuErrorCode = 'nvidia-smi-query-failed'
      } elseif ($gpuValues.Count -eq 0) {
        $gpuStatus = 'unavailable'; $gpuErrorCode = 'nvidia-gpu-not-detected'
      } else {
        $gpuStatus = 'available'; $gpuErrorCode = $null
        $gpuUtilization = [Math]::Round((($gpuValues | Measure-Object -Average).Average), 2)
      }
    } catch {
      $gpuStatus = 'unavailable'; $gpuErrorCode = 'nvidia-smi-query-failed'
    }
  }
  if ($gpuStatus -ne 'available') {
    try {
      $gpuEngines = @(Get-CimInstance `
        -ClassName Win32_PerfFormattedData_GPUPerformanceCounters_GPUEngine `
        -ErrorAction Stop | Where-Object {
          [string]$_.Name -notmatch '(?i)_Total' -and
          [string]$_.Name -match '(?i)engtype_(3D|Compute)'
        })
      $gpuEngineValues = @($gpuEngines | ForEach-Object {
        if ($null -ne $_.UtilizationPercentage) { [double]$_.UtilizationPercentage }
      })
      if ($gpuEngineValues.Count -gt 0) {
        $gpuStatus = 'available'
        $gpuErrorCode = $null
        $gpuUtilization = [Math]::Round(
          [Math]::Min(100.0, [Math]::Max(0.0, [double](($gpuEngineValues | Measure-Object -Sum).Sum))),
          2
        )
      } else {
        $gpuStatus = 'unavailable'; $gpuErrorCode = 'gpu-performance-engine-unavailable'
      }
    } catch {
      $gpuStatus = 'unavailable'; $gpuErrorCode = 'gpu-performance-counters-unavailable'
    }
  }
  try {
    $interfaces = @(Get-CimInstance Win32_PerfFormattedData_Tcpip_NetworkInterface -ErrorAction Stop |
      Where-Object { [string]$_.Name -ne '_Total' })
    if ($interfaces.Count -gt 0) {
      $receiveBytesPerSecond = [long](($interfaces | Measure-Object -Property BytesReceivedPersec -Sum).Sum)
      $sendBytesPerSecond = [long](($interfaces | Measure-Object -Property BytesSentPersec -Sum).Sum)
    }
  } catch { }
  try {
    if ($null -ne (Get-Command 'Get-NetAdapterStatistics' -ErrorAction SilentlyContinue)) {
      $adapterStatistics = @(Get-NetAdapterStatistics -ErrorAction Stop)
      if ($adapterStatistics.Count -gt 0) {
        $rxBytes = [long](($adapterStatistics | Measure-Object -Property ReceivedBytes -Sum).Sum)
        $txBytes = [long](($adapterStatistics | Measure-Object -Property SentBytes -Sum).Sum)
      }
    }
  } catch { }
  $process = [Diagnostics.Process]::GetCurrentProcess()
  return [ordered]@{
    cpu = [ordered]@{ logicalProcessors = $logicalProcessors; utilizationPercent = $cpuLoad }
    gpu = [ordered]@{
      available = $gpuStatus -eq 'available'
      status = $gpuStatus
      utilizationPercent = $gpuUtilization
      errorCode = $gpuErrorCode
    }
    memory = [ordered]@{
      totalBytes = $totalMemory
      availableBytes = $availableMemory
      processWorkingSetBytes = [long]$process.WorkingSet64
    }
    network = [ordered]@{
      receiveBytesPerSecond = $receiveBytesPerSecond
      sendBytesPerSecond = $sendBytesPerSecond
      rxBytes = $rxBytes
      txBytes = $txBytes
    }
  }
}

function Get-HchWorkerCapacityPressure {
  [CmdletBinding()]
  param()
  $resources = Get-HchResourceMetrics
  $pressure = [ordered]@{}
  if ($null -ne $resources.cpu.utilizationPercent) {
    $pressure.cpuPercent = [Math]::Round(
      [Math]::Min(100.0, [Math]::Max(0.0, [double]$resources.cpu.utilizationPercent)), 2
    )
  }
  if ($null -ne $resources.memory.totalBytes -and $null -ne $resources.memory.availableBytes -and
      [long]$resources.memory.totalBytes -gt 0) {
    $usedMemory = [Math]::Max(0L, [long]$resources.memory.totalBytes - [long]$resources.memory.availableBytes)
    $pressure.memoryPercent = [Math]::Round(
      [Math]::Min(100.0, (100.0 * $usedMemory / [long]$resources.memory.totalBytes)), 2
    )
  }
  if ([bool]$resources.gpu.available -and $null -ne $resources.gpu.utilizationPercent) {
    $pressure.gpuPercent = [Math]::Round(
      [Math]::Min(100.0, [Math]::Max(0.0, [double]$resources.gpu.utilizationPercent)), 2
    )
  }
  return Assert-HchCapacityPressure -Pressure ([pscustomobject]$pressure)
}

function Update-HchWorkerMetrics {
  param(
    [hashtable]$Config,
    [ValidateSet('snapshot', 'bootstrap-success', 'bootstrap-failure', 'claim', 'complete', 'failed', 'discarded')]
    [string]$Event = 'snapshot',
    [int]$ItemCount = 0,
    [long]$DurationMilliseconds = 0,
    [long]$RequestBytes = 0,
    [long]$ResponseBytes = 0,
    $CurrentBatch = $null,
    [switch]$ClearCurrentBatch,
    [switch]$BatchEnded,
    [switch]$RollbackPerformed
  )
  $metricsPath = Join-Path ([string]$Config.StateRoot) 'metrics.json'
  $previous = $null
  if (Test-Path -LiteralPath $metricsPath) {
    try { $previous = Read-HchJsonFile -Path $metricsPath } catch { $previous = $null }
  }
  $batchesTotal = [long](Get-HchNestedValue $previous @('batches', 'total') 0)
  $batchesCompleted = [long](Get-HchNestedValue $previous @('batches', 'completed') 0)
  $batchesFailed = [long](Get-HchNestedValue $previous @('batches', 'failed') 0)
  $jobsClaimed = [long](Get-HchNestedValue $previous @('jobs', 'claimed') 0)
  $jobsRunning = [long](Get-HchNestedValue $previous @('jobs', 'running') 0)
  $preEventJobsRunning = $jobsRunning
  $jobsCompleted = [long](Get-HchNestedValue $previous @('jobs', 'completed') 0)
  $jobsFailed = [long](Get-HchNestedValue $previous @('jobs', 'failed') 0)
  $jobsDiscarded = [long](Get-HchNestedValue $previous @('jobs', 'discarded') 0)
  $updatesSucceeded = [long](Get-HchNestedValue $previous @('updates', 'succeeded') 0)
  $updatesFailed = [long](Get-HchNestedValue $previous @('updates', 'failed') 0)
  $updatesAttempts = [long](Get-HchNestedValue $previous @('updates', 'attempts') ($updatesSucceeded + $updatesFailed))
  $updatesRollbacks = [long](Get-HchNestedValue $previous @('updates', 'rollbacks') 0)
  $totalDuration = [long](Get-HchNestedValue $previous @('performance', 'totalDurationMilliseconds') 0)
  $samples = [long](Get-HchNestedValue $previous @('performance', 'durationSamples') 0)
  $totalRequestBytes = [long](Get-HchNestedValue $previous @('network', 'requestBytes') 0)
  $totalResponseBytes = [long](Get-HchNestedValue $previous @('network', 'responseBytes') 0)
  switch ($Event) {
    'bootstrap-success' { $updatesAttempts++; $updatesSucceeded++ }
    'bootstrap-failure' {
      $updatesAttempts++; $updatesFailed++
      if ($RollbackPerformed) { $updatesRollbacks++ }
    }
    'claim' { if ($ItemCount -gt 0) { $batchesTotal++ }; $jobsClaimed += $ItemCount; $jobsRunning += $ItemCount }
    'complete' {
      $jobsCompleted += $ItemCount; $jobsRunning = [Math]::Max(0, $jobsRunning - $ItemCount)
      if ($BatchEnded) { $batchesCompleted++ }
    }
    'failed' {
      $jobsFailed += $ItemCount; $jobsRunning = [Math]::Max(0, $jobsRunning - $ItemCount)
      if ($BatchEnded) { $batchesFailed++ }
    }
    'discarded' { $jobsDiscarded += $ItemCount; $jobsRunning = [Math]::Max(0, $jobsRunning - $ItemCount) }
  }
  if ($DurationMilliseconds -gt 0) { $totalDuration += $DurationMilliseconds; $samples++ }
  $totalRequestBytes += $RequestBytes
  $totalResponseBytes += $ResponseBytes
  if ($ClearCurrentBatch) { $CurrentBatch = $null }
  elseif ($null -eq $CurrentBatch -and $null -ne $previous) { $CurrentBatch = $previous.currentBatch }
  $resources = Get-HchResourceMetrics

  $nowOffset = [DateTimeOffset]::UtcNow
  $nowText = $nowOffset.ToString('o')
  $currentUptime = Get-HchBootUptimeSeconds
  $intervalSeconds = 0.0
  $intervalMilliseconds = 0L
  $sameBoot = $true
  $previousObservedAt = Get-HchNestedValue $previous @('observedAt') $null
  $previousUptime = Get-HchNestedValue $previous @('uptimeSeconds') $null
  if ($null -ne $previousObservedAt) {
    try {
      $wallInterval = [Math]::Max(0.0, ($nowOffset - [DateTimeOffset]::Parse([string]$previousObservedAt)).TotalSeconds)
      if ($null -ne $previousUptime -and $null -ne $currentUptime) {
        $sameBoot = [long]$currentUptime -ge [long]$previousUptime
        if ($sameBoot) { $intervalSeconds = [Math]::Min($wallInterval, [double]([long]$currentUptime - [long]$previousUptime + 1)) }
      } else { $intervalSeconds = $wallInterval }
      $intervalMilliseconds = [long][Math]::Round($intervalSeconds * 1000)
    } catch { $intervalSeconds = 0.0; $intervalMilliseconds = 0L; $sameBoot = $false }
  }

  $cpuSampleCount = [long](Get-HchNestedValue $previous @('resources', 'cpu', 'sampleCount') 0)
  $cpuAverage = [double](Get-HchNestedValue $previous @('resources', 'cpu', 'averageUtilizationPercent') 0.0)
  $cpuActiveSeconds = [double](Get-HchNestedValue $previous @('resources', 'cpu', 'totalActiveSeconds') 0.0)
  if ($null -ne $resources.cpu.utilizationPercent) {
    $cpuCurrent = [double]$resources.cpu.utilizationPercent
    $cpuAverage = (($cpuAverage * $cpuSampleCount) + $cpuCurrent) / ($cpuSampleCount + 1)
    $cpuSampleCount++
    $cpuActiveSeconds += $intervalSeconds * ($cpuCurrent / 100.0)
  }

  $gpuSampleCount = [long](Get-HchNestedValue $previous @('resources', 'gpu', 'sampleCount') 0)
  $gpuAverage = [double](Get-HchNestedValue $previous @('resources', 'gpu', 'averageUtilizationPercent') 0.0)
  $gpuActiveSeconds = [double](Get-HchNestedValue $previous @('resources', 'gpu', 'totalActiveSeconds') 0.0)
  if ([string]$resources.gpu.status -eq 'available' -and $null -ne $resources.gpu.utilizationPercent) {
    $gpuCurrent = [double]$resources.gpu.utilizationPercent
    $gpuAverage = (($gpuAverage * $gpuSampleCount) + $gpuCurrent) / ($gpuSampleCount + 1)
    $gpuSampleCount++
    $gpuActiveSeconds += $intervalSeconds * ($gpuCurrent / 100.0)
  }

  $memorySampleCount = [long](Get-HchNestedValue $previous @('resources', 'memory', 'perItem', 'sampleCount') 0)
  $memoryAverageBytes = [double](Get-HchNestedValue $previous @('resources', 'memory', 'perItem', 'averageBytes') 0.0)
  $memoryPeakBytes = [long](Get-HchNestedValue $previous @('resources', 'memory', 'perItem', 'peakBytes') 0)
  if ($ItemCount -gt 0 -and $Event -in @('complete', 'failed', 'discarded')) {
    $memoryDenominator = [Math]::Max(1, [Math]::Max($preEventJobsRunning, $ItemCount))
    $memoryPerItemSample = [long]([long]$resources.memory.processWorkingSetBytes / $memoryDenominator)
    $newMemorySampleCount = $memorySampleCount + $ItemCount
    $memoryAverageBytes = (($memoryAverageBytes * $memorySampleCount) + ($memoryPerItemSample * $ItemCount)) / $newMemorySampleCount
    $memorySampleCount = $newMemorySampleCount
    $memoryPeakBytes = [Math]::Max($memoryPeakBytes, $memoryPerItemSample)
  }

  $rxCumulative = [long](Get-HchNestedValue $previous @('network', 'rxBytes') 0)
  $txCumulative = [long](Get-HchNestedValue $previous @('network', 'txBytes') 0)
  $previousSourceRx = Get-HchNestedValue $previous @('network', 'sourceRxBytes') $null
  $previousSourceTx = Get-HchNestedValue $previous @('network', 'sourceTxBytes') $null
  $sourceRx = $previousSourceRx
  $sourceTx = $previousSourceTx
  if ($null -ne $resources.network.rxBytes) {
    $sourceRx = [long]$resources.network.rxBytes
    if ($null -eq $previous) { $rxCumulative = $sourceRx }
    elseif ($null -eq $previousSourceRx) { $rxCumulative = [Math]::Max($rxCumulative, $sourceRx) }
    elseif ($sourceRx -ge [long]$previousSourceRx) { $rxCumulative += $sourceRx - [long]$previousSourceRx }
    else { $rxCumulative += $sourceRx }
  }
  if ($null -ne $resources.network.txBytes) {
    $sourceTx = [long]$resources.network.txBytes
    if ($null -eq $previous) { $txCumulative = $sourceTx }
    elseif ($null -eq $previousSourceTx) { $txCumulative = [Math]::Max($txCumulative, $sourceTx) }
    elseif ($sourceTx -ge [long]$previousSourceTx) { $txCumulative += $sourceTx - [long]$previousSourceTx }
    else { $txCumulative += $sourceTx }
  }

  $statusStandby = $false
  $statusPath = Join-Path ([string]$Config.StateRoot) 'status.json'
  if (Test-Path -LiteralPath $statusPath) {
    try { $statusStandby = [bool](Get-HchNestedValue (Read-HchJsonFile -Path $statusPath) @('standby') $false) } catch { }
  }
  $standbyActive = switch ($Event) {
    'bootstrap-success' { $true; break }
    'bootstrap-failure' { $false; break }
    'claim' { $ItemCount -eq 0; break }
    'complete' { [bool]($BatchEnded -or $ClearCurrentBatch); break }
    'failed' { [bool]($BatchEnded -or $ClearCurrentBatch); break }
    'discarded' { $false; break }
    default { $statusStandby; break }
  }
  $previousStandbyActive = [bool](Get-HchNestedValue $previous @('standby', 'active') $false)
  $standbyTotalMilliseconds = [long](Get-HchNestedValue $previous @('standby', 'totalMilliseconds') 0)
  if ($previousStandbyActive -and $sameBoot) { $standbyTotalMilliseconds += $intervalMilliseconds }
  $standbySince = if ($standbyActive) {
    if ($previousStandbyActive -and $sameBoot) {
      Get-HchNestedValue $previous @('standby', 'since') $nowText
    } else { $nowText }
  } else { $null }

  $perItemMemory = if ($jobsRunning -gt 0) {
    [long]([long]$resources.memory.processWorkingSetBytes / $jobsRunning)
  } else { $null }
  $record = [ordered]@{
    schema = 'hch.worker-metrics/v1'
    schemaVersion = 1
    observedAt = $nowText
    nodeId = [string]$Config.NodeId
    workerKeyId = Get-HchPublicKeyId -Config $Config
    uptimeSeconds = $currentUptime
    resources = [ordered]@{
      cpu = [ordered]@{
        logicalProcessors = [int]$resources.cpu.logicalProcessors
        utilizationPercent = $resources.cpu.utilizationPercent
        totalActiveSeconds = [Math]::Round($cpuActiveSeconds, 3)
        sampleCount = $cpuSampleCount
        averageUtilizationPercent = if ($cpuSampleCount -gt 0) { [Math]::Round($cpuAverage, 2) } else { $null }
      }
      gpu = [ordered]@{
        available = [bool]$resources.gpu.available
        status = [string]$resources.gpu.status
        utilizationPercent = $resources.gpu.utilizationPercent
        totalActiveSeconds = [Math]::Round($gpuActiveSeconds, 3)
        sampleCount = $gpuSampleCount
        averageUtilizationPercent = if ($gpuSampleCount -gt 0) { [Math]::Round($gpuAverage, 2) } else { $null }
        errorCode = $resources.gpu.errorCode
      }
      memory = [ordered]@{
        totalBytes = $resources.memory.totalBytes
        availableBytes = $resources.memory.availableBytes
        processWorkingSetBytes = $resources.memory.processWorkingSetBytes
        estimatedBytesPerRunningItem = $perItemMemory
        perItem = [ordered]@{
          sampleCount = $memorySampleCount
          averageBytes = if ($memorySampleCount -gt 0) { [long][Math]::Round($memoryAverageBytes) } else { $null }
          peakBytes = if ($memorySampleCount -gt 0) { $memoryPeakBytes } else { $null }
        }
      }
    }
    network = [ordered]@{
      receiveBytesPerSecond = $resources.network.receiveBytesPerSecond
      sendBytesPerSecond = $resources.network.sendBytesPerSecond
      requestBytes = $totalRequestBytes
      responseBytes = $totalResponseBytes
      rxBytes = $rxCumulative
      txBytes = $txCumulative
      sourceRxBytes = $sourceRx
      sourceTxBytes = $sourceTx
    }
    batches = [ordered]@{ total = $batchesTotal; completed = $batchesCompleted; failed = $batchesFailed }
    jobs = [ordered]@{
      claimed = $jobsClaimed; running = $jobsRunning; completed = $jobsCompleted
      failed = $jobsFailed; discarded = $jobsDiscarded
    }
    updates = [ordered]@{
      attempts = $updatesAttempts; succeeded = $updatesSucceeded
      failed = $updatesFailed; rollbacks = $updatesRollbacks
    }
    performance = [ordered]@{
      lastDurationMilliseconds = if ($DurationMilliseconds -gt 0) { $DurationMilliseconds } else { $null }
      totalDurationMilliseconds = $totalDuration
      durationSamples = $samples
      averageDurationMilliseconds = if ($samples -gt 0) { [Math]::Round($totalDuration / $samples, 2) } else { $null }
    }
    standby = [ordered]@{
      active = [bool]$standbyActive
      since = $standbySince
      totalMilliseconds = $standbyTotalMilliseconds
    }
    currentBatch = $CurrentBatch
  }
  Write-HchJsonAtomic -Path $metricsPath -Value $record
  return [pscustomobject]$record
}

function Disable-HchWorkerReady {
  param([hashtable]$Config, [string]$Reason)
  $readyPath = Join-Path ([string]$Config.StateRoot) 'ready.json'
  if (Test-Path -LiteralPath $readyPath) {
    $invalidatedPath = Join-Path ([string]$Config.StateRoot) `
      ('ready.invalidated.' + [DateTimeOffset]::UtcNow.ToString('yyyyMMddTHHmmssfffZ') + '.json')
    Move-Item -LiteralPath $readyPath -Destination $invalidatedPath
  }
  Set-HchWorkerStatus -Config $Config -State 'update-required' -Code $Reason -ClearCurrentBatch
}

function Assert-HchClaimGate {
  [CmdletBinding()]
  param([Parameter(Mandatory = $true)][hashtable]$Config)
  $readyPath = Join-Path ([string]$Config.StateRoot) 'ready.json'
  $appliedPath = Join-Path ([string]$Config.StateRoot) 'applied-manifest.json'
  if (-not (Test-Path -LiteralPath $readyPath) -or -not (Test-Path -LiteralPath $appliedPath)) {
    throw 'worker-not-ready-bootstrap-required'
  }
  $ready = Read-HchJsonFile -Path $readyPath
  $applied = Read-HchJsonFile -Path $appliedPath
  if ([string]$ready.nodeId -ne [string]$Config.NodeId) { throw 'ready-state-node-mismatch' }
  if ([string]$ready.workerKeyId -ne [string](Get-HchWorkerIdentity -Config $Config).keyId) {
    throw 'ready-state-worker-key-mismatch'
  }
  if ([DateTimeOffset]::Parse([string]$ready.readyUntil) -le [DateTimeOffset]::UtcNow) {
    Disable-HchWorkerReady -Config $Config -Reason 'ready-attestation-expired'
    throw 'worker-ready-attestation-expired'
  }
  if (-not ($ready.PSObject.Properties.Name -contains 'capacityPolicyHash') -or
      -not ($applied.PSObject.Properties.Name -contains 'capacityPolicyHash') -or
      -not ($ready.PSObject.Properties.Name -contains 'adaptiveWorkPolicyHash') -or
      -not ($applied.PSObject.Properties.Name -contains 'adaptiveWorkPolicyHash') -or
      [string]$ready.manifestHash -ne [string]$applied.manifestHash -or
      [long]$ready.manifestSequence -ne [long]$applied.sequence -or
      [string]$ready.policyHash -ne [string]$applied.policyHash -or
      [string]$ready.capacityPolicyHash -ne [string]$applied.capacityPolicyHash -or
      [string]$ready.adaptiveWorkPolicyHash -ne [string]$applied.adaptiveWorkPolicyHash) {
    Disable-HchWorkerReady -Config $Config -Reason 'ready-manifest-mismatch'
    throw 'worker-ready-manifest-mismatch'
  }
  return $ready
}

function Get-HchSafeInstallPath {
  param(
    [Parameter(Mandatory = $true)][hashtable]$Config,
    [Parameter(Mandatory = $true)][string]$RelativePath
  )
  if ([string]::IsNullOrWhiteSpace($RelativePath) -or [IO.Path]::IsPathRooted($RelativePath)) {
    throw 'install-target-must-be-relative'
  }
  $segments = $RelativePath -split '[\\/]'
  if ($segments -contains '..' -or $segments -contains '.') { throw 'install-target-traversal-rejected' }
  $root = [IO.Path]::GetFullPath([string]$Config.InstallRoot).TrimEnd('\', '/')
  $target = [IO.Path]::GetFullPath((Join-Path $root $RelativePath))
  if (-not $target.StartsWith($root + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) {
    throw 'install-target-outside-root'
  }
  $cursor = $root
  foreach ($segment in $segments) {
    $cursor = Join-Path $cursor $segment
    if (Test-Path -LiteralPath $cursor) {
      $item = Get-Item -Force -LiteralPath $cursor
      if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw 'install-target-reparse-point-rejected'
      }
    }
  }
  return $target
}

function Get-HchOrigin {
  param([Parameter(Mandatory = $true)][Uri]$Uri)
  return $Uri.GetLeftPart([UriPartial]::Authority).TrimEnd('/').ToLowerInvariant()
}

function Assert-HchAllowedOrigin {
  param(
    [Parameter(Mandatory = $true)][Uri]$Uri,
    [Parameter(Mandatory = $true)][object[]]$AllowedOrigins,
    [Parameter(Mandatory = $true)][string]$Purpose
  )
  $origin = Get-HchOrigin -Uri $Uri
  $allowed = @($AllowedOrigins | ForEach-Object {
    if (-not [string]::IsNullOrWhiteSpace([string]$_)) { Get-HchOrigin -Uri ([Uri][string]$_) }
  })
  if (-not ($allowed -contains $origin)) { throw "$Purpose-origin-not-allowed:$origin" }
}

function Resolve-HchArtifactUri {
  param([hashtable]$Config, [string]$Value)
  $uri = $null
  if ([Uri]::TryCreate($Value, [UriKind]::Absolute, [ref]$uri)) { return $uri }
  return [Uri]::new(([Uri]$Config.ControlPlaneBaseUri), $Value)
}

function Save-HchRemoteFile {
  param(
    [Parameter(Mandatory = $true)][Uri]$Uri,
    [Parameter(Mandatory = $true)][string]$Destination,
    [ValidateRange(1, 7200)][int]$TimeoutSeconds = 900
  )
  Add-Type -AssemblyName System.Net.Http
  $handler = [Net.Http.HttpClientHandler]::new()
  $handler.AllowAutoRedirect = $false
  $client = [Net.Http.HttpClient]::new($handler)
  $client.Timeout = [Threading.Timeout]::InfiniteTimeSpan
  $cancellation = [Threading.CancellationTokenSource]::new()
  $timer = [Diagnostics.Stopwatch]::StartNew()
  $timeoutMilliseconds = [long]$TimeoutSeconds * 1000L
  $response = $null
  $inputStream = $null
  $outputStream = $null
  try {
    $cancellation.CancelAfter([int][Math]::Min([long][int]::MaxValue, $timeoutMilliseconds))
    $downloadTask = $client.GetAsync(
      $Uri,
      [Net.Http.HttpCompletionOption]::ResponseHeadersRead,
      $cancellation.Token
    )
    $response = Wait-HchTaskWithinDeadline -Task $downloadTask -Stopwatch $timer `
      -TimeoutMilliseconds $timeoutMilliseconds -TimeoutCode 'artifact-download-timeout' `
      -CancellationSource $cancellation
    if (-not $response.IsSuccessStatusCode) { throw "artifact-download-rejected:$([int]$response.StatusCode)" }
    $streamTask = $response.Content.ReadAsStreamAsync()
    $inputStream = Wait-HchTaskWithinDeadline -Task $streamTask -Stopwatch $timer `
      -TimeoutMilliseconds $timeoutMilliseconds -TimeoutCode 'artifact-download-timeout' `
      -CancellationSource $cancellation
    $outputStream = [IO.File]::Open($Destination, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
    $copyTask = $inputStream.CopyToAsync($outputStream, 81920, $cancellation.Token)
    [void](Wait-HchTaskWithinDeadline -Task $copyTask -Stopwatch $timer `
      -TimeoutMilliseconds $timeoutMilliseconds -TimeoutCode 'artifact-download-timeout' `
      -CancellationSource $cancellation)
  } finally {
    $timer.Stop()
    if ($null -ne $outputStream) { $outputStream.Dispose() }
    if ($null -ne $inputStream) { $inputStream.Dispose() }
    if ($null -ne $response) { $response.Dispose() }
    $cancellation.Dispose()
    $client.Dispose()
    $handler.Dispose()
  }
}

function Stage-HchManifestArtifacts {
  param(
    [hashtable]$Config,
    $Manifest,
    [string]$StagingDirectory
  )
  $artifactDirectory = Join-Path $StagingDirectory 'artifacts'
  New-Item -ItemType Directory -Path $artifactDirectory -Force | Out-Null
  $staged = @{}
  foreach ($artifact in @($Manifest.Payload.artifacts)) {
    $name = [string]$artifact.name
    if ($name -notmatch '^[a-zA-Z0-9._-]{1,120}$') { throw 'artifact-name-invalid' }
    if ($staged.ContainsKey($name)) { throw "artifact-name-duplicate:$name" }
    $uri = Resolve-HchArtifactUri -Config $Config -Value ([string]$artifact.url)
    $allowedOrigins = @(Get-HchConfigValue $Config 'AllowedArtifactOrigins' @($Config.ControlPlaneBaseUri))
    Assert-HchAllowedOrigin -Uri $uri -AllowedOrigins $allowedOrigins -Purpose 'artifact'
    $target = Join-Path $artifactDirectory $name
    Save-HchRemoteFile -Uri $uri -Destination $target `
      -TimeoutSeconds ([int](Get-HchConfigValue $Config 'ArtifactDownloadTimeoutSeconds' 900))
    $actualBytes = (Get-Item -LiteralPath $target).Length
    if ($actualBytes -ne [long]$artifact.bytes) { throw "artifact-size-mismatch:$name" }
    $actualHash = Get-HchSha256File -Path $target
    if ($actualHash -ne (Get-HchNormalizedHash -Value ([string]$artifact.sha256))) {
      throw "artifact-hash-mismatch:$name"
    }
    $staged[$name] = $target
  }
  return $staged
}

function New-HchUpdateTransaction {
  param([hashtable]$Config, [long]$ManifestSequence)
  $transactionId = [guid]::NewGuid().ToString('n')
  $staging = Join-Path (Join-Path ([string]$Config.StateRoot) 'staging') $transactionId
  $backup = Join-Path (Join-Path ([string]$Config.StateRoot) 'backups') `
    (([DateTimeOffset]::UtcNow.ToString('yyyyMMddTHHmmssfffZ')) + '-' + $ManifestSequence + '-' + $transactionId)
  New-Item -ItemType Directory -Path $staging -Force | Out-Null
  New-Item -ItemType Directory -Path $backup -Force | Out-Null
  return [pscustomobject]@{
    Id = $transactionId
    StagingDirectory = $staging
    BackupDirectory = $backup
    JournalPath = Join-Path $backup 'transaction.json'
    Journal = [Collections.ArrayList]::new()
    State = 'staging'
  }
}

function Save-HchTransactionJournal {
  param($Transaction)
  $record = [ordered]@{
    schemaVersion = 2
    transactionId = [string]$Transaction.Id
    state = [string]$Transaction.State
    updatedAt = [DateTimeOffset]::UtcNow.ToString('o')
    changes = @($Transaction.Journal)
  }
  Write-HchJsonAtomic -Path ([string]$Transaction.JournalPath) -Value $record
}

function Backup-HchInstallTarget {
  param([hashtable]$Config, $Transaction, [string]$Target, [string]$Kind = 'file')
  if (@($Transaction.Journal | Where-Object { [string]$_.target -eq $Target }).Count -gt 0) {
    throw 'install-target-modified-more-than-once'
  }
  $root = [IO.Path]::GetFullPath([string]$Config.InstallRoot).TrimEnd('\', '/')
  $relative = $Target.Substring($root.Length).TrimStart('\', '/')
  $existed = Test-Path -LiteralPath $Target
  $backupPath = Join-Path (Join-Path ([string]$Transaction.BackupDirectory) 'files') $relative
  if ($existed -and $Kind -eq 'file') {
    $item = Get-Item -Force -LiteralPath $Target
    if ($item.PSIsContainer) { throw 'install-target-type-mismatch' }
    $backupParent = Split-Path -Parent $backupPath
    New-Item -ItemType Directory -Path $backupParent -Force | Out-Null
    Copy-Item -LiteralPath $Target -Destination $backupPath
  }
  $entry = [pscustomobject]@{
    kind = $Kind
    target = $Target
    backup = $backupPath
    existed = [bool]$existed
    applied = $false
  }
  [void]$Transaction.Journal.Add($entry)
  Save-HchTransactionJournal -Transaction $Transaction
  return $entry
}

function Install-HchStagedFile {
  param([hashtable]$Config, $Transaction, [string]$Source, [string]$RelativeTarget)
  $target = Get-HchSafeInstallPath -Config $Config -RelativePath $RelativeTarget
  $parent = Split-Path -Parent $target
  if (-not (Test-Path -LiteralPath $parent)) { New-Item -ItemType Directory -Path $parent -Force | Out-Null }
  $entry = Backup-HchInstallTarget -Config $Config -Transaction $Transaction -Target $target
  $temporary = Join-Path $parent ('.hch-install-' + [guid]::NewGuid().ToString('n') + '.tmp')
  try {
    Copy-Item -LiteralPath $Source -Destination $temporary
    if (Test-Path -LiteralPath $target) {
      $replaceBackup = Join-Path $parent ('.hch-replace-' + [guid]::NewGuid().ToString('n') + '.bak')
      try { [IO.File]::Replace($temporary, $target, $replaceBackup, $true) }
      finally { Remove-Item -LiteralPath $replaceBackup -Force -ErrorAction SilentlyContinue }
    }
    else { [IO.File]::Move($temporary, $target) }
    $entry.applied = $true
    Save-HchTransactionJournal -Transaction $Transaction
  } finally {
    Remove-Item -LiteralPath $temporary -Force -ErrorAction SilentlyContinue
  }
  return $target
}

function Install-HchJsonConfiguration {
  param([hashtable]$Config, $Transaction, $Value, [string]$RelativeTarget)
  $source = Join-Path ([string]$Transaction.StagingDirectory) `
    ('configuration-' + [guid]::NewGuid().ToString('n') + '.json')
  $canonical = Get-HchCanonicalFile -Config $Config -Value $Value
  try { Copy-Item -LiteralPath $canonical -Destination $source }
  finally { Remove-Item -LiteralPath $canonical -Force -ErrorAction SilentlyContinue }
  return Install-HchStagedFile -Config $Config -Transaction $Transaction `
    -Source $source -RelativeTarget $RelativeTarget
}

function Restore-HchUpdateTransaction {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory = $true)][hashtable]$Config,
    [Parameter(Mandatory = $true)]$Transaction
  )
  $changes = @($Transaction.Journal)
  [Array]::Reverse($changes)
  foreach ($change in $changes) {
    $installRoot = [IO.Path]::GetFullPath([string]$Config.InstallRoot).TrimEnd('\', '/')
    $targetPath = [IO.Path]::GetFullPath([string]$change.target)
    if (-not $targetPath.StartsWith($installRoot + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) {
      throw 'rollback-target-outside-install-root'
    }
    if (-not [bool]$change.applied) { continue }
    if ([string]$change.kind -eq 'file') {
      if ([bool]$change.existed) {
        Copy-Item -LiteralPath ([string]$change.backup) -Destination ([string]$change.target) -Force
      } else {
        Remove-Item -LiteralPath ([string]$change.target) -Force -ErrorAction SilentlyContinue
      }
    } elseif (-not [bool]$change.existed -and (Test-Path -LiteralPath ([string]$change.target))) {
      $children = @(Get-ChildItem -Force -LiteralPath ([string]$change.target))
      if ($children.Count -eq 0) { Remove-Item -LiteralPath ([string]$change.target) -Force }
    }
  }
  $Transaction.State = 'rolled-back'
  Save-HchTransactionJournal -Transaction $Transaction
}

function Invoke-HchModelPull {
  param([hashtable]$Config, $Manifest)
  try {
    if (Test-HchModelAvailable -Config $Config -Manifest $Manifest) { return }
  } catch { }
  $ollama = [Uri](Get-HchConfigValue $Config 'OllamaBaseUri' 'http://127.0.0.1:11434')
  $allowedOrigins = @(Get-HchConfigValue $Config 'AllowedSelfTestOrigins' @('http://127.0.0.1:11434'))
  Assert-HchAllowedOrigin -Uri $ollama -AllowedOrigins $allowedOrigins -Purpose 'engine'
  $pullUri = [Uri]::new($ollama, '/api/pull')
  $body = [ordered]@{ name = [string]$Manifest.Payload.engine.model; stream = $false }
  $jsonPath = Get-HchCanonicalFile -Config $Config -Value $body
  try {
    $bytes = [IO.File]::ReadAllBytes($jsonPath)
    [void](Invoke-HchHttpJson -Method POST -Uri $pullUri -BodyBytes $bytes `
      -TimeoutSeconds ([int](Get-HchConfigValue $Config 'ModelPullTimeoutSeconds' 3600)))
  } finally {
    Remove-Item -LiteralPath $jsonPath -Force -ErrorAction SilentlyContinue
  }
}

function Test-HchModelAvailable {
  param([hashtable]$Config, $Manifest)
  $ollama = [Uri](Get-HchConfigValue $Config 'OllamaBaseUri' 'http://127.0.0.1:11434')
  $allowedOrigins = @(Get-HchConfigValue $Config 'AllowedSelfTestOrigins' @('http://127.0.0.1:11434'))
  Assert-HchAllowedOrigin -Uri $ollama -AllowedOrigins $allowedOrigins -Purpose 'engine'
  $tags = Invoke-HchHttpJson -Method GET -Uri ([Uri]::new($ollama, '/api/tags'))
  $expectedName = [string]$Manifest.Payload.engine.model
  $expectedDigest = Get-HchNormalizedHash -Value ([string]$Manifest.Payload.engine.modelDigest)
  $model = @($tags.models | Where-Object {
    [string]$_.name -eq $expectedName -or [string]$_.model -eq $expectedName
  }) | Select-Object -First 1
  if (-not $model) { throw 'required-model-not-available' }
  if ($model.PSObject.Properties.Name -contains 'digest') {
    if ((Get-HchNormalizedHash -Value ([string]$model.digest)) -ne $expectedDigest) {
      throw 'required-model-digest-mismatch'
    }
  } else {
    throw 'required-model-digest-not-reported'
  }
  return $true
}

function Invoke-HchManifestPlan {
  param([hashtable]$Config, $Manifest, $Transaction, [hashtable]$StagedArtifacts)
  $actionTypes = @($Manifest.Payload.actions | ForEach-Object { [string]$_.type })
  foreach ($required in @('verify-artifact', 'configure-engine', 'pull-model-by-digest', 'apply-editorial-policy', 'self-test')) {
    if (-not ($actionTypes -contains $required)) { throw "manifest-required-action-missing:$required" }
  }
  foreach ($action in @($Manifest.Payload.actions)) {
    switch ([string]$action.type) {
      'verify-artifact' { continue }
      'apply-editorial-policy' {
        foreach ($name in @('policy', 'prompt', 'editorial-content-schema', 'editorial-source-schema')) {
          if (-not $StagedArtifacts.ContainsKey($name)) { throw "editorial-artifact-missing:$name" }
          $extension = if ($name -eq 'prompt') { '.md' } else { '.json' }
          [void](Install-HchStagedFile -Config $Config -Transaction $Transaction `
            -Source ([string]$StagedArtifacts[$name]) -RelativeTarget ('editorial\' + $name + $extension))
        }
      }
      'configure-engine' {
        [void](Assert-HchCapacityPolicy -Policy $Manifest.Payload.capacityPolicy)
        [void](Assert-HchAdaptiveWorkPolicy -Policy $Manifest.Payload.adaptiveWorkPolicy)
        $engineConfig = [ordered]@{
          schemaVersion = 2
          engine = $Manifest.Payload.engine
          generation = $Manifest.Payload.generation
          capacityPolicy = $Manifest.Payload.capacityPolicy
          capacityPolicyHash = Get-HchCanonicalSha256 -Config $Config -Value $Manifest.Payload.capacityPolicy
          adaptiveWorkPolicy = $Manifest.Payload.adaptiveWorkPolicy
          adaptiveWorkPolicyHash = Get-HchCanonicalSha256 -Config $Config -Value $Manifest.Payload.adaptiveWorkPolicy
          manifestSequence = [long]$Manifest.Payload.sequence
          manifestHash = [string]$Manifest.ManifestHash
        }
        [void](Install-HchJsonConfiguration -Config $Config -Transaction $Transaction `
          -Value $engineConfig -RelativeTarget 'config\engine.json')
      }
      'pull-model-by-digest' { Invoke-HchModelPull -Config $Config -Manifest $Manifest }
      'self-test' { continue }
      default { throw "manifest-action-not-allowed:$($action.type)" }
    }
  }
}

function Test-HchAppliedEnvironment {
  param([hashtable]$Config, $Manifest, [hashtable]$StagedArtifacts)
  foreach ($artifact in @($Manifest.Payload.artifacts)) {
    $name = [string]$artifact.name
    if (-not $StagedArtifacts.ContainsKey($name)) { throw "staged-artifact-missing:$name" }
    if ((Get-HchSha256File -Path ([string]$StagedArtifacts[$name])) -ne
        (Get-HchNormalizedHash -Value ([string]$artifact.sha256))) {
      throw "staged-artifact-reverification-failed:$name"
    }
  }
  [void](Test-HchModelAvailable -Config $Config -Manifest $Manifest)
  $engineConfigPath = Get-HchSafeInstallPath -Config $Config -RelativePath 'config\engine.json'
  if (-not (Test-Path -LiteralPath $engineConfigPath -PathType Leaf)) { throw 'engine-configuration-not-applied' }
  try { $engineConfig = Read-HchJsonFile -Path $engineConfigPath }
  catch { throw 'engine-configuration-invalid' }
  foreach ($field in @('provider', 'adapter', 'adapterVersion')) {
    $appliedValue = [string](Get-HchNestedValue -InputObject $engineConfig -Path @('engine', $field) -Default '')
    $manifestValue = [string](Get-HchNestedValue -InputObject $Manifest.Payload -Path @('engine', $field) -Default '')
    if ([string]::IsNullOrWhiteSpace($appliedValue) -or
        -not [string]::Equals($appliedValue, $manifestValue, [StringComparison]::Ordinal)) {
      throw "engine-configuration-mismatch:$field"
    }
  }
  [void](Assert-HchCapacityPolicy -Policy $engineConfig.capacityPolicy)
  $capacityPolicyHash = Get-HchCanonicalSha256 -Config $Config -Value $Manifest.Payload.capacityPolicy
  if ([string]$engineConfig.capacityPolicyHash -ne $capacityPolicyHash -or
      (Get-HchCanonicalSha256 -Config $Config -Value $engineConfig.capacityPolicy) -ne $capacityPolicyHash) {
    throw 'engine-capacity-policy-mismatch'
  }
  [void](Assert-HchAdaptiveWorkPolicy -Policy $engineConfig.adaptiveWorkPolicy)
  $adaptiveWorkPolicyHash = Get-HchCanonicalSha256 -Config $Config `
    -Value $Manifest.Payload.adaptiveWorkPolicy
  if ([string]$engineConfig.adaptiveWorkPolicyHash -ne $adaptiveWorkPolicyHash -or
      (Get-HchCanonicalSha256 -Config $Config -Value $engineConfig.adaptiveWorkPolicy) -ne
        $adaptiveWorkPolicyHash) {
    throw 'engine-adaptive-work-policy-mismatch'
  }
  return [ordered]@{
    configurationApplied = $true
    artifactsVerified = $true
    modelAvailable = $true
    generatorReachable = $true
    selfTestPassed = $true
  }
}

function New-HchUpdateReceipt {
  param([hashtable]$Config, $Identity, $Manifest, $Transaction, [string]$Result)
  if ($Result -notin @('applied', 'no-change')) { throw 'update-receipt-result-invalid' }
  $appliedPath = Join-Path ([string]$Config.StateRoot) 'applied-manifest.json'
  $previousManifestHash = $null
  if (Test-Path -LiteralPath $appliedPath) {
    $previousManifestHash = [string](Read-HchJsonFile -Path $appliedPath).manifestHash
  }
  $artifactHashes = [ordered]@{}
  foreach ($artifact in @($Manifest.Payload.artifacts | Sort-Object -Property name)) {
    $artifactHashes[[string]$artifact.name] = [string]$artifact.sha256
  }
  $appliedAt = [DateTimeOffset]::UtcNow.ToString('o')
  $receiptCore = [ordered]@{
    previousManifestHash = $previousManifestHash
    targetManifestHash = [string]$Manifest.ManifestHash
    artifactHashes = $artifactHashes
    result = $Result
    rollbackPerformed = $false
    appliedAt = $appliedAt
  }
  $sameManifest = -not [string]::IsNullOrWhiteSpace([string]$previousManifestHash) -and
    (Get-HchNormalizedHash -Value ([string]$previousManifestHash)) -eq
    (Get-HchNormalizedHash -Value ([string]$Manifest.ManifestHash))
  if (($sameManifest -and $Result -ne 'no-change') -or (-not $sameManifest -and $Result -ne 'applied')) {
    throw 'update-receipt-result-manifest-consistency-invalid'
  }
  $localLog = [ordered]@{
    schema = 'hch.worker-update-log/v1'
    schemaVersion = 1
    nodeId = [string]$Config.NodeId
    workerKeyId = [string]$Identity.keyId
    transactionId = [string]$Transaction.Id
    previousManifestHash = $previousManifestHash
    targetManifestHash = [string]$Manifest.ManifestHash
    result = $Result
    rollbackPerformed = $false
    appliedAt = $appliedAt
    appliedChanges = @($Transaction.Journal | ForEach-Object {
      [ordered]@{
        target = [string]$_.target
        backup = Get-HchNestedValue -InputObject $_ -Path @('backup') -Default $null
        existed = [bool](Get-HchNestedValue -InputObject $_ -Path @('existed') -Default $false)
        applied = [bool]$_.applied
      }
    })
  }
  $receiptHash = Get-HchCanonicalSha256 -Config $Config -Value $receiptCore
  $localAuditHash = Get-HchCanonicalSha256 -Config $Config -Value $localLog
  $receipt = [ordered]@{}
  foreach ($key in $receiptCore.Keys) { $receipt[$key] = $receiptCore[$key] }
  $receipt.receiptHash = $receiptHash
  $receipt.localAuditHash = $localAuditHash
  $persisted = [ordered]@{ receipt = $receipt; localLog = $localLog }
  Write-HchJsonAtomic -Path (Join-Path ([string]$Transaction.BackupDirectory) 'update-receipt.json') -Value $persisted
  return $receipt
}

function Invoke-HchWorkerBootstrap {
  [CmdletBinding()]
  param([Parameter(Mandatory = $true)][hashtable]$Config)
  # Cycle and node-heartbeat run in separate service processes. Serialize the
  # trust/update transaction so both cannot replace trust-state.json together.
  $bootstrapLockPath = Join-Path ([string]$Config.StateRoot) 'bootstrap.lock'
  $bootstrapLock = $null
  $lockDeadline = [DateTimeOffset]::UtcNow.AddSeconds(60)
  while ($null -eq $bootstrapLock -and [DateTimeOffset]::UtcNow -lt $lockDeadline) {
    try {
      $bootstrapLock = [IO.File]::Open(
        $bootstrapLockPath,
        [IO.FileMode]::OpenOrCreate,
        [IO.FileAccess]::ReadWrite,
        [IO.FileShare]::None
      )
    } catch [IO.IOException] {
      Start-Sleep -Milliseconds 250
    }
  }
  if ($null -eq $bootstrapLock) { throw 'worker-bootstrap-already-running' }
  $transaction = $null
  $timer = [Diagnostics.Stopwatch]::StartNew()
  try {
    $identity = Initialize-HchWorkerIdentity -Config $Config
    Set-HchWorkerStatus -Config $Config -State 'bootstrap-required'
    [void](Invoke-HchWorkerEnrollment -Config $Config -Identity $identity)
    $envelope = Invoke-HchUnsignedJsonRequest -Config $Config -Method GET `
      -Path '/api/editorial/orchestrator/manifest'
    $manifest = Test-HchSignedManifest -Config $Config -Envelope $envelope
    $readyPath = Join-Path ([string]$Config.StateRoot) 'ready.json'
    if (Test-Path -LiteralPath $readyPath) {
      try {
        $ready = Assert-HchClaimGate -Config $Config
        $refreshBeforeSeconds = [int](Get-HchConfigValue $Config 'ReadyRefreshBeforeSeconds' 3000)
        if ($refreshBeforeSeconds -lt 300 -or $refreshBeforeSeconds -gt 3300) {
          throw 'ready-refresh-window-out-of-range'
        }
        $readyRemainingSeconds = ([DateTimeOffset]::Parse([string]$ready.readyUntil) -
          [DateTimeOffset]::UtcNow).TotalSeconds
        if ([string]$ready.manifestHash -eq [string]$manifest.ManifestHash -and
            $readyRemainingSeconds -gt $refreshBeforeSeconds) { return $ready }
      } catch {
        Disable-HchWorkerReady -Config $Config -Reason 'ready-refresh-required'
      }
    }
    Disable-HchWorkerReady -Config $Config -Reason 'manifest-update-started'
    Set-HchWorkerStatus -Config $Config -State 'updating'
    $nonce = Get-HchChallenge -Config $Config -Identity $identity -Purpose 'bootstrap'
    $bootstrapControl = Get-HchWorkerControl -Config $Config
    $bootstrapRequestedCapacity = if ([bool]$bootstrapControl.acceptingClaims) {
      [int]$bootstrapControl.requestedParallelism
    } else { 0 }
    $bootstrapBody = [ordered]@{
      nodeId = [string]$Config.NodeId
      workerKeyId = [string]$identity.keyId
      platform = 'windows'
      architecture = [string]$env:PROCESSOR_ARCHITECTURE
      hostname = [Environment]::MachineName
      requestedCapacity = $bootstrapRequestedCapacity
      manifestSequence = [long]$manifest.Payload.sequence
      manifestHash = [string]$manifest.ManifestHash
      workerRuntimeVersion = $script:KitVersion
    }
    $bootstrapOperationKey = 'bootstrap-request'
    $bootstrapRequestId = Get-HchOperationRequestId -Config $Config `
      -OperationKey $bootstrapOperationKey -Target 'POST:/api/editorial/orchestrator/bootstrap' `
      -Body $bootstrapBody
    $bootstrap = Invoke-HchSignedJsonRequest -Config $Config -Identity $identity -Method POST `
      -Path '/api/editorial/orchestrator/bootstrap' -Nonce $nonce -RequestId $bootstrapRequestId `
      -Body $bootstrapBody
    if ([string]$bootstrap.manifestHash -ne [string]$manifest.ManifestHash) { throw 'bootstrap-manifest-mismatch' }
    if (-not ($bootstrap.PSObject.Properties.Name -contains 'capacityPolicy') -or
        -not ($bootstrap.PSObject.Properties.Name -contains 'adaptiveWorkPolicy') -or
        -not ($bootstrap.PSObject.Properties.Name -contains 'requestedCapacity')) {
      throw 'bootstrap-worker-policy-contract-missing'
    }
    [void](Assert-HchCapacityPolicy -Policy $bootstrap.capacityPolicy)
    [void](Assert-HchAdaptiveWorkPolicy -Policy $bootstrap.adaptiveWorkPolicy)
    $capacityPolicyHash = Get-HchCanonicalSha256 -Config $Config -Value $manifest.Payload.capacityPolicy
    $adaptiveWorkPolicyHash = Get-HchCanonicalSha256 -Config $Config `
      -Value $manifest.Payload.adaptiveWorkPolicy
    if ((Get-HchCanonicalSha256 -Config $Config -Value $bootstrap.capacityPolicy) -ne $capacityPolicyHash -or
        (Get-HchCanonicalSha256 -Config $Config -Value $bootstrap.adaptiveWorkPolicy) -ne
          $adaptiveWorkPolicyHash -or
        [int]$bootstrap.requestedCapacity -ne [int]$bootstrapBody.requestedCapacity) {
      throw 'bootstrap-worker-policy-contract-mismatch'
    }
    Complete-HchOperationRequest -Config $Config -OperationKey $bootstrapOperationKey `
      -RequestId $bootstrapRequestId
    $transaction = New-HchUpdateTransaction -Config $Config -ManifestSequence ([long]$manifest.Payload.sequence)
    $staged = Stage-HchManifestArtifacts -Config $Config -Manifest $manifest `
      -StagingDirectory ([string]$transaction.StagingDirectory)
    $transaction.State = 'applying'
    Save-HchTransactionJournal -Transaction $transaction
    Invoke-HchManifestPlan -Config $Config -Manifest $manifest -Transaction $transaction -StagedArtifacts $staged
    Set-HchWorkerStatus -Config $Config -State 'self-testing'
    $checks = Test-HchAppliedEnvironment -Config $Config -Manifest $manifest -StagedArtifacts $staged
    $receiptResult = 'applied'
    $currentAppliedPath = Join-Path ([string]$Config.StateRoot) 'applied-manifest.json'
    if (Test-Path -LiteralPath $currentAppliedPath) {
      $currentApplied = Read-HchJsonFile -Path $currentAppliedPath
      if ((Get-HchNormalizedHash -Value ([string]$currentApplied.manifestHash)) -eq
          (Get-HchNormalizedHash -Value ([string]$manifest.ManifestHash))) {
        $receiptResult = 'no-change'
      }
    }
    $updateReceipt = New-HchUpdateReceipt -Config $Config -Identity $identity -Manifest $manifest `
      -Transaction $transaction -Result $receiptResult

    $editorial = $manifest.Payload.editorial
    $attestation = [ordered]@{
      nodeId = [string]$Config.NodeId
      workerKeyId = [string]$identity.keyId
      manifestSequence = [long]$manifest.Payload.sequence
      manifestHash = [string]$manifest.ManifestHash
      challenge = [string]$bootstrap.challenge
      workerRuntimeVersion = [string]$script:KitVersion
      policyHash = [string]$editorial.policyHash
      adaptiveWorkPolicyHash = $adaptiveWorkPolicyHash
      promptConfigHash = [string]$editorial.promptConfigHash
      pipelineVersion = [string]$editorial.pipelineVersion
      model = [string]$manifest.Payload.engine.model
      modelDigest = [string]$manifest.Payload.engine.modelDigest
      protocol = [string]$manifest.Payload.engine.protocol
      provider = [string]$manifest.Payload.engine.provider
      engineAdapter = [string]$manifest.Payload.engine.adapter
      engineAdapterVersion = [string]$manifest.Payload.engine.adapterVersion
      checks = $checks
      updateReceipt = $updateReceipt
      appliedChanges = @($transaction.Journal | ForEach-Object {
        [ordered]@{ target = [IO.Path]::GetFileName([string]$_.target); applied = [bool]$_.applied }
      })
    }
    $attestationPath = [string]$bootstrap.attestationUrl
    if ([string]::IsNullOrWhiteSpace($attestationPath)) {
      $attestationPath = '/api/editorial/orchestrator/bootstrap/' + [Uri]::EscapeDataString([string]$bootstrap.bootstrapSessionId) + '/attest'
    }
    $attestNonce = Get-HchChallenge -Config $Config -Identity $identity -Purpose 'attest'
    $attestationOperationKey = 'attest-' + [string]$bootstrap.bootstrapSessionId
    $attestationRequestId = Get-HchOperationRequestId -Config $Config `
      -OperationKey $attestationOperationKey -Target ('POST:' + $attestationPath) -Body $attestation
    $accepted = Invoke-HchSignedJsonRequest -Config $Config -Identity $identity -Method POST `
      -Path $attestationPath -Nonce $attestNonce -RequestId $attestationRequestId -Body $attestation
    if ([string]$accepted.nodeId -ne [string]$Config.NodeId -or
        [string]$accepted.workerKeyId -ne [string]$identity.keyId -or
        [bool]$accepted.compatible -ne $true -or
        [string]$accepted.manifestHash -ne [string]$manifest.ManifestHash -or
        [long]$accepted.manifestSequence -ne [long]$manifest.Payload.sequence -or
        @('idle', 'processing', 'draining') -notcontains [string]$accepted.state -or
        -not ($accepted.PSObject.Properties.Name -contains 'capacity') -or
        -not ($accepted.PSObject.Properties.Name -contains 'serverTime')) {
      throw 'attestation-response-not-ready'
    }
    $attestedCapacity = Assert-HchAttestedCapacityGrant -Config $Config -Capacity $accepted.capacity `
      -RequestedCapacity ([int]$bootstrapBody.requestedCapacity) -Policy $manifest.Payload.capacityPolicy `
      -ServerTime ([string]$accepted.serverTime)
    Complete-HchOperationRequest -Config $Config -OperationKey $attestationOperationKey `
      -RequestId $attestationRequestId
    $appliedRecord = [ordered]@{
      schemaVersion = 2
      sequence = [long]$manifest.Payload.sequence
      manifestHash = [string]$manifest.ManifestHash
      policyHash = [string]$editorial.policyHash
      promptConfigHash = [string]$editorial.promptConfigHash
      pipelineVersion = [string]$editorial.pipelineVersion
      runtimeVersion = [string]$manifest.Payload.runtime.workerVersion
      provider = [string]$manifest.Payload.engine.provider
      engineAdapter = [string]$manifest.Payload.engine.adapter
      engineAdapterVersion = [string]$manifest.Payload.engine.adapterVersion
      model = [string]$manifest.Payload.engine.model
      modelDigest = [string]$manifest.Payload.engine.modelDigest
      capacityPolicyHash = $capacityPolicyHash
      adaptiveWorkPolicyHash = $adaptiveWorkPolicyHash
      transactionId = [string]$transaction.Id
      appliedAt = [DateTimeOffset]::UtcNow.ToString('o')
      rootKeyId = [string]$manifest.RootKeyId
      releaseKeyId = [string]$manifest.ReleaseKeyId
      delegationSequence = [long]$manifest.DelegationSequence
      delegationHash = [string]$manifest.DelegationHash
      trustVerifiedAt = [string]$manifest.VerifiedAt
    }
    Write-HchJsonAtomic -Path (Join-Path ([string]$Config.StateRoot) 'applied-manifest.json') -Value $appliedRecord
    $readyRecord = [ordered]@{
      schemaVersion = 2
      nodeId = [string]$Config.NodeId
      workerKeyId = [string]$identity.keyId
      manifestSequence = [long]$manifest.Payload.sequence
      manifestHash = [string]$manifest.ManifestHash
      policyHash = [string]$editorial.policyHash
      capacityPolicyHash = $capacityPolicyHash
      adaptiveWorkPolicyHash = $adaptiveWorkPolicyHash
      runtimeProfileHash = if ($accepted.PSObject.Properties.Name -contains 'runtimeProfileHash') { [string]$accepted.runtimeProfileHash } else { '' }
      readyUntil = [string]$accepted.readyUntil
      attestedAt = [DateTimeOffset]::UtcNow.ToString('o')
      rootKeyId = [string]$manifest.RootKeyId
      releaseKeyId = [string]$manifest.ReleaseKeyId
      trustVerifiedAt = [string]$manifest.VerifiedAt
    }
    Write-HchJsonAtomic -Path $readyPath -Value $readyRecord
    $capacitySnapshotArguments = @{
      Config = $Config
      RequestedCapacity = [int]$attestedCapacity.requestedCapacity
      GrantedCapacity = [int]$attestedCapacity.grantedCapacity
      CapacityReason = [string]$attestedCapacity.capacityReason
    }
    if ([string]$accepted.state -ne 'processing') { $capacitySnapshotArguments.ActiveAssignments = 0 }
    if ($null -eq $attestedCapacity.validUntil) {
      $capacitySnapshotArguments.ClearValidUntil = $true
    } else {
      $capacitySnapshotArguments.ValidUntil = [string]$attestedCapacity.validUntil
    }
    [void](Set-HchWorkerCapacitySnapshot @capacitySnapshotArguments)
    $transaction.State = 'committed'
    Save-HchTransactionJournal -Transaction $transaction
    if ([string]$accepted.state -eq 'processing') {
      Set-HchWorkerStatus -Config $Config -State 'processing' -ConnectionState 'connected'
    } else {
      $readyState = if ([string]$accepted.state -eq 'draining') { 'standby' } else { 'idle' }
      Set-HchWorkerStatus -Config $Config -State $readyState -ConnectionState 'connected' -ClearCurrentBatch
    }
    [void](Update-HchWorkerMetrics -Config $Config -Event 'bootstrap-success' `
      -DurationMilliseconds ([long]$timer.ElapsedMilliseconds) `
      -RequestBytes ([long]$script:LastHttpTelemetry.requestBytes) `
      -ResponseBytes ([long]$script:LastHttpTelemetry.responseBytes))
    return [pscustomobject]$readyRecord
  } catch {
    $failureCode = if ($_.Exception.Message -match '^root-action-refused-no-canonical-authorization:') {
      [string]$_.Exception.Message
    } else { 'bootstrap-or-update-failed' }
    if ($null -ne $transaction -and [string]$transaction.State -ne 'committed') {
      try { Restore-HchUpdateTransaction -Config $Config -Transaction $transaction } catch { }
      Write-HchJsonAtomic -Path (Join-Path ([string]$transaction.BackupDirectory) 'update-failure.json') -Value ([ordered]@{
        schema = 'hch.worker-update-failure/v1'
        nodeId = [string]$Config.NodeId
        transactionId = [string]$transaction.Id
        code = $failureCode
        rollbackPerformed = [string]$transaction.State -eq 'rolled-back'
        recordedAt = [DateTimeOffset]::UtcNow.ToString('o')
      })
    }
    Disable-HchWorkerReady -Config $Config -Reason 'bootstrap-or-update-failed'
    Set-HchWorkerStatus -Config $Config -State 'update-failed' `
      -Code $failureCode -ConnectionState 'error'
    [void](Update-HchWorkerMetrics -Config $Config -Event 'bootstrap-failure' `
      -DurationMilliseconds ([long]$timer.ElapsedMilliseconds) `
      -RequestBytes ([long]$script:LastHttpTelemetry.requestBytes) `
      -ResponseBytes ([long]$script:LastHttpTelemetry.responseBytes) `
      -RollbackPerformed:($null -ne $transaction -and [string]$transaction.State -eq 'rolled-back'))
    throw
  } finally {
    $timer.Stop()
    $bootstrapLock.Dispose()
  }
}

function Test-HchUpdateRequiredError {
  param([Exception]$Exception)
  $status = $Exception.Data['HchStatusCode']
  if ($status -eq 428) { return $true }
  return ($status -eq 409 -and $Exception.Message -match '(?i)policy|manifest|update-required|stale|desatualiz')
}

function Test-HchGeneratorStalledError {
  param([Exception]$Exception)
  if ($Exception.Data['HchStatusCode'] -ne 409) { return $false }
  $prefix = 'orchestrator-request-rejected:409:'
  $message = [string]$Exception.Message
  if (-not $message.StartsWith($prefix, [StringComparison]::Ordinal)) { return $false }
  try { $body = $message.Substring($prefix.Length) | ConvertFrom-Json }
  catch { return $false }
  return $null -ne $body -and [string]$body.code -eq 'generator-stalled'
}

function Assert-HchGeneratorStalledResponse {
  param(
    [Parameter(Mandatory = $true)][Exception]$Exception,
    [Parameter(Mandatory = $true)][string]$GenerationPlanHash
  )
  if (-not (Test-HchGeneratorStalledError -Exception $Exception)) {
    throw 'orchestrator-generator-stalled-response-invalid'
  }
  $prefix = 'orchestrator-request-rejected:409:'
  try { $body = ([string]$Exception.Message).Substring($prefix.Length) | ConvertFrom-Json }
  catch { throw 'orchestrator-generator-stalled-response-invalid' }
  if (-not ($body.PSObject.Properties.Name -contains 'generationPlanHash') -or
      [string]$body.generationPlanHash -ne $GenerationPlanHash) {
    throw 'orchestrator-generator-stalled-plan-mismatch'
  }
  return $true
}

function Invoke-HchAutomaticUpdate {
  param([hashtable]$Config, [string]$Reason)
  Disable-HchWorkerReady -Config $Config -Reason $Reason
  if ([bool](Get-HchConfigValue $Config 'AutomaticUpdateOnPolicyMismatch' $true)) {
    [void](Invoke-HchWorkerBootstrap -Config $Config)
  }
}

function Get-HchInstalledCapacityPolicy {
  param([hashtable]$Config, $Ready, [switch]$PublicOnly)
  $engineConfigPath = Join-Path ([string]$Config.InstallRoot) 'config\engine.json'
  $appliedPath = Join-Path ([string]$Config.StateRoot) 'applied-manifest.json'
  if (-not (Test-Path -LiteralPath $engineConfigPath -PathType Leaf) -or
      -not (Test-Path -LiteralPath $appliedPath -PathType Leaf)) {
    throw 'installed-capacity-policy-missing'
  }
  try {
    $engineConfig = Read-HchJsonFile -Path $engineConfigPath
    $applied = Read-HchJsonFile -Path $appliedPath
  } catch { throw 'installed-capacity-policy-invalid' }
  if (-not ($engineConfig.PSObject.Properties.Name -contains 'capacityPolicy') -or
      -not ($engineConfig.PSObject.Properties.Name -contains 'capacityPolicyHash') -or
      -not ($applied.PSObject.Properties.Name -contains 'capacityPolicyHash') -or
      -not ($Ready.PSObject.Properties.Name -contains 'capacityPolicyHash')) {
    throw 'installed-capacity-policy-missing'
  }
  if ([long]$engineConfig.manifestSequence -ne [long]$Ready.manifestSequence -or
      [string]$engineConfig.manifestHash -ne [string]$Ready.manifestHash) {
    throw 'installed-capacity-policy-manifest-mismatch'
  }
  [void](Assert-HchCapacityPolicy -Policy $engineConfig.capacityPolicy)
  if ($PublicOnly) {
    # The limited operator CLI never reads the worker private key. It may use
    # the same canonicalizer helper with a public-only operation to validate
    # an already signed and installed policy before enabling local claims.
    $canonicalPath = Get-HchCanonicalFile -Config $Config -Value $engineConfig.capacityPolicy
    try { $actualHash = Get-HchSha256File -Path $canonicalPath }
    finally { Remove-Item -LiteralPath $canonicalPath -Force -ErrorAction SilentlyContinue }
  } else {
    $actualHash = Get-HchCanonicalSha256 -Config $Config -Value $engineConfig.capacityPolicy
  }
  if ([string]$engineConfig.capacityPolicyHash -ne $actualHash -or
      [string]$applied.capacityPolicyHash -ne $actualHash -or
      [string]$Ready.capacityPolicyHash -ne $actualHash) {
    throw 'installed-capacity-policy-hash-mismatch'
  }
  return $engineConfig.capacityPolicy
}

function Assert-HchCapacityWindow {
  param(
    [hashtable]$Config,
    [Parameter(Mandatory = $true)][string]$GrantedUntil,
    [Parameter(Mandatory = $true)][string]$ServerTime,
    [Parameter(Mandatory = $true)]$Policy,
    [switch]$AllowExpired
  )
  try {
    $grantedUntilValue = [DateTimeOffset]::Parse($GrantedUntil)
    $serverTimeValue = [DateTimeOffset]::Parse($ServerTime)
  } catch { throw 'orchestrator-capacity-window-invalid' }
  $clockSkew = [int](Get-HchConfigValue $Config 'ClockSkewSeconds' 60)
  if ($clockSkew -lt 0 -or $clockSkew -gt 300) { throw 'clock-skew-out-of-range' }
  if ((-not $AllowExpired -and (
        $grantedUntilValue -le $serverTimeValue.AddSeconds(-$clockSkew) -or
        $grantedUntilValue -le [DateTimeOffset]::UtcNow.AddSeconds(-$clockSkew)
      )) -or
      $grantedUntilValue -gt $serverTimeValue.AddSeconds([int]$Policy.grantTtlSeconds + $clockSkew)) {
    throw 'orchestrator-capacity-window-invalid'
  }
  return $grantedUntilValue.ToString('o')
}

function Assert-HchAttestedCapacityGrant {
  param(
    [hashtable]$Config,
    [Parameter(Mandatory = $true)]$Capacity,
    [Parameter(Mandatory = $true)][int]$RequestedCapacity,
    [Parameter(Mandatory = $true)]$Policy,
    [Parameter(Mandatory = $true)][string]$ServerTime
  )
  foreach ($field in @('requestedCapacity', 'grantedCapacity', 'capacityClass', 'reason', 'grantedUntil')) {
    if (-not ($Capacity.PSObject.Properties.Name -contains $field)) {
      throw "orchestrator-attestation-capacity-field-missing:$field"
    }
  }
  $absoluteMaximum = [int]$Policy.absoluteRequestedMaximum
  if (-not (Test-HchIntegerInRange $Capacity.requestedCapacity 0 $absoluteMaximum) -or
      [int]$Capacity.requestedCapacity -ne $RequestedCapacity) {
    throw 'orchestrator-attestation-requested-capacity-invalid'
  }
  $expectedClass = Get-HchExpectedCapacityClass -Config $Config -Policy $Policy
  $expectedNodeCeiling = Get-HchExpectedNodeCeiling -Config $Config -Policy $Policy
  if ([string]$Capacity.capacityClass -ne $expectedClass) {
    throw 'orchestrator-attestation-capacity-class-invalid'
  }
  if (-not (Test-HchIntegerInRange $Capacity.grantedCapacity 0 $absoluteMaximum) -or
      [int]$Capacity.grantedCapacity -gt $RequestedCapacity -or
      [int]$Capacity.grantedCapacity -gt $expectedNodeCeiling) {
    throw 'orchestrator-attestation-granted-capacity-invalid'
  }
  if ([string]::IsNullOrWhiteSpace([string]$Capacity.reason) -or
      [string]$Capacity.reason -notmatch '^[a-z0-9][a-z0-9:+._-]{0,255}$') {
    throw 'orchestrator-attestation-capacity-reason-invalid'
  }
  $validUntil = if ([string]::IsNullOrWhiteSpace([string]$Capacity.grantedUntil)) {
    $null
  } else {
    Assert-HchCapacityWindow -Config $Config -GrantedUntil ([string]$Capacity.grantedUntil) `
      -ServerTime $ServerTime -Policy $Policy -AllowExpired
  }
  return [pscustomobject][ordered]@{
    requestedCapacity = [int]$Capacity.requestedCapacity
    grantedCapacity = [int]$Capacity.grantedCapacity
    activeAssignments = 0
    capacityReason = [string]$Capacity.reason
    validUntil = $validUntil
  }
}

function Assert-HchClaimCapacityDecision {
  param(
    [hashtable]$Config,
    [Parameter(Mandatory = $true)]$Capacity,
    [Parameter(Mandatory = $true)][int]$RequestedCapacity,
    [Parameter(Mandatory = $true)]$Policy,
    [Parameter(Mandatory = $true)]$ExpectedPressure,
    [Parameter(Mandatory = $true)][int]$NewAssignmentCount,
    [Parameter(Mandatory = $true)][string]$ServerTime,
    [switch]$AllowExpired
  )
  $required = @(
    'algorithmVersion', 'requestedCapacity', 'grantedCapacity', 'availableSlots',
    'activeAssignments', 'globalActiveAssignments', 'globalAvailableBeforeGrant',
    'capacityClass', 'nodeCeiling', 'reason', 'grantedUntil', 'pressure'
  )
  foreach ($field in $required) {
    if (-not ($Capacity.PSObject.Properties.Name -contains $field)) {
      throw "orchestrator-claim-capacity-field-missing:$field"
    }
  }
  foreach ($field in $Capacity.PSObject.Properties.Name) {
    if ([string]$field -notin $required) { throw "orchestrator-claim-capacity-field-unsupported:$field" }
  }
  if ([string]$Capacity.algorithmVersion -ne [string]$Policy.algorithmVersion) {
    throw 'orchestrator-claim-capacity-algorithm-mismatch'
  }
  $absoluteMaximum = [int]$Policy.absoluteRequestedMaximum
  if (-not (Test-HchIntegerInRange $Capacity.requestedCapacity 0 $absoluteMaximum) -or
      [int]$Capacity.requestedCapacity -ne $RequestedCapacity) {
    throw 'orchestrator-claim-requested-capacity-invalid'
  }
  $expectedClass = Get-HchExpectedCapacityClass -Config $Config -Policy $Policy
  $expectedNodeCeiling = Get-HchExpectedNodeCeiling -Config $Config -Policy $Policy
  if ([string]$Capacity.capacityClass -ne $expectedClass -or
      -not (Test-HchIntegerInRange $Capacity.nodeCeiling 0 $absoluteMaximum) -or
      [int]$Capacity.nodeCeiling -ne $expectedNodeCeiling) {
    throw 'orchestrator-claim-node-capacity-invalid'
  }
  if (-not (Test-HchIntegerInRange $Capacity.grantedCapacity 0 $absoluteMaximum) -or
      [int]$Capacity.grantedCapacity -gt $RequestedCapacity -or
      [int]$Capacity.grantedCapacity -gt [int]$Capacity.nodeCeiling) {
    throw 'orchestrator-claim-granted-capacity-invalid'
  }
  if (-not (Test-HchIntegerInRange $Capacity.activeAssignments 0 1000000) -or
      -not (Test-HchIntegerInRange $Capacity.globalActiveAssignments 0 1000000) -or
      -not (Test-HchIntegerInRange $Capacity.globalAvailableBeforeGrant 0 ([int]$Policy.globalAssignmentCeiling)) -or
      -not (Test-HchIntegerInRange $Capacity.availableSlots 0 $absoluteMaximum)) {
    throw 'orchestrator-claim-capacity-counters-invalid'
  }
  $expectedAvailableSlots = [Math]::Max(0, [int]$Capacity.grantedCapacity - [int]$Capacity.activeAssignments)
  if ([int]$Capacity.availableSlots -ne $expectedAvailableSlots -or
      $NewAssignmentCount -gt [int]$Capacity.availableSlots) {
    throw 'orchestrator-claim-assignments-exceed-grant'
  }
  if ([int]$Capacity.globalActiveAssignments -lt [int]$Capacity.activeAssignments) {
    throw 'orchestrator-claim-global-capacity-invalid'
  }
  if ([string]::IsNullOrWhiteSpace([string]$Capacity.reason) -or
      [string]$Capacity.reason -notmatch '^[a-z0-9][a-z0-9:+._-]{0,255}$') {
    throw 'orchestrator-claim-capacity-reason-invalid'
  }
  $observedPressure = Assert-HchCapacityPressure -Pressure $Capacity.pressure
  $normalizedExpectedPressure = Assert-HchCapacityPressure -Pressure $ExpectedPressure
  if ((Get-HchCanonicalSha256 -Config $Config -Value ([pscustomobject]$observedPressure)) -ne
      (Get-HchCanonicalSha256 -Config $Config -Value ([pscustomobject]$normalizedExpectedPressure))) {
    throw 'orchestrator-claim-capacity-pressure-mismatch'
  }
  $validUntil = Assert-HchCapacityWindow -Config $Config -GrantedUntil ([string]$Capacity.grantedUntil) `
    -ServerTime $ServerTime -Policy $Policy -AllowExpired:$AllowExpired
  return [pscustomobject][ordered]@{
    requestedCapacity = [int]$Capacity.requestedCapacity
    grantedCapacity = [int]$Capacity.grantedCapacity
    activeAssignments = [int]$Capacity.activeAssignments + $NewAssignmentCount
    capacityReason = [string]$Capacity.reason
    validUntil = $validUntil
  }
}

function Invoke-HchWorkerClaim {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory = $true)][hashtable]$Config,
    [ValidateRange(1, 64)][int]$RequestedCapacity = 1
  )
  $localLimit = [int](Get-HchConfigValue $Config 'LocalParallelismLimit' 8)
  if ($RequestedCapacity -gt $localLimit) { throw 'claim-capacity-exceeds-local-limit' }
  $orchestrationPath = Join-Path ([string]$Config.StateRoot) 'orchestration.json'
  if (-not (Test-Path -LiteralPath $orchestrationPath -PathType Leaf)) {
    throw 'claim-requires-node-heartbeat'
  }
  try { $orchestration = Read-HchJsonFile -Path $orchestrationPath }
  catch { throw 'claim-node-heartbeat-state-invalid' }
  if ([string]$orchestration.schema -ne 'hch.worker-orchestration/v1' -or
      [int]$orchestration.schemaVersion -ne 1 -or
      [string]$orchestration.nodeId -ne [string]$Config.NodeId -or
      [string]$orchestration.heartbeat.status -ne 'succeeded') {
    throw 'claim-node-heartbeat-state-invalid'
  }
  try {
    $heartbeatAgeSeconds = ([DateTimeOffset]::UtcNow -
      [DateTimeOffset]::Parse([string]$orchestration.heartbeat.lastAttemptAt)).TotalSeconds
  } catch { throw 'claim-node-heartbeat-state-invalid' }
  if ($heartbeatAgeSeconds -lt -30 -or $heartbeatAgeSeconds -gt 90) {
    throw 'claim-node-heartbeat-stale'
  }
  $recommendedCount = [int]$orchestration.claim.recommendedCount
  $heartbeatRequested = [int]$orchestration.capacity.requestedCapacity
  $heartbeatGranted = [int]$orchestration.capacity.grantedCapacity
  $heartbeatSlots = [int]$orchestration.capacity.availableSlots
  if (-not [bool]$orchestration.claim.allowed -or $recommendedCount -lt 1 -or
      $heartbeatRequested -lt 1 -or $heartbeatGranted -lt 1 -or $heartbeatSlots -lt 1) {
    throw 'claim-not-recommended-by-node-heartbeat'
  }
  $effectiveRequestedCapacity = [Math]::Min(
    $RequestedCapacity,
    [Math]::Min($recommendedCount, [Math]::Min($heartbeatGranted, $heartbeatSlots))
  )
  if ($effectiveRequestedCapacity -lt 1) { throw 'claim-effective-capacity-zero' }
  $ready = Assert-HchClaimGate -Config $Config
  $identity = Get-HchWorkerIdentity -Config $Config
  $nonce = Get-HchChallenge -Config $Config -Identity $identity -Purpose 'claim'
  $body = [ordered]@{
    nodeId = [string]$Config.NodeId
    workerKeyId = [string]$identity.keyId
    requestedCapacity = $effectiveRequestedCapacity
  }
  $operationKey = 'claim-request'
  $requestId = Get-HchOperationRequestId -Config $Config -OperationKey $operationKey `
    -Target 'POST:/api/editorial/orchestrator/claim' -Body $body
  $timer = [Diagnostics.Stopwatch]::StartNew()
  try {
    $response = Invoke-HchSignedJsonRequest -Config $Config -Identity $identity -Method POST `
      -Path '/api/editorial/orchestrator/claim' -Nonce $nonce -RequestId $requestId -Body $body
    if ([string]$response.requestId -ne $requestId) { throw 'orchestrator-claim-request-id-mismatch' }
    if ([string]$response.nodeId -ne [string]$Config.NodeId) { throw 'orchestrator-claim-node-mismatch' }
    foreach ($name in @('assignments', 'capacity', 'replayed', 'serverTime')) {
      if (-not ($response.PSObject.Properties.Name -contains $name)) {
        throw 'orchestrator-claim-response-contract-invalid'
      }
    }
    if (-not ($response.PSObject.Properties.Name -contains 'capacity') -or
        $null -eq $response.capacity) {
      throw 'orchestrator-claim-capacity-contract-required'
    }
    $claimCapacity = $response.capacity
    foreach ($name in @(
      'algorithmVersion', 'requestedCapacity', 'grantedCapacity', 'activeAssignments',
      'availableSlots', 'globalActiveAssignments', 'globalAvailableBeforeGrant',
      'capacityClass', 'nodeCeiling', 'reason', 'grantedUntil', 'pressure'
    )) {
      if (-not ($claimCapacity.PSObject.Properties.Name -contains $name)) {
        throw 'orchestrator-claim-capacity-contract-invalid'
      }
    }
    foreach ($name in @(
      'requestedCapacity', 'grantedCapacity', 'activeAssignments', 'availableSlots',
      'globalActiveAssignments', 'globalAvailableBeforeGrant', 'nodeCeiling'
    )) {
      $value = $claimCapacity.$name
      if ($null -eq $value -or [double]$value -ne [Math]::Truncate([double]$value) -or
          [long]$value -lt 0 -or [long]$value -gt 1000000) {
        throw 'orchestrator-claim-capacity-contract-invalid'
      }
    }
    if ([string]$claimCapacity.algorithmVersion -ne 'hch-adaptive-capacity-v1' -or
        [string]$claimCapacity.capacityClass -notin @('constrained', 'standard', 'accelerated')) {
      throw 'orchestrator-claim-capacity-metadata-invalid'
    }
    if ([int]$claimCapacity.requestedCapacity -gt 64 -or
        [int]$claimCapacity.grantedCapacity -gt 32 -or
        [int]$claimCapacity.availableSlots -gt 32 -or
        [int]$claimCapacity.globalAvailableBeforeGrant -gt 32 -or
        [int]$claimCapacity.nodeCeiling -gt 64) {
      throw 'orchestrator-claim-capacity-contract-invalid'
    }
    if ($null -eq $claimCapacity.pressure -or $claimCapacity.pressure -is [ValueType] -or
        $claimCapacity.pressure -is [string]) {
      throw 'orchestrator-claim-capacity-pressure-invalid'
    }
    foreach ($property in $claimCapacity.pressure.PSObject.Properties) {
      if ([string]$property.Name -notin @('cpuPercent', 'memoryPercent', 'gpuPercent')) {
        throw 'orchestrator-claim-capacity-pressure-invalid'
      }
      $pressureValue = [double]$property.Value
      if ([double]::IsNaN($pressureValue) -or [double]::IsInfinity($pressureValue) -or
          $pressureValue -lt 0 -or $pressureValue -gt 100) {
        throw 'orchestrator-claim-capacity-pressure-invalid'
      }
    }
    if ([int]$claimCapacity.requestedCapacity -ne $heartbeatRequested) {
      throw 'orchestrator-claim-capacity-heartbeat-mismatch'
    }
    $grantedCapacity = [int]$claimCapacity.grantedCapacity
    if ($grantedCapacity -lt 0 -or $grantedCapacity -gt $heartbeatRequested -or
        $grantedCapacity -ne $heartbeatGranted) {
      throw 'orchestrator-claim-granted-capacity-invalid'
    }
    $assignments = @($response.assignments)
    if ($assignments.Count -gt $effectiveRequestedCapacity -or
        $assignments.Count -gt $grantedCapacity -or
        $assignments.Count -gt [int]$claimCapacity.availableSlots) {
      throw 'orchestrator-claim-assignments-exceed-grant'
    }
    $activeAssignments = [int]$claimCapacity.activeAssignments
    if ([int]$claimCapacity.availableSlots -lt 0 -or
        [int]$claimCapacity.availableSlots -gt $grantedCapacity -or
        [int]$claimCapacity.availableSlots -ne [Math]::Max(0, $grantedCapacity - $activeAssignments)) {
      throw 'orchestrator-claim-available-slots-invalid'
    }
    $capacityReason = [string]$claimCapacity.reason
    if ([string]::IsNullOrWhiteSpace($capacityReason)) {
      throw 'orchestrator-claim-capacity-reason-invalid'
    }
    try {
      [void][DateTimeOffset]::Parse([string]$response.serverTime)
      [void][DateTimeOffset]::Parse([string]$claimCapacity.grantedUntil)
    } catch {
      throw 'orchestrator-claim-capacity-time-invalid'
    }
    if ($response.replayed -isnot [bool]) { throw 'orchestrator-claim-replayed-invalid' }
    $capacitySnapshotParameters = @{
      Config = $Config
      RequestedCapacity = $heartbeatRequested
      GrantedCapacity = $grantedCapacity
      ActiveAssignments = $activeAssignments + $assignments.Count
      CapacityReason = $capacityReason
      ValidUntil = [DateTimeOffset]::Parse([string]$claimCapacity.grantedUntil).ToString('o')
    }
    [void](Set-HchWorkerCapacitySnapshot @capacitySnapshotParameters)
    $expiredReplay = $false
    foreach ($assignment in $assignments) {
      try { [void](Assert-HchAssignmentIntegrity -Config $Config -Assignment $assignment) }
      catch {
        if ([bool]$response.replayed -and [string]$_.Exception.Message -eq 'assignment-integrity-lease-expired') {
          $expiredReplay = $true
          continue
        }
        throw
      }
    }
    if ($expiredReplay) {
      Complete-HchOperationRequest -Config $Config -OperationKey $operationKey -RequestId $requestId
      [void](Update-HchWorkerMetrics -Config $Config -Event 'discarded' -ItemCount $assignments.Count `
        -DurationMilliseconds ([long]$timer.ElapsedMilliseconds) -ClearCurrentBatch `
        -RequestBytes ([long]$script:LastHttpTelemetry.requestBytes) `
        -ResponseBytes ([long]$script:LastHttpTelemetry.responseBytes))
      Set-HchWorkerStatus -Config $Config -State 'standby' -ConnectionState 'connected' `
        -Code 'expired-claim-replay-resolved' -ClearCurrentBatch
      return [pscustomobject]@{
        requestId = [string]$response.requestId
        nodeId = [string]$response.nodeId
        capacity = $claimCapacity
        assignments = @()
        replayed = $true
        expiredReplayResolved = $true
        serverTime = [string]$response.serverTime
      }
    }
    Complete-HchOperationRequest -Config $Config -OperationKey $operationKey -RequestId $requestId
    $currentBatch = if ($assignments.Count -gt 0) {
      [ordered]@{
        batchId = [string]$response.requestId
        startedAt = [DateTimeOffset]::UtcNow.ToString('o')
        jobs = $assignments.Count
        assignmentIds = @($assignments | ForEach-Object { [string]$_.assignmentId })
      }
    } else { $null }
    if ($assignments.Count -gt 0) {
      [void](Update-HchWorkerMetrics -Config $Config -Event 'claim' -ItemCount $assignments.Count `
        -DurationMilliseconds ([long]$timer.ElapsedMilliseconds) -CurrentBatch $currentBatch `
        -RequestBytes ([long]$script:LastHttpTelemetry.requestBytes) `
        -ResponseBytes ([long]$script:LastHttpTelemetry.responseBytes))
      Set-HchWorkerStatus -Config $Config -State 'processing' -ConnectionState 'connected' -CurrentBatch $currentBatch
    } else {
      [void](Update-HchWorkerMetrics -Config $Config -Event 'claim' -ItemCount 0 `
        -DurationMilliseconds ([long]$timer.ElapsedMilliseconds) -ClearCurrentBatch `
        -RequestBytes ([long]$script:LastHttpTelemetry.requestBytes) `
        -ResponseBytes ([long]$script:LastHttpTelemetry.responseBytes))
      Set-HchWorkerStatus -Config $Config -State 'standby' -ConnectionState 'connected' -ClearCurrentBatch
    }
    return $response
  } catch {
    if (Test-HchUpdateRequiredError -Exception $_.Exception) {
      Complete-HchOperationRequest -Config $Config -OperationKey $operationKey -RequestId $requestId
      [void](Update-HchWorkerMetrics -Config $Config -Event 'discarded' -ItemCount 0 `
        -DurationMilliseconds ([long]$timer.ElapsedMilliseconds))
      Invoke-HchAutomaticUpdate -Config $Config -Reason 'claim-requires-update'
      throw 'claim-not-retried-after-worker-update'
    }
    $claimErrorCode = if ([string]$_.Exception.Message -match '^assignment-(input-snapshot|runtime-profile|integrity)-') {
      'orchestrator-claim-response-integrity-failed'
    } else { 'orchestrator-claim-request-failed' }
    Set-HchWorkerStatus -Config $Config -State 'connection-error' `
      -Code $claimErrorCode -ConnectionState 'error'
    throw
  } finally {
    $timer.Stop()
  }
}

function Get-HchRemainingBatch {
  param([hashtable]$Config, [string]$CompletedAssignmentId)
  $statusPath = Join-Path ([string]$Config.StateRoot) 'status.json'
  if (-not (Test-Path -LiteralPath $statusPath)) { return $null }
  try { $status = Read-HchJsonFile -Path $statusPath } catch { return $null }
  if ($null -eq $status.currentBatch) { return $null }
  $remaining = @($status.currentBatch.assignmentIds | Where-Object { [string]$_ -ne $CompletedAssignmentId })
  if ($remaining.Count -eq 0) { return $null }
  return [ordered]@{
    batchId = [string]$status.currentBatch.batchId
    startedAt = [string]$status.currentBatch.startedAt
    jobs = $remaining.Count
    assignmentIds = $remaining
  }
}

function Assert-HchExactObjectProperties {
  param(
    [Parameter(Mandatory = $true)]$Value,
    [Parameter(Mandatory = $true)][string[]]$Expected,
    [Parameter(Mandatory = $true)][string]$ErrorCode
  )
  if ($null -eq $Value -or $Value -is [string] -or $Value -is [ValueType]) {
    throw $ErrorCode
  }
  $actual = @($Value.PSObject.Properties.Name)
  if ($actual.Count -ne $Expected.Count) { throw $ErrorCode }
  foreach ($name in $Expected) {
    if ($actual -notcontains $name) { throw $ErrorCode }
  }
}

function Assert-HchNodeHeartbeatResponse {
  param(
    [Parameter(Mandatory = $true)][hashtable]$Config,
    [Parameter(Mandatory = $true)]$Response,
    [Parameter(Mandatory = $true)][string]$RequestId,
    [Parameter(Mandatory = $true)][ValidateRange(0, 64)][int]$RequestedCapacity
  )
  Assert-HchExactObjectProperties -Value $Response -Expected @(
    'requestId', 'nodeId', 'heartbeatAt', 'serverTime', 'nextHeartbeatSeconds',
    'capacity', 'workload', 'workSizing', 'claim'
  ) -ErrorCode 'orchestrator-node-heartbeat-response-contract-invalid'
  if ([string]$Response.requestId -ne $RequestId) {
    throw 'orchestrator-node-heartbeat-request-id-mismatch'
  }
  if ([string]$Response.nodeId -ne [string]$Config.NodeId) {
    throw 'orchestrator-node-heartbeat-node-mismatch'
  }
  foreach ($name in @('heartbeatAt', 'serverTime')) {
    try { [void][DateTimeOffset]::Parse([string]$Response.$name) }
    catch { throw "orchestrator-node-heartbeat-$($name.ToLowerInvariant())-invalid" }
  }
  if ([int]$Response.nextHeartbeatSeconds -ne 60) {
    throw 'orchestrator-node-heartbeat-interval-invalid'
  }
  foreach ($name in @('capacity', 'workload', 'claim')) {
    if (-not ($Response.PSObject.Properties.Name -contains $name) -or $null -eq $Response.$name) {
      throw "orchestrator-node-heartbeat-$name-missing"
    }
  }

  $capacity = $Response.capacity
  Assert-HchExactObjectProperties -Value $capacity -Expected @(
    'configuredCapacity', 'requestedCapacity', 'grantedCapacity',
    'activeAssignments', 'availableSlots', 'capacityClass', 'reason', 'grantedUntil'
  ) -ErrorCode 'orchestrator-node-heartbeat-capacity-contract-invalid'
  $capacityValues = [ordered]@{}
  foreach ($name in @(
    'configuredCapacity', 'requestedCapacity', 'grantedCapacity',
    'activeAssignments', 'availableSlots'
  )) {
    $value = $capacity.$name
    if ($null -eq $value -or [double]$value -ne [Math]::Truncate([double]$value) -or
        [long]$value -lt 0 -or [long]$value -gt 1000000) {
      throw "orchestrator-node-heartbeat-capacity-$($name.ToLowerInvariant())-invalid"
    }
    $capacityValues[$name] = [int]$value
  }
  if ($capacityValues.requestedCapacity -ne $RequestedCapacity -or
      $capacityValues.grantedCapacity -gt $capacityValues.configuredCapacity -or
      $capacityValues.availableSlots -gt $capacityValues.grantedCapacity) {
    throw 'orchestrator-node-heartbeat-capacity-contract-invalid'
  }
  if ([string]$capacity.capacityClass -notin @('constrained', 'standard', 'accelerated') -or
      [string]::IsNullOrWhiteSpace([string]$capacity.reason)) {
    throw 'orchestrator-node-heartbeat-capacity-metadata-invalid'
  }
  $grantedUntil = $null
  if ($null -ne $capacity.grantedUntil -and
      -not [string]::IsNullOrWhiteSpace([string]$capacity.grantedUntil)) {
    try { $grantedUntil = [DateTimeOffset]::Parse([string]$capacity.grantedUntil).ToString('o') }
    catch { throw 'orchestrator-node-heartbeat-capacity-granted-until-invalid' }
  }

  $workloadValues = [ordered]@{}
  Assert-HchExactObjectProperties -Value $Response.workload -Expected @(
    'claimable', 'generating', 'futureTotal', 'claimableByTier'
  ) -ErrorCode 'orchestrator-node-heartbeat-workload-contract-invalid'
  foreach ($name in @('claimable', 'generating', 'futureTotal')) {
    $value = $Response.workload.$name
    if ($null -eq $value -or [double]$value -ne [Math]::Truncate([double]$value) -or
        [long]$value -lt 0 -or [long]$value -gt 2147483647) {
      throw "orchestrator-node-heartbeat-workload-$($name.ToLowerInvariant())-invalid"
    }
    $workloadValues[$name] = [int]$value
  }
  if ($workloadValues.futureTotal -lt $workloadValues.claimable -or
      $workloadValues.futureTotal -lt $workloadValues.generating) {
    throw 'orchestrator-node-heartbeat-workload-total-invalid'
  }
  $installedAdaptivePolicy = Get-HchInstalledAdaptiveWorkPolicy -Config $Config
  $adaptivePolicy = $installedAdaptivePolicy.Policy
  $expectedTierIds = @($adaptivePolicy.tiers | ForEach-Object { [string]$_.id })
  Assert-HchExactObjectProperties -Value $Response.workload.claimableByTier `
    -Expected $expectedTierIds -ErrorCode 'orchestrator-node-heartbeat-workload-tier-contract-invalid'
  foreach ($tierId in $expectedTierIds) {
    $tierValue = $Response.workload.claimableByTier.$tierId
    if ($null -eq $tierValue -or [double]$tierValue -ne [Math]::Truncate([double]$tierValue) -or
        [long]$tierValue -lt 0 -or [long]$tierValue -gt 2147483647) {
      throw 'orchestrator-node-heartbeat-workload-tier-invalid'
    }
  }

  Assert-HchExactObjectProperties -Value $Response.workSizing -Expected @(
    'algorithmVersion', 'currentTier', 'currentRank', 'maxOutputTokens',
    'editorialProfile', 'minimumUnit', 'reason', 'updatedAt',
    'processingWindowSeconds', 'nearWindowSeconds', 'firstProgressGraceSeconds',
    'stallAfterSeconds', 'finalizationGraceSeconds'
  ) -ErrorCode 'orchestrator-node-heartbeat-work-sizing-contract-invalid'
  $selectedTier = @($adaptivePolicy.tiers | Where-Object {
    [string]$_.id -eq [string]$Response.workSizing.currentTier -and
    [int]$_.rank -eq [int]$Response.workSizing.currentRank -and
    [int]$_.maxOutputTokens -eq [int]$Response.workSizing.maxOutputTokens -and
    [string]$_.editorialProfile -eq [string]$Response.workSizing.editorialProfile -and
    [bool]$_.minimumUnit -eq [bool]$Response.workSizing.minimumUnit
  })
  if ($selectedTier.Count -ne 1 -or
      [string]$Response.workSizing.algorithmVersion -ne [string]$adaptivePolicy.algorithmVersion) {
    throw 'orchestrator-node-heartbeat-work-sizing-policy-mismatch'
  }
  try { [void][DateTimeOffset]::Parse([string]$Response.workSizing.updatedAt) }
  catch { throw 'orchestrator-node-heartbeat-work-sizing-updated-at-invalid' }

  Assert-HchExactObjectProperties -Value $Response.claim -Expected @(
    'allowed', 'recommendedCount', 'reason'
  ) -ErrorCode 'orchestrator-node-heartbeat-claim-contract-invalid'
  if ($Response.claim.allowed -isnot [bool]) {
    throw 'orchestrator-node-heartbeat-claim-allowed-invalid'
  }
  $recommendedCount = $Response.claim.recommendedCount
  if ($null -eq $recommendedCount -or
      [double]$recommendedCount -ne [Math]::Truncate([double]$recommendedCount) -or
      [long]$recommendedCount -lt 0 -or [long]$recommendedCount -gt 64 -or
      [int]$recommendedCount -gt $capacityValues.availableSlots -or
      [int]$recommendedCount -gt $workloadValues.claimable -or
      (-not [bool]$Response.claim.allowed -and [int]$recommendedCount -ne 0) -or
      ([bool]$Response.claim.allowed -and [int]$recommendedCount -lt 1)) {
    throw 'orchestrator-node-heartbeat-claim-recommendation-invalid'
  }
  if ([string]::IsNullOrWhiteSpace([string]$Response.claim.reason)) {
    throw 'orchestrator-node-heartbeat-claim-reason-invalid'
  }
  if ($RequestedCapacity -eq 0 -and
      ([bool]$Response.claim.allowed -or [int]$recommendedCount -ne 0 -or
       $capacityValues.grantedCapacity -ne 0 -or $capacityValues.availableSlots -ne 0)) {
    throw 'orchestrator-node-heartbeat-zero-capacity-contract-invalid'
  }
  return [pscustomobject]@{
    heartbeatAt = [DateTimeOffset]::Parse([string]$Response.heartbeatAt).ToString('o')
    serverTime = [DateTimeOffset]::Parse([string]$Response.serverTime).ToString('o')
    nextHeartbeatSeconds = 60
    capacity = [pscustomobject][ordered]@{
      configuredCapacity = $capacityValues.configuredCapacity
      requestedCapacity = $capacityValues.requestedCapacity
      grantedCapacity = $capacityValues.grantedCapacity
      activeAssignments = $capacityValues.activeAssignments
      availableSlots = $capacityValues.availableSlots
      capacityClass = [string]$capacity.capacityClass
      reason = [string]$capacity.reason
      grantedUntil = $grantedUntil
    }
    workload = [pscustomobject][ordered]@{
      claimable = $workloadValues.claimable
      generating = $workloadValues.generating
      futureTotal = $workloadValues.futureTotal
      claimableByTier = $Response.workload.claimableByTier
    }
    workSizing = $Response.workSizing
    claim = [pscustomobject][ordered]@{
      allowed = [bool]$Response.claim.allowed
      recommendedCount = [int]$recommendedCount
      reason = [string]$Response.claim.reason
    }
  }
}

function Write-HchNodeHeartbeatSnapshot {
  param(
    [Parameter(Mandatory = $true)][hashtable]$Config,
    [Parameter(Mandatory = $true)][ValidateSet('succeeded', 'failed')][string]$Status,
    [Parameter(Mandatory = $true)][string]$LastAttemptAt,
    [AllowNull()]$ValidatedResponse = $null,
    [string]$ErrorCode = ''
  )
  $path = Join-Path ([string]$Config.StateRoot) 'orchestration.json'
  $previous = $null
  if (Test-Path -LiteralPath $path -PathType Leaf) {
    try { $previous = Read-HchJsonFile -Path $path } catch { $previous = $null }
  }
  $lastSuccessAt = if ($Status -eq 'succeeded') {
    [string]$ValidatedResponse.heartbeatAt
  } elseif ($null -ne $previous) { $previous.heartbeat.lastSuccessAt } else { $null }
  $intervalSeconds = if ($Status -eq 'succeeded') {
    [int]$ValidatedResponse.nextHeartbeatSeconds
  } else { [int](Get-HchConfigValue $Config 'NodeHeartbeatIntervalSeconds' 60) }
  $nextHeartbeatBase = if ($Status -eq 'succeeded') {
    [DateTimeOffset]::Parse([string]$ValidatedResponse.heartbeatAt)
  } else { [DateTimeOffset]::Parse($LastAttemptAt) }
  $nextHeartbeatAt = $nextHeartbeatBase.AddSeconds($intervalSeconds).ToString('o')
  $capacity = if ($Status -eq 'succeeded') {
    $ValidatedResponse.capacity
  } elseif ($null -ne $previous) { $previous.capacity } else {
    [ordered]@{
      configuredCapacity = [int](Get-HchConfigValue $Config 'RequestedCapacity' 1)
      requestedCapacity = 0; grantedCapacity = 0; availableSlots = 0; activeAssignments = 0
      capacityClass = 'standard'; reason = 'heartbeat-unavailable'; grantedUntil = $null
    }
  }
  $workload = if ($Status -eq 'succeeded') {
    $ValidatedResponse.workload
  } elseif ($null -ne $previous) { $previous.workload } else {
    [ordered]@{ claimable = 0; generating = 0; futureTotal = 0 }
  }
  $workSizing = if ($Status -eq 'succeeded') {
    $ValidatedResponse.workSizing
  } elseif ($null -ne $previous -and $previous.PSObject.Properties.Name -contains 'workSizing') {
    $previous.workSizing
  } else { $null }
  $claim = if ($Status -eq 'succeeded') {
    $ValidatedResponse.claim
  } else {
    [ordered]@{ allowed = $false; recommendedCount = 0; reason = 'heartbeat-unavailable' }
  }
  $mode = if ($Status -eq 'failed') { 'unavailable' }
    elseif ([int]$capacity.requestedCapacity -eq 0) { 'heartbeat-only' }
    elseif ([bool]$claim.allowed -and [int]$claim.recommendedCount -gt 0) { 'execution-authorized' }
    else { 'waiting-for-work' }
  $record = [ordered]@{
    schema = 'hch.worker-orchestration/v1'
    schemaVersion = 1
    observedAt = [DateTimeOffset]::UtcNow.ToString('o')
    nodeId = [string]$Config.NodeId
    mode = $mode
    heartbeat = [ordered]@{
      status = $Status
      lastAttemptAt = [DateTimeOffset]::Parse($LastAttemptAt).ToString('o')
      lastSuccessAt = $lastSuccessAt
      nextHeartbeatAt = $nextHeartbeatAt
      intervalSeconds = $intervalSeconds
      errorCode = if ($Status -eq 'failed') { $ErrorCode } else { $null }
    }
    capacity = $capacity
    workload = $workload
    workSizing = $workSizing
    claim = $claim
  }
  Write-HchJsonAtomic -Path $path -Value $record
  return [pscustomobject]$record
}

function Invoke-HchWorkerNodeHeartbeat {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory = $true)][hashtable]$Config,
    [Parameter(Mandatory = $true)][ValidateRange(0, 64)][int]$RequestedCapacity,
    [AllowNull()][hashtable]$Pressure = $null
  )
  $localLimit = [int](Get-HchConfigValue $Config 'LocalParallelismLimit' 8)
  if ($RequestedCapacity -gt $localLimit) {
    throw 'node-heartbeat-capacity-exceeds-local-limit'
  }
  $interval = [int](Get-HchConfigValue $Config 'NodeHeartbeatIntervalSeconds' 60)
  if ($interval -ne 60) { throw 'node-heartbeat-interval-must-be-60' }
  $timeout = [int](Get-HchConfigValue $Config 'NodeHeartbeatRequestTimeoutSeconds' 10)
  if ($timeout -lt 3 -or $timeout -gt 15) { throw 'node-heartbeat-request-timeout-out-of-range' }
  $normalizedPressure = [ordered]@{}
  if ($null -ne $Pressure) {
    $allowedPressure = @('cpuPercent', 'memoryPercent', 'gpuPercent')
    foreach ($key in $Pressure.Keys) {
      if ([string]$key -notin $allowedPressure) { throw 'node-heartbeat-pressure-field-invalid' }
      $value = [double]$Pressure[$key]
      if ([double]::IsNaN($value) -or [double]::IsInfinity($value) -or
          $value -lt 0 -or $value -gt 100) {
        throw 'node-heartbeat-pressure-value-invalid'
      }
      $normalizedPressure[[string]$key] = [Math]::Round($value, 2)
    }
  }
  $attemptAt = [DateTimeOffset]::UtcNow.ToString('o')
  $requestId = [guid]::NewGuid().ToString('n')
  try {
    $identity = Get-HchWorkerIdentity -Config $Config
    $body = [ordered]@{
      nodeId = [string]$Config.NodeId
      workerKeyId = [string]$identity.keyId
      requestedCapacity = $RequestedCapacity
    }
    if ($normalizedPressure.Count -gt 0) { $body.pressure = $normalizedPressure }
    $nonce = Get-HchChallenge -Config $Config -Identity $identity -Purpose 'node-heartbeat' `
      -TimeoutSeconds $timeout
    $response = Invoke-HchSignedJsonRequest -Config $Config -Identity $identity -Method POST `
      -Path '/api/editorial/orchestrator/nodes/heartbeat' -Nonce $nonce -RequestId $requestId `
      -Body $body -TimeoutSeconds $timeout
    $validated = Assert-HchNodeHeartbeatResponse -Config $Config -Response $response `
      -RequestId $requestId -RequestedCapacity $RequestedCapacity
    [void](Write-HchNodeHeartbeatSnapshot -Config $Config -Status 'succeeded' `
      -LastAttemptAt $attemptAt -ValidatedResponse $validated)
    $capacitySnapshotParameters = @{
      Config = $Config
      RequestedCapacity = $RequestedCapacity
      GrantedCapacity = [int]$validated.capacity.grantedCapacity
      ActiveAssignments = [int]$validated.capacity.activeAssignments
      CapacityReason = [string]$validated.capacity.reason
    }
    if ($null -ne $validated.capacity.grantedUntil) {
      $capacitySnapshotParameters.ValidUntil = [string]$validated.capacity.grantedUntil
    } else {
      $capacitySnapshotParameters.ClearValidUntil = $true
    }
    [void](Set-HchWorkerCapacitySnapshot @capacitySnapshotParameters)
    return $response
  } catch {
    $rawCode = if ([string]::IsNullOrWhiteSpace([string]$_.Exception.Message)) {
      'orchestrator-node-heartbeat-failed'
    } else { ([string]$_.Exception.Message).Split(':')[0] }
    $code = ([string]$rawCode -replace '[^A-Za-z0-9._-]', '-').Trim('-')
    if ([string]::IsNullOrWhiteSpace($code)) { $code = 'orchestrator-node-heartbeat-failed' }
    if ($code.Length -gt 96) { $code = $code.Substring(0, 96) }
    [void](Write-HchNodeHeartbeatSnapshot -Config $Config -Status 'failed' `
      -LastAttemptAt $attemptAt -ErrorCode $code)
    throw
  }
}

function Get-HchRemainingBatch {
  param([hashtable]$Config, [string]$CompletedAssignmentId)
  $statusPath = Join-Path ([string]$Config.StateRoot) 'status.json'
  if (-not (Test-Path -LiteralPath $statusPath)) { return $null }
  try { $status = Read-HchJsonFile -Path $statusPath } catch { return $null }
  if ($null -eq $status.currentBatch) { return $null }
  $remaining = @($status.currentBatch.assignmentIds | Where-Object { [string]$_ -ne $CompletedAssignmentId })
  if ($remaining.Count -eq 0) { return $null }
  return [ordered]@{
    batchId = [string]$status.currentBatch.batchId
    startedAt = [string]$status.currentBatch.startedAt
    jobs = $remaining.Count
    assignmentIds = $remaining
  }
}

function Assert-HchAssignmentProgress {
  param([Parameter(Mandatory = $true)]$Progress)
  $required = @('phase', 'attempt', 'sequence', 'contentBytes', 'updatedAt')
  foreach ($field in $required) {
    if (-not ($Progress.PSObject.Properties.Name -contains $field)) {
      throw "assignment-progress-field-missing:$field"
    }
  }
  foreach ($field in $Progress.PSObject.Properties.Name) {
    if ([string]$field -notin $required) { throw "assignment-progress-field-unsupported:$field" }
  }
  if ([string]$Progress.phase -notin @('starting', 'responding', 'finalizing') -or
      -not (Test-HchIntegerInRange $Progress.attempt 1 2) -or
      -not (Test-HchIntegerInRange $Progress.sequence 0 4000000) -or
      -not (Test-HchIntegerInRange $Progress.contentBytes 0 4000000)) {
    throw 'assignment-progress-value-invalid'
  }
  try { $updatedAt = [DateTimeOffset]::Parse([string]$Progress.updatedAt) }
  catch { throw 'assignment-progress-timestamp-invalid' }
  if ($updatedAt -gt [DateTimeOffset]::UtcNow.AddMinutes(5)) {
    throw 'assignment-progress-timestamp-invalid'
  }
  if ([string]$Progress.phase -eq 'starting' -and
      ([long]$Progress.sequence -ne 0 -or [long]$Progress.contentBytes -ne 0) -and
      [int]$Progress.attempt -eq 1) {
    throw 'assignment-progress-starting-invalid'
  }
  if ([string]$Progress.phase -in @('responding', 'finalizing') -and
      ([long]$Progress.sequence -lt 1 -or [long]$Progress.contentBytes -lt 1)) {
    throw 'assignment-progress-response-empty'
  }
  return [pscustomobject][ordered]@{
    phase = [string]$Progress.phase
    attempt = [int]$Progress.attempt
    sequence = [long]$Progress.sequence
    contentBytes = [long]$Progress.contentBytes
    updatedAt = $updatedAt.ToUniversalTime().ToString('o')
  }
}

function Assert-HchAssignmentHeartbeatResponse {
  param(
    [Parameter(Mandatory = $true)][hashtable]$Config,
    [Parameter(Mandatory = $true)]$Assignment,
    [Parameter(Mandatory = $true)]$Response,
    [Parameter(Mandatory = $true)][string]$GenerationPlanHash
  )
  foreach ($field in @(
    'assignmentId', 'generationPlanHash', 'leaseExpiresAt', 'liveness',
    'workSizing', 'serverTime'
  )) {
    if (-not ($Response.PSObject.Properties.Name -contains $field)) {
      throw "orchestrator-heartbeat-response-field-missing:$field"
    }
  }
  if ([string]$Response.assignmentId -ne [string]$Assignment.assignmentId -or
      [string]$Response.generationPlanHash -ne $GenerationPlanHash) {
    throw 'orchestrator-heartbeat-assignment-mismatch'
  }
  try {
    $serverTime = [DateTimeOffset]::Parse([string]$Response.serverTime)
    $leaseExpiresAt = [DateTimeOffset]::Parse([string]$Response.leaseExpiresAt)
  } catch { throw 'orchestrator-heartbeat-time-invalid' }
  if ($leaseExpiresAt -le $serverTime) { throw 'orchestrator-heartbeat-lease-invalid' }

  $liveness = $Response.liveness
  foreach ($field in @('state', 'lastProgressAt', 'staleAfterSeconds')) {
    if (-not ($liveness.PSObject.Properties.Name -contains $field)) {
      throw "orchestrator-heartbeat-liveness-field-missing:$field"
    }
  }
  if ([string]$liveness.state -notin @('starting', 'responding', 'finalizing')) {
    throw 'orchestrator-heartbeat-liveness-state-invalid'
  }
  $expectedGrace = if ([string]$liveness.state -eq 'finalizing') {
    [int]$Assignment.generationPlan.finalizationGraceSeconds
  } elseif ($null -ne $liveness.lastProgressAt) {
    [int]$Assignment.generationPlan.stallAfterSeconds
  } else { [int]$Assignment.generationPlan.firstProgressGraceSeconds }
  if (-not (Test-HchIntegerInRange $liveness.staleAfterSeconds 30 86400) -or
      [int]$liveness.staleAfterSeconds -ne $expectedGrace) {
    throw 'orchestrator-heartbeat-liveness-grace-invalid'
  }
  if ($null -ne $liveness.lastProgressAt) {
    try { $lastProgressAt = [DateTimeOffset]::Parse([string]$liveness.lastProgressAt) }
    catch { throw 'orchestrator-heartbeat-last-progress-invalid' }
    if ($lastProgressAt -gt $serverTime) { throw 'orchestrator-heartbeat-last-progress-invalid' }
  }

  $workSizing = $Response.workSizing
  foreach ($field in @('currentTier', 'currentRank', 'reason')) {
    if (-not ($workSizing.PSObject.Properties.Name -contains $field)) {
      throw "orchestrator-heartbeat-work-sizing-field-missing:$field"
    }
  }
  $installed = Get-HchInstalledAdaptiveWorkPolicy -Config $Config
  $tier = @($installed.Policy.tiers | Where-Object {
    [string]$_.id -eq [string]$workSizing.currentTier -and
    [int]$_.rank -eq [int]$workSizing.currentRank
  }) | Select-Object -First 1
  if ($null -eq $tier -or [int]$workSizing.currentRank -gt [int]$Assignment.generationPlan.tierRank -or
      [string]$workSizing.reason -notin @(
        'minimum-unit-window-ignored', 'within-window',
        'near-window-downshift', 'already-downshifted'
      )) {
    throw 'orchestrator-heartbeat-work-sizing-invalid'
  }
  return $Response
}

function Invoke-HchWorkerHeartbeat {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory = $true)][hashtable]$Config,
    [Parameter(Mandatory = $true)]$Assignment,
    [Parameter(Mandatory = $true)]$Progress,
    [switch]$DeferAutomaticUpdate
  )
  [void](Assert-HchClaimGate -Config $Config)
  $assignmentIntegrity = Assert-HchAssignmentIntegrity -Config $Config -Assignment $Assignment
  $validatedProgress = Assert-HchAssignmentProgress -Progress $Progress
  $identity = Get-HchWorkerIdentity -Config $Config
  $heartbeatTimeout = [int](Get-HchConfigValue $Config 'HeartbeatRequestTimeoutSeconds' 10)
  if ($heartbeatTimeout -lt 3 -or $heartbeatTimeout -gt 15) {
    throw 'heartbeat-request-timeout-out-of-range'
  }
  $nonce = Get-HchChallenge -Config $Config -Identity $identity -Purpose 'heartbeat' `
    -TimeoutSeconds $heartbeatTimeout
  $body = [ordered]@{
    assignmentId = [string]$Assignment.assignmentId
    nodeId = [string]$Config.NodeId
    workerKeyId = [string]$identity.keyId
    leaseToken = [string]$Assignment.leaseToken
    generationPlanHash = [string]$assignmentIntegrity.generationPlanHash
    progress = [ordered]@{
      phase = [string]$validatedProgress.phase
      attempt = [int]$validatedProgress.attempt
      sequence = [long]$validatedProgress.sequence
      contentBytes = [long]$validatedProgress.contentBytes
    }
  }
  $path = '/api/editorial/orchestrator/assignments/' +
    [Uri]::EscapeDataString([string]$Assignment.assignmentId) + '/heartbeat'
  $operationKey = @(
    'heartbeat', [string]$Assignment.assignmentId, [int]$validatedProgress.attempt,
    [long]$validatedProgress.sequence, [long]$validatedProgress.contentBytes,
    [string]$validatedProgress.phase
  ) -join '-'
  $requestId = Get-HchOperationRequestId -Config $Config -OperationKey $operationKey `
    -Target ('POST:' + $path) -Body $body
  try {
    $response = Invoke-HchSignedJsonRequest -Config $Config -Identity $identity -Method POST `
      -Path $path -Nonce $nonce -RequestId $requestId -Body $body `
      -TimeoutSeconds $heartbeatTimeout
    [void](Assert-HchAssignmentHeartbeatResponse -Config $Config -Assignment $Assignment `
      -Response $response -GenerationPlanHash ([string]$assignmentIntegrity.generationPlanHash))
    Complete-HchOperationRequest -Config $Config -OperationKey $operationKey -RequestId $requestId
    Set-HchWorkerStatus -Config $Config -State 'processing' -ConnectionState 'connected' `
      -AssignmentProgress ([ordered]@{
        assignmentId = [string]$Assignment.assignmentId
        generationPlanHash = [string]$assignmentIntegrity.generationPlanHash
        phase = [string]$validatedProgress.phase
        attempt = [int]$validatedProgress.attempt
        sequence = [long]$validatedProgress.sequence
        contentBytes = [long]$validatedProgress.contentBytes
        updatedAt = [string]$validatedProgress.updatedAt
      })
    [void](Update-HchWorkerMetrics -Config $Config -Event 'snapshot' `
      -RequestBytes ([long]$script:LastHttpTelemetry.requestBytes) `
      -ResponseBytes ([long]$script:LastHttpTelemetry.responseBytes))
    return $response
  } catch {
    if (Test-HchGeneratorStalledError -Exception $_.Exception) {
      [void](Assert-HchGeneratorStalledResponse -Exception $_.Exception `
        -GenerationPlanHash ([string]$assignmentIntegrity.generationPlanHash))
      Complete-HchOperationRequest -Config $Config -OperationKey $operationKey `
        -RequestId $requestId
      throw
    }
    if (Test-HchUpdateRequiredError -Exception $_.Exception) {
      Complete-HchOperationRequest -Config $Config -OperationKey $operationKey -RequestId $requestId
      [void](Update-HchWorkerMetrics -Config $Config -Event 'discarded' -ItemCount 1)
      if ($DeferAutomaticUpdate) {
        Disable-HchWorkerReady -Config $Config -Reason 'heartbeat-rejected-policy-stale'
      } else {
        Invoke-HchAutomaticUpdate -Config $Config -Reason 'heartbeat-rejected-policy-stale'
      }
      throw 'assignment-must-be-discarded-after-heartbeat'
    }
    throw
  }
}

function Invoke-HchWorkerFail {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory = $true)][hashtable]$Config,
    [Parameter(Mandatory = $true)]$Assignment,
    [Parameter(Mandatory = $true)][ValidatePattern('^[a-z0-9][a-z0-9._-]{0,119}$')][string]$ErrorCode,
    [ValidateRange(0, 86400000)][long]$WorkDurationMilliseconds = 0
  )
  $assignmentIntegrity = Assert-HchAssignmentIntegrity -Config $Config -Assignment $Assignment
  $identity = Get-HchWorkerIdentity -Config $Config
  $nonce = Get-HchChallenge -Config $Config -Identity $identity -Purpose 'fail'
  $body = [ordered]@{
    assignmentId = [string]$Assignment.assignmentId
    nodeId = [string]$Config.NodeId
    workerKeyId = [string]$identity.keyId
    leaseToken = [string]$Assignment.leaseToken
    generationPlanHash = [string]$assignmentIntegrity.generationPlanHash
    errorCode = $ErrorCode
  }
  $path = '/api/editorial/orchestrator/assignments/' +
    [Uri]::EscapeDataString([string]$Assignment.assignmentId) + '/fail'
  $operationKey = 'fail-' + [string]$Assignment.assignmentId
  $requestId = Get-HchOperationRequestId -Config $Config -OperationKey $operationKey `
    -Target ('POST:' + $path) -Body $body
  $response = Invoke-HchSignedJsonRequest -Config $Config -Identity $identity -Method POST `
    -Path $path -Nonce $nonce -RequestId $requestId -Body $body
  if ([string]$response.assignmentId -ne [string]$Assignment.assignmentId -or
      [string]$response.generationPlanHash -ne [string]$assignmentIntegrity.generationPlanHash) {
    throw 'orchestrator-fail-assignment-mismatch'
  }
  Complete-HchOperationRequest -Config $Config -OperationKey $operationKey -RequestId $requestId
  $remainingBatch = Get-HchRemainingBatch -Config $Config -CompletedAssignmentId ([string]$Assignment.assignmentId)
  if ($null -ne $remainingBatch) {
    [void](Update-HchWorkerActiveAssignmentCount -Config $Config -Delta -1)
    [void](Update-HchWorkerMetrics -Config $Config -Event 'failed' -ItemCount 1 `
      -DurationMilliseconds $WorkDurationMilliseconds -CurrentBatch $remainingBatch `
      -RequestBytes ([long]$script:LastHttpTelemetry.requestBytes) `
      -ResponseBytes ([long]$script:LastHttpTelemetry.responseBytes))
    Set-HchWorkerStatus -Config $Config -State 'processing' -ConnectionState 'connected' `
      -CurrentBatch $remainingBatch -ClearAssignmentProgress
  } else {
    [void](Update-HchWorkerActiveAssignmentCount -Config $Config -Delta -1)
    [void](Update-HchWorkerMetrics -Config $Config -Event 'failed' -ItemCount 1 `
      -DurationMilliseconds $WorkDurationMilliseconds -ClearCurrentBatch -BatchEnded `
      -RequestBytes ([long]$script:LastHttpTelemetry.requestBytes) `
      -ResponseBytes ([long]$script:LastHttpTelemetry.responseBytes))
    Set-HchWorkerStatus -Config $Config -State 'standby' -ConnectionState 'connected' -ClearCurrentBatch
  }
  return $response
}

function Invoke-HchWorkerComplete {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory = $true)][hashtable]$Config,
    [Parameter(Mandatory = $true)]$Assignment,
    [Parameter(Mandatory = $true)]$Draft,
    [switch]$DeferAutomaticUpdate,
    [ValidateRange(0, 86400000)][long]$WorkDurationMilliseconds = 0
  )
  $ready = Assert-HchClaimGate -Config $Config
  $assignmentIntegrity = Assert-HchAssignmentIntegrity -Config $Config -Assignment $Assignment
  $identity = Get-HchWorkerIdentity -Config $Config
  if ([string]$Assignment.runtimeProfile.policyHash -ne [string]$ready.policyHash -or
      [string]$Assignment.runtimeProfile.manifestHash -ne [string]$ready.manifestHash -or
      [long]$Assignment.runtimeProfile.manifestSequence -ne [long]$ready.manifestSequence) {
    [void](Update-HchWorkerMetrics -Config $Config -Event 'discarded' -ItemCount 1)
    if ($DeferAutomaticUpdate) {
      Disable-HchWorkerReady -Config $Config -Reason 'completion-local-policy-mismatch'
    } else {
      Invoke-HchAutomaticUpdate -Config $Config -Reason 'completion-local-policy-mismatch'
    }
    throw 'result-discarded-local-policy-mismatch'
  }
  $body = [ordered]@{
    assignmentId = [string]$Assignment.assignmentId
    nodeId = [string]$Config.NodeId
    workerKeyId = [string]$identity.keyId
    leaseToken = [string]$Assignment.leaseToken
    manifestSequence = [long]$Assignment.runtimeProfile.manifestSequence
    manifestHash = [string]$Assignment.runtimeProfile.manifestHash
    policyHash = [string]$Assignment.runtimeProfile.policyHash
    runtimeProfileHash = [string]$assignmentIntegrity.runtimeProfileHash
    generationPlanHash = [string]$assignmentIntegrity.generationPlanHash
    inputSnapshotHash = [string]$assignmentIntegrity.inputSnapshotHash
    draft = $Draft
  }
  $nonce = Get-HchChallenge -Config $Config -Identity $identity -Purpose 'complete'
  $path = '/api/editorial/orchestrator/assignments/' +
    [Uri]::EscapeDataString([string]$Assignment.assignmentId) + '/complete'
  $operationKey = 'complete-' + [string]$Assignment.assignmentId
  $requestId = Get-HchOperationRequestId -Config $Config -OperationKey $operationKey `
    -Target ('POST:' + $path) -Body $body
  $timer = [Diagnostics.Stopwatch]::StartNew()
  try {
    $response = Invoke-HchSignedJsonRequest -Config $Config -Identity $identity -Method POST `
      -Path $path -Nonce $nonce -RequestId $requestId -Body $body
    if ([string]$response.assignmentId -ne [string]$Assignment.assignmentId -or
        [string]$response.generationPlanHash -ne [string]$assignmentIntegrity.generationPlanHash) {
      throw 'orchestrator-complete-assignment-mismatch'
    }
    if ([bool]$response.commitAccepted -ne $true -or
        [string]$response.status -ne 'pending-review' -or
        [bool]$response.automaticApproval -ne $false -or
        [bool]$response.automaticPublication -ne $false) {
      throw 'orchestrator-complete-safety-contract-invalid'
    }
    Complete-HchOperationRequest -Config $Config -OperationKey $operationKey -RequestId $requestId
    $recordedDuration = if ($WorkDurationMilliseconds -gt 0) {
      $WorkDurationMilliseconds
    } else { [long]$timer.ElapsedMilliseconds }
    $remainingBatch = Get-HchRemainingBatch -Config $Config -CompletedAssignmentId ([string]$Assignment.assignmentId)
    if ($null -ne $remainingBatch) {
      [void](Update-HchWorkerActiveAssignmentCount -Config $Config -Delta -1)
      $metrics = Update-HchWorkerMetrics -Config $Config -Event 'complete' -ItemCount 1 `
        -DurationMilliseconds $recordedDuration -CurrentBatch $remainingBatch `
        -RequestBytes ([long]$script:LastHttpTelemetry.requestBytes) `
        -ResponseBytes ([long]$script:LastHttpTelemetry.responseBytes)
      Set-HchWorkerStatus -Config $Config -State 'processing' -ConnectionState 'connected' `
        -CurrentBatch $remainingBatch -ClearAssignmentProgress
    } else {
      [void](Update-HchWorkerActiveAssignmentCount -Config $Config -Delta -1)
      $metrics = Update-HchWorkerMetrics -Config $Config -Event 'complete' -ItemCount 1 `
        -DurationMilliseconds $recordedDuration -ClearCurrentBatch -BatchEnded `
        -RequestBytes ([long]$script:LastHttpTelemetry.requestBytes) `
        -ResponseBytes ([long]$script:LastHttpTelemetry.responseBytes)
      Set-HchWorkerStatus -Config $Config -State 'standby' -ConnectionState 'connected' -ClearCurrentBatch
    }
    return $response
  } catch {
    if (Test-HchUpdateRequiredError -Exception $_.Exception) {
      Complete-HchOperationRequest -Config $Config -OperationKey $operationKey -RequestId $requestId
      [void](Update-HchWorkerMetrics -Config $Config -Event 'discarded' -ItemCount 1 `
        -DurationMilliseconds ([long]$timer.ElapsedMilliseconds) -ClearCurrentBatch)
      if ($DeferAutomaticUpdate) {
        Disable-HchWorkerReady -Config $Config -Reason 'completion-rejected-policy-stale'
      } else {
        Invoke-HchAutomaticUpdate -Config $Config -Reason 'completion-rejected-policy-stale'
      }
      throw 'result-rejected-and-discarded-policy-stale'
    }
    Set-HchWorkerStatus -Config $Config -State 'connection-error' `
      -Code 'orchestrator-complete-request-failed' -ConnectionState 'error'
    throw
  } finally {
    $timer.Stop()
  }
}

function Get-HchWorkerKitStatus {
  [CmdletBinding()]
  param([Parameter(Mandatory = $true)][hashtable]$Config)
  $statusPath = Join-Path ([string]$Config.StateRoot) 'status.json'
  $readyPath = Join-Path ([string]$Config.StateRoot) 'ready.json'
  $appliedPath = Join-Path ([string]$Config.StateRoot) 'applied-manifest.json'
  return [pscustomobject]@{
    nodeId = [string]$Config.NodeId
    kitVersion = $script:KitVersion
    state = if (Test-Path -LiteralPath $statusPath) { Read-HchJsonFile -Path $statusPath } else { $null }
    ready = if (Test-Path -LiteralPath $readyPath) { Read-HchJsonFile -Path $readyPath } else { $null }
    appliedManifest = if (Test-Path -LiteralPath $appliedPath) { Read-HchJsonFile -Path $appliedPath } else { $null }
    capacity = if (Test-Path -LiteralPath (Join-Path ([string]$Config.StateRoot) 'capacity.json')) {
      Read-HchJsonFile -Path (Join-Path ([string]$Config.StateRoot) 'capacity.json')
    } else { $null }
    metrics = if (Test-Path -LiteralPath (Join-Path ([string]$Config.StateRoot) 'metrics.json')) {
      Read-HchJsonFile -Path (Join-Path ([string]$Config.StateRoot) 'metrics.json')
    } else { $null }
  }
}

Export-ModuleMember -Function @(
  'Import-HchWorkerConfig',
  'Get-HchWorkerControl',
  'Set-HchWorkerControl',
  'Set-HchWorkerCapacitySnapshot',
  'Update-HchWorkerActiveAssignmentCount',
  'Get-HchWorkerCycleTaskName',
  'Get-HchWorkerServiceName',
  'Get-HchWorkerServiceDisplayName',
  'Assert-HchCapacityPolicy',
  'Assert-HchAdaptiveWorkPolicy',
  'Get-HchInstalledAdaptiveWorkPolicy',
  'Assert-HchAssignmentProgress',
  'Get-HchInstalledCapacityPolicy',
  'Get-HchWorkerCapacityPressure',
  'Assert-HchNodeRuntime',
  'Initialize-HchWorkerIdentity',
  'Get-HchWorkerIdentity',
  'Get-HchWorkerPublicKeyId',
  'Test-HchSignedManifest',
  'Invoke-HchUnsignedJsonRequest',
  'Invoke-HchSignedJsonRequest',
  'Invoke-HchWorkerEnrollment',
  'Get-HchChallenge',
  'Assert-HchAssignmentIntegrity',
  'Move-HchExpiredOperationRequest',
  'Set-HchWorkerStatus',
  'Disable-HchWorkerReady',
  'Assert-HchClaimGate',
  'Restore-HchUpdateTransaction',
  'Invoke-HchWorkerBootstrap',
  'Invoke-HchWorkerNodeHeartbeat',
  'Invoke-HchWorkerClaim',
  'Invoke-HchWorkerHeartbeat',
  'Invoke-HchWorkerFail',
  'Invoke-HchWorkerComplete',
  'Get-HchWorkerKitStatus',
  'Update-HchWorkerMetrics',
  'Get-HchNormalizedHash',
  'Write-HchJsonAtomic',
  'Read-HchJsonFile'
)
