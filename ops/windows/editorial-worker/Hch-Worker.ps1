[CmdletBinding()]
param(
  [Parameter(Mandatory = $true, Position = 0)]
  [ValidateSet('configure', 'validate', 'start', 'pause', 'stop', 'status', 'set-parallelism')]
  [string]$Command,
  [string]$ConfigPath = (Join-Path $PSScriptRoot 'WorkerConfig.psd1'),
  [ValidateRange(0, 64)][int]$Parallelism = 1,
  [ValidateRange(3, 120)][int]$ControlPlaneTimeoutSeconds = 120,
  [switch]$NotifyControlPlane
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'Hch.EditorialWorker.psm1') -Force
$config = Import-HchWorkerConfig -Path $ConfigPath
$serviceName = Get-HchWorkerServiceName -Config $config

function Get-HchProcessingService {
  if ($null -eq (Get-Command 'Get-Service' -ErrorAction SilentlyContinue)) { return $null }
  return Get-Service -Name $serviceName -ErrorAction SilentlyContinue
}

function Invoke-HchLocalValidate {
  $nodePath = Assert-HchNodeRuntime -Config $config
  # Dashboard and operator CLI run without access to the service-held private
  # key. Validation proves the public identity and signed runtime state; only
  # the SCM service performs authenticated queue calls with the private key.
  $workerKeyId = Get-HchWorkerPublicKeyId -Config $config
  $readyPath = Join-Path ([string]$config.StateRoot) 'ready.json'
  $appliedPath = Join-Path ([string]$config.StateRoot) 'applied-manifest.json'
  if (-not (Test-Path -LiteralPath $readyPath -PathType Leaf)) { throw 'worker-ready-state-missing' }
  if (-not (Test-Path -LiteralPath $appliedPath -PathType Leaf)) { throw 'worker-applied-manifest-missing' }
  $ready = Read-HchJsonFile -Path $readyPath
  $applied = Read-HchJsonFile -Path $appliedPath
  if ([string]$ready.nodeId -ne [string]$config.NodeId -or
      [string]$ready.workerKeyId -ne $workerKeyId) { throw 'worker-ready-identity-mismatch' }
  if ((ConvertFrom-HchTimestamp -Value ([string]$ready.readyUntil)) -le [DateTimeOffset]::UtcNow) {
    throw 'worker-ready-attestation-expired'
  }
  if ([string]$ready.manifestHash -ne [string]$applied.manifestHash -or
      [long]$ready.manifestSequence -ne [long]$applied.sequence -or
      [string]$ready.policyHash -ne [string]$applied.policyHash) {
    throw 'worker-ready-applied-manifest-mismatch'
  }
  [void](Get-HchInstalledCapacityPolicy -Config $config -Ready $ready -PublicOnly)

  $generator = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot 'editorial-generator.mjs'))
  $output = @(& $nodePath $generator preflight `
    --runtime-root ([string]$config.InstallRoot) `
    --applied-manifest $appliedPath `
    --ollama-base-uri ([string]$config.OllamaBaseUri) 2>&1)
  if ($LASTEXITCODE -ne 0) {
    $safeCode = @($output | Where-Object { [string]$_ -match '^[a-z0-9][a-z0-9._:-]{0,159}$' } | Select-Object -First 1)
    if ($safeCode.Count -eq 1) { throw [string]$safeCode[0] }
    throw 'worker-generator-preflight-failed'
  }
  $preflight = (($output | ForEach-Object { [string]$_ }) -join "`n") | ConvertFrom-Json
  if (-not [bool]$preflight.valid) { throw 'worker-generator-preflight-invalid' }
  $service = Get-HchProcessingService
  return [pscustomobject]@{
    valid = $true
    nodeId = [string]$config.NodeId
    workerKeyId = $workerKeyId
    readyUntil = [string]$ready.readyUntil
    manifestSequence = [long]$ready.manifestSequence
    manifestHash = [string]$ready.manifestHash
    policyHash = [string]$ready.policyHash
    provider = [string]$preflight.provider
    model = [string]$preflight.model
    modelDigest = [string]$preflight.modelDigest
    processingServiceInstalled = $null -ne $service
    processingServiceState = if ($null -ne $service) { [string]$service.Status } else { $null }
    reservationAttempted = $false
  }
}

function Get-HchCliStatus {
  $worker = Get-HchWorkerKitStatus -Config $config
  $control = Get-HchWorkerControl -Config $config
  $service = Get-HchProcessingService
  $journalPath = Join-Path (Join-Path ([string]$config.StateRoot) 'cycles') 'active-batch.json'
  $journalSummary = $null
  if (Test-Path -LiteralPath $journalPath -PathType Leaf) {
    try {
      $journal = Read-HchJsonFile -Path $journalPath
      $journalSummary = [ordered]@{
        activeAssignments = @($journal.items).Count
        phases = @($journal.items | ForEach-Object { [string]$_.phase } | Sort-Object -Unique)
        updatedAt = [string]$journal.updatedAt
      }
    } catch {
      $journalSummary = [ordered]@{ activeAssignments = $null; phases = @('invalid'); updatedAt = $null }
    }
  }
  $capacity = if ($null -ne $worker.capacity) {
    $worker.capacity
  } elseif ($null -ne $worker.state -and
      $null -ne $worker.state.PSObject.Properties['capacity']) {
    $worker.state.capacity
  } else {
    [pscustomobject][ordered]@{
      requestedCapacity = 0
      grantedCapacity = 0
      activeAssignments = if ($null -ne $journalSummary -and $null -ne $journalSummary.activeAssignments) {
        [int]$journalSummary.activeAssignments
      } else { 0 }
      capacityReason = 'not-negotiated'
      validUntil = $null
    }
  }
  $grantCurrent = $false
  if ($null -ne $capacity.validUntil) {
    try {
      $grantCurrent = (ConvertFrom-HchTimestamp -Value ([string]$capacity.validUntil)) -gt
        [DateTimeOffset]::UtcNow
    }
    catch { $grantCurrent = $false }
  }
  return [pscustomobject]@{
    nodeId = [string]$config.NodeId
    control = $control
    desiredParallelism = [int]$control.requestedParallelism
    effectiveParallelism = if ([bool]$control.acceptingClaims -and $grantCurrent) {
      [int]$capacity.grantedCapacity
    } else { 0 }
    localParallelismLimit = if ($config.ContainsKey('LocalParallelismLimit')) { [int]$config.LocalParallelismLimit } else { 8 }
    capacity = [ordered]@{
      requestedCapacity = [int]$capacity.requestedCapacity
      grantedCapacity = [int]$capacity.grantedCapacity
      activeAssignments = [int]$capacity.activeAssignments
      capacityReason = [string]$capacity.capacityReason
      validUntil = $capacity.validUntil
      grantCurrent = $grantCurrent
    }
    service = if ($null -ne $service) {
      [ordered]@{ name = $serviceName; state = [string]$service.Status; persistent = $true }
    } else { $null }
    activeCycle = $journalSummary
    worker = $worker
  }
}

function Invoke-HchServerDrainNotification {
  if (-not $NotifyControlPlane) {
    return [pscustomobject][ordered]@{
      notified = $false
      delegatedToService = $true
      grantedCapacity = $null
      activeAssignments = $null
      reason = 'local-drain-active-service-notification-pending'
      validUntil = $null
      errorCode = $null
    }
  }
  $identityRoot = Join-Path ([string]$config.StateRoot) 'identity'
  $privateKeyPath = Join-Path $identityRoot 'worker-private.pk8.pem'
  try {
    # The dashboard runs as a limited operator and deliberately cannot read
    # the service-held signing key. Local drain is already authoritative; the
    # persistent service performs the signed capacity-zero notification on
    # its next cycle.
    $privateKeyStream = [IO.File]::Open(
      $privateKeyPath,
      [IO.FileMode]::Open,
      [IO.FileAccess]::Read,
      [IO.FileShare]::Read
    )
    $privateKeyStream.Dispose()
  } catch {
    return [pscustomobject][ordered]@{
      notified = $false
      delegatedToService = $true
      grantedCapacity = $null
      activeAssignments = $null
      reason = 'local-drain-active-service-notification-pending'
      validUntil = $null
      errorCode = $null
    }
  }
  try {
    $response = Invoke-HchWorkerNodeHeartbeat -Config $config -RequestedCapacity 0
    if ($null -eq $response.capacity -or [int]$response.capacity.requestedCapacity -ne 0 -or
        [bool]$response.claim.allowed -or [int]$response.claim.recommendedCount -ne 0) {
      throw 'server-drain-heartbeat-response-invalid'
    }
    return [pscustomobject][ordered]@{
      notified = $true
      delegatedToService = $false
      grantedCapacity = [int]$response.capacity.grantedCapacity
      activeAssignments = [int]$response.capacity.activeAssignments
      reason = [string]$response.capacity.reason
      validUntil = [string]$response.capacity.grantedUntil
      errorCode = $null
    }
  } catch {
    $candidate = ([string]$_.Exception.Message).ToLowerInvariant() -replace '[^a-z0-9._-]', '-'
    $candidate = $candidate.Trim('-')
    if ([string]::IsNullOrWhiteSpace($candidate) -or $candidate.Length -gt 120) {
      $candidate = 'server-drain-notification-failed'
    }
    return [pscustomobject][ordered]@{
      notified = $false
      delegatedToService = $false
      grantedCapacity = $null
      activeAssignments = $null
      reason = 'local-drain-active-heartbeat-notification-pending'
      validUntil = $null
      errorCode = $candidate
    }
  }
}

function Set-HchLocalDrainStatus {
  param([string]$CodePrefix = 'drain')
  $worker = Get-HchWorkerKitStatus -Config $config
  $activeAssignments = if ($null -ne $worker.capacity) {
    [int]$worker.capacity.activeAssignments
  } else { 0 }
  $currentBatch = if ($null -ne $worker.state -and
      $null -ne $worker.state.PSObject.Properties['currentBatch']) {
    $worker.state.currentBatch
  } else { $null }
  $hasActiveWork = $activeAssignments -gt 0 -or $null -ne $currentBatch
  Set-HchWorkerStatus -Config $config `
    -State $(if ($hasActiveWork) { 'processing' } else { 'standby' }) `
    -Code $(if ($hasActiveWork) { "$CodePrefix-active-assignments" } else { "$CodePrefix-complete" }) `
    -CurrentBatch $currentBatch -ClearCurrentBatch:(-not $hasActiveWork)
  return $hasActiveWork
}

switch ($Command) {
  'configure' {
    $service = Get-HchProcessingService
    if ($null -ne $service -and [string]$service.Status -eq 'StopPending') {
      throw 'worker-configure-refused-while-cycle-running'
    }
    $identity = Initialize-HchWorkerIdentity -Config $config
    [void](Set-HchWorkerControl -Config $config -Parallelism 0 -AcceptingClaims $false -UpdatedBy 'configure')
    $installed = if ($null -eq $service) {
      & (Join-Path $PSScriptRoot 'Install-HchWorkerService.ps1') -ConfigPath $ConfigPath
    } else {
      [pscustomobject]@{
        serviceName = $serviceName
        displayName = Get-HchWorkerServiceDisplayName -Config $config
        installed = $true
        state = [string]$service.Status
        claimsEnabledByConfigure = $false
      }
    }
    [pscustomobject]@{
      configured = $true
      nodeId = [string]$config.NodeId
      workerKeyId = [string]$identity.keyId
      service = $installed
      acceptingClaims = $false
      defaultActivationParallelism = 1
    }
    break
  }
  'validate' {
    # Local-only checks: this branch contains no claim or queue API operation.
    Invoke-HchLocalValidate
    break
  }
  'start' {
    [void](Invoke-HchLocalValidate)
    $service = Get-HchProcessingService
    if ($null -eq $service) { throw 'worker-processing-service-not-installed' }
    if ([string]$service.Status -ne 'Running') { throw 'worker-processing-service-not-running' }
    $control = Get-HchWorkerControl -Config $config
    $resume = if ([int]$control.requestedParallelism -gt 0) {
      [int]$control.requestedParallelism
    } else { [Math]::Max(1, [int]$control.lastNonZeroParallelism) }
    try {
      [void](Set-HchWorkerControl -Config $config -Parallelism $resume -AcceptingClaims $true -UpdatedBy 'start')
      Set-HchWorkerStatus -Config $config -State 'standby' `
        -Code 'start-requested-awaiting-server-capacity'
    } catch {
      [void](Set-HchWorkerControl -Config $config -Parallelism 0 -AcceptingClaims $false -UpdatedBy 'start-rollback')
      [void](Set-HchLocalDrainStatus -CodePrefix 'start-rollback')
      throw
    }
    [pscustomobject]@{ started = $true; serviceName = $serviceName; requestedParallelism = $resume }
    break
  }
  'pause' {
    $control = Get-HchWorkerControl -Config $config
    [void](Set-HchWorkerControl -Config $config -Parallelism 0 -AcceptingClaims $false -UpdatedBy 'pause')
    $draining = Set-HchLocalDrainStatus
    $serverDrain = Invoke-HchServerDrainNotification
    # Preserve the local drain state even when the best-effort control-plane
    # notification records a connection error. Its connection evidence remains.
    $draining = Set-HchLocalDrainStatus
    [pscustomobject]@{
      paused = $true
      draining = [bool]$draining
      priorParallelism = [int]$control.requestedParallelism
      serviceName = $serviceName
      serviceRemainsRunning = $true
      serverDrain = $serverDrain
    }
    break
  }
  'stop' {
    $control = Get-HchWorkerControl -Config $config
    [void](Set-HchWorkerControl -Config $config -Parallelism 0 -AcceptingClaims $false -UpdatedBy 'stop')
    $draining = Set-HchLocalDrainStatus -CodePrefix 'operator-stop'
    $serverDrain = Invoke-HchServerDrainNotification
    [pscustomobject]@{
      stopRequested = $true
      activeAssignmentsWillBeCancelled = [bool]$draining
      cancellationErrorCode = 'operator-stop-requested'
      priorParallelism = [int]$control.requestedParallelism
      serviceName = $serviceName
      serviceRemainsRunning = $true
      serverDrain = $serverDrain
    }
    break
  }
  'set-parallelism' {
    $control = Get-HchWorkerControl -Config $config
    if ($Parallelism -eq 0) {
      [void](Set-HchWorkerControl -Config $config -Parallelism 0 -AcceptingClaims $false -UpdatedBy 'pause')
      [void](Set-HchLocalDrainStatus)
      $serverDrain = Invoke-HchServerDrainNotification
      [void](Set-HchLocalDrainStatus)
    } else {
      $serverDrain = $null
      [void](Set-HchWorkerControl -Config $config -Parallelism $Parallelism `
        -AcceptingClaims ([bool]$control.acceptingClaims) -UpdatedBy 'set-parallelism')
    }
    $updated = Get-HchWorkerControl -Config $config
    $updatedStatus = Get-HchCliStatus
    [pscustomobject]@{
      requestedParallelism = [int]$updated.requestedParallelism
      desiredParallelism = [int]$updated.requestedParallelism
      effectiveParallelism = [int]$updatedStatus.effectiveParallelism
      capacity = $updatedStatus.capacity
      acceptingClaims = [bool]$updated.acceptingClaims
      localLimit = if ($config.ContainsKey('LocalParallelismLimit')) { [int]$config.LocalParallelismLimit } else { 8 }
      serverGrantNegotiatedOnNextClaim = $true
      serverDrain = $serverDrain
    }
    break
  }
  'status' {
    Get-HchCliStatus
    break
  }
}
