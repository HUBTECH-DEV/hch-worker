[CmdletBinding()]
param(
  [string]$ConfigPath = (Join-Path $PSScriptRoot 'WorkerConfig.psd1')
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'Hch.EditorialWorker.psm1') -Force

$script:GeneratorPath = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot 'editorial-generator.mjs'))
$script:CycleRoot = $null
$script:JournalPath = $null
$script:LastCyclePath = $null
$script:Config = $null
$script:NodePath = $null

function ConvertTo-HchProcessArgument {
  param([Parameter(Mandatory = $true)][string]$Value)
  if ($Value.Length -gt 0 -and $Value -notmatch '[\s"]') { return $Value }
  $builder = [Text.StringBuilder]::new()
  [void]$builder.Append('"')
  $backslashes = 0
  foreach ($character in $Value.ToCharArray()) {
    if ($character -eq '\') { $backslashes++; continue }
    if ($character -eq '"') {
      [void]$builder.Append(('\' * (($backslashes * 2) + 1)))
      [void]$builder.Append('"')
    } else {
      if ($backslashes -gt 0) { [void]$builder.Append(('\' * $backslashes)) }
      [void]$builder.Append($character)
    }
    $backslashes = 0
  }
  if ($backslashes -gt 0) { [void]$builder.Append(('\' * ($backslashes * 2))) }
  [void]$builder.Append('"')
  return $builder.ToString()
}

function Start-HchNodeProcess {
  param([Parameter(Mandatory = $true)][string[]]$Arguments)
  $startInfo = [Diagnostics.ProcessStartInfo]::new()
  $startInfo.FileName = $script:NodePath
  $startInfo.Arguments = (@($Arguments | ForEach-Object {
    ConvertTo-HchProcessArgument -Value ([string]$_)
  }) -join ' ')
  $startInfo.UseShellExecute = $false
  $startInfo.CreateNoWindow = $true
  $startInfo.WindowStyle = [Diagnostics.ProcessWindowStyle]::Hidden
  $startInfo.RedirectStandardOutput = $true
  $startInfo.RedirectStandardError = $true
  $process = [Diagnostics.Process]::new()
  $process.StartInfo = $startInfo
  if (-not $process.Start()) { throw 'worker-generator-process-start-failed' }
  return $process
}

function Invoke-HchGeneratorPreflight {
  $process = Start-HchNodeProcess -Arguments @(
    $script:GeneratorPath,
    'preflight',
    '--runtime-root', [string]$script:Config.InstallRoot,
    '--applied-manifest', (Join-Path ([string]$script:Config.StateRoot) 'applied-manifest.json'),
    '--ollama-base-uri', [string]$script:Config.OllamaBaseUri
  )
  try {
    if (-not $process.WaitForExit(30000)) {
      $process.Kill(); $process.WaitForExit()
      throw 'worker-generator-preflight-timeout'
    }
    $stdout = $process.StandardOutput.ReadToEnd().Trim()
    $stderr = $process.StandardError.ReadToEnd().Trim()
    if ($process.ExitCode -ne 0) {
      $code = if ($stderr -match '^[a-z0-9][a-z0-9._:-]{0,159}$') { $stderr } else { 'worker-generator-preflight-failed' }
      throw $code
    }
    if ([string]::IsNullOrWhiteSpace($stdout)) { throw 'worker-generator-preflight-response-empty' }
    $result = $stdout | ConvertFrom-Json
    if (-not [bool]$result.valid) { throw 'worker-generator-preflight-invalid' }
    return $result
  } finally {
    $process.Dispose()
  }
}

function Assert-HchCycleChildPath {
  param([Parameter(Mandatory = $true)][string]$Path)
  $root = [IO.Path]::GetFullPath($script:CycleRoot).TrimEnd('\', '/')
  $resolved = [IO.Path]::GetFullPath($Path)
  if (-not $resolved.StartsWith($root + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) {
    throw 'worker-cycle-path-outside-state-root'
  }
  return $resolved
}

function Remove-HchCycleWorkDirectory {
  param([string]$Path)
  if ([string]::IsNullOrWhiteSpace($Path)) { return }
  $safePath = Assert-HchCycleChildPath -Path $Path
  if (Test-Path -LiteralPath $safePath) {
    Remove-Item -LiteralPath $safePath -Recurse -Force
  }
}

function ConvertTo-HchJournalItem {
  param($Item)
  return [ordered]@{
    assignment = $Item.Assignment
    phase = [string]$Item.Phase
    workDirectory = [string]$Item.WorkDirectory
    assignmentPath = [string]$Item.AssignmentPath
    draftPath = [string]$Item.DraftPath
    progressPath = [string]$Item.ProgressPath
    startedAt = [string]$Item.StartedAt
    generationDurationMilliseconds = [long]$Item.GenerationDurationMilliseconds
    generatorPid = if ($null -ne $Item.Process -and -not $Item.Process.HasExited) { [int]$Item.Process.Id } else { $null }
    processStartedAt = if ($null -ne $Item.Process -and -not $Item.Process.HasExited) {
      $Item.Process.StartTime.ToUniversalTime().ToString('o')
    } else { $null }
    errorCode = if ([string]::IsNullOrWhiteSpace([string]$Item.ErrorCode)) { $null } else { [string]$Item.ErrorCode }
    progress = [ordered]@{
      phase = [string]$Item.LastProgressPhase
      attempt = [int]$Item.LastProgressAttempt
      sequence = [long]$Item.LastProgressSequence
      contentBytes = [long]$Item.LastProgressContentBytes
      updatedAt = [string]$Item.LastProgressUpdatedAt
    }
    updatedAt = [DateTimeOffset]::UtcNow.ToString('o')
  }
}

function Save-HchCycleJournal {
  param([Parameter(Mandatory = $true)][Collections.IEnumerable]$Items, [string]$BatchId)
  $journalItems = @($Items | ForEach-Object { ConvertTo-HchJournalItem -Item $_ })
  if ($journalItems.Count -eq 0) {
    Remove-Item -LiteralPath $script:JournalPath -Force -ErrorAction SilentlyContinue
    return
  }
  Write-HchJsonAtomic -Path $script:JournalPath -Value ([ordered]@{
    schema = 'hch.worker-cycle-journal/v1'
    schemaVersion = 1
    nodeId = [string]$script:Config.NodeId
    batchId = $BatchId
    updatedAt = [DateTimeOffset]::UtcNow.ToString('o')
    items = $journalItems
  })
}

function Write-HchCycleSummary {
  param([string]$State, [string]$Code, [int]$Assignments = 0, [int]$Completed = 0, [int]$Failed = 0)
  $record = [ordered]@{
    schema = 'hch.worker-cycle-summary/v1'
    schemaVersion = 1
    nodeId = [string]$script:Config.NodeId
    observedAt = [DateTimeOffset]::UtcNow.ToString('o')
    state = $State
    code = $Code
    assignments = $Assignments
    completed = $Completed
    failed = $Failed
  }
  Write-HchJsonAtomic -Path $script:LastCyclePath -Value $record
  return [pscustomobject]$record
}

function Get-HchHeartbeatIntervalSeconds {
  param($Assignment)
  $remaining = ((ConvertFrom-HchTimestamp -Value ([string]$Assignment.leaseExpiresAt)) -
    [DateTimeOffset]::UtcNow).TotalSeconds
  if ($remaining -le 15) { throw 'worker-cycle-lease-window-too-short' }
  return [Math]::Min(30, [Math]::Max(5, [Math]::Floor($remaining / 3)))
}

function Set-HchNextHeartbeat {
  param($Item)
  $seconds = Get-HchHeartbeatIntervalSeconds -Assignment $Item.Assignment
  $frequency = [double][Diagnostics.Stopwatch]::Frequency
  $Item.NextHeartbeatTick = [long]([Diagnostics.Stopwatch]::GetTimestamp() + ($seconds * $frequency))
}

function Invoke-HchItemHeartbeat {
  param($Item, [Collections.IEnumerable]$AllItems, [string]$BatchId)
  $progress = Get-HchItemProgress -Item $Item
  $heartbeat = Invoke-HchWorkerHeartbeat -Config $script:Config -Assignment $Item.Assignment `
    -Progress $progress -DeferAutomaticUpdate
  if ([string]$heartbeat.assignmentId -ne [string]$Item.Assignment.assignmentId -or
      -not ($heartbeat.PSObject.Properties.Name -contains 'leaseExpiresAt')) {
    throw 'worker-cycle-heartbeat-response-invalid'
  }
  $Item.Assignment.leaseExpiresAt = [string]$heartbeat.leaseExpiresAt
  [void](Assert-HchAssignmentIntegrity -Config $script:Config -Assignment $Item.Assignment)
  Set-HchNextHeartbeat -Item $Item
  Save-HchCycleJournal -Items $AllItems -BatchId $BatchId
}

function Get-HchItemProgress {
  param($Item)
  if (-not (Test-Path -LiteralPath $Item.ProgressPath -PathType Leaf)) {
    throw 'worker-generator-progress-missing'
  }
  try { $progress = Read-HchJsonFile -Path $Item.ProgressPath }
  catch { throw 'worker-generator-progress-invalid' }
  $validated = Assert-HchAssignmentProgress -Progress $progress
  if ([int]$validated.attempt -lt [int]$Item.LastProgressAttempt) {
    throw 'worker-generator-progress-regressed'
  }
  if ([int]$validated.attempt -eq [int]$Item.LastProgressAttempt -and
      ([long]$validated.sequence -lt [long]$Item.LastProgressSequence -or
       [long]$validated.contentBytes -lt [long]$Item.LastProgressContentBytes)) {
    throw 'worker-generator-progress-regressed'
  }
  if ((ConvertFrom-HchTimestamp -Value ([string]$validated.updatedAt)) -lt
      (ConvertFrom-HchTimestamp -Value ([string]$Item.LastProgressUpdatedAt))) {
    throw 'worker-generator-progress-timestamp-regressed'
  }
  $Item.LastProgressSequence = [long]$validated.sequence
  $Item.LastProgressContentBytes = [long]$validated.contentBytes
  $Item.LastProgressAttempt = [int]$validated.attempt
  $Item.LastProgressPhase = [string]$validated.phase
  $Item.LastProgressUpdatedAt = [string]$validated.updatedAt
  return $validated
}

function Stop-HchGeneratorWhenStalled {
  param($Item)
  if ($null -eq $Item.Process -or $Item.Process.HasExited) { return $false }
  $progress = Get-HchItemProgress -Item $Item
  $plan = $Item.Assignment.generationPlan
  $now = [DateTimeOffset]::UtcNow
  $updatedAt = ConvertFrom-HchTimestamp -Value ([string]$progress.updatedAt)
  $code = $null
  if ([string]$progress.phase -eq 'starting' -and
      ($now - $updatedAt).TotalSeconds -gt [int]$plan.firstProgressGraceSeconds) {
    $code = 'generator-stalled'
  } elseif ([string]$progress.phase -eq 'responding' -and
      ($now - $updatedAt).TotalSeconds -gt [int]$plan.stallAfterSeconds) {
    $code = 'generator-stalled'
  } elseif ([string]$progress.phase -eq 'finalizing' -and
      ($now - $updatedAt).TotalSeconds -gt [int]$plan.finalizationGraceSeconds) {
    $code = 'generator-stalled'
  }
  if ($null -eq $code) { return $false }
  # The signed window is advisory. Termination is based exclusively on a lack
  # of observable progress; even a minimum-unit job may run indefinitely while
  # its monotonic progress record keeps advancing.
  $Item.ErrorCode = $code
  $Item.Process.Kill()
  $Item.Process.WaitForExit()
  return $true
}

function Stop-HchGeneratorProcesses {
  param([Collections.IEnumerable]$Items)
  foreach ($item in @($Items)) {
    if ($null -eq $item.Process) { continue }
    try {
      if (-not $item.Process.HasExited) { $item.Process.Kill(); $item.Process.WaitForExit() }
    } catch { }
  }
}

function Test-HchOperatorStopRequested {
  param([Collections.IEnumerable]$Items)
  $control = Get-HchWorkerControl -Config $script:Config
  if ([string]$control.updatedBy -ne 'stop' -or [bool]$control.acceptingClaims) { return $false }
  $requestedAt = ConvertFrom-HchTimestamp -Value ([string]$control.updatedAt)
  $oldestStart = @($Items | ForEach-Object {
    ConvertFrom-HchTimestamp -Value ([string]$_.StartedAt)
  } |
    Sort-Object | Select-Object -First 1)
  return $oldestStart.Count -eq 1 -and $requestedAt -ge $oldestStart[0]
}

function Stop-HchItemsByOperatorRequest {
  param([Collections.ArrayList]$Items, [string]$BatchId)
  foreach ($item in @($Items)) {
    try {
      if ($null -ne $item.Process -and -not $item.Process.HasExited) {
        $item.Process.Kill()
        $item.Process.WaitForExit()
      }
    } catch { }
    $item.ErrorCode = 'operator-stop-requested'
    $item.GenerationDurationMilliseconds = [long](
      [DateTimeOffset]::UtcNow - (ConvertFrom-HchTimestamp -Value ([string]$item.StartedAt))
    ).TotalMilliseconds
    $item.Phase = 'fail-unknown'
    Save-HchCycleJournal -Items $Items -BatchId $BatchId
    try {
      Invoke-HchWorkerFail -Config $script:Config -Assignment $item.Assignment `
        -ErrorCode 'operator-stop-requested' `
        -WorkDurationMilliseconds ([long]$item.GenerationDurationMilliseconds) | Out-Null
      Remove-HchRecoveredItem -Items $Items -Item $item -BatchId $BatchId
    } catch {
      # Keep fail-unknown in the journal. The next cycle replays the same
      # correlated failure operation instead of silently losing the lease.
    }
  }
  return $Items.Count -eq 0
}

function Test-HchPolicyMismatchError {
  param([Exception]$Exception)
  return [string]$Exception.Message -match '(?i)policy|manifest|update-required|stale|must-be-discarded|local-policy-mismatch'
}

function Test-HchGeneratorStalledError {
  param([Exception]$Exception)
  return $Exception.Data['HchStatusCode'] -eq 409 -and
    [string]$Exception.Message -match '(?i)generator-stalled'
}

function Test-HchLeaseLostError {
  param([Exception]$Exception)
  return [string]$Exception.Message -match '(?i)lease perdido|assignment ativo n.o encontrado|assignment n.o est. em processamento'
}

function Get-HchGeneratorErrorCode {
  param([string]$Stderr)
  $candidate = @($Stderr -split "`r?`n" | Where-Object { $_ -match '^[a-z0-9][a-z0-9._:-]{0,119}$' } | Select-Object -First 1)
  if ($candidate.Count -eq 1) {
    $safe = ([string]$candidate[0]).ToLowerInvariant() -replace '[^a-z0-9._-]', '-'
    $safe = $safe.Trim('-')
    if (-not [string]::IsNullOrWhiteSpace($safe)) {
      return ('generator-' + $safe).Substring(0, [Math]::Min(120, 10 + $safe.Length))
    }
  }
  return 'generator-execution-failed'
}

function Test-HchSafeOrphanProcess {
  param($JournalItem)
  if ($null -eq $JournalItem.generatorPid -or $null -eq $JournalItem.processStartedAt) { return $null }
  try {
    $process = Get-Process -Id ([int]$JournalItem.generatorPid) -ErrorAction Stop
    if (-not [string]::Equals([IO.Path]::GetFullPath([string]$process.Path), [IO.Path]::GetFullPath($script:NodePath), [StringComparison]::OrdinalIgnoreCase)) {
      return $null
    }
    $expectedStart = (ConvertFrom-HchTimestamp -Value ([string]$JournalItem.processStartedAt)).UtcDateTime
    if ([Math]::Abs(($process.StartTime.ToUniversalTime() - $expectedStart).TotalSeconds) -gt 2) { return $null }
    $cim = Get-CimInstance Win32_Process -Filter ('ProcessId=' + [string]$process.Id) -ErrorAction Stop
    $commandLine = [string]$cim.CommandLine
    if ($commandLine -notlike ('*' + $script:GeneratorPath + '*') -or
        $commandLine -notlike ('*' + [string]$JournalItem.assignmentPath + '*')) { return $null }
    return $process
  } catch { return $null }
}

function Remove-HchRecoveredItem {
  param([Collections.ArrayList]$Items, $Item, [string]$BatchId)
  Remove-HchCycleWorkDirectory -Path ([string]$Item.WorkDirectory)
  [void]$Items.Remove($Item)
  Save-HchCycleJournal -Items $Items -BatchId $BatchId
}

function Invoke-HchJournalRecovery {
  if (-not (Test-Path -LiteralPath $script:JournalPath -PathType Leaf)) { return $null }
  try { $journal = Read-HchJsonFile -Path $script:JournalPath }
  catch { throw 'worker-cycle-journal-invalid' }
  if ([string]$journal.schema -ne 'hch.worker-cycle-journal/v1' -or
      [int]$journal.schemaVersion -ne 1 -or
      [string]$journal.nodeId -ne [string]$script:Config.NodeId) {
    throw 'worker-cycle-journal-invalid'
  }
  $items = [Collections.ArrayList]::new()
  foreach ($stored in @($journal.items)) {
    $workDirectory = Assert-HchCycleChildPath -Path ([string]$stored.workDirectory)
    $assignmentPath = Assert-HchCycleChildPath -Path ([string]$stored.assignmentPath)
    $draftPath = Assert-HchCycleChildPath -Path ([string]$stored.draftPath)
    $progressPath = if ($stored.PSObject.Properties.Name -contains 'progressPath') {
      Assert-HchCycleChildPath -Path ([string]$stored.progressPath)
    } else { Assert-HchCycleChildPath -Path (Join-Path $workDirectory 'progress.json') }
    $item = [pscustomobject]@{
      Assignment = $stored.assignment
      Phase = [string]$stored.phase
      WorkDirectory = $workDirectory
      AssignmentPath = $assignmentPath
      DraftPath = $draftPath
      ProgressPath = $progressPath
      StartedAt = [string]$stored.startedAt
      GenerationDurationMilliseconds = [long]$stored.generationDurationMilliseconds
      Process = $null
      NextHeartbeatTick = 0L
      ErrorCode = [string]$stored.errorCode
      LastProgressSequence = if ($null -ne $stored.progress) { [long]$stored.progress.sequence } else { 0L }
      LastProgressContentBytes = if ($null -ne $stored.progress) { [long]$stored.progress.contentBytes } else { 0L }
      LastProgressAttempt = if ($null -ne $stored.progress) { [int]$stored.progress.attempt } else { 1 }
      LastProgressPhase = if ($null -ne $stored.progress) { [string]$stored.progress.phase } else { 'starting' }
      LastProgressUpdatedAt = if ($null -ne $stored.progress) { [string]$stored.progress.updatedAt } else { [string]$stored.startedAt }
    }
    [void]$items.Add($item)
    $orphan = Test-HchSafeOrphanProcess -JournalItem $stored
    if ($null -ne $orphan) {
      try { $orphan.Kill(); $orphan.WaitForExit() } finally { $orphan.Dispose() }
    }
  }

  $batchId = [string]$journal.batchId
  $requiresBootstrap = $false
  foreach ($item in @($items)) {
    $expiresAt = ConvertFrom-HchTimestamp -Value ([string]$item.Assignment.leaseExpiresAt)
    if ($expiresAt -le [DateTimeOffset]::UtcNow) {
      # Completion is idempotent on the orchestrator. Once the lease is
      # terminal, retaining the local draft cannot improve safety: a committed
      # generation already lives canonically on the server, while an uncommitted
      # result must be discarded. In either case the local journal can advance.
      [void](Update-HchWorkerMetrics -Config $script:Config -Event 'discarded' -ItemCount 1)
      [void](Update-HchWorkerActiveAssignmentCount -Config $script:Config -Delta -1)
      Remove-HchRecoveredItem -Items $items -Item $item -BatchId $batchId
      continue
    }

    if ([string]$item.Phase -in @('claimed', 'generating', 'abandoned')) {
      Set-HchWorkerStatus -Config $script:Config -State 'connection-error' `
        -Code 'prior-cycle-awaiting-lease-expiry' -ConnectionState 'error'
      return Write-HchCycleSummary -State 'blocked' -Code 'prior-cycle-awaiting-lease-expiry' `
        -Assignments $items.Count
    }

    if ([string]$item.Phase -eq 'fail-unknown') {
      try {
        Invoke-HchWorkerFail -Config $script:Config -Assignment $item.Assignment `
          -ErrorCode ([string]$item.ErrorCode) `
          -WorkDurationMilliseconds ([long]$item.GenerationDurationMilliseconds) | Out-Null
        Remove-HchRecoveredItem -Items $items -Item $item -BatchId $batchId
      } catch {
        return Write-HchCycleSummary -State 'blocked' -Code 'fail-reconciliation-pending' `
          -Assignments $items.Count
      }
      continue
    }

    if ([string]$item.Phase -notin @('draft-ready', 'completing', 'commit-unknown')) {
      throw 'worker-cycle-journal-phase-invalid'
    }
    if (-not (Test-Path -LiteralPath $item.DraftPath -PathType Leaf)) {
      throw 'worker-cycle-recovery-draft-missing'
    }
    $draft = Read-HchJsonFile -Path $item.DraftPath
    try {
      if ([string]$item.Phase -eq 'draft-ready') {
        Invoke-HchItemHeartbeat -Item $item -AllItems $items -BatchId $batchId
      }
      $item.Phase = 'completing'
      Save-HchCycleJournal -Items $items -BatchId $batchId
      Invoke-HchWorkerComplete -Config $script:Config -Assignment $item.Assignment -Draft $draft `
        -DeferAutomaticUpdate -WorkDurationMilliseconds ([long]$item.GenerationDurationMilliseconds) | Out-Null
      Remove-HchRecoveredItem -Items $items -Item $item -BatchId $batchId
    } catch {
      if (Test-HchPolicyMismatchError -Exception $_.Exception) {
        $requiresBootstrap = $true
        Remove-HchRecoveredItem -Items $items -Item $item -BatchId $batchId
        continue
      }
      $item.Phase = 'commit-unknown'
      Save-HchCycleJournal -Items $items -BatchId $batchId
      return Write-HchCycleSummary -State 'blocked' -Code 'commit-reconciliation-pending' `
        -Assignments $items.Count
    }
  }
  if ($requiresBootstrap) { [void](Invoke-HchWorkerBootstrap -Config $script:Config) }
  if ($items.Count -eq 0) {
    return Write-HchCycleSummary -State 'recovered' -Code 'prior-cycle-reconciled'
  }
  return Write-HchCycleSummary -State 'blocked' -Code 'prior-cycle-unresolved' -Assignments $items.Count
}

$config = Import-HchWorkerConfig -Path $ConfigPath
$script:Config = $config
$script:NodePath = Assert-HchNodeRuntime -Config $config
if (-not (Test-Path -LiteralPath $script:GeneratorPath -PathType Leaf)) { throw 'worker-generator-runner-not-found' }
$script:CycleRoot = Join-Path ([string]$config.StateRoot) 'cycles'
if (-not (Test-Path -LiteralPath $script:CycleRoot)) {
  New-Item -ItemType Directory -Path $script:CycleRoot -Force | Out-Null
}
$script:JournalPath = Join-Path $script:CycleRoot 'active-batch.json'
$script:LastCyclePath = Join-Path $script:CycleRoot 'last-cycle.json'
$lockPath = Join-Path $script:CycleRoot 'cycle.lock'
$lock = $null
$items = [Collections.ArrayList]::new()
$batchId = ''
$completedCount = 0
$failedCount = 0

try {
  try {
    $lock = [IO.File]::Open($lockPath, [IO.FileMode]::OpenOrCreate, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
  } catch [IO.IOException] {
    return Write-HchCycleSummary -State 'deferred' -Code 'worker-cycle-already-running'
  }

  $recovery = Invoke-HchJournalRecovery
  if ($null -ne $recovery) {
    if (Test-Path -LiteralPath $script:JournalPath -PathType Leaf) { return $recovery }
  }

  # Readiness is a renewable service lease, not a claim permission. Keep it
  # alive while paused/drained; the control checks below still block claims.
  $ready = $null
  try { $ready = Assert-HchClaimGate -Config $config } catch { }
  $refreshBefore = if ($config.ContainsKey('ReadyRefreshBeforeSeconds')) {
    [int]$config.ReadyRefreshBeforeSeconds
  } else { 3000 }
  if ($null -eq $ready -or
      ((ConvertFrom-HchTimestamp -Value ([string]$ready.readyUntil)) -
        [DateTimeOffset]::UtcNow).TotalSeconds -le $refreshBefore) {
    [void](Invoke-HchWorkerBootstrap -Config $config)
    $ready = Assert-HchClaimGate -Config $config
  }

  $control = Get-HchWorkerControl -Config $config
  if (-not [bool]$control.acceptingClaims -or [int]$control.requestedParallelism -eq 0) {
    $capacityPath = Join-Path ([string]$config.StateRoot) 'capacity.json'
    # Capacity zero is advertised only by the independent node-heartbeat loop.
    # The execution loop remains fail-closed and never calls /claim while drained.
    $finalCapacity = if (Test-Path -LiteralPath $capacityPath -PathType Leaf) {
      try { Read-HchJsonFile -Path $capacityPath } catch { $null }
    } else { $null }
    $activeDrainAssignments = if ($null -ne $finalCapacity) {
      [int]$finalCapacity.activeAssignments
    } else { 0 }
    if ($activeDrainAssignments -gt 0) {
      Set-HchWorkerStatus -Config $config -State 'processing' -Code 'drain-active-assignments'
      [void](Update-HchWorkerMetrics -Config $config -Event 'snapshot')
      return Write-HchCycleSummary -State 'draining' -Code 'active-assignments-preserved' `
        -Assignments $activeDrainAssignments
    }
    Set-HchWorkerStatus -Config $config -State 'standby' -Code 'drain-no-new-claims' -ClearCurrentBatch
    [void](Update-HchWorkerMetrics -Config $config -Event 'snapshot' -ClearCurrentBatch)
    return Write-HchCycleSummary -State 'drained' -Code 'new-claims-disabled'
  }

  [void](Invoke-HchGeneratorPreflight)

  $capacityPolicy = Get-HchInstalledCapacityPolicy -Config $config -Ready $ready
  $manifestLimit = [int]$capacityPolicy.absoluteRequestedMaximum
  if ($manifestLimit -lt 1 -or $manifestLimit -gt 64) {
    throw 'worker-cycle-signed-capacity-policy-invalid'
  }
  $localLimit = if ($config.ContainsKey('LocalParallelismLimit')) { [int]$config.LocalParallelismLimit } else { 8 }
  # Bootstrap and engine preflight can take time. Re-read the operator control
  # at the last safe boundary so a pause requested during preflight prevents
  # the subsequent queue claim.
  $control = Get-HchWorkerControl -Config $config
  if (-not [bool]$control.acceptingClaims -or [int]$control.requestedParallelism -eq 0) {
    Set-HchWorkerStatus -Config $config -State 'standby' -Code 'drain-before-claim' -ClearCurrentBatch
    [void](Update-HchWorkerMetrics -Config $config -Event 'snapshot' -ClearCurrentBatch)
    return Write-HchCycleSummary -State 'drained' -Code 'new-claims-disabled-before-claim'
  }
  $requestedCapacity = [Math]::Min(
    [int]$control.requestedParallelism,
    [Math]::Min($localLimit, $manifestLimit)
  )
  if ($requestedCapacity -lt 1) { throw 'worker-cycle-effective-parallelism-invalid' }

  $claim = Invoke-HchWorkerClaim -Config $config -RequestedCapacity $requestedCapacity
  $assignments = @($claim.assignments)
  if ($assignments.Count -eq 0) {
    return Write-HchCycleSummary -State 'standby' -Code 'queue-empty-or-capacity-not-granted'
  }
  if ($null -eq $claim.capacity -or
      $assignments.Count -gt [int]$claim.capacity.availableSlots) {
    throw 'worker-cycle-assignments-exceed-granted-capacity'
  }
  $batchId = [string]$claim.requestId
  foreach ($assignment in $assignments) {
    if ([string]$assignment.status -ne 'processing') { throw 'worker-cycle-assignment-state-invalid' }
    [void](Assert-HchAssignmentIntegrity -Config $config -Assignment $assignment)
    $workDirectory = Join-Path $script:CycleRoot ('work-' + [guid]::NewGuid().ToString('n'))
    New-Item -ItemType Directory -Path $workDirectory -Force | Out-Null
    $assignmentPath = Join-Path $workDirectory 'assignment.json'
    $draftPath = Join-Path $workDirectory 'draft.json'
    $progressPath = Join-Path $workDirectory 'progress.json'
    Write-HchJsonAtomic -Path $assignmentPath -Value $assignment
    $initialProgressAt = [DateTimeOffset]::UtcNow.ToString('o')
    Write-HchJsonAtomic -Path $progressPath -Value ([ordered]@{
      phase = 'starting'; attempt = 1; sequence = 0L; contentBytes = 0L
      updatedAt = $initialProgressAt
    })
    $item = [pscustomobject]@{
      Assignment = $assignment
      Phase = 'claimed'
      WorkDirectory = $workDirectory
      AssignmentPath = $assignmentPath
      DraftPath = $draftPath
      ProgressPath = $progressPath
      StartedAt = $initialProgressAt
      GenerationDurationMilliseconds = 0L
      Process = $null
      NextHeartbeatTick = 0L
      ErrorCode = ''
      LastProgressSequence = 0L
      LastProgressContentBytes = 0L
      LastProgressAttempt = 1
      LastProgressPhase = 'starting'
      LastProgressUpdatedAt = $initialProgressAt
    }
    [void]$items.Add($item)
  }
  Save-HchCycleJournal -Items $items -BatchId $batchId

  foreach ($item in @($items)) {
    Invoke-HchItemHeartbeat -Item $item -AllItems $items -BatchId $batchId
    $item.Process = Start-HchNodeProcess -Arguments @(
      $script:GeneratorPath,
      'generate',
      '--assignment', [string]$item.AssignmentPath,
      '--runtime-root', [string]$config.InstallRoot,
      '--applied-manifest', (Join-Path ([string]$config.StateRoot) 'applied-manifest.json'),
      '--ollama-base-uri', [string]$config.OllamaBaseUri,
      '--progress', [string]$item.ProgressPath,
      '--output', [string]$item.DraftPath
    )
    $item.Phase = 'generating'
    Save-HchCycleJournal -Items $items -BatchId $batchId
  }

  while ($items.Count -gt 0) {
    Start-Sleep -Milliseconds 500
    if (Test-HchOperatorStopRequested -Items $items) {
      $cancelled = Stop-HchItemsByOperatorRequest -Items $items -BatchId $batchId
      if (-not $cancelled) {
        return Write-HchCycleSummary -State 'blocked' -Code 'operator-stop-report-pending' `
          -Assignments $items.Count -Completed $completedCount -Failed $failedCount
      }
      return Write-HchCycleSummary -State 'stopped' -Code 'operator-stop-reported' `
        -Assignments $assignments.Count -Completed $completedCount -Failed $assignments.Count
    }
    $abortBatch = $false
    $abortException = $null
    $requiresBootstrap = $false
    foreach ($item in @($items)) {
      if ($null -ne $item.Process -and -not $item.Process.HasExited) {
        try { [void](Stop-HchGeneratorWhenStalled -Item $item) }
        catch {
          $item.ErrorCode = 'generator-progress-invalid'
          try { $item.Process.Kill(); $item.Process.WaitForExit() } catch { }
        }
      }
      if ($null -ne $item.Process -and -not $item.Process.HasExited -and
          [Diagnostics.Stopwatch]::GetTimestamp() -ge [long]$item.NextHeartbeatTick) {
        try { Invoke-HchItemHeartbeat -Item $item -AllItems $items -BatchId $batchId }
        catch {
          if (Test-HchGeneratorStalledError -Exception $_.Exception) {
            $item.ErrorCode = 'generator-stalled'
            try {
              if (-not $item.Process.HasExited) { $item.Process.Kill(); $item.Process.WaitForExit() }
            } finally {
              $item.Process.Dispose()
              $item.Process = $null
            }
            $startedAt = ConvertFrom-HchTimestamp -Value ([string]$item.StartedAt)
            $item.GenerationDurationMilliseconds = [long](
              [DateTimeOffset]::UtcNow - $startedAt
            ).TotalMilliseconds
            try {
              Invoke-HchWorkerFail -Config $config -Assignment $item.Assignment `
                -ErrorCode 'generator-stalled' `
                -WorkDurationMilliseconds ([long]$item.GenerationDurationMilliseconds) | Out-Null
              $failedCount++
              Remove-HchRecoveredItem -Items $items -Item $item -BatchId $batchId
            } catch {
              if (Test-HchPolicyMismatchError -Exception $_.Exception) {
                Stop-HchGeneratorProcesses -Items $items
                $item.Phase = 'abandoned'
                Save-HchCycleJournal -Items $items -BatchId $batchId
                [void](Invoke-HchWorkerBootstrap -Config $config)
                return Write-HchCycleSummary -State 'abandoned' `
                  -Code 'stalled-failure-gate-policy-stale' -Assignments $items.Count `
                  -Completed $completedCount -Failed $failedCount
              }
              $item.Phase = 'fail-unknown'
              Save-HchCycleJournal -Items $items -BatchId $batchId
              Stop-HchGeneratorProcesses -Items $items
              return Write-HchCycleSummary -State 'blocked' `
                -Code 'stalled-fail-reconciliation-pending' -Assignments $items.Count `
                -Completed $completedCount -Failed $failedCount
            }
            continue
          }
          if (Test-HchPolicyMismatchError -Exception $_.Exception) {
            $abortBatch = $true
            $abortException = $_.Exception
            $requiresBootstrap = $true
            break
          }
          if (Test-HchLeaseLostError -Exception $_.Exception) {
            $item.ErrorCode = 'progress-heartbeat-lease-lost'
            try { if (-not $item.Process.HasExited) { $item.Process.Kill(); $item.Process.WaitForExit() } } catch { }
            $item.Phase = 'abandoned'
            Remove-Item -LiteralPath $item.DraftPath -Force -ErrorAction SilentlyContinue
            Remove-HchRecoveredItem -Items $items -Item $item -BatchId $batchId
            continue
          }
          # A transient control-plane failure must not terminate useful work.
          # Keep observing local monotonic progress and retry this progress
          # heartbeat quickly. The orchestrator remains authoritative: if it
          # does not receive a signal within its lease window, the next retry
          # returns lease-lost and the process is then interrupted.
          $retrySeconds = 5
          $frequency = [double][Diagnostics.Stopwatch]::Frequency
          $item.NextHeartbeatTick = [long]([Diagnostics.Stopwatch]::GetTimestamp() +
            ($retrySeconds * $frequency))
          Save-HchCycleJournal -Items $items -BatchId $batchId
        }
      }
    }
    if ($abortBatch) {
      Stop-HchGeneratorProcesses -Items $items
      foreach ($item in @($items)) {
        $item.Phase = 'abandoned'
        Remove-Item -LiteralPath $item.DraftPath -Force -ErrorAction SilentlyContinue
      }
      Save-HchCycleJournal -Items $items -BatchId $batchId
      if ($requiresBootstrap) { [void](Invoke-HchWorkerBootstrap -Config $config) }
      return Write-HchCycleSummary -State 'abandoned' -Code 'heartbeat-or-policy-gate-failed' `
        -Assignments $items.Count
    }

    foreach ($item in @($items)) {
      if ($null -eq $item.Process -or -not $item.Process.HasExited) { continue }
      $item.Process.WaitForExit()
      $stdout = $item.Process.StandardOutput.ReadToEnd().Trim()
      $stderr = $item.Process.StandardError.ReadToEnd().Trim()
      $exitCode = $item.Process.ExitCode
      $item.Process.Dispose()
      $item.Process = $null
      $startedAt = ConvertFrom-HchTimestamp -Value ([string]$item.StartedAt)
      $item.GenerationDurationMilliseconds = [long]([DateTimeOffset]::UtcNow - $startedAt).TotalMilliseconds

      if ($exitCode -ne 0) {
        if ([string]::IsNullOrWhiteSpace([string]$item.ErrorCode)) {
          $item.ErrorCode = Get-HchGeneratorErrorCode -Stderr $stderr
        }
        try {
          try { Invoke-HchItemHeartbeat -Item $item -AllItems $items -BatchId $batchId }
          catch {
            if (-not (Test-HchGeneratorStalledError -Exception $_.Exception)) { throw }
            $item.ErrorCode = 'generator-stalled'
          }
          Invoke-HchWorkerFail -Config $config -Assignment $item.Assignment `
            -ErrorCode ([string]$item.ErrorCode) `
            -WorkDurationMilliseconds ([long]$item.GenerationDurationMilliseconds) | Out-Null
          $failedCount++
          Remove-HchRecoveredItem -Items $items -Item $item -BatchId $batchId
        } catch {
          if (Test-HchPolicyMismatchError -Exception $_.Exception) {
            Stop-HchGeneratorProcesses -Items $items
            $item.Phase = 'abandoned'
            Save-HchCycleJournal -Items $items -BatchId $batchId
            [void](Invoke-HchWorkerBootstrap -Config $config)
            return Write-HchCycleSummary -State 'abandoned' -Code 'failure-gate-policy-stale' `
              -Assignments $items.Count -Completed $completedCount -Failed $failedCount
          }
          $item.Phase = 'fail-unknown'
          Save-HchCycleJournal -Items $items -BatchId $batchId
          Stop-HchGeneratorProcesses -Items $items
          return Write-HchCycleSummary -State 'blocked' -Code 'fail-reconciliation-pending' `
            -Assignments $items.Count -Completed $completedCount -Failed $failedCount
        }
        continue
      }

      if ([string]::IsNullOrWhiteSpace($stdout)) { throw 'worker-generator-success-response-empty' }
      $generatorResult = $stdout | ConvertFrom-Json
      if (-not [bool]$generatorResult.ok -or -not (Test-Path -LiteralPath $item.DraftPath -PathType Leaf)) {
        throw 'worker-generator-success-contract-invalid'
      }
      $draft = Read-HchJsonFile -Path $item.DraftPath
      $item.Phase = 'draft-ready'
      Save-HchCycleJournal -Items $items -BatchId $batchId
      try {
        Invoke-HchItemHeartbeat -Item $item -AllItems $items -BatchId $batchId
        $item.Phase = 'completing'
        Save-HchCycleJournal -Items $items -BatchId $batchId
        Invoke-HchWorkerComplete -Config $config -Assignment $item.Assignment -Draft $draft `
          -DeferAutomaticUpdate -WorkDurationMilliseconds ([long]$item.GenerationDurationMilliseconds) | Out-Null
        $completedCount++
        Remove-HchRecoveredItem -Items $items -Item $item -BatchId $batchId
      } catch {
        if (Test-HchPolicyMismatchError -Exception $_.Exception) {
          Stop-HchGeneratorProcesses -Items $items
          Remove-Item -LiteralPath $item.DraftPath -Force -ErrorAction SilentlyContinue
          $item.Phase = 'abandoned'
          Save-HchCycleJournal -Items $items -BatchId $batchId
          [void](Invoke-HchWorkerBootstrap -Config $config)
          return Write-HchCycleSummary -State 'abandoned' -Code 'completion-policy-stale' `
            -Assignments $items.Count -Completed $completedCount -Failed $failedCount
        }
        $item.Phase = 'commit-unknown'
        Save-HchCycleJournal -Items $items -BatchId $batchId
        Stop-HchGeneratorProcesses -Items $items
        return Write-HchCycleSummary -State 'blocked' -Code 'commit-reconciliation-pending' `
          -Assignments $items.Count -Completed $completedCount -Failed $failedCount
      }
    }
  }

  return Write-HchCycleSummary -State 'completed' -Code 'cycle-finished' `
    -Assignments $assignments.Count -Completed $completedCount -Failed $failedCount
} catch {
  $failureCode = [string]$_.Exception.Message
  Stop-HchGeneratorProcesses -Items $items
  if ($items.Count -gt 0) { Save-HchCycleJournal -Items $items -BatchId $batchId }
  $diagnostic = [ordered]@{
    observedAt = [DateTimeOffset]::UtcNow.ToString('o')
    message = [string]$_.Exception.Message
    fullyQualifiedErrorId = [string]$_.FullyQualifiedErrorId
    scriptStackTrace = [string]$_.ScriptStackTrace
  }
  Write-HchJsonAtomic -Path (Join-Path ([string]$config.StateRoot) 'worker-cycle-diagnostic.json') `
    -Value $diagnostic
  if ($failureCode -eq 'worker-bootstrap-already-running') {
    # The service deliberately runs the claim cycle and the presence heartbeat
    # independently. A concurrent signed bootstrap is healthy coordination,
    # not an orchestrator connection or authentication failure.
    return Write-HchCycleSummary -State 'deferred' -Code $failureCode `
      -Assignments $items.Count -Completed $completedCount -Failed $failedCount
  }
  if ($failureCode -notmatch '^[a-z0-9][a-z0-9._:-]{2,159}$') {
    $failureCode = 'worker-cycle-failed-closed'
  }
  Set-HchWorkerStatus -Config $config -State 'connection-error' `
    -Code $failureCode -ConnectionState 'error'
  [void](Write-HchCycleSummary -State 'failed-closed' -Code $failureCode `
    -Assignments $items.Count -Completed $completedCount -Failed $failedCount)
  throw
} finally {
  if ($null -ne $lock) { $lock.Dispose() }
}
