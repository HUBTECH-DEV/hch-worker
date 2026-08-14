[CmdletBinding(SupportsShouldProcess = $true)]
param(
  [string]$ConfigPath,
  [string]$DestinationRoot = (Join-Path $env:ProgramFiles 'HCH\EditorialWorker'),
  [ValidateRange(3, 3600)][int]$PollSeconds = 15,
  [ValidateRange(30, 86400)][int]$StopTimeoutSeconds = 3600,
  [string]$ExpectedPublisherThumbprint = $env:HCH_WINDOWS_PUBLISHER_THUMBPRINT,
  [string]$PublisherCertificatePath = (Join-Path $PSScriptRoot 'trust\hch-windows-publisher.cer'),
  [switch]$AllowUnsignedDevelopmentBuild,
  [switch]$NoStart
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
if ([string]::IsNullOrWhiteSpace($ConfigPath)) { $ConfigPath = Join-Path $PSScriptRoot 'WorkerConfig.psd1' }
Import-Module (Join-Path $PSScriptRoot 'Hch.EditorialWorker.psm1') -Force
if ($null -eq (Get-Command 'Get-ScheduledTask' -ErrorAction SilentlyContinue)) {
  throw 'scheduled-tasks-module-unavailable'
}

$principal = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  throw 'worker-service-install-requires-administrator'
}
$config = Import-HchWorkerConfig -Path $ConfigPath
$serviceName = Get-HchWorkerServiceName -Config $config
$displayName = Get-HchWorkerServiceDisplayName -Config $config
$serviceAccount = 'NT SERVICE\' + $serviceName
$version = (Get-Content -Raw -LiteralPath (Join-Path $PSScriptRoot 'VERSION')).Trim()
if ($version -notmatch '^\d+\.\d+\.\d+$') { throw 'worker-kit-version-invalid' }
$versionRoot = [IO.Path]::GetFullPath((Join-Path $DestinationRoot ('versions\' + $version)))
$installedKitRoot = Join-Path $versionRoot 'ops\windows\editorial-worker'
$installedDashboardRoot = Join-Path $versionRoot 'ops\worker-dashboard'
$installedLibRoot = Join-Path $versionRoot 'lib'
$installedRuntimeRoot = Join-Path $versionRoot 'runtime'
$installedNodePath = Join-Path $installedRuntimeRoot 'node.exe'
$installedConfigRoot = Join-Path $env:ProgramData 'HCH\EditorialWorker\config'
$installedConfigPath = Join-Path $installedConfigRoot 'WorkerConfig.psd1'
$serviceTempRoot = Join-Path ([string]$config.StateRoot) 'service-temp'
$identityRoot = Join-Path ([string]$config.StateRoot) 'identity'
$privateKeyPath = Join-Path $identityRoot 'worker-private.pk8.pem'
$rootKeyDirectory = Split-Path -Parent ([string]$config.RootPublicKeyPath)
if (-not (Test-Path -LiteralPath ([string]$config.RootPublicKeyPath) -PathType Leaf)) {
  throw 'worker-service-root-public-key-not-found'
}
if (-not (Test-Path -LiteralPath $privateKeyPath -PathType Leaf)) {
  throw 'worker-service-private-key-not-found'
}
$serviceBinarySource = Join-Path $PSScriptRoot 'service\bin\HchEditorialWorkerService.exe'
$artifactEvidencePath = $serviceBinarySource + '.release.json'
$serviceBinaryPath = Join-Path $installedKitRoot 'service\bin\HchEditorialWorkerService.exe'
$runnerPath = Join-Path $installedKitRoot 'Run-WorkerCycle.ps1'
$heartbeatRunnerPath = Join-Path $installedKitRoot 'Send-WorkerNodeHeartbeat.ps1'
$controlCliPath = Join-Path $installedKitRoot 'Hch-Worker.ps1'
$installedDashboardServerPath = Join-Path $installedDashboardRoot 'server.mjs'
$powershellPath = Join-Path $PSHOME 'powershell.exe'
$programFilesRoot = [IO.Path]::GetFullPath($env:ProgramFiles).TrimEnd('\', '/')
$destinationRootFull = [IO.Path]::GetFullPath($DestinationRoot).TrimEnd('\', '/')
if (-not $destinationRootFull.StartsWith(
    $programFilesRoot + [IO.Path]::DirectorySeparatorChar,
    [StringComparison]::OrdinalIgnoreCase)) {
  throw 'worker-service-destination-must-be-under-program-files'
}
$programDataRoot = [IO.Path]::GetFullPath($env:ProgramData).TrimEnd('\', '/')
foreach ($mutablePath in @(
  [string]$config.StateRoot,
  [string]$config.InstallRoot,
  [string]$config.RootPublicKeyPath
)) {
  $canonicalMutablePath = [IO.Path]::GetFullPath($mutablePath)
  if (-not $canonicalMutablePath.StartsWith(
      $programDataRoot + [IO.Path]::DirectorySeparatorChar,
      [StringComparison]::OrdinalIgnoreCase)) {
    throw 'worker-service-mutable-path-must-be-under-program-data'
  }
}

function Invoke-HchSc {
  param([Parameter(Mandatory = $true)][string[]]$Arguments)
  $output = @(& (Join-Path $env:SystemRoot 'System32\sc.exe') @Arguments 2>&1)
  if ($LASTEXITCODE -ne 0) {
    $field = if ($Arguments.Count -gt 2) { ':' + $Arguments[2].TrimEnd('=') } else { '' }
    throw ('worker-service-scm-command-failed:' + $Arguments[0] + $field)
  }
  return $output
}

function Grant-HchServiceAccess {
  param(
    [Parameter(Mandatory = $true)][string]$Path,
    [Parameter(Mandatory = $true)][string]$Rights,
    [switch]$Recursive
  )
  if (-not (Test-Path -LiteralPath $Path)) { return }
  $aclArguments = @($Path, '/inheritance:e', '/grant:r', ($serviceAccount + ':' + $Rights))
  if ($Recursive) { $aclArguments += @('/T', '/C') }
  $output = @(& (Join-Path $env:SystemRoot 'System32\icacls.exe') @aclArguments 2>&1)
  if ($LASTEXITCODE -ne 0) { throw 'worker-service-acl-configuration-failed' }
}

function Protect-HchServicePrivateKey {
  param([Parameter(Mandatory = $true)][string]$Path)
  if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { throw 'worker-service-private-key-not-found' }
  $aclArguments = @(
    $Path,
    '/inheritance:r',
    '/grant:r', ($serviceAccount + ':R'),
    '/grant:r', ('*S-1-5-18:F'),
    '/grant:r', ('*S-1-5-32-544:F')
  )
  $output = @(& (Join-Path $env:SystemRoot 'System32\icacls.exe') @aclArguments 2>&1)
  if ($LASTEXITCODE -ne 0) { throw 'worker-service-private-key-acl-failed' }
}

$operationTarget = $serviceName + ' -> ' + $versionRoot
if ($PSCmdlet.ShouldProcess($operationTarget, 'build, install and register persistent HCH Windows Service')) {
  if ([string]::IsNullOrWhiteSpace($ExpectedPublisherThumbprint) -and
      (Test-Path -LiteralPath $PublisherCertificatePath -PathType Leaf)) {
    $ExpectedPublisherThumbprint = ([Security.Cryptography.X509Certificates.X509Certificate2]::new(
      [IO.Path]::GetFullPath($PublisherCertificatePath))).Thumbprint
  }
  if (-not $AllowUnsignedDevelopmentBuild) {
    [void](& (Join-Path $PSScriptRoot 'Test-HchPublisherTrust.ps1') -CertificatePath $PublisherCertificatePath)
  }
  [void](& (Join-Path $PSScriptRoot 'Test-HchWorkerReleaseArtifact.ps1') `
    -BinaryPath $serviceBinarySource `
    -EvidencePath $artifactEvidencePath `
    -ExpectedPublisherThumbprint $ExpectedPublisherThumbprint `
    -AllowUnsignedDevelopmentBuild:$AllowUnsignedDevelopmentBuild)
  # Installation and SCM startup never opt the worker into queue processing.
  [void](Set-HchWorkerControl -Config $config -Parallelism 0 -AcceptingClaims $false -UpdatedBy 'service-install')
  $existing = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
  $existingWasRunning = $null -ne $existing -and [string]$existing.Status -eq 'Running'
  $previousServiceConfig = if ($null -ne $existing) {
    Get-CimInstance -ClassName Win32_Service -Filter ("Name='" + $serviceName + "'") -ErrorAction Stop
  } else { $null }
$previousDelayedAutoStart = if ($null -ne $existing) {
    $delayedValue = Get-ItemPropertyValue `
      -LiteralPath ('HKLM:\SYSTEM\CurrentControlSet\Services\' + $serviceName) `
      -Name DelayedAutoStart -ErrorAction SilentlyContinue
    if ($null -eq $delayedValue) { 0 } else { [int]$delayedValue }
  } else { 0 }
  $previousInstalledConfig = if (Test-Path -LiteralPath $installedConfigPath -PathType Leaf) {
    [IO.File]::ReadAllBytes($installedConfigPath)
  } else { $null }
  $previousPrivateKeyAcl = Get-Acl -LiteralPath $privateKeyPath
  $previousRootKeyAcl = Get-Acl -LiteralPath ([string]$config.RootPublicKeyPath)
  $dashboardTaskName = 'HCH Editorial Dashboard - ' + [string]$config.NodeId
  $previousDashboardTask = Get-ScheduledTask -TaskName $dashboardTaskName -ErrorAction SilentlyContinue
  $previousDashboardTaskXml = if ($null -ne $previousDashboardTask) {
    Export-ScheduledTask -TaskName $dashboardTaskName
  } else { $null }
  $previousDashboardTaskWasRunning = $null -ne $previousDashboardTask -and
    [string]$previousDashboardTask.State -eq 'Running'
  $legacyTaskName = Get-HchWorkerCycleTaskName -Config $config
  $previousLegacyTask = Get-ScheduledTask -TaskName $legacyTaskName -ErrorAction SilentlyContinue
  $previousLegacyTaskXml = if ($null -ne $previousLegacyTask) {
    Export-ScheduledTask -TaskName $legacyTaskName
  } else { $null }
  $previousLegacyTaskWasRunning = $null -ne $previousLegacyTask -and
    [string]$previousLegacyTask.State -eq 'Running'
  $serviceCreated = $false
  $dashboardMutationAttempted = $null -ne $previousDashboardTask
  $legacyTaskRemoved = $false
  try {
  if ($previousDashboardTaskWasRunning) {
    Stop-ScheduledTask -TaskName $dashboardTaskName -ErrorAction Stop
    $dashboardStopDeadline = [DateTimeOffset]::UtcNow.AddSeconds(15)
    do {
      Start-Sleep -Milliseconds 250
      $dashboardTaskState = Get-ScheduledTask -TaskName $dashboardTaskName -ErrorAction SilentlyContinue
    } while ($null -ne $dashboardTaskState -and [string]$dashboardTaskState.State -eq 'Running' -and
      [DateTimeOffset]::UtcNow -lt $dashboardStopDeadline)
    if ($null -ne $dashboardTaskState -and [string]$dashboardTaskState.State -eq 'Running') {
      throw 'worker-dashboard-legacy-task-stop-timeout'
    }
  }
  if ($null -ne $existing -and [string]$existing.Status -ne 'Stopped') {
    Stop-Service -Name $serviceName
    $existing.WaitForStatus([System.ServiceProcess.ServiceControllerStatus]::Stopped,
      [TimeSpan]::FromSeconds($StopTimeoutSeconds + 30))
  }
  $nodeSourcePath = Assert-HchNodeRuntime -Config $config
  $nodeSignature = Get-AuthenticodeSignature -LiteralPath $nodeSourcePath
  if ([string]$nodeSignature.Status -ne 'Valid' -or $null -eq $nodeSignature.SignerCertificate) {
    throw 'worker-service-node-authenticode-invalid'
  }
  if (-not (Test-Path -LiteralPath $serviceTempRoot -PathType Container)) {
    New-Item -ItemType Directory -Path $serviceTempRoot -Force | Out-Null
  }
  foreach ($directory in @(
    $installedKitRoot,
    $installedDashboardRoot,
    $installedLibRoot,
    $installedRuntimeRoot,
    $installedConfigRoot
  )) {
    if (-not (Test-Path -LiteralPath $directory -PathType Container)) {
      New-Item -ItemType Directory -Path $directory -Force | Out-Null
    }
  }
  Get-ChildItem -LiteralPath $PSScriptRoot -Force | Where-Object {
    $_.Name -notin @('WorkerConfig.psd1', '.gitignore', 'tests')
  } | ForEach-Object {
    Copy-Item -LiteralPath $_.FullName -Destination $installedKitRoot -Recurse -Force
  }
  $repositoryRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..\..'))
  $sourceDashboardRoot = Join-Path $repositoryRoot 'ops\worker-dashboard'
  if (-not (Test-Path -LiteralPath (Join-Path $sourceDashboardRoot 'server.mjs') -PathType Leaf)) {
    throw 'worker-dashboard-source-not-found'
  }
  Get-ChildItem -LiteralPath $sourceDashboardRoot -Force | ForEach-Object {
    Copy-Item -LiteralPath $_.FullName -Destination $installedDashboardRoot -Recurse -Force
  }
  foreach ($libraryName in @(
    'canonical-text.mjs',
    'editorial-normalization.mjs',
    'editorial-model-catalog.mjs',
    'editorial-policy.mjs',
    'editorial-worker-signatures.mjs'
  )) {
    Copy-Item -LiteralPath (Join-Path $repositoryRoot ('lib\' + $libraryName)) `
      -Destination (Join-Path $installedLibRoot $libraryName) -Force
  }
  Copy-Item -LiteralPath ([IO.Path]::GetFullPath($ConfigPath)) -Destination $installedConfigPath -Force
  Copy-Item -LiteralPath $nodeSourcePath -Destination $installedNodePath -Force

  # Remove Zone.Identifier only after proving that every installed file is an
  # exact byte-for-byte copy of the locally selected kit. This lets the host
  # use RemoteSigned on machines whose LocalMachine policy is AllSigned while
  # still rejecting a partial or altered copy. Bypass is never used.
  $sourcePrefix = [IO.Path]::GetFullPath($PSScriptRoot).TrimEnd('\', '/') + [IO.Path]::DirectorySeparatorChar
  $sourceFiles = Get-ChildItem -LiteralPath $PSScriptRoot -File -Recurse -Force | Where-Object {
    $_.FullName -notmatch '[\\/]tests[\\/]' -and
    $_.FullName -notmatch '[\\/]WorkerConfig\.psd1$' -and
    $_.Name -ne '.gitignore'
  }
  foreach ($sourceFile in $sourceFiles) {
    $relative = $sourceFile.FullName.Substring($sourcePrefix.Length)
    $destinationFile = Join-Path $installedKitRoot $relative
    if (-not (Test-Path -LiteralPath $destinationFile -PathType Leaf) -or
        (Get-FileHash -LiteralPath $sourceFile.FullName -Algorithm SHA256).Hash -ne
        (Get-FileHash -LiteralPath $destinationFile -Algorithm SHA256).Hash) {
      throw 'worker-service-installed-kit-hash-mismatch'
    }
  }
  $dashboardSourcePrefix = [IO.Path]::GetFullPath($sourceDashboardRoot).TrimEnd('\', '/') +
    [IO.Path]::DirectorySeparatorChar
  foreach ($sourceFile in Get-ChildItem -LiteralPath $sourceDashboardRoot -File -Recurse -Force) {
    $relative = $sourceFile.FullName.Substring($dashboardSourcePrefix.Length)
    $destinationFile = Join-Path $installedDashboardRoot $relative
    if (-not (Test-Path -LiteralPath $destinationFile -PathType Leaf) -or
        (Get-FileHash -LiteralPath $sourceFile.FullName -Algorithm SHA256).Hash -ne
        (Get-FileHash -LiteralPath $destinationFile -Algorithm SHA256).Hash) {
      throw 'worker-service-installed-dashboard-hash-mismatch'
    }
  }
  foreach ($libraryName in @(
    'canonical-text.mjs',
    'editorial-normalization.mjs',
    'editorial-model-catalog.mjs',
    'editorial-policy.mjs',
    'editorial-worker-signatures.mjs'
  )) {
    $sourceLibrary = Join-Path $repositoryRoot ('lib\' + $libraryName)
    $destinationLibrary = Join-Path $installedLibRoot $libraryName
    if ((Get-FileHash -LiteralPath $sourceLibrary -Algorithm SHA256).Hash -ne
        (Get-FileHash -LiteralPath $destinationLibrary -Algorithm SHA256).Hash) {
      throw 'worker-service-installed-library-hash-mismatch'
    }
  }
  if ((Get-FileHash -LiteralPath ([IO.Path]::GetFullPath($ConfigPath)) -Algorithm SHA256).Hash -ne
      (Get-FileHash -LiteralPath $installedConfigPath -Algorithm SHA256).Hash) {
    throw 'worker-service-installed-config-hash-mismatch'
  }
  if ((Get-FileHash -LiteralPath $nodeSourcePath -Algorithm SHA256).Hash -ne
      (Get-FileHash -LiteralPath $installedNodePath -Algorithm SHA256).Hash) {
    throw 'worker-service-installed-node-hash-mismatch'
  }
  $installedNodeSignature = Get-AuthenticodeSignature -LiteralPath $installedNodePath
  if ([string]$installedNodeSignature.Status -ne 'Valid' -or
      $null -eq $installedNodeSignature.SignerCertificate -or
      [string]$installedNodeSignature.SignerCertificate.Thumbprint -ne
      [string]$nodeSignature.SignerCertificate.Thumbprint) {
    throw 'worker-service-installed-node-authenticode-invalid'
  }
  Get-ChildItem -LiteralPath $versionRoot -File -Recurse -Force | Unblock-File
  Unblock-File -LiteralPath $installedConfigPath

  # Pin the service configuration to the verified machine-scope copy so it
  # does not depend on a user profile PATH or AppData ACL after logoff.
  $configText = [IO.File]::ReadAllText($installedConfigPath)
  $nodeSettingPattern = '(?m)^(?<indent>[ \t]*)NodePath[ \t]*=[ \t]*.+$'
  if ([regex]::Matches($configText, $nodeSettingPattern).Count -ne 1) {
    throw 'worker-service-config-node-path-not-unique'
  }
  $escapedInstalledNodePath = $installedNodePath.Replace("'", "''")
  $configText = [regex]::Replace($configText, $nodeSettingPattern,
    ('${indent}NodePath = ''' + $escapedInstalledNodePath + ''''))
  $dashboardSettingPattern = '(?m)^(?<indent>[ \t]*)DashboardRoot[ \t]*=[ \t]*.+$'
  if ([regex]::Matches($configText, $dashboardSettingPattern).Count -ne 1) {
    throw 'worker-service-config-dashboard-root-not-unique'
  }
  $escapedInstalledDashboardRoot = $installedDashboardRoot.Replace("'", "''")
  $configText = [regex]::Replace($configText, $dashboardSettingPattern,
    ('${indent}DashboardRoot = ''' + $escapedInstalledDashboardRoot + ''''))
  [IO.File]::WriteAllText($installedConfigPath, $configText, [Text.UTF8Encoding]::new($false))
  $installedConfig = Import-HchWorkerConfig -Path $installedConfigPath
  if ([IO.Path]::GetFullPath([string]$installedConfig.NodePath) -ne [IO.Path]::GetFullPath($installedNodePath)) {
    throw 'worker-service-installed-node-config-mismatch'
  }
  if ([IO.Path]::GetFullPath([string]$installedConfig.DashboardRoot) -ne
      [IO.Path]::GetFullPath($installedDashboardRoot)) {
    throw 'worker-service-installed-dashboard-config-mismatch'
  }

  foreach ($requiredPath in @(
    $serviceBinaryPath,
    $runnerPath,
    $heartbeatRunnerPath,
    $controlCliPath,
    $installedDashboardServerPath,
    $powershellPath,
    $installedConfigPath
  )) {
    if (-not (Test-Path -LiteralPath $requiredPath -PathType Leaf)) { throw 'worker-service-installed-file-missing' }
  }

  $dashboardPort = if ($installedConfig.ContainsKey('DashboardPort')) {
    [int]$installedConfig.DashboardPort
  } else { 4319 }
  $quoted = { param([string]$Value) '"' + $Value.Replace('"', '\"') + '"' }
  $imagePath = (& $quoted $serviceBinaryPath) +
    ' --service-name ' + (& $quoted $serviceName) +
    ' --powershell ' + (& $quoted $powershellPath) +
    ' --runner ' + (& $quoted $runnerPath) +
    ' --heartbeat-runner ' + (& $quoted $heartbeatRunnerPath) +
    ' --control-cli ' + (& $quoted $controlCliPath) +
    ' --config ' + (& $quoted $installedConfigPath) +
    ' --node ' + (& $quoted $installedNodePath) +
    ' --dashboard-server ' + (& $quoted $installedDashboardServerPath) +
    ' --dashboard-root ' + (& $quoted $installedDashboardRoot) +
    ' --dashboard-port ' + $dashboardPort +
    ' --temp-root ' + (& $quoted $serviceTempRoot) +
    ' --poll-seconds ' + $PollSeconds +
    ' --stop-timeout-seconds ' + $StopTimeoutSeconds

  if ($null -eq $existing) {
    [void](Invoke-HchSc -Arguments @(
      'create', $serviceName,
      'binPath=', $serviceBinaryPath,
      'start=', 'auto'
    ))
    $serviceCreated = $true
  }
  Set-ItemProperty -LiteralPath ('HKLM:\SYSTEM\CurrentControlSet\Services\' + $serviceName) `
    -Name ImagePath -Value $imagePath -Type ExpandString
  [void](Invoke-HchSc -Arguments @('config', $serviceName, 'start=', 'delayed-auto'))
  [void](Invoke-HchSc -Arguments @('config', $serviceName, 'obj=', $serviceAccount))
  [void](Invoke-HchSc -Arguments @('config', $serviceName, 'DisplayName=', $displayName))
  [void](Invoke-HchSc -Arguments @('sidtype', $serviceName, 'unrestricted'))
  [void](Invoke-HchSc -Arguments @('description', $serviceName,
    'HCH signed central-queue editorial worker; approval and publication remain central.'))
  [void](Invoke-HchSc -Arguments @('failure', $serviceName, 'reset=', '86400',
    'actions=', 'restart/5000/restart/15000/restart/60000'))
  [void](Invoke-HchSc -Arguments @('failureflag', $serviceName, '1'))

  Grant-HchServiceAccess -Path ([string]$config.StateRoot) -Rights '(OI)(CI)M' -Recursive
  Grant-HchServiceAccess -Path ([string]$config.InstallRoot) -Rights '(OI)(CI)M' -Recursive
  Grant-HchServiceAccess -Path $installedConfigRoot -Rights '(OI)(CI)RX' -Recursive
  Grant-HchServiceAccess -Path $versionRoot -Rights '(OI)(CI)RX'
  Grant-HchServiceAccess -Path ([string]$config.RootPublicKeyPath) -Rights 'R'
  Grant-HchServiceAccess -Path $identityRoot -Rights '(OI)(CI)M' -Recursive
  Grant-HchServiceAccess -Path $serviceTempRoot -Rights '(OI)(CI)M' -Recursive
  Protect-HchServicePrivateKey -Path $privateKeyPath
  Grant-HchServiceAccess -Path $rootKeyDirectory -Rights '(OI)(CI)RX'

  if (-not [Diagnostics.EventLog]::SourceExists($serviceName)) {
    New-EventLog -LogName Application -Source $serviceName
  }

  if ($null -ne (Get-Command 'Get-ScheduledTask' -ErrorAction SilentlyContinue) -and
      $null -ne (Get-ScheduledTask -TaskName $legacyTaskName -ErrorAction SilentlyContinue)) {
    Unregister-ScheduledTask -TaskName $legacyTaskName -Confirm:$false
    $legacyTaskRemoved = $true
  }

  if (-not $NoStart) {
    Start-Service -Name $serviceName
    $dashboardReady = $false
    $dashboardDeadline = [DateTimeOffset]::UtcNow.AddSeconds(30)
    while ([DateTimeOffset]::UtcNow -lt $dashboardDeadline -and -not $dashboardReady) {
      try {
        $dashboardResponse = Invoke-WebRequest -UseBasicParsing `
          -Uri ('http://127.0.0.1:' + [string]$dashboardPort + '/') -TimeoutSec 2
        $dashboardReady = [int]$dashboardResponse.StatusCode -eq 200
      } catch { Start-Sleep -Milliseconds 500 }
    }
    if (-not $dashboardReady) { throw 'worker-service-dashboard-health-check-failed' }
  }
  if ($null -ne (Get-Command 'Get-ScheduledTask' -ErrorAction SilentlyContinue) -and
      $null -ne (Get-ScheduledTask -TaskName $dashboardTaskName -ErrorAction SilentlyContinue)) {
    Stop-ScheduledTask -TaskName $dashboardTaskName -ErrorAction SilentlyContinue
    Unregister-ScheduledTask -TaskName $dashboardTaskName -Confirm:$false
  }
  } catch {
    $installError = $_
    try { [void](Set-HchWorkerControl -Config $config -Parallelism 0 -AcceptingClaims $false -UpdatedBy 'service-install-rollback') }
    catch { }
    try {
      $currentService = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
      if ($null -ne $currentService -and [string]$currentService.Status -ne 'Stopped') {
        Stop-Service -Name $serviceName -ErrorAction SilentlyContinue
      }
      if ($serviceCreated) {
        [void](& (Join-Path $env:SystemRoot 'System32\sc.exe') 'delete' $serviceName 2>&1)
      } elseif ($null -ne $previousServiceConfig) {
        $previousStart = if ([string]$previousServiceConfig.StartMode -eq 'Disabled') {
          'disabled'
        } elseif ([string]$previousServiceConfig.StartMode -eq 'Auto' -and $previousDelayedAutoStart -eq 1) {
          'delayed-auto'
        } elseif ([string]$previousServiceConfig.StartMode -eq 'Auto') {
          'auto'
        } else { 'demand' }
        Set-ItemProperty -LiteralPath ('HKLM:\SYSTEM\CurrentControlSet\Services\' + $serviceName) `
          -Name ImagePath -Value ([string]$previousServiceConfig.PathName) -Type ExpandString
        [void](Invoke-HchSc -Arguments @('config', $serviceName, 'start=', $previousStart))
        [void](Invoke-HchSc -Arguments @('config', $serviceName, 'obj=', [string]$previousServiceConfig.StartName))
        [void](Invoke-HchSc -Arguments @('config', $serviceName, 'DisplayName=', [string]$previousServiceConfig.DisplayName))
      }
      if ($null -ne $previousInstalledConfig) {
        [IO.File]::WriteAllBytes($installedConfigPath, $previousInstalledConfig)
      }
      Set-Acl -LiteralPath $privateKeyPath -AclObject $previousPrivateKeyAcl
      Set-Acl -LiteralPath ([string]$config.RootPublicKeyPath) -AclObject $previousRootKeyAcl
      if ($dashboardMutationAttempted) {
        if ($null -ne $previousDashboardTaskXml) {
          Register-ScheduledTask -TaskName $dashboardTaskName -Xml $previousDashboardTaskXml -Force | Out-Null
          if ($previousDashboardTaskWasRunning) { Start-ScheduledTask -TaskName $dashboardTaskName }
        } else {
          Unregister-ScheduledTask -TaskName $dashboardTaskName -Confirm:$false -ErrorAction SilentlyContinue
        }
      }
      if ($legacyTaskRemoved -and $null -ne $previousLegacyTaskXml) {
        Register-ScheduledTask -TaskName $legacyTaskName -Xml $previousLegacyTaskXml -Force | Out-Null
        if ($previousLegacyTaskWasRunning) { Start-ScheduledTask -TaskName $legacyTaskName }
      }
      if (-not $serviceCreated -and $existingWasRunning) { Start-Service -Name $serviceName }
    } catch {
      try { Write-EventLog -LogName Application -Source 'Windows PowerShell' -EventId 4100 `
        -EntryType Error -Message ('hch-worker-service-install-rollback-failed:' + $serviceName) }
      catch { }
    }
    throw $installError
  }
}

$installedService = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
[pscustomobject]@{
  serviceName = $serviceName
  displayName = $displayName
  installed = $null -ne $installedService
  state = if ($null -ne $installedService) { [string]$installedService.Status } else { $null }
  startupType = 'AutomaticDelayedStart'
  serviceAccount = $serviceAccount
  version = $version
  versionRoot = $versionRoot
  configPath = $installedConfigPath
  dashboardRoot = $installedDashboardRoot
  claimsEnabledByInstall = $false
  legacyProcessingTaskUsed = $false
}
