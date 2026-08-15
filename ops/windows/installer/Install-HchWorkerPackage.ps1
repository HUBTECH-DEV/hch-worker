[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)][string]$PayloadRoot,
  [Parameter(Mandatory = $true)][string]$ResponsePath
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$principal = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  throw 'hch-setup-requires-administrator'
}
$payload = [IO.Path]::GetFullPath($PayloadRoot)
$responseFile = [IO.Path]::GetFullPath($ResponsePath)
$settings = Get-Content -Raw -LiteralPath $responseFile | ConvertFrom-Json
if ([string]$settings.orchestratorUrl -notmatch '^https://[A-Za-z0-9.-]+(?::\d+)?$') {
  throw 'hch-setup-orchestrator-url-invalid'
}
if ([string]$settings.nodeId -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]{2,127}$') {
  throw 'hch-setup-node-id-invalid'
}
if ([int]$settings.parallelism -lt 0 -or [int]$settings.parallelism -gt 64) {
  throw 'hch-setup-parallelism-invalid'
}
if ([string]::IsNullOrWhiteSpace([string]$settings.enrollmentToken)) {
  throw 'hch-setup-enrollment-token-required'
}
if ($settings.acceptPublisherTrust -ne $true) { throw 'hch-setup-publisher-trust-not-accepted' }

$kitRoot = Join-Path $payload 'ops\windows\editorial-worker'
$installer = Join-Path $kitRoot 'Install-HchWorkerService.ps1'
$module = Join-Path $kitRoot 'Hch.EditorialWorker.psm1'
$nodePath = Join-Path $payload 'runtime\node.exe'
$rootSource = Join-Path $payload 'trust\orchestrator-root.pem'
$publisherCertificate = Join-Path $kitRoot 'trust\hch-windows-publisher.cer'
foreach ($required in @($installer, $module, $nodePath, $rootSource, $publisherCertificate)) {
  if (-not (Test-Path -LiteralPath $required -PathType Leaf)) { throw 'hch-setup-payload-incomplete' }
}

$programDataRoot = Join-Path $env:ProgramData 'HCH\EditorialWorker'
$stateRoot = Join-Path $programDataRoot 'state'
$runtimeRoot = Join-Path $programDataRoot 'runtime'
$trustRoot = Join-Path $programDataRoot 'trust'
$rootTarget = Join-Path $trustRoot 'orchestrator-root.pem'
$setupRoot = Join-Path $programDataRoot 'setup'
$configPath = Join-Path $setupRoot 'WorkerConfig.psd1'
foreach ($directory in @($stateRoot, $runtimeRoot, $trustRoot, $setupRoot)) {
  New-Item -ItemType Directory -Path $directory -Force | Out-Null
}
Copy-Item -LiteralPath $rootSource -Destination $rootTarget -Force
$publisher = [Security.Cryptography.X509Certificates.X509Certificate2]::new($publisherCertificate)
if ($publisher.Subject -notmatch 'HUBTECH CONSULTORIA E DESENVOLVIMENTO LTDA' -or $publisher.HasPrivateKey) {
  throw 'hch-setup-publisher-certificate-invalid'
}
foreach ($storeName in @('Root', 'TrustedPublisher')) {
  $store = [Security.Cryptography.X509Certificates.X509Store]::new($storeName, 'LocalMachine')
  try { $store.Open('ReadWrite'); $store.Add($publisher) } finally { $store.Close() }
}

function Quote-HchPsLiteral([string]$Value) { return "'" + $Value.Replace("'", "''") + "'" }
$parallelism = [int]$settings.parallelism
$initialCapacity = if ($parallelism -eq 0) { 1 } else { $parallelism }
$config = @"
@{
  SchemaVersion = 2
  NodeId = $(Quote-HchPsLiteral ([string]$settings.nodeId))
  ControlPlaneBaseUri = $(Quote-HchPsLiteral ([string]$settings.orchestratorUrl))
  RequestedCapacity = $initialCapacity
  LocalParallelismLimit = 64
  RootPublicKeyPath = $(Quote-HchPsLiteral $rootTarget)
  StateRoot = $(Quote-HchPsLiteral $stateRoot)
  InstallRoot = $(Quote-HchPsLiteral $runtimeRoot)
  NodePath = $(Quote-HchPsLiteral $nodePath)
  MinimumNodeMajor = 22
  ClockSkewSeconds = 60
  RequestLifetimeSeconds = 120
  HeartbeatRequestTimeoutSeconds = 10
  NodeHeartbeatIntervalSeconds = 60
  NodeHeartbeatRequestTimeoutSeconds = 10
  ReadyRefreshBeforeSeconds = 3000
  AllowedArtifactOrigins = @($(Quote-HchPsLiteral ([string]$settings.orchestratorUrl)))
  AllowedSelfTestOrigins = @($(Quote-HchPsLiteral ([string]$settings.orchestratorUrl)), 'http://127.0.0.1:11434')
  OllamaBaseUri = 'http://127.0.0.1:11434'
  ModelPullTimeoutSeconds = 3600
  AutomaticUpdateOnPolicyMismatch = `$true
  DashboardRoot = $(Quote-HchPsLiteral (Join-Path $payload 'ops\worker-dashboard'))
  DashboardPort = 4319
}
"@
[IO.File]::WriteAllText($configPath, $config, [Text.UTF8Encoding]::new($false))

$priorToken = [Environment]::GetEnvironmentVariable('HCH_EDITORIAL_ENROLLMENT_TOKEN', 'Machine')
try {
  [Environment]::SetEnvironmentVariable(
    'HCH_EDITORIAL_ENROLLMENT_TOKEN', [string]$settings.enrollmentToken, 'Machine')
  Import-Module $module -Force
  $workerConfig = Import-HchWorkerConfig -Path $configPath
  [void](Initialize-HchWorkerIdentity -Config $workerConfig)
  $result = & $installer -ConfigPath $configPath
  if ($parallelism -eq 0) {
    & (Join-Path $kitRoot 'Hch-Worker.ps1') -Command set-parallelism `
      -ConfigPath (Join-Path $env:ProgramData 'HCH\EditorialWorker\config\WorkerConfig.psd1') `
      -Parallelism 0 | Out-Null
  }
  $readyPath = Join-Path $stateRoot 'ready.json'
  $deadline = [DateTimeOffset]::UtcNow.AddMinutes(3)
  while (-not (Test-Path -LiteralPath $readyPath -PathType Leaf) -and
      [DateTimeOffset]::UtcNow -lt $deadline) { Start-Sleep -Milliseconds 500 }
  if (-not (Test-Path -LiteralPath $readyPath -PathType Leaf)) {
    throw 'hch-setup-worker-readiness-timeout'
  }
  [pscustomobject]@{
    serviceName = [string]$result.serviceName
    state = [string]$result.state
    dashboardUrl = 'http://127.0.0.1:4319'
  }
} finally {
  [Environment]::SetEnvironmentVariable('HCH_EDITORIAL_ENROLLMENT_TOKEN', $priorToken, 'Machine')
  Remove-Item -LiteralPath $responseFile -Force -ErrorAction SilentlyContinue
}
