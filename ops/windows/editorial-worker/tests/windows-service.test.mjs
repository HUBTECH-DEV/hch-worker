import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { existsSync, mkdtempSync, readdirSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { basename, dirname, extname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

const kitRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const serviceRoot = join(kitRoot, "service");

function filesBelow(root, predicate) {
  if (!existsSync(root)) return [];
  const result = [];
  for (const entry of readdirSync(root, { withFileTypes: true })) {
    const path = join(root, entry.name);
    if (entry.isDirectory()) result.push(...filesBelow(path, predicate));
    else if (entry.isFile() && predicate(path)) result.push(path);
  }
  return result.sort();
}

function source(paths) {
  return paths.map((path) => readFileSync(path, "utf8")).join("\n");
}

function powershell(script) {
  const encoded = Buffer.from(script, "utf16le").toString("base64");
  return execFileSync(
    "powershell.exe",
    ["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-EncodedCommand", encoded],
    { encoding: "utf8", windowsHide: true },
  ).trim();
}

test("the editorial runtime is a native .NET Framework Windows Service without a visible terminal", () => {
  const csharpFiles = filesBelow(serviceRoot, (path) => extname(path).toLowerCase() === ".cs");
  const buildPath = join(kitRoot, "Build-HchWorkerService.ps1");

  assert.ok(existsSync(buildPath), "the service must have a reproducible build script");
  assert.equal(csharpFiles.length, 1, "the kit must contain one auditable Windows Service host source");

  const build = readFileSync(buildPath, "utf8");
  const csharp = source(csharpFiles);
  assert.match(build, /csc(?:\.exe)?/i);
  assert.match(build, /System\.ServiceProcess/i);
  assert.match(build, /HchEditorialWorkerService\.cs/i);
  assert.match(csharp, /:\s*ServiceBase/);
  assert.match(csharp, /ServiceBase\.Run/);
  assert.match(csharp, /OnStart\s*\(/);
  assert.match(csharp, /OnStop\s*\(/);

  // The host may invoke the existing PowerShell cycle, but never through a
  // command shell or a visible child window.
  assert.match(csharp, /ProcessStartInfo/);
  assert.match(csharp, /UseShellExecute\s*=\s*false/);
  assert.match(csharp, /CreateNoWindow\s*=\s*true/);
  assert.match(csharp, /WindowStyle\s*=\s*ProcessWindowStyle\.Hidden/);
  assert.match(csharp, /-NoProfile/);
  assert.match(csharp, /-NonInteractive/);
  assert.match(csharp, /RemoteSigned/);
  assert.match(csharp, /NotifyControlPlane/);
  assert.doesNotMatch(csharp, /ExecutionPolicy[^\r\n]*Bypass/i);
  assert.doesNotMatch(csharp, /(?:cmd\.exe|\/bin\/sh|powershell(?:\.exe)?\s+-Command)/i);
  assert.match(csharp, /StopDashboardProcess/);
  assert.doesNotMatch(csharp, /activeCycle\.(?:Kill|CloseMainWindow)/i);
});

test("SCM stop is cooperative and drains before the service exits", () => {
  const csharp = source(filesBelow(serviceRoot, (path) => extname(path).toLowerCase() === ".cs"));

  assert.match(csharp, /OnStop\s*\(/);
  assert.match(csharp, /Cancel|stopRequested|stopping/i);
  assert.match(csharp, /WaitForExit|Join|active(?:Assignment|Cycle)|grace/i);

  const drainIndex = csharp.search(/Cancel|stopRequested|stopping/i);
  const waitIndex = csharp.search(/WaitForExitAsync|WaitForExit|active(?:Assignment|Cycle)|grace/i);
  assert.ok(drainIndex >= 0 && waitIndex > drainIndex, "new cycles must stop before waiting for active work");
});

test("installation and local CLI use SCM, not Task Scheduler, for editorial processing", () => {
  const serviceScripts = filesBelow(kitRoot, (path) => {
    const name = basename(path);
    return extname(path).toLowerCase() === ".ps1" && /service/i.test(name);
  });
  assert.ok(serviceScripts.length >= 1, "an idempotent Windows Service installer must be present");

  const installer = source(serviceScripts);
  const cli = readFileSync(join(kitRoot, "Hch-Worker.ps1"), "utf8");
  const cycle = readFileSync(join(kitRoot, "Run-WorkerCycle.ps1"), "utf8");

  assert.match(installer, /New-Service|sc(?:\.exe)?[^\r\n]*(?:create|config)/i);
  assert.match(installer, /Get-Service|sc(?:\.exe)?[^\r\n]*query/i);
  assert.match(installer, /Automatic|delayed-auto|DelayedAutoStart/i);
  assert.match(installer, /Start-Service|sc(?:\.exe)?[^\r\n]*start/i);
  assert.ok(installer.indexOf("Set-HchWorkerControl") < installer.indexOf("Start-Service"));
  assert.ok(installer.indexOf("installed-kit-hash-mismatch") < installer.indexOf("Unblock-File"));
  assert.match(installer, /installed-node-hash-mismatch/);
  assert.match(installer, /Get-AuthenticodeSignature -LiteralPath \$nodeSourcePath/);
  assert.match(installer, /worker-service-node-authenticode-invalid/);
  assert.match(installer, /Test-HchWorkerReleaseArtifact\.ps1/);
  assert.match(installer, /ExpectedPublisherThumbprint/);
  assert.match(installer, /AllowUnsignedDevelopmentBuild/);
  assert.doesNotMatch(installer, /Build-HchWorkerService\.ps1/);
  assert.match(installer, /worker-service-installed-node-authenticode-invalid/);
  assert.match(installer, /installed-dashboard-hash-mismatch/);
  assert.match(installer, /installed-dashboard-config-mismatch/);
  assert.match(installer, /worker-service-dashboard-health-check-failed/);
  assert.match(installer, /Unregister-ScheduledTask/);
  assert.match(installer, /editorial-policy\.mjs/);
  assert.match(installer, /worker-private\.pk8\.pem/);
  assert.match(installer, /'\/inheritance:r'/);
  assert.match(installer, /\*S-1-5-18:F/);
  assert.match(installer, /\*S-1-5-32-544:F/);
  assert.match(installer, /Grant-HchServiceAccess[\s\S]*-Recursive/);

  // Unregister-ScheduledTask is allowed only to retire the previous runtime.
  assert.doesNotMatch(cli, /Register-ScheduledTask|New-ScheduledTask(?:Action|Trigger|Principal|SettingsSet)|Enable-ScheduledTask|Start-ScheduledTask/i);
  assert.doesNotMatch(installer, /New-ScheduledTask(?:Action|Trigger|Principal|SettingsSet)|Enable-ScheduledTask/i);
  assert.match(installer, /Export-ScheduledTask/);
  assert.match(installer, /service-install-rollback/);
  assert.doesNotMatch(cycle, /ScheduledTask|schtasks\.exe/i);
  assert.match(cli, /Get-Service|Start-Service|Get-Hch.*Service/i);

  const startBlock = cli.slice(cli.indexOf("  'start' {"), cli.indexOf("  'pause' {"));
  const pauseBlock = cli.slice(cli.indexOf("  'pause' {"), cli.indexOf("  'stop' {"));
  const stopBlock = cli.slice(cli.indexOf("  'stop' {"), cli.indexOf("  'set-parallelism' {"));
  assert.ok(startBlock.includes("Set-HchWorkerControl"), "start must persist operator intent before resuming");
  assert.ok(pauseBlock.includes("Set-HchWorkerControl"), "pause must persist local drain first");
  assert.ok(stopBlock.includes("Set-HchWorkerControl"), "stop must persist cancellation intent first");
  assert.match(stopBlock, /Invoke-HchServerDrainNotification/);
  assert.match(stopBlock, /operator-stop-requested/);
  assert.match(cli, /delegatedToService|service-notification-pending/);
  assert.doesNotMatch(stopBlock, /Stop-Service|Stop-Process|taskkill/i);
  assert.match(cycle, /Stop-HchItemsByOperatorRequest/);
  assert.match(cli, /Invoke-HchWorkerNodeHeartbeat -Config \$config -RequestedCapacity 0/);
  assert.doesNotMatch(cycle, /Invoke-HchWorkerClaim[\s\S]{0,160}RequestedCapacity 0/);
  assert.match(cycle, /drain-active-assignments/);
  assert.match(cycle, /active-assignments-preserved/);
});

test("service installation is opt-in and never enables claims by itself", () => {
  const serviceScripts = source(filesBelow(kitRoot, (path) => {
    const name = basename(path);
    return extname(path).toLowerCase() === ".ps1" && /service/i.test(name);
  }));
  const cli = readFileSync(join(kitRoot, "Hch-Worker.ps1"), "utf8");

  assert.doesNotMatch(serviceScripts, /AcceptingClaims\s+\$true|acceptingClaims['"\s:=]+true/i);
  const configureBlock = cli.slice(cli.indexOf("  'configure' {"), cli.indexOf("  'validate' {"));
  assert.match(configureBlock, /Parallelism 0/);
  assert.match(configureBlock, /AcceptingClaims \$false/);
});

test("an existing service identity does not replace the shared StateRoot ACL", () => {
  const workerModule = readFileSync(join(kitRoot, "Hch.EditorialWorker.psm1"), "utf8");
  const identityStart = workerModule.indexOf("function Initialize-HchWorkerIdentity");
  const identityEnd = workerModule.indexOf("function Get-HchWorkerIdentity", identityStart);
  const identityBlock = workerModule.slice(identityStart, identityEnd);
  const existingIdentityGate = identityBlock.indexOf(
    "Test-Path -LiteralPath $metadataPath -PathType Leaf",
  );
  const stateAclReset = identityBlock.indexOf(
    "Set-HchRestrictedAcl -Path ([string]$Config.StateRoot) -Container",
  );

  assert.ok(existingIdentityGate >= 0, "existing identities must have a fast path");
  assert.ok(
    existingIdentityGate < stateAclReset,
    "the service principal must not remove the dashboard operator from shared state",
  );
  assert.match(identityBlock, /return Get-HchWorkerIdentity -Config \$Config/);
});

test("operator validation uses only the public identity after private-key hardening", () => {
  const workerModule = readFileSync(join(kitRoot, "Hch.EditorialWorker.psm1"), "utf8");
  const cli = readFileSync(join(kitRoot, "Hch-Worker.ps1"), "utf8");
  const validateStart = cli.indexOf("function Invoke-HchLocalValidate");
  const validateEnd = cli.indexOf("function Get-HchCliStatus", validateStart);
  const validateBlock = cli.slice(validateStart, validateEnd);

  assert.match(workerModule, /\[switch\]\$PublicOnly/);
  assert.match(validateBlock, /Get-HchWorkerPublicKeyId -Config \$config/);
  assert.match(validateBlock, /Get-HchInstalledCapacityPolicy[^\r\n]*-PublicOnly/);
  assert.doesNotMatch(validateBlock, /worker-private\.pk8\.pem/);
});

test("the native service sends a serial node heartbeat every 60 seconds independently of long work", () => {
  const csharp = source(filesBelow(serviceRoot, (path) => extname(path).toLowerCase() === ".cs"));
  const installer = readFileSync(join(kitRoot, "Install-HchWorkerService.ps1"), "utf8");
  const heartbeat = readFileSync(join(kitRoot, "Send-WorkerNodeHeartbeat.ps1"), "utf8");

  assert.match(csharp, /heartbeatThread = new Thread\(RunHeartbeatLoop\)/);
  assert.match(csharp, /nextHeartbeatTick \+= \(long\)\(60 \* ticksPerSecond\)/);
  assert.match(csharp, /while \(nextHeartbeatTick <= now\)/);
  assert.match(csharp, /RunOneHeartbeat\(\)/);
  assert.match(csharp, /heartbeatRunnerPath/);
  assert.match(installer, /--heartbeat-runner/);
  assert.match(heartbeat, /Invoke-HchWorkerNodeHeartbeat/);
  assert.doesNotMatch(heartbeat, /Invoke-HchWorkerClaim|Run-WorkerCycle|editorial-generator/);
});

test("SCM service names are deterministic, bounded and unique per node", (context) => {
  if (process.platform !== "win32") return context.skip("Windows PowerShell integration test");
  const modulePath = join(kitRoot, "Hch.EditorialWorker.psm1").replaceAll("'", "''");
  const result = JSON.parse(powershell(`
    Import-Module '${modulePath}' -Force
    $one = Get-HchWorkerServiceName -Config @{ NodeId = 'Windows Worker / São Paulo' }
    $again = Get-HchWorkerServiceName -Config @{ NodeId = 'Windows Worker / São Paulo' }
    $other = Get-HchWorkerServiceName -Config @{ NodeId = 'Windows Worker - Sao Paulo' }
    @{ one = $one; again = $again; other = $other } | ConvertTo-Json -Compress
  `));

  assert.equal(result.one, result.again);
  assert.notEqual(result.one, result.other);
  assert.match(result.one, /^HchEditorialWorker-[a-z0-9-]+$/i);
  assert.ok(result.one.length <= 128);
});

test("the local compiler produces a winexe and preserves Windows arguments with spaces and backslashes", (context) => {
  if (process.platform !== "win32") return context.skip("Windows .NET Framework integration test");
  const directory = mkdtempSync(join(tmpdir(), "hch-worker-service-build-"));
  context.after(() => rmSync(directory, { recursive: true, force: true }));
  const outputPath = join(directory, "HchEditorialWorkerService.exe");
  const buildPath = join(kitRoot, "Build-HchWorkerService.ps1").replaceAll("'", "''");
  const escapedOutput = outputPath.replaceAll("'", "''");
  const encoded = powershell(String.raw`
    $ProgressPreference = 'SilentlyContinue'
    [void](& '${buildPath}' -OutputPath '${escapedOutput}')
    $assembly = [Reflection.Assembly]::LoadFrom('${escapedOutput}')
    $type = $assembly.GetType('Hch.EditorialWorker.ServiceHost.HchEditorialWorkerService', $true)
    $method = $type.GetMethod('Quote', [Reflection.BindingFlags]'Static,NonPublic')
    $values = @(
      $method.Invoke($null, [object[]]@('C:\Program Files\HCH\WorkerConfig.psd1')),
      $method.Invoke($null, [object[]]@('C:\ending\')),
      $method.Invoke($null, [object[]]@('a"b'))
    )
    [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes(($values | ConvertTo-Json -Compress)))
  `);
  const values = JSON.parse(Buffer.from(encoded, "base64").toString("utf8"));
  assert.deepEqual(values, [
    '"C:\\Program Files\\HCH\\WorkerConfig.psd1"',
    '"C:\\ending\\\\"',
    '"a\\"b"',
  ]);
  assert.ok(existsSync(outputPath));
});

test("Windows Service release has a patched semantic version", () => {
  assert.equal(readFileSync(join(kitRoot, "VERSION"), "utf8").trim(), "3.1.0");
});

test("assignment progress heartbeat tolerates transient transport failure and stops only on liveness loss", () => {
  const cycle = readFileSync(join(kitRoot, "Run-WorkerCycle.ps1"), "utf8");
  assert.match(cycle, /Invoke-HchItemHeartbeat/);
  assert.match(cycle, /Stop-HchGeneratorWhenStalled/);
  assert.match(cycle, /Test-HchLeaseLostError/);
  assert.match(cycle, /progress-heartbeat-lease-lost/);
  assert.match(cycle, /transient control-plane failure must not terminate useful work/i);
  assert.match(cycle, /NextHeartbeatTick[\s\S]{0,240}\$retrySeconds/);
  assert.doesNotMatch(cycle, /catch\s*\{[\s\S]{0,240}\$abortBatch\s*=\s*\$true[\s\S]{0,120}control-plane-request-timeout/i);
  assert.doesNotMatch(cycle, /commit-reconciliation-required/);
  assert.match(cycle, /Completion is idempotent on the orchestrator/);
});

test("service heartbeat renews readiness without enabling claims", () => {
  const heartbeat = readFileSync(join(kitRoot, "Send-WorkerNodeHeartbeat.ps1"), "utf8");
  assert.match(heartbeat, /Assert-HchClaimGate/);
  assert.match(heartbeat, /Invoke-HchWorkerBootstrap/);
  assert.match(heartbeat, /try\s*\{\s*\[void\]\(Invoke-HchWorkerBootstrap[\s\S]*?\}\s*catch\s*\{\s*\}/);
  assert.match(heartbeat, /if\s*\(\$null\s*-eq\s*\$ready\)\s*\{\s*0/);
  assert.match(heartbeat, /Invoke-HchWorkerNodeHeartbeat/);
  assert.match(heartbeat, /RequestedCapacity \$capacity/);
  assert.doesNotMatch(heartbeat, /Invoke-HchWorkerClaim|editorial-generator/);
});

test("release artifact gate requires integrity, publisher identity, and timestamp", () => {
  const verifier = readFileSync(join(kitRoot, "Test-HchWorkerReleaseArtifact.ps1"), "utf8");
  const signer = readFileSync(join(kitRoot, "Sign-HchWorkerReleaseArtifact.ps1"), "utf8");
  const manifest = readFileSync(join(serviceRoot, "HchEditorialWorkerService.exe.manifest"), "utf8");
  const csharp = readFileSync(join(serviceRoot, "HchEditorialWorkerService.cs"), "utf8");
  assert.match(verifier, /worker-release-artifact-hash-mismatch/);
  assert.match(verifier, /worker-release-authenticode-required/);
  assert.match(verifier, /worker-release-timestamp-required/);
  assert.match(verifier, /worker-release-publisher-mismatch/);
  assert.match(signer, /\/fd SHA256/);
  assert.match(signer, /\/tr \$TimestampUrl \/td SHA256/);
  assert.match(manifest, /requestedExecutionLevel level="asInvoker"/);
  assert.match(csharp, /AssemblyCompany\("HUBTECH CONSULTORIA E DESENVOLVIMENTO LTDA"\)/);
  assert.match(csharp, /AssemblyFileVersion\("3\.1\.0\.0"\)/);
});

test("manual publisher trust is explicit, machine-scoped, and never exports the private key", () => {
  const create = readFileSync(join(kitRoot, "New-HchInternalCodeSigningCertificate.ps1"), "utf8");
  const install = readFileSync(join(kitRoot, "Install-HchPublisherTrust.ps1"), "utf8");
  assert.match(create, /KeyExportPolicy NonExportable/);
  assert.match(create, /Type CodeSigningCert/);
  assert.match(install, /ShouldContinue/);
  assert.match(install, /LocalMachine/);
  assert.match(install, /'Root', 'TrustedPublisher'/);
  assert.match(install, /HUBTECH CONSULTORIA E DESENVOLVIMENTO LTDA/);
  assert.doesNotMatch(install, /Set-MpPreference|Add-MpPreference|ExclusionPath|DisableRealtimeMonitoring/i);
});
