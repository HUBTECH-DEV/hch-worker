import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import {
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

const testDirectory = dirname(fileURLToPath(import.meta.url));
const repositoryRoot = resolve(testDirectory, "../../../..");
const exporter = join(repositoryRoot, "scripts", "windows", "Export-HchWorkerCanaryEvidence.ps1");
const sourceCommit = "a".repeat(40);
const version = "4.0.0";

const completedAssignment = "11111111-1111-4111-8111-111111111111";
const failedAssignment = "22222222-2222-4222-8222-222222222222";
const completedPlanHash = hash("completed-generation-plan");
const failedPlanHash = hash("failed-generation-plan");
const nodeId = "windows-canary-node-0001";
const workerKeyId = "worker-key-canary-0001";
const startedMs = Date.parse("2026-08-31T12:00:00.000Z");

const pwshProbe = spawnSync("pwsh", ["-NoLogo", "-NoProfile", "-Command", "$PSVersionTable.PSVersion.ToString()"], {
  encoding: "utf8",
});

test("exports deterministic unsigned v2 evidence only from a complete real-capture bundle", (context) => {
  if (pwshProbe.error || pwshProbe.status !== 0) return context.skip("PowerShell 7 is unavailable");

  const directory = mkdtempSync(join(tmpdir(), "hch-worker-canary-export-"));
  context.after(() => rmSync(directory, { recursive: true, force: true }));
  const fixture = createCaptureBundle(directory);
  const firstPath = join(directory, "canary-evidence-1.json");
  const secondPath = join(directory, "canary-evidence-2.json");

  const first = runExporter(fixture.captureDirectory, firstPath, fixture.msiPath);
  assert.equal(first.status, 0, first.stderr || first.stdout);
  assert.match(first.stdout, /Unsigned deterministic canary evidence exported/);
  const second = runExporter(fixture.captureDirectory, secondPath, fixture.msiPath);
  assert.equal(second.status, 0, second.stderr || second.stdout);

  const firstBytes = readFileSync(firstPath);
  const secondBytes = readFileSync(secondPath);
  assert.deepEqual(firstBytes, secondBytes, "The same frozen sources must produce identical evidence bytes");
  assert.notEqual(firstBytes[0], 0xef, "Evidence must not contain a UTF-8 BOM");
  assert.equal(firstBytes.at(-1), 0x0a, "Evidence must have one final LF");
  assert.equal(firstBytes.includes(Buffer.from("\r\n")), false, "Evidence must not contain CRLF");

  const evidence = JSON.parse(firstBytes.toString("utf8"));
  assert.deepEqual(Object.keys(evidence), [
    "schema", "status", "sanitized", "version", "sourceCommit", "msiSha256",
    "startedAtUtc", "completedAtUtc", "gates", "heartbeatSamples", "progressSamples",
    "completions", "failures", "rollbackReceipt",
  ]);
  assert.equal(evidence.schema, "hch.worker-windows-canary/v2");
  assert.equal(evidence.status, "passed");
  assert.equal(evidence.sanitized, true);
  assert.equal(evidence.version, version);
  assert.equal(evidence.sourceCommit, sourceCommit);
  assert.equal(evidence.msiSha256, hashBytes(readFileSync(fixture.msiPath)));
  assert.equal(evidence.heartbeatSamples.length, 10);
  assert.equal(evidence.progressSamples.length, 2);
  assert.equal(evidence.completions.length, 1);
  assert.equal(evidence.failures.length, 1);
  assert.deepEqual(Object.values(evidence.gates), [true, true, true, true, true, true]);

  for (const sample of evidence.heartbeatSamples) {
    assert.equal(sample.receiptSha256, heartbeatReceiptSha256(sample, "node-heartbeat"));
  }
  for (const sample of evidence.progressSamples) {
    assert.equal(sample.receiptSha256, progressReceiptSha256(sample));
  }
  assert.equal(evidence.completions[0].receiptSha256, completionReceiptSha256(evidence.completions[0]));
  assert.equal(evidence.failures[0].receiptSha256, failureReceiptSha256(evidence.failures[0]));
  assert.equal(
    evidence.rollbackReceipt.legacyHeartbeat.receiptSha256,
    heartbeatReceiptSha256(evidence.rollbackReceipt.legacyHeartbeat, "legacy-node-heartbeat"),
  );
  assert.equal(evidence.rollbackReceipt.receiptSha256, rollbackReceiptSha256(evidence.rollbackReceipt));

  const serialized = firstBytes.toString("utf8");
  for (const prohibited of [
    "ownerEmail", "workerPublicKey", "leaseToken", "sourceProductRoot",
    "securityDescriptorSddl", "draftHash", "requestBodyDigest",
  ]) {
    assert.equal(serialized.includes(prohibited), false, `Evidence leaked source-only field ${prohibited}`);
  }
});

test("fails closed when a required accepted capture is absent", (context) => {
  if (pwshProbe.error || pwshProbe.status !== 0) return context.skip("PowerShell 7 is unavailable");

  const directory = mkdtempSync(join(tmpdir(), "hch-worker-canary-export-missing-"));
  context.after(() => rmSync(directory, { recursive: true, force: true }));
  const fixture = createCaptureBundle(directory);
  unlinkSync(join(fixture.captureDirectory, "accepted", "completions", "completion.json"));
  const evidencePath = join(directory, "canary-evidence.json");

  const result = runExporter(fixture.captureDirectory, evidencePath, fixture.msiPath);
  assert.notEqual(result.status, 0, "An incomplete real-capture bundle was accepted");
  assert.match(`${result.stdout}\n${result.stderr}`, /capture count is outside the permitted bound/);
  assert.throws(() => readFileSync(evidencePath), /ENOENT/);
});

test("refuses secret-shaped material and never emits partial evidence", (context) => {
  if (pwshProbe.error || pwshProbe.status !== 0) return context.skip("PowerShell 7 is unavailable");

  const directory = mkdtempSync(join(tmpdir(), "hch-worker-canary-export-secret-"));
  context.after(() => rmSync(directory, { recursive: true, force: true }));
  const fixture = createCaptureBundle(directory);
  const progressPath = join(fixture.captureDirectory, "accepted", "assignment-heartbeats", "progress-1.json");
  const progress = JSON.parse(readFileSync(progressPath, "utf8"));
  progress.leaseToken = "must-never-enter-evidence";
  writeJson(progressPath, progress);
  const evidencePath = join(directory, "canary-evidence.json");

  const result = runExporter(fixture.captureDirectory, evidencePath, fixture.msiPath);
  assert.notEqual(result.status, 0, "Secret-shaped capture material was accepted");
  assert.match(`${result.stdout}\n${result.stderr}`, /prohibited secret-shaped material/);
  assert.throws(() => readFileSync(evidencePath), /ENOENT/);
});

test("does not trust source-supplied receipt aggregates and refuses overwrite", (context) => {
  if (pwshProbe.error || pwshProbe.status !== 0) return context.skip("PowerShell 7 is unavailable");

  const directory = mkdtempSync(join(tmpdir(), "hch-worker-canary-export-aggregate-"));
  context.after(() => rmSync(directory, { recursive: true, force: true }));
  const fixture = createCaptureBundle(directory);
  const heartbeatPath = join(fixture.captureDirectory, "accepted", "node-heartbeats", "heartbeat-01.json");
  const heartbeat = JSON.parse(readFileSync(heartbeatPath, "utf8"));
  heartbeat.receiptSha256 = "f".repeat(64);
  writeJson(heartbeatPath, heartbeat);
  const evidencePath = join(directory, "canary-evidence.json");

  const suppliedAggregate = runExporter(fixture.captureDirectory, evidencePath, fixture.msiPath);
  assert.notEqual(suppliedAggregate.status, 0, "A source-supplied receipt aggregate was trusted");
  assert.match(`${suppliedAggregate.stdout}\n${suppliedAggregate.stderr}`, /exact permitted property set/);
  assert.throws(() => readFileSync(evidencePath), /ENOENT/);

  delete heartbeat.receiptSha256;
  writeJson(heartbeatPath, heartbeat);
  writeFileSync(evidencePath, "do-not-overwrite\n", "utf8");
  const overwrite = runExporter(fixture.captureDirectory, evidencePath, fixture.msiPath);
  assert.notEqual(overwrite.status, 0, "Existing evidence was overwritten");
  assert.match(`${overwrite.stdout}\n${overwrite.stderr}`, /Refusing to overwrite existing canary evidence/);
  assert.equal(readFileSync(evidencePath, "utf8"), "do-not-overwrite\n");
});

test("rejects a paused-state probe captured from a different candidate build", (context) => {
  if (pwshProbe.error || pwshProbe.status !== 0) return context.skip("PowerShell 7 is unavailable");

  const directory = mkdtempSync(join(tmpdir(), "hch-worker-canary-export-identity-"));
  context.after(() => rmSync(directory, { recursive: true, force: true }));
  const fixture = createCaptureBundle(directory);
  const probePath = join(fixture.captureDirectory, "probes", "installed-state.json");
  const probe = JSON.parse(readFileSync(probePath, "utf8"));
  probe.sourceCommit = "b".repeat(40);
  writeJson(probePath, probe);

  const result = runExporter(fixture.captureDirectory, join(directory, "canary-evidence.json"), fixture.msiPath);
  assert.notEqual(result.status, 0, "A state probe from another candidate build was accepted");
  assert.match(`${result.stdout}\n${result.stderr}`, /does not bind the candidate identity or state/);
});

test("requires the accepted legacy heartbeat strictly after rollback", (context) => {
  if (pwshProbe.error || pwshProbe.status !== 0) return context.skip("PowerShell 7 is unavailable");

  const directory = mkdtempSync(join(tmpdir(), "hch-worker-canary-export-rollback-order-"));
  context.after(() => rmSync(directory, { recursive: true, force: true }));
  const fixture = createCaptureBundle(directory);
  const rollbackPath = join(fixture.captureDirectory, "rollback", "rollback.json");
  const rollback = JSON.parse(readFileSync(rollbackPath, "utf8"));
  rollback.legacyHeartbeat.serverTime = rollback.serverTime;
  rollback.legacyHeartbeat.heartbeatAt = iso(Date.parse(rollback.serverTime) - 1_000);
  writeJson(rollbackPath, rollback);

  const result = runExporter(fixture.captureDirectory, join(directory, "canary-evidence.json"), fixture.msiPath);
  assert.notEqual(result.status, 0, "A legacy heartbeat at the rollback timestamp was accepted");
  assert.match(`${result.stdout}\n${result.stderr}`, /strictly after restoration/);
});

test("requires restart proof before rollback validation and the legacy heartbeat", (context) => {
  if (pwshProbe.error || pwshProbe.status !== 0) return context.skip("PowerShell 7 is unavailable");

  const directory = mkdtempSync(join(tmpdir(), "hch-worker-canary-export-restart-order-"));
  context.after(() => rmSync(directory, { recursive: true, force: true }));
  const fixture = createCaptureBundle(directory);
  const rollbackPath = join(fixture.captureDirectory, "rollback", "rollback.json");
  const rollback = JSON.parse(readFileSync(rollbackPath, "utf8"));
  const restartPath = join(fixture.captureDirectory, "probes", "restart-state.json");
  const restart = JSON.parse(readFileSync(restartPath, "utf8"));
  restart.observedAtUtc = iso(Date.parse(rollback.serverTime) + 1_000);
  writeJson(restartPath, restart);

  const result = runExporter(fixture.captureDirectory, join(directory, "canary-evidence.json"), fixture.msiPath);
  assert.notEqual(result.status, 0, "A restart captured after rollback was accepted");
  assert.match(`${result.stdout}\n${result.stderr}`, /boundaries are not chronologically valid/);
});

test("source documents the runtime persistence gap and performs no signing", () => {
  const source = readFileSync(exporter, "utf8");
  assert.match(source, /Current runtime limitation:/);
  assert.match(source, /does not yet persist accepted node-heartbeat/);
  assert.match(source, /Missing sources fail closed/);
  assert.doesNotMatch(source, /Sign-HchWorkerCanaryEvidence|SignedCms|CmsSigner|Certificate/i);
  assert.doesNotMatch(source, /Get-Date|UtcNow|DateTimeOffset\]::Now/i);
});

function createCaptureBundle(directory) {
  const captureDirectory = join(directory, "capture");
  const msiPath = join(directory, "HCH-Worker-4.0.0-win-x64.msi");
  mkdirSync(captureDirectory, { recursive: true });
  writeFileSync(msiPath, Buffer.from("fixed canary MSI candidate bytes\n", "utf8"));
  const msiSha256 = hashBytes(readFileSync(msiPath));

  writeJson(join(captureDirectory, "probes", "installed-state.json"), pausedProbe(
    "installed-paused-drain",
    iso(startedMs - 30_000),
    msiSha256,
  ));
  writeJson(join(captureDirectory, "probes", "restart-state.json"), pausedProbe(
    "restart-paused-drain",
    iso(startedMs + 600_000),
    msiSha256,
  ));
  writeJson(join(captureDirectory, "probes", "legacy-before-start.json"), {
    schema: "hch.worker-windows-scm-capture/v1",
    capture: "legacy-before-start",
    serviceName: "HchEditorialWorkerService",
    serviceState: "Stopped",
    startMode: "Disabled",
    processId: 0,
    observedAtUtc: iso(startedMs - 20_000),
  });

  writeJson(join(captureDirectory, "runtime", "enrollment", "operational-key.json"), {
    schemaVersion: 1,
    protocol: "operational-key-proof-v1",
    requestId: "70000000-0000-4000-8000-000000000001",
    tokenId: "canary-enrollment-token-id",
    nodeId,
    workerKeyId,
    workerPublicKeyPem: "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEATestOnlyCanaryPublicKeyMaterial000000=\n-----END PUBLIC KEY-----",
    workerPublicKeyFingerprint: hash("worker-public-key"),
    ownerUserId: "70000000-0000-4000-8000-000000000002",
    ownerEmail: "canary.operator@example.invalid",
    ownerSshKeyId: "owner-ssh-key-canary-0001",
    ownerSshKeyFingerprint: hash("owner-ssh-key"),
    status: "active",
    enrolledAt: iso(startedMs - 60_000),
  });

  const manifestHash = hash("manifest");
  const contentContractHash = hash("content-contract");
  const policyHash = hash("policy");
  const trustVerifiedAt = iso(startedMs - 55_000);
  writeJson(join(captureDirectory, "runtime", "ready.json"), {
    schemaVersion: 1,
    ready: true,
    nodeId,
    keyId: workerKeyId,
    manifestSequence: 4,
    manifestHash,
    contentContractHash,
    policyHash,
    provider: "ollama",
    engineAdapter: "ollama-streaming",
    engineAdapterVersion: "1.0.0",
    workerRuntimeVersion: version,
    runtimeProfileHash: hash("runtime-profile"),
    capacityPolicyHash: hash("capacity-policy"),
    adaptiveWorkPolicyHash: hash("adaptive-work-policy"),
    requestedCapacity: 0,
    grantedCapacity: 0,
    capacityClass: "drain",
    capacityReason: "installed-paused-drain",
    capacityGrantedUntil: null,
    bootstrapSessionId: "70000000-0000-4000-8000-000000000003",
    readyUntil: iso(startedMs + 1_200_000),
    attestedAt: iso(startedMs - 50_000),
    trustVerifiedAt,
  });
  writeJson(join(captureDirectory, "runtime", "trust-state.json"), {
    schema: "hch.worker-trust-state/v1",
    schemaVersion: 1,
    rootKeyId: "orchestrator-root-key-0001",
    rootFingerprint: hash("root-key"),
    releaseKeyId: "worker-release-key-0001",
    delegationSequence: 3,
    delegationHash: hash("delegation"),
    manifestSequence: 4,
    manifestHash,
    contentContractHash,
    policyHash,
    verifiedAt: trustVerifiedAt,
  });

  for (let index = 0; index < 10; index += 1) {
    const serverTime = startedMs + (index * 100_000);
    writeJson(join(
      captureDirectory,
      "accepted",
      "node-heartbeats",
      `heartbeat-${String(index + 1).padStart(2, "0")}.json`,
    ), {
      schema: "hch.worker-canary-node-heartbeat-capture/v1",
      validatedAtUtc: iso(serverTime + 250),
      response: heartbeatResponse(index, serverTime),
    });
  }

  writeJson(join(captureDirectory, "accepted", "assignment-heartbeats", "progress-1.json"),
    progressCapture(1, 15, 1024, startedMs + 200_000));
  writeJson(join(captureDirectory, "accepted", "assignment-heartbeats", "progress-2.json"),
    progressCapture(2, 75, 4096, startedMs + 300_000));

  writeJson(join(captureDirectory, "accepted", "completions", "completion.json"), {
    schema: "hch.worker-canary-complete-capture/v1",
    validatedAtUtc: iso(startedMs + 400_250),
    response: {
      assignmentId: completedAssignment,
      generationPlanHash: completedPlanHash,
      commitAccepted: true,
      status: "pending-review",
      automaticApproval: false,
      automaticPublication: false,
      replayed: false,
      serverTime: iso(startedMs + 400_000),
    },
  });
  writeJson(join(captureDirectory, "accepted", "failures", "failure.json"), {
    schema: "hch.worker-canary-fail-capture/v1",
    validatedAtUtc: iso(startedMs + 500_250),
    requestErrorCode: "canary-controlled-generation-failure",
    response: {
      assignmentId: failedAssignment,
      generationPlanHash: failedPlanHash,
      status: "failed-attempt",
      replayed: false,
      serverTime: iso(startedMs + 500_000),
    },
  });

  writeJson(join(captureDirectory, "runtime", "journals", "assignments", `${completedAssignment}.json`), {
    schemaVersion: 1,
    assignmentId: completedAssignment,
    generationPlanHash: completedPlanHash,
    leaseTokenHash: hash("completed-lease-token"),
    leaseExpiresAt: iso(startedMs + 700_000),
    phase: 6,
    requestId: "30000000-0000-4000-8000-000000000001",
    requestBodyDigest: hash("completion-request-body"),
    draftHash: hash("completion-draft"),
    lastErrorCode: null,
    updatedAt: iso(startedMs + 401_000),
  });
  writeJson(join(captureDirectory, "runtime", "journals", "assignments", `${failedAssignment}.json`), {
    schemaVersion: 1,
    assignmentId: failedAssignment,
    generationPlanHash: failedPlanHash,
    leaseTokenHash: hash("failed-lease-token"),
    leaseExpiresAt: iso(startedMs + 800_000),
    phase: 7,
    requestId: "40000000-0000-4000-8000-000000000001",
    requestBodyDigest: hash("failure-request-body"),
    draftHash: null,
    lastErrorCode: "canary-controlled-generation-failure",
    updatedAt: iso(startedMs + 501_000),
  });

  const serviceDefinition = {
    serviceName: "HchEditorialWorkerService",
    imagePath: "C:\\Program Files\\HCH Worker\\worker.exe",
    accountName: "LocalSystem",
    startMode: 2,
    serviceType: 16,
    delayedAutomaticStart: true,
    failureActionsSha256: hash("failure-actions"),
    securityDescriptorSddl: "D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCLCSWRPWPDTLOCRRC;;;BA)",
  };
  const backupPayload = {
    schemaVersion: 1,
    migrationId: "80000000-0000-4000-8000-000000000001",
    sourceVersion: "3.1.0",
    sourceProductRoot: "C:\\ProgramData\\HCH\\EditorialWorker",
    sourceSnapshotSha256: hash("legacy-source-snapshot"),
    nodeId,
    keyId: "legacy-worker-key-0001",
    files: [],
    aclReceipts: [],
    serviceDefinition,
    capturedAt: iso(startedMs - 120_000),
  };
  writeJson(join(captureDirectory, "rollback", "backup-receipt.json"), {
    payload: backupPayload,
    receiptSha256: hash(stableJson(backupPayload)),
  });

  const legacyHeartbeatServerTime = startedMs + 1_000_000;
  writeJson(join(captureDirectory, "rollback", "rollback.json"), {
    schema: "hch.worker-canary-rollback-capture/v1",
    validatedAtUtc: iso(startedMs + 950_250),
    receiptId: "60000000-0000-4000-8000-000000000001",
    serverTime: iso(startedMs + 950_000),
    targetVersion: "3.1.0",
    v4ServiceDisabled: true,
    legacyServiceStartMode: "AutomaticDelayed",
    legacyBackupReceiptRelativePath: "rollback/backup-receipt.json",
    restoredServiceDefinition: serviceDefinition,
    legacyHeartbeat: {
      workerVersion: "3.1.0",
      requestId: "50000000-0000-4000-8000-000000000001",
      nodeId,
      heartbeatAt: iso(legacyHeartbeatServerTime - 1_000),
      nextHeartbeatSeconds: 60,
      capacity: {
        configuredCapacity: 4,
        requestedCapacity: 0,
        grantedCapacity: 0,
        activeAssignments: 0,
        availableSlots: 0,
        capacityClass: "drain",
        reason: "rollback-validation",
        grantedUntil: null,
      },
      serverTime: iso(legacyHeartbeatServerTime),
    },
  });

  return { captureDirectory, msiPath };
}

function pausedProbe(capture, observedAtUtc, msiSha256) {
  return {
    schema: "hch.worker-windows-state-capture/v1",
    capture,
    workerVersion: version,
    sourceCommit,
    msiSha256,
    serviceState: "Running",
    operationalState: "Paused",
    acceptingClaims: false,
    maxConcurrentJobs: 0,
    grantedCapacity: 0,
    activeAssignments: 0,
    observedAtUtc,
  };
}

function heartbeatResponse(index, serverTime) {
  const active = index >= 2 && index <= 7 ? 1 : 0;
  return {
    requestId: `10000000-0000-4000-8000-${String(index + 1).padStart(12, "0")}`,
    nodeId,
    heartbeatAt: iso(serverTime - 1_000),
    nextHeartbeatSeconds: 60,
    capacity: {
      configuredCapacity: 4,
      requestedCapacity: 1,
      grantedCapacity: 1,
      activeAssignments: active,
      availableSlots: 1 - active,
      capacityClass: "canary",
      reason: "canary-capacity",
      grantedUntil: iso(serverTime + 300_000),
    },
    serverTime: iso(serverTime),
  };
}

function progressCapture(sequence, observedPercent, contentBytes, observedAtMs) {
  const serverTime = observedAtMs + 1_000;
  return {
    schema: "hch.worker-canary-assignment-heartbeat-capture/v1",
    validatedAtUtc: iso(observedAtMs),
    observedPercent,
    requestBodySha256: hash(`assignment-progress-request-${sequence}`),
    requestProgress: {
      phase: "responding",
      attempt: 1,
      sequence,
      contentBytes,
    },
    response: {
      assignmentId: completedAssignment,
      generationPlanHash: completedPlanHash,
      leaseExpiresAt: iso(serverTime + 300_000),
      liveness: {
        state: "responding",
        lastProgressAt: iso(observedAtMs),
        staleAfterSeconds: 120,
      },
      workSizing: {
        currentTier: "compact",
        currentRank: 1,
        reason: "within-window",
      },
      serverTime: iso(serverTime),
    },
  };
}

function runExporter(captureDirectory, evidencePath, msiPath) {
  return spawnSync("pwsh", [
    "-NoLogo",
    "-NoProfile",
    "-File",
    exporter,
    "-CaptureDirectory",
    captureDirectory,
    "-EvidencePath",
    evidencePath,
    "-Version",
    version,
    "-SourceCommit",
    sourceCommit,
    "-MsiPath",
    msiPath,
  ], { encoding: "utf8", timeout: 120_000 });
}

function heartbeatReceiptSha256(sample, kind) {
  const capacity = sample.capacity;
  return receiptHash(kind, [
    ...(kind === "legacy-node-heartbeat" ? [`workerVersion=${sample.workerVersion}`] : []),
    `requestId=${sample.requestId}`,
    `nodeId=${sample.nodeId}`,
    `heartbeatAtUnixMs=${timeValue(sample.heartbeatAt)}`,
    `nextHeartbeatSeconds=${sample.nextHeartbeatSeconds}`,
    `capacity.configuredCapacity=${capacity.configuredCapacity}`,
    `capacity.requestedCapacity=${capacity.requestedCapacity}`,
    `capacity.grantedCapacity=${capacity.grantedCapacity}`,
    `capacity.activeAssignments=${capacity.activeAssignments}`,
    `capacity.availableSlots=${capacity.availableSlots}`,
    `capacity.capacityClass=${capacity.capacityClass}`,
    `capacity.reason=${capacity.reason}`,
    `capacity.grantedUntilUnixMs=${capacity.grantedUntil === null ? "~" : timeValue(capacity.grantedUntil)}`,
    `serverTimeUnixMs=${timeValue(sample.serverTime)}`,
  ]);
}

function progressReceiptSha256(sample) {
  const progress = sample.requestProgress;
  const response = sample.response;
  return receiptHash("assignment-heartbeat", [
    `assignmentId=${sample.assignmentId}`,
    `observedPercent=${sample.observedPercent}`,
    `observedAtUnixMs=${timeValue(sample.observedAtUtc)}`,
    `requestBodySha256=${sample.requestBodySha256}`,
    `requestProgress.phase=${progress.phase}`,
    `requestProgress.attempt=${progress.attempt}`,
    `requestProgress.sequence=${progress.sequence}`,
    `requestProgress.contentBytes=${progress.contentBytes}`,
    `response.assignmentId=${response.assignmentId}`,
    `response.generationPlanHash=${response.generationPlanHash}`,
    `response.leaseExpiresAtUnixMs=${timeValue(response.leaseExpiresAt)}`,
    `response.liveness.state=${response.liveness.state}`,
    `response.liveness.lastProgressAtUnixMs=${timeValue(response.liveness.lastProgressAt)}`,
    `response.liveness.staleAfterSeconds=${response.liveness.staleAfterSeconds}`,
    `response.workSizing.currentTier=${response.workSizing.currentTier}`,
    `response.workSizing.currentRank=${response.workSizing.currentRank}`,
    `response.workSizing.reason=${response.workSizing.reason}`,
    `response.serverTimeUnixMs=${timeValue(response.serverTime)}`,
  ]);
}

function completionReceiptSha256(sample) {
  const journal = sample.journal;
  return receiptHash("complete", [
    `assignmentId=${sample.assignmentId}`,
    `generationPlanHash=${sample.generationPlanHash}`,
    `commitAccepted=${sample.commitAccepted}`,
    `status=${sample.status}`,
    `automaticApproval=${sample.automaticApproval}`,
    `automaticPublication=${sample.automaticPublication}`,
    `replayed=${sample.replayed}`,
    `serverTimeUnixMs=${timeValue(sample.serverTime)}`,
    `journal.schemaVersion=${journal.schemaVersion}`,
    `journal.assignmentId=${journal.assignmentId}`,
    `journal.generationPlanHash=${journal.generationPlanHash}`,
    `journal.phase=${journal.phase}`,
    `journal.requestId=${journal.requestId}`,
    `journal.requestBodySha256=${journal.requestBodySha256}`,
    `journal.draftSha256=${journal.draftSha256}`,
    `journal.lastErrorCode=${journal.lastErrorCode === null ? "~" : journal.lastErrorCode}`,
    `journal.updatedAtUnixMs=${timeValue(journal.updatedAtUtc)}`,
  ]);
}

function failureReceiptSha256(sample) {
  const journal = sample.journal;
  return receiptHash("fail", [
    `assignmentId=${sample.assignmentId}`,
    `generationPlanHash=${sample.generationPlanHash}`,
    `status=${sample.status}`,
    `replayed=${sample.replayed}`,
    `serverTimeUnixMs=${timeValue(sample.serverTime)}`,
    `requestErrorCode=${sample.requestErrorCode}`,
    `journal.schemaVersion=${journal.schemaVersion}`,
    `journal.assignmentId=${journal.assignmentId}`,
    `journal.generationPlanHash=${journal.generationPlanHash}`,
    `journal.phase=${journal.phase}`,
    `journal.requestId=${journal.requestId}`,
    `journal.requestBodySha256=${journal.requestBodySha256}`,
    `journal.draftSha256=${journal.draftSha256 === null ? "~" : journal.draftSha256}`,
    `journal.lastErrorCode=${journal.lastErrorCode}`,
    `journal.updatedAtUnixMs=${timeValue(journal.updatedAtUtc)}`,
  ]);
}

function rollbackReceiptSha256(sample) {
  return receiptHash("rollback", [
    `receiptId=${sample.receiptId}`,
    `serverTimeUnixMs=${timeValue(sample.serverTime)}`,
    `targetVersion=${sample.targetVersion}`,
    `v4ServiceDisabled=${sample.v4ServiceDisabled}`,
    `legacyServiceStartMode=${sample.legacyServiceStartMode}`,
    `backupSha256=${sample.backupSha256}`,
    `previousServiceDefinitionSha256=${sample.previousServiceDefinitionSha256}`,
    `restoredServiceDefinitionSha256=${sample.restoredServiceDefinitionSha256}`,
    `legacyHeartbeatReceiptSha256=${sample.legacyHeartbeat.receiptSha256}`,
  ]);
}

function receiptHash(kind, fields) {
  return hash(["schema=hch.worker-canary-receipt/v1", `kind=${kind}`, ...fields, ""].join("\n"));
}

function stableJson(value) {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(stableJson).join(",")}]`;
  return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${stableJson(value[key])}`).join(",")}}`;
}

function writeJson(path, value) {
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, `${JSON.stringify(value)}\n`, "utf8");
}

function hash(value) {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

function hashBytes(value) {
  return createHash("sha256").update(value).digest("hex");
}

function timeValue(value) {
  return String(Date.parse(value));
}

function iso(milliseconds) {
  return new Date(milliseconds).toISOString();
}
