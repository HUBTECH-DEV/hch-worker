import assert from "node:assert/strict";
import { createHash, randomUUID } from "node:crypto";
import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

const testDirectory = dirname(fileURLToPath(import.meta.url));
const repositoryRoot = resolve(testDirectory, "../../../..");
const validator = join(repositoryRoot, "scripts", "windows", "Test-HchWorkerCanaryEvidence.ps1");
const signer = join(repositoryRoot, "scripts", "windows", "Sign-HchWorkerCanaryEvidence.ps1");
const sourceCommit = "a".repeat(40);
const version = "4.0.0";

test("Windows promotion requires pinned CMS attestation and derived v2 canary samples", (context) => {
  if (process.platform !== "win32") return context.skip("Windows certificate store is required");
  const probe = spawnSync("pwsh", ["-NoLogo", "-NoProfile", "-Command", "Get-Command New-SelfSignedCertificate | Out-Null"], {
    encoding: "utf8",
  });
  if (probe.error || probe.status !== 0) return context.skip("PowerShell certificate cmdlets are unavailable");
  const directory = mkdtempSync(join(tmpdir(), "hch-worker-canary-gates-"));
  const certificate = createAttesterCertificate();
  context.after(() => {
    removeAttesterCertificate(certificate.thumbprint);
    rmSync(directory, { recursive: true, force: true });
  });

  const msiPath = join(directory, "HCH-Worker-4.0.0-win-x64.msi");
  const msiBytes = Buffer.from("synthetic signed-candidate bytes\n", "utf8");
  writeFileSync(msiPath, msiBytes);
  const msiSha256 = createHash("sha256").update(msiBytes).digest("hex");
  const valid = createValidEvidence(msiSha256);

  const passed = runSignedValidator(directory, msiPath, valid, certificate);
  assert.equal(passed.status, 0, passed.stderr || passed.stdout);
  assert.match(passed.stdout, /CMS attester/);
  assert.match(passed.stdout, /10 heartbeats/);

  const selfDeclared = writeEvidence(directory, valid);
  const emptySignature = join(directory, `unsigned-${randomUUID()}.p7s`);
  writeFileSync(emptySignature, Buffer.alloc(0));
  assertRejected(
    runValidator(msiPath, selfDeclared, emptySignature, certificate),
    /must both be non-empty/,
    "Unsigned self-declared JSON was accepted",
  );

  const signedThenTampered = writeAndSign(directory, valid, certificate);
  const tampered = structuredClone(valid);
  tampered.status = "passed ";
  writeFileSync(signedThenTampered.evidencePath, JSON.stringify(tampered), "utf8");
  assertRejected(
    runValidator(msiPath, signedThenTampered.evidencePath, signedThenTampered.signaturePath, certificate),
    /does not authenticate the exact canary evidence bytes/,
    "Tampered evidence bytes were accepted",
  );

  const v1 = structuredClone(valid);
  v1.schema = "hch.worker-windows-canary/v1";
  const v1Paths = writeEvidence(directory, v1);
  assertRejected(
    runSigner(v1Paths, join(directory, `v1-${randomUUID()}.p7s`), certificate),
    /Only passed, sanitized hch.worker-windows-canary\/v2 evidence may be signed/,
    "The controlled signer accepted legacy aggregate evidence",
  );

  const duplicateHeartbeat = structuredClone(valid);
  duplicateHeartbeat.heartbeatSamples[5].requestId = duplicateHeartbeat.heartbeatSamples[4].requestId;
  assertSignedEvidenceRejected(directory, msiPath, duplicateHeartbeat, certificate, /repeats a value that must be unique/);

  const impossibleProtocolId = structuredClone(valid);
  impossibleProtocolId.heartbeatSamples[0].requestId = "heartbeat-request-not-a-uuid";
  impossibleProtocolId.heartbeatSamples[0].receiptSha256 = heartbeatReceiptSha256(
    impossibleProtocolId.heartbeatSamples[0],
    "node-heartbeat",
  );
  assertSignedEvidenceRejected(
    directory,
    msiPath,
    impossibleProtocolId,
    certificate,
    /must be a non-empty canonical D-format UUID/,
  );

  const unknownRootProperty = structuredClone(valid);
  unknownRootProperty.operatorNote = "not part of the evidence contract";
  assertSignedEvidenceRejected(
    directory,
    msiPath,
    unknownRootProperty,
    certificate,
    /must contain exactly/,
  );

  const unknownGate = structuredClone(valid);
  unknownGate.gates.unverifiedClaim = true;
  assertSignedEvidenceRejected(directory, msiPath, unknownGate, certificate, /must contain exactly/);

  const dishonestAggregate = structuredClone(valid);
  dishonestAggregate.heartbeats = { count: 999, maximumGapSeconds: 1, stale: false };
  dishonestAggregate.heartbeatSamples.splice(5, 1);
  assertSignedEvidenceRejected(
    directory,
    msiPath,
    dishonestAggregate,
    certificate,
    /forbids legacy self-declared aggregate: heartbeats/,
  );

  const tooFewHeartbeatSamples = structuredClone(valid);
  tooFewHeartbeatSamples.heartbeatSamples.splice(5, 1);
  assertSignedEvidenceRejected(
    directory,
    msiPath,
    tooFewHeartbeatSamples,
    certificate,
    /at least 10 unique heartbeat samples/,
  );

  const stalledProgress = structuredClone(valid);
  stalledProgress.progressSamples[1].observedPercent = stalledProgress.progressSamples[0].observedPercent;
  assertSignedEvidenceRejected(
    directory,
    msiPath,
    stalledProgress,
    certificate,
    /strictly increasing sequence, content bytes, percent and serverTime/,
  );

  const mismatchedProgressPlan = structuredClone(valid);
  mismatchedProgressPlan.progressSamples[1].response.generationPlanHash = hash("another-generation-plan");
  mismatchedProgressPlan.progressSamples[1].receiptSha256 = progressReceiptSha256(
    mismatchedProgressPlan.progressSamples[1],
  );
  assertSignedEvidenceRejected(
    directory,
    msiPath,
    mismatchedProgressPlan,
    certificate,
    /must bind one immutable generationPlanHash/,
  );

  const tamperedReceipt = structuredClone(valid);
  tamperedReceipt.heartbeatSamples[0].capacity.reason = "tampered-receipt";
  assertSignedEvidenceRejected(
    directory,
    msiPath,
    tamperedReceipt,
    certificate,
    /receipt digest does not match its canonical sanitized fields/,
  );

  const randomReceiptHash = structuredClone(valid);
  randomReceiptHash.progressSamples[0].receiptSha256 = "f".repeat(64);
  assertSignedEvidenceRejected(
    directory,
    msiPath,
    randomReceiptHash,
    certificate,
    /receipt digest does not match its canonical sanitized fields/,
  );

  const automaticPublication = structuredClone(valid);
  automaticPublication.completions[0].automaticPublication = true;
  automaticPublication.completions[0].receiptSha256 = completionReceiptSha256(automaticPublication.completions[0]);
  assertSignedEvidenceRejected(
    directory,
    msiPath,
    automaticPublication,
    certificate,
    /completion sample is invalid or unreconciled/,
  );

  const unresolvedCompletion = structuredClone(valid);
  unresolvedCompletion.completions[0].journal.phase = "commitUnknown";
  unresolvedCompletion.completions[0].receiptSha256 = completionReceiptSha256(unresolvedCompletion.completions[0]);
  assertSignedEvidenceRejected(
    directory,
    msiPath,
    unresolvedCompletion,
    certificate,
    /completion journal is not durably reconciled/,
  );

  const failureJournalMismatch = structuredClone(valid);
  failureJournalMismatch.failures[0].journal.lastErrorCode = "different-safe-error";
  failureJournalMismatch.failures[0].receiptSha256 = failureReceiptSha256(failureJournalMismatch.failures[0]);
  assertSignedEvidenceRejected(
    directory,
    msiPath,
    failureJournalMismatch,
    certificate,
    /failure journal is not durably reconciled/,
  );

  const sameOutcomeAssignment = structuredClone(valid);
  sameOutcomeAssignment.failures[0].assignmentId = sameOutcomeAssignment.completions[0].assignmentId;
  assertSignedEvidenceRejected(
    directory,
    msiPath,
    sameOutcomeAssignment,
    certificate,
    /completion and failure must use distinct assignments/,
  );

  const badRollbackHash = structuredClone(valid);
  badRollbackHash.rollbackReceipt.restoredServiceDefinitionSha256 = hash("different-service-definition");
  assertSignedEvidenceRejected(
    directory,
    msiPath,
    badRollbackHash,
    certificate,
    /did not restore the exact legacy service definition hash/,
  );

  const heartbeatBeforeRollback = structuredClone(valid);
  heartbeatBeforeRollback.rollbackReceipt.legacyHeartbeat.serverTime = iso(
    Date.parse(heartbeatBeforeRollback.rollbackReceipt.serverTime) - 1,
  );
  heartbeatBeforeRollback.rollbackReceipt.legacyHeartbeat.heartbeatAt = iso(
    Date.parse(heartbeatBeforeRollback.rollbackReceipt.legacyHeartbeat.serverTime) - 1_000,
  );
  heartbeatBeforeRollback.rollbackReceipt.legacyHeartbeat.receiptSha256 = heartbeatReceiptSha256(
    heartbeatBeforeRollback.rollbackReceipt.legacyHeartbeat,
    "legacy-node-heartbeat",
  );
  heartbeatBeforeRollback.rollbackReceipt.receiptSha256 = rollbackReceiptSha256(
    heartbeatBeforeRollback.rollbackReceipt,
  );
  assertSignedEvidenceRejected(
    directory,
    msiPath,
    heartbeatBeforeRollback,
    certificate,
    /does not contain an accepted legacy heartbeat/,
  );

  const wrongPins = writeAndSign(directory, valid, certificate);
  const pinMismatch = runValidator(msiPath, wrongPins.evidencePath, wrongPins.signaturePath, {
    thumbprint: "b".repeat(40),
    sha256: certificate.sha256,
  });
  assertRejected(pinMismatch, /does not match both protected certificate pins/, "Wrong attester pin was accepted");

  const oldEvidence = createValidEvidence(msiSha256, new Date(Date.now() - (25 * 60 * 60 * 1000)));
  const oldEvidencePath = writeEvidence(directory, oldEvidence);
  assertRejected(
    runSigner(oldEvidencePath, join(directory, `late-${randomUUID()}.p7s`), certificate),
    /after canary completion and within 24 hours/,
    "Controlled signing accepted evidence outside the 24-hour window",
  );

  const futureSignatureEvidence = writeEvidence(directory, valid);
  const futureSignature = join(directory, `future-${randomUUID()}.p7s`);
  signEvidenceAt(
    directory,
    futureSignatureEvidence,
    futureSignature,
    certificate,
    new Date(Date.now() + (10 * 60 * 1000)).toISOString(),
  );
  assertRejected(
    runValidator(msiPath, futureSignatureEvidence, futureSignature, certificate),
    /beyond the permitted five-minute UTC clock skew/,
    "Future CMS signingTime was accepted",
  );
});

function createValidEvidence(msiSha256, completed = new Date(Date.now() - 30_000)) {
  const completedMs = completed.getTime();
  const startedMs = completedMs - (18 * 60 * 1000);
  const nodeId = "windows-canary-node-0001";
  const completedAssignment = "11111111-1111-4111-8111-111111111111";
  const failedAssignment = "22222222-2222-4222-8222-222222222222";
  const completionGenerationPlanHash = hash("completion-generation-plan");
  const failureGenerationPlanHash = hash("failure-generation-plan");
  const heartbeatSamples = Array.from({ length: 10 }, (_, index) => {
    const serverTime = iso(startedMs + 1_000 + (index * 107_000));
    const sample = {
      requestId: `10000000-0000-4000-8000-${String(index + 1).padStart(12, "0")}`,
      nodeId,
      heartbeatAt: iso(Date.parse(serverTime) - 1_000),
      nextHeartbeatSeconds: 60,
      capacity: {
        configuredCapacity: 4,
        requestedCapacity: 1,
        grantedCapacity: 1,
        activeAssignments: index >= 2 && index <= 7 ? 1 : 0,
        availableSlots: index >= 2 && index <= 7 ? 0 : 1,
        capacityClass: "canary",
        reason: "canary-capacity",
        grantedUntil: iso(Date.parse(serverTime) + 300_000),
      },
      serverTime,
    };
    sample.receiptSha256 = heartbeatReceiptSha256(sample, "node-heartbeat");
    return sample;
  });

  const progressSamples = [
    createProgressReceipt({
      assignmentId: completedAssignment,
      generationPlanHash: completionGenerationPlanHash,
      observedPercent: 10,
      observedAtUtc: iso(startedMs + 219_000),
      phase: "responding",
      attempt: 1,
      sequence: 1,
      contentBytes: 1024,
      serverTime: iso(startedMs + 220_000),
    }),
    createProgressReceipt({
      assignmentId: completedAssignment,
      generationPlanHash: completionGenerationPlanHash,
      observedPercent: 80,
      observedAtUtc: iso(startedMs + 319_000),
      phase: "responding",
      attempt: 1,
      sequence: 2,
      contentBytes: 4096,
      serverTime: iso(startedMs + 320_000),
    }),
  ];

  const completion = {
    assignmentId: completedAssignment,
    generationPlanHash: completionGenerationPlanHash,
    commitAccepted: true,
    status: "pending-review",
    automaticApproval: false,
    automaticPublication: false,
    replayed: false,
    serverTime: iso(startedMs + 420_000),
    journal: {
      schemaVersion: 1,
      assignmentId: completedAssignment,
      generationPlanHash: completionGenerationPlanHash,
      phase: "completed",
      requestId: "30000000-0000-4000-8000-000000000001",
      requestBodySha256: hash("completion-request-body"),
      draftSha256: hash("completion-draft"),
      lastErrorCode: null,
      updatedAtUtc: iso(startedMs + 421_000),
    },
  };
  completion.receiptSha256 = completionReceiptSha256(completion);

  const failure = {
    assignmentId: failedAssignment,
    generationPlanHash: failureGenerationPlanHash,
    status: "failed-attempt",
    replayed: false,
    serverTime: iso(startedMs + 520_000),
    requestErrorCode: "canary-controlled-generation-failure",
    journal: {
      schemaVersion: 1,
      assignmentId: failedAssignment,
      generationPlanHash: failureGenerationPlanHash,
      phase: "failed",
      requestId: "40000000-0000-4000-8000-000000000001",
      requestBodySha256: hash("failure-request-body"),
      draftSha256: null,
      lastErrorCode: "canary-controlled-generation-failure",
      updatedAtUtc: iso(startedMs + 521_000),
    },
  };
  failure.receiptSha256 = failureReceiptSha256(failure);

  const legacyHeartbeat = {
    workerVersion: "3.1.0",
    requestId: "50000000-0000-4000-8000-000000000001",
    nodeId,
    heartbeatAt: iso(completedMs - 1_000),
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
    serverTime: iso(completedMs),
  };
  legacyHeartbeat.receiptSha256 = heartbeatReceiptSha256(legacyHeartbeat, "legacy-node-heartbeat");

  const rollbackReceipt = {
    receiptId: "60000000-0000-4000-8000-000000000001",
    serverTime: iso(startedMs + 1_000_000),
    targetVersion: "3.1.0",
    v4ServiceDisabled: true,
    legacyServiceStartMode: "AutomaticDelayed",
    backupSha256: hash("rollback-backup"),
    previousServiceDefinitionSha256: hash("legacy-service-definition"),
    restoredServiceDefinitionSha256: hash("legacy-service-definition"),
    legacyHeartbeat,
  };
  rollbackReceipt.receiptSha256 = rollbackReceiptSha256(rollbackReceipt);

  return {
    schema: "hch.worker-windows-canary/v2",
    status: "passed",
    sanitized: true,
    version,
    sourceCommit,
    msiSha256,
    startedAtUtc: iso(startedMs),
    completedAtUtc: iso(completedMs),
    gates: {
      installedPausedDrain: true,
      legacyServiceStoppedDisabled: true,
      enrollment: true,
      bootstrap: true,
      claim: true,
      restartPausedDrain: true,
    },
    heartbeatSamples,
    progressSamples,
    completions: [completion],
    failures: [failure],
    rollbackReceipt,
  };
}

function createProgressReceipt({
  assignmentId,
  generationPlanHash,
  observedPercent,
  observedAtUtc,
  phase,
  attempt,
  sequence,
  contentBytes,
  serverTime,
}) {
  const sample = {
    assignmentId,
    observedPercent,
    observedAtUtc,
    requestBodySha256: hash(`assignment-heartbeat-request-${assignmentId}-${sequence}`),
    requestProgress: { phase, attempt, sequence, contentBytes },
    response: {
      assignmentId,
      generationPlanHash,
      leaseExpiresAt: iso(Date.parse(serverTime) + 300_000),
      liveness: {
        state: phase,
        lastProgressAt: observedAtUtc,
        staleAfterSeconds: 120,
      },
      workSizing: {
        currentTier: "compact",
        currentRank: 1,
        reason: "within-window",
      },
      serverTime,
    },
  };
  sample.receiptSha256 = progressReceiptSha256(sample);
  return sample;
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

function timeValue(value) {
  return String(Date.parse(value));
}

function createAttesterCertificate() {
  const subject = `CN=HCH Worker Canary Test ${randomUUID()}`;
  const command = [
    "$ErrorActionPreference = 'Stop'",
    `$certificate = New-SelfSignedCertificate -Type CodeSigningCert -Subject '${subject}' -CertStoreLocation 'Cert:\\CurrentUser\\My' -KeyExportPolicy NonExportable -NotAfter (Get-Date).AddDays(2)`,
    "$sha256 = [Convert]::ToHexString($certificate.GetCertHash([Security.Cryptography.HashAlgorithmName]::SHA256))",
    "[pscustomobject]@{ thumbprint = $certificate.Thumbprint; sha256 = $sha256 } | ConvertTo-Json -Compress",
  ].join("\n");
  const result = spawnSync("pwsh", ["-NoLogo", "-NoProfile", "-Command", command], { encoding: "utf8" });
  assert.equal(result.status, 0, result.stderr || result.stdout);
  return JSON.parse(result.stdout.trim().split(/\r?\n/).at(-1));
}

function removeAttesterCertificate(thumbprint) {
  const command = [
    "$ErrorActionPreference = 'Stop'",
    `$path = 'Cert:\\CurrentUser\\My\\${thumbprint}'`,
    "$certificate = Get-Item -LiteralPath $path",
    "if ($certificate.Subject -notlike 'CN=HCH Worker Canary Test *') { throw 'Refusing to remove non-test certificate.' }",
    "Remove-Item -LiteralPath $path -Force",
  ].join("\n");
  const result = spawnSync("pwsh", [
    "-NoLogo",
    "-NoProfile",
    "-Command",
    command,
  ], { encoding: "utf8" });
  assert.equal(result.status, 0, result.stderr || result.stdout);
}

function assertSignedEvidenceRejected(directory, msiPath, evidence, certificate, pattern) {
  const result = runSignedValidator(directory, msiPath, evidence, certificate);
  assertRejected(result, pattern, "Invalid signed canary evidence was accepted");
}

function assertRejected(result, pattern, message) {
  assert.notEqual(result.status, 0, message);
  assert.match(`${result.stdout}\n${result.stderr}`, pattern);
}

function runSignedValidator(directory, msiPath, evidence, certificate) {
  const paths = writeAndSign(directory, evidence, certificate);
  return runValidator(msiPath, paths.evidencePath, paths.signaturePath, certificate);
}

function writeAndSign(directory, evidence, certificate) {
  const evidencePath = writeEvidence(directory, evidence);
  const signaturePath = join(directory, `canary-${randomUUID()}.p7s`);
  const signing = runSigner(evidencePath, signaturePath, certificate);
  assert.equal(signing.status, 0, signing.stderr || signing.stdout);
  return { evidencePath, signaturePath };
}

function writeEvidence(directory, evidence) {
  const evidencePath = join(directory, `canary-${randomUUID()}.json`);
  writeFileSync(evidencePath, JSON.stringify(evidence), "utf8");
  return evidencePath;
}

function runSigner(evidencePath, signaturePath, certificate) {
  return spawnSync("pwsh", [
    "-NoLogo",
    "-NoProfile",
    "-File",
    signer,
    "-EvidencePath",
    evidencePath,
    "-EvidenceSignaturePath",
    signaturePath,
    "-AttesterThumbprint",
    certificate.thumbprint,
    "-ExpectedAttesterCertificateSha256",
    certificate.sha256,
  ], { encoding: "utf8", timeout: 120_000 });
}

function signEvidenceAt(directory, evidencePath, signaturePath, certificate, signingTimeUtc) {
  const scriptPath = join(directory, `sign-at-${randomUUID()}.ps1`);
  writeFileSync(scriptPath, [
    "param([string]$EvidencePath, [string]$SignaturePath, [string]$Thumbprint, [string]$SigningTimeUtc)",
    "$ErrorActionPreference = 'Stop'",
    "$certificate = Get-Item -LiteralPath (\"Cert:\\CurrentUser\\My\\$Thumbprint\")",
    "$contentInfo = [Security.Cryptography.Pkcs.ContentInfo]::new([IO.File]::ReadAllBytes($EvidencePath))",
    "$signedCms = [Security.Cryptography.Pkcs.SignedCms]::new($contentInfo, $true)",
    "$cmsSigner = [Security.Cryptography.Pkcs.CmsSigner]::new([Security.Cryptography.Pkcs.SubjectIdentifierType]::IssuerAndSerialNumber, $certificate)",
    "$cmsSigner.IncludeOption = [Security.Cryptography.X509Certificates.X509IncludeOption]::EndCertOnly",
    "$cmsSigner.DigestAlgorithm = [Security.Cryptography.Oid]::new('2.16.840.1.101.3.4.2.1')",
    "$timestamp = [DateTimeOffset]::Parse($SigningTimeUtc, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::RoundtripKind).UtcDateTime",
    "$cmsSigner.SignedAttributes.Add([Security.Cryptography.Pkcs.Pkcs9SigningTime]::new($timestamp))",
    "$signedCms.ComputeSignature($cmsSigner, $true)",
    "[IO.File]::WriteAllBytes($SignaturePath, $signedCms.Encode())",
  ].join("\n"), "utf8");
  const result = spawnSync("pwsh", [
    "-NoLogo",
    "-NoProfile",
    "-File",
    scriptPath,
    "-EvidencePath",
    evidencePath,
    "-SignaturePath",
    signaturePath,
    "-Thumbprint",
    certificate.thumbprint,
    "-SigningTimeUtc",
    signingTimeUtc,
  ], { encoding: "utf8", timeout: 120_000 });
  assert.equal(result.status, 0, result.stderr || result.stdout);
}

function runValidator(msiPath, evidencePath, signaturePath, certificate) {
  return spawnSync("pwsh", [
    "-NoLogo",
    "-NoProfile",
    "-File",
    validator,
    "-EvidencePath",
    evidencePath,
    "-EvidenceSignaturePath",
    signaturePath,
    "-ExpectedAttesterThumbprint",
    certificate.thumbprint,
    "-ExpectedAttesterCertificateSha256",
    certificate.sha256,
    "-Version",
    version,
    "-SourceCommit",
    sourceCommit,
    "-MsiPath",
    msiPath,
  ], { encoding: "utf8", timeout: 120_000 });
}

function hash(value) {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

function iso(milliseconds) {
  return new Date(milliseconds).toISOString();
}
