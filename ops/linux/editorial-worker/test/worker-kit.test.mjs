import assert from "node:assert/strict";
import test from "node:test";
import {
  mkdtemp,
  readFile,
  readdir,
  rm,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  canonicalizeJson,
  signManifestEnvelope,
  signReleaseKeyDelegation,
  verifyWorkerRequestSignature,
  workerPublicKeyFingerprint,
} from "../crypto.mjs";
import { sha256Hex } from "../crypto.mjs";
import { validateWorkerConfig } from "../lib/config.mjs";
import {
  capacityPolicyHash,
  sampleCapacityPressure,
  validateCapacityPolicy,
} from "../lib/capacity.mjs";
import {
  configureLocalWorker,
  localWorkerStatus,
  setLocalParallelism,
  startLocalWorker,
  stopLocalWorker,
  validateLocalWorker,
} from "../lib/control.mjs";

test("CLI entrypoint resolves release symlinks before executing", async () => {
  const source = await readFile(new URL("../worker.mjs", import.meta.url), "utf8");
  assert.match(source, /realpathSync\(resolve\(process\.argv\[1\]\)\)/);
});

test("VPS timer uses the portable claim lifecycle", async () => {
  const source = await readFile(
    new URL("../../../../scripts/run-editorial-republication.sh", import.meta.url),
    "utf8",
  );
  assert.match(source, /HCH_EDITORIAL_WORKER_ENTRYPOINT\}\" run-one/);
  assert.doesNotMatch(source, /HCH_EDITORIAL_WORKER_ENTRYPOINT\}\" execute/);
});

test("VPS supervisor uses the installed pinned Node runtime", async () => {
  const source = await readFile(
    new URL("../../../systemd/hch-editorial-worker.service", import.meta.url),
    "utf8",
  );
  assert.match(source, /ExecStart=\/usr\/local\/libexec\/hch-node .*worker\.mjs supervise/);
  assert.doesNotMatch(source, /ExecStart=\/usr\/bin\/node/);
  assert.match(source, /^PrivateDevices=true$/m);
});

test("macOS installer retires conflicting legacy agents and preserves Ollama", async () => {
  const source = await readFile(
    new URL("../../../macos/editorial-worker/install-launch-agents.sh", import.meta.url),
    "utf8",
  );
  assert.match(source, /online\.hubtech\.hch\.editorial-worker\.cycle\.plist\.in/);
  for (const label of [
    "online.hubtech.hch.editorial-worker.bootstrap",
    "online.hubtech.hch.editorial-worker.heartbeat",
    "com.hubtech.hch-orchestrator-listener",
    "com.hubtech.hch-mac-worker",
    "com.hubtech.hch-worker-dashboard",
  ]) {
    assert.match(source, new RegExp(label.replaceAll(".", "\\.")));
  }
  assert.doesNotMatch(source, /legacy_label=.*com\.hubtech\.hch-orchestrator-ollama/);
});

test("macOS cycle is not deferred as a background launchd process", async () => {
  const source = await readFile(
    new URL(
      "../../../macos/editorial-worker/launchd/online.hubtech.hch.editorial-worker.cycle.plist.in",
      import.meta.url,
    ),
    "utf8",
  );
  assert.doesNotMatch(source, /<key>ProcessType<\/key>/);
});
import {
  bootstrapWorker,
  bootstrapWorkerLocked,
  resolveEnrollmentToken,
} from "../lib/bootstrap.mjs";
import { executeWorkerCycle } from "../lib/execute.mjs";
import { gpuActiveSecondsDelta, nodeHeartbeat } from "../lib/node-heartbeat.mjs";
import {
  createRuntimeProfileFromManifest,
  verifyRuntimeProfile,
} from "../lib/runtime-profile.mjs";
import {
  KIT_VERSION,
  assertWorkerRuntimeVersion,
  completeOperation,
  operationRequestId,
  updateMetrics,
} from "../lib/local-state.mjs";
import { parseDashboardMetrics } from "../../../worker-dashboard/lib/hch-worker-adapter.mjs";

test("bootstrap enrolls, verifies trust/artifacts/model, attests, and never executes work", async (t) => {
  const fixture = await createFixture(t);
  const result = await bootstrapWorker(fixture.config, {
    enroll: true,
    enrollmentToken: "administrative-test-value",
    fetchImpl: fixture.control.fetch,
  });
  assert.equal(result.state, "ready");
  assert.equal(result.workStarted, false);
  assert.equal(result.manifestHash, fixture.manifest.hash);
  assert.equal(fixture.control.paths.includes("/api/editorial/orchestrator/execute"), false);
  assert.equal(fixture.control.attestations.length, 1);

  const applied = await jsonFile(fixture.stateDirectory, "applied-manifest.json");
  const ready = await jsonFile(fixture.stateDirectory, "ready.json");
  const status = await jsonFile(fixture.stateDirectory, "status.json");
  const metrics = await jsonFile(fixture.stateDirectory, "metrics.json");
  const receiptRecord = await jsonFile(
    fixture.stateDirectory,
    `receipts/${fixture.manifest.hash}.json`,
  );
  const trustState = await jsonFile(fixture.stateDirectory, "trust-state.json");
  const capacity = await jsonFile(fixture.stateDirectory, "capacity.json");
  const engineConfig = await jsonFile(
    fixture.stateDirectory,
    "runtime/config/engine.json",
  );
  const expectedRuntimeProfile = await createRuntimeProfileFromManifest(
    fixture.manifest,
  );
  assert.equal(applied.manifestSequence, fixture.manifest.sequence);
  assert.equal(applied.workerRuntimeVersion, KIT_VERSION);
  assert.deepEqual(applied.runtimeProfile, expectedRuntimeProfile);
  assert.equal(applied.runtimeProfileHash, expectedRuntimeProfile.runtimeProfileHash);
  assert.equal(applied.provider, fixture.manifest.engine.provider);
  assert.equal(applied.engineAdapter, fixture.manifest.engine.adapter);
  assert.equal(
    applied.engineAdapterVersion,
    fixture.manifest.engine.adapterVersion,
  );
  assert.equal(ready.ready, true);
  assert.equal(ready.workerRuntimeVersion, KIT_VERSION);
  assert.equal(ready.runtimeProfileHash, expectedRuntimeProfile.runtimeProfileHash);
  assert.equal(status.state, "standby");
  assert.equal(status.kitVersion, KIT_VERSION);
  assert.equal(status.ready, true);
  assert.equal(status.connection.ed25519, true);
  assert.equal(status.transport.tlsStatus, "verified");
  assert.equal(status.transport.certificateStatus, "valid");
  assert.equal(status.trust.status, "verified");
  assert.equal(status.trust.rootKeyId, fixture.control.rootKeyId);
  assert.equal(status.trust.releaseKeyId, fixture.control.releaseKeyId);
  assert.equal(status.capacity.requestedCapacity, 2);
  assert.equal(status.capacity.grantedCapacity, 2);
  assert.equal(status.capacity.effectiveGrantedCapacity, 2);
  assert.equal(status.capacity.reason, "requested-capacity-granted");
  assert.equal(capacity.requestedCapacity, 2);
  assert.equal(capacity.grantedCapacity, 2);
  assert.equal(capacity.source, "attestation");
  assert.equal(capacity.capacityPolicyHash, await capacityPolicyHash(fixture.manifest.capacityPolicy));
  assert.equal(trustState.delegationSequence, 2);
  assert.equal(
    trustState.delegationHash,
    await sha256Hex(canonicalizeJson(fixture.delegation)),
  );
  assert.deepEqual(Object.keys(trustState).sort(), [
    "delegationHash",
    "delegationSequence",
    "manifestHash",
    "manifestSequence",
    "policyHash",
    "releaseKeyId",
    "rootFingerprint",
    "rootKeyId",
    "schema",
    "schemaVersion",
    "verifiedAt",
  ]);
  assert.equal(engineConfig.provider, fixture.manifest.engine.provider);
  assert.equal(engineConfig.adapter, fixture.manifest.engine.adapter);
  assert.equal(engineConfig.adapterVersion, fixture.manifest.engine.adapterVersion);
  assert.deepEqual(Object.keys(status).sort(), [
    "capacity",
    "code",
    "connection",
    "currentBatch",
    "kitVersion",
    "manifestHash",
    "manifestSequence",
    "nodeId",
    "observedAt",
    "platform",
    "ready",
    "readyUntil",
    "running",
    "schema",
    "schemaVersion",
    "standby",
    "state",
    "transport",
    "trust",
    "uptimeSeconds",
    "workerKeyId",
  ]);
  assert.deepEqual(Object.keys(status.transport).sort(), [
    "certificateExpiresAt",
    "certificateFingerprint",
    "certificateStatus",
    "errorCode",
    "tlsStatus",
  ]);
  assert.deepEqual(Object.keys(status.trust).sort(), [
    "errorCode",
    "lastVerifiedAt",
    "manifestHash",
    "manifestSequence",
    "policyHash",
    "releaseKeyId",
    "rootKeyId",
    "status",
  ]);
  assert.deepEqual(Object.keys(status.capacity).sort(), [
    "activeAssignments",
    "capacityClass",
    "effectiveGrantedCapacity",
    "grantExpired",
    "grantedCapacity",
    "grantedUntil",
    "pressure",
    "reason",
    "requestedCapacity",
  ]);
  assert.equal(metrics.updates.succeeded, 1);
  assert.equal(metrics.updates.failed, 0);
  assert.deepEqual(Object.keys(metrics.batches).sort(), ["completed", "failed", "total"]);
  assert.deepEqual(Object.keys(metrics.jobs).sort(), [
    "claimed",
    "completed",
    "discarded",
    "failed",
    "running",
  ]);
  assert.equal(metrics.resources.gpu.status, "unsupported");
  assert.equal(metrics.resources.gpu.utilizationPercent, null);
  assert.equal("devices" in metrics.resources.gpu, false);
  assert.equal(metrics.network.sourceRxBytes, null);
  assert.equal(metrics.network.sourceTxBytes, null);
  assert.deepEqual(Object.keys(metrics).sort(), [
    "batches",
    "currentBatch",
    "jobs",
    "network",
    "nodeId",
    "observedAt",
    "performance",
    "resources",
    "schema",
    "schemaVersion",
    "standby",
    "updates",
    "uptimeSeconds",
    "workerKeyId",
  ]);
  assert.deepEqual(Object.keys(metrics.network).sort(), [
    "receiveBytesPerSecond",
    "requestBytes",
    "responseBytes",
    "rxBytes",
    "sendBytesPerSecond",
    "sourceRxBytes",
    "sourceTxBytes",
    "txBytes",
  ]);
  assert.ok(metrics.network.requestBytes > 0);
  assert.ok(metrics.network.responseBytes > 0);

  const {
    localAuditHash,
    receiptHash,
    ...receiptWithoutHashes
  } = receiptRecord.updateReceipt;
  assert.equal(
    receiptHash,
    await sha256Hex(canonicalizeJson(receiptWithoutHashes)),
  );
  assert.equal(
    localAuditHash,
    await sha256Hex(canonicalizeJson(receiptRecord.journal)),
  );
  assert.deepEqual(
    receiptRecord.updateReceipt.artifactHashes,
    Object.fromEntries(
      fixture.manifest.artifacts.map((artifact) => [artifact.name, artifact.sha256]),
    ),
  );
  assert.equal(receiptRecord.updateReceipt.rollbackPerformed, false);
  assert.equal(
    fixture.control.attestations[0].updateReceipt.localAuditHash,
    localAuditHash,
  );
  assert.equal("engineVersion" in fixture.control.attestations[0], false);
  assert.equal(
    fixture.control.attestations[0].provider,
    fixture.manifest.engine.provider,
  );
  assert.equal(
    fixture.control.attestations[0].engineAdapter,
    fixture.manifest.engine.adapter,
  );
  assert.equal(
    fixture.control.attestations[0].engineAdapterVersion,
    fixture.manifest.engine.adapterVersion,
  );
  assert.equal(
    fixture.control.attestations[0].workerRuntimeVersion,
    KIT_VERSION,
  );
  assert.deepEqual(Object.keys(fixture.control.attestations[0]).sort(), [
    "adaptiveWorkPolicyHash",
    "challenge",
    "checks",
    "engineAdapter",
    "engineAdapterVersion",
    "manifestHash",
    "manifestSequence",
    "model",
    "modelDigest",
    "nodeId",
    "pipelineVersion",
    "policyHash",
    "promptConfigHash",
    "protocol",
    "provider",
    "releaseKeyId",
    "rootKeyId",
    "trustVerifiedAt",
    "updateReceipt",
    "workerKeyId",
    "workerRuntimeVersion",
  ]);

  for (const artifact of fixture.manifest.artifacts) {
    const installed = await readFile(
      join(fixture.stateDirectory, "runtime", "artifacts", artifact.name),
    );
    assert.equal(await sha256Hex(installed), artifact.sha256);
  }
  assert.doesNotMatch(JSON.stringify(status), /administrative-test-value|PRIVATE KEY/);
  assert.doesNotMatch(JSON.stringify(metrics), /administrative-test-value|PRIVATE KEY/);

  const challengeRequests = fixture.control.requests.filter(
    (request) => request.path === "/api/editorial/orchestrator/challenge",
  );
  assert.ok(challengeRequests.length >= 2);
  for (const request of challengeRequests) {
    assert.match(request.nonce, /^client-[0-9a-f-]+-[0-9a-f-]+$/);
    assert.equal(request.signatureValid, true);
  }
});

test("readiness renewal does not overwrite an active assignment lifecycle", async (t) => {
  const fixture = await createFixture(t);
  await bootstrapWorker(fixture.config, {
    enroll: true,
    enrollmentToken: "administrative-test-value",
    fetchImpl: fixture.control.fetch,
  });
  const batch = {
    batchId: "batch-active",
    assignmentIds: ["assignment-active"],
    jobs: 1,
    completedJobs: 0,
    startedAt: "2026-08-22T19:40:00.000Z",
  };
  const status = await jsonFile(fixture.stateDirectory, "status.json");
  await writeFile(join(fixture.stateDirectory, "status.json"), JSON.stringify({
    ...status,
    state: "processing",
    running: true,
    standby: false,
    currentBatch: batch,
    code: "assignment-processing",
  }));
  const metrics = await jsonFile(fixture.stateDirectory, "metrics.json");
  await writeFile(join(fixture.stateDirectory, "metrics.json"), JSON.stringify({
    ...metrics,
    jobs: { ...metrics.jobs, running: 1 },
    standby: { ...metrics.standby, active: false, since: null },
    currentBatch: batch,
  }));

  await bootstrapWorkerLocked(fixture.config, fixture.stateDirectory, {
    fetchImpl: fixture.control.fetch,
    preserveLifecycle: true,
  });

  const renewedStatus = await jsonFile(fixture.stateDirectory, "status.json");
  const renewedMetrics = await jsonFile(fixture.stateDirectory, "metrics.json");
  assert.equal(renewedStatus.state, "processing");
  assert.equal(renewedStatus.running, true);
  assert.equal(renewedStatus.standby, false);
  assert.deepEqual(renewedStatus.currentBatch, batch);
  assert.equal(renewedStatus.code, "assignment-processing");
  assert.equal(renewedStatus.ready, true);
  assert.equal(renewedMetrics.jobs.running, 1);
  assert.equal(renewedMetrics.standby.active, false);
  assert.deepEqual(renewedMetrics.currentBatch, batch);
});

test("anti-rollback rejects an older signed manifest before bootstrap or artifacts", async (t) => {
  const fixture = await createFixture(t);
  await bootstrapWorker(fixture.config, {
    enroll: true,
    enrollmentToken: "admin",
    fetchImpl: fixture.control.fetch,
  });
  const previousPathCount = fixture.control.paths.length;
  const rollback = await fixture.control.replaceManifest({
    sequence: fixture.manifest.sequence - 1,
    minimumAcceptedSequence: fixture.manifest.sequence - 1,
    previousManifestHash: null,
  });
  await assert.rejects(
    bootstrapWorker(fixture.config, { fetchImpl: fixture.control.fetch }),
    (error) => error?.code === "manifest-rollback-refused",
  );
  assert.equal(rollback.sequence, fixture.manifest.sequence - 1);
  const newPaths = fixture.control.paths.slice(previousPathCount);
  assert.deepEqual(newPaths, ["/api/editorial/orchestrator/manifest"]);
});

test("manifest requiring 3.1.0 rejects an older executable kit", async (t) => {
  const fixture = await createFixture(t);
  assert.equal(fixture.manifest.runtime.workerVersion, KIT_VERSION);
  assert.throws(
    () => assertWorkerRuntimeVersion(fixture.manifest, "3.0.0"),
    (error) => error?.code === "worker-runtime-version-incompatible",
  );
});

test("bootstrap rejects a signed manifest for another worker runtime before apply", async (t) => {
  const fixture = await createFixture(t);
  await fixture.control.replaceManifest({
    runtime: {
      ...fixture.manifest.runtime,
      workerVersion: "3.0.0",
    },
  });
  const before = fixture.control.paths.length;
  await assert.rejects(
    bootstrapWorker(fixture.config, { fetchImpl: fixture.control.fetch }),
    (error) => error?.code === "worker-runtime-version-incompatible",
  );
  assert.deepEqual(
    fixture.control.paths.slice(before),
    ["/api/editorial/orchestrator/manifest"],
  );
  assert.equal(fixture.control.attestations.length, 0);
});

test("a higher delegation is pinned before an incompatible runtime is rejected", async (t) => {
  const fixture = await createFixture(t);
  await bootstrapWorker(fixture.config, {
    enroll: true,
    enrollmentToken: "admin",
    fetchImpl: fixture.control.fetch,
  });
  const nextDelegation = await fixture.control.replaceDelegation({ sequence: 3 });
  await fixture.control.replaceManifest({
    sequence: fixture.manifest.sequence + 1,
    previousManifestHash: fixture.manifest.hash,
    runtime: {
      ...fixture.manifest.runtime,
      workerVersion: "3.0.0",
    },
  });
  await assert.rejects(
    bootstrapWorker(fixture.config, { fetchImpl: fixture.control.fetch }),
    (error) => error?.code === "worker-runtime-version-incompatible",
  );
  const invalidatedReady = await jsonFile(fixture.stateDirectory, "ready.json");
  assert.equal(invalidatedReady.ready, false);
  assert.equal(invalidatedReady.reason, "manifest-update-required");
  const pinnedTrust = await jsonFile(fixture.stateDirectory, "trust-state.json");
  assert.equal(pinnedTrust.delegationSequence, 3);
  assert.equal(
    pinnedTrust.delegationHash,
    await sha256Hex(canonicalizeJson(nextDelegation)),
  );
  await fixture.control.replaceDelegation({ sequence: 2 });
  const beforeReplay = fixture.control.paths.length;
  await assert.rejects(
    bootstrapWorker(fixture.config, { fetchImpl: fixture.control.fetch }),
    (error) => error?.code === "delegation-rollback-refused",
  );
  assert.deepEqual(
    fixture.control.paths.slice(beforeReplay),
    ["/api/editorial/orchestrator/manifest"],
  );
});

test("delegation anti-rollback rejects an older still-valid root delegation", async (t) => {
  const fixture = await createFixture(t);
  await bootstrapWorker(fixture.config, {
    enroll: true,
    enrollmentToken: "admin",
    fetchImpl: fixture.control.fetch,
  });
  await fixture.control.replaceDelegation({ sequence: 1 });
  const before = fixture.control.paths.length;
  await assert.rejects(
    bootstrapWorker(fixture.config, { fetchImpl: fixture.control.fetch }),
    (error) => error?.code === "delegation-rollback-refused",
  );
  assert.deepEqual(
    fixture.control.paths.slice(before),
    ["/api/editorial/orchestrator/manifest"],
  );
  const trustState = await jsonFile(fixture.stateDirectory, "trust-state.json");
  assert.equal(trustState.delegationSequence, 2);
});

test("delegation anti-rollback rejects equivocation at the same sequence", async (t) => {
  const fixture = await createFixture(t);
  await bootstrapWorker(fixture.config, {
    enroll: true,
    enrollmentToken: "admin",
    fetchImpl: fixture.control.fetch,
  });
  const originalTrust = await jsonFile(fixture.stateDirectory, "trust-state.json");
  await fixture.control.replaceDelegation({
    sequence: 2,
    created: Math.floor(Date.now() / 1_000) - 300,
  });
  await assert.rejects(
    bootstrapWorker(fixture.config, { fetchImpl: fixture.control.fetch }),
    (error) => error?.code === "delegation-equivocation-refused",
  );
  assert.deepEqual(
    await jsonFile(fixture.stateDirectory, "trust-state.json"),
    originalTrust,
  );
});

test("a higher verified delegation replaces both persisted anchors", async (t) => {
  const fixture = await createFixture(t);
  await bootstrapWorker(fixture.config, {
    enroll: true,
    enrollmentToken: "admin",
    fetchImpl: fixture.control.fetch,
  });
  const nextDelegation = await fixture.control.replaceDelegation({ sequence: 3 });
  await bootstrapWorker(fixture.config, { fetchImpl: fixture.control.fetch });
  const trustState = await jsonFile(fixture.stateDirectory, "trust-state.json");
  assert.equal(trustState.delegationSequence, 3);
  assert.equal(
    trustState.delegationHash,
    await sha256Hex(canonicalizeJson(nextDelegation)),
  );
});

test("a higher delegation is pinned before apply and rejects an old replay after failure", async (t) => {
  const fixture = await createFixture(t);
  await bootstrapWorker(fixture.config, {
    enroll: true,
    enrollmentToken: "admin",
    fetchImpl: fixture.control.fetch,
  });
  const nextDelegation = await fixture.control.replaceDelegation({ sequence: 3 });
  fixture.control.setCorruptArtifact("policy");
  await assert.rejects(
    bootstrapWorker(fixture.config, { fetchImpl: fixture.control.fetch }),
    (error) => error?.code === "artifact-hash-mismatch",
  );
  const pinnedTrust = await jsonFile(fixture.stateDirectory, "trust-state.json");
  assert.equal(pinnedTrust.delegationSequence, 3);
  assert.equal(
    pinnedTrust.delegationHash,
    await sha256Hex(canonicalizeJson(nextDelegation)),
  );
  fixture.control.setCorruptArtifact(null);
  await fixture.control.replaceDelegation({ sequence: 2 });
  const beforeReplay = fixture.control.paths.length;
  await assert.rejects(
    bootstrapWorker(fixture.config, { fetchImpl: fixture.control.fetch }),
    (error) => error?.code === "delegation-rollback-refused",
  );
  assert.deepEqual(
    fixture.control.paths.slice(beforeReplay),
    ["/api/editorial/orchestrator/manifest"],
  );
});

test("a higher delegation remains pinned when attestation fails and rejects replay", async (t) => {
  const fixture = await createFixture(t);
  await bootstrapWorker(fixture.config, {
    enroll: true,
    enrollmentToken: "admin",
    fetchImpl: fixture.control.fetch,
  });
  const nextDelegation = await fixture.control.replaceDelegation({ sequence: 3 });
  fixture.control.setAttestationCompatible(false);
  await assert.rejects(
    bootstrapWorker(fixture.config, { fetchImpl: fixture.control.fetch }),
    (error) => error?.code === "attestation-response-invalid",
  );
  const pinnedTrust = await jsonFile(fixture.stateDirectory, "trust-state.json");
  assert.equal(pinnedTrust.delegationSequence, 3);
  assert.equal(
    pinnedTrust.delegationHash,
    await sha256Hex(canonicalizeJson(nextDelegation)),
  );
  fixture.control.setAttestationCompatible(true);
  await fixture.control.replaceDelegation({ sequence: 2 });
  const beforeReplay = fixture.control.paths.length;
  await assert.rejects(
    bootstrapWorker(fixture.config, { fetchImpl: fixture.control.fetch }),
    (error) => error?.code === "delegation-rollback-refused",
  );
  assert.deepEqual(
    fixture.control.paths.slice(beforeReplay),
    ["/api/editorial/orchestrator/manifest"],
  );
});

test("RuntimeProfile v2 hashes and verifies the complete engine identity", async (t) => {
  const fixture = await createFixture(t);
  const profile = await createRuntimeProfileFromManifest(fixture.manifest);
  assert.deepEqual(await verifyRuntimeProfile(profile, fixture.manifest), profile);
  for (const field of ["provider", "engineAdapter", "engineAdapterVersion"]) {
    const tampered = { ...profile, [field]: `${profile[field]}-tampered` };
    await assert.rejects(
      verifyRuntimeProfile(tampered, fixture.manifest),
      (error) => error?.code === "runtime-profile-hash-mismatch",
    );
  }
  const tampered = { ...profile, provider: "another-provider" };
  const { runtimeProfileHash: _oldHash, ...tamperedCore } = tampered;
  tampered.runtimeProfileHash = await sha256Hex(canonicalizeJson(tamperedCore));
  await assert.rejects(
    verifyRuntimeProfile(tampered, fixture.manifest),
    (error) => error?.code === "runtime-profile-manifest-mismatch",
  );
  const missing = { ...profile };
  delete missing.engineAdapterVersion;
  await assert.rejects(
    verifyRuntimeProfile(missing, fixture.manifest),
    (error) => error?.code === "runtime-profile-fields-invalid",
  );
  await assert.rejects(
    verifyRuntimeProfile({ ...profile, untrustedOption: true }, fixture.manifest),
    (error) => error?.code === "runtime-profile-fields-invalid",
  );
});

test("manifest validation requires the RuntimeProfile v2 provider", async (t) => {
  const fixture = await createFixture(t);
  const { provider: _provider, ...engineWithoutProvider } = fixture.manifest.engine;
  await fixture.control.replaceManifest({ engine: engineWithoutProvider });
  await assert.rejects(
    bootstrapWorker(fixture.config, {
      enroll: true,
      enrollmentToken: "admin",
      fetchImpl: fixture.control.fetch,
    }),
    (error) => error?.code === "manifest-engine-invalid",
  );
  assert.equal(fixture.control.attestations.length, 0);
});

test("root-required instantiated actions are refused before any signed bootstrap", async (t) => {
  const fixture = await createFixture(t);
  await fixture.control.replaceManifest({
    actions: [
      ...fixture.manifest.actions,
      { type: "install-runtime-artifact", authorizationClass: "root-required" },
    ],
  });
  await assert.rejects(
    bootstrapWorker(fixture.config, {
      enroll: true,
      enrollmentToken: "admin",
      fetchImpl: fixture.control.fetch,
    }),
    (error) => error?.code === "root-action-refused",
  );
  assert.equal(
    fixture.control.paths.filter((path) => path === "/api/editorial/orchestrator/bootstrap").length,
    0,
  );
  assert.equal(fixture.control.attestations.length, 0);
});

test("artifact hash mismatch rolls back application and never attests", async (t) => {
  const fixture = await createFixture(t, { corruptArtifact: "policy" });
  await assert.rejects(
    bootstrapWorker(fixture.config, {
      enroll: true,
      enrollmentToken: "admin",
      fetchImpl: fixture.control.fetch,
    }),
    (error) => new Set(["artifact-hash-mismatch", "artifact-size-mismatch"]).has(error?.code),
  );
  await assert.rejects(readFile(join(fixture.stateDirectory, "applied-manifest.json")), /ENOENT/);
  assert.equal(fixture.control.attestations.length, 0);
  const status = await jsonFile(fixture.stateDirectory, "status.json");
  assert.equal(status.state, "update-failed");
  assert.equal(status.ready, false);
});

test("artifact media type must match exactly instead of sharing a prefix", async (t) => {
  const fixture = await createFixture(t, { wrongArtifactMediaType: "policy" });
  await assert.rejects(
    bootstrapWorker(fixture.config, {
      enroll: true,
      enrollmentToken: "admin",
      fetchImpl: fixture.control.fetch,
    }),
    (error) => error?.code === "artifact-media-type-mismatch",
  );
  assert.equal(fixture.control.attestations.length, 0);
});

test("local /api/tags must expose the exact model digest", async (t) => {
  const fixture = await createFixture(t, { wrongModelDigest: true });
  await assert.rejects(
    bootstrapWorker(fixture.config, {
      enroll: true,
      enrollmentToken: "admin",
      fetchImpl: fixture.control.fetch,
    }),
    (error) => error?.code === "model-digest-unavailable",
  );
  await assert.rejects(readFile(join(fixture.stateDirectory, "applied-manifest.json")), /ENOENT/);
  assert.equal(fixture.control.attestations.length, 0);
});

test("Darwin omits misleading generic pressure unless availability is sampled", () => {
  assert.deepEqual(sampleCapacityPressure({ platform: "darwin" }), {});
  assert.deepEqual(sampleCapacityPressure({
    platform: "darwin",
    logicalProcessors: 4,
    oneMinuteLoad: 2,
    totalMemoryBytes: 100,
  }), { cpuPercent: 50 });
  assert.deepEqual(sampleCapacityPressure({
    platform: "darwin",
    logicalProcessors: 4,
    oneMinuteLoad: 2,
    totalMemoryBytes: 100,
    availableMemoryBytes: 40,
  }), { cpuPercent: 50, memoryPercent: 60 });
});

test("node heartbeat reports durable GPU telemetry without inflating active time", async (t) => {
  const fixture = await createFixture(t);
  await bootstrapWorker(fixture.config, {
    enroll: true,
    enrollmentToken: "admin",
    fetchImpl: fixture.control.fetch,
  });
  await setLocalParallelism(fixture.config, 0);
  const startedAt = Date.now();
  const available = (utilizationPercent) => ({
    available: true,
    status: "available",
    utilizationPercent,
    errorCode: null,
  });

  await nodeHeartbeat(fixture.config, {
    fetchImpl: fixture.control.fetch,
    gpuSample: available(42),
    now: new Date(startedAt),
  });
  const heartbeatRequest = fixture.control.requests.findLast(
    (request) => request.path === "/api/editorial/orchestrator/nodes/heartbeat",
  );
  assert.equal(heartbeatRequest.body.pressure.gpuPercent, 42);
  let metrics = await jsonFile(fixture.stateDirectory, "metrics.json");
  assert.equal(metrics.resources.gpu.status, "available");
  assert.equal(metrics.resources.gpu.sampleCount, 1);
  assert.equal(metrics.resources.gpu.totalActiveSeconds, 0);
  assert.equal(parseDashboardMetrics(metrics).gpu.status, "available");

  await Promise.all([
    updateMetrics(fixture.stateDirectory, fixture.config, (value) => {
      value.jobs.claimed += 1;
    }),
    updateMetrics(fixture.stateDirectory, fixture.config, (value) => {
      value.batches.total += 1;
    }),
  ]);
  metrics = await jsonFile(fixture.stateDirectory, "metrics.json");
  assert.equal(metrics.jobs.claimed, 1);
  assert.equal(metrics.batches.total, 1);
  assert.equal(metrics.resources.gpu.status, "available");

  await nodeHeartbeat(fixture.config, {
    fetchImpl: fixture.control.fetch,
    gpuSample: {
      available: false,
      status: "unavailable",
      utilizationPercent: null,
      errorCode: "gpu-probe-failed",
    },
    now: new Date(startedAt + 60_000),
  });
  metrics = await jsonFile(fixture.stateDirectory, "metrics.json");
  assert.equal(metrics.resources.gpu.status, "unavailable");
  assert.equal(metrics.resources.gpu.sampleCount, 1);
  assert.equal(metrics.resources.gpu.averageUtilizationPercent, 42);

  await nodeHeartbeat(fixture.config, {
    fetchImpl: fixture.control.fetch,
    gpuSample: available(50),
    now: new Date(startedAt + 120_000),
  });
  metrics = await jsonFile(fixture.stateDirectory, "metrics.json");
  assert.equal(metrics.resources.gpu.status, "available");
  assert.equal(metrics.resources.gpu.sampleCount, 2);
  assert.equal(metrics.resources.gpu.averageUtilizationPercent, 46);
  assert.equal(metrics.resources.gpu.totalActiveSeconds, 0);

  await assert.rejects(nodeHeartbeat(fixture.config, {
    fetchImpl: async () => { throw new Error("control plane offline"); },
    gpuSample: available(25),
    now: new Date(startedAt + 180_000),
  }));
  metrics = await jsonFile(fixture.stateDirectory, "metrics.json");
  assert.equal(metrics.resources.gpu.status, "available");
  assert.equal(metrics.resources.gpu.sampleCount, 3);
  assert.equal(metrics.resources.gpu.averageUtilizationPercent, 39);
  assert.equal(metrics.resources.gpu.totalActiveSeconds, 60);
  assert.equal(parseDashboardMetrics(metrics).gpu.status, "available");

  assert.equal(gpuActiveSecondsDelta(null, new Date(startedAt).toISOString()), 0);
  assert.equal(gpuActiveSecondsDelta({
    heartbeat: { lastAttemptAt: new Date(startedAt).toISOString() },
  }, new Date(startedAt + 300_000).toISOString()), 120);
});

test("execute requires the current ready/applied gate and retries with one request id and new nonces", async (t) => {
  const fixture = await createFixture(t, { failFirstExecute: true });
  await bootstrapWorker(fixture.config, {
    enroll: true,
    enrollmentToken: "admin",
    fetchImpl: fixture.control.fetch,
  });
  const observedTimeouts = [];
  const pressure = { cpuPercent: 42.555, memoryPercent: 61.254 };
  const normalizedPressure = { cpuPercent: 42.56, memoryPercent: 61.25 };
  await nodeHeartbeat(fixture.config, {
    fetchImpl: fixture.control.fetch,
    pressure,
  });
  const result = await executeWorkerCycle(fixture.config, {
    fetchImpl: fixture.control.fetch,
    timeoutSignalFactory(milliseconds) {
      observedTimeouts.push(milliseconds);
      return new AbortController().signal;
    },
  });
  assert.equal(result.claimed, 2);
  assert.deepEqual(result.results.map((item) => item.status), [
    "pending-review",
    "failed-attempt",
  ]);
  const executeRequests = fixture.control.requests.filter(
    (request) => request.path === "/api/editorial/orchestrator/execute",
  );
  assert.equal(executeRequests.length, 2);
  assert.equal(executeRequests[0].requestId, executeRequests[1].requestId);
  assert.notEqual(executeRequests[0].nonce, executeRequests[1].nonce);
  assert.equal(executeRequests.every((request) => request.signatureValid), true);
  assert.deepEqual(executeRequests.map((request) => request.body), [
    {},
    {},
  ]);
  const executeChallenges = fixture.control.requests.filter(
    (request) =>
      request.path === "/api/editorial/orchestrator/challenge" &&
      request.purpose === "execute",
  );
  assert.equal(executeChallenges.length, 2);
  assert.notEqual(executeChallenges[0].requestId, executeChallenges[1].requestId);
  assert.deepEqual(
    observedTimeouts.filter(
      (milliseconds) => milliseconds === fixture.config.executeRequestTimeoutMilliseconds,
    ),
    [fixture.config.executeRequestTimeoutMilliseconds, fixture.config.executeRequestTimeoutMilliseconds],
  );
  assert.equal(
    observedTimeouts.filter(
      (milliseconds) => milliseconds === fixture.config.requestTimeoutMilliseconds,
    ).length,
    3,
  );

  const metrics = await jsonFile(fixture.stateDirectory, "metrics.json");
  assert.equal(metrics.batches.total, 1);
  assert.equal(metrics.batches.failed, 1);
  assert.equal(metrics.jobs.claimed, 2);
  assert.equal(metrics.jobs.completed, 1);
  assert.equal(metrics.jobs.failed, 1);
  assert.equal(metrics.resources.memory.perItem.sampleCount, 2);
  assert.equal(Number.isSafeInteger(metrics.resources.memory.perItem.averageBytes), true);
  assert.equal(metrics.resources.memory.estimatedBytesPerRunningItem, null);
  assert.equal(metrics.standby.active, true);
  const capacity = await jsonFile(fixture.stateDirectory, "capacity.json");
  assert.equal(capacity.source, "execute");
  assert.equal(capacity.requestedCapacity, 2);
  assert.equal(capacity.grantedCapacity, 2);
  assert.equal(capacity.reason, "requested-capacity-granted");
  assert.deepEqual(capacity.pressure, normalizedPressure);
});

test("execute does not contact the API when ready.json diverges", async (t) => {
  const fixture = await createFixture(t);
  await bootstrapWorker(fixture.config, {
    enroll: true,
    enrollmentToken: "admin",
    fetchImpl: fixture.control.fetch,
  });
  await nodeHeartbeat(fixture.config, { fetchImpl: fixture.control.fetch });
  const readyPath = join(fixture.stateDirectory, "ready.json");
  const ready = JSON.parse(await readFile(readyPath, "utf8"));
  ready.manifestHash = "0".repeat(64);
  await writeFile(readyPath, JSON.stringify(ready), "utf8");
  const before = fixture.control.paths.length;
  await assert.rejects(
    executeWorkerCycle(fixture.config, { fetchImpl: fixture.control.fetch }),
    (error) => error?.code === "worker-not-ready",
  );
  assert.equal(fixture.control.paths.length, before);
});

test("execute pins and invalidates a newer manifest under the same delegation", async (t) => {
  const fixture = await createFixture(t);
  await bootstrapWorker(fixture.config, {
    enroll: true,
    enrollmentToken: "admin",
    fetchImpl: fixture.control.fetch,
  });
  await nodeHeartbeat(fixture.config, { fetchImpl: fixture.control.fetch });
  const nextManifest = await fixture.control.replaceManifest({
    sequence: fixture.manifest.sequence + 1,
    previousManifestHash: fixture.manifest.hash,
  });
  await assert.rejects(
    executeWorkerCycle(fixture.config, { fetchImpl: fixture.control.fetch }),
    (error) => error?.code === "update-required",
  );
  const [ready, trustState, status] = await Promise.all([
    jsonFile(fixture.stateDirectory, "ready.json"),
    jsonFile(fixture.stateDirectory, "trust-state.json"),
    jsonFile(fixture.stateDirectory, "status.json"),
  ]);
  assert.equal(ready.ready, false);
  assert.equal(ready.targetManifestHash, nextManifest.hash);
  assert.equal(trustState.manifestHash, nextManifest.hash);
  assert.equal(trustState.manifestSequence, nextManifest.sequence);
  assert.equal(status.ready, false);
});

test("execute does not contact the API when the persisted runtime version diverges", async (t) => {
  const fixture = await createFixture(t);
  await bootstrapWorker(fixture.config, {
    enroll: true,
    enrollmentToken: "admin",
    fetchImpl: fixture.control.fetch,
  });
  await nodeHeartbeat(fixture.config, { fetchImpl: fixture.control.fetch });
  const readyPath = join(fixture.stateDirectory, "ready.json");
  const ready = JSON.parse(await readFile(readyPath, "utf8"));
  ready.workerRuntimeVersion = "3.0.0";
  await writeFile(readyPath, JSON.stringify(ready), "utf8");
  const before = fixture.control.paths.length;
  await assert.rejects(
    executeWorkerCycle(fixture.config, { fetchImpl: fixture.control.fetch }),
    (error) => error?.code === "worker-not-ready",
  );
  assert.equal(fixture.control.paths.length, before);
});

test("execute refuses an installed engine identity outside RuntimeProfile v2", async (t) => {
  const fixture = await createFixture(t);
  await bootstrapWorker(fixture.config, {
    enroll: true,
    enrollmentToken: "admin",
    fetchImpl: fixture.control.fetch,
  });
  await nodeHeartbeat(fixture.config, { fetchImpl: fixture.control.fetch });
  const enginePath = join(
    fixture.stateDirectory,
    "runtime",
    "config",
    "engine.json",
  );
  const engine = JSON.parse(await readFile(enginePath, "utf8"));
  engine.provider = "another-provider";
  await writeFile(enginePath, JSON.stringify(engine), "utf8");
  const before = fixture.control.paths.length;
  await assert.rejects(
    executeWorkerCycle(fixture.config, { fetchImpl: fixture.control.fetch }),
    (error) => error?.code === "runtime-profile-installation-mismatch",
  );
  const contacted = fixture.control.paths.slice(before);
  assert.deepEqual(contacted, ["/api/editorial/orchestrator/manifest"]);
  assert.equal(
    contacted.includes("/api/editorial/orchestrator/execute"),
    false,
  );
});

test("execute rejects a response correlated to another request id", async (t) => {
  const fixture = await createFixture(t, { wrongExecuteRequestId: true });
  await bootstrapWorker(fixture.config, {
    enroll: true,
    enrollmentToken: "admin",
    fetchImpl: fixture.control.fetch,
  });
  await nodeHeartbeat(fixture.config, { fetchImpl: fixture.control.fetch });
  await assert.rejects(
    executeWorkerCycle(fixture.config, { fetchImpl: fixture.control.fetch }),
    (error) => error?.code === "execute-response-invalid",
  );
});

test("zero parallelism remains heartbeat-only and cannot receive work", async (t) => {
  const fixture = await createFixture(t);
  await bootstrapWorker(fixture.config, {
    enroll: true,
    enrollmentToken: "admin",
    fetchImpl: fixture.control.fetch,
  });
  const control = await setLocalParallelism(fixture.config, 0);
  assert.equal(control.effectiveParallelism, 0);
  assert.equal(control.drainRequested, true);
  await nodeHeartbeat(fixture.config, {
    fetchImpl: fixture.control.fetch,
    pressure: { cpuPercent: 25, memoryPercent: 40 },
  });
  const heartbeatStatus = await jsonFile(fixture.stateDirectory, "status.json");
  assert.equal(heartbeatStatus.state, "draining");
  assert.equal(heartbeatStatus.running, false);
  assert.equal(heartbeatStatus.standby, true);
  assert.equal(heartbeatStatus.currentBatch, null);
  assert.equal(heartbeatStatus.code, "drain-requested");
  const executeCountBefore = fixture.control.paths.filter(
    (path) => path === "/api/editorial/orchestrator/execute",
  ).length;
  const result = await executeWorkerCycle(fixture.config, {
    fetchImpl: fixture.control.fetch,
  });
  assert.equal(result.claimed, 0);
  assert.deepEqual(result.results, []);
  assert.equal(result.capacity.requestedCapacity, 0);
  assert.equal(result.capacity.grantedCapacity, 0);
  assert.equal(result.heartbeatOnly, true);
  assert.match(result.capacity.reason, /capacity-zero/);
  assert.equal(
    fixture.control.paths.filter((path) => path === "/api/editorial/orchestrator/execute").length,
    executeCountBefore,
  );
  const [capacity, status] = await Promise.all([
    jsonFile(fixture.stateDirectory, "capacity.json"),
    jsonFile(fixture.stateDirectory, "status.json"),
  ]);
  assert.equal(capacity.requestedCapacity, 0);
  assert.equal(capacity.grantedCapacity, 0);
  assert.equal(status.state, "draining");
  assert.equal(status.capacity.effectiveGrantedCapacity, 0);
});

test("node heartbeat refreshes status without overwriting active work", async (t) => {
  const fixture = await createFixture(t);
  await bootstrapWorker(fixture.config, {
    enroll: true,
    enrollmentToken: "admin",
    fetchImpl: fixture.control.fetch,
  });
  const statusPath = join(fixture.stateDirectory, "status.json");
  const status = await jsonFile(fixture.stateDirectory, "status.json");
  const batch = {
    batchId: "heartbeat-active",
    assignmentIds: ["assignment-active"],
    jobs: 1,
    completedJobs: 0,
    startedAt: "2026-08-22T20:00:00.000Z",
  };
  await writeFile(statusPath, JSON.stringify({
    ...status,
    observedAt: "2026-08-22T20:00:00.000Z",
    state: "processing",
    running: true,
    standby: false,
    currentBatch: batch,
    code: "assignment-processing",
  }));

  await nodeHeartbeat(fixture.config, { fetchImpl: fixture.control.fetch });

  const refreshed = await jsonFile(fixture.stateDirectory, "status.json");
  assert.notEqual(refreshed.observedAt, "2026-08-22T20:00:00.000Z");
  assert.equal(refreshed.state, "processing");
  assert.equal(refreshed.running, true);
  assert.equal(refreshed.standby, false);
  assert.deepEqual(refreshed.currentBatch, batch);
  assert.equal(refreshed.code, "assignment-processing");
});

test("bootstrap with requested capacity zero attests directly into drain", async (t) => {
  const fixture = await createFixture(t);
  const drainConfig = validateWorkerConfig({
    ...fixture.config,
    requestedCapacity: 0,
  });
  const result = await bootstrapWorker(drainConfig, {
    enroll: true,
    enrollmentToken: "admin",
    fetchImpl: fixture.control.fetch,
  });
  assert.equal(result.state, "draining");
  assert.equal(result.workStarted, false);
  const [ready, status, capacity] = await Promise.all([
    jsonFile(fixture.stateDirectory, "ready.json"),
    jsonFile(fixture.stateDirectory, "status.json"),
    jsonFile(fixture.stateDirectory, "capacity.json"),
  ]);
  assert.equal(ready.ready, true);
  assert.equal(ready.requestedCapacity, 0);
  assert.equal(ready.grantedCapacity, 0);
  assert.equal(status.state, "draining");
  assert.equal(capacity.reason, "drain-requested");
});

test("local control CLI operations validate without claiming and stop during an active lock", async (t) => {
  const fixture = await createFixture(t);
  await bootstrapWorker(fixture.config, {
    enroll: true,
    enrollmentToken: "admin",
    fetchImpl: fixture.control.fetch,
  });
  const configured = await configureLocalWorker(fixture.config);
  assert.equal(configured.acceptingClaims, false);
  assert.equal(configured.requestedCapacity, 0);
  const beforeValidate = fixture.control.paths.length;
  const validation = await validateLocalWorker(fixture.config, {
    fetchImpl: fixture.control.fetch,
  });
  assert.equal(validation.valid, true);
  assert.equal(validation.reservationAttempted, false);
  assert.deepEqual(fixture.control.paths.slice(beforeValidate), ["/api/tags"]);
  const configuredParallelism = await setLocalParallelism(fixture.config, 8);
  assert.equal(configuredParallelism.requestedParallelism, 8);
  assert.equal(configuredParallelism.effectiveParallelism, 0);
  const started = await startLocalWorker(fixture.config, {
    fetchImpl: fixture.control.fetch,
  });
  assert.equal(started.requestedCapacity, 8);
  assert.equal(started.acceptingClaims, true);

  await writeFile(join(fixture.stateDirectory, ".worker.lock"), "active-cycle", "utf8");
  const stopped = await stopLocalWorker(fixture.config);
  assert.equal(stopped.stopRequested, true);
  assert.equal(stopped.activeAssignmentsWillBeCancelled, true);
  assert.equal(stopped.cancellationErrorCode, "operator-stop-requested");
  assert.equal(stopped.priorCapacity, 8);
  await rm(join(fixture.stateDirectory, ".worker.lock"), { force: true });
  const status = await localWorkerStatus(fixture.config, {
    timerEnabled: "disabled",
    timerActive: "inactive",
    serviceActive: "active",
  });
  assert.equal(status.effectiveParallelism, 0);
  assert.equal(status.capacity.effectiveGrantedCapacity, 0);
  assert.equal(status.systemd.serviceActive, "active");
  assert.equal(
    fixture.control.paths.slice(beforeValidate).includes("/api/editorial/orchestrator/claim"),
    false,
  );
  assert.equal(
    fixture.control.paths.slice(beforeValidate).includes("/api/editorial/orchestrator/execute"),
    false,
  );
});

test("local validation rejects ready state from another worker runtime", async (t) => {
  const fixture = await createFixture(t);
  await bootstrapWorker(fixture.config, {
    enroll: true,
    enrollmentToken: "admin",
    fetchImpl: fixture.control.fetch,
  });
  const readyPath = join(fixture.stateDirectory, "ready.json");
  const ready = JSON.parse(await readFile(readyPath, "utf8"));
  ready.workerRuntimeVersion = "3.0.0";
  await writeFile(readyPath, JSON.stringify(ready), "utf8");
  await assert.rejects(
    validateLocalWorker(fixture.config, { fetchImpl: fixture.control.fetch }),
    (error) => error?.code === "worker-local-validation-failed",
  );
});

test("signed capacity policy is strict and local requested capacity supports 0 through 64", async (t) => {
  const fixture = await createFixture(t);
  assert.deepEqual(validateCapacityPolicy(fixture.manifest.capacityPolicy), fixture.manifest.capacityPolicy);
  assert.throws(
    () => validateCapacityPolicy({
      ...fixture.manifest.capacityPolicy,
      telemetryMayOnlyReduce: false,
    }),
    (error) => error?.code === "capacity-policy-unsupported",
  );
  assert.throws(
    () => validateCapacityPolicy({
      ...fixture.manifest.capacityPolicy,
      remoteCommand: "unsafe",
    }),
    (error) => error?.code === "capacity-policy-invalid",
  );
  for (const requestedCapacity of [0, 64]) {
    assert.equal(
      validateWorkerConfig({ ...fixture.config, requestedCapacity }).requestedCapacity,
      requestedCapacity,
    );
  }
  assert.throws(
    () => validateWorkerConfig({ ...fixture.config, requestedCapacity: 65 }),
    /requestedCapacity/,
  );
});

test("Linux workerctl exposes the uniform long-lived service control contract", async () => {
  const source = await readFile(
    new URL("../../../../scripts/hch-editorial-workerctl", import.meta.url),
    "utf8",
  );
  for (const command of ["configure", "validate", "start", "pause", "stop", "status", "set-parallelism"]) {
    assert.match(source, new RegExp(`\\b${command}\\b`));
  }
  const stopBlock = source.slice(source.indexOf("  stop)"), source.indexOf("  status)"));
  assert.match(stopBlock, /control-stop/);
  assert.doesNotMatch(stopBlock, /disable --now|systemctl[^\n]*stop/);
  const validateBlock = source.slice(source.indexOf("  validate)"), source.indexOf("  start)"));
  assert.doesNotMatch(validateBlock, /execute|claim/);
});

test("one-shot enrollment keeps the credential ephemeral and out of argv", async () => {
  const source = await readFile(
    new URL("../../../../scripts/run-editorial-enrollment.sh", import.meta.url),
    "utf8",
  );
  assert.match(source, /runtime_directory=\/run\/hch-editorial-worker/);
  assert.match(source, /mktemp "\$\{runtime_directory\}\/enrollment-token\.XXXXXXXX"/);
  assert.match(source, /chmod 0600 "\$\{credential_path\}"/);
  assert.match(source, /trap cleanup EXIT/);
  assert.match(source, /runuser/);
  assert.match(source, /HCH_EDITORIAL_ENROLLMENT_TOKEN_FILE="\$\{credential_path\}"/);
  assert.doesNotMatch(source, /--token|Authorization:|Bearer /);
});

test("pending operation ids are reused and completed operations get a new id", async (t) => {
  const stateRoot = await temporaryDirectory(t);
  const first = await operationRequestId(stateRoot, "bootstrap:test", "{}");
  const replay = await operationRequestId(stateRoot, "bootstrap:test", "{}");
  assert.equal(replay.requestId, first.requestId);
  await completeOperation(stateRoot, first.operationKey);
  const next = await operationRequestId(stateRoot, "bootstrap:test", "{}");
  assert.notEqual(next.requestId, first.requestId);
});

test("configuration enforces HTTPS control plane and loopback local engine", async (t) => {
  const directory = await temporaryDirectory(t);
  const base = {
    schemaVersion: 1,
    nodeId: "vps-primary",
    keyId: "vps-primary-key-v1",
    orchestratorBaseUrl: "https://orchestrator.test",
    stateDirectory: join(directory, "state"),
    rootPublicKeyPath: join(directory, "root.pem"),
    rootPublicKeyFingerprint: `SHA256:${"A".repeat(43)}`,
    rootKeyId: "hch-root-v1",
    localEngineBaseUrl: "http://127.0.0.1:11434",
  };
  const validated = validateWorkerConfig(base);
  assert.equal(validated.nodeId, "vps-primary");
  assert.equal(validated.localEngineNumThreads, undefined);
  assert.equal(validated.requestTimeoutMilliseconds, 15_000);
  assert.equal(validated.executeRequestTimeoutMilliseconds, 45 * 60_000);
  assert.equal(
    validateWorkerConfig({
      ...base,
      executeRequestTimeoutMilliseconds: 60 * 60_000,
    }).executeRequestTimeoutMilliseconds,
    60 * 60_000,
  );
  assert.throws(
    () => validateWorkerConfig({
      ...base,
      executeRequestTimeoutMilliseconds: 45 * 60_000 - 1,
    }),
    /executeRequestTimeoutMilliseconds/,
  );
  assert.throws(
    () => validateWorkerConfig({ ...base, orchestratorBaseUrl: "http://orchestrator.test" }),
    /HTTPS/,
  );
  assert.throws(
    () => validateWorkerConfig({ ...base, localEngineBaseUrl: "http://192.0.2.10:11434" }),
    /loopback/,
  );
  assert.throws(
    () => validateWorkerConfig({ ...base, enrollmentToken: "must-not-be-here" }),
    /Unsupported config field/,
  );
  assert.throws(
    () => validateWorkerConfig({ ...base, enrollmentTokenEnvironment: "HCH/TOKEN" }),
    /environment variable name/,
  );
  for (const localEngineNumThreads of [0, -1, 1.5, "2", 65]) {
    assert.throws(
      () => validateWorkerConfig({ ...base, localEngineNumThreads }),
      /localEngineNumThreads/,
    );
  }
  assert.equal(
    validateWorkerConfig({ ...base, localEngineNumThreads: 2 }).localEngineNumThreads,
    2,
  );
});

test("enrollment credential file is one-shot, private, bounded, and unambiguous", async (t) => {
  const directory = await temporaryDirectory(t);
  const credentialPath = join(directory, "enrollment-token");
  await writeFile(credentialPath, "credential-test-value\n", { mode: 0o600 });
  const suffix = crypto.randomUUID().replaceAll("-", "_").toUpperCase();
  const valueName = `HCH_TEST_ENROLLMENT_${suffix}`;
  const fileName = `${valueName}_FILE`;
  const config = { enrollmentTokenEnvironment: valueName };
  t.after(() => {
    delete process.env[valueName];
    delete process.env[fileName];
  });

  process.env[fileName] = credentialPath;
  assert.equal(await resolveEnrollmentToken(config), "credential-test-value\n");
  assert.equal(process.env[fileName], undefined);

  process.env[valueName] = "direct-value";
  assert.equal(await resolveEnrollmentToken(config), "direct-value");
  assert.equal(process.env[valueName], undefined);

  process.env[valueName] = "direct-value";
  process.env[fileName] = credentialPath;
  await assert.rejects(
    resolveEnrollmentToken(config),
    (error) => error?.code === "enrollment-token-source-ambiguous",
  );
  assert.equal(process.env[valueName], undefined);
  assert.equal(process.env[fileName], undefined);

  await writeFile(credentialPath, "x".repeat(16 * 1024 + 1), { mode: 0o600 });
  process.env[fileName] = credentialPath;
  await assert.rejects(
    resolveEnrollmentToken(config),
    (error) =>
      error?.code === "enrollment-token-file-invalid" &&
      !error.message.includes("x".repeat(32)),
  );
});

test("bootstrap enrolls from the configured credential file without persisting it", async (t) => {
  const fixture = await createFixture(t);
  const suffix = crypto.randomUUID().replaceAll("-", "_").toUpperCase();
  const valueName = `HCH_TEST_BOOTSTRAP_${suffix}`;
  const fileName = `${valueName}_FILE`;
  const credentialPath = join(fixture.directory, "bootstrap-enrollment-token");
  const token = "credential-bootstrap-secret";
  await writeFile(credentialPath, `${token}\n`, { mode: 0o600 });
  const config = validateWorkerConfig({
    ...fixture.config,
    enrollmentTokenEnvironment: valueName,
  });
  process.env[fileName] = credentialPath;
  t.after(() => {
    delete process.env[valueName];
    delete process.env[fileName];
  });
  const result = await bootstrapWorker(config, {
    enroll: true,
    fetchImpl: fixture.control.fetch,
  });
  assert.equal(result.state, "ready");
  assert.equal(process.env[fileName], undefined);
  const [status, metrics, enrolled] = await Promise.all([
    jsonFile(fixture.stateDirectory, "status.json"),
    jsonFile(fixture.stateDirectory, "metrics.json"),
    jsonFile(fixture.stateDirectory, "enrolled.json"),
  ]);
  assert.equal(enrolled.status, "active");
  assert.doesNotMatch(JSON.stringify({ status, metrics, enrolled }), new RegExp(token));
});

test("published config example and JSON schemas are valid JSON", async () => {
  const example = JSON.parse(
    await readFile(new URL("../config.example.json", import.meta.url), "utf8"),
  );
  assert.equal(validateWorkerConfig(example).nodeId, "vps-primary");
  assert.equal(validateWorkerConfig(example).localEngineNumThreads, 1);
  const schemaDirectory = new URL("../schemas/", import.meta.url);
  const schemaNames = await readdir(schemaDirectory);
  assert.deepEqual(schemaNames.sort(), [
    "adaptive-work-policy-v1.schema.json",
    "worker-assignment-progress-v1.schema.json",
    "worker-assignment-v1.schema.json",
    "worker-attestation-v2.schema.json",
    "worker-capacity-v1.schema.json",
    "worker-config-v1.schema.json",
    "worker-control-v1.schema.json",
    "worker-generation-plan-v1.schema.json",
    "worker-metrics-v1.schema.json",
    "worker-orchestration-v1.schema.json",
    "worker-runtime-profile-v2.schema.json",
    "worker-status-v1.schema.json",
    "worker-trust-state-v1.schema.json",
    "worker-update-receipt-v1.schema.json",
  ]);
  for (const name of schemaNames) {
    const schema = JSON.parse(await readFile(new URL(name, schemaDirectory), "utf8"));
    assert.equal(schema.$schema, "https://json-schema.org/draft/2020-12/schema");
  }
});

async function createFixture(t, behavior = {}) {
  const directory = await temporaryDirectory(t);
  const stateDirectory = join(directory, "state");
  const rootPath = join(directory, "root.pem");
  const rootKeys = await crypto.subtle.generateKey(
    { name: "Ed25519" },
    true,
    ["sign", "verify"],
  );
  const releaseKeys = await crypto.subtle.generateKey(
    { name: "Ed25519" },
    true,
    ["sign", "verify"],
  );
  const rootPublicPem = toPem(
    await crypto.subtle.exportKey("spki", rootKeys.publicKey),
    "PUBLIC KEY",
  );
  await writeFile(rootPath, rootPublicPem, { mode: 0o644 });
  const rootFingerprint = await workerPublicKeyFingerprint(rootPublicPem);
  const rootKeyId = "hch-root-v1";
  const releaseKeyId = "hch-release-test-v1";
  const now = Math.floor(Date.now() / 1_000);
  const delegation = await signReleaseKeyDelegation(
    releaseKeys.publicKey,
    rootKeys.privateKey,
    {
      rootKeyId,
      releaseKeyId,
      sequence: 2,
      created: now - 60,
      notBefore: now - 30,
      expires: now + 86_400,
    },
  );
  const artifacts = new Map([
    ["policy", Buffer.from('{"policy":"canonical"}\n')],
    ["prompt", Buffer.from("Generate a reviewed editorial draft.\n")],
    ["editorial-content-schema", Buffer.from('{"type":"object"}\n')],
    ["editorial-source-schema", Buffer.from('{"type":"object","title":"source"}\n')],
  ]);
  const artifactDeclarations = await Promise.all(
    [...artifacts].map(async ([name, bytes]) => {
      const digest = await sha256Hex(bytes);
      const mediaType = name === "prompt"
        ? "text/markdown; charset=utf-8"
        : name.includes("schema")
          ? "application/schema+json; charset=utf-8"
          : "application/json; charset=utf-8";
      return {
        name,
        mediaType,
        bytes: bytes.byteLength,
        sha256: digest,
        url: `/api/editorial/orchestrator/artifacts/${name}?sha256=${digest}`,
        authorizationClass: "release",
      };
    }),
  );
  const manifestBase = {
    schemaVersion: "2.0",
    protocolVersion: "2.0",
    bootstrapVersion: "2.0.0",
    hashAlgorithm: "sha256",
    sequence: 2,
    releaseId: "hch-editorial-test.2",
    issuedAt: new Date((now - 30) * 1_000).toISOString(),
    expiresAt: new Date((now + 3_600) * 1_000).toISOString(),
    previousManifestHash: null,
    minimumAcceptedSequence: 2,
    updateMode: "mandatory",
    configurationHash: "configuration-test",
    runtime: {
      workerVersion: KIT_VERSION,
      supportedPlatforms: ["linux", "macos", "windows"],
      executableUpdatesRequireRoot: true,
    },
    engine: {
      provider: "vps-local",
      adapter: "ollama",
      adapterVersion: "1.0.0",
      model: "qwen2.5:1.5b-instruct",
      modelDigest: "65ec06548149b04c096a120e4a6da9d4017ea809c91734ea5631e89f96ddc57b",
      protocol: "ollama-chat",
      healthPath: "/api/tags",
      generationPath: "/api/chat",
    },
    generation: {
      temperature: 0.2,
      contextWindow: 8192,
      maxOutputTokens: 2400,
      maximumParallelAssignments: 2,
    },
    capacityPolicy: {
      algorithmVersion: "hch-adaptive-capacity-v1",
      absoluteRequestedMaximum: 64,
      defaultNodeCeiling: 16,
      globalAssignmentCeiling: 32,
      grantTtlSeconds: 120,
      telemetryMayOnlyReduce: true,
      classCeilings: {
        constrained: 4,
        standard: 16,
        accelerated: 32,
      },
      platformClasses: {
        linux: "standard",
        macos: "standard",
        windows: "standard",
      },
      nodeClasses: { "vps-primary": "standard" },
      nodeCeilings: { "vps-primary": 16 },
      pressure: {
        softLimitPercent: 80,
        hardLimitPercent: 92,
        softReductionFactor: 0.5,
      },
    },
    adaptiveWorkPolicy: {
      algorithmVersion: "hch-adaptive-work-v1",
      windowMode: "advisory",
      minimumTierIgnoresWindow: true,
      livenessBasis: "progress",
      processingWindowSeconds: 2700,
      nearWindowRatio: 0.8,
      firstProgressGraceSeconds: 900,
      stallAfterSeconds: 600,
      finalizationGraceSeconds: 180,
      tiers: [
        {
          id: "minimum", rank: 0, maxOutputTokens: 768,
          editorialProfile: "EDITORIAL_MINIMUM", minimumUnit: true,
        },
        {
          id: "compact", rank: 1, maxOutputTokens: 1536,
          editorialProfile: "EDITORIAL_COMPACT", minimumUnit: false,
        },
        {
          id: "full", rank: 2, maxOutputTokens: 2400,
          editorialProfile: "EDITORIAL_LONG_FORM", minimumUnit: false,
        },
      ],
    },
    editorial: {
      policyId: "third-party-editorial-generation",
      policyVersion: "1.0.0",
      policyHash: "b".repeat(64),
      promptConfigHash: "c".repeat(64),
      pipelineVersion: "1.2.0",
    },
    actions: [
      { type: "verify-artifact", authorizationClass: "release" },
      { type: "configure-engine", authorizationClass: "release" },
      { type: "pull-model-by-digest", authorizationClass: "release" },
      { type: "apply-editorial-policy", authorizationClass: "release" },
      { type: "self-test", authorizationClass: "release" },
    ],
    artifacts: artifactDeclarations,
    security: {
      authorizationByIp: false,
      arbitraryRemoteCommands: false,
    },
    safety: {
      automaticApproval: false,
      automaticPublication: false,
      credentialsInManifest: false,
    },
  };
  const manifest = await withManifestHash(manifestBase);
  const config = validateWorkerConfig({
    schemaVersion: 1,
    nodeId: "vps-primary",
    keyId: "vps-primary-key-v1",
    orchestratorBaseUrl: "https://orchestrator.test",
    stateDirectory,
    rootPublicKeyPath: rootPath,
    rootPublicKeyFingerprint: rootFingerprint,
    rootKeyId,
    localEngineBaseUrl: "http://127.0.0.1:11434",
    requestedCapacity: 2,
    artifactMaximumBytes: 1024 * 1024,
    requestTimeoutMilliseconds: 5_000,
    executeRequestTimeoutMilliseconds: 45 * 60_000,
    requestRetries: 2,
    enrollmentTokenEnvironment: "HCH_EDITORIAL_ENROLLMENT_TOKEN",
  });
  const control = createControlPlane({
    config,
    rootKeyId,
    rootFingerprint,
    rootPrivateKey: rootKeys.privateKey,
    releaseKeyId,
    releasePublicKey: releaseKeys.publicKey,
    releasePrivateKey: releaseKeys.privateKey,
    delegation,
    manifest,
    artifacts,
    behavior,
  });
  await control.refreshEnvelope();
  return {
    directory,
    stateDirectory,
    rootPath,
    rootPublicPem,
    manifest,
    delegation,
    config,
    control,
  };
}

function createControlPlane(context) {
  let enrolledPublicKey;
  let envelope;
  let activeManifest = context.manifest;
  let activeDelegation = context.delegation;
  let attestationCompatible = true;
  let bootstrapRequestedCapacity = context.config.requestedCapacity;
  let heartbeatRequestedCapacity = 0;
  let heartbeatPressure = {};
  let executeFailures = context.behavior.failFirstExecute ? 1 : 0;
  const challenges = new Map();
  const requests = [];
  const paths = [];
  const attestations = [];

  const api = {
    rootKeyId: context.rootKeyId,
    releaseKeyId: context.releaseKeyId,
    requests,
    paths,
    attestations,
    async refreshEnvelope() {
      const now = Math.floor(Date.now() / 1_000);
      envelope = {
        manifest: await signManifestEnvelope(
          activeManifest,
          context.releasePrivateKey,
          {
            keyId: context.releaseKeyId,
            created: now - 5,
            expires: now + 1_800,
          },
        ),
        delegation: activeDelegation,
        rootKeyId: context.rootKeyId,
        rootPublicKeyFingerprint: context.rootFingerprint,
      };
    },
    async replaceManifest(patch) {
      const { hash: _oldHash, ...base } = activeManifest;
      activeManifest = await withManifestHash({ ...base, ...patch });
      await api.refreshEnvelope();
      return activeManifest;
    },
    async replaceDelegation(overrides = {}) {
      const now = Math.floor(Date.now() / 1_000);
      const created = overrides.created ?? now - 90;
      activeDelegation = await signReleaseKeyDelegation(
        context.releasePublicKey,
        context.rootPrivateKey,
        {
          rootKeyId: context.rootKeyId,
          releaseKeyId: context.releaseKeyId,
          sequence: overrides.sequence,
          created,
          notBefore: overrides.notBefore ?? created,
          expires: overrides.expires ?? now + 86_400,
        },
      );
      await api.refreshEnvelope();
      return activeDelegation;
    },
    setCorruptArtifact(name) {
      context.behavior.corruptArtifact = name;
    },
    setAttestationCompatible(value) {
      attestationCompatible = value === true;
    },
    fetch: async (urlValue, init = {}) => {
      const url = urlValue instanceof URL ? urlValue : new URL(urlValue);
      paths.push(url.pathname);
      if (url.pathname === "/api/editorial/orchestrator/enrollment") {
        assert.match(init.headers.Authorization, /^Bearer \S+$/);
        const body = JSON.parse(init.body);
        enrolledPublicKey = body.publicKeyPem;
        return jsonResponse({
          nodeId: body.nodeId,
          keyId: body.keyId,
          fingerprint: await workerPublicKeyFingerprint(body.publicKeyPem),
          status: "active",
          enrolledAt: new Date().toISOString(),
        }, 201);
      }
      if (url.pathname === "/api/editorial/orchestrator/manifest") {
        return jsonResponse(envelope);
      }
      if (url.pathname.startsWith("/api/editorial/orchestrator/artifacts/")) {
        const name = url.pathname.split("/").at(-1);
        const original = context.artifacts.get(name);
        if (!original) return jsonResponse({ code: "not-found" }, 404);
        const body = context.behavior.corruptArtifact === name
          ? Buffer.concat([original.subarray(0, -1), Buffer.from("X")])
          : original;
        const declaration = activeManifest.artifacts.find((item) => item.name === name);
        return new Response(body, {
          status: 200,
          headers: {
            "Content-Type": context.behavior.wrongArtifactMediaType === name
              ? `${declaration.mediaType.split(";", 1)[0]}p`
              : declaration.mediaType,
          },
        });
      }
      if (url.origin === context.config.localEngineBaseUrl && url.pathname === "/api/tags") {
        return jsonResponse({
          version: "0.11.0-test",
          models: [{
            name: activeManifest.engine.model,
            digest: context.behavior.wrongModelDigest
              ? "0".repeat(64)
              : activeManifest.engine.modelDigest,
          }],
        });
      }
      if (!enrolledPublicKey) return jsonResponse({ code: "worker-key-unavailable" }, 401);
      const verification = await verifyWorkerRequestSignature({
        method: init.method,
        authority: url.host,
        path: url.pathname,
        body: init.body,
        headers: new Headers(init.headers),
      }, enrolledPublicKey, { now: Math.floor(Date.now() / 1_000) });
      const body = JSON.parse(init.body);
      const requestRecord = {
        path: url.pathname,
        requestId: new Headers(init.headers).get("x-hch-request-id"),
        nonce: new Headers(init.headers).get("x-hch-nonce"),
        purpose: body.purpose,
        body,
        signatureValid: verification.ok,
      };
      requests.push(requestRecord);
      if (!verification.ok) return jsonResponse({ code: verification.code }, 401);

      if (url.pathname === "/api/editorial/orchestrator/challenge") {
        assert.match(requestRecord.nonce, /^client-/);
        const nonce = `server-${crypto.randomUUID()}-${crypto.randomUUID()}`;
        challenges.set(body.purpose, nonce);
        return jsonResponse({
          nodeId: body.nodeId,
          keyId: body.keyId,
          purpose: body.purpose,
          nonce,
          expiresAt: new Date(Date.now() + 5 * 60_000).toISOString(),
          signatureProfile: "hch-editorial-worker-request/v1",
        });
      }
      const expectedPurpose = url.pathname.includes("/attest")
        ? "attest"
        : url.pathname.endsWith("/bootstrap")
          ? "bootstrap"
          : url.pathname.endsWith("/nodes/heartbeat")
            ? "node-heartbeat"
            : "execute";
      assert.equal(requestRecord.nonce, challenges.get(expectedPurpose));
      requestRecord.purpose = expectedPurpose;

      if (url.pathname === "/api/editorial/orchestrator/bootstrap") {
        bootstrapRequestedCapacity = body.requestedCapacity;
        return jsonResponse({
          bootstrapSessionId: "11111111-2222-4333-8444-555555555555",
          state: "awaiting-attestation",
          expiresAt: new Date(Date.now() + 15 * 60_000).toISOString(),
          challenge: `attestation-${crypto.randomUUID()}`,
          manifestSequence: activeManifest.sequence,
          manifestHash: activeManifest.hash,
          manifest: envelope,
          requestedCapacity: body.requestedCapacity,
          capacityPolicy: activeManifest.capacityPolicy,
          adaptiveWorkPolicy: activeManifest.adaptiveWorkPolicy,
          attestationUrl: "/api/editorial/orchestrator/bootstrap/11111111-2222-4333-8444-555555555555/attest",
          workEnabled: false,
        }, 202);
      }
      if (url.pathname.endsWith("/attest")) {
        attestations.push(body);
        const requestedCapacity = bootstrapRequestedCapacity;
        const grantedCapacity = Math.min(requestedCapacity, 16);
        const grantedUntil = new Date(Date.now() + 120_000).toISOString();
        return jsonResponse({
          nodeId: context.config.nodeId,
          workerKeyId: context.config.keyId,
          compatible: attestationCompatible,
          state: requestedCapacity === 0 ? "draining" : "idle",
          manifestSequence: activeManifest.sequence,
          manifestHash: activeManifest.hash,
          readyUntil: new Date(Date.now() + 60 * 60_000).toISOString(),
          capacity: {
            requestedCapacity,
            grantedCapacity,
            capacityClass: "standard",
            reason: requestedCapacity === 0
              ? "drain-requested"
              : "requested-capacity-granted",
            grantedUntil,
          },
          serverTime: new Date().toISOString(),
        });
      }
      if (url.pathname === "/api/editorial/orchestrator/nodes/heartbeat") {
        heartbeatRequestedCapacity = body.requestedCapacity;
        heartbeatPressure = body.pressure ?? {};
        const grantedCapacity = Math.min(heartbeatRequestedCapacity, 16);
        const claimable = 2;
        const recommendedCount = Math.min(grantedCapacity, claimable);
        const heartbeatAt = new Date().toISOString();
        return jsonResponse({
          requestId: requestRecord.requestId,
          nodeId: context.config.nodeId,
          heartbeatAt,
          nextHeartbeatSeconds: 60,
          capacity: {
            configuredCapacity: 16,
            requestedCapacity: heartbeatRequestedCapacity,
            grantedCapacity,
            activeAssignments: 0,
            availableSlots: grantedCapacity,
            capacityClass: "standard",
            reason: heartbeatRequestedCapacity === 0
              ? "capacity-zero"
              : "requested-capacity-granted",
            grantedUntil: heartbeatRequestedCapacity === 0
              ? null
              : new Date(Date.now() + 120_000).toISOString(),
          },
          workload: {
            claimable,
            generating: 0,
            futureTotal: claimable,
            claimableByTier: { minimum: claimable, compact: claimable, full: claimable },
          },
          workSizing: {
            algorithmVersion: "hch-adaptive-work-v1",
            currentTier: "full",
            currentRank: 2,
            maxOutputTokens: 2400,
            editorialProfile: "EDITORIAL_LONG_FORM",
            minimumUnit: false,
            reason: "attestation-reset",
            updatedAt: heartbeatAt,
            processingWindowSeconds: 2700,
            nearWindowSeconds: 2160,
            firstProgressGraceSeconds: 900,
            stallAfterSeconds: 600,
            finalizationGraceSeconds: 180,
          },
          claim: {
            allowed: recommendedCount > 0,
            recommendedCount,
            reason: recommendedCount > 0 ? "claim-recommended" : "capacity-zero",
          },
          serverTime: heartbeatAt,
        });
      }
      if (url.pathname === "/api/editorial/orchestrator/execute") {
        if (executeFailures > 0) {
          executeFailures -= 1;
          return jsonResponse({ code: "temporary-unavailable" }, 503);
        }
        const requestedCapacity = heartbeatRequestedCapacity;
        const grantedCapacity = Math.min(requestedCapacity, 16);
        const pressure = heartbeatPressure;
        const draining = requestedCapacity === 0;
        const results = draining ? [] : [
          { assignmentId: "assignment-01", status: "pending-review" },
          { assignmentId: "assignment-02", status: "failed-attempt", error: "test" },
        ];
        return jsonResponse({
          protocol: "central-orchestrator-v2",
          nodeId: context.config.nodeId,
          workerKeyId: context.config.keyId,
          requestId: context.behavior.wrongExecuteRequestId
            ? crypto.randomUUID()
            : requestRecord.requestId,
          claimed: results.length,
          capacity: {
            algorithmVersion: "hch-adaptive-capacity-v1",
            requestedCapacity,
            grantedCapacity,
            availableSlots: grantedCapacity,
            activeAssignments: 0,
            globalActiveAssignments: 0,
            globalAvailableBeforeGrant: 32,
            capacityClass: "standard",
            nodeCeiling: 16,
            reason: draining ? "drain-requested" : "requested-capacity-granted",
            grantedUntil: new Date(Date.now() + 120_000).toISOString(),
            pressure,
          },
          results,
        });
      }
      return jsonResponse({ code: "not-found" }, 404);
    },
  };
  return api;
}

async function withManifestHash(value) {
  return { ...value, hash: await sha256Hex(canonicalizeJson(value)) };
}

function jsonResponse(value, status = 200) {
  return new Response(JSON.stringify(value), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

function toPem(der, label) {
  const base64 = Buffer.from(der).toString("base64");
  return `-----BEGIN ${label}-----\n${base64.match(/.{1,64}/g).join("\n")}\n-----END ${label}-----\n`;
}

async function jsonFile(root, relativePath) {
  return JSON.parse(await readFile(join(root, ...relativePath.split("/")), "utf8"));
}

async function temporaryDirectory(t) {
  const directory = await mkdtemp(join(tmpdir(), "hch-linux-worker-"));
  t.after(() => rm(directory, { recursive: true, force: true }));
  return directory;
}
