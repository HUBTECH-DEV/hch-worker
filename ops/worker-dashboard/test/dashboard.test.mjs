import assert from "node:assert/strict";
import { realpathSync } from "node:fs";
import { request as httpRequest } from "node:http";
import test from "node:test";
import {
  mkdir,
  mkdtemp,
  readFile,
  realpath,
  readdir,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { Readable } from "node:stream";
import { deriveBatchProgress } from "../public/batch-progress.js";

test("current batch separates item progress from running item count", () => {
  assert.deepEqual(
    deriveBatchProgress(
      { totalJobs: 1 },
      { jobsRunning: 1 },
      { activeWork: [{ progressPercent: 37 }] },
    ),
    { itemPercent: 37, runningItems: 1, totalItems: 1, itemsPercent: 100 },
  );
  assert.deepEqual(
    deriveBatchProgress(
      { totalJobs: 4 },
      { jobsRunning: 2 },
      { activeWork: [{ progressPercent: 64 }] },
    ),
    { itemPercent: 64, runningItems: 2, totalItems: 4, itemsPercent: 50 },
  );
  assert.deepEqual(
    deriveBatchProgress(null, { jobsRunning: 0 }, null),
    { itemPercent: 0, runningItems: 0, totalItems: 0, itemsPercent: 0 },
  );
});

import {
  aggregateMetrics,
  applyWorkerStatePatch,
  assertNoSecrets,
  defaultMetrics,
  defaultWorkerState,
  parseMetrics,
  parseWorkerState,
} from "../lib/contracts.mjs";
import {
  initializeCollector,
  readCollectorSnapshot,
  recordMetricsEvent,
  runCollectorCli,
  updateWorkerState,
} from "../collector.mjs";
import {
  WORKER_CONTROL_FILE,
  atomicWriteJson,
  safeReadJson,
} from "../lib/storage.mjs";
import {
  buildDashboardStatus,
  operatorControlMatchesWorkerState,
} from "../lib/status.mjs";
import { parseWorkerOperatorControl } from "../lib/operator-control.mjs";
import { deriveWorkerControlView } from "../public/control-state.js";
import {
  executeWorkerControlAction,
  resolveWorkerControlConfig,
  WorkerControlExecutionError,
} from "../lib/control.mjs";
import {
  listenDashboard,
  resolveDashboardConfig,
} from "../server.mjs";
import {
  buildAdaptiveWorkStatus,
  parseAdaptiveWorkSizing,
  parseNativeActiveWork,
} from "../lib/adaptive-work.mjs";
import { compareVersions, createReleaseMonitor } from "../lib/releases.mjs";
import { runUpdateHandoff } from "../../worker-updater/hch-worker-update.mjs";

const T0 = new Date("2026-08-11T21:00:00.000Z");

test("release monitor detects only newer stable semantic releases", async () => {
  const payload = {
    tag_name: "v3.2.0",
    draft: false,
    prerelease: false,
    html_url: "https://github.com/HUBTECH-DEV/hch-worker/releases/tag/v3.2.0",
    published_at: "2026-08-15T12:00:00Z",
    body: "HCH-Worker-Compatibility: compatible\nHCH-Worker-Content-Impact: none\n",
  };
  const monitor = createReleaseMonitor({
    now: new Date("2026-08-15T12:05:00Z"),
    fetchImpl: async () => new Response(JSON.stringify(payload), {
      status: 200,
      headers: { "Content-Type": "application/json" },
    }),
  });
  const outdated = await monitor.snapshot("3.1.0");
  assert.equal(outdated.updateAvailable, true);
  assert.equal(outdated.latestVersion, "3.2.0");
  assert.equal(outdated.channel, "stable");
  assert.equal(outdated.compatibility, "compatible");
  assert.equal(outdated.contentImpact, "none");
  assert.equal((await monitor.snapshot("3.2.0")).updateAvailable, false);
  assert.equal(compareVersions("3.10.0", "3.2.9"), 1);
  assert.equal(compareVersions("3.2.0", "3.2.0-rc.1"), 1);
});

test("release monitor fails closed for absent or malformed releases", async () => {
  const absent = createReleaseMonitor({
    now: T0,
    fetchImpl: async () => new Response(null, { status: 404 }),
  });
  assert.deepEqual(
    await absent.snapshot("3.1.0"),
    {
      repository: "HUBTECH-DEV/hch-worker",
      channel: "stable",
      currentVersion: "3.1.0",
      latestVersion: null,
      updateAvailable: false,
      compatibility: "unspecified",
      contentImpact: "unspecified",
      releaseUrl: null,
      publishedAt: null,
      checkedAt: T0.toISOString(),
      status: "no-release",
      errorCode: null,
    },
  );
  const malformed = createReleaseMonitor({
    now: T0,
    fetchImpl: async () => new Response(JSON.stringify({
      tag_name: "v999",
      draft: false,
      prerelease: false,
      html_url: "https://attacker.invalid/release",
      published_at: "invalid",
    }), { status: 200 }),
  });
  const snapshot = await malformed.snapshot("3.1.0");
  assert.equal(snapshot.updateAvailable, false);
  assert.equal(snapshot.status, "error");
  assert.equal(snapshot.errorCode, "release-version-invalid");
});

test("update handoff invokes only the fixed backend and records a sanitized result", async (t) => {
  const directory = await temporaryDirectory(t);
  const backendRoot = join(directory, "backend");
  const stateDirectory = join(directory, "state");
  await mkdir(backendRoot);
  await mkdir(stateDirectory);
  const backend = join(backendRoot, "hch-worker-update-backend");
  await writeFile(backend, "placeholder\n", "utf8");
  const calls = [];
  const result = await runUpdateHandoff(
    ["apply", "--target-version", "3.2.0"],
    {
      backendRoot: await realpath(backendRoot),
      stateDirectory: await realpath(stateDirectory),
      backend: await realpath(backend),
      execFileImpl(file, args, options, callback) {
        calls.push({ file, args, options });
        queueMicrotask(() => callback(null, "private output", "private error"));
      },
    },
  );
  assert.equal(result.ok, true);
  assert.equal(result.targetVersion, "3.2.0");
  assert.deepEqual(calls.map(({ file, args }) => ({ file, args })), [{
    file: await realpath(backend),
    args: ["apply", "--target-version", "3.2.0"],
  }]);
  assert.equal(calls[0].options.shell, false);
  const status = JSON.parse(await readFile(join(stateDirectory, "worker-release-update.json"), "utf8"));
  assert.equal(status.status, "succeeded");
  assert.equal(status.targetVersion, "3.2.0");
  assert.equal(JSON.stringify(status).includes("private"), false);
  await assert.rejects(
    runUpdateHandoff(["apply", "--target-version", "3.2.0;evil"], {
      backend: await realpath(backend),
      backendRoot: await realpath(backendRoot),
      stateDirectory: await realpath(stateDirectory),
    }),
    /usage:/,
  );
});

test("dashboard reads the native HCH worker status and metrics contracts", async (t) => {
  const directory = await mkdtemp(join(tmpdir(),"hch-native-dashboard-"));
  t.after(() => rm(directory,{ recursive: true,force: true }));
  await writeFile(join(directory,"status.json"),JSON.stringify({
    schema: "hch.worker-status/v1",schemaVersion: 1,
    observedAt: "2026-08-11T21:00:00Z",nodeId: "windows-local-01",
    workerKeyId: "windows-local-key-v1",platform: "windows",kitVersion: "2.0.0",
    state: "processing",running: true,standby: false,ready: true,
    readyUntil: "2026-08-11T22:00:00Z",manifestSequence: 7,manifestHash: "sha256:manifest",
    connection: { api: "connected",tls: "verified",auth: "ed25519",ed25519: true,
      lastSuccessAt: "2026-08-11T21:00:00Z",lastFailureAt: null,lastErrorCode: null },
    transport: { tlsStatus: "verified",certificateStatus: "valid",
      certificateExpiresAt: "2026-12-01T00:00:00Z",certificateFingerprint: "sha256:certificate",
      errorCode: null },
    trust: { status: "verified",rootKeyId: "root-v1",releaseKeyId: "release-v1",
      manifestSequence: 7,manifestHash: "sha256:manifest",policyHash: "sha256:policy",
      lastVerifiedAt: "2026-08-11T21:00:00Z",errorCode: null },
    capacity: { requestedCapacity: 6,grantedCapacity: 4,activeAssignments: 2,
      capacityReason: "pressure-soft-reduction",validUntil: "2026-08-11T21:02:00Z" },
    uptimeSeconds: 3600,
    currentBatch: { batchId: "batch-7",startedAt: "2026-08-11T20:59:00Z",jobs: 2,
      assignmentIds: ["assignment-1","assignment-2"] },code: "ok",
  }),"utf8");
  await writeFile(join(directory,"metrics.json"),JSON.stringify({
    schema: "hch.worker-metrics/v1",schemaVersion: 1,
    observedAt: "2026-08-11T21:00:00Z",nodeId: "windows-local-01",
    workerKeyId: "windows-local-key-v1",uptimeSeconds: 3600,
    resources: {
      cpu: { logicalProcessors: 12,utilizationPercent: 50,totalActiveSeconds: 900,
        sampleCount: 10,averageUtilizationPercent: 25 },
      gpu: { available: true,status: "available",utilizationPercent: 40,totalActiveSeconds: 300,
        sampleCount: 10,averageUtilizationPercent: 20,errorCode: null },
      memory: { totalBytes: 16_000,availableBytes: 8_000,processWorkingSetBytes: 2_000,
        estimatedBytesPerRunningItem: 1_000,
        perItem: { sampleCount: 2,averageBytes: 1_000,peakBytes: 1_200 } },
    },
    network: { receiveBytesPerSecond: 10,sendBytesPerSecond: 5,requestBytes: 1_000,
      responseBytes: 2_000,rxBytes: 10_000,txBytes: 5_000,sourceRxBytes: 10_000,sourceTxBytes: 5_000 },
    batches: { total: 3,completed: 2,failed: 0 },
    jobs: { claimed: 6,running: 2,completed: 4,failed: 0,discarded: 0 },
    updates: { attempts: 1,succeeded: 1,failed: 0,rollbacks: 0 },
    performance: { lastDurationMilliseconds: 500,totalDurationMilliseconds: 2_000,
      durationSamples: 4,averageDurationMilliseconds: 500 },
    standby: { active: false,since: null,totalMilliseconds: 9_000 },
    currentBatch: { batchId: "batch-7",startedAt: "2026-08-11T20:59:00Z",jobs: 2,
      assignmentIds: ["assignment-1","assignment-2"] },
  }),"utf8");
  await writeFile(join(directory,WORKER_CONTROL_FILE),JSON.stringify({
    schema: "hch.worker-control/v1",schemaVersion: 1,nodeId: "windows-local-01",
    acceptingClaims: false,requestedParallelism: 0,lastNonZeroParallelism: 6,
    drainRequested: true,updatedAt: "2026-08-11T21:00:00Z",updatedBy: "stop",
  }),"utf8");
  const status = await buildDashboardStatus(directory,{
    now: new Date("2026-08-11T21:00:01Z"),processStartedAt: T0,
  });
  assert.equal(status.worker.id,"windows-local-01");
  assert.equal(status.connection.status,"connected");
  assert.equal(status.security.transport.certificateStatus,"valid");
  assert.equal(status.resources.cpu.averagePercent,25);
  assert.equal(status.resources.gpu.totalActiveSeconds,300);
  assert.equal(status.resources.memoryPerItem.averageBytes,1_000);
  assert.equal(status.throughput.totalBytes,3_000);
  assert.equal(status.network.rxBytes,10_000);
  assert.equal(status.workload.jobsRunning,2);
  assert.equal(status.workload.currentBatch.totalJobs,2);
  assert.deepEqual(status.capacity,{
    requestedCapacity: 6,grantedCapacity: 4,activeAssignments: 2,
    capacityReason: "pressure-soft-reduction",validUntil: "2026-08-11T21:02:00.000Z",
  });
  assert.deepEqual(status.operatorControl,{
    status: "valid",
    acceptingClaims: false,
    drainRequested: true,
    requestedParallelism: 0,
    lastNonZeroParallelism: 6,
    updatedAt: "2026-08-11T21:00:00.000Z",
  });
  assert.deepEqual(deriveWorkerControlView(status),{
    source: "operator-control",
    mode: "draining",
    acceptingClaims: false,
    drainRequested: true,
    activeAssignments: 2,
    canStart: true,
    canPause: false,
    canStop: true,
    requestedParallelism: 0,
    lastNonZeroParallelism: 6,
  });
  assert.deepEqual(status.alerts,[{
    code: "orchestration-not-reported",
    severity: "warning",
    message: "O worker ainda não publicou o heartbeat de orquestração.",
  }]);

  const failedState = JSON.parse(await readFile(join(directory,"status.json"),"utf8"));
  failedState.state = "connection-error";
  failedState.connection.api = "error";
  failedState.connection.ed25519 = false;
  failedState.connection.auth = "pending";
  failedState.connection.lastFailureAt = "2026-08-11T21:00:01Z";
  failedState.connection.lastErrorCode = "orchestrator-unreachable";
  await writeFile(join(directory,"status.json"),JSON.stringify(failedState),"utf8");
  const failed = await buildDashboardStatus(directory,{
    now: new Date("2026-08-11T21:00:02Z"),processStartedAt: T0,
  });
  assert.equal(failed.worker.state,"error");
  assert.equal(failed.connection.status,"error");
  assert.equal(failed.overall,"critical");
});

test("native worker status preserves identity, security, and capacity across platforms", async (t) => {
  const cases = [
    {
      platform: "windows",
      nodeId: "windows-worker-01",
      workerKeyId: "windows-worker-01-key-v1",
      certificateFingerprint: `sha256:${"a".repeat(64)}`,
      capacity: {
        requestedCapacity: 6,
        grantedCapacity: 4,
        activeAssignments: 2,
        capacityReason: "pressure-soft-reduction",
        validUntil: "2026-08-11T21:02:00Z",
      },
      expectedCapacity: {
        requestedCapacity: 6,
        grantedCapacity: 4,
        activeAssignments: 2,
        capacityReason: "pressure-soft-reduction",
        validUntil: "2026-08-11T21:02:00.000Z",
      },
    },
    {
      platform: "linux",
      nodeId: "linux-worker-01",
      workerKeyId: "linux-worker-01-key-v1",
      certificateFingerprint: `sha256:${"b".repeat(64)}`,
      capacity: {
        requestedCapacity: 8,
        grantedCapacity: 5,
        effectiveGrantedCapacity: 5,
        capacityClass: "standard",
        reason: "pressure-soft-reduction",
        grantedUntil: "2026-08-11T21:02:30Z",
        grantExpired: false,
        pressure: { cpuPercent: 41,memoryPercent: 52,gpuPercent: 18 },
        activeAssignments: 3,
      },
      expectedCapacity: {
        requestedCapacity: 8,
        grantedCapacity: 5,
        activeAssignments: 3,
        capacityReason: "pressure-soft-reduction",
        validUntil: "2026-08-11T21:02:30.000Z",
      },
    },
    {
      platform: "macos",
      nodeId: "mac-worker-01",
      workerKeyId: "mac-worker-01-key-v1",
      certificateFingerprint: `sha256:${"c".repeat(64)}`,
      capacity: {
        requestedCapacity: 1,
        grantedCapacity: 1,
        effectiveGrantedCapacity: 1,
        capacityClass: "constrained",
        reason: "capacity-granted",
        grantedUntil: "2026-08-11T21:03:00Z",
        grantExpired: false,
        pressure: { cpuPercent: 12,memoryPercent: 39,gpuPercent: 0 },
        activeAssignments: 0,
      },
      expectedCapacity: {
        requestedCapacity: 1,
        grantedCapacity: 1,
        activeAssignments: 0,
        capacityReason: "capacity-granted",
        validUntil: "2026-08-11T21:03:00.000Z",
      },
    },
  ];

  for (const fixture of cases) {
    await t.test(fixture.platform, async (t) => {
      const directory = await mkdtemp(join(tmpdir(),`hch-${fixture.platform}-status-`));
      t.after(() => rm(directory,{ recursive: true,force: true }));
      await writeFile(join(directory,"status.json"),JSON.stringify({
        schema: "hch.worker-status/v1",
        schemaVersion: 1,
        observedAt: "2026-08-11T21:00:00Z",
        nodeId: fixture.nodeId,
        workerKeyId: fixture.workerKeyId,
        platform: fixture.platform,
        kitVersion: "2.1.0",
        state: "ready",
        running: false,
        standby: true,
        ready: true,
        readyUntil: "2026-08-11T22:00:00Z",
        manifestSequence: 8,
        manifestHash: `sha256:${"d".repeat(64)}`,
        connection: {
          api: "connected",
          tls: "verified",
          auth: "ed25519",
          ed25519: true,
          lastSuccessAt: "2026-08-11T21:00:00Z",
          lastFailureAt: null,
          lastErrorCode: null,
        },
        transport: {
          tlsStatus: "verified",
          certificateStatus: "valid",
          certificateExpiresAt: "2027-08-11T21:00:00Z",
          certificateFingerprint: fixture.certificateFingerprint,
          errorCode: null,
        },
        trust: {
          status: "verified",
          rootKeyId: "hch-root-v2",
          releaseKeyId: "hch-release-v3",
          manifestSequence: 8,
          manifestHash: `sha256:${"d".repeat(64)}`,
          policyHash: `sha256:${"e".repeat(64)}`,
          lastVerifiedAt: "2026-08-11T21:00:00Z",
          errorCode: null,
        },
        capacity: fixture.capacity,
        uptimeSeconds: 600,
        currentBatch: null,
        code: "ready",
      }),"utf8");

      const status = await buildDashboardStatus(directory,{
        now: new Date("2026-08-11T21:00:01Z"),
        processStartedAt: T0,
      });
      assert.equal(status.worker.id,fixture.nodeId);
      assert.equal(status.worker.platform,fixture.platform);
      assert.equal(status.security.authentication.status,"authenticated");
      assert.equal(status.security.authentication.keyId,fixture.workerKeyId);
      assert.equal(status.security.transport.tlsStatus,"valid");
      assert.equal(status.security.transport.certificateStatus,"valid");
      assert.equal(
        status.security.transport.certificateFingerprint,
        fixture.certificateFingerprint,
      );
      assert.equal(status.security.ed25519Chain.status,"valid");
      assert.equal(status.security.ed25519Chain.rootKeyId,"hch-root-v2");
      assert.equal(status.security.ed25519Chain.releaseKeyId,"hch-release-v3");
      assert.deepEqual(status.capacity,fixture.expectedCapacity);
      assert.notEqual(status.worker.id,"unconfigured");
    });
  }
});

test("adaptive work telemetry is normalized across Windows, Linux, and macOS without content", async (t) => {
  const cases = [
    {
      platform: "windows",
      nodeId: "windows-worker-01",
      nativeTelemetry: {
        progress: adaptiveProgress({ assignmentId: "assignment-windows-01" }),
      },
      expectedStatus: "responding-slowly",
      expectedTier: null,
    },
    {
      platform: "linux",
      nodeId: "linux-worker-01",
      nativeTelemetry: {
        activeWork: [adaptiveActiveWork({
          assignmentId: "assignment-linux-01",
          nodeId: "linux-worker-01",
        })],
      },
      expectedStatus: "responding-slowly",
      expectedTier: "full",
    },
    {
      platform: "macos",
      nodeId: "mac-worker-01",
      nativeTelemetry: {
        activeWork: [adaptiveActiveWork({
          assignmentId: "assignment-macos-01",
          nodeId: "mac-worker-01",
          progressAt: "2026-08-11T21:20:00Z",
          livenessState: "stalled",
          livenessReason: "progress-stalled",
        })],
      },
      expectedStatus: "stalled",
      expectedTier: "full",
    },
  ];

  for (const fixture of cases) {
    await t.test(fixture.platform, async (t) => {
      const directory = await temporaryDirectory(t);
      await writeFile(
        join(directory, "status.json"),
        JSON.stringify(adaptiveWorkerStatus(fixture)),
        "utf8",
      );
      await writeFile(
        join(directory, "orchestration.json"),
        JSON.stringify(adaptiveOrchestration(fixture.nodeId)),
        "utf8",
      );

      const status = await buildDashboardStatus(directory, {
        now: new Date("2026-08-11T21:40:00Z"),
        processStartedAt: T0,
      });
      assert.equal(status.worker.platform, fixture.platform);
      assert.equal(status.adaptiveWork.available, true);
      assert.equal(status.adaptiveWork.workSizing.currentTier, "compact");
      assert.equal(status.adaptiveWork.workSizing.maxOutputTokens, 1_536);
      assert.equal(status.adaptiveWork.workSizing.nearWindowSeconds, 2_160);
      assert.equal(status.adaptiveWork.workSizing.processingWindowSeconds, 2_700);
      assert.equal(status.adaptiveWork.workSizing.minimumUnit, false);
      assert.equal(status.adaptiveWork.workSizing.downshiftReason, "near-window-downshift");
      assert.equal(status.orchestration.workSizing.reason, "near-window-downshift");
      assert.equal(Object.hasOwn(status.orchestration.workSizing, "downshiftReason"), false);
      assert.equal(status.adaptiveWork.activeWork.length, 1);
      assert.equal(status.adaptiveWork.activeWork[0].elapsedSeconds, 2_400);
      assert.equal(status.adaptiveWork.activeWork[0].phase, "responding");
      assert.equal(status.adaptiveWork.activeWork[0].lastProgressAt, fixture.platform === "macos"
        ? "2026-08-11T21:20:00.000Z"
        : "2026-08-11T21:39:00.000Z");
      assert.equal(status.adaptiveWork.activeWork[0].livenessStatus, fixture.expectedStatus);
      assert.equal(status.adaptiveWork.activeWork[0].tier, fixture.expectedTier);

      const publicBody = JSON.stringify(status.adaptiveWork);
      assert.doesNotMatch(publicBody, /contentBytes|generationPlanHash|leaseExpiresAt|prompt|draft/i);
      assert.match(publicBody, /maxOutputTokens/);
      assert.ok(status.alerts.some((alert) =>
        alert.code === (fixture.expectedStatus === "stalled"
          ? "adaptive-work-stalled"
          : "adaptive-work-responding-slowly")));
    });
  }
});

test("adaptive liveness keeps the advisory window distinct from a stall", () => {
  const minimumSizing = parseAdaptiveWorkSizing(adaptiveSizing({
    currentTier: "minimum",
    currentRank: 0,
    maxOutputTokens: 768,
    editorialProfile: "minimum-editorial",
    minimumUnit: true,
    reason: "minimum-unit-window-ignored",
  }));
  const activeWork = parseNativeActiveWork([
    adaptiveActiveWork({
      assignmentId: "assignment-minimum-01",
      nodeId: "mac-worker-01",
      tier: "minimum",
      tierRank: 0,
      maxOutputTokens: 768,
      claimedAt: "2026-08-11T20:00:00Z",
      progressAt: "2026-08-11T20:59:30Z",
      windowState: "ignored-at-minimum",
    }),
  ], { nodeId: "mac-worker-01" });
  const reduced = buildAdaptiveWorkStatus({
    now: new Date("2026-08-11T21:00:00Z"),
    workSizing: minimumSizing,
    activeWork,
  });
  assert.equal(reduced.activeWork[0].elapsedSeconds, 3_600);
  assert.equal(reduced.activeWork[0].windowState, "ignored-at-minimum");
  assert.equal(reduced.activeWork[0].minimumUnit, true);
  assert.equal(reduced.activeWork[0].livenessStatus, "progressing");

  assert.throws(
    () => parseNativeActiveWork([{
      ...adaptiveActiveWork({ nodeId: "mac-worker-01" }),
      content: "never expose this",
    }], { nodeId: "mac-worker-01" }),
    /fields are invalid/,
  );
  assert.throws(
    () => parseAdaptiveWorkSizing(adaptiveSizing({ updatedAt: 0 })),
    /workSizing.updatedAt is invalid/,
  );
  assert.doesNotThrow(() => assertNoSecrets({ maxOutputTokens: 768 }));
});

test("worker state patches are strict, normalized, and secret-free", () => {
  const initial = defaultWorkerState(T0);
  const updated = applyWorkerStatePatch(
    initial,
    {
      worker: {
        id: "windows-worker-01",
        displayName: "Windows editorial 01",
        state: "ready",
        version: "2.0.0",
        platform: "win32-x64",
        startedAt: "2026-08-11T20:55:00Z",
      },
      connection: {
        status: "connected",
        lastSuccessAt: "2026-08-11T21:00:05Z",
      },
    },
    new Date("2026-08-11T21:00:06Z"),
  );
  assert.equal(updated.revision, 1);
  assert.equal(updated.worker.state, "ready");
  assert.equal(updated.worker.startedAt, "2026-08-11T20:55:00.000Z");
  assert.equal(updated.connection.status, "connected");
  assert.equal(updated.connection.errorCode, null);
  assert.deepEqual(parseWorkerState(updated), updated);

  assert.throws(
    () => applyWorkerStatePatch(initial, { authentication: { authToken: "no" } }),
    /Forbidden secret-bearing field/,
  );
  assert.throws(
    () => applyWorkerStatePatch(initial, { worker: { remoteAddress: "203.0.113.1" } }),
    /unsupported field/,
  );
  assert.throws(
    () => assertNoSecrets({ nested: { privateKeyPem: "no" } }),
    /Forbidden secret-bearing field/,
  );
});

test("event aggregation calculates resources, workload, volume, network, and standby", () => {
  let metrics = defaultMetrics(T0);
  const apply = (event, now = event.occurredAt) => {
    const result = aggregateMetrics(metrics, event, new Date(now));
    metrics = result.metrics;
    return result;
  };

  apply(event("resource-01", "2026-08-11T21:00:01Z", "resource.sample", {
    cpuPercent: 20,
    cpuSecondsDelta: 1.5,
    gpu: {
      status: "available",
      utilizationPercent: 40,
      activeSecondsDelta: 1,
      errorCode: null,
    },
    networkRxBytesDelta: 100,
    networkTxBytesDelta: 50,
  }));
  apply(event("resource-02", "2026-08-11T21:00:02Z", "resource.sample", {
    cpuPercent: 60,
    cpuSecondsDelta: 2.5,
    gpu: {
      status: "available",
      utilizationPercent: 80,
      activeSecondsDelta: 2,
      errorCode: null,
    },
    networkRxBytesDelta: 300,
    networkTxBytesDelta: 150,
  }));
  apply(event("batch-start-01", "2026-08-11T21:00:03Z", "batch.started", {
    batchId: "batch-01",
    totalJobs: 2,
  }));
  apply(event("job-start-01", "2026-08-11T21:00:04Z", "job.started", {
    jobId: "job-01",
    batchId: "batch-01",
    inputBytes: 1_000,
  }));
  apply(event("job-start-02", "2026-08-11T21:00:05Z", "job.started", {
    jobId: "job-02",
    batchId: "batch-01",
    inputBytes: 2_000,
  }));
  apply(event("job-complete-01", "2026-08-11T21:00:10Z", "job.completed", {
    jobId: "job-01",
    batchId: "batch-01",
    outcome: "succeeded",
    durationMilliseconds: 10_000,
    memoryAverageBytes: 100,
    memoryPeakBytes: 200,
    outputBytes: 300,
  }));
  const completion = event("job-complete-02", "2026-08-11T21:00:20Z", "job.completed", {
    jobId: "job-02",
    batchId: "batch-01",
    outcome: "failed",
    durationMilliseconds: 30_000,
    memoryAverageBytes: 300,
    memoryPeakBytes: 400,
    outputBytes: 700,
  });
  apply(completion);
  apply(event("batch-complete-01", "2026-08-11T21:00:21Z", "batch.completed", {
    batchId: "batch-01",
  }));
  apply(event("standby-01", "2026-08-11T21:00:22Z", "standby.changed", {
    active: true,
  }));

  assert.equal(metrics.cpu.totalSeconds, 4);
  assert.equal(metrics.cpu.averagePercent, 40);
  assert.equal(metrics.gpu.status, "available");
  assert.equal(metrics.gpu.totalActiveSeconds, 3);
  assert.equal(metrics.gpu.averagePercent, 60);
  assert.equal(metrics.network.rxBytes, 400);
  assert.equal(metrics.network.txBytes, 200);
  assert.equal(metrics.memoryPerItem.averageBytes, 200);
  assert.equal(metrics.memoryPerItem.peakBytes, 400);
  assert.equal(metrics.processingTime.averageMilliseconds, 20_000);
  assert.deepEqual(metrics.volume, {
    inputBytes: 3_000,
    outputBytes: 1_000,
    totalBytes: 4_000,
  });
  assert.equal(metrics.workload.batchesTotal, 1);
  assert.equal(metrics.workload.batchesCompleted, 1);
  assert.equal(metrics.workload.jobsTotal, 2);
  assert.equal(metrics.workload.jobsCompleted, 2);
  assert.equal(metrics.workload.jobsSucceeded, 1);
  assert.equal(metrics.workload.jobsFailed, 1);
  assert.equal(metrics.workload.jobsRunning, 0);
  assert.equal(metrics.workload.currentBatch, null);
  assert.equal(metrics.standby.active, true);

  const duplicate = aggregateMetrics(metrics, completion, T0);
  assert.equal(duplicate.duplicate, true);
  assert.deepEqual(duplicate.metrics, metrics);
  assert.deepEqual(parseMetrics(metrics), metrics);
});

test("GPU unavailable, unsupported, and error remain distinct", () => {
  for (const [index, status] of ["unavailable", "unsupported", "error"].entries()) {
    const result = aggregateMetrics(
      defaultMetrics(T0),
      event(`gpu-state-${index}`, "2026-08-11T21:00:01Z", "resource.sample", {
        cpuPercent: 0,
        cpuSecondsDelta: 0,
        gpu: {
          status,
          utilizationPercent: null,
          activeSecondsDelta: 0,
          errorCode: status === "error" ? "gpu-probe-failed" : null,
        },
        networkRxBytesDelta: 0,
        networkTxBytesDelta: 0,
      }),
      T0,
    );
    assert.equal(result.metrics.gpu.status, status);
    assert.equal(result.metrics.gpu.averagePercent, null);
    assert.equal(result.metrics.gpu.errorCode, status === "error" ? "gpu-probe-failed" : null);
  }
});

test("collector serializes concurrent writers and leaves only complete JSON snapshots", async (t) => {
  const directory = await temporaryDirectory(t);
  await initializeCollector({ dataDirectory: directory });
  await updateWorkerState(
    {
      worker: {
        id: "vps-worker-01",
        displayName: "VPS editorial",
        state: "processing",
        version: "2.0.0",
        platform: "linux-x64",
        startedAt: T0.toISOString(),
      },
    },
    { dataDirectory: directory, now: T0 },
  );

  await Promise.all(
    Array.from({ length: 20 }, (_, index) =>
      recordMetricsEvent(
        {
          eventId: `concurrent-${String(index).padStart(3, "0")}`,
          occurredAt: new Date(T0.getTime() + index * 1_000).toISOString(),
          type: "resource.sample",
          data: {
            cpuPercent: 25,
            cpuSecondsDelta: 0.5,
            gpu: {
              status: "unsupported",
              utilizationPercent: null,
              activeSecondsDelta: 0,
              errorCode: null,
            },
            networkRxBytesDelta: 10,
            networkTxBytesDelta: 5,
          },
        },
        { dataDirectory: directory, now: new Date(T0.getTime() + 30_000) },
      ),
    ),
  );
  const snapshot = await readCollectorSnapshot({ dataDirectory: directory });
  assert.equal(snapshot.state.ok, true);
  assert.equal(snapshot.metrics.ok, true);
  assert.equal(snapshot.metrics.value.eventsAccepted, 20);
  assert.equal(snapshot.metrics.value.cpu.totalSeconds, 10);
  assert.equal(snapshot.metrics.value.cpu.averagePercent, 25);
  assert.equal(snapshot.metrics.value.network.rxBytes, 200);
  assert.equal(snapshot.metrics.value.network.txBytes, 100);
  const files = await readdir(directory);
  assert.deepEqual(files.sort(), ["metrics.json", "orchestration.json", "state.json"]);
  const persistedMetrics = await readFile(join(directory, "metrics.json"), "utf8");
  assert.doesNotThrow(() => JSON.parse(persistedMetrics));
});

test("collector CLI supports stdin and rejects secret-bearing input", async (t) => {
  const directory = await temporaryDirectory(t);
  const initOutput = captureStream();
  assert.equal(
    await runCollectorCli(
      ["init", "--data-dir", directory],
      { stdout: initOutput, stderr: captureStream(), stdin: Readable.from([]) },
    ),
    0,
  );
  assert.equal(JSON.parse(initOutput.text).initialized, true);

  const stateOutput = captureStream();
  const patch = JSON.stringify({ worker: { state: "standby" } });
  assert.equal(
    await runCollectorCli(
      ["state", "--data-dir", directory, "--stdin"],
      { stdout: stateOutput, stderr: captureStream(), stdin: Readable.from([patch]) },
    ),
    0,
  );
  assert.equal(JSON.parse(stateOutput.text).revision, 1);

  const errorOutput = captureStream();
  assert.equal(
    await runCollectorCli(
      ["state", "--data-dir", directory, "--json", '{"worker":{"apiToken":"no"}}'],
      { stdout: captureStream(), stderr: errorOutput, stdin: Readable.from([]) },
    ),
    1,
  );
  assert.match(errorOutput.text, /Forbidden secret-bearing field/);
  assert.doesNotMatch(errorOutput.text, /"no"/);
});

test("dashboard serves an accessible page and a no-store status API", async (t) => {
  const directory = await temporaryDirectory(t);
  await initializeCollector({ dataDirectory: directory });
  await updateWorkerState(healthyStatePatch(), {
    dataDirectory: directory,
    now: new Date("2026-08-11T21:01:00Z"),
  });
  await recordMetricsEvent(
    {
      eventId: "server-sample-01",
      occurredAt: "2026-08-11T21:01:01Z",
      type: "resource.sample",
      data: {
        cpuPercent: 42,
        cpuSecondsDelta: 3,
        gpu: {
          status: "unsupported",
          utilizationPercent: null,
          activeSecondsDelta: 0,
          errorCode: null,
        },
        networkRxBytesDelta: 1_000,
        networkTxBytesDelta: 500,
      },
    },
    { dataDirectory: directory, now: new Date("2026-08-11T21:01:01Z") },
  );

  const running = await listenDashboard({
    host: "127.0.0.1",
    port: 0,
    dataDirectory: directory,
    releaseFetch: async () => new Response(null, { status: 404 }),
    now: new Date("2026-08-11T21:01:05Z"),
    processStartedAt: new Date("2026-08-11T21:00:55Z"),
  });
  t.after(() => new Promise((resolvePromise) => running.server.close(resolvePromise)));
  const base = `http://127.0.0.1:${running.address.port}`;

  const statusResponse = await fetch(`${base}/api/status`);
  assert.equal(statusResponse.status, 200);
  assert.equal(statusResponse.headers.get("cache-control"), "no-store, max-age=0");
  assert.equal(statusResponse.headers.get("pragma"), "no-cache");
  assert.equal(statusResponse.headers.get("expires"), "0");
  assert.match(statusResponse.headers.get("content-security-policy"), /frame-ancestors 'none'/);
  const status = await statusResponse.json();
  assert.equal(status.overall, "warning");
  assert.equal(status.worker.id, "windows-worker-01");
  assert.equal(status.worker.uptimeSeconds, 65);
  assert.equal(status.connection.status, "connected");
  assert.equal(status.security.ed25519Chain.status, "valid");
  assert.equal(status.resources.cpu.averagePercent, 42);
  assert.equal(status.resources.gpu.status, "unsupported");
  assert.equal(status.network.rxBytes, 1_000);
  assert.deepEqual(status.alerts, [{
    code: "orchestration-heartbeat-not-confirmed",
    severity: "warning",
    message: "Nenhum heartbeat autenticado foi confirmado pela VPS.",
  }]);
  assert.deepEqual(status.control, {
    available: false,
    updateEnabled: false,
    busy: false,
    lastAction: null,
    lastActionAt: null,
    lastOutcome: null,
    lastErrorCode: null,
    csrfToken: null,
  });
  assert.deepEqual(status.operatorControl, {
    status: "not-reported",
    acceptingClaims: null,
    drainRequested: null,
    requestedParallelism: null,
    lastNonZeroParallelism: null,
    updatedAt: null,
  });
  assert.equal(JSON.stringify(status).includes(directory), false);

  const pageResponse = await fetch(base);
  const html = await pageResponse.text();
  assert.equal(pageResponse.status, 200);
  assert.match(html, /<main id="main">/);
  assert.match(html, /aria-live="polite"/);
  assert.match(html, /<progress id="batch-progress"/);
  assert.match(html, /<progress id="batch-items-progress"/);
  assert.match(html, /id="batch-item-percent">0%/);
  assert.match(html, /Memória média\/item/);
  assert.match(html, /id="control-start"[^>]*>\s*Iniciar processamento/);
  assert.match(html, /id="control-pause"[^>]*>\s*Pausar processamento/);
  assert.match(html, /id="control-stop"[^>]*>\s*Parar e cancelar ativos/);
  assert.match(html, /id="control-parallelism"[^>]*min="0"[^>]*max="64"/);
  assert.match(html, /id="control-feedback"[^>]*role="status"/);
  assert.match(html, /<dialog id="control-confirmation"/);
  assert.match(html, /id="adaptive-work-title"/);
  assert.match(html, /id="adaptive-tier"/);
  assert.match(html, /id="adaptive-token-ceiling"/);
  assert.match(html, /id="adaptive-work-list"[^>]*aria-live="polite"/);
  assert.match(html, /Motivo do downshift/);
  assert.match(html, /nenhuma credencial ou conteúdo editorial é exibido/);
  assert.match(html, /<script src="\/app\.js" type="module"><\/script>/);
  assert.match(html, /mantém cada assignment ativo até heartbeat e finalização seguros/);
  assert.doesNotMatch(html, /<script[^>]*>\s*[^<]/);

  const postResponse = await fetch(`${base}/api/status`, { method: "POST" });
  assert.equal(postResponse.status, 405);
  assert.equal(postResponse.headers.get("allow"), "GET, HEAD");
});

test("operator control has a strict read-only contract", async (t) => {
  const directory = await temporaryDirectory(t);
  const record = {
    schema: "hch.worker-control/v1",
    schemaVersion: 1,
    nodeId: "windows-worker-01",
    acceptingClaims: false,
    requestedParallelism: 0,
    lastNonZeroParallelism: 4,
    drainRequested: true,
    updatedAt: "2026-08-11T21:00:00Z",
    updatedBy: "stop",
  };
  await writeFile(join(directory, WORKER_CONTROL_FILE), JSON.stringify(record), "utf8");
  const read = await safeReadJson(
    directory,
    WORKER_CONTROL_FILE,
    parseWorkerOperatorControl,
  );
  assert.equal(read.ok, true);
  assert.equal(read.value.acceptingClaims, false);
  assert.equal(read.value.drainRequested, true);
  assert.equal("updatedBy" in read.value, false);
  await assert.rejects(
    atomicWriteJson(directory, WORKER_CONTROL_FILE, record),
    /Unsupported dashboard data file/,
  );
  assert.throws(
    () => parseWorkerOperatorControl({ ...record, command: "start" }),
    /fields are invalid/,
  );
  assert.throws(
    () => parseWorkerOperatorControl({
      ...record,
      acceptingClaims: true,
      drainRequested: true,
    }),
    /state is inconsistent/,
  );
  assert.equal(deriveWorkerControlView({
    operatorControl: { status: "not-reported" },
    capacity: { requestedCapacity: 3, activeAssignments: 0 },
  }).mode, "active");
  assert.equal(deriveWorkerControlView({
    operatorControl: { status: "invalid" },
    capacity: { requestedCapacity: 3, activeAssignments: 0 },
  }).mode, "invalid");

  const portable = parseWorkerOperatorControl({
    schema: "hch.worker-control/v1",
    schemaVersion: 1,
    nodeId: "mac-worker-01",
    workerKeyId: "mac-worker-01-key-v1",
    acceptingClaims: true,
    requestedCapacity: 1,
    lastNonZeroCapacity: 1,
    drainRequested: false,
    updatedAt: "2026-08-11T21:00:00Z",
    updatedBy: "dashboard-start",
  });
  assert.deepEqual(portable, {
    nodeId: "mac-worker-01",
    workerKeyId: "mac-worker-01-key-v1",
    acceptingClaims: true,
    drainRequested: false,
    requestedParallelism: 1,
    lastNonZeroParallelism: 1,
    updatedAt: "2026-08-11T21:00:00.000Z",
  });

  const state = {
    worker: { id: "mac-worker-01" },
    authentication: { keyId: "mac-worker-01-key-v1" },
  };
  assert.equal(operatorControlMatchesWorkerState(portable, state), true);
  assert.equal(operatorControlMatchesWorkerState({
    ...portable,
    workerKeyId: "mac-worker-01-key-v2",
  }, state), false);
});

test("worker control executes only the fixed PowerShell file contract", async (t) => {
  const fixture = await controlFixture(t);
  const config = resolveWorkerControlConfig({
    ...fixture,
    controlTimeoutMilliseconds: "75000",
    controlPlaneTimeoutSeconds: "15",
  });
  const calls = [];
  const execFileImpl = (file, args, options, callback) => {
    calls.push({ file, args, options });
    queueMicrotask(() => callback(null, "ignored-output", "ignored-diagnostic"));
  };

  assert.deepEqual(
    await executeWorkerControlAction(config, "start", { execFileImpl }),
    { ok: true, action: "start", requestedState: "starting" },
  );
  assert.deepEqual(
    await executeWorkerControlAction(config, "stop", { execFileImpl }),
    { ok: true, action: "stop", requestedState: "stopping" },
  );
  assert.deepEqual(
    await executeWorkerControlAction(config, { action: "set-parallelism", parallelism: 3 }, { execFileImpl }),
    { ok: true, action: "set-parallelism", requestedState: "parallelism-updating", parallelism: 3 },
  );
  assert.equal(calls.length, 3);
  for (const [index, call] of calls.entries()) {
    assert.equal(call.file, fixture.powershellPath);
    assert.deepEqual(call.args, [
      "-NoLogo",
      "-NoProfile",
      "-NonInteractive",
      "-ExecutionPolicy",
      "RemoteSigned",
      "-File",
      fixture.workerCliPath,
       index === 0 ? "start" : index === 1 ? "stop" : "set-parallelism",
      "-ConfigPath",
      fixture.workerConfigPath,
      "-ControlPlaneTimeoutSeconds",
      "15",
      ...(index === 2 ? ["-Parallelism", "3"] : []),
    ]);
    assert.equal(call.options.shell, false);
    assert.equal(call.options.windowsHide, true);
    assert.equal(call.options.cwd, fixture.kitDirectory);
    assert.equal(call.options.timeout, 75_000);
    assert.equal(call.args.includes("-Command"), false);
  }

  await assert.rejects(
    executeWorkerControlAction(config, "configure", { execFileImpl }),
    (error) => error instanceof WorkerControlExecutionError &&
      error.code === "worker-control-action-invalid",
  );
  assert.equal(calls.length, 3);
  await assert.rejects(
    executeWorkerControlAction(config, "start", {
      execFileImpl(_file, _args, _options, callback) {
        const timeout = new Error("private timeout detail");
        timeout.killed = true;
        queueMicrotask(() => callback(timeout, "private stdout", "private stderr"));
      },
    }),
    (error) => error instanceof WorkerControlExecutionError &&
      error.code === "worker-control-timeout" && !error.message.includes("private"),
  );
  assert.throws(
    () => resolveWorkerControlConfig({ workerCliPath: fixture.workerCliPath }),
    /requires fixed CLI, config, PowerShell, and trusted-root paths/,
  );
  assert.throws(
    () => resolveWorkerControlConfig({
      ...fixture,
      workerConfigPath: "relative.psd1",
    }),
    /absolute/,
  );
  assert.throws(
    () => resolveWorkerControlConfig({
      ...fixture,
      workerCliPath: join(fixture.kitDirectory, "missing", "Hch-Worker.ps1"),
    }),
    /unavailable/,
  );

  const outsideCliDirectory = join(dirname(fixture.kitDirectory), "untrusted-kit");
  await mkdir(outsideCliDirectory);
  const outsideCli = join(outsideCliDirectory, "Hch-Worker.ps1");
  await writeFile(outsideCli, "param([string]$Command)\n", "utf8");
  assert.throws(
    () => resolveWorkerControlConfig({
      ...fixture,
      workerCliPath: outsideCli,
    }),
    /outside its trusted directory/,
  );

  const linkedKit = join(fixture.kitDirectory, "linked");
  await mkdir(linkedKit);
  const linkedCli = join(linkedKit, "Hch-Worker.ps1");
  try {
    await symlink(fixture.workerCliPath, linkedCli, "file");
    assert.throws(
      () => resolveWorkerControlConfig({
        ...fixture,
        workerCliPath: linkedCli,
        workerCliRootPath: linkedKit,
      }),
      /canonical regular file/,
    );
  } catch (error) {
    if (error?.code === "EPERM" || error?.code === "EACCES") {
      t.diagnostic("This Windows configuration does not permit creating control-path symlinks.");
    } else {
      throw error;
    }
  }
});

test("fixed Node.js worker control executes only the canonical local script", async (t) => {
  const directory = await temporaryDirectory(t);
  const scriptDirectory = join(directory, "control");
  await mkdir(scriptDirectory, { recursive: true });
  const controlScriptPath = join(scriptDirectory, "hch-worker-control.mjs");
  const updateScriptPath = join(scriptDirectory, "hch-worker-update.mjs");
  await writeFile(controlScriptPath, "export {};\n", "utf8");
  await writeFile(updateScriptPath, "export {};\n", "utf8");
  const options = {
    driver: "fixed-node-script",
    controlScriptPath: await realpath(controlScriptPath),
    controlScriptRootPath: await realpath(scriptDirectory),
    updateScriptPath: await realpath(updateScriptPath),
    updateScriptRootPath: await realpath(scriptDirectory),
    controlTimeoutMilliseconds: 10_000,
  };
  const config = resolveWorkerControlConfig(options);
  const calls = [];
  const execFileImpl = (file, args, execOptions, callback) => {
    calls.push({ file, args, options: execOptions });
    queueMicrotask(() => callback(null, "ignored", "ignored"));
  };

  assert.deepEqual(
    await executeWorkerControlAction(config, "start", { execFileImpl }),
    { ok: true, action: "start", requestedState: "starting" },
  );
  assert.deepEqual(
    await executeWorkerControlAction(config, "stop", { execFileImpl }),
    { ok: true, action: "stop", requestedState: "stopping" },
  );
  assert.deepEqual(
    await executeWorkerControlAction(config, { action: "set-parallelism", parallelism: 6 }, { execFileImpl }),
    { ok: true, action: "set-parallelism", requestedState: "parallelism-updating", parallelism: 6 },
  );
  assert.deepEqual(
    await executeWorkerControlAction(config, { action: "update", targetVersion: "3.2.0" }, { execFileImpl }),
    { ok: true, action: "update", requestedState: "updating" },
  );
  assert.deepEqual(calls.map((call) => call.args), [
    ["--", options.controlScriptPath, "start"],
    ["--", options.controlScriptPath, "stop"],
    ["--", options.controlScriptPath, "set-parallelism", "6"],
    ["--", options.updateScriptPath, "apply", "--target-version", "3.2.0"],
  ]);
  for (const call of calls) {
    assert.equal(call.file, realpathSync(process.execPath));
    assert.equal(call.options.shell, false);
    assert.equal(call.options.cwd, options.controlScriptRootPath);
    assert.deepEqual(call.options.env, {
      PATH: "/usr/bin:/bin:/usr/sbin:/sbin",
      LANG: "C",
      LC_ALL: "C",
    });
    assert.ok(call.args.length === 3 || call.args.length === 4 || call.args.length === 5);
  }
  const wrongScript = join(scriptDirectory, "worker.mjs");
  await writeFile(wrongScript, "export {};\n", "utf8");
  assert.throws(
    () => resolveWorkerControlConfig({
      ...options,
      controlScriptPath: realpathSync(wrongScript),
    }),
    /canonical regular file|hch-worker-control\.mjs/,
  );
});

test("control API enforces same-origin CSRF and never exposes command output", async (t) => {
  const fixture = await controlFixture(t);
  const calls = [];
  const running = await listenDashboard({
    host: "127.0.0.1",
    port: 0,
    dataDirectory: fixture.dataDirectory,
    releaseFetch: async () => new Response(null, { status: 404 }),
    ...fixture,
    controlCsrfToken: "A".repeat(43),
    controlExecFile(file, args, options, callback) {
      calls.push({ file, args, options });
      queueMicrotask(() => callback(null, "stdout-secret-value", "C:\\private\\worker-path"));
    },
  });
  t.after(() => new Promise((resolvePromise) => running.server.close(resolvePromise)));
  const base = `http://127.0.0.1:${running.address.port}`;

  const contractResponse = await fetch(`${base}/api/control`, {
    headers: { Accept: "application/json" },
  });
  assert.equal(contractResponse.status, 200);
  assert.equal(contractResponse.headers.get("cache-control"), "no-store, max-age=0");
  const contract = await contractResponse.json();
  assert.equal(contract.available, true);
  assert.equal(contract.csrfToken, "A".repeat(43));

  const missingOrigin = await fetch(`${base}/api/control`, {
    method: "POST",
    headers: {
      Accept: "application/json",
      "Content-Type": "application/json",
      "Sec-Fetch-Site": "same-origin",
      "X-HCH-CSRF-Token": contract.csrfToken,
    },
    body: JSON.stringify({ action: "start" }),
  });
  assert.equal(missingOrigin.status, 400);
  assert.equal(calls.length, 0);

  const wrongMedia = await postControl(base, contract.csrfToken, { action: "start" }, {
    "Content-Type": "text/plain",
  });
  assert.equal(wrongMedia.status, 415);

  const crossOrigin = await postControl(base, contract.csrfToken, { action: "start" }, {
    Origin: `http://localhost:${running.address.port}`,
  });
  assert.equal(crossOrigin.status, 403);

  const crossSite = await postControl(base, contract.csrfToken, { action: "start" }, {
    "Sec-Fetch-Site": "cross-site",
  });
  assert.equal(crossSite.status, 403);

  const wrongCsrf = await postControl(base, "B".repeat(43), { action: "start" });
  assert.equal(wrongCsrf.status, 403);

  const extraField = await postControl(base, contract.csrfToken, {
    action: "start",
    command: "anything",
  });
  assert.equal(extraField.status, 400);

  const unsupportedAction = await postControl(base, contract.csrfToken, { action: "configure" });
  assert.equal(unsupportedAction.status, 400);

  const noReleaseUpdate = await postControl(base, contract.csrfToken, { action: "update" });
  assert.equal(noReleaseUpdate.status, 409);
  assert.equal((await noReleaseUpdate.json()).error, "worker-update-not-available");
  assert.equal(calls.length, 0);

  const malformed = await postControl(base, contract.csrfToken, "{");
  assert.equal(malformed.status, 400);

  const oversized = await postControl(base, contract.csrfToken, "x".repeat(129));
  assert.equal(oversized.status, 413);
  assert.equal(calls.length, 0);

  const started = await postControl(base, contract.csrfToken, { action: "start" });
  assert.equal(started.status, 200);
  const startedText = await started.text();
  assert.doesNotMatch(startedText, /stdout-secret-value|private|worker-path/i);
  assert.equal(JSON.parse(startedText).requestedState, "starting");

  const stopped = await postControl(base, contract.csrfToken, { action: "stop" });
  assert.equal(stopped.status, 200);
  assert.equal((await stopped.json()).requestedState, "stopping");
  const parallel = await postControl(base, contract.csrfToken, {
    action: "set-parallelism", parallelism: 4,
  });
  assert.equal(parallel.status, 200);
  assert.equal((await parallel.json()).parallelism, 4);
  assert.equal(calls.length, 3);
  assert.equal(calls[0].args.includes("start"), true);
  assert.equal(calls[1].args.includes("stop"), true);
  assert.equal(calls[2].args.includes("4"), true);

  const status = await (await fetch(`${base}/api/status`)).json();
  assert.equal(status.control.available, true);
  assert.equal(status.control.busy, false);
  assert.equal(status.control.lastAction, "set-parallelism");
  assert.equal(status.control.lastOutcome, "succeeded");
  assert.equal(status.control.csrfToken, null);

  const query = await fetch(`${base}/api/control?command=status`);
  assert.equal(query.status, 400);
  const options = await fetch(`${base}/api/control`, { method: "OPTIONS" });
  assert.equal(options.status, 405);
  assert.equal(options.headers.has("access-control-allow-origin"), false);
  const foreignHost = await rawHttpRequest(`${base}/api/status`, {
    Host: "attacker.invalid",
    Accept: "application/json",
  });
  assert.equal(foreignHost.statusCode, 403);
});

test("control API serializes actions and sanitizes execution failures", async (t) => {
  const fixture = await controlFixture(t);
  let releaseFirst;
  let firstStarted;
  const firstStartedPromise = new Promise((resolvePromise) => { firstStarted = resolvePromise; });
  let invocation = 0;
  const running = await listenDashboard({
    host: "127.0.0.1",
    port: 0,
    dataDirectory: fixture.dataDirectory,
    releaseFetch: async () => new Response(null, { status: 404 }),
    ...fixture,
    controlCsrfToken: "C".repeat(43),
    controlExecFile(_file, _args, _options, callback) {
      invocation += 1;
      if (invocation === 1) {
        releaseFirst = callback;
        firstStarted();
        return;
      }
      const failure = new Error("C:\\private\\worker.ps1 leaked detail");
      if (invocation === 2) failure.code = 1;
      else failure.killed = true;
      queueMicrotask(() => callback(failure, "secret stdout", "secret stderr"));
    },
  });
  t.after(() => new Promise((resolvePromise) => running.server.close(resolvePromise)));
  const base = `http://127.0.0.1:${running.address.port}`;
  const contract = await (await fetch(`${base}/api/control`)).json();

  const first = postControl(base, contract.csrfToken, { action: "start" });
  await firstStartedPromise;
  const concurrent = await postControl(base, contract.csrfToken, { action: "stop" });
  assert.equal(concurrent.status, 409);
  assert.equal(concurrent.headers.get("cache-control"), "no-store, max-age=0");
  assert.equal((await concurrent.json()).error, "worker-control-busy");
  assert.equal(invocation, 1);
  releaseFirst(null, "ignored", "ignored");
  assert.equal((await first).status, 200);

  const failed = await postControl(base, contract.csrfToken, { action: "stop" });
  assert.equal(failed.status, 502);
  const failedText = await failed.text();
  assert.equal(JSON.parse(failedText).error, "worker-control-failed");
  assert.doesNotMatch(failedText, /private|secret|worker\.ps1/i);
  assert.equal(invocation, 2);

  const timedOut = await postControl(base, contract.csrfToken, { action: "start" });
  assert.equal(timedOut.status, 504);
  assert.equal((await timedOut.json()).error, "worker-control-timeout");
  assert.equal(invocation, 3);
});

test("disabled control endpoint never invokes an executor", async (t) => {
  const directory = await temporaryDirectory(t);
  let invocations = 0;
  const running = await listenDashboard({
    host: "127.0.0.1",
    port: 0,
    dataDirectory: directory,
    releaseFetch: async () => new Response(null, { status: 404 }),
    controlExecFile() { invocations += 1; },
  });
  t.after(() => new Promise((resolvePromise) => running.server.close(resolvePromise)));
  const base = `http://127.0.0.1:${running.address.port}`;
  const contract = await (await fetch(`${base}/api/control`)).json();
  assert.equal(contract.available, false);
  assert.equal(contract.csrfToken, null);
  const response = await postControl(base, "D".repeat(43), { action: "start" });
  assert.equal(response.status, 503);
  assert.equal(invocations, 0);
});

test("unsafe, oversized, and malformed snapshots are rejected without path disclosure", async (t) => {
  const directory = await temporaryDirectory(t);
  await writeFile(join(directory, "state.json"), "{".repeat(10), "utf8");
  await writeFile(join(directory, "metrics.json"), "x".repeat(1_048_577), "utf8");
  const state = await safeReadJson(directory, "state.json", parseWorkerState);
  const metrics = await safeReadJson(directory, "metrics.json", parseMetrics);
  assert.deepEqual(state, { ok: false, code: "invalid-json" });
  assert.deepEqual(metrics, { ok: false, code: "too-large" });

  const running = await listenDashboard({
    host: "127.0.0.1",
    port: 0,
    dataDirectory: directory,
    releaseFetch: async () => new Response(null, { status: 404 }),
  });
  t.after(() => new Promise((resolvePromise) => running.server.close(resolvePromise)));
  const response = await fetch(`http://127.0.0.1:${running.address.port}/api/status`);
  const body = await response.text();
  assert.equal(response.status, 200);
  assert.match(body, /state-unreadable/);
  assert.match(body, /metrics-unreadable/);
  assert.equal(body.includes(directory), false);
});

test("safe reader rejects symbolic snapshot files", async (t) => {
  const directory = await temporaryDirectory(t);
  const outside = join(directory, "outside.json");
  await writeFile(outside, JSON.stringify(defaultWorkerState(T0)), "utf8");
  try {
    await symlink(outside, join(directory, "state.json"), "file");
  } catch (error) {
    if (error?.code === "EPERM" || error?.code === "EACCES") {
      t.skip("This Windows configuration does not permit creating test symlinks.");
      return;
    }
    throw error;
  }
  assert.deepEqual(
    await safeReadJson(directory, "state.json", parseWorkerState),
    { ok: false, code: "unsafe-path" },
  );
});

test("server configuration cannot bind the dashboard to a remote interface", () => {
  assert.equal(resolveDashboardConfig({ host: "localhost", port: 4319 }).host, "localhost");
  assert.equal(resolveDashboardConfig({ host: "::1", port: 0 }).port, 0);
  assert.throws(
    () => resolveDashboardConfig({ host: "0.0.0.0", port: 4319 }),
    /loopback/,
  );
  assert.throws(
    () => resolveDashboardConfig({ host: "192.0.2.10", port: 4319 }),
    /loopback/,
  );
});

test("published JSON schemas are parseable and deny additional properties", async () => {
  for (const filename of [
    "worker-state.schema.json",
    "metrics-event.schema.json",
    "metrics-snapshot.schema.json",
    "orchestration-snapshot.schema.json",
    "adaptive-work-status.schema.json",
  ]) {
    const schema = JSON.parse(
      await readFile(new URL(`../schemas/${filename}`, import.meta.url), "utf8"),
    );
    assert.equal(schema.$schema, "https://json-schema.org/draft/2020-12/schema");
    assert.equal(schema.additionalProperties, false);
    assert.ok(schema.$id.includes("worker-dashboard"));
  }
});

async function controlFixture(t) {
  const directory = await temporaryDirectory(t);
  const kitDirectory = join(directory, "worker-kit");
  const configDirectory = join(directory, "machine-config");
  const powershellDirectory = join(directory, "windows-powershell");
  const dataDirectory = join(directory, "state");
  await mkdir(kitDirectory, { recursive: true });
  await mkdir(configDirectory, { recursive: true });
  await mkdir(powershellDirectory, { recursive: true });
  await mkdir(dataDirectory, { recursive: true });
  const workerCliPath = join(kitDirectory, "Hch-Worker.ps1");
  const workerConfigPath = join(configDirectory, "WorkerConfig.psd1");
  const powershellPath = join(powershellDirectory, "powershell.exe");
  await writeFile(workerCliPath, "param([string]$Command)\n", "utf8");
  await writeFile(workerConfigPath, "@{ SchemaVersion = 2 }\n", "utf8");
  await writeFile(powershellPath, "fixed test executable placeholder\n", "utf8");
  return {
    kitDirectory: await realpath(kitDirectory),
    workerCliRootPath: await realpath(kitDirectory),
    workerConfigRootPath: await realpath(configDirectory),
    powershellRootPath: await realpath(powershellDirectory),
    dataDirectory,
    workerCliPath: await realpath(workerCliPath),
    workerConfigPath: await realpath(workerConfigPath),
    powershellPath: await realpath(powershellPath),
  };
}

function postControl(base, csrfToken, value, headerOverrides = {}) {
  const body = typeof value === "string" ? value : JSON.stringify(value);
  return fetch(`${base}/api/control`, {
    method: "POST",
    headers: {
      Accept: "application/json",
      "Content-Type": "application/json",
      Origin: base,
      "Sec-Fetch-Site": "same-origin",
      "X-HCH-CSRF-Token": csrfToken,
      ...headerOverrides,
    },
    body,
  });
}

function rawHttpRequest(url, headers) {
  return new Promise((resolvePromise, reject) => {
    const request = httpRequest(url, { method: "GET", headers }, (response) => {
      response.resume();
      response.once("end", () => resolvePromise({
        statusCode: response.statusCode,
        headers: response.headers,
      }));
    });
    request.once("error", reject);
    request.end();
  });
}

function event(eventId, occurredAt, type, data) {
  return { schemaVersion: 1, eventId, occurredAt, type, data };
}

function adaptiveSizing(overrides = {}) {
  return {
    algorithmVersion: "hch-adaptive-work-v1",
    currentTier: "compact",
    currentRank: 1,
    maxOutputTokens: 1_536,
    editorialProfile: "compact-editorial",
    minimumUnit: false,
    reason: "near-window-downshift",
    updatedAt: "2026-08-11T21:36:00Z",
    processingWindowSeconds: 2_700,
    nearWindowSeconds: 2_160,
    firstProgressGraceSeconds: 900,
    stallAfterSeconds: 600,
    finalizationGraceSeconds: 180,
    ...overrides,
  };
}

function adaptiveProgress(overrides = {}) {
  return {
    assignmentId: "assignment-01",
    generationPlanHash: "f".repeat(64),
    phase: "responding",
    attempt: 1,
    sequence: 8,
    contentBytes: 1_024,
    updatedAt: "2026-08-11T21:39:00Z",
    ...overrides,
  };
}

function adaptiveActiveWork(overrides = {}) {
  const {
    progressAt = "2026-08-11T21:39:00Z",
    livenessState = "responding",
    livenessReason = "progress-within-stall-grace",
    windowState = "near-window",
    ...fields
  } = overrides;
  return {
    assignmentId: "assignment-01",
    nodeId: "worker-01",
    status: "processing",
    tier: "full",
    tierRank: 2,
    maxOutputTokens: 2_400,
    progress: {
      phase: "responding",
      attempt: 1,
      sequence: 8,
      contentBytes: 1_024,
      lastProgressAt: progressAt,
    },
    liveness: {
      state: livenessState,
      progressed: false,
      lastProgressAt: progressAt,
      windowState,
      reason: livenessReason,
    },
    nearWindowObservedAt: "2026-08-11T21:36:00Z",
    processingDurationMilliseconds: 2_400_000,
    claimedAt: "2026-08-11T21:00:00Z",
    heartbeatAt: "2026-08-11T21:39:00Z",
    leaseExpiresAt: "2026-08-11T21:41:00Z",
    ...fields,
  };
}

function adaptiveWorkerStatus(fixture) {
  return {
    schema: "hch.worker-status/v1",
    schemaVersion: 1,
    observedAt: "2026-08-11T21:40:00Z",
    nodeId: fixture.nodeId,
    workerKeyId: `${fixture.nodeId}-key-v1`,
    platform: fixture.platform,
    kitVersion: "2.2.0",
    state: "processing",
    running: true,
    standby: false,
    ready: true,
    readyUntil: "2026-08-11T22:00:00Z",
    manifestSequence: 9,
    manifestHash: `sha256:${"d".repeat(64)}`,
    connection: {
      api: "connected",
      tls: "verified",
      auth: "ed25519",
      ed25519: true,
      lastSuccessAt: "2026-08-11T21:40:00Z",
      lastFailureAt: null,
      lastErrorCode: null,
    },
    transport: {
      tlsStatus: "verified",
      certificateStatus: "valid",
      certificateExpiresAt: "2027-08-11T21:00:00Z",
      certificateFingerprint: `sha256:${"c".repeat(64)}`,
      errorCode: null,
    },
    trust: {
      status: "verified",
      rootKeyId: "hch-root-v2",
      releaseKeyId: "hch-release-v4",
      manifestSequence: 9,
      manifestHash: `sha256:${"d".repeat(64)}`,
      policyHash: `sha256:${"e".repeat(64)}`,
      lastVerifiedAt: "2026-08-11T21:40:00Z",
      errorCode: null,
    },
    capacity: {
      requestedCapacity: 1,
      grantedCapacity: 1,
      activeAssignments: 1,
      capacityReason: "capacity-granted",
      validUntil: "2026-08-11T21:41:00Z",
    },
    uptimeSeconds: 3_600,
    currentBatch: {
      batchId: "batch-adaptive-01",
      startedAt: "2026-08-11T21:00:00Z",
      jobs: 1,
      assignmentIds: [fixture.nativeTelemetry.progress?.assignmentId ??
        fixture.nativeTelemetry.activeWork?.[0]?.assignmentId],
    },
    ...fixture.nativeTelemetry,
    code: "processing",
  };
}

function adaptiveOrchestration(nodeId) {
  return {
    schema: "hch.worker-orchestration/v1",
    schemaVersion: 1,
    observedAt: "2026-08-11T21:40:00Z",
    nodeId,
    mode: "waiting-for-work",
    heartbeat: {
      status: "succeeded",
      lastAttemptAt: "2026-08-11T21:40:00Z",
      lastSuccessAt: "2026-08-11T21:40:00Z",
      nextHeartbeatAt: "2026-08-11T21:41:00Z",
      intervalSeconds: 60,
      errorCode: null,
    },
    capacity: {
      configuredCapacity: 1,
      requestedCapacity: 1,
      grantedCapacity: 1,
      activeAssignments: 1,
      availableSlots: 0,
      capacityClass: "constrained",
      reason: "capacity-granted",
      grantedUntil: "2026-08-11T21:41:00Z",
    },
    workload: {
      claimable: 2,
      generating: 1,
      futureTotal: 3,
      claimableByTier: { minimum: 2, compact: 2, full: 2 },
    },
    workSizing: adaptiveSizing(),
    claim: { allowed: false, recommendedCount: 0, reason: "capacity-zero" },
  };
}

function healthyStatePatch() {
  return {
    worker: {
      id: "windows-worker-01",
      displayName: "Windows editorial 01",
      state: "ready",
      version: "2.0.0",
      platform: "win32-x64",
      startedAt: "2026-08-11T21:00:00Z",
    },
    connection: {
      status: "connected",
      lastSuccessAt: "2026-08-11T21:01:00Z",
      lastFailureAt: null,
      errorCode: null,
    },
    authentication: {
      status: "authenticated",
      keyId: "SHA256:worker-key",
      lastVerifiedAt: "2026-08-11T21:01:00Z",
      errorCode: null,
    },
    transport: {
      tlsStatus: "valid",
      certificateStatus: "valid",
      certificateExpiresAt: "2026-11-11T00:00:00Z",
      certificateFingerprint: "SHA256:certificate",
      errorCode: null,
    },
    trust: {
      status: "valid",
      rootKeyId: "SHA256:root",
      releaseKeyId: "SHA256:release",
      manifestSequence: 42,
      manifestHash: "sha256:manifest",
      policyHash: "sha256:policy",
      lastVerifiedAt: "2026-08-11T21:01:00Z",
      errorCode: null,
    },
  };
}

async function temporaryDirectory(t) {
  const directory = await mkdtemp(join(tmpdir(), "hch-worker-dashboard-"));
  t.after(() => rm(directory, { recursive: true, force: true }));
  return directory;
}

function captureStream() {
  return {
    text: "",
    write(chunk) {
      this.text += String(chunk);
      return true;
    },
  };
}
