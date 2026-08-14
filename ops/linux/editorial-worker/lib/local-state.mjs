import { cpus, freemem, totalmem } from "node:os";

import { sha256Hex } from "../crypto.mjs";
import {
  atomicWriteJson,
  readOptionalJson,
} from "./storage.mjs";
import { WorkerKitError } from "./errors.mjs";
import { workerPlatform } from "./platform.mjs";
import {
  capacityStatus,
  effectiveRequestedCapacity,
  readWorkerControl,
} from "./capacity.mjs";

const KIT_VERSION = "3.1.0";
const PROCESS_STARTED_AT = Date.now();
const PLATFORM = workerPlatform();

export async function updateStatus(stateRoot, config, patch) {
  const defaults = defaultStatus(config);
  const [storedStatus, capacitySnapshot, control] = await Promise.all([
    readOptionalJson(stateRoot, "status.json"),
    readOptionalJson(stateRoot, "capacity.json"),
    readWorkerControl(stateRoot, config),
  ]);
  const current = storedStatus ?? {};
  const merged = { ...defaults, ...current, ...patch };
  const connection = {
    ...defaults.connection,
    ...(current.connection ?? {}),
    ...(patch.connection ?? {}),
  };
  const transport = {
    ...defaults.transport,
    ...(current.transport ?? {}),
    ...(patch.transport ?? {}),
  };
  const trust = {
    ...defaults.trust,
    ...(current.trust ?? {}),
    ...(patch.trust ?? {}),
  };
  const next = {
    schema: defaults.schema,
    schemaVersion: defaults.schemaVersion,
    observedAt: new Date().toISOString(),
    nodeId: config.nodeId,
    workerKeyId: config.keyId,
    platform: PLATFORM,
    kitVersion: KIT_VERSION,
    state: merged.state,
    running: Boolean(merged.running),
    standby: Boolean(merged.standby),
    ready: Boolean(merged.ready),
    readyUntil: merged.readyUntil ?? null,
    manifestSequence: merged.manifestSequence ?? null,
    manifestHash: merged.manifestHash ?? null,
    connection: {
      api: connection.api,
      tls: connection.tls,
      auth: connection.auth,
      ed25519: Boolean(connection.ed25519),
      lastSuccessAt: connection.lastSuccessAt ?? null,
      lastFailureAt: connection.lastFailureAt ?? null,
      lastErrorCode: connection.lastErrorCode ?? null,
    },
    transport: {
      tlsStatus: transport.tlsStatus,
      certificateStatus: transport.certificateStatus,
      certificateExpiresAt: transport.certificateExpiresAt ?? null,
      certificateFingerprint: transport.certificateFingerprint ?? null,
      errorCode: transport.errorCode ?? null,
    },
    trust: {
      status: trust.status,
      rootKeyId: trust.rootKeyId ?? null,
      releaseKeyId: trust.releaseKeyId ?? null,
      manifestSequence: trust.manifestSequence ?? null,
      manifestHash: trust.manifestHash ?? null,
      policyHash: trust.policyHash ?? null,
      lastVerifiedAt: trust.lastVerifiedAt ?? null,
      errorCode: trust.errorCode ?? null,
    },
    capacity: {
      ...capacityStatus(capacitySnapshot, effectiveRequestedCapacity(control)),
      ...(patch.capacity ?? {}),
    },
    uptimeSeconds: Math.floor((Date.now() - PROCESS_STARTED_AT) / 1000),
    currentBatch: merged.currentBatch ?? null,
    code: merged.code,
  };
  assertSecretFree(next);
  await atomicWriteJson(stateRoot, "status.json", next);
  return next;
}

export async function updateMetrics(stateRoot, config, mutator) {
  const current = await readOptionalJson(stateRoot, "metrics.json");
  const next = normalizeMetrics(current, config);
  mutator(next);
  next.observedAt = new Date().toISOString();
  next.uptimeSeconds = Math.floor((Date.now() - PROCESS_STARTED_AT) / 1000);
  next.resources.cpu.logicalProcessors = cpus().length;
  next.resources.memory.totalBytes = totalmem();
  next.resources.memory.availableBytes = freemem();
  next.resources.memory.processWorkingSetBytes = process.memoryUsage().rss;
  next.resources.memory.estimatedBytesPerRunningItem = next.jobs.running > 0
    ? Math.round(next.resources.memory.processWorkingSetBytes / next.jobs.running)
    : null;
  next.performance.averageDurationMilliseconds = next.performance.durationSamples
    ? next.performance.totalDurationMilliseconds / next.performance.durationSamples
    : null;
  next.resources.memory.perItem.averageBytes = next.resources.memory.perItem.sampleCount
    ? Math.round(next.resources.memory.perItem.averageBytes)
    : null;
  assertSecretFree(next);
  await atomicWriteJson(stateRoot, "metrics.json", next);
  return next;
}

export async function operationRequestId(
  stateRoot,
  operationKey,
  bodyText,
  options = {},
) {
  const bodyHash = await sha256Hex(bodyText);
  const store = await readOptionalJson(stateRoot, "operations.json") ?? {
    schemaVersion: 1,
    operations: {},
    pendingExecute: null,
  };
  let key = operationKey;
  if (operationKey === "execute") {
    if (store.pendingExecute) key = store.pendingExecute;
    else {
      key = `execute:${crypto.randomUUID()}`;
      store.pendingExecute = key;
    }
  }
  const existing = store.operations[key];
  if (existing?.status === "pending") {
    if (existing.bodyHash !== bodyHash) {
      throw new WorkerKitError(
        "idempotency-body-mismatch",
        "A persisted operation id is associated with a different request body.",
      );
    }
    return { requestId: existing.requestId, operationKey: key };
  }
  const requestId = crypto.randomUUID();
  store.operations[key] = {
    requestId,
    bodyHash,
    status: "pending",
    createdAt: new Date().toISOString(),
    completedAt: null,
  };
  await atomicWriteJson(stateRoot, "operations.json", store);
  return { requestId, operationKey: key };
}

export async function completeOperation(stateRoot, operationKey) {
  const store = await readOptionalJson(stateRoot, "operations.json");
  if (!store?.operations?.[operationKey]) return;
  store.operations[operationKey].status = "completed";
  store.operations[operationKey].completedAt = new Date().toISOString();
  if (store.pendingExecute === operationKey) store.pendingExecute = null;
  await atomicWriteJson(stateRoot, "operations.json", store);
}

export function recordNetwork(metrics, traffic) {
  metrics.network.requestBytes += traffic.requestBytes;
  metrics.network.responseBytes += traffic.responseBytes;
  metrics.network.txBytes += traffic.requestBytes;
  metrics.network.rxBytes += traffic.responseBytes;
}

export function recordDuration(metrics, durationMilliseconds, sample = {}) {
  const duration = Math.max(0, Math.round(durationMilliseconds));
  metrics.performance.lastDurationMilliseconds = duration;
  metrics.performance.totalDurationMilliseconds += duration;
  metrics.performance.durationSamples += 1;
  if (sample.cpuStarted) {
    const usage = process.cpuUsage(sample.cpuStarted);
    const cpuSeconds = (usage.user + usage.system) / 1_000_000;
    const utilization = duration > 0
      ? Math.min(100, cpuSeconds / (duration / 1_000) / Math.max(1, cpus().length) * 100)
      : 0;
    const cpu = metrics.resources.cpu;
    cpu.utilizationPercent = utilization;
    cpu.totalActiveSeconds += cpuSeconds;
    cpu.averageUtilizationPercent = cpu.sampleCount
      ? (cpu.averageUtilizationPercent * cpu.sampleCount + utilization) / (cpu.sampleCount + 1)
      : utilization;
    cpu.sampleCount += 1;
  }
  if (sample.items > 0) {
    const perItem = Math.round(process.memoryUsage().rss / sample.items);
    const memory = metrics.resources.memory.perItem;
    const nextSamples = memory.sampleCount + sample.items;
    memory.averageBytes = memory.sampleCount
      ? (memory.averageBytes * memory.sampleCount + perItem * sample.items) / nextSamples
      : perItem;
    memory.peakBytes = Math.max(memory.peakBytes ?? 0, perItem);
    memory.sampleCount = nextSamples;
  }
}

export function leaveStandby(metrics) {
  if (metrics.standby.active && metrics.standby.since) {
    metrics.standby.totalMilliseconds += Math.max(
      0,
      Date.now() - Date.parse(metrics.standby.since),
    );
  }
  metrics.standby.active = false;
  metrics.standby.since = null;
}

export function enterStandby(metrics) {
  if (!metrics.standby.active) {
    metrics.standby.active = true;
    metrics.standby.since = new Date().toISOString();
  }
}

export function defaultStatus(config) {
  return {
    schema: "hch.worker-status/v1",
    schemaVersion: 1,
    observedAt: new Date().toISOString(),
    nodeId: config.nodeId,
    workerKeyId: config.keyId,
    platform: PLATFORM,
    kitVersion: KIT_VERSION,
    state: "bootstrap-required",
    running: false,
    standby: false,
    ready: false,
    readyUntil: null,
    manifestSequence: null,
    manifestHash: null,
    connection: {
      api: "unknown",
      tls: "unknown",
      auth: "pending",
      ed25519: false,
      lastSuccessAt: null,
      lastFailureAt: null,
      lastErrorCode: null,
    },
    transport: {
      tlsStatus: "unknown",
      certificateStatus: "unverified",
      certificateExpiresAt: null,
      certificateFingerprint: null,
      errorCode: null,
    },
    trust: {
      status: "pending",
      rootKeyId: null,
      releaseKeyId: null,
      manifestSequence: null,
      manifestHash: null,
      policyHash: null,
      lastVerifiedAt: null,
      errorCode: null,
    },
    capacity: capacityStatus(null, config.requestedCapacity),
    uptimeSeconds: Math.floor((Date.now() - PROCESS_STARTED_AT) / 1000),
    currentBatch: null,
    code: "bootstrap-required",
  };
}

export function defaultMetrics(config) {
  return {
    schema: "hch.worker-metrics/v1",
    schemaVersion: 1,
    observedAt: new Date().toISOString(),
    nodeId: config.nodeId,
    workerKeyId: config.keyId,
    uptimeSeconds: Math.floor((Date.now() - PROCESS_STARTED_AT) / 1000),
    resources: {
      cpu: {
        logicalProcessors: cpus().length,
        utilizationPercent: null,
        totalActiveSeconds: 0,
        sampleCount: 0,
        averageUtilizationPercent: null,
      },
      gpu: {
        available: false,
        status: "unsupported",
        utilizationPercent: null,
        totalActiveSeconds: 0,
        sampleCount: 0,
        averageUtilizationPercent: null,
        errorCode: null,
      },
      memory: {
        totalBytes: totalmem(),
        availableBytes: freemem(),
        processWorkingSetBytes: process.memoryUsage().rss,
        estimatedBytesPerRunningItem: null,
        perItem: { sampleCount: 0, averageBytes: null, peakBytes: null },
      },
    },
    network: {
      receiveBytesPerSecond: null,
      sendBytesPerSecond: null,
      requestBytes: 0,
      responseBytes: 0,
      rxBytes: 0,
      txBytes: 0,
      sourceRxBytes: null,
      sourceTxBytes: null,
    },
    batches: { total: 0, completed: 0, failed: 0 },
    jobs: { claimed: 0, running: 0, completed: 0, failed: 0, discarded: 0 },
    updates: { attempts: 0, succeeded: 0, failed: 0, rollbacks: 0 },
    performance: {
      lastDurationMilliseconds: null,
      totalDurationMilliseconds: 0,
      durationSamples: 0,
      averageDurationMilliseconds: null,
    },
    currentBatch: null,
    standby: {
      active: true,
      since: new Date().toISOString(),
      totalMilliseconds: 0,
    },
  };
}

function normalizeMetrics(value, config) {
  const defaults = defaultMetrics(config);
  const current = value && typeof value === "object" ? value : {};
  const resources = current.resources ?? {};
  const cpu = resources.cpu ?? {};
  const memory = resources.memory ?? {};
  const perItem = memory.perItem ?? {};
  const network = current.network ?? {};
  const batches = current.batches ?? {};
  const jobs = current.jobs ?? {};
  const updates = current.updates ?? {};
  const performance = current.performance ?? {};
  const standby = current.standby ?? {};
  const memorySamples = nonnegativeInteger(perItem.sampleCount, 0);
  return {
    schema: defaults.schema,
    schemaVersion: defaults.schemaVersion,
    observedAt: new Date().toISOString(),
    nodeId: config.nodeId,
    workerKeyId: config.keyId,
    uptimeSeconds: nonnegativeInteger(current.uptimeSeconds, 0),
    resources: {
      cpu: {
        logicalProcessors: positiveInteger(cpu.logicalProcessors, cpus().length),
        utilizationPercent: percentageOrNull(cpu.utilizationPercent),
        totalActiveSeconds: nonnegativeNumber(cpu.totalActiveSeconds, 0),
        sampleCount: nonnegativeInteger(cpu.sampleCount, 0),
        averageUtilizationPercent: percentageOrNull(cpu.averageUtilizationPercent),
      },
      gpu: {
        available: false,
        status: "unsupported",
        utilizationPercent: null,
        totalActiveSeconds: 0,
        sampleCount: 0,
        averageUtilizationPercent: null,
        errorCode: null,
      },
      memory: {
        totalBytes: nonnegativeInteger(memory.totalBytes, totalmem()),
        availableBytes: nonnegativeInteger(memory.availableBytes, freemem()),
        processWorkingSetBytes: nonnegativeInteger(
          memory.processWorkingSetBytes,
          process.memoryUsage().rss,
        ),
        estimatedBytesPerRunningItem: nullableNonnegativeInteger(
          memory.estimatedBytesPerRunningItem,
        ),
        perItem: {
          sampleCount: memorySamples,
          averageBytes: memorySamples
            ? nonnegativeNumber(perItem.averageBytes, 0)
            : null,
          peakBytes: memorySamples
            ? nonnegativeInteger(perItem.peakBytes, 0)
            : null,
        },
      },
    },
    network: {
      receiveBytesPerSecond: nullableNonnegativeInteger(network.receiveBytesPerSecond),
      sendBytesPerSecond: nullableNonnegativeInteger(network.sendBytesPerSecond),
      requestBytes: nonnegativeInteger(network.requestBytes, 0),
      responseBytes: nonnegativeInteger(network.responseBytes, 0),
      rxBytes: nonnegativeInteger(network.rxBytes, 0),
      txBytes: nonnegativeInteger(network.txBytes, 0),
      sourceRxBytes: nullableNonnegativeInteger(network.sourceRxBytes),
      sourceTxBytes: nullableNonnegativeInteger(network.sourceTxBytes),
    },
    batches: {
      total: nonnegativeInteger(batches.total, 0),
      completed: nonnegativeInteger(batches.completed ?? batches.succeeded, 0),
      failed: nonnegativeInteger(batches.failed, 0),
    },
    jobs: {
      claimed: nonnegativeInteger(jobs.claimed ?? jobs.total, 0),
      running: nonnegativeInteger(jobs.running, 0),
      completed: nonnegativeInteger(jobs.completed ?? jobs.succeeded, 0),
      failed: nonnegativeInteger(jobs.failed, 0),
      discarded: nonnegativeInteger(jobs.discarded, 0),
    },
    updates: {
      attempts: nonnegativeInteger(updates.attempts, 0),
      succeeded: nonnegativeInteger(updates.succeeded, 0),
      failed: nonnegativeInteger(updates.failed, 0),
      rollbacks: nonnegativeInteger(updates.rollbacks, 0),
    },
    performance: {
      lastDurationMilliseconds: nullableNonnegativeInteger(
        performance.lastDurationMilliseconds,
      ),
      totalDurationMilliseconds: nonnegativeInteger(
        performance.totalDurationMilliseconds,
        0,
      ),
      durationSamples: nonnegativeInteger(performance.durationSamples, 0),
      averageDurationMilliseconds: nonnegativeNumberOrNull(
        performance.averageDurationMilliseconds,
      ),
    },
    standby: {
      active: Boolean(standby.active),
      since: typeof standby.since === "string" ? standby.since : null,
      totalMilliseconds: nonnegativeInteger(standby.totalMilliseconds, 0),
    },
    currentBatch:
      current.currentBatch && typeof current.currentBatch === "object"
        ? current.currentBatch
        : null,
  };
}

function nonnegativeInteger(value, fallback) {
  return Number.isSafeInteger(value) && value >= 0 ? value : fallback;
}

function positiveInteger(value, fallback) {
  return Number.isSafeInteger(value) && value > 0 ? value : fallback;
}

function nullableNonnegativeInteger(value) {
  return Number.isSafeInteger(value) && value >= 0 ? value : null;
}

function nonnegativeNumber(value, fallback) {
  return typeof value === "number" && Number.isFinite(value) && value >= 0
    ? value
    : fallback;
}

function nonnegativeNumberOrNull(value) {
  return typeof value === "number" && Number.isFinite(value) && value >= 0
    ? value
    : null;
}

function percentageOrNull(value) {
  return typeof value === "number" && Number.isFinite(value) && value >= 0 && value <= 100
    ? value
    : null;
}

export function assertSecretFree(value, path = "state", ancestors = new Set()) {
  if (!value || typeof value !== "object") return;
  if (ancestors.has(value)) throw new TypeError("Local state must not be cyclic.");
  ancestors.add(value);
  try {
    for (const key of Object.keys(value)) {
      const isPublishedSizingField = key === "maxOutputTokens" &&
        Number.isSafeInteger(value[key]) && value[key] > 0;
      if (
        !isPublishedSizingField &&
        /secret|password|token|authorization|cookie|credential|bearer|private.?key|api.?key/i.test(key)
      ) {
        throw new WorkerKitError(
          "secret-field-refused",
          `Secret-bearing field refused at ${path}.${key}.`,
        );
      }
      assertSecretFree(value[key], `${path}.${key}`, ancestors);
    }
  } finally {
    ancestors.delete(value);
  }
}
