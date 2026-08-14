import { parseMetrics, parseWorkerState } from "./contracts.mjs";
import {
  parseAdaptiveWorkSizing,
  parseNativeActiveWork,
  parseSingleWorkerProgress,
} from "./adaptive-work.mjs";

const SECRET_FIELD =
  /secret|password|passwd|token|authorization|cookie|credential|bearer|private.?key|api.?key/i;
const NON_SECRET_TOKEN_BUDGET_FIELDS = new Set(["maxOutputTokens"]);

/**
 * Converts the status emitted by the Windows/Linux HCH worker kits into the
 * dashboard's deliberately smaller read-only contract. The conversion keeps
 * the worker state directory as the single source of truth: no bridge process
 * and no second mutable telemetry store are required.
 */
export function parseDashboardWorkerState(value) {
  if (value?.schema !== "hch.worker-status/v1") return parseWorkerState(value);
  assertNoSecrets(value);
  const status = object(value,"worker status");
  const observedAt = timestamp(status.observedAt,"observedAt");
  const uptimeSeconds = nullableNonNegativeInteger(status.uptimeSeconds,"uptimeSeconds");
  const connection = object(status.connection,"connection");
  const transport = object(status.transport,"transport");
  const trust = object(status.trust,"trust");
  const capacity = status.capacity === undefined
    ? { requestedCapacity: 0,grantedCapacity: 0,activeAssignments: 0,
        capacityReason: "not-reported",validUntil: null }
    : parseCapacity(status.capacity);
  const nativeWorkerState = text(status.state,"state",96);
  const workerState = map(nativeWorkerState,{
    "bootstrap-required": "bootstrapping",
    "connection-error": "error",
    uninitialized: "unknown",
  },nativeWorkerState);
  const apiState = text(connection.api,"connection.api",32);
  const trustState = text(trust.status,"trust.status",32);
  const certificateState = text(transport.certificateStatus,"certificateStatus",32);
  const tlsState = text(transport.tlsStatus,"tlsStatus",32);
  const authenticated = connection.ed25519 === true && connection.auth === "ed25519";
  const workSizing = status.workSizing === undefined || status.workSizing === null
    ? null
    : parseAdaptiveWorkSizing(status.workSizing);
  const activeWork = Object.hasOwn(status, "activeWork")
    ? parseNativeActiveWork(status.activeWork, {
        nodeId: identifier(status.nodeId,"nodeId",128),
      })
    : parseSingleWorkerProgress(status, { workSizing });
  const parsed = parseWorkerState({
    schemaVersion: 1,
    revision: 0,
    updatedAt: observedAt,
    worker: {
      id: identifier(status.nodeId,"nodeId",128),
      displayName: `HCH · ${identifier(status.nodeId,"nodeId",128)}`,
      state: workerState,
      version: nullableIdentifier(status.kitVersion,"kitVersion",64),
      platform: nullableIdentifier(status.platform,"platform",96),
      startedAt: uptimeSeconds === null
        ? null
        : new Date(Date.parse(observedAt) - uptimeSeconds * 1000).toISOString(),
    },
    connection: {
      status: map(apiState,{ connected: "connected",error: "error",unknown: "unknown" },"unknown"),
      lastSuccessAt: nullableTimestamp(connection.lastSuccessAt,"lastSuccessAt"),
      lastFailureAt: nullableTimestamp(connection.lastFailureAt,"lastFailureAt"),
      errorCode: nullableIdentifier(connection.lastErrorCode,"lastErrorCode",96),
    },
    authentication: {
      status: authenticated ? "authenticated" : apiState === "error" ? "error" : "pending",
      keyId: nullableIdentifier(status.workerKeyId,"workerKeyId",256),
      lastVerifiedAt: authenticated
        ? nullableTimestamp(connection.lastSuccessAt,"lastSuccessAt")
        : null,
      errorCode: authenticated ? null : nullableIdentifier(connection.lastErrorCode,"lastErrorCode",96),
    },
    transport: {
      tlsStatus: map(tlsState,{ verified: "valid",error: "error",unavailable: "unavailable",unknown: "unknown" },"error"),
      certificateStatus: map(certificateState,{
        valid: "valid",expiring: "expiring",expired: "expired",invalid: "invalid",
        unverified: "unverified",unknown: "unknown",error: "error",
      },"error"),
      certificateExpiresAt: nullableTimestamp(transport.certificateExpiresAt,"certificateExpiresAt"),
      certificateFingerprint: nullableIdentifier(
        transport.certificateFingerprint,"certificateFingerprint",256,
      ),
      errorCode: nullableIdentifier(transport.errorCode,"transport.errorCode",96),
    },
    trust: {
      status: map(trustState,{
        verified: "valid",pending: "unverified",expired: "expired",error: "error",
        valid: "valid",invalid: "invalid",unverified: "unverified",updating: "updating",
      },"error"),
      rootKeyId: nullableIdentifier(trust.rootKeyId,"rootKeyId",256),
      releaseKeyId: nullableIdentifier(trust.releaseKeyId,"releaseKeyId",256),
      manifestSequence: trust.manifestSequence === null || trust.manifestSequence === undefined
        ? null
        : nonNegativeInteger(trust.manifestSequence,"manifestSequence"),
      manifestHash: nullableIdentifier(trust.manifestHash,"manifestHash",256),
      policyHash: nullableIdentifier(trust.policyHash,"policyHash",256),
      lastVerifiedAt: nullableTimestamp(trust.lastVerifiedAt,"lastVerifiedAt"),
      errorCode: nullableIdentifier(trust.errorCode,"trust.errorCode",96),
    },
  });
  return { ...parsed,capacity,workSizing,activeWork };
}

function parseCapacity(value) {
  const capacity = object(value,"capacity");
  const requestedCapacity = nonNegativeInteger(capacity.requestedCapacity,"capacity.requestedCapacity");
  const grantedCapacity = nonNegativeInteger(capacity.grantedCapacity,"capacity.grantedCapacity");
  const activeAssignments = nonNegativeInteger(capacity.activeAssignments,"capacity.activeAssignments");
  const nativeFields = Object.hasOwn(capacity,"reason") || Object.hasOwn(capacity,"grantedUntil");
  const windowsFields = Object.hasOwn(capacity,"capacityReason") || Object.hasOwn(capacity,"validUntil");
  if (nativeFields && windowsFields) {
    throw new TypeError("capacity must not mix native and Windows field names");
  }
  const reasonField = nativeFields ? "reason" : "capacityReason";
  const validUntilField = nativeFields ? "grantedUntil" : "validUntil";
  if (requestedCapacity > 64 || grantedCapacity > 64) {
    throw new TypeError("capacity exceeds the local telemetry contract");
  }
  return {
    requestedCapacity,
    grantedCapacity,
    activeAssignments,
    capacityReason: text(capacity[reasonField],`capacity.${reasonField}`,256),
    validUntil: nullableTimestamp(capacity[validUntilField],`capacity.${validUntilField}`),
  };
}

export function parseDashboardMetrics(value) {
  if (value?.schema !== "hch.worker-metrics/v1") return parseMetrics(value);
  assertNoSecrets(value);
  const metrics = object(value,"worker metrics");
  const resources = object(metrics.resources,"resources");
  const cpu = object(resources.cpu,"resources.cpu");
  const gpu = object(resources.gpu,"resources.gpu");
  const memory = object(resources.memory,"resources.memory");
  const perItem = object(memory.perItem,"resources.memory.perItem");
  const network = object(metrics.network,"network");
  const batches = object(metrics.batches,"batches");
  const jobs = object(metrics.jobs,"jobs");
  const performance = object(metrics.performance,"performance");
  const standby = object(metrics.standby,"standby");
  const observedAt = timestamp(metrics.observedAt,"observedAt");
  const cpuSamples = nonNegativeInteger(cpu.sampleCount,"cpu.sampleCount");
  const cpuAverage = nullablePercentage(cpu.averageUtilizationPercent,"cpu.averageUtilizationPercent");
  const gpuSamples = nonNegativeInteger(gpu.sampleCount,"gpu.sampleCount");
  const gpuAverage = nullablePercentage(gpu.averageUtilizationPercent,"gpu.averageUtilizationPercent");
  const memorySamples = nonNegativeInteger(perItem.sampleCount,"memory.sampleCount");
  const memoryAverage = nullableNonNegativeNumber(perItem.averageBytes,"memory.averageBytes");
  const durationSamples = nonNegativeInteger(performance.durationSamples,"durationSamples");
  const totalDuration = nonNegativeNumber(performance.totalDurationMilliseconds,"totalDurationMilliseconds");
  const inputBytes = nonNegativeInteger(network.requestBytes,"network.requestBytes");
  const outputBytes = nonNegativeInteger(network.responseBytes,"network.responseBytes");
  const jobsRunning = nonNegativeInteger(jobs.running,"jobs.running");
  const currentBatch = adaptCurrentBatch(metrics.currentBatch,jobsRunning,observedAt);
  const nativeIds = Array.isArray(metrics.currentBatch?.assignmentIds)
    ? metrics.currentBatch.assignmentIds.map((item,index) => identifier(item,`assignmentIds[${index}]`,128))
    : [];
  const runningJobIds = Array.from({ length: jobsRunning },(_,index) =>
    nativeIds[index] ?? `${identifier(metrics.nodeId,"nodeId",80)}-running-${index + 1}`,
  );
  const completed = nonNegativeInteger(jobs.completed,"jobs.completed");
  const failed = nonNegativeInteger(jobs.failed,"jobs.failed");
  const discarded = nonNegativeInteger(jobs.discarded,"jobs.discarded");
  return parseMetrics({
    schemaVersion: 1,
    revision: 0,
    updatedAt: observedAt,
    lastEventAt: observedAt,
    eventsAccepted: cpuSamples,
    cpu: {
      totalSeconds: nonNegativeNumber(cpu.totalActiveSeconds,"cpu.totalActiveSeconds"),
      sampleCount: cpuSamples,
      percentSum: cpuAverage === null ? 0 : cpuAverage * cpuSamples,
      averagePercent: cpuSamples === 0 ? null : cpuAverage,
    },
    gpu: {
      status: map(text(gpu.status,"gpu.status",32),{
        available: "available",unavailable: "unavailable",unsupported: "unsupported",error: "error",
      },"error"),
      totalActiveSeconds: nonNegativeNumber(gpu.totalActiveSeconds,"gpu.totalActiveSeconds"),
      sampleCount: gpuSamples,
      percentSum: gpuAverage === null ? 0 : gpuAverage * gpuSamples,
      averagePercent: gpuSamples === 0 ? null : gpuAverage,
      errorCode: nullableIdentifier(gpu.errorCode,"gpu.errorCode",96),
    },
    memoryPerItem: {
      sampleCount: memorySamples,
      averageBytesSum: memoryAverage === null ? 0 : memoryAverage * memorySamples,
      averageBytes: memorySamples === 0 ? null : memoryAverage,
      peakBytes: nullableNonNegativeNumber(perItem.peakBytes,"memory.peakBytes"),
    },
    processingTime: {
      sampleCount: durationSamples,
      totalMilliseconds: totalDuration,
      averageMilliseconds: durationSamples === 0 ? null : totalDuration / durationSamples,
    },
    volume: {
      inputBytes,
      outputBytes,
      totalBytes: inputBytes + outputBytes,
    },
    network: {
      rxBytes: nonNegativeInteger(network.rxBytes,"network.rxBytes"),
      txBytes: nonNegativeInteger(network.txBytes,"network.txBytes"),
    },
    workload: {
      batchesTotal: nonNegativeInteger(batches.total,"batches.total"),
      batchesCompleted: nonNegativeInteger(batches.completed,"batches.completed"),
      jobsTotal: nonNegativeInteger(jobs.claimed,"jobs.claimed"),
      jobsCompleted: completed + failed + discarded,
      jobsSucceeded: completed,
      jobsFailed: failed + discarded,
      jobsRunning,
      runningJobIds,
      currentBatch,
    },
    standby: {
      active: standby.active === true,
      since: nullableTimestamp(standby.since,"standby.since"),
      totalMilliseconds: nonNegativeNumber(standby.totalMilliseconds,"standby.totalMilliseconds"),
    },
    deduplication: { recentEventIds: [] },
  });
}

function adaptCurrentBatch(value,jobsRunning,observedAt) {
  if (value === null || value === undefined) return null;
  const batch = object(value,"currentBatch");
  const id = identifier(batch.batchId ?? batch.id,"currentBatch.batchId",128);
  const totalJobs = nonNegativeInteger(
    batch.jobs ?? batch.totalJobs ?? jobsRunning,
    "currentBatch.jobs",
  );
  const completedJobs = Math.min(
    totalJobs,
    nonNegativeInteger(batch.completedJobs ?? 0,"currentBatch.completedJobs"),
  );
  return {
    id,
    startedAt: timestamp(batch.startedAt ?? observedAt,"currentBatch.startedAt"),
    totalJobs,
    completedJobs,
  };
}

function assertNoSecrets(value,path = "$") {
  if (!value || typeof value !== "object") return;
  if (Array.isArray(value)) {
    value.forEach((item,index) => assertNoSecrets(item,`${path}[${index}]`));
    return;
  }
  for (const [key,child] of Object.entries(value)) {
    if (SECRET_FIELD.test(key) && !NON_SECRET_TOKEN_BUDGET_FIELDS.has(key)) {
      throw new TypeError(`Forbidden secret-bearing field at ${path}.${key}.`);
    }
    assertNoSecrets(child,`${path}.${key}`);
  }
}

function object(value,name) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new TypeError(`${name} must be an object.`);
  }
  return value;
}

function text(value,name,maximum) {
  if (typeof value !== "string" || !value || value.length > maximum) {
    throw new TypeError(`${name} must be bounded text.`);
  }
  return value;
}

function identifier(value,name,maximum) {
  if (typeof value !== "string" || !value || value.length > maximum || /[\x00-\x20\x7f]/.test(value)) {
    throw new TypeError(`${name} must be a bounded identifier.`);
  }
  return value;
}

function nullableIdentifier(value,name,maximum) {
  return value === null || value === undefined || value === "" ? null : identifier(value,name,maximum);
}

function timestamp(value,name) {
  const milliseconds = Date.parse(String(value));
  if (!Number.isFinite(milliseconds)) throw new TypeError(`${name} must be an ISO timestamp.`);
  return new Date(milliseconds).toISOString();
}

function nullableTimestamp(value,name) {
  return value === null || value === undefined || value === "" ? null : timestamp(value,name);
}

function nonNegativeNumber(value,name) {
  const number = Number(value);
  if (!Number.isFinite(number) || number < 0) throw new TypeError(`${name} must be non-negative.`);
  return number;
}

function nullableNonNegativeNumber(value,name) {
  return value === null || value === undefined ? null : nonNegativeNumber(value,name);
}

function nonNegativeInteger(value,name) {
  const number = Number(value);
  if (!Number.isSafeInteger(number) || number < 0) throw new TypeError(`${name} must be a non-negative integer.`);
  return number;
}

function nullableNonNegativeInteger(value,name) {
  return value === null || value === undefined ? null : nonNegativeInteger(value,name);
}

function nullablePercentage(value,name) {
  if (value === null || value === undefined) return null;
  const number = nonNegativeNumber(value,name);
  if (number > 100) throw new TypeError(`${name} must not exceed 100.`);
  return number;
}

function map(value,mapping,fallback) {
  return Object.hasOwn(mapping,value) ? mapping[value] : fallback;
}
