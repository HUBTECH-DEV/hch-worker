import { parseAdaptiveWorkSizing } from "./adaptive-work.mjs";

export const STATE_SCHEMA_VERSION = 1;
export const METRICS_SCHEMA_VERSION = 1;
export const EVENT_SCHEMA_VERSION = 1;
export const ORCHESTRATION_SCHEMA_VERSION = 1;

const WORKER_STATES = new Set([
  "unknown",
  "bootstrapping",
  "updating",
  "self-testing",
  "ready",
  "idle",
  "processing",
  "standby",
  "draining",
  "paused",
  "update-required",
  "update-failed",
  "error",
  "stopped",
]);
const CONNECTION_STATES = new Set([
  "unknown",
  "connecting",
  "connected",
  "degraded",
  "disconnected",
  "error",
]);
const AUTHENTICATION_STATES = new Set([
  "unknown",
  "pending",
  "authenticated",
  "rejected",
  "expired",
  "revoked",
  "error",
]);
const TLS_STATES = new Set([
  "unknown",
  "valid",
  "invalid",
  "unavailable",
  "error",
]);
const CERTIFICATE_STATES = new Set([
  "unknown",
  "valid",
  "expiring",
  "expired",
  "invalid",
  "unverified",
  "error",
]);
const TRUST_STATES = new Set([
  "unknown",
  "valid",
  "invalid",
  "expired",
  "unverified",
  "updating",
  "error",
]);
const GPU_STATES = new Set([
  "available",
  "unavailable",
  "unsupported",
  "error",
]);
const ORCHESTRATION_MODES = new Set([
  "heartbeat-only",
  "waiting-for-work",
  "execution-authorized",
  "unavailable",
]);
const HEARTBEAT_STATES = new Set([
  "unknown",
  "pending",
  "succeeded",
  "failed",
  "error",
]);
const CAPACITY_CLASSES = new Set([
  "constrained",
  "standard",
  "accelerated",
]);
const EVENT_TYPES = new Set([
  "resource.sample",
  "job.started",
  "job.completed",
  "batch.started",
  "batch.completed",
  "standby.changed",
]);
const SECRET_FIELD =
  /secret|password|passwd|token|authorization|cookie|credential|bearer|private.?key|api.?key/i;
const NON_SECRET_TOKEN_BUDGET_FIELDS = new Set(["maxOutputTokens"]);

export function defaultWorkerState(now = new Date()) {
  const updatedAt = isoTimestamp(now, "now");
  return {
    schemaVersion: STATE_SCHEMA_VERSION,
    revision: 0,
    updatedAt,
    worker: {
      id: "unconfigured",
      displayName: "Worker não configurado",
      state: "unknown",
      version: null,
      platform: null,
      startedAt: null,
    },
    connection: {
      status: "unknown",
      lastSuccessAt: null,
      lastFailureAt: null,
      errorCode: null,
    },
    authentication: {
      status: "unknown",
      keyId: null,
      lastVerifiedAt: null,
      errorCode: null,
    },
    transport: {
      tlsStatus: "unknown",
      certificateStatus: "unknown",
      certificateExpiresAt: null,
      certificateFingerprint: null,
      errorCode: null,
    },
    trust: {
      status: "unknown",
      rootKeyId: null,
      releaseKeyId: null,
      manifestSequence: null,
      manifestHash: null,
      policyHash: null,
      lastVerifiedAt: null,
      errorCode: null,
    },
  };
}

export function defaultMetrics(now = new Date()) {
  const updatedAt = isoTimestamp(now, "now");
  return {
    schemaVersion: METRICS_SCHEMA_VERSION,
    revision: 0,
    updatedAt,
    lastEventAt: null,
    eventsAccepted: 0,
    cpu: {
      totalSeconds: 0,
      sampleCount: 0,
      percentSum: 0,
      averagePercent: null,
    },
    gpu: {
      status: "unavailable",
      totalActiveSeconds: 0,
      sampleCount: 0,
      percentSum: 0,
      averagePercent: null,
      errorCode: null,
    },
    memoryPerItem: {
      sampleCount: 0,
      averageBytesSum: 0,
      averageBytes: null,
      peakBytes: null,
    },
    processingTime: {
      sampleCount: 0,
      totalMilliseconds: 0,
      averageMilliseconds: null,
    },
    volume: {
      inputBytes: 0,
      outputBytes: 0,
      totalBytes: 0,
    },
    network: {
      rxBytes: 0,
      txBytes: 0,
    },
    workload: {
      batchesTotal: 0,
      batchesCompleted: 0,
      jobsTotal: 0,
      jobsCompleted: 0,
      jobsSucceeded: 0,
      jobsFailed: 0,
      jobsRunning: 0,
      runningJobIds: [],
      currentBatch: null,
    },
    standby: {
      active: true,
      since: updatedAt,
      totalMilliseconds: 0,
    },
    deduplication: {
      recentEventIds: [],
    },
  };
}

export function defaultOrchestration(now = new Date(), nodeId = "unconfigured") {
  const observedAt = isoTimestamp(now, "now");
  return {
    schema: "hch.worker-orchestration/v1",
    schemaVersion: ORCHESTRATION_SCHEMA_VERSION,
    observedAt,
    nodeId: identifier(nodeId, "nodeId", 128),
    mode: "unavailable",
    heartbeat: {
      status: "unknown",
      lastAttemptAt: null,
      lastSuccessAt: null,
      nextHeartbeatAt: null,
      intervalSeconds: 60,
      errorCode: null,
    },
    capacity: {
      configuredCapacity: null,
      requestedCapacity: null,
      grantedCapacity: null,
      activeAssignments: null,
      availableSlots: null,
      capacityClass: null,
      reason: null,
      grantedUntil: null,
    },
    workload: {
      claimable: null,
      generating: null,
      futureTotal: null,
      claimableByTier: null,
    },
    workSizing: null,
    claim: {
      allowed: null,
      recommendedCount: null,
      reason: null,
    },
  };
}

export function parseOrchestration(value) {
  assertNoSecrets(value);
  const snapshot = record(value, "orchestration snapshot");
  exactKeys(snapshot, [
    "schema",
    "schemaVersion",
    "observedAt",
    "nodeId",
    "mode",
    "heartbeat",
    "capacity",
    "workload",
    ...(Object.hasOwn(snapshot, "workSizing") ? ["workSizing"] : []),
    "claim",
  ], "orchestration snapshot");
  if (
    snapshot.schema !== "hch.worker-orchestration/v1" ||
    snapshot.schemaVersion !== ORCHESTRATION_SCHEMA_VERSION
  ) {
    throw new TypeError("Unsupported orchestration schema.");
  }

  const heartbeat = record(snapshot.heartbeat, "orchestration heartbeat");
  exactKeys(heartbeat, [
    "status",
    "lastAttemptAt",
    "lastSuccessAt",
    "nextHeartbeatAt",
    "intervalSeconds",
    "errorCode",
  ], "orchestration heartbeat");
  const intervalSeconds = unsignedInteger(
    heartbeat.intervalSeconds,
    "heartbeat.intervalSeconds",
  );
  if (intervalSeconds < 1 || intervalSeconds > 3600) {
    throw new TypeError("heartbeat.intervalSeconds must be between 1 and 3600.");
  }

  const capacity = record(snapshot.capacity, "orchestration capacity");
  exactKeys(capacity, [
    "configuredCapacity",
    "requestedCapacity",
    "grantedCapacity",
    "activeAssignments",
    "availableSlots",
    "capacityClass",
    "reason",
    "grantedUntil",
  ], "orchestration capacity");
  const configuredCapacity = nullableBoundedCounter(
    capacity.configuredCapacity,
    64,
    "capacity.configuredCapacity",
  );
  const requestedCapacity = nullableBoundedCounter(
    capacity.requestedCapacity,
    64,
    "capacity.requestedCapacity",
  );
  const grantedCapacity = nullableBoundedCounter(
    capacity.grantedCapacity,
    32,
    "capacity.grantedCapacity",
  );
  const activeAssignments = nullableUnsignedInteger(
    capacity.activeAssignments,
    "capacity.activeAssignments",
  );
  const availableSlots = nullableBoundedCounter(
    capacity.availableSlots,
    32,
    "capacity.availableSlots",
  );
  if (
    availableSlots !== null &&
    grantedCapacity !== null &&
    availableSlots > grantedCapacity
  ) {
    throw new TypeError("capacity.availableSlots cannot exceed grantedCapacity.");
  }

  const workload = record(snapshot.workload, "orchestration workload");
  exactKeys(workload, [
    "claimable",
    "generating",
    "futureTotal",
    ...(Object.hasOwn(workload, "claimableByTier") ? ["claimableByTier"] : []),
  ], "orchestration workload");
  const claimable = nullableUnsignedInteger(workload.claimable, "workload.claimable");
  const generating = nullableUnsignedInteger(workload.generating, "workload.generating");
  const futureTotal = nullableUnsignedInteger(workload.futureTotal, "workload.futureTotal");
  if (
    futureTotal !== null &&
    ((claimable !== null && futureTotal < claimable) ||
      (generating !== null && futureTotal < generating))
  ) {
    throw new TypeError("workload.futureTotal cannot be lower than its reported subsets.");
  }
  const claimableByTier = workload.claimableByTier === undefined ||
    workload.claimableByTier === null
    ? null
    : parseClaimableByTier(workload.claimableByTier, claimable);
  const workSizing = snapshot.workSizing === undefined || snapshot.workSizing === null
    ? null
    : parseAdaptiveWorkSizing(snapshot.workSizing);

  const claim = record(snapshot.claim, "orchestration claim");
  exactKeys(claim, ["allowed", "recommendedCount", "reason"], "orchestration claim");
  const allowed = nullableBoolean(claim.allowed, "claim.allowed");
  const recommendedCount = nullableBoundedCounter(
    claim.recommendedCount,
    32,
    "claim.recommendedCount",
  );
  if (
    allowed !== null &&
    recommendedCount !== null &&
    allowed !== (recommendedCount > 0)
  ) {
    throw new TypeError("claim.allowed must match whether recommendedCount is positive.");
  }
  if (
    recommendedCount !== null &&
    ((grantedCapacity !== null && recommendedCount > grantedCapacity) ||
      (availableSlots !== null && recommendedCount > availableSlots) ||
      (claimable !== null && recommendedCount > claimable))
  ) {
    throw new TypeError("claim.recommendedCount exceeds capacity or claimable workload.");
  }

  const mode = enumeration(snapshot.mode, ORCHESTRATION_MODES, "mode");
  if (
    allowed !== null &&
    ((mode === "execution-authorized") !== allowed)
  ) {
    throw new TypeError("execution-authorized mode must match claim.allowed.");
  }

  return {
    schema: "hch.worker-orchestration/v1",
    schemaVersion: ORCHESTRATION_SCHEMA_VERSION,
    observedAt: isoTimestamp(snapshot.observedAt, "observedAt"),
    nodeId: identifier(snapshot.nodeId, "nodeId", 128),
    mode,
    heartbeat: {
      status: enumeration(heartbeat.status, HEARTBEAT_STATES, "heartbeat.status"),
      lastAttemptAt: nullableTimestamp(heartbeat.lastAttemptAt, "heartbeat.lastAttemptAt"),
      lastSuccessAt: nullableTimestamp(heartbeat.lastSuccessAt, "heartbeat.lastSuccessAt"),
      nextHeartbeatAt: nullableTimestamp(heartbeat.nextHeartbeatAt, "heartbeat.nextHeartbeatAt"),
      intervalSeconds,
      errorCode: nullableIdentifier(heartbeat.errorCode, "heartbeat.errorCode", 96),
    },
    capacity: {
      configuredCapacity,
      requestedCapacity,
      grantedCapacity,
      activeAssignments,
      availableSlots,
      capacityClass: capacity.capacityClass === null
        ? null
        : enumeration(capacity.capacityClass, CAPACITY_CLASSES, "capacity.capacityClass"),
      reason: nullableText(capacity.reason, "capacity.reason", 160),
      grantedUntil: nullableTimestamp(capacity.grantedUntil, "capacity.grantedUntil"),
    },
    workload: { claimable, generating, futureTotal, claimableByTier },
    workSizing,
    claim: {
      allowed,
      recommendedCount,
      reason: nullableText(claim.reason, "claim.reason", 160),
    },
  };
}

export function parseWorkerState(value) {
  assertNoSecrets(value);
  const object = record(value, "worker state");
  exactKeys(object, [
    "schemaVersion",
    "revision",
    "updatedAt",
    "worker",
    "connection",
    "authentication",
    "transport",
    "trust",
  ], "worker state");
  if (object.schemaVersion !== STATE_SCHEMA_VERSION) {
    throw new TypeError("Unsupported worker state schemaVersion.");
  }
  return {
    schemaVersion: STATE_SCHEMA_VERSION,
    revision: unsignedInteger(object.revision, "revision"),
    updatedAt: isoTimestamp(object.updatedAt, "updatedAt"),
    worker: parseWorker(object.worker),
    connection: parseConnection(object.connection),
    authentication: parseAuthentication(object.authentication),
    transport: parseTransport(object.transport),
    trust: parseTrust(object.trust),
  };
}

export function applyWorkerStatePatch(currentValue, patchValue, now = new Date()) {
  const current = parseWorkerState(currentValue);
  assertNoSecrets(patchValue);
  const patch = record(patchValue, "state patch");
  allowedKeys(
    patch,
    ["worker", "connection", "authentication", "transport", "trust"],
    "state patch",
  );
  return parseWorkerState({
    ...current,
    revision: current.revision + 1,
    updatedAt: isoTimestamp(now, "now"),
    worker: patch.worker ? { ...current.worker, ...record(patch.worker, "worker patch") } : current.worker,
    connection: patch.connection
      ? { ...current.connection, ...record(patch.connection, "connection patch") }
      : current.connection,
    authentication: patch.authentication
      ? { ...current.authentication, ...record(patch.authentication, "authentication patch") }
      : current.authentication,
    transport: patch.transport
      ? { ...current.transport, ...record(patch.transport, "transport patch") }
      : current.transport,
    trust: patch.trust
      ? { ...current.trust, ...record(patch.trust, "trust patch") }
      : current.trust,
  });
}

export function parseMetrics(value) {
  assertNoSecrets(value);
  const object = record(value, "metrics");
  exactKeys(object, [
    "schemaVersion",
    "revision",
    "updatedAt",
    "lastEventAt",
    "eventsAccepted",
    "cpu",
    "gpu",
    "memoryPerItem",
    "processingTime",
    "volume",
    "network",
    "workload",
    "standby",
    "deduplication",
  ], "metrics");
  if (object.schemaVersion !== METRICS_SCHEMA_VERSION) {
    throw new TypeError("Unsupported metrics schemaVersion.");
  }
  const cpu = record(object.cpu, "cpu");
  exactKeys(cpu, ["totalSeconds", "sampleCount", "percentSum", "averagePercent"], "cpu");
  const gpu = record(object.gpu, "gpu");
  exactKeys(gpu, [
    "status",
    "totalActiveSeconds",
    "sampleCount",
    "percentSum",
    "averagePercent",
    "errorCode",
  ], "gpu");
  const memory = record(object.memoryPerItem, "memoryPerItem");
  exactKeys(memory, [
    "sampleCount",
    "averageBytesSum",
    "averageBytes",
    "peakBytes",
  ], "memoryPerItem");
  const processing = record(object.processingTime, "processingTime");
  exactKeys(processing, [
    "sampleCount",
    "totalMilliseconds",
    "averageMilliseconds",
  ], "processingTime");
  const volume = record(object.volume, "volume");
  exactKeys(volume, ["inputBytes", "outputBytes", "totalBytes"], "volume");
  const network = record(object.network, "network");
  exactKeys(network, ["rxBytes", "txBytes"], "network");
  const workload = record(object.workload, "workload");
  exactKeys(workload, [
    "batchesTotal",
    "batchesCompleted",
    "jobsTotal",
    "jobsCompleted",
    "jobsSucceeded",
    "jobsFailed",
    "jobsRunning",
    "runningJobIds",
    "currentBatch",
  ], "workload");
  const standby = record(object.standby, "standby");
  exactKeys(standby, ["active", "since", "totalMilliseconds"], "standby");
  const deduplication = record(object.deduplication, "deduplication");
  exactKeys(deduplication, ["recentEventIds"], "deduplication");

  const sampleCount = unsignedInteger(cpu.sampleCount, "cpu.sampleCount");
  const cpuPercentSum = finiteNonNegative(cpu.percentSum, "cpu.percentSum");
  const gpuSampleCount = unsignedInteger(gpu.sampleCount, "gpu.sampleCount");
  const gpuPercentSum = finiteNonNegative(gpu.percentSum, "gpu.percentSum");
  const memorySampleCount = unsignedInteger(memory.sampleCount, "memory.sampleCount");
  const averageBytesSum = finiteNonNegative(memory.averageBytesSum, "memory.averageBytesSum");
  const processingSampleCount = unsignedInteger(processing.sampleCount, "processing.sampleCount");
  const totalMilliseconds = finiteNonNegative(
    processing.totalMilliseconds,
    "processing.totalMilliseconds",
  );
  const inputBytes = unsignedInteger(volume.inputBytes, "volume.inputBytes");
  const outputBytes = unsignedInteger(volume.outputBytes, "volume.outputBytes");
  const runningJobIds = identifierArray(workload.runningJobIds, "runningJobIds", 256);
  const currentBatch = workload.currentBatch === null
    ? null
    : parseCurrentBatch(workload.currentBatch);

  return {
    schemaVersion: METRICS_SCHEMA_VERSION,
    revision: unsignedInteger(object.revision, "revision"),
    updatedAt: isoTimestamp(object.updatedAt, "updatedAt"),
    lastEventAt: nullableTimestamp(object.lastEventAt, "lastEventAt"),
    eventsAccepted: unsignedInteger(object.eventsAccepted, "eventsAccepted"),
    cpu: {
      totalSeconds: finiteNonNegative(cpu.totalSeconds, "cpu.totalSeconds"),
      sampleCount,
      percentSum: cpuPercentSum,
      averagePercent: derivedAverage(cpu.averagePercent, cpuPercentSum, sampleCount, "cpu.averagePercent"),
    },
    gpu: {
      status: enumeration(gpu.status, GPU_STATES, "gpu.status"),
      totalActiveSeconds: finiteNonNegative(gpu.totalActiveSeconds, "gpu.totalActiveSeconds"),
      sampleCount: gpuSampleCount,
      percentSum: gpuPercentSum,
      averagePercent: derivedAverage(
        gpu.averagePercent,
        gpuPercentSum,
        gpuSampleCount,
        "gpu.averagePercent",
      ),
      errorCode: nullableIdentifier(gpu.errorCode, "gpu.errorCode", 96),
    },
    memoryPerItem: {
      sampleCount: memorySampleCount,
      averageBytesSum,
      averageBytes: derivedAverage(
        memory.averageBytes,
        averageBytesSum,
        memorySampleCount,
        "memory.averageBytes",
      ),
      peakBytes: nullableNonNegative(memory.peakBytes, "memory.peakBytes"),
    },
    processingTime: {
      sampleCount: processingSampleCount,
      totalMilliseconds,
      averageMilliseconds: derivedAverage(
        processing.averageMilliseconds,
        totalMilliseconds,
        processingSampleCount,
        "processing.averageMilliseconds",
      ),
    },
    volume: {
      inputBytes,
      outputBytes,
      totalBytes: exactDerivedInteger(volume.totalBytes, inputBytes + outputBytes, "volume.totalBytes"),
    },
    network: {
      rxBytes: unsignedInteger(network.rxBytes, "network.rxBytes"),
      txBytes: unsignedInteger(network.txBytes, "network.txBytes"),
    },
    workload: {
      batchesTotal: unsignedInteger(workload.batchesTotal, "workload.batchesTotal"),
      batchesCompleted: unsignedInteger(workload.batchesCompleted, "workload.batchesCompleted"),
      jobsTotal: unsignedInteger(workload.jobsTotal, "workload.jobsTotal"),
      jobsCompleted: unsignedInteger(workload.jobsCompleted, "workload.jobsCompleted"),
      jobsSucceeded: unsignedInteger(workload.jobsSucceeded, "workload.jobsSucceeded"),
      jobsFailed: unsignedInteger(workload.jobsFailed, "workload.jobsFailed"),
      jobsRunning: exactDerivedInteger(
        workload.jobsRunning,
        runningJobIds.length,
        "workload.jobsRunning",
      ),
      runningJobIds,
      currentBatch,
    },
    standby: {
      active: booleanValue(standby.active, "standby.active"),
      since: nullableTimestamp(standby.since, "standby.since"),
      totalMilliseconds: finiteNonNegative(
        standby.totalMilliseconds,
        "standby.totalMilliseconds",
      ),
    },
    deduplication: {
      recentEventIds: identifierArray(
        deduplication.recentEventIds,
        "recentEventIds",
        512,
      ),
    },
  };
}

export function parseMetricsEvent(value) {
  assertNoSecrets(value);
  const event = record(value, "metrics event");
  exactKeys(event, ["schemaVersion", "eventId", "type", "occurredAt", "data"], "metrics event");
  if (event.schemaVersion !== EVENT_SCHEMA_VERSION) {
    throw new TypeError("Unsupported metrics event schemaVersion.");
  }
  const type = enumeration(event.type, EVENT_TYPES, "event.type");
  const base = {
    schemaVersion: EVENT_SCHEMA_VERSION,
    eventId: identifier(event.eventId, "eventId", 128, 8),
    type,
    occurredAt: isoTimestamp(event.occurredAt, "occurredAt"),
  };
  return { ...base, data: parseEventData(type, event.data) };
}

export function aggregateMetrics(currentValue, eventValue, now = new Date()) {
  const current = structuredClone(parseMetrics(currentValue));
  const event = parseMetricsEvent(eventValue);
  if (current.deduplication.recentEventIds.includes(event.eventId)) {
    return { metrics: current, duplicate: true };
  }

  const eventTime = Date.parse(event.occurredAt);
  const standbyStart = current.standby.active && current.standby.since
    ? Date.parse(current.standby.since)
    : null;
  if (event.type === "resource.sample") {
    current.cpu.totalSeconds += event.data.cpuSecondsDelta;
    current.cpu.sampleCount += 1;
    current.cpu.percentSum += event.data.cpuPercent;
    current.cpu.averagePercent = current.cpu.percentSum / current.cpu.sampleCount;
    current.network.rxBytes += event.data.networkRxBytesDelta;
    current.network.txBytes += event.data.networkTxBytesDelta;
    current.gpu.status = event.data.gpu.status;
    current.gpu.errorCode = event.data.gpu.errorCode;
    if (event.data.gpu.status === "available") {
      current.gpu.totalActiveSeconds += event.data.gpu.activeSecondsDelta;
      current.gpu.sampleCount += 1;
      current.gpu.percentSum += event.data.gpu.utilizationPercent;
      current.gpu.averagePercent = current.gpu.percentSum / current.gpu.sampleCount;
    }
  } else if (event.type === "batch.started") {
    current.workload.batchesTotal += 1;
    current.workload.currentBatch = {
      id: event.data.batchId,
      startedAt: event.occurredAt,
      totalJobs: event.data.totalJobs,
      completedJobs: 0,
    };
    leaveStandby(current, eventTime, standbyStart);
  } else if (event.type === "batch.completed") {
    current.workload.batchesCompleted += 1;
    if (current.workload.currentBatch?.id === event.data.batchId) {
      current.workload.currentBatch = null;
    }
  } else if (event.type === "job.started") {
    if (!current.workload.runningJobIds.includes(event.data.jobId)) {
      current.workload.jobsTotal += 1;
      current.workload.runningJobIds.push(event.data.jobId);
      current.workload.jobsRunning = current.workload.runningJobIds.length;
      current.volume.inputBytes += event.data.inputBytes;
      current.volume.totalBytes = current.volume.inputBytes + current.volume.outputBytes;
    }
    leaveStandby(current, eventTime, standbyStart);
  } else if (event.type === "job.completed") {
    current.workload.runningJobIds = current.workload.runningJobIds.filter(
      (id) => id !== event.data.jobId,
    );
    current.workload.jobsRunning = current.workload.runningJobIds.length;
    current.workload.jobsCompleted += 1;
    if (event.data.outcome === "succeeded") current.workload.jobsSucceeded += 1;
    else current.workload.jobsFailed += 1;
    current.processingTime.sampleCount += 1;
    current.processingTime.totalMilliseconds += event.data.durationMilliseconds;
    current.processingTime.averageMilliseconds =
      current.processingTime.totalMilliseconds / current.processingTime.sampleCount;
    current.memoryPerItem.sampleCount += 1;
    current.memoryPerItem.averageBytesSum += event.data.memoryAverageBytes;
    current.memoryPerItem.averageBytes =
      current.memoryPerItem.averageBytesSum / current.memoryPerItem.sampleCount;
    current.memoryPerItem.peakBytes = Math.max(
      current.memoryPerItem.peakBytes ?? 0,
      event.data.memoryPeakBytes,
    );
    current.volume.outputBytes += event.data.outputBytes;
    current.volume.totalBytes = current.volume.inputBytes + current.volume.outputBytes;
    if (current.workload.currentBatch?.id === event.data.batchId) {
      current.workload.currentBatch.completedJobs += 1;
    }
  } else if (event.type === "standby.changed") {
    if (event.data.active && !current.standby.active) {
      current.standby.active = true;
      current.standby.since = event.occurredAt;
    } else if (!event.data.active && current.standby.active) {
      leaveStandby(current, eventTime, standbyStart);
    }
  }

  current.revision += 1;
  current.eventsAccepted += 1;
  current.lastEventAt = event.occurredAt;
  current.updatedAt = isoTimestamp(now, "now");
  current.deduplication.recentEventIds.push(event.eventId);
  current.deduplication.recentEventIds =
    current.deduplication.recentEventIds.slice(-512);
  return { metrics: parseMetrics(current), duplicate: false };
}

export function assertNoSecrets(value, path = "input", ancestors = new Set()) {
  if (!value || typeof value !== "object") return;
  if (ancestors.has(value)) throw new TypeError(`${path} must not be cyclic.`);
  ancestors.add(value);
  try {
    if (Array.isArray(value)) {
      value.forEach((item, index) => assertNoSecrets(item, `${path}[${index}]`, ancestors));
      return;
    }
    for (const [key, child] of Object.entries(value)) {
      if (SECRET_FIELD.test(key) && !NON_SECRET_TOKEN_BUDGET_FIELDS.has(key)) {
        throw new TypeError(`Forbidden secret-bearing field at ${path}.${key}.`);
      }
      assertNoSecrets(child, `${path}.${key}`, ancestors);
    }
  } finally {
    ancestors.delete(value);
  }
}

function parseEventData(type, value) {
  const data = record(value, `${type}.data`);
  if (type === "resource.sample") {
    exactKeys(data, [
      "cpuPercent",
      "cpuSecondsDelta",
      "gpu",
      "networkRxBytesDelta",
      "networkTxBytesDelta",
    ], `${type}.data`);
    const gpu = record(data.gpu, "resource.sample.data.gpu");
    exactKeys(gpu, ["status", "utilizationPercent", "activeSecondsDelta", "errorCode"], "gpu sample");
    const status = enumeration(gpu.status, GPU_STATES, "gpu.status");
    return {
      cpuPercent: percentage(data.cpuPercent, "cpuPercent"),
      cpuSecondsDelta: finiteNonNegative(data.cpuSecondsDelta, "cpuSecondsDelta"),
      gpu: {
        status,
        utilizationPercent: status === "available"
          ? percentage(gpu.utilizationPercent, "gpu.utilizationPercent")
          : mustBeNull(gpu.utilizationPercent, "gpu.utilizationPercent"),
        activeSecondsDelta: status === "available"
          ? finiteNonNegative(gpu.activeSecondsDelta, "gpu.activeSecondsDelta")
          : mustBeZero(gpu.activeSecondsDelta, "gpu.activeSecondsDelta"),
        errorCode: status === "error"
          ? identifier(gpu.errorCode, "gpu.errorCode", 96)
          : nullableIdentifier(gpu.errorCode, "gpu.errorCode", 96),
      },
      networkRxBytesDelta: unsignedInteger(data.networkRxBytesDelta, "networkRxBytesDelta"),
      networkTxBytesDelta: unsignedInteger(data.networkTxBytesDelta, "networkTxBytesDelta"),
    };
  }
  if (type === "job.started") {
    exactKeys(data, ["jobId", "batchId", "inputBytes"], `${type}.data`);
    return {
      jobId: identifier(data.jobId, "jobId", 128),
      batchId: identifier(data.batchId, "batchId", 128),
      inputBytes: unsignedInteger(data.inputBytes, "inputBytes"),
    };
  }
  if (type === "job.completed") {
    exactKeys(data, [
      "jobId",
      "batchId",
      "outcome",
      "durationMilliseconds",
      "memoryAverageBytes",
      "memoryPeakBytes",
      "outputBytes",
    ], `${type}.data`);
    const average = unsignedInteger(data.memoryAverageBytes, "memoryAverageBytes");
    const peak = unsignedInteger(data.memoryPeakBytes, "memoryPeakBytes");
    if (peak < average) throw new TypeError("memoryPeakBytes must be at least memoryAverageBytes.");
    return {
      jobId: identifier(data.jobId, "jobId", 128),
      batchId: identifier(data.batchId, "batchId", 128),
      outcome: enumeration(data.outcome, new Set(["succeeded", "failed"]), "outcome"),
      durationMilliseconds: finiteNonNegative(data.durationMilliseconds, "durationMilliseconds"),
      memoryAverageBytes: average,
      memoryPeakBytes: peak,
      outputBytes: unsignedInteger(data.outputBytes, "outputBytes"),
    };
  }
  if (type === "batch.started") {
    exactKeys(data, ["batchId", "totalJobs"], `${type}.data`);
    return {
      batchId: identifier(data.batchId, "batchId", 128),
      totalJobs: unsignedInteger(data.totalJobs, "totalJobs"),
    };
  }
  if (type === "batch.completed") {
    exactKeys(data, ["batchId"], `${type}.data`);
    return { batchId: identifier(data.batchId, "batchId", 128) };
  }
  exactKeys(data, ["active"], `${type}.data`);
  return { active: booleanValue(data.active, "active") };
}

function parseWorker(value) {
  const object = record(value, "worker");
  exactKeys(object, ["id", "displayName", "state", "version", "platform", "startedAt"], "worker");
  return {
    id: identifier(object.id, "worker.id", 128),
    displayName: text(object.displayName, "worker.displayName", 160),
    state: enumeration(object.state, WORKER_STATES, "worker.state"),
    version: nullableIdentifier(object.version, "worker.version", 64),
    platform: nullableIdentifier(object.platform, "worker.platform", 96),
    startedAt: nullableTimestamp(object.startedAt, "worker.startedAt"),
  };
}

function parseConnection(value) {
  const object = record(value, "connection");
  exactKeys(object, ["status", "lastSuccessAt", "lastFailureAt", "errorCode"], "connection");
  return {
    status: enumeration(object.status, CONNECTION_STATES, "connection.status"),
    lastSuccessAt: nullableTimestamp(object.lastSuccessAt, "connection.lastSuccessAt"),
    lastFailureAt: nullableTimestamp(object.lastFailureAt, "connection.lastFailureAt"),
    errorCode: nullableIdentifier(object.errorCode, "connection.errorCode", 96),
  };
}

function parseAuthentication(value) {
  const object = record(value, "authentication");
  exactKeys(object, ["status", "keyId", "lastVerifiedAt", "errorCode"], "authentication");
  return {
    status: enumeration(object.status, AUTHENTICATION_STATES, "authentication.status"),
    keyId: nullableIdentifier(object.keyId, "authentication.keyId", 256),
    lastVerifiedAt: nullableTimestamp(object.lastVerifiedAt, "authentication.lastVerifiedAt"),
    errorCode: nullableIdentifier(object.errorCode, "authentication.errorCode", 96),
  };
}

function parseTransport(value) {
  const object = record(value, "transport");
  exactKeys(object, [
    "tlsStatus",
    "certificateStatus",
    "certificateExpiresAt",
    "certificateFingerprint",
    "errorCode",
  ], "transport");
  return {
    tlsStatus: enumeration(object.tlsStatus, TLS_STATES, "transport.tlsStatus"),
    certificateStatus: enumeration(
      object.certificateStatus,
      CERTIFICATE_STATES,
      "transport.certificateStatus",
    ),
    certificateExpiresAt: nullableTimestamp(
      object.certificateExpiresAt,
      "transport.certificateExpiresAt",
    ),
    certificateFingerprint: nullableIdentifier(
      object.certificateFingerprint,
      "transport.certificateFingerprint",
      256,
    ),
    errorCode: nullableIdentifier(object.errorCode, "transport.errorCode", 96),
  };
}

function parseTrust(value) {
  const object = record(value, "trust");
  exactKeys(object, [
    "status",
    "rootKeyId",
    "releaseKeyId",
    "manifestSequence",
    "manifestHash",
    "policyHash",
    "lastVerifiedAt",
    "errorCode",
  ], "trust");
  return {
    status: enumeration(object.status, TRUST_STATES, "trust.status"),
    rootKeyId: nullableIdentifier(object.rootKeyId, "trust.rootKeyId", 256),
    releaseKeyId: nullableIdentifier(object.releaseKeyId, "trust.releaseKeyId", 256),
    manifestSequence: object.manifestSequence === null
      ? null
      : unsignedInteger(object.manifestSequence, "trust.manifestSequence"),
    manifestHash: nullableIdentifier(object.manifestHash, "trust.manifestHash", 256),
    policyHash: nullableIdentifier(object.policyHash, "trust.policyHash", 256),
    lastVerifiedAt: nullableTimestamp(object.lastVerifiedAt, "trust.lastVerifiedAt"),
    errorCode: nullableIdentifier(object.errorCode, "trust.errorCode", 96),
  };
}

function parseCurrentBatch(value) {
  const object = record(value, "currentBatch");
  exactKeys(object, ["id", "startedAt", "totalJobs", "completedJobs"], "currentBatch");
  const totalJobs = unsignedInteger(object.totalJobs, "currentBatch.totalJobs");
  const completedJobs = unsignedInteger(object.completedJobs, "currentBatch.completedJobs");
  if (completedJobs > totalJobs) throw new TypeError("completedJobs cannot exceed totalJobs.");
  return {
    id: identifier(object.id, "currentBatch.id", 128),
    startedAt: isoTimestamp(object.startedAt, "currentBatch.startedAt"),
    totalJobs,
    completedJobs,
  };
}

function parseClaimableByTier(value, claimable) {
  const tiers = record(value, "workload.claimableByTier");
  const entries = Object.entries(tiers);
  if (entries.length < 1 || entries.length > 8) {
    throw new TypeError("workload.claimableByTier must contain between 1 and 8 tiers.");
  }
  const output = {};
  for (const [tier, count] of entries) {
    const safeTier = identifier(tier, "workload.claimableByTier tier", 32);
    const safeCount = unsignedInteger(count, `workload.claimableByTier.${safeTier}`);
    if (claimable !== null && safeCount > claimable) {
      throw new TypeError("workload.claimableByTier cannot exceed workload.claimable.");
    }
    output[safeTier] = safeCount;
  }
  return Object.freeze(output);
}

function leaveStandby(metrics, eventTime, standbyStart) {
  if (!metrics.standby.active) return;
  if (Number.isFinite(standbyStart) && eventTime >= standbyStart) {
    metrics.standby.totalMilliseconds += eventTime - standbyStart;
  }
  metrics.standby.active = false;
  metrics.standby.since = null;
}

function record(value, name) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new TypeError(`${name} must be an object.`);
  }
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) {
    throw new TypeError(`${name} must be a plain object.`);
  }
  return value;
}

function exactKeys(object, allowed, name) {
  allowedKeys(object, allowed, name);
  const missing = allowed.filter((key) => !Object.hasOwn(object, key));
  if (missing.length) throw new TypeError(`${name} is missing field ${missing[0]}.`);
}

function allowedKeys(object, allowed, name) {
  const allowedSet = new Set(allowed);
  const unknown = Object.keys(object).filter((key) => !allowedSet.has(key));
  if (unknown.length) throw new TypeError(`${name} contains unsupported field ${unknown[0]}.`);
}

function enumeration(value, allowed, name) {
  if (typeof value !== "string" || !allowed.has(value)) {
    throw new TypeError(`${name} has an unsupported value.`);
  }
  return value;
}

function identifier(value, name, maximum, minimum = 1) {
  if (
    typeof value !== "string" ||
    value.length < minimum ||
    value.length > maximum ||
    /[\x00-\x20\x7f]/.test(value)
  ) {
    throw new TypeError(`${name} must be a bounded identifier without whitespace.`);
  }
  return value;
}

function nullableIdentifier(value, name, maximum) {
  return value === null ? null : identifier(value, name, maximum);
}

function text(value, name, maximum) {
  if (typeof value !== "string" || !value.trim() || value.length > maximum || /[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/.test(value)) {
    throw new TypeError(`${name} must be bounded display text.`);
  }
  return value.trim();
}

function nullableText(value, name, maximum) {
  return value === null ? null : text(value, name, maximum);
}

function isoTimestamp(value, name) {
  const date = value instanceof Date ? value : new Date(value);
  if (!Number.isFinite(date.getTime())) throw new TypeError(`${name} must be an ISO-8601 timestamp.`);
  return date.toISOString();
}

function nullableTimestamp(value, name) {
  return value === null ? null : isoTimestamp(value, name);
}

function unsignedInteger(value, name) {
  if (!Number.isSafeInteger(value) || value < 0) throw new TypeError(`${name} must be a non-negative safe integer.`);
  return value;
}

function nullableUnsignedInteger(value, name) {
  return value === null ? null : unsignedInteger(value, name);
}

function boundedCounter(value, maximum, name) {
  const parsed = unsignedInteger(value, name);
  if (parsed > maximum) throw new TypeError(`${name} must not exceed ${maximum}.`);
  return parsed;
}

function nullableBoundedCounter(value, maximum, name) {
  return value === null ? null : boundedCounter(value, maximum, name);
}

function finiteNonNegative(value, name) {
  if (!Number.isFinite(value) || value < 0) throw new TypeError(`${name} must be a finite non-negative number.`);
  return value;
}

function nullableNonNegative(value, name) {
  return value === null ? null : finiteNonNegative(value, name);
}

function percentage(value, name) {
  const number = finiteNonNegative(value, name);
  if (number > 100) throw new TypeError(`${name} must not exceed 100.`);
  return number;
}

function booleanValue(value, name) {
  if (typeof value !== "boolean") throw new TypeError(`${name} must be boolean.`);
  return value;
}

function nullableBoolean(value, name) {
  return value === null ? null : booleanValue(value, name);
}

function mustBeNull(value, name) {
  if (value !== null) throw new TypeError(`${name} must be null when GPU is not available.`);
  return null;
}

function mustBeZero(value, name) {
  if (value !== 0) throw new TypeError(`${name} must be zero when GPU is not available.`);
  return 0;
}

function derivedAverage(value, sum, count, name) {
  const expected = count === 0 ? null : sum / count;
  if (expected === null) {
    if (value !== null) throw new TypeError(`${name} must be null without samples.`);
    return null;
  }
  if (!Number.isFinite(value) || Math.abs(value - expected) > 1e-9) {
    throw new TypeError(`${name} does not match its aggregate.`);
  }
  return value;
}

function exactDerivedInteger(value, expected, name) {
  const parsed = unsignedInteger(value, name);
  if (parsed !== expected) throw new TypeError(`${name} does not match its aggregate.`);
  return parsed;
}

function identifierArray(value, name, maximumLength) {
  if (!Array.isArray(value) || value.length > maximumLength) {
    throw new TypeError(`${name} must be a bounded array.`);
  }
  const parsed = value.map((item, index) => identifier(item, `${name}[${index}]`, 128));
  if (new Set(parsed).size !== parsed.length) throw new TypeError(`${name} must not contain duplicates.`);
  return parsed;
}
