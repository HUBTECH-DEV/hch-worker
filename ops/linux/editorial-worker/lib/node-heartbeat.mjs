import { canonicalizeJson } from "../crypto.mjs";
import { WorkerKitError, errorCode } from "./errors.mjs";
import {
  effectiveRequestedCapacity,
  readWorkerControl,
  sampleCapacityPressure,
} from "./capacity.mjs";
import { signedPost } from "./http.mjs";
import { ensureWorkerIdentity } from "./identity.mjs";
import { assertSecretFree, updateStatus } from "./local-state.mjs";
import {
  atomicWriteJson,
  ensurePrivateDirectory,
  readOptionalJson,
} from "./storage.mjs";

export const NODE_HEARTBEAT_INTERVAL_SECONDS = 60;
export const NODE_HEARTBEAT_PATH = "/api/editorial/orchestrator/nodes/heartbeat";
export const NODE_HEARTBEAT_PURPOSE = "node-heartbeat";

const CAPACITY_CLASSES = new Set(["constrained", "standard", "accelerated"]);
const CLAIM_REASONS = new Set([
  "fleet-claims-disabled",
  "capacity-zero",
  "no-claimable-work",
  "claim-recommended",
]);
const HEARTBEAT_STATES = new Set([
  "unknown",
  "pending",
  "succeeded",
  "failed",
  "error",
]);
const ORCHESTRATION_MODES = new Set([
  "heartbeat-only",
  "waiting-for-work",
  "execution-authorized",
  "unavailable",
]);

/**
 * Performs exactly one signed node heartbeat and writes the dashboard snapshot.
 * This operation never calls claim, execute, an assignment heartbeat, or a local engine.
 */
export async function nodeHeartbeat(config, options = {}) {
  const attemptedAt = currentDate(options.now).toISOString();
  let stateRoot;
  let previous = null;
  try {
    stateRoot = await ensurePrivateDirectory(config.stateDirectory);
    let previousValue;
    try {
      previousValue = await readOptionalJson(stateRoot, "orchestration.json");
    } catch (error) {
      if (!String(error?.message).includes("is not valid JSON")) throw error;
      previousValue = null;
    }
    if (previousValue !== null) {
      try {
        previous = validateOrchestrationSnapshot(previousValue, {
          expectedNodeId: config.nodeId,
        });
      } catch {
        // A structurally invalid prior snapshot is not reused as remote truth.
      }
    }

    const identity = await ensureWorkerIdentity(config, stateRoot);
    const control = await readWorkerControl(stateRoot, config);
    const requestedCapacity = effectiveRequestedCapacity(control);
    const requestId = options.requestId ?? crypto.randomUUID();
    identifier(requestId, "requestId", 160);
    const pressure = options.pressure === undefined
      ? sampleCapacityPressure(options.resources)
      : validateCapacityPressure(options.pressure);
    const requestBody = {
      nodeId: config.nodeId,
      workerKeyId: config.keyId,
      requestedCapacity,
      ...(pressure === undefined ? {} : { pressure }),
    };
    const responseValue = await signedPost(config, identity, {
      path: NODE_HEARTBEAT_PATH,
      purpose: NODE_HEARTBEAT_PURPOSE,
      bodyText: canonicalizeJson(requestBody),
      requestId,
    }, heartbeatRequestOptions(options, 55_000));
    const response = validateNodeHeartbeatResponse(responseValue, {
      nodeId: config.nodeId,
      requestId,
      requestedCapacity,
    });
    const snapshot = successfulSnapshot(response, attemptedAt);
    assertSecretFree(snapshot, "orchestration");
    await atomicWriteJson(stateRoot, "orchestration.json", snapshot);
    const previousCapacity = await readOptionalJson(stateRoot, "capacity.json");
    if (previousCapacity?.schema === "hch.worker-capacity/v1") {
      await atomicWriteJson(stateRoot, "capacity.json", {
        ...previousCapacity,
        observedAt: response.serverTime,
        requestedCapacity: response.capacity.requestedCapacity,
        grantedCapacity: response.capacity.grantedCapacity,
        capacityClass: response.capacity.capacityClass,
        reason: response.capacity.reason,
        grantedUntil: response.capacity.grantedUntil,
        pressure,
        activeAssignments: response.capacity.activeAssignments,
        availableSlots: response.capacity.availableSlots,
        source: "node-heartbeat",
      });
    }
    await updateStatus(stateRoot, config, {});
    return {
      ...snapshot,
      requestId: response.requestId,
      workStarted: false,
      claimStarted: false,
    };
  } catch (error) {
    if (stateRoot) {
      const failed = failedSnapshot(
        config,
        previous,
        attemptedAt,
        errorCode(error, "node-heartbeat-failed"),
      );
      try {
        assertSecretFree(failed, "orchestration");
        await atomicWriteJson(stateRoot, "orchestration.json", failed);
      } catch {
        // Preserve the original operation failure if local state cannot be written.
      }
    }
    throw error;
  }
}

function heartbeatRequestOptions(options, deadlineMilliseconds) {
  return {
    ...options,
    requestRetries: 0,
    totalDeadlineMilliseconds: deadlineMilliseconds,
    timeoutMilliseconds: Math.min(
      options.timeoutMilliseconds ?? deadlineMilliseconds,
      deadlineMilliseconds,
    ),
    operationTimeoutMilliseconds: Math.min(
      options.operationTimeoutMilliseconds ?? deadlineMilliseconds,
      deadlineMilliseconds,
    ),
  };
}

export function validateNodeHeartbeatResponse(value, expected) {
  try {
    const response = exactRecord(value, [
      "requestId",
      "nodeId",
      "heartbeatAt",
      "nextHeartbeatSeconds",
      "capacity",
      "workload",
      "workSizing",
      "claim",
      "serverTime",
    ], "node heartbeat response");
    const requestId = identifier(response.requestId, "response.requestId", 160);
    const nodeId = identifier(response.nodeId, "response.nodeId", 128);
    if (requestId !== expected.requestId || nodeId !== expected.nodeId) {
      invalidResponse("The node heartbeat response is correlated to another request or node.");
    }
    if (response.nextHeartbeatSeconds !== NODE_HEARTBEAT_INTERVAL_SECONDS) {
      invalidResponse("The node heartbeat interval is not the required 60 seconds.");
    }
    const capacity = parseCapacity(response.capacity, false);
    const workload = parseWorkload(response.workload, false);
    const workSizing = parseWorkSizing(response.workSizing, false);
    const claim = parseClaim(response.claim, false);
    if (capacity.requestedCapacity !== expected.requestedCapacity) {
      invalidResponse("The granted capacity does not match the requested capacity.");
    }
    validateCapacityRelationships(capacity);
    validateWorkloadRelationships(workload);
    validateClaimRelationships(claim, capacity, workload, true);
    return {
      requestId,
      nodeId,
      heartbeatAt: timestamp(response.heartbeatAt, "response.heartbeatAt"),
      nextHeartbeatSeconds: response.nextHeartbeatSeconds,
      capacity,
      workload,
      workSizing,
      claim,
      serverTime: timestamp(response.serverTime, "response.serverTime"),
    };
  } catch (error) {
    if (error?.code === "node-heartbeat-response-invalid") throw error;
    throw new WorkerKitError(
      "node-heartbeat-response-invalid",
      "The orchestrator returned an invalid node heartbeat response.",
      { cause: error },
    );
  }
}

export function validateOrchestrationSnapshot(value, options = {}) {
  const snapshot = exactRecord(value, [
    "schema",
    "schemaVersion",
    "observedAt",
    "nodeId",
    "mode",
    "heartbeat",
    "capacity",
    "workload",
    "workSizing",
    "claim",
  ], "orchestration snapshot");
  if (snapshot.schema !== "hch.worker-orchestration/v1" || snapshot.schemaVersion !== 1) {
    throw new TypeError("Unsupported orchestration snapshot schema.");
  }
  const nodeId = identifier(snapshot.nodeId, "orchestration.nodeId", 128);
  if (options.expectedNodeId !== undefined && nodeId !== options.expectedNodeId) {
    throw new TypeError("The orchestration snapshot belongs to another node.");
  }
  const heartbeat = parseSnapshotHeartbeat(snapshot.heartbeat);
  const capacity = parseCapacity(snapshot.capacity, true);
  const workload = parseWorkload(snapshot.workload, true);
  const workSizing = parseWorkSizing(snapshot.workSizing, true);
  const claim = parseClaim(snapshot.claim, true);
  validateCapacityRelationships(capacity);
  validateWorkloadRelationships(workload);
  validateClaimRelationships(claim, capacity, workload);
  const mode = enumeration(snapshot.mode, ORCHESTRATION_MODES, "orchestration.mode");
  if (claim.allowed !== null && ((mode === "execution-authorized") !== claim.allowed)) {
    throw new TypeError("Orchestration mode does not match claim authorization.");
  }
  return {
    schema: "hch.worker-orchestration/v1",
    schemaVersion: 1,
    observedAt: timestamp(snapshot.observedAt, "orchestration.observedAt"),
    nodeId,
    mode,
    heartbeat,
    capacity,
    workload,
    workSizing,
    claim,
  };
}

function successfulSnapshot(response, attemptedAt) {
  const executionAuthorized = response.claim.allowed && response.claim.recommendedCount > 0;
  const mode = executionAuthorized
    ? "execution-authorized"
    : response.capacity.grantedCapacity === 0
      ? "heartbeat-only"
      : "waiting-for-work";
  return {
    schema: "hch.worker-orchestration/v1",
    schemaVersion: 1,
    observedAt: response.serverTime,
    nodeId: response.nodeId,
    mode,
    heartbeat: {
      status: "succeeded",
      lastAttemptAt: attemptedAt,
      lastSuccessAt: response.heartbeatAt,
      nextHeartbeatAt: addSeconds(
        response.heartbeatAt,
        response.nextHeartbeatSeconds,
      ),
      intervalSeconds: response.nextHeartbeatSeconds,
      errorCode: null,
    },
    capacity: response.capacity,
    workload: response.workload,
    workSizing: response.workSizing,
    claim: response.claim,
  };
}

function failedSnapshot(config, previous, attemptedAt, code) {
  return {
    schema: "hch.worker-orchestration/v1",
    schemaVersion: 1,
    observedAt: attemptedAt,
    nodeId: config.nodeId,
    mode: previous?.mode ?? "unavailable",
    heartbeat: {
      status: "failed",
      lastAttemptAt: attemptedAt,
      lastSuccessAt: previous?.heartbeat.lastSuccessAt ?? null,
      nextHeartbeatAt: addSeconds(attemptedAt, NODE_HEARTBEAT_INTERVAL_SECONDS),
      intervalSeconds: NODE_HEARTBEAT_INTERVAL_SECONDS,
      errorCode: code,
    },
    capacity: previous?.capacity ?? {
      configuredCapacity: null,
        requestedCapacity: previous?.capacity.requestedCapacity ?? config.requestedCapacity,
      grantedCapacity: null,
      activeAssignments: null,
      availableSlots: null,
      capacityClass: null,
      reason: null,
      grantedUntil: null,
    },
    workload: previous?.workload ?? {
      claimable: null,
      generating: null,
      futureTotal: null,
      claimableByTier: null,
    },
    workSizing: previous?.workSizing ?? null,
    claim: previous?.claim ?? {
      allowed: null,
      recommendedCount: null,
      reason: null,
    },
  };
}

function parseSnapshotHeartbeat(value) {
  const heartbeat = exactRecord(value, [
    "status",
    "lastAttemptAt",
    "lastSuccessAt",
    "nextHeartbeatAt",
    "intervalSeconds",
    "errorCode",
  ], "orchestration heartbeat");
  const intervalSeconds = boundedInteger(
    heartbeat.intervalSeconds,
    1,
    3_600,
    "heartbeat.intervalSeconds",
  );
  return {
    status: enumeration(heartbeat.status, HEARTBEAT_STATES, "heartbeat.status"),
    lastAttemptAt: nullableTimestamp(heartbeat.lastAttemptAt, "heartbeat.lastAttemptAt"),
    lastSuccessAt: nullableTimestamp(heartbeat.lastSuccessAt, "heartbeat.lastSuccessAt"),
    nextHeartbeatAt: nullableTimestamp(heartbeat.nextHeartbeatAt, "heartbeat.nextHeartbeatAt"),
    intervalSeconds,
    errorCode: heartbeat.errorCode === null
      ? null
      : identifier(heartbeat.errorCode, "heartbeat.errorCode", 96),
  };
}

function parseCapacity(value, nullable) {
  const capacity = exactRecord(value, [
    "configuredCapacity",
    "requestedCapacity",
    "grantedCapacity",
    "activeAssignments",
    "availableSlots",
    "capacityClass",
    "reason",
    "grantedUntil",
  ], "heartbeat capacity");
  return {
    configuredCapacity: nullableInteger(
      capacity.configuredCapacity,
      0,
      64,
      "capacity.configuredCapacity",
      nullable,
    ),
    requestedCapacity: nullableInteger(
      capacity.requestedCapacity,
      0,
      64,
      "capacity.requestedCapacity",
      nullable,
    ),
    grantedCapacity: nullableInteger(
      capacity.grantedCapacity,
      0,
      32,
      "capacity.grantedCapacity",
      nullable,
    ),
    activeAssignments: nullableInteger(
      capacity.activeAssignments,
      0,
      Number.MAX_SAFE_INTEGER,
      "capacity.activeAssignments",
      nullable,
    ),
    availableSlots: nullableInteger(
      capacity.availableSlots,
      0,
      32,
      "capacity.availableSlots",
      nullable,
    ),
    capacityClass: capacity.capacityClass === null && nullable
      ? null
      : enumeration(capacity.capacityClass, CAPACITY_CLASSES, "capacity.capacityClass"),
    reason: capacity.reason === null && nullable
      ? null
      : boundedText(capacity.reason, "capacity.reason", 160),
    grantedUntil: capacity.grantedUntil === null
      ? null
      : timestamp(capacity.grantedUntil, "capacity.grantedUntil"),
  };
}

function parseWorkload(value, nullable) {
  const workload = exactRecord(value, [
    "claimable",
    "generating",
    "futureTotal",
    "claimableByTier",
  ], "heartbeat workload");
  return {
    claimable: nullableInteger(
      workload.claimable,
      0,
      Number.MAX_SAFE_INTEGER,
      "workload.claimable",
      nullable,
    ),
    generating: nullableInteger(
      workload.generating,
      0,
      Number.MAX_SAFE_INTEGER,
      "workload.generating",
      nullable,
    ),
    futureTotal: nullableInteger(
      workload.futureTotal,
      0,
      Number.MAX_SAFE_INTEGER,
      "workload.futureTotal",
      nullable,
    ),
    claimableByTier: parseClaimableByTier(
      workload.claimableByTier,
      nullable,
      workload.claimable,
    ),
  };
}

function parseClaimableByTier(value, nullable, claimable) {
  if (value === null && nullable) return null;
  const tiers = record(value, "workload.claimableByTier");
  const entries = Object.entries(tiers);
  if (entries.length < 1 || entries.length > 8) {
    throw new TypeError("workload.claimableByTier must contain between 1 and 8 tiers.");
  }
  const output = {};
  for (const [tier, count] of entries) {
    if (!/^[a-z][a-z0-9-]{0,31}$/.test(tier)) {
      throw new TypeError("workload.claimableByTier contains an invalid tier id.");
    }
    const normalized = boundedInteger(
      count,
      0,
      Number.MAX_SAFE_INTEGER,
      `workload.claimableByTier.${tier}`,
    );
    if (claimable !== null && normalized > claimable) {
      throw new TypeError("workload.claimableByTier exceeds workload.claimable.");
    }
    output[tier] = normalized;
  }
  return output;
}

function parseWorkSizing(value, nullable) {
  if (value === null && nullable) return null;
  const sizing = exactRecord(value, [
    "algorithmVersion",
    "currentTier",
    "currentRank",
    "maxOutputTokens",
    "editorialProfile",
    "minimumUnit",
    "reason",
    "updatedAt",
    "processingWindowSeconds",
    "nearWindowSeconds",
    "firstProgressGraceSeconds",
    "stallAfterSeconds",
    "finalizationGraceSeconds",
  ], "heartbeat workSizing");
  if (sizing.algorithmVersion !== "hch-adaptive-work-v1") {
    throw new TypeError("workSizing.algorithmVersion is unsupported.");
  }
  const currentTier = identifier(sizing.currentTier, "workSizing.currentTier", 32);
  if (!/^[a-z][a-z0-9-]{0,31}$/.test(currentTier)) {
    throw new TypeError("workSizing.currentTier is invalid.");
  }
  const currentRank = boundedInteger(sizing.currentRank, 0, 15, "workSizing.currentRank");
  const minimumUnit = booleanValue(sizing.minimumUnit, "workSizing.minimumUnit");
  if (minimumUnit !== (currentRank === 0)) {
    throw new TypeError("workSizing.minimumUnit does not match currentRank.");
  }
  const processingWindowSeconds = boundedInteger(
    sizing.processingWindowSeconds,
    60,
    86_400,
    "workSizing.processingWindowSeconds",
  );
  const nearWindowSeconds = boundedInteger(
    sizing.nearWindowSeconds,
    1,
    processingWindowSeconds,
    "workSizing.nearWindowSeconds",
  );
  return {
    algorithmVersion: "hch-adaptive-work-v1",
    currentTier,
    currentRank,
    maxOutputTokens: boundedInteger(
      sizing.maxOutputTokens,
      1,
      4_096,
      "workSizing.maxOutputTokens",
    ),
    editorialProfile: identifier(
      sizing.editorialProfile,
      "workSizing.editorialProfile",
      64,
    ),
    minimumUnit,
    reason: enumeration(sizing.reason, new Set([
      "attestation-reset",
      "minimum-unit-window-ignored",
      "within-window",
      "near-window-downshift",
      "already-downshifted",
    ]), "workSizing.reason"),
    updatedAt: timestamp(sizing.updatedAt, "workSizing.updatedAt"),
    processingWindowSeconds,
    nearWindowSeconds,
    firstProgressGraceSeconds: boundedInteger(
      sizing.firstProgressGraceSeconds,
      30,
      processingWindowSeconds,
      "workSizing.firstProgressGraceSeconds",
    ),
    stallAfterSeconds: boundedInteger(
      sizing.stallAfterSeconds,
      30,
      processingWindowSeconds,
      "workSizing.stallAfterSeconds",
    ),
    finalizationGraceSeconds: boundedInteger(
      sizing.finalizationGraceSeconds,
      30,
      processingWindowSeconds,
      "workSizing.finalizationGraceSeconds",
    ),
  };
}

function parseClaim(value, nullable) {
  const claim = exactRecord(value, [
    "allowed",
    "recommendedCount",
    "reason",
  ], "heartbeat claim");
  const allowed = claim.allowed === null && nullable
    ? null
    : booleanValue(claim.allowed, "claim.allowed");
  const recommendedCount = nullableInteger(
    claim.recommendedCount,
    0,
    32,
    "claim.recommendedCount",
    nullable,
  );
  const reason = claim.reason === null && nullable
    ? null
    : nullable
      ? boundedText(claim.reason, "claim.reason", 160)
      : enumeration(claim.reason, CLAIM_REASONS, "claim.reason");
  return { allowed, recommendedCount, reason };
}

function validateCapacityRelationships(capacity) {
  if (
    capacity.availableSlots !== null &&
    capacity.grantedCapacity !== null &&
    capacity.availableSlots > capacity.grantedCapacity
  ) {
    throw new TypeError("capacity.availableSlots exceeds grantedCapacity.");
  }
  if (
    capacity.grantedCapacity !== null &&
    ((capacity.requestedCapacity !== null &&
      capacity.grantedCapacity > capacity.requestedCapacity) ||
      (capacity.configuredCapacity !== null &&
        capacity.grantedCapacity > capacity.configuredCapacity))
  ) {
    throw new TypeError("capacity.grantedCapacity exceeds a negotiated ceiling.");
  }
}

function validateWorkloadRelationships(workload) {
  if (
    workload.futureTotal !== null &&
    ((workload.claimable !== null && workload.futureTotal < workload.claimable) ||
      (workload.generating !== null && workload.futureTotal < workload.generating))
  ) {
    throw new TypeError("workload.futureTotal is below a reported subset.");
  }
}

function validateClaimRelationships(claim, capacity, workload, strictReason = false) {
  if (
    claim.allowed !== null &&
    claim.recommendedCount !== null &&
    claim.allowed !== (claim.recommendedCount > 0)
  ) {
    throw new TypeError("claim.allowed does not match recommendedCount.");
  }
  if (
    claim.recommendedCount !== null &&
    ((capacity.grantedCapacity !== null &&
      claim.recommendedCount > capacity.grantedCapacity) ||
      (capacity.availableSlots !== null &&
        claim.recommendedCount > capacity.availableSlots) ||
      (workload.claimable !== null &&
        claim.recommendedCount > workload.claimable))
  ) {
    throw new TypeError("claim.recommendedCount exceeds capacity or workload.");
  }
  if (
    strictReason &&
    claim.reason !== null &&
    ((claim.reason === "claim-recommended") !== (claim.recommendedCount > 0))
  ) {
    throw new TypeError("claim.reason does not match recommendedCount.");
  }
}

function validateCapacityPressure(value) {
  if (value === undefined) return undefined;
  const pressure = record(value, "pressure");
  const allowed = ["cpuPercent", "memoryPercent", "gpuPercent"];
  const unknown = Object.keys(pressure).find((key) => !allowed.includes(key));
  if (unknown) throw new TypeError(`pressure contains unsupported field ${unknown}.`);
  const normalized = {};
  for (const key of allowed) {
    if (Object.hasOwn(pressure, key)) {
      const metric = pressure[key];
      if (typeof metric !== "number" || !Number.isFinite(metric) || metric < 0 || metric > 100) {
        throw new TypeError(`pressure.${key} must be between 0 and 100.`);
      }
      normalized[key] = metric;
    }
  }
  return normalized;
}

function exactRecord(value, keys, name) {
  const object = record(value, name);
  const allowed = new Set(keys);
  const unknown = Object.keys(object).find((key) => !allowed.has(key));
  if (unknown) throw new TypeError(`${name} contains unsupported field ${unknown}.`);
  const missing = keys.find((key) => !Object.hasOwn(object, key));
  if (missing) throw new TypeError(`${name} is missing field ${missing}.`);
  return object;
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

function enumeration(value, allowed, name) {
  if (typeof value !== "string" || !allowed.has(value)) {
    throw new TypeError(`${name} has an unsupported value.`);
  }
  return value;
}

function identifier(value, name, maximum) {
  if (
    typeof value !== "string" ||
    !value ||
    value.length > maximum ||
    /[\x00-\x20\x7f]/.test(value)
  ) {
    throw new TypeError(`${name} must be a bounded identifier without whitespace.`);
  }
  return value;
}

function boundedText(value, name, maximum) {
  if (
    typeof value !== "string" ||
    !value.trim() ||
    value.length > maximum ||
    /[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/.test(value)
  ) {
    throw new TypeError(`${name} must be bounded display text.`);
  }
  return value.trim();
}

function boundedInteger(value, minimum, maximum, name) {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    throw new TypeError(`${name} must be an integer between ${minimum} and ${maximum}.`);
  }
  return value;
}

function nullableInteger(value, minimum, maximum, name, nullable) {
  if (value === null && nullable) return null;
  return boundedInteger(value, minimum, maximum, name);
}

function booleanValue(value, name) {
  if (typeof value !== "boolean") throw new TypeError(`${name} must be boolean.`);
  return value;
}

function timestamp(value, name) {
  if (typeof value !== "string" || !Number.isFinite(Date.parse(value))) {
    throw new TypeError(`${name} must be an ISO-8601 timestamp.`);
  }
  return new Date(value).toISOString();
}

function nullableTimestamp(value, name) {
  return value === null ? null : timestamp(value, name);
}

function currentDate(value) {
  const date = value === undefined ? new Date() : value instanceof Date ? value : new Date(value);
  if (!Number.isFinite(date.getTime())) throw new TypeError("now must be a valid timestamp.");
  return new Date(date);
}

function addSeconds(value, seconds) {
  return new Date(Date.parse(value) + seconds * 1_000).toISOString();
}

function invalidResponse(message) {
  throw new WorkerKitError("node-heartbeat-response-invalid", message);
}
