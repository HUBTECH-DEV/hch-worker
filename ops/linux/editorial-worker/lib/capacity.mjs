import { cpus, freemem, loadavg, totalmem } from "node:os";

import { canonicalizeJson, sha256Hex } from "../crypto.mjs";
import { WorkerKitError } from "./errors.mjs";
import {
  atomicWriteJson,
  readOptionalJson,
} from "./storage.mjs";

const CAPACITY_CLASSES = new Set(["constrained", "standard", "accelerated"]);
const PRESSURE_FIELDS = new Set(["cpuPercent", "memoryPercent", "gpuPercent"]);
const POLICY_FIELDS = new Set([
  "algorithmVersion",
  "absoluteRequestedMaximum",
  "defaultNodeCeiling",
  "globalAssignmentCeiling",
  "grantTtlSeconds",
  "telemetryMayOnlyReduce",
  "classCeilings",
  "platformClasses",
  "nodeClasses",
  "nodeCeilings",
  "pressure",
]);
const DECISION_FIELDS = new Set([
  "algorithmVersion",
  "requestedCapacity",
  "grantedCapacity",
  "availableSlots",
  "activeAssignments",
  "globalActiveAssignments",
  "globalAvailableBeforeGrant",
  "capacityClass",
  "nodeCeiling",
  "reason",
  "grantedUntil",
  "pressure",
]);
const GRANT_FIELDS = new Set([
  "requestedCapacity",
  "grantedCapacity",
  "capacityClass",
  "reason",
  "grantedUntil",
]);

export function validateCapacityPolicy(value) {
  const policy = exactRecord(value, POLICY_FIELDS, "capacityPolicy", "capacity-policy-invalid");
  if (
    policy.algorithmVersion !== "hch-adaptive-capacity-v1" ||
    policy.absoluteRequestedMaximum !== 64 ||
    policy.telemetryMayOnlyReduce !== true
  ) {
    throw capacityError(
      "capacity-policy-unsupported",
      "The signed capacity policy uses unsupported structural guarantees.",
    );
  }
  const defaultNodeCeiling = capacityInteger(
    policy.defaultNodeCeiling,
    "capacityPolicy.defaultNodeCeiling",
  );
  const globalAssignmentCeiling = boundedInteger(
    policy.globalAssignmentCeiling,
    1,
    4096,
    "capacityPolicy.globalAssignmentCeiling",
  );
  const grantTtlSeconds = boundedInteger(
    policy.grantTtlSeconds,
    1,
    3600,
    "capacityPolicy.grantTtlSeconds",
  );
  const classCeilings = exactRecord(
    policy.classCeilings,
    CAPACITY_CLASSES,
    "capacityPolicy.classCeilings",
    "capacity-policy-invalid",
  );
  const normalizedClassCeilings = {};
  for (const name of CAPACITY_CLASSES) {
    normalizedClassCeilings[name] = capacityInteger(
      classCeilings[name],
      `capacityPolicy.classCeilings.${name}`,
    );
  }
  if (
    normalizedClassCeilings.constrained > normalizedClassCeilings.standard ||
    normalizedClassCeilings.standard > normalizedClassCeilings.accelerated
  ) {
    throw capacityError(
      "capacity-policy-invalid",
      "Capacity class ceilings must be monotonic.",
    );
  }
  const platformClasses = capacityClassMap(
    policy.platformClasses,
    "capacityPolicy.platformClasses",
    ["linux", "macos", "windows"],
  );
  const nodeClasses = capacityClassMap(
    policy.nodeClasses,
    "capacityPolicy.nodeClasses",
    [],
  );
  const nodeCeilings = capacityIntegerMap(
    policy.nodeCeilings,
    "capacityPolicy.nodeCeilings",
  );
  const pressure = exactRecord(
    policy.pressure,
    new Set(["softLimitPercent", "hardLimitPercent", "softReductionFactor"]),
    "capacityPolicy.pressure",
    "capacity-policy-invalid",
  );
  const softLimitPercent = percentage(
    pressure.softLimitPercent,
    "capacityPolicy.pressure.softLimitPercent",
  );
  const hardLimitPercent = percentage(
    pressure.hardLimitPercent,
    "capacityPolicy.pressure.hardLimitPercent",
  );
  if (
    softLimitPercent >= hardLimitPercent ||
    typeof pressure.softReductionFactor !== "number" ||
    !Number.isFinite(pressure.softReductionFactor) ||
    pressure.softReductionFactor < 0 ||
    pressure.softReductionFactor > 1
  ) {
    throw capacityError("capacity-policy-invalid", "Capacity pressure policy is invalid.");
  }
  return {
    algorithmVersion: policy.algorithmVersion,
    absoluteRequestedMaximum: 64,
    defaultNodeCeiling,
    globalAssignmentCeiling,
    grantTtlSeconds,
    telemetryMayOnlyReduce: true,
    classCeilings: normalizedClassCeilings,
    platformClasses,
    nodeClasses,
    nodeCeilings,
    pressure: {
      softLimitPercent,
      hardLimitPercent,
      softReductionFactor: pressure.softReductionFactor,
    },
  };
}

export function validateRequestedCapacity(value, maximum = 64) {
  return boundedInteger(value, 0, maximum, "requestedCapacity", "requested-capacity-invalid");
}

export function validateCapacityPressure(value = {}) {
  const pressure = exactRecord(
    value,
    PRESSURE_FIELDS,
    "pressure",
    "capacity-pressure-invalid",
    { allowMissing: true },
  );
  const normalized = {};
  for (const field of PRESSURE_FIELDS) {
    if (pressure[field] !== undefined) {
      normalized[field] = roundPercentage(percentage(pressure[field], `pressure.${field}`));
    }
  }
  return normalized;
}

export function sampleCapacityPressure(resources = {}) {
  const logicalProcessors = resources.logicalProcessors ?? cpus().length;
  const oneMinuteLoad = resources.oneMinuteLoad ?? loadavg()[0];
  const memoryTotal = resources.totalMemoryBytes ?? totalmem();
  const memoryAvailable = resources.availableMemoryBytes ?? freemem();
  const pressure = {
    cpuPercent: roundPercentage(
      Math.max(0, Number(oneMinuteLoad)) / Math.max(1, Number(logicalProcessors)) * 100,
    ),
    memoryPercent: roundPercentage(
      (Math.max(0, Number(memoryTotal)) - Math.max(0, Number(memoryAvailable))) /
        Math.max(1, Number(memoryTotal)) * 100,
    ),
  };
  if (resources.gpuPercent !== undefined && resources.gpuPercent !== null) {
    pressure.gpuPercent = resources.gpuPercent;
  }
  return validateCapacityPressure(pressure);
}

export async function capacityPolicyHash(policy) {
  return sha256Hex(canonicalizeJson(validateCapacityPolicy(policy)));
}

export function capacityClassForWorker(policyValue, nodeId, platform = "linux") {
  const policy = validateCapacityPolicy(policyValue);
  const capacityClass = policy.nodeClasses[nodeId] ?? policy.platformClasses[platform];
  if (!CAPACITY_CLASSES.has(capacityClass)) {
    throw capacityError(
      "capacity-policy-worker-class-missing",
      "The signed policy does not assign a supported capacity class to this worker.",
    );
  }
  return capacityClass;
}

export function capacityCeilingForWorker(policyValue, nodeId, platform = "linux") {
  const policy = validateCapacityPolicy(policyValue);
  const capacityClass = capacityClassForWorker(policy, nodeId, platform);
  return Math.min(
    policy.absoluteRequestedMaximum,
    policy.nodeCeilings[nodeId] ?? policy.classCeilings[capacityClass] ?? policy.defaultNodeCeiling,
  );
}

export function validateAttestedCapacityGrant(value, context) {
  const grant = exactRecord(
    value,
    GRANT_FIELDS,
    "capacity grant",
    "capacity-grant-invalid",
  );
  const common = validateGrantCommon(grant, context);
  validateGrantTtl(common.grantedUntil, context);
  return common;
}

export function validateCapacityDecision(value, context) {
  const decision = exactRecord(
    value,
    DECISION_FIELDS,
    "capacity decision",
    "capacity-decision-invalid",
  );
  if (decision.algorithmVersion !== context.policy.algorithmVersion) {
    throw capacityError(
      "capacity-decision-invalid",
      "Capacity decision algorithm does not match the signed policy.",
    );
  }
  const common = validateGrantCommon(decision, context);
  const availableSlots = capacityInteger(decision.availableSlots, "capacity.availableSlots");
  const activeAssignments = nonnegativeInteger(
    decision.activeAssignments,
    "capacity.activeAssignments",
  );
  const globalActiveAssignments = nonnegativeInteger(
    decision.globalActiveAssignments,
    "capacity.globalActiveAssignments",
  );
  const globalAvailableBeforeGrant = boundedInteger(
    decision.globalAvailableBeforeGrant,
    0,
    context.policy.globalAssignmentCeiling,
    "capacity.globalAvailableBeforeGrant",
  );
  const nodeCeiling = capacityInteger(decision.nodeCeiling, "capacity.nodeCeiling");
  const expectedCeiling = capacityCeilingForWorker(
    context.policy,
    context.nodeId,
    context.platform ?? "linux",
  );
  if (
    nodeCeiling !== expectedCeiling ||
    availableSlots !== Math.max(0, common.grantedCapacity - activeAssignments) ||
    common.grantedCapacity > globalAvailableBeforeGrant ||
    globalActiveAssignments < activeAssignments
  ) {
    throw capacityError(
      "capacity-decision-invalid",
      "Capacity decision arithmetic is inconsistent with the signed policy.",
    );
  }
  const pressure = validateCapacityPressure(decision.pressure);
  if (
    context.pressure &&
    canonicalizeJson(pressure) !== canonicalizeJson(validateCapacityPressure(context.pressure))
  ) {
    throw capacityError(
      "capacity-pressure-echo-mismatch",
      "Capacity decision does not echo the signed request pressure.",
    );
  }
  validateGrantTtl(common.grantedUntil, context, { allowExpired: true });
  return {
    algorithmVersion: decision.algorithmVersion,
    ...common,
    availableSlots,
    activeAssignments,
    globalActiveAssignments,
    globalAvailableBeforeGrant,
    nodeCeiling,
    pressure,
  };
}

export async function persistCapacityGrant(stateRoot, config, grant, context) {
  const policyHash = await capacityPolicyHash(context.policy);
  const record = {
    schema: "hch.worker-capacity/v1",
    schemaVersion: 1,
    observedAt: new Date().toISOString(),
    nodeId: config.nodeId,
    workerKeyId: config.keyId,
    manifestSequence: context.manifest.sequence,
    manifestHash: context.manifest.hash,
    capacityPolicyHash: policyHash,
    algorithmVersion: context.policy.algorithmVersion,
    requestedCapacity: grant.requestedCapacity,
    grantedCapacity: grant.grantedCapacity,
    capacityClass: grant.capacityClass,
    reason: grant.reason,
    grantedUntil: grant.grantedUntil,
    pressure: grant.pressure ?? {},
    activeAssignments: grant.activeAssignments ?? 0,
    availableSlots: grant.availableSlots ?? Math.max(0, grant.grantedCapacity),
    source: context.source,
  };
  await atomicWriteJson(stateRoot, "capacity.json", record);
  return record;
}

export function capacityStatus(snapshot, requestedCapacity, now = new Date()) {
  const validUntil = typeof snapshot?.grantedUntil === "string"
    ? Date.parse(snapshot.grantedUntil)
    : Number.NaN;
  const grantExpired = !Number.isFinite(validUntil) || validUntil <= now.getTime();
  const draining = requestedCapacity === 0;
  return {
    requestedCapacity,
    grantedCapacity: nonnegativeIntegerOr(snapshot?.grantedCapacity, 0),
    effectiveGrantedCapacity: draining || grantExpired
      ? 0
      : nonnegativeIntegerOr(snapshot?.grantedCapacity, 0),
    capacityClass: CAPACITY_CLASSES.has(snapshot?.capacityClass)
      ? snapshot.capacityClass
      : null,
    reason: draining ? "drain-requested" : safeReason(snapshot?.reason, "not-negotiated"),
    grantedUntil: Number.isFinite(validUntil) ? new Date(validUntil).toISOString() : null,
    grantExpired,
    pressure: validateCapacityPressure(snapshot?.pressure ?? {}),
    activeAssignments: nonnegativeIntegerOr(snapshot?.activeAssignments, 0),
  };
}

export function defaultWorkerControl(config) {
  const configured = validateRequestedCapacity(config.requestedCapacity);
  const nonzero = Math.max(1, configured);
  return {
    schema: "hch.worker-control/v1",
    schemaVersion: 1,
    nodeId: config.nodeId,
    workerKeyId: config.keyId,
    acceptingClaims: configured > 0,
    requestedCapacity: configured,
    lastNonZeroCapacity: nonzero,
    drainRequested: configured === 0,
    updatedAt: null,
    updatedBy: "config-default",
  };
}

export async function readWorkerControl(stateRoot, config) {
  const value = await readOptionalJson(stateRoot, "worker-control.json");
  if (!value) return defaultWorkerControl(config);
  const fields = new Set([
    "schema",
    "schemaVersion",
    "nodeId",
    "workerKeyId",
    "acceptingClaims",
    "requestedCapacity",
    "lastNonZeroCapacity",
    "drainRequested",
    "updatedAt",
    "updatedBy",
  ]);
  exactRecord(value, fields, "worker control", "worker-control-invalid");
  const requestedCapacity = validateRequestedCapacity(value.requestedCapacity);
  const lastNonZeroCapacity = boundedInteger(
    value.lastNonZeroCapacity,
    1,
    64,
    "lastNonZeroCapacity",
    "worker-control-invalid",
  );
  if (
    value.schema !== "hch.worker-control/v1" ||
    value.schemaVersion !== 1 ||
    value.nodeId !== config.nodeId ||
    value.workerKeyId !== config.keyId ||
    typeof value.acceptingClaims !== "boolean" ||
    typeof value.drainRequested !== "boolean" ||
    value.acceptingClaims === value.drainRequested ||
    (value.acceptingClaims && requestedCapacity === 0) ||
    (value.updatedAt !== null && !Number.isFinite(Date.parse(value.updatedAt))) ||
    !/^[a-z0-9][a-z0-9._-]{0,79}$/i.test(value.updatedBy ?? "")
  ) {
    throw capacityError("worker-control-invalid", "Worker control state is invalid.");
  }
  return { ...value, requestedCapacity, lastNonZeroCapacity };
}

export async function writeWorkerControl(stateRoot, config, input) {
  const previous = await readWorkerControl(stateRoot, config);
  const requestedCapacity = validateRequestedCapacity(input.requestedCapacity);
  const acceptingClaims = input.acceptingClaims === true && requestedCapacity > 0;
  const record = {
    schema: "hch.worker-control/v1",
    schemaVersion: 1,
    nodeId: config.nodeId,
    workerKeyId: config.keyId,
    acceptingClaims,
    requestedCapacity,
    lastNonZeroCapacity: requestedCapacity > 0
      ? requestedCapacity
      : previous.lastNonZeroCapacity,
    drainRequested: !acceptingClaims,
    updatedAt: new Date().toISOString(),
    updatedBy: safeReason(input.updatedBy, "operator-cli"),
  };
  await atomicWriteJson(stateRoot, "worker-control.json", record);
  return record;
}

export function effectiveRequestedCapacity(control) {
  return control?.acceptingClaims === true && control?.drainRequested === false
    ? validateRequestedCapacity(control.requestedCapacity)
    : 0;
}

function validateGrantCommon(grant, context) {
  const policy = validateCapacityPolicy(context.policy);
  const requestedCapacity = validateRequestedCapacity(
    grant.requestedCapacity,
    policy.absoluteRequestedMaximum,
  );
  const grantedCapacity = boundedInteger(
    grant.grantedCapacity,
    0,
    policy.absoluteRequestedMaximum,
    "capacity.grantedCapacity",
    "capacity-grant-invalid",
  );
  const expectedClass = capacityClassForWorker(
    policy,
    context.nodeId,
    context.platform ?? "linux",
  );
  const ceiling = capacityCeilingForWorker(policy, context.nodeId, context.platform ?? "linux");
  const reason = safeReason(grant.reason, null);
  const grantedUntil = timestamp(grant.grantedUntil, "capacity.grantedUntil");
  if (
    requestedCapacity !== context.requestedCapacity ||
    grantedCapacity > requestedCapacity ||
    grantedCapacity > ceiling ||
    grant.capacityClass !== expectedClass ||
    !reason ||
    (requestedCapacity === 0 && (grantedCapacity !== 0 || !reason.includes("drain-requested")))
  ) {
    throw capacityError(
      "capacity-grant-invalid",
      "Capacity grant is inconsistent with the signed policy or request.",
    );
  }
  return { requestedCapacity, grantedCapacity, capacityClass: expectedClass, reason, grantedUntil };
}

function validateGrantTtl(grantedUntil, context, options = {}) {
  const policy = validateCapacityPolicy(context.policy);
  const now = normalizedDate(context.now ?? Date.now());
  const serverTime = context.serverTime ? new Date(timestamp(context.serverTime, "serverTime")) : null;
  const expiresAt = Date.parse(grantedUntil);
  if (!options.allowExpired && expiresAt <= now.getTime()) {
    throw capacityError("capacity-grant-expired", "Capacity grant is already expired.");
  }
  if (
    serverTime &&
    (expiresAt <= serverTime.getTime() ||
      expiresAt > serverTime.getTime() + policy.grantTtlSeconds * 1_000 + 5_000)
  ) {
    throw capacityError("capacity-grant-ttl-invalid", "Capacity grant TTL exceeds the signed policy.");
  }
  if (!serverTime && expiresAt > now.getTime() + policy.grantTtlSeconds * 1_000 + 5 * 60_000) {
    throw capacityError("capacity-grant-ttl-invalid", "Capacity grant expiry is implausibly far in the future.");
  }
}

function normalizedDate(value) {
  if (value instanceof Date) return value;
  const milliseconds = typeof value === "number" && value < 10_000_000_000
    ? value * 1_000
    : value;
  const normalized = new Date(milliseconds);
  if (Number.isNaN(normalized.getTime())) {
    throw capacityError("capacity-grant-ttl-invalid", "Capacity grant comparison time is invalid.");
  }
  return normalized;
}

function capacityClassMap(value, name, required) {
  const map = record(value, name, "capacity-policy-invalid");
  for (const field of required) {
    if (!(field in map)) throw capacityError("capacity-policy-invalid", `${name}.${field} is required.`);
  }
  const normalized = {};
  for (const [key, capacityClass] of Object.entries(map)) {
    if (!/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(key) || !CAPACITY_CLASSES.has(capacityClass)) {
      throw capacityError("capacity-policy-invalid", `${name} contains an invalid mapping.`);
    }
    normalized[key] = capacityClass;
  }
  return normalized;
}

function capacityIntegerMap(value, name) {
  const map = record(value, name, "capacity-policy-invalid");
  const normalized = {};
  for (const [key, ceiling] of Object.entries(map)) {
    if (!/^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,127}$/.test(key)) {
      throw capacityError("capacity-policy-invalid", `${name} contains an invalid node id.`);
    }
    normalized[key] = capacityInteger(ceiling, `${name}.${key}`);
  }
  return normalized;
}

function exactRecord(value, fields, name, code, options = {}) {
  const object = record(value, name, code);
  const unknown = Object.keys(object).find((key) => !fields.has(key));
  if (unknown) throw capacityError(code, `${name} contains unsupported field ${unknown}.`);
  if (!options.allowMissing) {
    const missing = [...fields].find((key) => !(key in object));
    if (missing) throw capacityError(code, `${name}.${missing} is required.`);
  }
  return object;
}

function record(value, name, code) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw capacityError(code, `${name} must be an object.`);
  }
  return value;
}

function capacityInteger(value, name) {
  return boundedInteger(value, 0, 64, name, "capacity-policy-invalid");
}

function nonnegativeInteger(value, name) {
  return boundedInteger(value, 0, Number.MAX_SAFE_INTEGER, name, "capacity-decision-invalid");
}

function boundedInteger(value, minimum, maximum, name, code = "capacity-policy-invalid") {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    throw capacityError(code, `${name} must be an integer between ${minimum} and ${maximum}.`);
  }
  return value;
}

function percentage(value, name) {
  if (typeof value !== "number" || !Number.isFinite(value) || value < 0 || value > 100) {
    throw capacityError("capacity-pressure-invalid", `${name} must be between 0 and 100.`);
  }
  return value;
}

function roundPercentage(value) {
  return Math.round(Math.min(100, Math.max(0, value)) * 100) / 100;
}

function timestamp(value, name) {
  if (typeof value !== "string" || !Number.isFinite(Date.parse(value))) {
    throw capacityError("capacity-grant-invalid", `${name} must be an ISO timestamp.`);
  }
  return new Date(value).toISOString();
}

function safeReason(value, fallback) {
  return typeof value === "string" && /^[a-z0-9][a-z0-9:._+-]{0,255}$/i.test(value)
    ? value
    : fallback;
}

function nonnegativeIntegerOr(value, fallback) {
  return Number.isSafeInteger(value) && value >= 0 ? value : fallback;
}

function capacityError(code, message) {
  return new WorkerKitError(code, message);
}
