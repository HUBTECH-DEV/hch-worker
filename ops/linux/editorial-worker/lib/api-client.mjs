import { canonicalizeJson } from "../crypto.mjs";
import { signedPost } from "./http.mjs";
import { readJson } from "./storage.mjs";
import { verifyRuntimeProfile } from "./runtime-profile.mjs";
import { verifyGenerationPlan } from "./adaptive-work.mjs";
import { WorkerKitError } from "./errors.mjs";

const HASH = /^[a-f0-9]{64}$/;

export async function claimAssignments(config, identity, stateRoot, options = {}) {
  const requestedCapacity = options.requestedCapacity ?? 1;
  if (!Number.isSafeInteger(requestedCapacity) || requestedCapacity < 1 || requestedCapacity > 64) {
    throw new TypeError("Claim requestedCapacity must be between 1 and 64.");
  }
  const requestId = options.requestId ?? crypto.randomUUID();
  const response = await signedPost(config, identity, {
    path: "/api/editorial/orchestrator/claim",
    purpose: "claim",
    bodyText: canonicalizeJson({
      nodeId: identity.nodeId,
      workerKeyId: identity.keyId,
      requestedCapacity,
    }),
    requestId,
  }, options);
  if (
    response?.requestId !== requestId ||
    response?.nodeId !== identity.nodeId ||
    !Array.isArray(response?.assignments) ||
    response.assignments.length > requestedCapacity ||
    !capacityDecision(response?.capacity, requestedCapacity) ||
    typeof response?.replayed !== "boolean" ||
    !validTimestamp(response?.serverTime)
  ) {
    invalid("claim-response-invalid", "The claim response is invalid or not correlated.");
  }
  const applied = await readJson(stateRoot, "applied-manifest.json");
  const assignments = [];
  for (const value of response.assignments) {
    assignments.push(await validateAssignment(
      value,
      applied.adaptiveWorkPolicy,
      applied.runtimeProfile,
    ));
  }
  return { ...response, assignments };
}

export async function heartbeatAssignment(config, identity, assignment, progress, options = {}) {
  const requestId = options.requestId ?? crypto.randomUUID();
  let response;
  try {
    response = await signedPost(config, identity, {
      path: `/api/editorial/orchestrator/assignments/${assignment.assignmentId}/heartbeat`,
      purpose: "heartbeat",
      bodyText: canonicalizeJson({
        ...assignmentIdentity(identity, assignment),
        progress: validateProgress(progress),
      }),
      requestId,
    }, heartbeatRequestOptions(options));
  } catch (error) {
    throw correlateHeartbeatError(error, assignment);
  }
  if (
    response?.assignmentId !== assignment.assignmentId ||
    response?.generationPlanHash !== assignment.generationPlanHash ||
    !validTimestamp(response?.leaseExpiresAt) ||
    !validTimestamp(response?.serverTime) ||
    !response?.liveness ||
    !new Set(["starting", "responding", "finalizing"]).has(response.liveness.state) ||
    !Number.isSafeInteger(response.liveness.staleAfterSeconds) ||
    response.liveness.staleAfterSeconds < 1 ||
    !response?.workSizing ||
    typeof response.workSizing.currentTier !== "string" ||
    !Number.isSafeInteger(response.workSizing.currentRank) ||
    typeof response.workSizing.reason !== "string"
  ) {
    invalid("heartbeat-response-invalid", "The assignment heartbeat response is invalid.");
  }
  return response;
}

export function correlateHeartbeatError(error, assignment) {
  if (error?.status !== 409 || error?.code !== "generator-stalled") return error;
  if (error.responsePayload?.generationPlanHash === assignment.generationPlanHash) {
    return error;
  }
  return new WorkerKitError(
    "heartbeat-response-invalid",
    "The generator-stalled response was not correlated to this generation plan.",
  );
}

export async function completeAssignment(config, identity, assignment, draft, options = {}) {
  const profile = await verifyRuntimeProfile(assignment.runtimeProfile);
  const requestId = options.requestId ?? crypto.randomUUID();
  const response = await signedPost(config, identity, {
    path: `/api/editorial/orchestrator/assignments/${assignment.assignmentId}/complete`,
    purpose: "complete",
    bodyText: canonicalizeJson({
      ...assignmentIdentity(identity, assignment),
      manifestSequence: profile.manifestSequence,
      manifestHash: profile.manifestHash,
      policyHash: profile.policyHash,
      runtimeProfileHash: profile.runtimeProfileHash,
      inputSnapshotHash: assignment.inputSnapshotHash,
      draft,
    }),
    requestId,
  }, options);
  if (
    response?.assignmentId !== assignment.assignmentId ||
    response?.generationPlanHash !== assignment.generationPlanHash ||
    response?.commitAccepted !== true ||
    response?.status !== "pending-review" ||
    response?.automaticApproval !== false ||
    response?.automaticPublication !== false ||
    typeof response?.replayed !== "boolean" ||
    !validTimestamp(response?.serverTime)
  ) {
    invalid("complete-response-invalid", "The completion response is invalid or unsafe.");
  }
  return response;
}

export async function failAssignment(config, identity, assignment, failureCode, options = {}) {
  const errorCode = safeFailureCode(failureCode);
  const requestId = options.requestId ?? crypto.randomUUID();
  const response = await signedPost(config, identity, {
    path: `/api/editorial/orchestrator/assignments/${assignment.assignmentId}/fail`,
    purpose: "fail",
    bodyText: canonicalizeJson({
      ...assignmentIdentity(identity, assignment),
      errorCode,
    }),
    requestId,
  }, options);
  if (
    response?.assignmentId !== assignment.assignmentId ||
    response?.generationPlanHash !== assignment.generationPlanHash ||
    response?.status !== "failed-attempt" ||
    typeof response?.replayed !== "boolean" ||
    !validTimestamp(response?.serverTime)
  ) {
    invalid("fail-response-invalid", "The failure response is invalid or not correlated.");
  }
  return response;
}

export async function validateAssignment(value, adaptiveWorkPolicy, appliedRuntimeProfile) {
  const assignment = exactRecord(value, [
    "assignmentId",
    "leaseToken",
    "leaseExpiresAt",
    "status",
    "inputSnapshotHash",
    "entry",
    "runtimeProfile",
    "generationPlan",
    "generationPlanHash",
  ], "assignment");
  if (
    !identifier(assignment.assignmentId, 160) ||
    !identifier(assignment.leaseToken, 160) ||
    !validTimestamp(assignment.leaseExpiresAt) ||
    assignment.status !== "processing" ||
    !HASH.test(String(assignment.inputSnapshotHash ?? "")) ||
    !HASH.test(String(assignment.generationPlanHash ?? "")) ||
    !assignment.entry || typeof assignment.entry !== "object" || Array.isArray(assignment.entry)
  ) {
    invalid("assignment-response-invalid", "The claimed assignment is invalid.");
  }
  const runtimeProfile = await verifyRuntimeProfile(assignment.runtimeProfile);
  const installedRuntimeProfile = await verifyRuntimeProfile(appliedRuntimeProfile);
  if (
    runtimeProfile.runtimeProfileHash !== installedRuntimeProfile.runtimeProfileHash ||
    canonicalizeJson(runtimeProfile) !== canonicalizeJson(installedRuntimeProfile)
  ) {
    invalid(
      "assignment-runtime-profile-mismatch",
      "The assignment RuntimeProfile differs from the signed applied profile.",
    );
  }
  const generationPlan = await verifyGenerationPlan(
    assignment.generationPlan,
    assignment.generationPlanHash,
    adaptiveWorkPolicy,
    runtimeProfile,
  );
  return Object.freeze({ ...assignment, runtimeProfile, generationPlan });
}

function heartbeatRequestOptions(options) {
  const deadlineMilliseconds = 25_000;
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

export function validateProgress(value) {
  const progress = exactRecord(value, [
    "phase", "attempt", "sequence", "contentBytes",
  ], "progress");
  if (
    !new Set(["starting", "responding", "finalizing"]).has(progress.phase) ||
    !Number.isSafeInteger(progress.attempt) || progress.attempt < 1 || progress.attempt > 8 ||
    !Number.isSafeInteger(progress.sequence) || progress.sequence < 0 ||
    !Number.isSafeInteger(progress.contentBytes) || progress.contentBytes < 0
  ) {
    throw new TypeError("Assignment progress is invalid.");
  }
  return { ...progress };
}

function assignmentIdentity(identity, assignment) {
  return {
    assignmentId: assignment.assignmentId,
    nodeId: identity.nodeId,
    workerKeyId: identity.keyId,
    leaseToken: assignment.leaseToken,
    generationPlanHash: assignment.generationPlanHash,
  };
}

function capacityDecision(value, requestedCapacity) {
  return Boolean(
    value && typeof value === "object" &&
    Number.isSafeInteger(value.requestedCapacity) && value.requestedCapacity === requestedCapacity &&
    Number.isSafeInteger(value.grantedCapacity) && value.grantedCapacity >= 0 &&
    Number.isSafeInteger(value.availableSlots) && value.availableSlots >= 0 &&
    Number.isSafeInteger(value.activeAssignments) && value.activeAssignments >= 0 &&
    value.availableSlots <= value.grantedCapacity &&
    typeof value.reason === "string" && value.reason &&
    (value.grantedUntil === null || validTimestamp(value.grantedUntil)),
  );
}

function safeFailureCode(value) {
  const normalized = String(value ?? "worker-generation-failed")
    .toLowerCase()
    .replace(/[^a-z0-9._-]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 200);
  return normalized || "worker-generation-failed";
}

function exactRecord(value, fields, name) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new TypeError(`${name} must be an object.`);
  }
  const keys = Object.keys(value);
  if (keys.some((field) => !fields.includes(field)) || fields.some((field) => !keys.includes(field))) {
    throw new TypeError(`${name} has missing or unsupported fields.`);
  }
  return value;
}

function identifier(value, maximum) {
  return typeof value === "string" && value.length > 0 && value.length <= maximum &&
    !/[\x00-\x20\x7f]/.test(value);
}

function validTimestamp(value) {
  return typeof value === "string" && Number.isFinite(Date.parse(value));
}

function invalid(code, message) {
  throw new WorkerKitError(code, message);
}
