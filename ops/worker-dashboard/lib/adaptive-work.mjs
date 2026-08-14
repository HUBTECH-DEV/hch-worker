const ALGORITHM_VERSION = "hch-adaptive-work-v1";
const PHASES = new Set(["starting", "responding", "finalizing"]);
const LIVENESS_STATES = new Set([...PHASES, "stalled"]);
const WINDOW_STATES = new Set([
  "within-window",
  "near-window",
  "over-window",
  "ignored-at-minimum",
]);
const LIVENESS_REASONS = new Set([
  "progress-advanced",
  "awaiting-first-progress",
  "progress-within-stall-grace",
  "finalization-in-progress",
  "first-progress-grace-exceeded",
  "progress-stalled",
  "finalization-grace-exceeded",
]);
const WORK_SIZING_REASONS = new Set([
  "attestation-reset",
  "minimum-unit-window-ignored",
  "within-window",
  "near-window-downshift",
  "already-downshifted",
]);

export function parseAdaptiveWorkSizing(value) {
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
  ], "adaptive work sizing");
  if (sizing.algorithmVersion !== ALGORITHM_VERSION) {
    throw new TypeError("Unsupported adaptive work algorithm.");
  }
  const currentRank = boundedInteger(sizing.currentRank, 0, 15, "workSizing.currentRank");
  const maximumOutputTokens = boundedInteger(
    sizing.maxOutputTokens,
    1,
    32_768,
    "workSizing.maxOutputTokens",
  );
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
  const firstProgressGraceSeconds = boundedInteger(
    sizing.firstProgressGraceSeconds,
    30,
    processingWindowSeconds,
    "workSizing.firstProgressGraceSeconds",
  );
  const stallAfterSeconds = boundedInteger(
    sizing.stallAfterSeconds,
    30,
    processingWindowSeconds,
    "workSizing.stallAfterSeconds",
  );
  const finalizationGraceSeconds = boundedInteger(
    sizing.finalizationGraceSeconds,
    30,
    processingWindowSeconds,
    "workSizing.finalizationGraceSeconds",
  );
  if (typeof sizing.minimumUnit !== "boolean" || sizing.minimumUnit !== (currentRank === 0)) {
    throw new TypeError("workSizing.minimumUnit does not match currentRank.");
  }
  return Object.freeze({
    algorithmVersion: ALGORITHM_VERSION,
    currentTier: identifier(sizing.currentTier, "workSizing.currentTier", 32),
    currentRank,
    maxOutputTokens: maximumOutputTokens,
    editorialProfile: identifier(sizing.editorialProfile, "workSizing.editorialProfile", 64),
    minimumUnit: sizing.minimumUnit,
    reason: enumeration(
      sizing.reason,
      WORK_SIZING_REASONS,
      "workSizing.reason",
    ),
    updatedAt: nullableTimestamp(sizing.updatedAt, "workSizing.updatedAt"),
    processingWindowSeconds,
    nearWindowSeconds,
    firstProgressGraceSeconds,
    stallAfterSeconds,
    finalizationGraceSeconds,
  });
}

export function parseNativeActiveWork(value, options = {}) {
  if (value === undefined || value === null) return Object.freeze([]);
  if (!Array.isArray(value) || value.length > 64) {
    throw new TypeError("activeWork must be an array with at most 64 items.");
  }
  const nodeId = options.nodeId ?? null;
  const identifiers = new Set();
  return Object.freeze(value.map((candidate, index) => {
    const item = exactRecord(candidate, [
      "assignmentId",
      "nodeId",
      "status",
      "tier",
      "tierRank",
      "maxOutputTokens",
      "progress",
      "liveness",
      "nearWindowObservedAt",
      "processingDurationMilliseconds",
      "claimedAt",
      "heartbeatAt",
      "leaseExpiresAt",
    ], `activeWork[${index}]`);
    const assignmentId = identifier(item.assignmentId, `activeWork[${index}].assignmentId`, 128);
    if (identifiers.has(assignmentId)) throw new TypeError("activeWork assignmentId is duplicated.");
    identifiers.add(assignmentId);
    const observedNodeId = identifier(item.nodeId, `activeWork[${index}].nodeId`, 128);
    if (nodeId !== null && observedNodeId !== nodeId) {
      throw new TypeError("activeWork belongs to another worker.");
    }
    if (item.status !== "processing") throw new TypeError("activeWork status must be processing.");
    const tierRank = nullableBoundedInteger(
      item.tierRank,
      0,
      15,
      `activeWork[${index}].tierRank`,
    );
    const progress = item.progress === null
      ? null
      : parseProgress(item.progress, `activeWork[${index}].progress`);
    const liveness = item.liveness === null
      ? null
      : parseLiveness(item.liveness, `activeWork[${index}].liveness`);
    if (progress && liveness && liveness.state !== "stalled" && progress.phase !== liveness.state) {
      throw new TypeError("activeWork progress and liveness phases do not match.");
    }
    return Object.freeze({
      assignmentId,
      tier: nullableIdentifier(item.tier, `activeWork[${index}].tier`, 32),
      tierRank,
      maxOutputTokens: nullableBoundedInteger(
        item.maxOutputTokens,
        1,
        32_768,
        `activeWork[${index}].maxOutputTokens`,
      ),
      progress,
      liveness,
      nearWindowObservedAt: nullableTimestamp(
        item.nearWindowObservedAt,
        `activeWork[${index}].nearWindowObservedAt`,
      ),
      processingDurationMilliseconds: nonNegativeNumber(
        item.processingDurationMilliseconds,
        `activeWork[${index}].processingDurationMilliseconds`,
      ),
      claimedAt: timestamp(item.claimedAt, `activeWork[${index}].claimedAt`),
      heartbeatAt: nullableTimestamp(item.heartbeatAt, `activeWork[${index}].heartbeatAt`),
      leaseExpiresAt: nullableTimestamp(
        item.leaseExpiresAt,
        `activeWork[${index}].leaseExpiresAt`,
      ),
    });
  }));
}

export function parseSingleWorkerProgress(status, options = {}) {
  if (status?.progress === undefined || status.progress === null) return Object.freeze([]);
  const progressRecord = exactRecord(status.progress, [
    "assignmentId",
    "generationPlanHash",
    "phase",
    "attempt",
    "sequence",
    "contentBytes",
    "updatedAt",
  ], "worker progress");
  sha256Hex(progressRecord.generationPlanHash, "progress.generationPlanHash");
  const progress = parseProgress({
    phase: progressRecord.phase,
    attempt: progressRecord.attempt,
    sequence: progressRecord.sequence,
    contentBytes: progressRecord.contentBytes,
    lastProgressAt: progressRecord.updatedAt,
  }, "worker progress");
  const sizing = options.workSizing ?? null;
  const claimedAt = status.currentBatch?.startedAt ?? status.observedAt;
  return Object.freeze([Object.freeze({
    assignmentId: identifier(progressRecord.assignmentId, "progress.assignmentId", 128),
    tier: sizing?.currentTier ?? null,
    tierRank: sizing?.currentRank ?? null,
    maxOutputTokens: sizing?.maxOutputTokens ?? null,
    progress,
    liveness: null,
    nearWindowObservedAt: null,
    processingDurationMilliseconds: 0,
    claimedAt: timestamp(claimedAt, "progress.claimedAt"),
    heartbeatAt: null,
    leaseExpiresAt: null,
  })]);
}

export function buildAdaptiveWorkStatus(input) {
  const now = timestamp(input.now ?? new Date(), "now");
  const nowMilliseconds = Date.parse(now);
  const workSizing = input.workSizing ?? null;
  const items = Array.isArray(input.activeWork) ? input.activeWork : [];
  return Object.freeze({
    available: workSizing !== null || items.length > 0,
    workSizing: publicWorkSizing(workSizing),
    activeWork: Object.freeze(items.map((item) => {
      const elapsedSeconds = Math.max(
        Math.floor(item.processingDurationMilliseconds / 1_000),
        Math.floor((nowMilliseconds - Date.parse(item.claimedAt)) / 1_000),
        0,
      );
      const phase = item.progress?.phase ?? (
        item.liveness?.state && item.liveness.state !== "stalled"
          ? item.liveness.state
          : null
      );
      const lastProgressAt = item.liveness?.lastProgressAt ?? item.progress?.lastProgressAt ?? null;
      const progressAgeSeconds = lastProgressAt === null
        ? Math.max(0, Math.floor((nowMilliseconds - Date.parse(item.claimedAt)) / 1_000))
        : Math.max(0, Math.floor((nowMilliseconds - Date.parse(lastProgressAt)) / 1_000));
      const livenessStatus = classifyDashboardLiveness({
        phase,
        elapsedSeconds,
        progressAgeSeconds,
        liveness: item.liveness,
        minimumUnit: item.tierRank === 0,
        workSizing,
      });
      return Object.freeze({
        assignmentId: item.assignmentId,
        tier: item.tier,
        tierRank: item.tierRank,
        maxOutputTokens: item.maxOutputTokens,
        progressPercent: estimateProgressPercent(item.progress, item.maxOutputTokens),
        minimumUnit: item.tierRank === null
          ? null
          : item.tierRank === 0,
        elapsedSeconds,
        phase,
        lastProgressAt,
        progressAgeSeconds,
        livenessStatus,
        livenessReason: item.liveness?.reason ?? inferredReason(livenessStatus, phase),
        windowState: item.liveness?.windowState ?? inferredWindowState(
          elapsedSeconds,
          workSizing,
          item.tierRank === 0,
        ),
      });
    })),
  });
}

function estimateProgressPercent(progress, maxOutputTokens) {
  if (!progress) return 0;
  if (progress.phase === "finalizing") return 95;
  if (progress.phase === "starting") return progress.sequence > 0 || progress.contentBytes > 0 ? 8 : 3;
  const ceiling = Number.isInteger(maxOutputTokens) && maxOutputTokens > 0 ? maxOutputTokens : 1;
  const estimatedTokens = Math.max(progress.sequence, Math.ceil(progress.contentBytes / 4));
  return Math.min(90, Math.max(10, Math.round(10 + (estimatedTokens / ceiling) * 80)));
}

function publicWorkSizing(sizing) {
  if (sizing === null) return null;
  return Object.freeze({
    algorithmVersion: sizing.algorithmVersion,
    currentTier: sizing.currentTier,
    currentRank: sizing.currentRank,
    maxOutputTokens: sizing.maxOutputTokens,
    editorialProfile: sizing.editorialProfile,
    minimumUnit: sizing.minimumUnit,
    downshiftReason: sizing.reason,
    updatedAt: sizing.updatedAt,
    processingWindowSeconds: sizing.processingWindowSeconds,
    nearWindowSeconds: sizing.nearWindowSeconds,
    firstProgressGraceSeconds: sizing.firstProgressGraceSeconds,
    stallAfterSeconds: sizing.stallAfterSeconds,
    finalizationGraceSeconds: sizing.finalizationGraceSeconds,
  });
}

function classifyDashboardLiveness(input) {
  if (input.liveness?.state === "stalled") return "stalled";
  if (input.liveness?.state === "finalizing") return "finalizing";
  const staleAfterSeconds = input.phase === "finalizing"
    ? input.workSizing?.finalizationGraceSeconds
    : input.phase === "responding"
      ? input.workSizing?.stallAfterSeconds
      : input.workSizing?.firstProgressGraceSeconds;
  if (staleAfterSeconds !== undefined && input.progressAgeSeconds >= staleAfterSeconds) {
    return "stalled";
  }
  if (input.phase === "finalizing") return "finalizing";
  if (input.phase === "starting" || input.phase === null) return "awaiting-first-progress";
  const ignoresWindow = input.minimumUnit ||
    input.liveness?.windowState === "ignored-at-minimum";
  const slowByWindow = !ignoresWindow && input.workSizing !== null &&
    input.elapsedSeconds >= input.workSizing.nearWindowSeconds;
  const slowByProgress = staleAfterSeconds !== undefined &&
    input.progressAgeSeconds >= Math.max(1, Math.floor(staleAfterSeconds / 2));
  return slowByWindow || slowByProgress ? "responding-slowly" : "progressing";
}

function inferredReason(status, phase) {
  if (status === "stalled") {
    if (phase === "finalizing") return "finalization-grace-exceeded";
    if (phase === "responding") return "progress-stalled";
    return "first-progress-grace-exceeded";
  }
  if (status === "finalizing") return "finalization-in-progress";
  if (status === "awaiting-first-progress") return "awaiting-first-progress";
  return status === "responding-slowly"
    ? "progress-within-stall-grace"
    : "progress-advanced";
}

function inferredWindowState(elapsedSeconds, sizing, minimumUnit) {
  if (!sizing) return null;
  if (minimumUnit || sizing.minimumUnit) return "ignored-at-minimum";
  if (elapsedSeconds >= sizing.processingWindowSeconds) return "over-window";
  if (elapsedSeconds >= sizing.nearWindowSeconds) return "near-window";
  return "within-window";
}

function parseProgress(value, name) {
  const progress = exactRecord(value, [
    "phase",
    "attempt",
    "sequence",
    "contentBytes",
    "lastProgressAt",
  ], name);
  return Object.freeze({
    phase: enumeration(progress.phase, PHASES, `${name}.phase`),
    attempt: boundedInteger(progress.attempt, 1, 8, `${name}.attempt`),
    sequence: boundedInteger(progress.sequence, 0, Number.MAX_SAFE_INTEGER, `${name}.sequence`),
    contentBytes: boundedInteger(
      progress.contentBytes,
      0,
      Number.MAX_SAFE_INTEGER,
      `${name}.contentBytes`,
    ),
    lastProgressAt: nullableTimestamp(progress.lastProgressAt, `${name}.lastProgressAt`),
  });
}

function parseLiveness(value, name) {
  const liveness = exactRecord(value, [
    "state",
    "progressed",
    "lastProgressAt",
    "windowState",
    "reason",
  ], name);
  if (typeof liveness.progressed !== "boolean") throw new TypeError(`${name}.progressed is invalid.`);
  return Object.freeze({
    state: enumeration(liveness.state, LIVENESS_STATES, `${name}.state`),
    progressed: liveness.progressed,
    lastProgressAt: nullableTimestamp(liveness.lastProgressAt, `${name}.lastProgressAt`),
    windowState: enumeration(liveness.windowState, WINDOW_STATES, `${name}.windowState`),
    reason: enumeration(liveness.reason, LIVENESS_REASONS, `${name}.reason`),
  });
}

function exactRecord(value, fields, name) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new TypeError(`${name} must be an object.`);
  }
  const expected = new Set(fields);
  const keys = Object.keys(value);
  if (keys.length !== expected.size || keys.some((key) => !expected.has(key))) {
    throw new TypeError(`${name} fields are invalid.`);
  }
  return value;
}

function enumeration(value, values, name) {
  if (!values.has(value)) throw new TypeError(`${name} is invalid.`);
  return value;
}

function identifier(value, name, maximum) {
  if (typeof value !== "string" || !value || value.length > maximum || /[\x00-\x20\x7f]/.test(value)) {
    throw new TypeError(`${name} is invalid.`);
  }
  return value;
}

function nullableIdentifier(value, name, maximum) {
  return value === null ? null : identifier(value, name, maximum);
}

function boundedInteger(value, minimum, maximum, name) {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    throw new TypeError(`${name} is invalid.`);
  }
  return value;
}

function nullableBoundedInteger(value, minimum, maximum, name) {
  return value === null ? null : boundedInteger(value, minimum, maximum, name);
}

function nonNegativeNumber(value, name) {
  if (typeof value !== "number" || !Number.isFinite(value) || value < 0) {
    throw new TypeError(`${name} is invalid.`);
  }
  return value;
}

function timestamp(value, name) {
  if (!(value instanceof Date) && (typeof value !== "string" || !value.trim())) {
    throw new TypeError(`${name} is invalid.`);
  }
  const milliseconds = value instanceof Date ? value.getTime() : Date.parse(value);
  if (!Number.isFinite(milliseconds)) throw new TypeError(`${name} is invalid.`);
  return new Date(milliseconds).toISOString();
}

function nullableTimestamp(value, name) {
  return value === null ? null : timestamp(value, name);
}

function sha256Hex(value, name) {
  if (typeof value !== "string" || !/^[a-f0-9]{64}$/.test(value)) {
    throw new TypeError(`${name} is invalid.`);
  }
  return value;
}
