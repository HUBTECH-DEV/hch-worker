import { canonicalizeJson } from "./editorial-worker-signatures.mjs";

export const ADAPTIVE_WORK_ALGORITHM_VERSION = "hch-adaptive-work-v1";

const POLICY_FIELDS = Object.freeze([
  "algorithmVersion",
  "windowMode",
  "minimumTierIgnoresWindow",
  "livenessBasis",
  "processingWindowSeconds",
  "nearWindowRatio",
  "firstProgressGraceSeconds",
  "stallAfterSeconds",
  "finalizationGraceSeconds",
  "tiers",
]);
const TIER_FIELDS = Object.freeze([
  "id",
  "rank",
  "maxOutputTokens",
  "editorialProfile",
  "minimumUnit",
]);
const PLAN_FIELDS = Object.freeze([
  "algorithmVersion",
  "tierId",
  "tierRank",
  "maxOutputTokens",
  "editorialProfile",
  "minimumUnit",
  "processingWindowSeconds",
  "nearWindowSeconds",
  "firstProgressGraceSeconds",
  "stallAfterSeconds",
  "finalizationGraceSeconds",
  "policyHash",
]);
const PHASES = Object.freeze(["starting", "responding", "finalizing"]);
const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;
const SHA256_HEX = /^[a-f0-9]{64}$/;

/**
 * Validates and returns a canonical, deeply frozen copy of the signed adaptive
 * work policy. Unknown fields are rejected so they cannot silently disappear
 * from the plan derived by an older worker.
 */
export function validateAdaptiveWorkPolicy(value) {
  const policy = plainObject(value, "adaptiveWorkPolicy");
  exactFields(policy, POLICY_FIELDS, "adaptiveWorkPolicy");
  if (policy.algorithmVersion !== ADAPTIVE_WORK_ALGORITHM_VERSION) {
    throw new TypeError(
      `adaptiveWorkPolicy.algorithmVersion deve ser ${ADAPTIVE_WORK_ALGORITHM_VERSION}.`,
    );
  }
  if (policy.windowMode !== "advisory") {
    throw new TypeError("adaptiveWorkPolicy.windowMode deve ser advisory.");
  }
  if (policy.minimumTierIgnoresWindow !== true) {
    throw new TypeError("adaptiveWorkPolicy.minimumTierIgnoresWindow deve ser true.");
  }
  if (policy.livenessBasis !== "progress") {
    throw new TypeError("adaptiveWorkPolicy.livenessBasis deve ser progress.");
  }

  const processingWindowSeconds = boundedInteger(
    policy.processingWindowSeconds,
    "adaptiveWorkPolicy.processingWindowSeconds",
    60,
    86_400,
  );
  const nearWindowRatio = boundedNumber(
    policy.nearWindowRatio,
    "adaptiveWorkPolicy.nearWindowRatio",
    0.5,
    0.95,
  );
  const firstProgressGraceSeconds = boundedInteger(
    policy.firstProgressGraceSeconds,
    "adaptiveWorkPolicy.firstProgressGraceSeconds",
    30,
    processingWindowSeconds,
  );
  const stallAfterSeconds = boundedInteger(
    policy.stallAfterSeconds,
    "adaptiveWorkPolicy.stallAfterSeconds",
    30,
    processingWindowSeconds,
  );
  const finalizationGraceSeconds = boundedInteger(
    policy.finalizationGraceSeconds,
    "adaptiveWorkPolicy.finalizationGraceSeconds",
    30,
    processingWindowSeconds,
  );

  if (!Array.isArray(policy.tiers) || policy.tiers.length < 2 || policy.tiers.length > 8) {
    throw new RangeError("adaptiveWorkPolicy.tiers deve conter entre 2 e 8 tiers.");
  }

  const tierIds = new Set();
  const tiers = policy.tiers.map((candidate, index) => {
    const tier = plainObject(candidate, `adaptiveWorkPolicy.tiers[${index}]`);
    exactFields(tier, TIER_FIELDS, `adaptiveWorkPolicy.tiers[${index}]`);
    const id = identifier(tier.id, `adaptiveWorkPolicy.tiers[${index}].id`);
    if (tierIds.has(id)) {
      throw new TypeError(`adaptiveWorkPolicy.tiers contém id duplicado: ${id}.`);
    }
    tierIds.add(id);
    const rank = boundedInteger(
      tier.rank,
      `adaptiveWorkPolicy.tiers[${index}].rank`,
      0,
      policy.tiers.length - 1,
    );
    if (rank !== index) {
      throw new TypeError(
        "adaptiveWorkPolicy.tiers deve estar ordenado com ranks contíguos iniciados em 0.",
      );
    }
    const maxOutputTokens = boundedInteger(
      tier.maxOutputTokens,
      `adaptiveWorkPolicy.tiers[${index}].maxOutputTokens`,
      1,
      4_096,
    );
    if (index > 0 && maxOutputTokens <= policy.tiers[index - 1].maxOutputTokens) {
      throw new TypeError(
        "adaptiveWorkPolicy.tiers deve ter maxOutputTokens estritamente crescente.",
      );
    }
    const editorialProfile = identifier(
      tier.editorialProfile,
      `adaptiveWorkPolicy.tiers[${index}].editorialProfile`,
    );
    if (typeof tier.minimumUnit !== "boolean") {
      throw new TypeError(
        `adaptiveWorkPolicy.tiers[${index}].minimumUnit deve ser booleano.`,
      );
    }
    if (tier.minimumUnit !== (rank === 0)) {
      throw new TypeError(
        "Somente o tier de rank 0 deve declarar minimumUnit=true.",
      );
    }
    return Object.freeze({ id, rank, maxOutputTokens, editorialProfile, minimumUnit: tier.minimumUnit });
  });

  return Object.freeze({
    algorithmVersion: ADAPTIVE_WORK_ALGORITHM_VERSION,
    windowMode: "advisory",
    minimumTierIgnoresWindow: true,
    livenessBasis: "progress",
    processingWindowSeconds,
    nearWindowRatio,
    firstProgressGraceSeconds,
    stallAfterSeconds,
    finalizationGraceSeconds,
    tiers: Object.freeze(tiers),
  });
}

/** Creates the highest generation plan permitted by the supplied tier ceiling. */
export function createGenerationPlan(adaptiveWorkPolicy, ceilingRank, options) {
  const policy = validateAdaptiveWorkPolicy(adaptiveWorkPolicy);
  const requestedCeiling = nonNegativeInteger(ceilingRank, "ceilingRank");
  const configuration = plainObject(options, "options");
  exactFields(configuration, ["policyHash", "editorialProfile"], "options", true);
  const policyHash = sha256Hex(configuration.policyHash, "options.policyHash");
  const selected = policy.tiers[Math.min(requestedCeiling, policy.tiers.length - 1)];
  const editorialProfile = configuration.editorialProfile === undefined
    ? selected.editorialProfile
    : identifier(configuration.editorialProfile, "options.editorialProfile");

  return Object.freeze({
    algorithmVersion: policy.algorithmVersion,
    tierId: selected.id,
    tierRank: selected.rank,
    maxOutputTokens: selected.maxOutputTokens,
    editorialProfile,
    minimumUnit: selected.minimumUnit,
    processingWindowSeconds: policy.processingWindowSeconds,
    nearWindowSeconds: Math.floor(
      policy.processingWindowSeconds * policy.nearWindowRatio,
    ),
    firstProgressGraceSeconds: policy.firstProgressGraceSeconds,
    stallAfterSeconds: policy.stallAfterSeconds,
    finalizationGraceSeconds: policy.finalizationGraceSeconds,
    policyHash,
  });
}

/** Returns the lowercase SHA-256 digest of the plan's canonical JCS bytes. */
export async function generationPlanHash(generationPlan) {
  const plan = validateGenerationPlan(generationPlan);
  const bytes = new TextEncoder().encode(canonicalizeJson(plan));
  const cryptoProvider = globalThis.crypto?.subtle
    ? globalThis.crypto
    : (await import("node:crypto")).webcrypto;
  const digest = await cryptoProvider.subtle.digest("SHA-256", bytes);
  return [...new Uint8Array(digest)]
    .map((value) => value.toString(16).padStart(2, "0"))
    .join("");
}

/**
 * Lowers the ceiling for subsequent assignments once the current assignment
 * reaches its near-window boundary. Re-evaluating the same assignment against
 * the returned ceiling is idempotent.
 */
export function decideAdaptiveDownshift(input) {
  const value = plainObject(input, "input");
  const policy = validateAdaptiveWorkPolicy(value.adaptiveWorkPolicy);
  const plan = validateGenerationPlan(value.generationPlan);
  const currentCeilingRank = boundedInteger(
    value.currentCeilingRank,
    "input.currentCeilingRank",
    0,
    policy.tiers.length - 1,
  );
  const elapsedSeconds = nonNegativeNumber(value.elapsedSeconds, "input.elapsedSeconds");
  requirePlanFromPolicy(plan, policy);

  if (plan.minimumUnit) {
    return Object.freeze({
      changed: false,
      nextRank: currentCeilingRank,
      nextTierId: policy.tiers[currentCeilingRank].id,
      reason: "minimum-unit-window-ignored",
      nearWindowSeconds: plan.nearWindowSeconds,
    });
  }
  if (elapsedSeconds < plan.nearWindowSeconds) {
    return Object.freeze({
      changed: false,
      nextRank: currentCeilingRank,
      nextTierId: policy.tiers[currentCeilingRank].id,
      reason: "within-window",
      nearWindowSeconds: plan.nearWindowSeconds,
    });
  }

  const nextRank = Math.min(currentCeilingRank, plan.tierRank - 1);
  const changed = nextRank < currentCeilingRank;
  return Object.freeze({
    changed,
    nextRank,
    nextTierId: policy.tiers[nextRank].id,
    reason: changed ? "near-window-downshift" : "already-downshifted",
    nearWindowSeconds: plan.nearWindowSeconds,
  });
}

/**
 * Classifies execution only from server timestamps and monotonic progress.
 * Exceeding the total processing window is observable but never equivalent to
 * a stall. At the minimum tier the total window is explicitly ignored.
 */
export function classifyAssignmentLiveness(input) {
  const value = plainObject(input, "input");
  const plan = validateGenerationPlan(value.generationPlan);
  const startedAtMs = timestampMs(value.startedAt, "input.startedAt");
  const serverTimeMs = timestampMs(value.serverTime, "input.serverTime");
  if (serverTimeMs < startedAtMs) {
    throw new RangeError("input.serverTime não pode ser anterior a input.startedAt.");
  }

  const previousProgress = optionalProgress(value.previousProgress, "input.previousProgress");
  const currentProgress = optionalProgress(value.currentProgress, "input.currentProgress");
  validateProgressTransition(previousProgress, currentProgress);
  const progressed = madeMaterialProgress(previousProgress, currentProgress);
  const observedAtMs = value.progressObservedAt === null || value.progressObservedAt === undefined
    ? null
    : timestampMs(value.progressObservedAt, "input.progressObservedAt");
  if (observedAtMs !== null && (observedAtMs < startedAtMs || observedAtMs > serverTimeMs)) {
    throw new RangeError(
      "input.progressObservedAt deve estar entre input.startedAt e input.serverTime.",
    );
  }
  const phaseObservedAtMs = value.phaseObservedAt === null || value.phaseObservedAt === undefined
    ? null
    : timestampMs(value.phaseObservedAt, "input.phaseObservedAt");
  if (
    phaseObservedAtMs !== null &&
    (phaseObservedAtMs < startedAtMs || phaseObservedAtMs > serverTimeMs)
  ) {
    throw new RangeError(
      "input.phaseObservedAt deve estar entre input.startedAt e input.serverTime.",
    );
  }

  const elapsedSeconds = (serverTimeMs - startedAtMs) / 1_000;
  const windowState = plan.minimumUnit
    ? "ignored-at-minimum"
    : elapsedSeconds >= plan.processingWindowSeconds
      ? "over-window"
      : elapsedSeconds >= plan.nearWindowSeconds
        ? "near-window"
        : "within-window";
  const lastProgressMs = progressed ? serverTimeMs : observedAtMs;
  const phase = currentProgress?.phase ?? "starting";
  const enteredCurrentPhase = Boolean(currentProgress) && (
    !previousProgress ||
    currentProgress.attempt > previousProgress.attempt ||
    currentProgress.phase !== previousProgress.phase
  );
  const finalizationStartedMs = phase === "finalizing"
    ? enteredCurrentPhase
      ? serverTimeMs
      : phaseObservedAtMs
    : null;
  if (phase === "finalizing" && finalizationStartedMs === null) {
    throw new TypeError(
      "input.phaseObservedAt é obrigatório enquanto a phase finalizing permanece ativa.",
    );
  }
  const graceSeconds = phase === "finalizing"
    ? plan.finalizationGraceSeconds
    : phase === "starting" || lastProgressMs === null
      ? plan.firstProgressGraceSeconds
      : plan.stallAfterSeconds;
  // Entrar em finalizing muda apenas o relógio da fase. Isso não constitui
  // progresso material e nunca sobrescreve lastProgressAt.
  const referenceMs = phase === "finalizing"
    ? finalizationStartedMs
    : phase === "starting"
      ? phaseObservedAtMs ?? startedAtMs
      : lastProgressMs ?? startedAtMs;
  const stalled = (serverTimeMs - referenceMs) / 1_000 >= graceSeconds;

  return Object.freeze({
    state: stalled ? "stalled" : phase,
    progressed,
    lastProgressAt: lastProgressMs === null ? null : new Date(lastProgressMs).toISOString(),
    windowState,
    reason: stalled
      ? phase === "finalizing"
        ? "finalization-grace-exceeded"
        : phase === "starting" || lastProgressMs === null
          ? "first-progress-grace-exceeded"
          : "progress-stalled"
      : progressed
        ? "progress-advanced"
        : phase === "finalizing"
          ? "finalization-in-progress"
          : phase === "starting" || lastProgressMs === null
            ? "awaiting-first-progress"
            : "progress-within-stall-grace",
  });
}

function validateGenerationPlan(value) {
  const plan = plainObject(value, "generationPlan");
  exactFields(plan, PLAN_FIELDS, "generationPlan");
  if (plan.algorithmVersion !== ADAPTIVE_WORK_ALGORITHM_VERSION) {
    throw new TypeError(
      `generationPlan.algorithmVersion deve ser ${ADAPTIVE_WORK_ALGORITHM_VERSION}.`,
    );
  }
  const normalized = {
    algorithmVersion: ADAPTIVE_WORK_ALGORITHM_VERSION,
    tierId: identifier(plan.tierId, "generationPlan.tierId"),
    tierRank: nonNegativeInteger(plan.tierRank, "generationPlan.tierRank"),
    maxOutputTokens: boundedInteger(
      plan.maxOutputTokens,
      "generationPlan.maxOutputTokens",
      1,
      4_096,
    ),
    editorialProfile: identifier(
      plan.editorialProfile,
      "generationPlan.editorialProfile",
    ),
    minimumUnit: booleanValue(plan.minimumUnit, "generationPlan.minimumUnit"),
    processingWindowSeconds: boundedInteger(
      plan.processingWindowSeconds,
      "generationPlan.processingWindowSeconds",
      60,
      86_400,
    ),
    nearWindowSeconds: boundedInteger(
      plan.nearWindowSeconds,
      "generationPlan.nearWindowSeconds",
      30,
      plan.processingWindowSeconds,
    ),
    firstProgressGraceSeconds: boundedInteger(
      plan.firstProgressGraceSeconds,
      "generationPlan.firstProgressGraceSeconds",
      30,
      plan.processingWindowSeconds,
    ),
    stallAfterSeconds: boundedInteger(
      plan.stallAfterSeconds,
      "generationPlan.stallAfterSeconds",
      30,
      plan.processingWindowSeconds,
    ),
    finalizationGraceSeconds: boundedInteger(
      plan.finalizationGraceSeconds,
      "generationPlan.finalizationGraceSeconds",
      30,
      plan.processingWindowSeconds,
    ),
    policyHash: sha256Hex(plan.policyHash, "generationPlan.policyHash"),
  };
  if (normalized.minimumUnit !== (normalized.tierRank === 0)) {
    throw new TypeError("generationPlan.minimumUnit deve corresponder ao tierRank 0.");
  }
  return Object.freeze(normalized);
}

function requirePlanFromPolicy(plan, policy) {
  const tier = policy.tiers[plan.tierRank];
  if (
    !tier ||
    plan.algorithmVersion !== policy.algorithmVersion ||
    plan.tierId !== tier.id ||
    plan.maxOutputTokens !== tier.maxOutputTokens ||
    plan.minimumUnit !== tier.minimumUnit ||
    plan.processingWindowSeconds !== policy.processingWindowSeconds ||
    plan.nearWindowSeconds !== Math.floor(
      policy.processingWindowSeconds * policy.nearWindowRatio,
    ) ||
    plan.firstProgressGraceSeconds !== policy.firstProgressGraceSeconds ||
    plan.stallAfterSeconds !== policy.stallAfterSeconds ||
    plan.finalizationGraceSeconds !== policy.finalizationGraceSeconds
    || policy.windowMode !== "advisory"
    || policy.minimumTierIgnoresWindow !== true
    || policy.livenessBasis !== "progress"
  ) {
    throw new TypeError("generationPlan não corresponde à adaptiveWorkPolicy informada.");
  }
}

function optionalProgress(value, name) {
  if (value === null || value === undefined) return null;
  const progress = plainObject(value, name);
  exactFields(progress, ["phase", "attempt", "sequence", "contentBytes"], name);
  if (!PHASES.includes(progress.phase)) {
    throw new TypeError(`${name}.phase deve ser starting, responding ou finalizing.`);
  }
  return Object.freeze({
    phase: progress.phase,
    attempt: boundedInteger(progress.attempt, `${name}.attempt`, 1, 1_000_000),
    sequence: nonNegativeInteger(progress.sequence, `${name}.sequence`),
    contentBytes: nonNegativeInteger(progress.contentBytes, `${name}.contentBytes`),
  });
}

function validateProgressTransition(previous, current) {
  if (!previous || !current) return;
  if (current.attempt < previous.attempt) {
    throw new RangeError("O attempt do progresso não pode regredir.");
  }
  if (current.attempt > previous.attempt) return;
  if (current.sequence < previous.sequence || current.contentBytes < previous.contentBytes) {
    throw new RangeError("sequence e contentBytes não podem regredir no mesmo attempt.");
  }
  if (PHASES.indexOf(current.phase) < PHASES.indexOf(previous.phase)) {
    throw new RangeError("A phase do progresso não pode regredir no mesmo attempt.");
  }
}

function madeMaterialProgress(previous, current) {
  if (!current) return false;
  if (!previous || current.attempt > previous.attempt) {
    return current.sequence > 0 && current.contentBytes > 0;
  }
  return current.attempt === previous.attempt &&
    current.sequence > previous.sequence &&
    current.contentBytes > previous.contentBytes;
}

function plainObject(value, name) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new TypeError(`${name} deve ser um objeto JSON.`);
  }
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) {
    throw new TypeError(`${name} deve ser um objeto JSON simples.`);
  }
  return value;
}

function exactFields(value, allowed, name, optionalEditorialProfile = false) {
  const allowedSet = new Set(allowed);
  for (const key of Object.keys(value)) {
    if (!allowedSet.has(key)) throw new TypeError(`${name}.${key} não é reconhecido.`);
  }
  for (const key of allowed) {
    if (optionalEditorialProfile && key === "editorialProfile") continue;
    if (!Object.hasOwn(value, key)) throw new TypeError(`${name}.${key} é obrigatório.`);
  }
}

function identifier(value, name) {
  if (typeof value !== "string" || !IDENTIFIER.test(value)) {
    throw new TypeError(`${name} deve ser um identificador ASCII de 1 a 64 caracteres.`);
  }
  return value;
}

function sha256Hex(value, name) {
  if (typeof value !== "string" || !SHA256_HEX.test(value)) {
    throw new TypeError(`${name} deve ser um SHA-256 hexadecimal minúsculo.`);
  }
  return value;
}

function booleanValue(value, name) {
  if (typeof value !== "boolean") throw new TypeError(`${name} deve ser booleano.`);
  return value;
}

function boundedInteger(value, name, minimum, maximum) {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    throw new RangeError(`${name} deve ser um inteiro entre ${minimum} e ${maximum}.`);
  }
  return value;
}

function nonNegativeInteger(value, name) {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new RangeError(`${name} deve ser um inteiro maior ou igual a 0.`);
  }
  return value;
}

function boundedNumber(value, name, minimum, maximum) {
  if (!Number.isFinite(value) || value < minimum || value > maximum) {
    throw new RangeError(`${name} deve estar entre ${minimum} e ${maximum}.`);
  }
  return value;
}

function nonNegativeNumber(value, name) {
  if (!Number.isFinite(value) || value < 0) {
    throw new RangeError(`${name} deve ser um número maior ou igual a 0.`);
  }
  return value;
}

function timestampMs(value, name) {
  if (typeof value !== "string" || !value.trim()) {
    throw new TypeError(`${name} deve ser um timestamp ISO 8601 do servidor.`);
  }
  const parsed = Date.parse(value);
  if (!Number.isFinite(parsed)) {
    throw new RangeError(`${name} deve ser um timestamp ISO 8601 válido.`);
  }
  return parsed;
}
