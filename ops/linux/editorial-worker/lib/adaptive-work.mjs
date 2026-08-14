import { canonicalizeJson, sha256Hex } from "../crypto.mjs";
import {
  createGenerationPlan,
  generationPlanHash,
  validateAdaptiveWorkPolicy,
} from "../../../../lib/editorial-work-sizing.mjs";
import { WorkerKitError } from "./errors.mjs";

const SHA256 = /^[a-f0-9]{64}$/;

export { validateAdaptiveWorkPolicy };

export async function adaptiveWorkPolicyHash(value) {
  const policy = validateAdaptiveWorkPolicy(value);
  return sha256Hex(canonicalizeJson(policy));
}

/**
 * Verifies that a server-issued plan is the exact JCS-derived plan represented
 * by the signed adaptive policy and that its immutable digest is correlated to
 * the assignment. The RuntimeProfile remains the engine ceiling.
 */
export async function verifyGenerationPlan(
  value,
  declaredHash,
  adaptiveWorkPolicy,
  runtimeProfile,
) {
  if (!SHA256.test(String(declaredHash ?? ""))) {
    throw adaptiveError("generation-plan-hash-invalid", "generationPlanHash must be lowercase SHA-256.");
  }
  const policy = validateAdaptiveWorkPolicy(adaptiveWorkPolicy);
  const policyHash = await adaptiveWorkPolicyHash(policy);
  const calculatedHash = await generationPlanHash(value);
  if (calculatedHash !== declaredHash) {
    throw adaptiveError(
      "generation-plan-hash-mismatch",
      "The assignment generation plan does not match its JCS SHA-256 digest.",
    );
  }
  const plan = structuredClone(value);
  const expected = createGenerationPlan(policy, plan.tierRank, {
    policyHash,
    editorialProfile: plan.editorialProfile,
  });
  if (canonicalizeJson(plan) !== canonicalizeJson(expected)) {
    throw adaptiveError(
      "generation-plan-policy-mismatch",
      "The assignment generation plan is not derived from the signed adaptive policy.",
    );
  }
  if (
    !runtimeProfile ||
    !Number.isSafeInteger(runtimeProfile.maxOutputTokens) ||
    plan.maxOutputTokens > runtimeProfile.maxOutputTokens
  ) {
    throw adaptiveError(
      "generation-plan-runtime-ceiling-exceeded",
      "The assignment generation plan exceeds the attested RuntimeProfile ceiling.",
    );
  }
  return Object.freeze(plan);
}

export function createAssignmentProgress(initialAttempt = 1) {
  if (!Number.isSafeInteger(initialAttempt) || initialAttempt < 1 || initialAttempt > 8) {
    throw new TypeError("initialAttempt must be an integer between 1 and 8.");
  }
  let current = Object.freeze({
    phase: "starting",
    attempt: initialAttempt,
    sequence: 0,
    contentBytes: 0,
  });
  return Object.freeze({
    snapshot() {
      return { ...current };
    },
    startAttempt(attempt) {
      if (!Number.isSafeInteger(attempt) || attempt < current.attempt || attempt > 8) {
        throw new TypeError("Progress attempt cannot regress and must be at most 8.");
      }
      current = Object.freeze({
        phase: "starting",
        attempt,
        sequence: 0,
        contentBytes: 0,
      });
      return { ...current };
    },
    recordContent(bytes) {
      if (!Number.isSafeInteger(bytes) || bytes < 1) {
        throw new TypeError("Progress bytes must be a positive integer.");
      }
      current = Object.freeze({
        phase: "responding",
        attempt: current.attempt,
        sequence: current.sequence + 1,
        contentBytes: current.contentBytes + bytes,
      });
      return { ...current };
    },
    beginFinalization() {
      current = Object.freeze({ ...current, phase: "finalizing" });
      return { ...current };
    },
  });
}

function adaptiveError(code, message) {
  return new WorkerKitError(code, message);
}
