import { canonicalizeJson, sha256Hex } from "../crypto.mjs";
import { WorkerKitError } from "./errors.mjs";

export const RUNTIME_PROFILE_CORE_FIELDS = Object.freeze([
  "provider",
  "engineAdapter",
  "engineAdapterVersion",
  "model",
  "modelDigest",
  "protocol",
  "temperature",
  "contextWindow",
  "maxOutputTokens",
  "policyId",
  "policyVersion",
  "policyHash",
  "promptConfigHash",
  "pipelineVersion",
  "manifestSequence",
  "manifestHash",
]);

const RUNTIME_PROFILE_FIELDS = new Set([
  ...RUNTIME_PROFILE_CORE_FIELDS,
  "runtimeProfileHash",
]);

const REQUIRED_TEXT_FIELDS = [
  "model",
  "protocol",
  "policyId",
  "policyVersion",
  "policyHash",
  "promptConfigHash",
  "pipelineVersion",
];

/**
 * Builds the exact immutable RuntimeProfile v2 core represented by a signed
 * manifest. The three engine identity fields are deliberately independent:
 * provider names the inference provider, while adapter and adapter version
 * identify the code path used to speak to it.
 */
export function runtimeProfileCoreFromManifest(manifest) {
  return {
    provider: manifest?.engine?.provider,
    engineAdapter: manifest?.engine?.adapter,
    engineAdapterVersion: manifest?.engine?.adapterVersion,
    model: manifest?.engine?.model,
    modelDigest: manifest?.engine?.modelDigest,
    protocol: manifest?.engine?.protocol,
    temperature: manifest?.generation?.temperature,
    contextWindow: manifest?.generation?.contextWindow,
    maxOutputTokens: manifest?.generation?.maxOutputTokens,
    policyId: manifest?.editorial?.policyId,
    policyVersion: manifest?.editorial?.policyVersion,
    policyHash: manifest?.editorial?.policyHash,
    promptConfigHash: manifest?.editorial?.promptConfigHash,
    pipelineVersion: manifest?.editorial?.pipelineVersion,
    manifestSequence: manifest?.sequence,
    manifestHash: manifest?.hash,
  };
}

export async function createRuntimeProfileFromManifest(manifest) {
  const core = runtimeProfileCoreFromManifest(manifest);
  validateRuntimeProfileCore(core);
  return {
    ...core,
    runtimeProfileHash: await sha256Hex(canonicalizeJson(core)),
  };
}

/**
 * Verifies an immutable RuntimeProfile v2. The hash is calculated after
 * removing only runtimeProfileHash; unknown properties are rejected so no
 * unhashed or ambiguously interpreted configuration can reach the generator.
 */
export async function verifyRuntimeProfile(runtimeProfile, manifest = null) {
  if (!isRecord(runtimeProfile)) {
    throw new WorkerKitError(
      "runtime-profile-shape-invalid",
      "RuntimeProfile v2 must be an object.",
    );
  }
  const keys = Object.keys(runtimeProfile);
  const missing = [...RUNTIME_PROFILE_FIELDS].filter((field) => !keys.includes(field));
  const unknown = keys.filter((field) => !RUNTIME_PROFILE_FIELDS.has(field));
  if (missing.length || unknown.length) {
    throw new WorkerKitError(
      "runtime-profile-fields-invalid",
      "RuntimeProfile v2 has missing or unsupported fields.",
    );
  }
  const core = Object.fromEntries(
    RUNTIME_PROFILE_CORE_FIELDS.map((field) => [field, runtimeProfile[field]]),
  );
  validateRuntimeProfileCore(core);
  if (!isLowerSha256(runtimeProfile.runtimeProfileHash)) {
    throw new WorkerKitError(
      "runtime-profile-hash-invalid",
      "runtimeProfileHash must be a lowercase SHA-256 value.",
    );
  }
  const calculatedHash = await sha256Hex(canonicalizeJson(core));
  if (calculatedHash !== runtimeProfile.runtimeProfileHash) {
    throw new WorkerKitError(
      "runtime-profile-hash-mismatch",
      "RuntimeProfile v2 does not match its immutable canonical hash.",
    );
  }
  if (manifest) {
    const expected = runtimeProfileCoreFromManifest(manifest);
    validateRuntimeProfileCore(expected);
    if (canonicalizeJson(core) !== canonicalizeJson(expected)) {
      throw new WorkerKitError(
        "runtime-profile-manifest-mismatch",
        "RuntimeProfile v2 does not match the currently verified manifest.",
      );
    }
  }
  return { ...core, runtimeProfileHash: calculatedHash };
}

function validateRuntimeProfileCore(core) {
  for (const field of ["provider", "engineAdapter", "engineAdapterVersion"]) {
    if (
      typeof core[field] !== "string" ||
      !/^[A-Za-z0-9][A-Za-z0-9._:+/-]{0,159}$/.test(core[field])
    ) {
      throw new WorkerKitError(
        "runtime-profile-value-invalid",
        `RuntimeProfile v2 field ${field} is not a portable engine identifier.`,
      );
    }
  }
  for (const field of REQUIRED_TEXT_FIELDS) {
    if (typeof core[field] !== "string" || !core[field].trim()) {
      throw new WorkerKitError(
        "runtime-profile-value-invalid",
        `RuntimeProfile v2 field ${field} must be non-empty text.`,
      );
    }
  }
  if (!/^(?:sha256:)?[a-f0-9]{64}$/i.test(String(core.modelDigest ?? ""))) {
    throw new WorkerKitError(
      "runtime-profile-value-invalid",
      "RuntimeProfile v2 modelDigest must be a SHA-256 digest.",
    );
  }
  if (!isLowerSha256(core.policyHash) || !isLowerSha256(core.promptConfigHash)) {
    throw new WorkerKitError(
      "runtime-profile-value-invalid",
      "RuntimeProfile v2 editorial hashes must be lowercase SHA-256 values.",
    );
  }
  if (
    typeof core.temperature !== "number" ||
    !Number.isFinite(core.temperature) ||
    core.temperature < 0 ||
    !Number.isSafeInteger(core.contextWindow) ||
    core.contextWindow <= 0 ||
    !Number.isSafeInteger(core.maxOutputTokens) ||
    core.maxOutputTokens <= 0 ||
    !Number.isSafeInteger(core.manifestSequence) ||
    core.manifestSequence <= 0 ||
    !isLowerSha256(core.manifestHash)
  ) {
    throw new WorkerKitError(
      "runtime-profile-value-invalid",
      "RuntimeProfile v2 contains invalid generation or manifest values.",
    );
  }
}

function isLowerSha256(value) {
  return /^[a-f0-9]{64}$/.test(String(value ?? ""));
}

function isRecord(value) {
  return Boolean(value && typeof value === "object" && !Array.isArray(value));
}
