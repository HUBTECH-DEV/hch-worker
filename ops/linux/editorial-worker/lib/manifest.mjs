import {
  canonicalizeJson,
  manifestContentContractHash,
  sha256Hex,
  verifyManifestWithDelegation,
  workerPublicKeyFingerprint,
} from "../crypto.mjs";
import { validateCapacityPolicy } from "./capacity.mjs";
import { validateAdaptiveWorkPolicy } from "./adaptive-work.mjs";
import { WorkerKitError } from "./errors.mjs";
import { workerPlatform } from "./platform.mjs";

const RELEASE_ACTIONS = new Set([
  "verify-artifact",
  "configure-engine",
  "pull-model-by-digest",
  "apply-editorial-policy",
  "self-test",
]);
const ARTIFACT_FIELDS = new Set([
  "name",
  "mediaType",
  "bytes",
  "sha256",
  "url",
  "authorizationClass",
]);

export async function verifyManifestResponse(
  response,
  config,
  rootPublicKeyPem,
  appliedState = null,
  options = {},
) {
  if (!isRecord(response) || !isRecord(response.manifest) || !isRecord(response.delegation)) {
    throw new WorkerKitError(
      "manifest-envelope-invalid",
      "The orchestrator manifest envelope is incomplete.",
    );
  }
  const rootFingerprint = await workerPublicKeyFingerprint(rootPublicKeyPem);
  if (
    rootFingerprint !== config.rootPublicKeyFingerprint ||
    response.rootPublicKeyFingerprint !== config.rootPublicKeyFingerprint ||
    response.rootKeyId !== config.rootKeyId
  ) {
    throw new WorkerKitError(
      "root-key-pin-mismatch",
      "The manifest root identity does not match the locally pinned root key.",
    );
  }
  let verified = await verifyManifestWithDelegation(
    response.manifest,
    response.delegation,
    rootPublicKeyPem,
    {
      now: options.now,
      expectedKeyId: config.rootKeyId,
    },
  );
  const expiredFallback = !verified.ok && isExpiryFailure(verified.code);
  if (expiredFallback && appliedState?.manifestHash) {
    verified = await verifyManifestWithDelegation(
      response.manifest,
      response.delegation,
      rootPublicKeyPem,
      {
        now: options.now,
        expectedKeyId: config.rootKeyId,
        allowExpired: true,
      },
    );
  }
  if (!verified.ok) {
    throw new WorkerKitError(
      `manifest-${verified.code}`,
      "The root → release → manifest signature chain is invalid.",
    );
  }
  const allowExpired = Date.parse(verified.payload?.expiresAt) <= normalizedNow(options.now);
  const manifest = validateManifestPayload(verified.payload, options.now, process.platform, { allowExpired });
  const hashless = { ...manifest };
  delete hashless.hash;
  const calculatedHash = await sha256Hex(canonicalizeJson(hashless));
  if (calculatedHash !== manifest.hash.toLowerCase()) {
    throw new WorkerKitError(
      "manifest-hash-mismatch",
      "The canonical manifest hash does not match its payload.",
    );
  }
  if (expiredFallback && (
    !appliedState ||
    manifest.hash !== appliedState.manifestHash ||
    manifest.sequence !== appliedState.manifestSequence
  )) {
    throw new WorkerKitError(
      "manifest-expired-update-refused",
      "An expired signature chain may only renew the identical applied manifest.",
    );
  }
  // Hash the verified signed payload, not its locally normalized validation
  // view, so the persisted value is exactly the protocol value attested by
  // the orchestrator and shared signature verifier.
  const contentContractHash = await manifestContentContractHash(verified.payload);
  const delegationSequence = verified.delegation.sequence;
  if (!Number.isSafeInteger(delegationSequence) || delegationSequence < 1) {
    throw new WorkerKitError(
      "delegation-sequence-invalid",
      "The verified root to release delegation sequence is invalid.",
    );
  }
  const delegationHash = await sha256Hex(canonicalizeJson(response.delegation));
  enforceDelegationAntiRollback(
    { delegationSequence, delegationHash },
    options.trustState,
    config,
    rootFingerprint,
  );
  enforceAntiRollback(manifest, appliedState);
  return {
    manifest,
    rootKeyId: config.rootKeyId,
    rootFingerprint,
    releaseKeyId: verified.keyId,
    releaseFingerprint: verified.delegation.fingerprint,
    delegationSequence,
    delegationHash,
    contentContractHash,
    expiredFallback,
  };
}

export function validateManifestPayload(
  value,
  nowValue,
  platformValue = process.platform,
  options = {},
) {
  const manifest = record(value, "manifest");
  if (manifest.schemaVersion !== "2.0" || manifest.protocolVersion !== "2.0") {
    throw new WorkerKitError("manifest-version-unsupported", "Only manifest protocol 2.0 is supported.");
  }
  const sequence = positiveInteger(manifest.sequence, "manifest.sequence");
  const minimumAcceptedSequence = positiveInteger(
    manifest.minimumAcceptedSequence,
    "manifest.minimumAcceptedSequence",
  );
  if (sequence < minimumAcceptedSequence) {
    throw new WorkerKitError(
      "manifest-minimum-sequence-invalid",
      "Manifest sequence is below its own minimum accepted sequence.",
    );
  }
  const issuedAt = timestamp(manifest.issuedAt, "manifest.issuedAt");
  const expiresAt = timestamp(manifest.expiresAt, "manifest.expiresAt");
  const now = nowValue instanceof Date
    ? nowValue.getTime()
    : typeof nowValue === "number"
      ? (nowValue < 10_000_000_000 ? nowValue * 1_000 : nowValue)
      : Date.now();
  if (
    Date.parse(issuedAt) > now + 5 * 60_000 ||
    (Date.parse(expiresAt) <= now && options.allowExpired !== true) ||
    Date.parse(expiresAt) <= Date.parse(issuedAt)
  ) {
    throw new WorkerKitError("manifest-expired", "Manifest payload is expired or has an invalid validity window.");
  }
  const runtime = record(manifest.runtime, "manifest.runtime");
  const platform = workerPlatform(platformValue);
  if (
    typeof runtime.workerVersion !== "string" ||
    !Array.isArray(runtime.supportedPlatforms) ||
    !runtime.supportedPlatforms.includes(platform)
  ) {
    throw new WorkerKitError(
      "manifest-platform-incompatible",
      `Manifest does not support this ${platform} worker.`,
    );
  }
  const engine = record(manifest.engine, "manifest.engine");
  if (
    !isPortableEngineIdentifier(engine.provider) ||
    !isPortableEngineIdentifier(engine.adapter) ||
    !isPortableEngineIdentifier(engine.adapterVersion) ||
    typeof engine.model !== "string" ||
    !engine.model ||
    !isSha256(engine.modelDigest) ||
    engine.healthPath !== "/api/tags" ||
    typeof engine.protocol !== "string" ||
    !engine.protocol
  ) {
    throw new WorkerKitError("manifest-engine-invalid", "Manifest engine contract is invalid.");
  }
  const generation = record(manifest.generation, "manifest.generation");
  if (
    typeof generation.temperature !== "number" ||
    !Number.isFinite(generation.temperature) ||
    generation.temperature < 0 ||
    !Number.isSafeInteger(generation.contextWindow) ||
    generation.contextWindow <= 0 ||
    !Number.isSafeInteger(generation.maxOutputTokens) ||
    generation.maxOutputTokens <= 0
  ) {
    throw new WorkerKitError(
      "manifest-generation-invalid",
      "Manifest generation parameters are invalid.",
    );
  }
  const capacityPolicy = validateCapacityPolicy(manifest.capacityPolicy);
  const adaptiveWorkPolicy = validateAdaptiveWorkPolicy(manifest.adaptiveWorkPolicy);
  const editorial = record(manifest.editorial, "manifest.editorial");
  for (const field of [
    "policyId",
    "policyVersion",
    "policyHash",
    "promptConfigHash",
    "pipelineVersion",
  ]) {
    if (typeof editorial[field] !== "string" || !editorial[field]) {
      throw new WorkerKitError("manifest-editorial-invalid", `Manifest editorial ${field} is invalid.`);
    }
  }
  if (!isLowerSha256(editorial.policyHash) || !isLowerSha256(editorial.promptConfigHash)) {
    throw new WorkerKitError(
      "manifest-editorial-invalid",
      "Manifest editorial hashes must be lowercase SHA-256 values.",
    );
  }
  if (!Array.isArray(manifest.actions) || !Array.isArray(manifest.artifacts)) {
    throw new WorkerKitError("manifest-plan-invalid", "Manifest action and artifact arrays are required.");
  }
  validateActions(manifest.actions);
  const artifacts = manifest.artifacts.map(validateArtifact);
  if (new Set(artifacts.map((artifact) => artifact.name)).size !== artifacts.length) {
    throw new WorkerKitError("manifest-artifact-duplicate", "Manifest artifact names must be unique.");
  }
  if (
    manifest.security?.authorizationByIp !== false ||
    manifest.security?.arbitraryRemoteCommands !== false ||
    manifest.safety?.credentialsInManifest !== false ||
    manifest.safety?.automaticApproval !== false ||
    manifest.safety?.automaticPublication !== false
  ) {
    throw new WorkerKitError("manifest-safety-invalid", "Manifest safety guarantees are not acceptable.");
  }
  if (!isSha256(manifest.hash)) {
    throw new WorkerKitError("manifest-hash-invalid", "Manifest hash must be 64 hexadecimal SHA-256 characters.");
  }
  if (manifest.previousManifestHash !== null && !isSha256(manifest.previousManifestHash)) {
    throw new WorkerKitError("manifest-chain-invalid", "previousManifestHash is invalid.");
  }
  return { ...manifest, capacityPolicy, adaptiveWorkPolicy, artifacts };
}

function normalizedNow(value) {
  if (value instanceof Date) return value.getTime();
  if (typeof value === "number") return value < 10_000_000_000 ? value * 1_000 : value;
  return Date.now();
}

function isExpiryFailure(code) {
  return new Set(["expired", "delegation-expired"]).has(String(code));
}

export function enforceDelegationAntiRollback(
  candidate,
  trustState,
  config,
  rootFingerprint,
) {
  if (!trustState) return;
  if (
    trustState.schemaVersion !== 1 ||
    (trustState.rootKeyId !== undefined && trustState.rootKeyId !== config.rootKeyId) ||
    (trustState.rootFingerprint !== undefined &&
      trustState.rootFingerprint !== rootFingerprint)
  ) {
    throw new WorkerKitError(
      "delegation-state-invalid",
      "The persisted delegation trust anchor is invalid.",
    );
  }
  const hasSequence = trustState.delegationSequence !== undefined;
  const hasHash = trustState.delegationHash !== undefined;
  // A trust state written by kit 2.0 before this anchor existed is migrated by
  // the next successful bootstrap. A partial anchor is never accepted.
  if (!hasSequence && !hasHash) return;
  if (
    !hasSequence ||
    !hasHash ||
    !Number.isSafeInteger(trustState.delegationSequence) ||
    trustState.delegationSequence < 1 ||
    !isSha256(trustState.delegationHash)
  ) {
    throw new WorkerKitError(
      "delegation-state-invalid",
      "The persisted delegation trust anchor is incomplete or invalid.",
    );
  }
  if (candidate.delegationSequence < trustState.delegationSequence) {
    throw new WorkerKitError(
      "delegation-rollback-refused",
      "The root to release delegation sequence would roll the worker back.",
    );
  }
  if (
    candidate.delegationSequence === trustState.delegationSequence &&
    candidate.delegationHash !== trustState.delegationHash.toLowerCase()
  ) {
    throw new WorkerKitError(
      "delegation-equivocation-refused",
      "The same delegation sequence carries a different canonical envelope hash.",
    );
  }
}

export function trustStateFromManifestVerification(verification, verifiedAt = new Date()) {
  return {
    schema: "hch.worker-trust-state/v1",
    schemaVersion: 1,
    rootKeyId: verification.rootKeyId,
    rootFingerprint: verification.rootFingerprint,
    releaseKeyId: verification.releaseKeyId,
    delegationSequence: verification.delegationSequence,
    delegationHash: verification.delegationHash,
    manifestSequence: verification.manifest.sequence,
    manifestHash: verification.manifest.hash,
    contentContractHash: verification.contentContractHash,
    policyHash: verification.manifest.editorial.policyHash,
    verifiedAt: verifiedAt.toISOString(),
  };
}

export function enforceAntiRollback(manifest, appliedState) {
  if (!appliedState) return;
  if (
    appliedState.schemaVersion !== 1 ||
    !Number.isSafeInteger(appliedState.manifestSequence) ||
    !isSha256(appliedState.manifestHash)
  ) {
    throw new WorkerKitError("applied-state-invalid", "The locally applied manifest state is invalid.");
  }
  if (manifest.sequence < appliedState.manifestSequence) {
    throw new WorkerKitError("manifest-rollback-refused", "Manifest sequence would roll the worker back.");
  }
  if (
    manifest.sequence === appliedState.manifestSequence &&
    manifest.hash !== appliedState.manifestHash
  ) {
    throw new WorkerKitError("manifest-equivocation-refused", "The same sequence carries a different hash.");
  }
  if (
    manifest.sequence > appliedState.manifestSequence &&
    manifest.previousManifestHash !== appliedState.manifestHash
  ) {
    throw new WorkerKitError("manifest-chain-break", "Manifest does not extend the locally applied hash chain.");
  }
}

export function assertLocalModel(tagsPayload, manifest) {
  if (!Array.isArray(tagsPayload?.models)) {
    throw new WorkerKitError("model-list-invalid", "Local /api/tags did not return a models array.");
  }
  const expectedDigest = normalizeDigest(manifest.engine.modelDigest);
  const match = tagsPayload.models.find((model) =>
    (model?.name === manifest.engine.model || model?.model === manifest.engine.model) &&
    normalizeDigest(model?.digest) === expectedDigest,
  );
  if (!match) {
    throw new WorkerKitError(
      "model-digest-unavailable",
      "The exact manifest model and digest are not available in the local engine.",
    );
  }
  return { name: manifest.engine.model, digest: expectedDigest };
}

function validateActions(actions) {
  const seen = new Set();
  for (const value of actions) {
    const action = record(value, "manifest action");
    const keys = Object.keys(action);
    if (keys.some((key) => !new Set(["type", "authorizationClass"]).has(key))) {
      throw new WorkerKitError(
        "manifest-action-fields-refused",
        "Manifest action contains fields outside the declarative allowlist.",
      );
    }
    if (action.authorizationClass === "root-required") {
      throw new WorkerKitError(
        "root-action-refused",
        "Instantiated root-required actions are not accepted by this worker kit.",
      );
    }
    if (action.authorizationClass !== "release" || !RELEASE_ACTIONS.has(action.type)) {
      throw new WorkerKitError(
        "manifest-action-refused",
        "Manifest action is not in the release-action allowlist.",
      );
    }
    if (seen.has(action.type)) {
      throw new WorkerKitError("manifest-action-duplicate", "Manifest actions must not be duplicated.");
    }
    seen.add(action.type);
  }
}

function validateArtifact(value) {
  const artifact = record(value, "manifest artifact");
  const unknown = Object.keys(artifact).find((key) => !ARTIFACT_FIELDS.has(key));
  if (unknown) throw new WorkerKitError("manifest-artifact-fields-refused", "Artifact contains unsupported fields.");
  if (!/^[a-z0-9][a-z0-9-]{0,79}$/.test(artifact.name ?? "")) {
    throw new WorkerKitError("manifest-artifact-name-invalid", "Artifact name is unsafe.");
  }
  if (artifact.authorizationClass === "root-required") {
    throw new WorkerKitError("root-artifact-refused", "Root-required artifact is not accepted by release delegation.");
  }
  if (
    artifact.authorizationClass !== "release" ||
    typeof artifact.mediaType !== "string" ||
    !artifact.mediaType ||
    !Number.isSafeInteger(artifact.bytes) ||
    artifact.bytes <= 0 ||
    !isSha256(artifact.sha256) ||
    typeof artifact.url !== "string"
  ) {
    throw new WorkerKitError("manifest-artifact-invalid", "Artifact declaration is invalid.");
  }
  return { ...artifact, sha256: artifact.sha256.toLowerCase() };
}

function normalizeDigest(value) {
  return String(value ?? "").toLowerCase().replace(/^sha256:/, "");
}

function isSha256(value) {
  return /^[a-f0-9]{64}$/i.test(String(value ?? "").replace(/^sha256:/i, ""));
}

function isLowerSha256(value) {
  return /^[a-f0-9]{64}$/.test(String(value ?? ""));
}

function isPortableEngineIdentifier(value) {
  return typeof value === "string" &&
    /^[A-Za-z0-9][A-Za-z0-9._:+/-]{0,159}$/.test(value);
}

function positiveInteger(value, name) {
  if (!Number.isSafeInteger(value) || value <= 0) {
    throw new WorkerKitError("manifest-number-invalid", `${name} must be a positive integer.`);
  }
  return value;
}

function timestamp(value, name) {
  if (typeof value !== "string" || !Number.isFinite(Date.parse(value))) {
    throw new WorkerKitError("manifest-time-invalid", `${name} must be an ISO timestamp.`);
  }
  return new Date(value).toISOString();
}

function record(value, name) {
  if (!isRecord(value)) throw new WorkerKitError("manifest-shape-invalid", `${name} must be an object.`);
  return value;
}

function isRecord(value) {
  return Boolean(value && typeof value === "object" && !Array.isArray(value));
}
