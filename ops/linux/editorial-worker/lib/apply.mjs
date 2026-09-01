import {
  canonicalizeJson,
  manifestContentContractHash,
  sha256Hex,
} from "../crypto.mjs";
import { capacityPolicyHash } from "./capacity.mjs";
import { adaptiveWorkPolicyHash, validateAdaptiveWorkPolicy } from "./adaptive-work.mjs";
import { downloadArtifact, queryLocalModel } from "./http.mjs";
import { assertLocalModel } from "./manifest.mjs";
import { createRuntimeProfileFromManifest } from "./runtime-profile.mjs";
import {
  atomicWriteFile,
  atomicWriteJson,
  readOptionalFile,
  removeStateFile,
} from "./storage.mjs";
import { WorkerKitError } from "./errors.mjs";
import { KIT_VERSION, assertWorkerRuntimeVersion } from "./local-state.mjs";

const EDITORIAL_DESTINATIONS = new Map([
  ["policy", "runtime/editorial/policy.json"],
  ["prompt", "runtime/editorial/prompt.md"],
  ["editorial-content-schema", "runtime/editorial/editorial-content-schema.json"],
  ["editorial-source-schema", "runtime/editorial/editorial-source-schema.json"],
]);

export async function stageApplyAndSelfTest(
  config,
  stateRoot,
  manifest,
  previousApplied,
  options = {},
) {
  assertWorkerRuntimeVersion(manifest);
  const runtimeProfile = await createRuntimeProfileFromManifest(manifest);
  const signedCapacityPolicyHash = await capacityPolicyHash(manifest.capacityPolicy);
  const adaptiveWorkPolicy = validateAdaptiveWorkPolicy(manifest.adaptiveWorkPolicy);
  const signedAdaptiveWorkPolicyHash = await adaptiveWorkPolicyHash(adaptiveWorkPolicy);
  const contentContractHash = options.contentContractHash ??
    await manifestContentContractHash(manifest);
  if (!/^[a-f0-9]{64}$/.test(contentContractHash)) {
    throw new WorkerKitError(
      "manifest-content-contract-invalid",
      "The verified manifest content contract hash is invalid.",
    );
  }
  if (
    previousApplied?.contentContractHash === contentContractHash ||
    isLegacyContentContractBackfill(previousApplied, manifest.hash)
  ) {
    return refreshCompatibleManifestMetadata(
      config,
      stateRoot,
      manifest,
      previousApplied,
      {
        adaptiveWorkPolicy,
        contentContractHash,
        runtimeProfile,
        signedAdaptiveWorkPolicyHash,
        signedCapacityPolicyHash,
      },
      options,
    );
  }
  const staged = new Map();
  const artifactHashes = {};
  for (const artifact of manifest.artifacts) {
    const downloaded = await downloadArtifact(config, artifact, options);
    if (downloaded.bytes.byteLength !== artifact.bytes) {
      throw new WorkerKitError("artifact-size-mismatch", `Artifact ${artifact.name} has an unexpected size.`);
    }
    const digest = await sha256Hex(downloaded.bytes);
    if (digest !== artifact.sha256) {
      throw new WorkerKitError("artifact-hash-mismatch", `Artifact ${artifact.name} failed SHA-256 validation.`);
    }
    const contentType = downloaded.headers.get("content-type") ?? "";
    const expectedType = artifact.mediaType.split(";", 1)[0].trim().toLowerCase();
    const receivedType = contentType.split(";", 1)[0].trim().toLowerCase();
    if (receivedType !== expectedType) {
      throw new WorkerKitError("artifact-media-type-mismatch", `Artifact ${artifact.name} has an unexpected media type.`);
    }
    staged.set(artifact.name, downloaded.bytes);
    artifactHashes[artifact.name] = digest;
    await atomicWriteFile(
      stateRoot,
      `staging/${manifest.hash}/${artifact.name}`,
      downloaded.bytes,
    );
  }

  for (const required of EDITORIAL_DESTINATIONS.keys()) {
    if (!staged.has(required)) {
      throw new WorkerKitError("artifact-required-missing", `Required artifact ${required} is absent.`);
    }
  }
  const targets = [
    ...manifest.artifacts.map((artifact) => `runtime/artifacts/${artifact.name}`),
    ...EDITORIAL_DESTINATIONS.values(),
    "runtime/config/engine.json",
    "applied-manifest.json",
  ];
  const backup = new Map();
  for (const target of targets) backup.set(target, await readOptionalFile(stateRoot, target));

  const appliedAt = new Date().toISOString();
  const appliedState = {
    schemaVersion: 1,
    manifestSequence: manifest.sequence,
    manifestHash: manifest.hash,
    contentContractHash,
    previousManifestHash: manifest.previousManifestHash,
    releaseId: manifest.releaseId,
    workerRuntimeVersion: KIT_VERSION,
    policyHash: manifest.editorial.policyHash,
    promptConfigHash: manifest.editorial.promptConfigHash,
    pipelineVersion: manifest.editorial.pipelineVersion,
    provider: manifest.engine.provider,
    engineAdapter: manifest.engine.adapter,
    engineAdapterVersion: manifest.engine.adapterVersion,
    model: manifest.engine.model,
    modelDigest: normalizeDigest(manifest.engine.modelDigest),
    protocol: manifest.engine.protocol,
    runtimeProfileHash: runtimeProfile.runtimeProfileHash,
    runtimeProfile,
    capacityPolicyHash: signedCapacityPolicyHash,
    capacityPolicy: manifest.capacityPolicy,
    adaptiveWorkPolicyHash: signedAdaptiveWorkPolicyHash,
    adaptiveWorkPolicy,
    artifacts: manifest.artifacts,
    artifactHashes,
    appliedAt,
  };
  try {
    for (const artifact of manifest.artifacts) {
      await atomicWriteFile(
        stateRoot,
        `runtime/artifacts/${artifact.name}`,
        staged.get(artifact.name),
      );
    }
    for (const [name, destination] of EDITORIAL_DESTINATIONS) {
      await atomicWriteFile(stateRoot, destination, staged.get(name));
    }
    await atomicWriteJson(stateRoot, "runtime/config/engine.json", {
      schemaVersion: 1,
      provider: manifest.engine.provider,
      adapter: manifest.engine.adapter,
      adapterVersion: manifest.engine.adapterVersion,
      model: manifest.engine.model,
      modelDigest: normalizeDigest(manifest.engine.modelDigest),
      protocol: manifest.engine.protocol,
      generation: manifest.generation,
      capacityPolicy: manifest.capacityPolicy,
      capacityPolicyHash: signedCapacityPolicyHash,
      adaptiveWorkPolicy,
      adaptiveWorkPolicyHash: signedAdaptiveWorkPolicyHash,
      contentContractHash,
      sourceManifestHash: manifest.hash,
    });

    const engine = await queryLocalModel(config, options);
    assertLocalModel(engine.payload, manifest);
    await verifyInstalledArtifacts(stateRoot, manifest);
    await atomicWriteJson(stateRoot, "applied-manifest.json", appliedState);

    const receiptCore = {
      previousManifestHash: previousApplied?.manifestHash ?? null,
      targetManifestHash: manifest.hash,
      artifactHashes,
      result: previousApplied?.manifestHash === manifest.hash ? "no-change" : "applied",
      rollbackPerformed: false,
      appliedAt,
    };
    const receiptHash = await sha256Hex(canonicalizeJson(receiptCore));
    const localJournal = {
      schemaVersion: 1,
      nodeId: config.nodeId,
      keyId: config.keyId,
      manifestSequence: manifest.sequence,
      manifestHash: manifest.hash,
      releaseId: manifest.releaseId,
      workerRuntimeVersion: KIT_VERSION,
      receiptHash,
      receipt: receiptCore,
      actionResults: manifest.actions.map((action) => ({
        type: action.type,
        authorizationClass: action.authorizationClass,
        result: actionResult(action.type),
      })),
      artifacts: manifest.artifacts.map((artifact) => ({
        name: artifact.name,
        bytes: artifact.bytes,
        sha256: artifact.sha256,
      })),
      checks: {
        configurationApplied: true,
        artifactsVerified: true,
        modelAvailable: true,
        generatorReachable: true,
        selfTestPassed: true,
      },
      engine: {
        provider: manifest.engine.provider,
        adapter: manifest.engine.adapter,
        adapterVersion: manifest.engine.adapterVersion,
        observedEngineVersion: engine.observedEngineVersion,
        model: manifest.engine.model,
        modelDigest: normalizeDigest(manifest.engine.modelDigest),
        protocol: manifest.engine.protocol,
      },
      runtimeProfile,
      capacityPolicyHash: signedCapacityPolicyHash,
      adaptiveWorkPolicyHash: signedAdaptiveWorkPolicyHash,
      contentContractHash,
    };
    const localAuditHash = await sha256Hex(canonicalizeJson(localJournal));
    const updateReceipt = {
      ...receiptCore,
      receiptHash,
      localAuditHash,
    };
    await atomicWriteJson(stateRoot, `receipts/${manifest.hash}.json`, {
      schemaVersion: 1,
      journal: localJournal,
      localAuditHash,
      updateReceipt,
    });
    return {
      appliedState,
      updateReceipt,
      runtimeProfile,
      checks: {
        configurationApplied: true,
        artifactsVerified: true,
        modelAvailable: true,
        generatorReachable: true,
        selfTestPassed: true,
      },
    };
  } catch (error) {
    await restoreBackup(stateRoot, backup);
    throw error;
  }
}

export function isLegacyContentContractBackfill(previousApplied, targetManifestHash) {
  if (!previousApplied || previousApplied.contentContractHash != null) return false;
  return /^[a-f0-9]{64}$/.test(previousApplied.manifestHash) &&
    /^[a-f0-9]{64}$/.test(targetManifestHash) &&
    previousApplied.manifestHash === targetManifestHash;
}

async function refreshCompatibleManifestMetadata(
  config,
  stateRoot,
  manifest,
  previousApplied,
  calculated,
  options,
) {
  const {
    adaptiveWorkPolicy,
    contentContractHash,
    runtimeProfile,
    signedAdaptiveWorkPolicyHash,
    signedCapacityPolicyHash,
  } = calculated;
  await verifyInstalledArtifacts(stateRoot, manifest);
  const engine = await queryLocalModel(config, options);
  assertLocalModel(engine.payload, manifest);
  const artifactHashes = Object.fromEntries(
    manifest.artifacts.map((artifact) => [artifact.name, artifact.sha256]),
  );
  const appliedAt = new Date().toISOString();
  const appliedState = {
    ...previousApplied,
    schemaVersion: 1,
    manifestSequence: manifest.sequence,
    manifestHash: manifest.hash,
    contentContractHash,
    previousManifestHash: manifest.previousManifestHash,
    releaseId: manifest.releaseId,
    policyHash: manifest.editorial.policyHash,
    promptConfigHash: manifest.editorial.promptConfigHash,
    pipelineVersion: manifest.editorial.pipelineVersion,
    provider: manifest.engine.provider,
    engineAdapter: manifest.engine.adapter,
    engineAdapterVersion: manifest.engine.adapterVersion,
    model: manifest.engine.model,
    modelDigest: normalizeDigest(manifest.engine.modelDigest),
    protocol: manifest.engine.protocol,
    runtimeProfileHash: runtimeProfile.runtimeProfileHash,
    runtimeProfile,
    capacityPolicyHash: signedCapacityPolicyHash,
    capacityPolicy: manifest.capacityPolicy,
    adaptiveWorkPolicyHash: signedAdaptiveWorkPolicyHash,
    adaptiveWorkPolicy,
    artifacts: manifest.artifacts,
    artifactHashes,
    appliedAt,
    metadataRefreshedAt: appliedAt,
  };
  const backup = new Map([
    ["runtime/config/engine.json", await readOptionalFile(stateRoot, "runtime/config/engine.json")],
    ["applied-manifest.json", await readOptionalFile(stateRoot, "applied-manifest.json")],
  ]);
  try {
    await atomicWriteJson(stateRoot, "runtime/config/engine.json", {
      schemaVersion: 1,
      provider: manifest.engine.provider,
      adapter: manifest.engine.adapter,
      adapterVersion: manifest.engine.adapterVersion,
      model: manifest.engine.model,
      modelDigest: normalizeDigest(manifest.engine.modelDigest),
      protocol: manifest.engine.protocol,
      generation: manifest.generation,
      capacityPolicy: manifest.capacityPolicy,
      capacityPolicyHash: signedCapacityPolicyHash,
      adaptiveWorkPolicy,
      adaptiveWorkPolicyHash: signedAdaptiveWorkPolicyHash,
      contentContractHash,
      sourceManifestHash: manifest.hash,
    });
    await atomicWriteJson(stateRoot, "applied-manifest.json", appliedState);
    const receiptCore = {
      previousManifestHash: previousApplied.manifestHash,
      targetManifestHash: manifest.hash,
      artifactHashes,
      result: "no-change",
      rollbackPerformed: false,
      appliedAt,
    };
    const receiptHash = await sha256Hex(canonicalizeJson(receiptCore));
    const localJournal = {
      schemaVersion: 1,
      nodeId: config.nodeId,
      keyId: config.keyId,
      manifestSequence: manifest.sequence,
      manifestHash: manifest.hash,
      contentContractHash,
      previousContentContractHash: previousApplied.contentContractHash ?? null,
      releaseId: manifest.releaseId,
      receiptHash,
      receipt: receiptCore,
      actionResults: manifest.actions.map((action) => ({
        type: action.type,
        authorizationClass: action.authorizationClass,
        result: "unchanged-compatible",
      })),
      artifacts: manifest.artifacts.map((artifact) => ({
        name: artifact.name,
        bytes: artifact.bytes,
        sha256: artifact.sha256,
      })),
      checks: {
        configurationApplied: true,
        artifactsVerified: true,
        modelAvailable: true,
        generatorReachable: true,
        selfTestPassed: true,
      },
      engine: {
        provider: manifest.engine.provider,
        adapter: manifest.engine.adapter,
        adapterVersion: manifest.engine.adapterVersion,
        observedEngineVersion: engine.observedEngineVersion,
        model: manifest.engine.model,
        modelDigest: normalizeDigest(manifest.engine.modelDigest),
        protocol: manifest.engine.protocol,
      },
      runtimeProfile,
      capacityPolicyHash: signedCapacityPolicyHash,
      adaptiveWorkPolicyHash: signedAdaptiveWorkPolicyHash,
    };
    const localAuditHash = await sha256Hex(canonicalizeJson(localJournal));
    const updateReceipt = { ...receiptCore, receiptHash, localAuditHash };
    await atomicWriteJson(stateRoot, `receipts/${manifest.hash}.json`, {
      schemaVersion: 1,
      journal: localJournal,
      localAuditHash,
      updateReceipt,
    });
    return {
      appliedState,
      updateReceipt,
      runtimeProfile,
      metadataOnly: true,
      checks: {
        configurationApplied: true,
        artifactsVerified: true,
        modelAvailable: true,
        generatorReachable: true,
        selfTestPassed: true,
      },
    };
  } catch (error) {
    await restoreBackup(stateRoot, backup);
    throw error;
  }
}

export async function verifyInstalledArtifacts(stateRoot, manifest) {
  for (const artifact of manifest.artifacts) {
    const bytes = await readOptionalFile(
      stateRoot,
      `runtime/artifacts/${artifact.name}`,
      artifact.bytes,
    );
    if (!bytes || bytes.byteLength !== artifact.bytes || await sha256Hex(bytes) !== artifact.sha256) {
      throw new WorkerKitError(
        "installed-artifact-invalid",
        `Installed artifact ${artifact.name} does not match the manifest.`,
      );
    }
  }
}

async function restoreBackup(stateRoot, backup) {
  for (const [target, bytes] of backup) {
    if (bytes === null) await removeStateFile(stateRoot, target).catch(() => {});
    else await atomicWriteFile(stateRoot, target, bytes).catch(() => {});
  }
}

function normalizeDigest(value) {
  return String(value).toLowerCase().replace(/^sha256:/, "");
}

function actionResult(type) {
  return ({
    "verify-artifact": "verified",
    "configure-engine": "applied",
    "pull-model-by-digest": "verified-present",
    "apply-editorial-policy": "applied",
    "self-test": "passed",
  })[type];
}
