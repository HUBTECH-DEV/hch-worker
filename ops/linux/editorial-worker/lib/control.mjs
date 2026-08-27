import { canonicalizeJson, workerPublicKeyFingerprint } from "../crypto.mjs";
import { verifyInstalledArtifacts } from "./apply.mjs";
import {
  capacityPolicyHash,
  capacityStatus,
  effectiveRequestedCapacity,
  readWorkerControl,
  validateCapacityPolicy,
  validateRequestedCapacity,
  writeWorkerControl,
} from "./capacity.mjs";
import { ensureWorkerIdentity } from "./identity.mjs";
import { queryLocalModel } from "./http.mjs";
import { assertLocalModel } from "./manifest.mjs";
import { verifyRuntimeProfile } from "./runtime-profile.mjs";
import {
  ensurePrivateDirectory,
  readJson,
  readOptionalJson,
  readSafeText,
  withWorkerLock,
} from "./storage.mjs";
import { WorkerKitError } from "./errors.mjs";
import { adaptiveWorkPolicyHash, validateAdaptiveWorkPolicy } from "./adaptive-work.mjs";
import { KIT_VERSION } from "./local-state.mjs";

export async function configureLocalWorker(config) {
  return withWorkerLock(config.stateDirectory, async (stateRoot) => {
    const identity = await ensureWorkerIdentity(config, stateRoot);
    const control = await writeWorkerControl(stateRoot, config, {
      requestedCapacity: 0,
      acceptingClaims: false,
      updatedBy: "configure",
    });
    return {
      configured: true,
      nodeId: config.nodeId,
      workerKeyId: identity.keyId,
      fingerprint: identity.fingerprint,
      acceptingClaims: false,
      requestedCapacity: 0,
      resumeCapacity: control.lastNonZeroCapacity,
    };
  });
}

export async function validateLocalWorker(config, options = {}) {
  const stateRoot = await ensurePrivateDirectory(config.stateDirectory);
  const [
    identity,
    applied,
    ready,
    status,
    trustState,
    engineConfig,
    capacitySnapshot,
    control,
    rootPublicKeyPem,
  ] = await Promise.all([
    ensureWorkerIdentity(config, stateRoot),
    readJson(stateRoot, "applied-manifest.json"),
    readJson(stateRoot, "ready.json"),
    readJson(stateRoot, "status.json"),
    readJson(stateRoot, "trust-state.json"),
    readJson(stateRoot, "runtime/config/engine.json"),
    readJson(stateRoot, "capacity.json"),
    readWorkerControl(stateRoot, config),
    readSafeText(config.rootPublicKeyPath),
  ]);
  const policy = validateCapacityPolicy(applied.capacityPolicy);
  const policyHash = await capacityPolicyHash(policy);
  const adaptiveWorkPolicy = validateAdaptiveWorkPolicy(applied.adaptiveWorkPolicy);
  const signedAdaptiveWorkPolicyHash = await adaptiveWorkPolicyHash(adaptiveWorkPolicy);
  const runtimeProfile = await verifyRuntimeProfile(applied.runtimeProfile, {
    ...appliedManifestView(applied),
    capacityPolicy: policy,
  });
  const rootFingerprint = await workerPublicKeyFingerprint(rootPublicKeyPem);
  if (
    rootFingerprint !== config.rootPublicKeyFingerprint ||
    ready.ready !== true ||
    ready.nodeId !== config.nodeId ||
    ready.keyId !== config.keyId ||
    ready.manifestHash !== applied.manifestHash ||
    ready.workerRuntimeVersion !== KIT_VERSION ||
    applied.workerRuntimeVersion !== KIT_VERSION ||
    ready.manifestSequence !== applied.manifestSequence ||
    ready.policyHash !== applied.policyHash ||
    ready.runtimeProfileHash !== runtimeProfile.runtimeProfileHash ||
    ready.capacityPolicyHash !== policyHash ||
    ready.adaptiveWorkPolicyHash !== signedAdaptiveWorkPolicyHash ||
    applied.capacityPolicyHash !== policyHash ||
    applied.adaptiveWorkPolicyHash !== signedAdaptiveWorkPolicyHash ||
    engineConfig.capacityPolicyHash !== policyHash ||
    engineConfig.adaptiveWorkPolicyHash !== signedAdaptiveWorkPolicyHash ||
    capacitySnapshot.capacityPolicyHash !== policyHash ||
    capacitySnapshot.manifestHash !== applied.manifestHash ||
    capacitySnapshot.manifestSequence !== applied.manifestSequence ||
    trustState.manifestHash !== applied.manifestHash ||
    trustState.manifestSequence !== applied.manifestSequence ||
    trustState.policyHash !== applied.policyHash ||
    status.ready !== true ||
    status.manifestHash !== applied.manifestHash ||
    status.manifestSequence !== applied.manifestSequence ||
    !Number.isFinite(Date.parse(ready.readyUntil)) ||
    Date.parse(ready.readyUntil) <= Date.now()
  ) {
    throw new WorkerKitError(
      "worker-local-validation-failed",
      "Local ready, trust, runtime, or signed capacity state is inconsistent.",
    );
  }
  if (
    canonicalizeJson(validateCapacityPolicy(engineConfig.capacityPolicy)) !== canonicalizeJson(policy) ||
    canonicalizeJson(validateAdaptiveWorkPolicy(engineConfig.adaptiveWorkPolicy)) !==
      canonicalizeJson(adaptiveWorkPolicy) ||
    identity.nodeId !== config.nodeId ||
    identity.keyId !== config.keyId
  ) {
    throw new WorkerKitError(
      "worker-local-validation-failed",
      "Installed capacity policy or worker identity is inconsistent.",
    );
  }
  await verifyInstalledArtifacts(stateRoot, appliedManifestView(applied));
  if (options.checkLocalEngine !== false) {
    const engine = await queryLocalModel(config, options);
    assertLocalModel(engine.payload, appliedManifestView(applied));
  }
  return {
    valid: true,
    nodeId: config.nodeId,
    workerKeyId: config.keyId,
    manifestSequence: applied.manifestSequence,
    manifestHash: applied.manifestHash,
    policyHash: applied.policyHash,
    capacityPolicyHash: policyHash,
    adaptiveWorkPolicyHash: signedAdaptiveWorkPolicyHash,
    requestedCapacity: effectiveRequestedCapacity(control),
    readyUntil: new Date(ready.readyUntil).toISOString(),
    reservationAttempted: false,
  };
}

export async function startLocalWorker(config, options = {}) {
  await validateLocalWorker(config, options);
  const stateRoot = await ensurePrivateDirectory(config.stateDirectory);
  const control = await readWorkerControl(stateRoot, config);
  const requestedCapacity = control.requestedCapacity > 0
    ? control.requestedCapacity
    : control.lastNonZeroCapacity;
  const updated = await writeWorkerControl(stateRoot, config, {
    requestedCapacity,
    acceptingClaims: true,
    updatedBy: "start",
  });
  return {
    started: true,
    requestedCapacity: effectiveRequestedCapacity(updated),
    acceptingClaims: true,
  };
}

export async function pauseLocalWorker(config) {
  const stateRoot = await ensurePrivateDirectory(config.stateDirectory);
  const previous = await readWorkerControl(stateRoot, config);
  const updated = await writeWorkerControl(stateRoot, config, {
    requestedCapacity: 0,
    acceptingClaims: false,
    updatedBy: "pause",
  });
  return {
    paused: true,
    draining: true,
    priorCapacity: effectiveRequestedCapacity(previous),
    resumeCapacity: updated.lastNonZeroCapacity,
  };
}

export async function stopLocalWorker(config) {
  const stateRoot = await ensurePrivateDirectory(config.stateDirectory);
  const previous = await readWorkerControl(stateRoot, config);
  const updated = await writeWorkerControl(stateRoot, config, {
    requestedCapacity: 0,
    acceptingClaims: false,
    updatedBy: "stop",
  });
  return {
    stopRequested: true,
    activeAssignmentsWillBeCancelled: true,
    cancellationErrorCode: "operator-stop-requested",
    priorCapacity: effectiveRequestedCapacity(previous),
    resumeCapacity: updated.lastNonZeroCapacity,
  };
}

export async function setLocalParallelism(config, parallelism) {
  const requestedCapacity = validateRequestedCapacity(parallelism);
  const stateRoot = await ensurePrivateDirectory(config.stateDirectory);
  const previous = await readWorkerControl(stateRoot, config);
  const updated = await writeWorkerControl(stateRoot, config, {
    requestedCapacity,
    acceptingClaims: requestedCapacity > 0 && previous.acceptingClaims,
    updatedBy: requestedCapacity === 0 ? "pause" : "set-parallelism",
  });
  return {
    requestedParallelism: updated.requestedCapacity,
    effectiveParallelism: effectiveRequestedCapacity(updated),
    acceptingClaims: updated.acceptingClaims,
    drainRequested: updated.drainRequested,
    serverGrantNegotiatedOnNextCycle: true,
  };
}

export async function localWorkerStatus(config, systemd = {}) {
  const stateRoot = await ensurePrivateDirectory(config.stateDirectory);
  const [control, status, ready, capacity] = await Promise.all([
    readWorkerControl(stateRoot, config),
    readOptionalJson(stateRoot, "status.json"),
    readOptionalJson(stateRoot, "ready.json"),
    readOptionalJson(stateRoot, "capacity.json"),
  ]);
  const requestedCapacity = effectiveRequestedCapacity(control);
  return {
    nodeId: config.nodeId,
    workerKeyId: config.keyId,
    control,
    effectiveParallelism: requestedCapacity,
    capacity: capacityStatus(capacity, requestedCapacity),
    ready,
    worker: status,
    systemd: {
      timerEnabled: systemd.timerEnabled ?? null,
      timerActive: systemd.timerActive ?? null,
      serviceActive: systemd.serviceActive ?? null,
    },
  };
}

function appliedManifestView(applied) {
  if (!applied || typeof applied !== "object") {
    throw new WorkerKitError("applied-state-invalid", "Applied manifest state is missing.");
  }
  return {
    sequence: applied.manifestSequence,
    hash: applied.manifestHash,
    engine: {
      provider: applied.provider,
      adapter: applied.engineAdapter,
      adapterVersion: applied.engineAdapterVersion,
      model: applied.model,
      modelDigest: applied.modelDigest,
      protocol: applied.protocol,
    },
    generation: applied.runtimeProfile && {
      temperature: applied.runtimeProfile.temperature,
      contextWindow: applied.runtimeProfile.contextWindow,
      maxOutputTokens: applied.runtimeProfile.maxOutputTokens,
    },
    editorial: {
      policyId: applied.runtimeProfile?.policyId,
      policyVersion: applied.runtimeProfile?.policyVersion,
      policyHash: applied.policyHash,
      promptConfigHash: applied.promptConfigHash,
      pipelineVersion: applied.pipelineVersion,
    },
    artifacts: applied.artifacts,
    adaptiveWorkPolicy: applied.adaptiveWorkPolicy,
  };
}
