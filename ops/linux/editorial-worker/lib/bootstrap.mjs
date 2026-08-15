import { hostname } from "node:os";
import { isAbsolute } from "node:path";

import { canonicalizeJson, sha256Hex } from "../crypto.mjs";
import { ensureWorkerIdentity } from "./identity.mjs";
import {
  createTrafficCounter,
  enrollWorker,
  fetchSignedManifest,
  signedPost,
} from "./http.mjs";
import {
  trustStateFromManifestVerification,
  verifyManifestResponse,
} from "./manifest.mjs";
import {
  capacityPolicyHash,
  effectiveRequestedCapacity,
  persistCapacityGrant,
  readWorkerControl,
  validateAttestedCapacityGrant,
  validateCapacityPolicy,
} from "./capacity.mjs";
import { stageApplyAndSelfTest } from "./apply.mjs";
import {
  completeOperation,
  enterStandby,
  operationRequestId,
  recordDuration,
  recordNetwork,
  leaveStandby,
  updateMetrics,
  updateStatus,
} from "./local-state.mjs";
import {
  atomicWriteJson,
  readOptionalJson,
  readPrivateText,
  readSafeText,
  withWorkerLock,
} from "./storage.mjs";
import { WorkerKitError, errorCode } from "./errors.mjs";
import { workerPlatform } from "./platform.mjs";
import {
  adaptiveWorkPolicyHash,
  validateAdaptiveWorkPolicy,
} from "./adaptive-work.mjs";

export async function bootstrapWorker(config, options = {}) {
  return withWorkerLock(config.stateDirectory, (stateRoot) =>
    bootstrapWorkerLocked(config, stateRoot, options));
}

// Used only by the long-lived supervisor, which already owns the worker lock.
export async function bootstrapWorkerLocked(config, stateRoot, options = {}) {
    const startedAt = Date.now();
    const cpuStarted = process.cpuUsage();
    const traffic = createTrafficCounter();
    await updateStatus(stateRoot, config, {
      state: "updating",
      running: false,
      standby: false,
      ready: false,
      code: "bootstrap-started",
    });
    await updateMetrics(stateRoot, config, (metrics) => {
      metrics.updates.attempts += 1;
      leaveStandby(metrics);
    });
    try {
      const identity = await ensureWorkerIdentity(config, stateRoot);
      const control = await readWorkerControl(stateRoot, config);
      const requestedCapacity = effectiveRequestedCapacity(control);
      if (options.enroll) {
        const token = await resolveEnrollmentToken(config, options);
        const enrollment = await enrollWorker(config, identity, token, {
          ...options,
          traffic,
        });
        if (
          enrollment?.nodeId !== identity.nodeId ||
          enrollment?.keyId !== identity.keyId ||
          enrollment?.fingerprint !== identity.fingerprint ||
          enrollment?.status !== "active" ||
          !Number.isFinite(Date.parse(enrollment?.enrolledAt))
        ) {
          throw new WorkerKitError(
            "enrollment-response-invalid",
            "Enrollment response does not match the local identity.",
          );
        }
        await atomicWriteJson(stateRoot, "enrolled.json", {
          schemaVersion: 1,
          nodeId: identity.nodeId,
          keyId: identity.keyId,
          fingerprint: identity.fingerprint,
          status: enrollment.status,
          enrolledAt: enrollment.enrolledAt,
        });
      }

      const [rootPublicKeyPem, previousApplied, previousTrustState] = await Promise.all([
        readSafeText(config.rootPublicKeyPath),
        readOptionalJson(stateRoot, "applied-manifest.json"),
        readOptionalJson(stateRoot, "trust-state.json"),
      ]);
      const publishedEnvelope = await fetchSignedManifest(config, {
        ...options,
        traffic,
      });
      await updateStatus(stateRoot, config, {
        state: "updating",
        connection: {
          api: "connected",
          tls: "verified",
          lastSuccessAt: new Date().toISOString(),
          lastErrorCode: null,
        },
        transport: {
          tlsStatus: "verified",
          certificateStatus: "valid",
          certificateExpiresAt: null,
          certificateFingerprint: null,
          errorCode: null,
        },
      });
      const published = await verifyManifestResponse(
        publishedEnvelope,
        config,
        rootPublicKeyPem,
        previousApplied,
        { ...options, trustState: previousTrustState },
      );
      let pinnedTrustState = trustStateFromManifestVerification(published);
      await atomicWriteJson(stateRoot, "trust-state.json", pinnedTrustState);
      if (previousApplied?.manifestHash !== published.manifest.hash) {
        await atomicWriteJson(stateRoot, "ready.json", {
          schemaVersion: 1,
          ready: false,
          nodeId: config.nodeId,
          keyId: config.keyId,
          targetManifestHash: published.manifest.hash,
          invalidatedAt: new Date().toISOString(),
          reason: "manifest-update-required",
        });
      }

      const bootstrapBody = {
        nodeId: config.nodeId,
        workerKeyId: config.keyId,
        platform: workerPlatform(),
        architecture: process.arch,
        hostname: hostname(),
        requestedCapacity,
      };
      const bootstrapBodyText = canonicalizeJson(bootstrapBody);
      const bootstrapBodyHash = await sha256Hex(bootstrapBodyText);
      const bootstrapOperation = await operationRequestId(
        stateRoot,
        `bootstrap:${published.manifest.hash}:${bootstrapBodyHash}`,
        bootstrapBodyText,
      );
      const bootstrap = await signedPost(config, identity, {
        path: "/api/editorial/orchestrator/bootstrap",
        purpose: "bootstrap",
        bodyText: bootstrapBodyText,
        requestId: bootstrapOperation.requestId,
      }, { ...options, traffic });
      validateBootstrapResponse(bootstrap, published.manifest, requestedCapacity);
      const sessionManifest = await verifyManifestResponse(
        bootstrap.manifest,
        config,
        rootPublicKeyPem,
        previousApplied,
        {
          ...options,
          trustState: pinnedTrustState,
        },
      );
      pinnedTrustState = trustStateFromManifestVerification(sessionManifest);
      await atomicWriteJson(stateRoot, "trust-state.json", pinnedTrustState);
      if (sessionManifest.manifest.hash !== published.manifest.hash) {
        throw new WorkerKitError(
          "bootstrap-manifest-changed",
          "Bootstrap returned a manifest different from the one requested.",
        );
      }
      const acceptedTrust = sessionManifest;
      await completeOperation(stateRoot, bootstrapOperation.operationKey);
      const adaptiveWorkPolicy = validateAdaptiveWorkPolicy(
        published.manifest.adaptiveWorkPolicy,
      );
      const signedAdaptiveWorkPolicyHash = await adaptiveWorkPolicyHash(
        adaptiveWorkPolicy,
      );

      await updateStatus(stateRoot, config, {
        state: "updating",
        manifestSequence: published.manifest.sequence,
        manifestHash: published.manifest.hash,
        code: "applying-manifest",
        connection: {
          api: "connected",
          tls: "verified",
          auth: "ed25519",
          ed25519: true,
          lastSuccessAt: new Date().toISOString(),
          lastErrorCode: null,
        },
        transport: {
          tlsStatus: "verified",
          certificateStatus: "valid",
          certificateExpiresAt: null,
          certificateFingerprint: null,
          errorCode: null,
        },
        trust: {
          status: "verified",
          rootKeyId: acceptedTrust.rootKeyId,
          releaseKeyId: acceptedTrust.releaseKeyId,
          manifestSequence: published.manifest.sequence,
          manifestHash: published.manifest.hash,
          policyHash: published.manifest.editorial.policyHash,
          lastVerifiedAt: new Date().toISOString(),
          errorCode: null,
        },
      });
      const applied = await stageApplyAndSelfTest(
        config,
        stateRoot,
        published.manifest,
        previousApplied,
        { ...options, traffic },
      );

      const attestationBody = {
        nodeId: config.nodeId,
        workerKeyId: config.keyId,
        manifestSequence: published.manifest.sequence,
        manifestHash: published.manifest.hash,
        challenge: bootstrap.challenge,
        workerRuntimeVersion: published.manifest.runtime.workerVersion,
        policyHash: published.manifest.editorial.policyHash,
        adaptiveWorkPolicyHash: signedAdaptiveWorkPolicyHash,
        rootKeyId: acceptedTrust.rootKeyId,
        releaseKeyId: acceptedTrust.releaseKeyId,
        trustVerifiedAt: new Date().toISOString(),
        promptConfigHash: published.manifest.editorial.promptConfigHash,
        pipelineVersion: published.manifest.editorial.pipelineVersion,
        model: published.manifest.engine.model,
        modelDigest: normalizeDigest(published.manifest.engine.modelDigest),
        protocol: published.manifest.engine.protocol,
        provider: applied.runtimeProfile.provider,
        engineAdapter: applied.runtimeProfile.engineAdapter,
        engineAdapterVersion: applied.runtimeProfile.engineAdapterVersion,
        checks: applied.checks,
        updateReceipt: applied.updateReceipt,
      };
      const attestationBodyText = canonicalizeJson(attestationBody);
      const attestationBodyHash = await sha256Hex(attestationBodyText);
      const attestOperation = await operationRequestId(
        stateRoot,
        `attest:${bootstrap.bootstrapSessionId}:${attestationBodyHash}`,
        attestationBodyText,
      );
      const attested = await signedPost(config, identity, {
        path: `/api/editorial/orchestrator/bootstrap/${bootstrap.bootstrapSessionId}/attest`,
        purpose: "attest",
        bodyText: attestationBodyText,
        requestId: attestOperation.requestId,
      }, { ...options, traffic });
      const capacityGrant = validateAttestation(
        attested,
        published.manifest,
        config,
        requestedCapacity,
        options.now,
      );
      await completeOperation(stateRoot, attestOperation.operationKey);
      const capacity = await persistCapacityGrant(
        stateRoot,
        config,
        { ...capacityGrant, pressure: {}, activeAssignments: 0 },
        {
          manifest: published.manifest,
          policy: published.manifest.capacityPolicy,
          source: "attestation",
        },
      );
      const trustVerifiedAt = new Date().toISOString();
      const readyState = {
        schemaVersion: 1,
        ready: true,
        nodeId: config.nodeId,
        keyId: config.keyId,
        manifestSequence: published.manifest.sequence,
        manifestHash: published.manifest.hash,
        policyHash: published.manifest.editorial.policyHash,
        provider: applied.runtimeProfile.provider,
        engineAdapter: applied.runtimeProfile.engineAdapter,
        engineAdapterVersion: applied.runtimeProfile.engineAdapterVersion,
        runtimeProfileHash: applied.runtimeProfile.runtimeProfileHash,
        capacityPolicyHash: await capacityPolicyHash(published.manifest.capacityPolicy),
        adaptiveWorkPolicyHash: signedAdaptiveWorkPolicyHash,
        requestedCapacity: capacity.requestedCapacity,
        grantedCapacity: capacity.grantedCapacity,
        capacityClass: capacity.capacityClass,
        capacityReason: capacity.reason,
        capacityGrantedUntil: capacity.grantedUntil,
        bootstrapSessionId: bootstrap.bootstrapSessionId,
        readyUntil: new Date(attested.readyUntil).toISOString(),
        attestedAt: new Date().toISOString(),
        trustVerifiedAt,
      };
      await atomicWriteJson(stateRoot, "ready.json", readyState);
      await updateStatus(stateRoot, config, {
        state: requestedCapacity === 0 ? "draining" : "standby",
        running: false,
        standby: true,
        ready: true,
        readyUntil: readyState.readyUntil,
        manifestSequence: readyState.manifestSequence,
        manifestHash: readyState.manifestHash,
        code: requestedCapacity === 0 ? "drain-requested" : "ready",
        trust: {
          status: "verified",
          rootKeyId: acceptedTrust.rootKeyId,
          releaseKeyId: acceptedTrust.releaseKeyId,
          manifestSequence: published.manifest.sequence,
          manifestHash: published.manifest.hash,
          policyHash: published.manifest.editorial.policyHash,
          lastVerifiedAt: readyState.trustVerifiedAt,
          errorCode: null,
        },
      });
      await updateMetrics(stateRoot, config, (metrics) => {
        metrics.updates.succeeded += 1;
        recordNetwork(metrics, traffic);
        recordDuration(metrics, Date.now() - startedAt, { cpuStarted });
        enterStandby(metrics);
      });
      return {
        nodeId: config.nodeId,
        keyId: config.keyId,
        state: requestedCapacity === 0 ? "draining" : "ready",
        manifestSequence: readyState.manifestSequence,
        manifestHash: readyState.manifestHash,
        readyUntil: readyState.readyUntil,
        workStarted: false,
      };
    } catch (error) {
      const code = errorCode(error, "bootstrap-failed");
      await updateStatus(stateRoot, config, {
        state: "update-failed",
        running: false,
        standby: false,
        ready: false,
        readyUntil: null,
        code,
        connection: {
          api: "error",
          ...(code === "network-request-failed" ? { tls: "error" } : {}),
          lastFailureAt: new Date().toISOString(),
          lastErrorCode: code,
        },
        ...(code === "network-request-failed" ? {
          transport: {
            tlsStatus: "error",
            certificateStatus: "unverified",
            certificateExpiresAt: null,
            certificateFingerprint: null,
            errorCode: code,
          },
        } : {}),
        trust: {
          status: code === "manifest-expired" ? "expired" : "error",
          errorCode: code,
        },
      }).catch(() => {});
      await updateMetrics(stateRoot, config, (metrics) => {
        metrics.updates.failed += 1;
        recordNetwork(metrics, traffic);
        recordDuration(metrics, Date.now() - startedAt, { cpuStarted });
      }).catch(() => {});
      throw error;
    }
}

export async function resolveEnrollmentToken(config, options = {}) {
  if (options.enrollmentToken !== undefined) return options.enrollmentToken;
  const valueName = config.enrollmentTokenEnvironment;
  const fileName = `${valueName}_FILE`;
  const directValue = process.env[valueName];
  const credentialPath = process.env[fileName];
  delete process.env[valueName];
  delete process.env[fileName];
  if (directValue?.trim() && credentialPath?.trim()) {
    throw new WorkerKitError(
      "enrollment-token-source-ambiguous",
      `Set only one of ${valueName} or ${fileName}.`,
    );
  }
  if (directValue?.trim()) return directValue;
  if (!credentialPath?.trim()) return undefined;
  if (!isAbsolute(credentialPath.trim())) {
    throw new WorkerKitError(
      "enrollment-token-file-invalid",
      `${fileName} must name an absolute credential file.`,
    );
  }
  try {
    return await readPrivateText(credentialPath.trim(), 16 * 1024);
  } catch (error) {
    throw new WorkerKitError(
      "enrollment-token-file-invalid",
      "The enrollment credential file must be a private regular non-symlink file within the size limit.",
      { cause: error },
    );
  }
}

function validateBootstrapResponse(response, manifest, requestedCapacity) {
  const responsePolicy = validateCapacityPolicy(response?.capacityPolicy);
  if (
    typeof response?.bootstrapSessionId !== "string" ||
    !/^[A-Za-z0-9-]{16,160}$/.test(response.bootstrapSessionId) ||
    typeof response?.challenge !== "string" ||
    response.challenge.length < 16 ||
    response.manifestHash !== manifest.hash ||
    response.manifestSequence !== manifest.sequence ||
    response.state !== "awaiting-attestation" ||
    !Number.isFinite(Date.parse(response.expiresAt)) ||
    Date.parse(response.expiresAt) <= Date.now() ||
    response.attestationUrl !==
      `/api/editorial/orchestrator/bootstrap/${response.bootstrapSessionId}/attest` ||
    response.workEnabled !== false ||
    response.requestedCapacity !== requestedCapacity ||
    canonicalizeJson(responsePolicy) !== canonicalizeJson(manifest.capacityPolicy) ||
    canonicalizeJson(validateAdaptiveWorkPolicy(response?.adaptiveWorkPolicy)) !==
      canonicalizeJson(validateAdaptiveWorkPolicy(manifest.adaptiveWorkPolicy)) ||
    !response.manifest
  ) {
    throw new WorkerKitError("bootstrap-response-invalid", "Bootstrap response is incompatible.");
  }
}

function validateAttestation(response, manifest, config, requestedCapacity, now) {
  const expectedStates = requestedCapacity === 0
    ? new Set(["draining"])
    : new Set(["idle", "processing"]);
  if (
    response?.nodeId !== config.nodeId ||
    response?.workerKeyId !== config.keyId ||
    response?.compatible !== true ||
    response?.manifestSequence !== manifest.sequence ||
    response?.manifestHash !== manifest.hash ||
    !expectedStates.has(response?.state) ||
    !Number.isFinite(Date.parse(response?.serverTime)) ||
    !Number.isFinite(Date.parse(response?.readyUntil)) ||
    Date.parse(response.readyUntil) <= Date.now()
  ) {
    throw new WorkerKitError("attestation-response-invalid", "Attestation did not make the worker ready.");
  }
  return validateAttestedCapacityGrant(response.capacity, {
    policy: manifest.capacityPolicy,
    requestedCapacity,
    nodeId: config.nodeId,
    platform: "linux",
    serverTime: response.serverTime,
    now,
  });
}

function normalizeDigest(value) {
  return String(value).toLowerCase().replace(/^sha256:/, "");
}
