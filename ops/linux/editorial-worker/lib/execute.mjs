import { canonicalizeJson } from "../crypto.mjs";
import { ensureWorkerIdentity } from "./identity.mjs";
import {
  createTrafficCounter,
  fetchSignedManifest,
  signedPost,
} from "./http.mjs";
import {
  trustStateFromManifestVerification,
  verifyManifestResponse,
} from "./manifest.mjs";
import { verifyRuntimeProfile } from "./runtime-profile.mjs";
import {
  capacityPolicyHash,
  effectiveRequestedCapacity,
  persistCapacityGrant,
  readWorkerControl,
  validateCapacityDecision,
  validateCapacityPolicy,
} from "./capacity.mjs";
import { validateOrchestrationSnapshot } from "./node-heartbeat.mjs";
import {
  completeOperation,
  enterStandby,
  KIT_VERSION,
  operationRequestId,
  recordDuration,
  recordNetwork,
  leaveStandby,
  updateMetrics,
  updateStatus,
} from "./local-state.mjs";
import {
  atomicWriteJson,
  readJson,
  readSafeText,
  withWorkerLock,
} from "./storage.mjs";
import { WorkerKitError, errorCode } from "./errors.mjs";

export async function executeWorkerCycle(config, options = {}) {
  if (config.nodeId !== "vps-primary") {
    throw new WorkerKitError(
      "execute-node-refused",
      "The /execute adapter is reserved for node vps-primary.",
    );
  }
  return withWorkerLock(config.stateDirectory, async (stateRoot) => {
    const startedAt = Date.now();
    const cpuStarted = process.cpuUsage();
    const traffic = createTrafficCounter();
    let executionAttempted = false;
    try {
      const [
        identity,
        applied,
        ready,
        status,
        rootPublicKeyPem,
        trustState,
        engineConfig,
        control,
        orchestrationValue,
      ] = await Promise.all([
        ensureWorkerIdentity(config, stateRoot),
        readJson(stateRoot, "applied-manifest.json"),
        readJson(stateRoot, "ready.json"),
        readJson(stateRoot, "status.json"),
        readSafeText(config.rootPublicKeyPath),
        readJson(stateRoot, "trust-state.json"),
        readJson(stateRoot, "runtime/config/engine.json"),
        readWorkerControl(stateRoot, config),
        readJson(stateRoot, "orchestration.json"),
      ]);
      assertReadyGate(config, applied, ready, status);
      const orchestration = validateOrchestrationSnapshot(orchestrationValue, {
        expectedNodeId: config.nodeId,
      });
      const heartbeatAgeMilliseconds = Date.now() - Date.parse(
        orchestration.heartbeat.lastSuccessAt ?? "",
      );
      if (
        orchestration.heartbeat.status !== "succeeded" ||
        !Number.isFinite(heartbeatAgeMilliseconds) ||
        heartbeatAgeMilliseconds < -30_000 ||
        heartbeatAgeMilliseconds > 90_000
      ) {
        throw new WorkerKitError(
          "execute-node-heartbeat-stale",
          "A recent successful node heartbeat is required before execute.",
        );
      }
      const envelope = await fetchSignedManifest(config, { ...options, traffic });
      const current = await verifyManifestResponse(
        envelope,
        config,
        rootPublicKeyPem,
        applied,
        { ...options, trustState },
      );
      const verifiedTrustState = trustStateFromManifestVerification(current);
      if (
        trustState.delegationSequence !== current.delegationSequence ||
        trustState.delegationHash !== current.delegationHash ||
        trustState.manifestSequence !== current.manifest.sequence ||
        trustState.manifestHash !== current.manifest.hash ||
        trustState.policyHash !== current.manifest.editorial.policyHash
      ) {
        await atomicWriteJson(
          stateRoot,
          "trust-state.json",
          verifiedTrustState,
        );
      }
      if (
        current.manifest.hash !== applied.manifestHash ||
        current.manifest.sequence !== applied.manifestSequence
      ) {
        await atomicWriteJson(stateRoot, "ready.json", {
          schemaVersion: 1,
          ready: false,
          nodeId: config.nodeId,
          keyId: config.keyId,
          targetManifestHash: current.manifest.hash,
          invalidatedAt: new Date().toISOString(),
          reason: "manifest-update-required",
        });
        throw new WorkerKitError(
          "update-required",
          "The canonical manifest changed; bootstrap is required before execute.",
        );
      }
      const runtimeProfile = await verifyRuntimeProfile(
        applied.runtimeProfile,
        current.manifest,
      );
      if (applied.runtimeProfileHash !== runtimeProfile.runtimeProfileHash) {
        throw new WorkerKitError(
          "runtime-profile-state-mismatch",
          "The applied RuntimeProfile v2 hash is inconsistent.",
        );
      }
      const signedCapacityPolicy = validateCapacityPolicy(current.manifest.capacityPolicy);
      const signedCapacityPolicyHash = await capacityPolicyHash(signedCapacityPolicy);
      assertInstalledRuntimeProfile(
        engineConfig,
        runtimeProfile,
        current.manifest,
        signedCapacityPolicy,
        signedCapacityPolicyHash,
        applied,
        ready,
      );
      const requestedCapacity = effectiveRequestedCapacity(control);
      if (requestedCapacity !== orchestration.capacity.requestedCapacity) {
        throw new WorkerKitError(
          "execute-heartbeat-capacity-mismatch",
          "Local operator control changed after the last node heartbeat.",
        );
      }
      if (
        requestedCapacity === 0 ||
        orchestration.capacity.grantedCapacity === 0 ||
        orchestration.capacity.availableSlots === 0 ||
        orchestration.claim.allowed !== true ||
        orchestration.claim.recommendedCount < 1
      ) {
        await updateStatus(stateRoot, config, {
          state: requestedCapacity === 0 ? "draining" : "standby",
          running: false,
          standby: true,
          code: requestedCapacity === 0
            ? "heartbeat-only-capacity-zero"
            : "heartbeat-no-claim-recommended",
          currentBatch: null,
        });
        await updateMetrics(stateRoot, config, (metrics) => {
          metrics.jobs.running = 0;
          metrics.currentBatch = null;
          enterStandby(metrics);
        });
        return {
          protocol: "central-orchestrator-v2",
          nodeId: config.nodeId,
          requestId: null,
          claimed: 0,
          capacity: orchestration.capacity,
          results: [],
          heartbeatOnly: true,
        };
      }
      const bodyText = canonicalizeJson({});
      const operation = await operationRequestId(stateRoot, "execute", bodyText);
      await updateStatus(stateRoot, config, {
        state: requestedCapacity === 0 ? "draining" : "processing",
        running: requestedCapacity > 0,
        standby: requestedCapacity === 0,
        code: requestedCapacity === 0 ? "drain-negotiation-started" : "execute-started",
        transport: {
          tlsStatus: "verified",
          certificateStatus: "valid",
          certificateExpiresAt: null,
          certificateFingerprint: null,
          errorCode: null,
        },
        trust: {
          status: "verified",
          rootKeyId: current.rootKeyId,
          releaseKeyId: current.releaseKeyId,
          manifestSequence: current.manifest.sequence,
          manifestHash: current.manifest.hash,
          policyHash: current.manifest.editorial.policyHash,
          lastVerifiedAt: new Date().toISOString(),
          errorCode: null,
        },
      });
      await updateMetrics(stateRoot, config, (metrics) => {
        metrics.jobs.running = 0;
        leaveStandby(metrics);
      });
      executionAttempted = true;
      const response = await signedPost(config, identity, {
        path: "/api/editorial/orchestrator/execute",
        purpose: "execute",
        bodyText,
        requestId: operation.requestId,
      }, {
        ...options,
        traffic,
        operationTimeoutMilliseconds: config.executeRequestTimeoutMilliseconds,
      });
      const capacityDecision = validateExecuteResponse(
        response,
        config,
        operation.requestId,
        {
          policy: signedCapacityPolicy,
          requestedCapacity: orchestration.capacity.requestedCapacity,
          nodeId: config.nodeId,
          platform: "linux",
          now: options.now,
        },
      );
      await completeOperation(stateRoot, operation.operationKey);
      await persistCapacityGrant(stateRoot, config, capacityDecision, {
        manifest: current.manifest,
        policy: signedCapacityPolicy,
        source: "execute",
      });
      const failedJobs = response.results.filter((result) =>
        result?.status === "failed-attempt" || result?.error,
      ).length;
      const successfulJobs = Math.max(0, response.results.length - failedJobs);
      await updateMetrics(stateRoot, config, (metrics) => {
        metrics.batches.total += 1;
        if (failedJobs) metrics.batches.failed += 1;
        else metrics.batches.completed += 1;
        metrics.jobs.claimed += response.claimed;
        metrics.jobs.completed += successfulJobs;
        metrics.jobs.failed += failedJobs;
        metrics.jobs.running = 0;
        metrics.currentBatch = null;
        recordNetwork(metrics, traffic);
        recordDuration(metrics, Date.now() - startedAt, {
          cpuStarted,
          items: response.claimed,
        });
        enterStandby(metrics);
      });
      await updateStatus(stateRoot, config, {
        state: requestedCapacity === 0 ? "draining" : "standby",
        running: false,
        standby: true,
        code: requestedCapacity === 0 ? "drain-confirmed" : "execute-complete",
        currentBatch: null,
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
      });
      return {
        protocol: response.protocol,
        nodeId: response.nodeId,
        requestId: response.requestId,
        claimed: response.claimed,
        capacity: capacityDecision,
        results: response.results.map((result) => ({
          assignmentId: result.assignmentId,
          status: result.status,
        })),
      };
    } catch (error) {
      const code = errorCode(error, "execute-failed");
      await updateMetrics(stateRoot, config, (metrics) => {
        if (executionAttempted) {
          metrics.batches.total += 1;
          metrics.batches.failed += 1;
        }
        metrics.jobs.running = 0;
        metrics.currentBatch = null;
        recordNetwork(metrics, traffic);
        recordDuration(metrics, Date.now() - startedAt, { cpuStarted });
      }).catch(() => {});
      await updateStatus(stateRoot, config, {
        state: code === "update-required"
          ? "update-required"
          : code === "worker-not-ready"
            ? "bootstrap-required"
            : "connection-error",
        running: false,
        standby: false,
        ready: false,
        readyUntil: null,
        code,
        currentBatch: null,
        connection: {
          ...(executionAttempted ? { api: "error" } : {}),
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
        ...(code === "update-required" ? {
          trust: { status: "error", errorCode: code },
        } : {}),
      }).catch(() => {});
      throw error;
    }
  });
}

function assertReadyGate(config, applied, ready, status) {
  if (
    applied?.schemaVersion !== 1 ||
    ready?.schemaVersion !== 1 ||
    ready.ready !== true ||
    ready.nodeId !== config.nodeId ||
    ready.keyId !== config.keyId ||
    ready.manifestHash !== applied.manifestHash ||
    ready.workerRuntimeVersion !== KIT_VERSION ||
    applied.workerRuntimeVersion !== KIT_VERSION ||
    ready.manifestSequence !== applied.manifestSequence ||
    ready.contentContractHash !== applied.contentContractHash ||
    ready.policyHash !== applied.policyHash ||
    ready.provider !== applied.provider ||
    ready.engineAdapter !== applied.engineAdapter ||
    ready.engineAdapterVersion !== applied.engineAdapterVersion ||
    ready.runtimeProfileHash !== applied.runtimeProfileHash ||
    applied.runtimeProfile?.provider !== applied.provider ||
    applied.runtimeProfile?.engineAdapter !== applied.engineAdapter ||
    applied.runtimeProfile?.engineAdapterVersion !== applied.engineAdapterVersion ||
    applied.runtimeProfile?.runtimeProfileHash !== applied.runtimeProfileHash ||
    status?.ready !== true ||
    !new Set(["idle", "standby", "draining"]).has(status?.state) ||
    status?.manifestHash !== applied.manifestHash ||
    status?.manifestSequence !== applied.manifestSequence ||
    status?.contentContractHash !== applied.contentContractHash ||
    status?.readyUntil !== ready.readyUntil ||
    status?.connection?.api !== "connected" ||
    status?.connection?.tls !== "verified" ||
    status?.connection?.auth !== "ed25519" ||
    status?.connection?.ed25519 !== true ||
    status?.transport?.tlsStatus !== "verified" ||
    status?.transport?.certificateStatus !== "valid" ||
    status?.trust?.status !== "verified" ||
    status?.trust?.manifestHash !== applied.manifestHash ||
    status?.trust?.manifestSequence !== applied.manifestSequence ||
    status?.trust?.contentContractHash !== applied.contentContractHash ||
    status?.trust?.policyHash !== applied.policyHash ||
    !Number.isFinite(Date.parse(ready.readyUntil)) ||
    Date.parse(ready.readyUntil) <= Date.now()
  ) {
    throw new WorkerKitError(
      "worker-not-ready",
      "ready.json and applied-manifest.json do not authorize execute.",
    );
  }
}

function assertInstalledRuntimeProfile(
  engineConfig,
  runtimeProfile,
  manifest,
  capacityPolicy,
  expectedCapacityPolicyHash,
  applied,
  ready,
) {
  if (
    engineConfig?.schemaVersion !== 1 ||
    engineConfig.provider !== runtimeProfile.provider ||
    engineConfig.adapter !== runtimeProfile.engineAdapter ||
    engineConfig.adapterVersion !== runtimeProfile.engineAdapterVersion ||
    engineConfig.model !== runtimeProfile.model ||
    normalizeDigest(engineConfig.modelDigest) !== normalizeDigest(runtimeProfile.modelDigest) ||
    engineConfig.protocol !== runtimeProfile.protocol ||
    engineConfig.sourceManifestHash !== manifest.hash ||
    canonicalizeJson(validateCapacityPolicy(engineConfig.capacityPolicy)) !==
      canonicalizeJson(capacityPolicy) ||
    engineConfig.capacityPolicyHash !== expectedCapacityPolicyHash ||
    applied.capacityPolicyHash !== expectedCapacityPolicyHash ||
    ready.capacityPolicyHash !== expectedCapacityPolicyHash
  ) {
    throw new WorkerKitError(
      "runtime-profile-installation-mismatch",
      "The installed engine configuration does not match RuntimeProfile v2.",
    );
  }
}

function validateExecuteResponse(response, config, requestId, capacityContext) {
  const capacity = validateCapacityDecision(response?.capacity, capacityContext);
  if (
    response?.protocol !== "central-orchestrator-v2" ||
    response?.nodeId !== config.nodeId ||
    response?.workerKeyId !== config.keyId ||
    response?.requestId !== requestId ||
    !Number.isSafeInteger(response?.claimed) ||
    response.claimed < 0 ||
    response.claimed > capacity.availableSlots ||
    !Array.isArray(response?.results) ||
    response.results.length !== response.claimed ||
    response.results.some((result) =>
      !result ||
      typeof result !== "object" ||
      typeof result.assignmentId !== "string" ||
      !result.assignmentId ||
      typeof result.status !== "string" ||
      !result.status
    ) ||
    new Set(response.results.map((result) => result.assignmentId)).size !==
      response.results.length
  ) {
    throw new WorkerKitError("execute-response-invalid", "The execute response is incompatible.");
  }
  if (
    capacity.requestedCapacity === 0 &&
    (response.claimed !== 0 || response.results.length !== 0 || capacity.grantedCapacity !== 0)
  ) {
    throw new WorkerKitError("execute-drain-violated", "Drain response attempted to assign work.");
  }
  return capacity;
}

function normalizeDigest(value) {
  return String(value ?? "").toLowerCase().replace(/^sha256:/, "");
}
