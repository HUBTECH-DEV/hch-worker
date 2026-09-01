import { nodeHeartbeat, NODE_HEARTBEAT_INTERVAL_SECONDS } from "./node-heartbeat.mjs";
import { ensureWorkerIdentity } from "./identity.mjs";
import { effectiveRequestedCapacity, readWorkerControl } from "./capacity.mjs";
import { createAssignmentProgress } from "./adaptive-work.mjs";
import {
  claimAssignments,
  completeAssignment,
  failAssignment,
  heartbeatAssignment,
} from "./api-client.mjs";
import { generateEditorialDraft } from "./generator.mjs";
import {
  enterStandby,
  leaveStandby,
  updateMetrics,
  updateStatus,
} from "./local-state.mjs";
import {
  ensurePrivateDirectory,
  readOptionalJson,
  withWorkerLock,
} from "./storage.mjs";
import { WorkerKitError, errorCode } from "./errors.mjs";
import { bootstrapWorkerLocked } from "./bootstrap.mjs";

export const ASSIGNMENT_HEARTBEAT_INTERVAL_SECONDS = 30;

/**
 * Long-lived portable Linux/macOS service. Presence is serialized and kept
 * independent from the one active workPromise, so a slow job cannot suppress
 * the required 60-second node pulse.
 */
export async function runPortableSupervisor(config, options = {}) {
  return withWorkerLock(config.stateDirectory, () =>
    runPortableSupervisorLocked(config, options));
}

async function runPortableSupervisorLocked(config, options = {}) {
  const stateRoot = await ensurePrivateDirectory(config.stateDirectory);
  const wait = options.delay ?? delay;
  const now = options.now ?? Date.now;
  const heartbeatOnce = options.nodeHeartbeat ?? nodeHeartbeat;
  const runAssignment = options.runAssignment ?? runOnePortableAssignmentLocked;
  const maximumCycles = options.maximumCycles ?? Number.POSITIVE_INFINITY;
  let cycles = 0;
  let nextHeartbeatAt = now();
  const workPromises = new Set();
  const workloadTracker = createConcurrentWorkloadTracker(stateRoot, config);
  while (!(options.shouldStop?.() ?? false) && cycles < maximumCycles) {
    const remaining = Math.max(0, nextHeartbeatAt - now());
    if (remaining) await wait(remaining);
    if (options.shouldStop?.() ?? false) break;
    let snapshot = null;
    let readinessBlocksClaims = false;
    try {
      await renewReadyAttestation(config, stateRoot, {
        ...options,
        activeAssignments: workPromises.size,
      });
    } catch (error) {
      const ready = await readOptionalJson(stateRoot, "ready.json").catch(() => null);
      readinessBlocksClaims = ready?.ready !== true ||
        !Number.isFinite(Date.parse(ready.readyUntil)) ||
        Date.parse(ready.readyUntil) <= now();
      options.onHeartbeatError?.(error);
    }
    try {
      snapshot = await heartbeatOnce(config, {
        ...options,
        forceDrain: readinessBlocksClaims,
      });
      const target = readinessBlocksClaims ? 0 : claimTarget(snapshot);
      while (workPromises.size < target) {
        const workPromise = Promise.resolve()
          .then(() => runAssignment(config, { ...options, workloadTracker }))
          .catch((error) => options.onWorkError?.(error))
          .finally(() => { workPromises.delete(workPromise); });
        workPromises.add(workPromise);
      }
    } catch (error) {
      options.onHeartbeatError?.(error);
    }
    cycles += 1;
    nextHeartbeatAt += NODE_HEARTBEAT_INTERVAL_SECONDS * 1_000;
    while (nextHeartbeatAt <= now()) {
      nextHeartbeatAt += NODE_HEARTBEAT_INTERVAL_SECONDS * 1_000;
    }
  }
  // A graceful stop blocks new claims but preserves the active assignment,
  // its 30-second heartbeat and its final complete/fail operation.
  if (workPromises.size && options.waitForWorkOnStop !== false) {
    await Promise.allSettled([...workPromises]);
  }
  return { cycles, activeWorkers: workPromises.size };
}

export async function renewReadyAttestation(config, stateRoot, options = {}) {
  const ready = await readOptionalJson(stateRoot, "ready.json");
  const refreshBeforeMilliseconds = (options.readyRefreshBeforeSeconds ?? 3000) * 1000;
  const remaining = Date.parse(ready?.readyUntil ?? "") - (options.now?.() ?? Date.now());
  if (ready?.ready === true && Number.isFinite(remaining) && remaining > refreshBeforeMilliseconds) {
    return ready;
  }
  return (options.bootstrapWorkerLocked ?? bootstrapWorkerLocked)(config, stateRoot, options);
}

export async function runOnePortableAssignment(config, options = {}) {
  return withWorkerLock(config.stateDirectory, () =>
    runOnePortableAssignmentLocked(config, options));
}

async function runOnePortableAssignmentLocked(config, options = {}) {
  const stateRoot = await ensurePrivateDirectory(config.stateDirectory);
  const workloadTracker = options.workloadTracker ??
    createConcurrentWorkloadTracker(stateRoot, config);
  const [identity, control, ready, applied, orchestration] = await Promise.all([
    ensureWorkerIdentity(config, stateRoot),
    readWorkerControl(stateRoot, config),
    readOptionalJson(stateRoot, "ready.json"),
    readOptionalJson(stateRoot, "applied-manifest.json"),
    readOptionalJson(stateRoot, "orchestration.json"),
  ]);
  assertClaimGate(config, control, ready, applied, orchestration);
  const claim = await claimAssignments(config, identity, stateRoot, {
    ...options,
    requestedCapacity: 1,
  });
  if (claim.assignments.length > 1) {
    throw new WorkerKitError("single-work-promise-violated", "Portable supervisor accepts one assignment at a time.");
  }
  if (!claim.assignments.length) return { claimed: 0, completed: 0, failed: 0 };
  const assignment = {
    ...claim.assignments[0],
    adaptiveWorkPolicy: applied.adaptiveWorkPolicy,
  };
  const progress = createAssignmentProgress();
  const cancellation = new AbortController();
  const heartbeat = startAssignmentHeartbeat(
    config,
    identity,
    assignment,
    progress,
    cancellation,
    options,
  );
  const operatorStop = startOperatorStopMonitor(
    config, stateRoot, assignment, cancellation, options,
  );
  await workloadTracker.started(claim, assignment);
  try {
    const generated = await generateEditorialDraft(
      assignment,
      stateRoot,
      config.localEngineBaseUrl,
      {
        ...options,
        adaptiveWorkPolicy: applied.adaptiveWorkPolicy,
        progress,
        signal: cancellation.signal,
      },
    );
    await stopHeartbeatBeforeComplete(heartbeat);
    const completed = await completeAssignment(
      config,
      identity,
      assignment,
      generated.draft,
      options,
    );
    await workloadTracker.finished(assignment, true, "batch-completed");
    return {
      claimed: 1,
      completed: 1,
      failed: 0,
      assignmentId: assignment.assignmentId,
      status: completed.status,
    };
  } catch (error) {
    const code = heartbeat.stalled
      ? "generator-stalled"
      : operatorStop.requested
        ? "operator-stop-requested"
        : safeErrorCode(error);
    if (!heartbeat.lost || heartbeat.stalled) {
      await failAssignment(config, identity, assignment, code, options).catch(() => {});
    }
    await workloadTracker.finished(assignment, false, code).catch(() => {});
    throw error;
  } finally {
    await operatorStop.stopAndWait();
    await heartbeat.stopAndWait();
  }
}

export function startOperatorStopMonitor(config, stateRoot, assignment, cancellation, options = {}) {
  const intervalMilliseconds = options.operatorControlPollMilliseconds ?? 500;
  const startedAt = Date.now();
  let stopped = false;
  let requested = false;
  let inFlight = null;
  const timer = setInterval(() => {
    if (stopped || inFlight) return;
    inFlight = readWorkerControl(stateRoot, config)
      .then((control) => {
        const requestedAt = Date.parse(control.updatedAt);
        if (control.updatedBy === "stop" && control.acceptingClaims === false &&
            Number.isFinite(requestedAt) && requestedAt >= startedAt && !cancellation.signal.aborted) {
          requested = true;
          cancellation.abort(new WorkerKitError(
            "operator-stop-requested",
            `Operator stopped assignment ${assignment.assignmentId}.`,
          ));
        }
      })
      .catch(() => {})
      .finally(() => { inFlight = null; });
  }, intervalMilliseconds);
  timer.unref?.();
  return {
    get requested() { return requested; },
    async stopAndWait() {
      stopped = true;
      clearInterval(timer);
      await inFlight?.catch(() => {});
    },
  };
}

export async function stopHeartbeatBeforeComplete(heartbeat) {
  await heartbeat.stopAndWait();
  if (heartbeat.lost) {
    throw new WorkerKitError(
      "lease-lost-discard-result",
      "Lease heartbeat was lost; discard the local result.",
    );
  }
}

export function startAssignmentHeartbeat(
  config,
  identity,
  assignment,
  progress,
  cancellation,
  options = {},
) {
  const intervalMilliseconds = options.assignmentHeartbeatIntervalMilliseconds ??
    ASSIGNMENT_HEARTBEAT_INTERVAL_SECONDS * 1_000;
  const sendHeartbeat = options.heartbeatAssignment ?? heartbeatAssignment;
  if (!Number.isSafeInteger(intervalMilliseconds) || intervalMilliseconds < 1) {
    throw new TypeError("assignmentHeartbeatIntervalMilliseconds must be positive.");
  }
  let stopped = false;
  let lost = false;
  let stalled = false;
  let timer = null;
  let inFlight = null;
  let nextHeartbeatAt = Date.now() + intervalMilliseconds;
  const schedule = () => {
    if (stopped) return;
    const delayMilliseconds = Math.max(0, nextHeartbeatAt - Date.now());
    timer = setTimeout(tick, delayMilliseconds);
    timer.unref?.();
  };
  const tick = async () => {
    if (stopped || inFlight) return;
    nextHeartbeatAt += intervalMilliseconds;
    while (nextHeartbeatAt <= Date.now()) nextHeartbeatAt += intervalMilliseconds;
    inFlight = sendHeartbeat(
      config,
      identity,
      assignment,
      progress.snapshot(),
      options,
    );
    try {
      const response = await inFlight;
      assignment.leaseExpiresAt = response.leaseExpiresAt;
    } catch (error) {
      stalled = errorCode(error) === "generator-stalled";
      lost = true;
      stopped = true;
      cancellation.abort(new WorkerKitError(
        stalled ? "generator-stalled" : "lease-lost-discard-result",
        stalled
          ? "The orchestrator classified the generator as stalled."
          : "The assignment lease heartbeat failed.",
      ));
    } finally {
      inFlight = null;
      schedule();
    }
  };
  schedule();
  return {
    get lost() { return lost; },
    get stalled() { return stalled; },
    async stopAndWait() {
      stopped = true;
      if (timer) clearTimeout(timer);
      await inFlight?.catch(() => {});
    },
  };
}

function claimTarget(snapshot) {
  if (!(snapshot?.heartbeat?.status === "succeeded" &&
    snapshot?.capacity?.requestedCapacity > 0 &&
    snapshot?.capacity?.grantedCapacity > 0 &&
    snapshot?.capacity?.availableSlots > 0 &&
    snapshot?.claim?.allowed === true &&
    snapshot?.claim?.recommendedCount > 0)) return 0;
  return Math.min(
    snapshot.capacity.requestedCapacity,
    snapshot.capacity.grantedCapacity,
    snapshot.capacity.availableSlots,
    snapshot.claim.recommendedCount,
  );
}

function assertClaimGate(config, control, ready, applied, orchestration) {
  const heartbeatAge = Date.now() - Date.parse(orchestration?.heartbeat?.lastSuccessAt ?? "");
  if (
    effectiveRequestedCapacity(control) < 1 ||
    control.acceptingClaims !== true ||
    ready?.ready !== true || Date.parse(ready.readyUntil) <= Date.now() ||
    ready.manifestHash !== applied?.manifestHash ||
    ready.contentContractHash !== applied?.contentContractHash ||
    orchestration?.nodeId !== config.nodeId ||
    orchestration?.heartbeat?.status !== "succeeded" ||
    !Number.isFinite(heartbeatAge) || heartbeatAge < 0 || heartbeatAge > 120_000 ||
    orchestration?.claim?.allowed !== true || orchestration.claim.recommendedCount < 1
  ) {
    throw new WorkerKitError("claims-gates-closed", "Portable worker is paused, stale, or not ready to claim.");
  }
}

export function createConcurrentWorkloadTracker(stateRoot, config) {
  let transition = Promise.resolve();
  let batch = null;
  const active = new Map();
  const serialize = (operation) => {
    const result = transition.then(operation, operation);
    transition = result.catch(() => {});
    return result;
  };
  const snapshot = () => batch ? {
    batchId: batch.batchId,
    assignmentIds: [...batch.assignmentIds],
    jobs: batch.assignmentIds.size,
    completedJobs: batch.completed + batch.failed,
    failedJobs: batch.failed,
    activeJobs: active.size,
    startedAt: batch.startedAt,
  } : null;
  return {
    started(claim, assignment) {
      return serialize(async () => {
        if (active.has(assignment.assignmentId)) {
          throw new WorkerKitError(
            "assignment-progress-duplicate",
            "The concurrent workload tracker already contains this assignment.",
          );
        }
        const createdBatch = batch === null;
        if (createdBatch) {
          batch = {
            batchId: claim.requestId,
            assignmentIds: new Set(),
            completed: 0,
            failed: 0,
            lastFailureCode: null,
            startedAt: new Date().toISOString(),
          };
        }
        batch.assignmentIds.add(assignment.assignmentId);
        active.set(assignment.assignmentId, assignment);
        const currentBatch = snapshot();
        await updateMetrics(stateRoot, config, (metrics) => {
          if (createdBatch) metrics.batches.total += 1;
          metrics.jobs.claimed += 1;
          metrics.jobs.running = active.size;
          metrics.currentBatch = currentBatch;
          leaveStandby(metrics);
        });
        await updateStatus(stateRoot, config, {
          state: "processing",
          running: true,
          standby: false,
          code: "assignment-processing",
          currentBatch,
        });
      });
    },
    finished(assignment, succeeded, code) {
      return serialize(async () => {
        if (!active.delete(assignment.assignmentId) || batch === null) return;
        if (succeeded) batch.completed += 1;
        else {
          batch.failed += 1;
          batch.lastFailureCode = code;
        }
        const batchEnded = active.size === 0;
        const currentBatch = batchEnded ? null : snapshot();
        const batchFailed = batch.failed > 0;
        await updateMetrics(stateRoot, config, (metrics) => {
          metrics.jobs.running = active.size;
          if (succeeded) metrics.jobs.completed += 1;
          else metrics.jobs.failed += 1;
          if (batchEnded) {
            if (batchFailed) metrics.batches.failed += 1;
            else metrics.batches.completed += 1;
            metrics.currentBatch = null;
            enterStandby(metrics);
          } else {
            metrics.currentBatch = currentBatch;
          }
        });
        await updateStatus(stateRoot, config, {
          state: batchEnded
            ? (batchFailed ? "connection-error" : "standby")
            : "processing",
          running: !batchEnded,
          standby: batchEnded && !batchFailed,
          code: batchEnded && batchFailed ? batch.lastFailureCode : code,
          currentBatch,
        });
        if (batchEnded) batch = null;
      });
    },
    activeCount() { return active.size; },
  };
}

function safeErrorCode(error) {
  return String(errorCode(error, "worker-generation-failed"))
    .toLowerCase()
    .replace(/[^a-z0-9._-]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 200) || "worker-generation-failed";
}

function delay(milliseconds) {
  return new Promise((resolvePromise) => setTimeout(resolvePromise, milliseconds));
}
