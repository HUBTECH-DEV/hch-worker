import {
  defaultMetrics,
  defaultOrchestration,
  defaultWorkerState,
  parseOrchestration,
} from "./contracts.mjs";
import {
  parseDashboardMetrics,
  parseDashboardWorkerState,
} from "./hch-worker-adapter.mjs";
import { parseWorkerOperatorControl } from "./operator-control.mjs";
import { buildAdaptiveWorkStatus } from "./adaptive-work.mjs";
import {
  METRICS_FILE,
  ORCHESTRATION_FILE,
  STATE_FILE,
  WORKER_CONTROL_FILE,
  WORKER_STATUS_FILE,
  safeReadJson,
} from "./storage.mjs";

export async function buildDashboardStatus(dataDirectory, options = {}) {
  const now = options.now instanceof Date ? options.now : new Date(options.now ?? Date.now());
  const staleAfterMilliseconds = options.staleAfterMilliseconds ?? 120_000;
  const processStartedAt = options.processStartedAt instanceof Date
    ? options.processStartedAt
    : new Date(options.processStartedAt ?? Date.now());
  const [dashboardStateRead,workerStateRead,metricsRead,operatorControlRead,orchestrationRead] = await Promise.all([
    safeReadJson(dataDirectory, STATE_FILE, parseDashboardWorkerState),
    safeReadJson(dataDirectory, WORKER_STATUS_FILE, parseDashboardWorkerState),
    safeReadJson(dataDirectory, METRICS_FILE, parseDashboardMetrics),
    safeReadJson(dataDirectory, WORKER_CONTROL_FILE, parseWorkerOperatorControl, {
      maximumBytes: 16 * 1024,
    }),
    safeReadJson(dataDirectory, ORCHESTRATION_FILE, parseOrchestration),
  ]);
  const stateRead = dashboardStateRead.ok
    ? dashboardStateRead
    : workerStateRead.ok
      ? workerStateRead
      : dashboardStateRead.code !== "missing"
        ? dashboardStateRead
        : workerStateRead;
  const state = stateRead.ok ? stateRead.value : defaultWorkerState(now);
  const metrics = metricsRead.ok ? metricsRead.value : defaultMetrics(now);
  const orchestration = orchestrationRead.ok
    ? orchestrationRead.value
    : defaultOrchestration(now);
  const adaptiveWork = buildAdaptiveWorkStatus({
    now,
    workSizing: orchestration.workSizing ?? state.workSizing ?? null,
    activeWork: state.activeWork ?? [],
  });
  const alerts = [];
  const operatorControlMatchesWorker = operatorControlRead.ok &&
    operatorControlMatchesWorkerState(operatorControlRead.value, state, stateRead.ok);
  const operatorControlStatus = operatorControlMatchesWorker
    ? "valid"
    : operatorControlRead.code === "missing" ? "not-reported" : "invalid";

  if (!stateRead.ok) {
    alerts.push(alert(
      stateRead.code === "missing" ? "state-not-reported" : "state-unreadable",
      "warning",
      stateRead.code === "missing"
        ? "O worker ainda não publicou seu estado."
        : "O arquivo de estado foi rejeitado por segurança ou formato.",
    ));
  }
  if (!metricsRead.ok) {
    alerts.push(alert(
      metricsRead.code === "missing" ? "metrics-not-reported" : "metrics-unreadable",
      "warning",
      metricsRead.code === "missing"
        ? "O worker ainda não publicou telemetria."
        : "O arquivo de telemetria foi rejeitado por segurança ou formato.",
    ));
  }
  if (operatorControlStatus === "invalid") {
    alerts.push(alert(
      "operator-control-unreadable",
      "warning",
      "O controle operacional local foi rejeitado por segurança, identidade ou formato.",
    ));
  }
  if (!orchestrationRead.ok) {
    alerts.push(alert(
      orchestrationRead.code === "missing"
        ? "orchestration-not-reported"
        : "orchestration-unreadable",
      "warning",
      orchestrationRead.code === "missing"
        ? "O worker ainda não publicou o heartbeat de orquestração."
        : "O snapshot de orquestração foi rejeitado por segurança ou formato.",
    ));
  }

  const stateAge = now.getTime() - Date.parse(state.updatedAt);
  if (stateRead.ok && stateAge >= staleAfterMilliseconds) {
    alerts.push(alert("state-stale", "warning", "O estado do worker está desatualizado."));
  }
  if (orchestrationRead.ok) {
    addOrchestrationAlerts(orchestration, state, alerts, now, staleAfterMilliseconds);
  }
  addAdaptiveWorkAlerts(adaptiveWork, alerts);
  addConnectionAlerts(state, alerts);
  addSecurityAlerts(state, alerts, now);
  addWorkerAlerts(state, alerts);
  addGpuAlerts(metrics, alerts);

  const workerStartedAt = state.worker.startedAt
    ? Date.parse(state.worker.startedAt)
    : null;
  const uptimeSeconds = Number.isFinite(workerStartedAt)
    ? Math.max(0, Math.floor((now.getTime() - workerStartedAt) / 1000))
    : null;

  return {
    schemaVersion: 1,
    generatedAt: now.toISOString(),
    overall: alerts.some((item) => item.severity === "critical")
      ? "critical"
      : alerts.some((item) => item.severity === "warning")
        ? "warning"
        : "healthy",
    dashboard: {
      uptimeSeconds: Math.max(
        0,
        Math.floor((now.getTime() - processStartedAt.getTime()) / 1000),
      ),
    },
    worker: {
      ...state.worker,
      uptimeSeconds,
      stateUpdatedAt: state.updatedAt,
      stateRevision: state.revision,
    },
    connection: state.connection,
    security: {
      authentication: state.authentication,
      transport: state.transport,
      ed25519Chain: state.trust,
    },
    resources: {
      cpu: {
        totalSeconds: metrics.cpu.totalSeconds,
        averagePercent: metrics.cpu.averagePercent,
        samples: metrics.cpu.sampleCount,
      },
      gpu: {
        status: metrics.gpu.status,
        totalActiveSeconds: metrics.gpu.totalActiveSeconds,
        averagePercent: metrics.gpu.averagePercent,
        samples: metrics.gpu.sampleCount,
        errorCode: metrics.gpu.errorCode,
      },
      memoryPerItem: {
        averageBytes: metrics.memoryPerItem.averageBytes,
        peakBytes: metrics.memoryPerItem.peakBytes,
        samples: metrics.memoryPerItem.sampleCount,
      },
    },
    throughput: {
      averageProcessingMilliseconds: metrics.processingTime.averageMilliseconds,
      totalProcessingMilliseconds: metrics.processingTime.totalMilliseconds,
      inputBytes: metrics.volume.inputBytes,
      outputBytes: metrics.volume.outputBytes,
      totalBytes: metrics.volume.totalBytes,
    },
    network: {
      rxBytes: metrics.network.rxBytes,
      txBytes: metrics.network.txBytes,
    },
    workload: {
      batchesTotal: metrics.workload.batchesTotal,
      batchesCompleted: metrics.workload.batchesCompleted,
      jobsTotal: metrics.workload.jobsTotal,
      jobsCompleted: metrics.workload.jobsCompleted,
      jobsSucceeded: metrics.workload.jobsSucceeded,
      jobsFailed: metrics.workload.jobsFailed,
      jobsRunning: metrics.workload.jobsRunning,
      runningJobIds: metrics.workload.runningJobIds,
      currentBatch: metrics.workload.currentBatch,
      standby: metrics.standby,
    },
    orchestration,
    adaptiveWork,
    capacity: orchestrationRead.ok ? {
      requestedCapacity: orchestration.capacity.requestedCapacity,
      grantedCapacity: orchestration.capacity.grantedCapacity,
      activeAssignments: orchestration.capacity.activeAssignments,
      capacityReason: orchestration.capacity.reason,
      validUntil: orchestration.capacity.grantedUntil,
    } : state.capacity ?? {
      requestedCapacity: 0,
      grantedCapacity: 0,
      activeAssignments: metrics.workload.jobsRunning,
      capacityReason: "not-reported",
      validUntil: null,
    },
    operatorControl: operatorControlStatus === "valid" ? {
      status: "valid",
      acceptingClaims: operatorControlRead.value.acceptingClaims,
      drainRequested: operatorControlRead.value.drainRequested,
      requestedParallelism: operatorControlRead.value.requestedParallelism,
      lastNonZeroParallelism: operatorControlRead.value.lastNonZeroParallelism,
      updatedAt: operatorControlRead.value.updatedAt,
    } : {
      status: operatorControlStatus,
      acceptingClaims: null,
      drainRequested: null,
      requestedParallelism: null,
      lastNonZeroParallelism: null,
      updatedAt: null,
    },
    telemetry: {
      revision: metrics.revision,
      updatedAt: metrics.updatedAt,
      lastEventAt: metrics.lastEventAt,
      eventsAccepted: metrics.eventsAccepted,
    },
    alerts,
  };
}

export function operatorControlMatchesWorkerState(control, state, stateReported = true) {
  if (!stateReported) return true;
  return control.nodeId === state.worker.id && (
    control.workerKeyId === null ||
    control.workerKeyId === state.authentication.keyId
  );
}

function addAdaptiveWorkAlerts(adaptiveWork, alerts) {
  const stalled = adaptiveWork.activeWork.filter((item) => item.livenessStatus === "stalled");
  if (stalled.length > 0) {
    alerts.push(alert(
      "adaptive-work-stalled",
      "critical",
      `${stalled.length} trabalho${stalled.length === 1 ? "" : "s"} ativo${stalled.length === 1 ? "" : "s"} sem progresso dentro da tolerância assinada.`,
    ));
  }
  const slow = adaptiveWork.activeWork.filter(
    (item) => item.livenessStatus === "responding-slowly",
  );
  if (slow.length > 0) {
    alerts.push(alert(
      "adaptive-work-responding-slowly",
      "warning",
      `${slow.length} trabalho${slow.length === 1 ? "" : "s"} continua${slow.length === 1 ? "" : "m"} respondendo lentamente, com progresso observado.`,
    ));
  }
}

function addOrchestrationAlerts(orchestration, state, alerts, now, staleAfterMilliseconds) {
  if (
    orchestration.nodeId !== "unconfigured" &&
    state.worker.id !== "unconfigured" &&
    orchestration.nodeId !== state.worker.id
  ) {
    alerts.push(alert(
      "orchestration-node-mismatch",
      "critical",
      "O heartbeat de orquestração pertence a outro nó.",
    ));
  }
  if (new Set(["failed", "error"]).has(orchestration.heartbeat.status)) {
    alerts.push(alert(
      "orchestration-heartbeat-failed",
      "warning",
      "O último heartbeat do nó falhou.",
    ));
  }
  if (!orchestration.heartbeat.lastSuccessAt) {
    alerts.push(alert(
      "orchestration-heartbeat-not-confirmed",
      "warning",
      "Nenhum heartbeat autenticado foi confirmado pela VPS.",
    ));
    return;
  }
  const heartbeatAge = now.getTime() - Date.parse(orchestration.heartbeat.lastSuccessAt);
  if (Number.isFinite(heartbeatAge) && heartbeatAge >= staleAfterMilliseconds) {
    alerts.push(alert(
      "orchestration-heartbeat-stale",
      "warning",
      "O último heartbeat autenticado está desatualizado.",
    ));
  }
}

function addConnectionAlerts(state, alerts) {
  if (state.connection.status === "connected") return;
  const critical = new Set(["error", "disconnected"]);
  alerts.push(alert(
    "orchestrator-connection",
    critical.has(state.connection.status) ? "critical" : "warning",
    `Conexão com o orquestrador: ${state.connection.status}.`,
  ));
}

function addSecurityAlerts(state, alerts, now) {
  if (state.authentication.status !== "authenticated") {
    alerts.push(alert(
      "worker-authentication",
      new Set(["rejected", "expired", "revoked", "error"]).has(state.authentication.status)
        ? "critical"
        : "warning",
      `Autenticação do worker: ${state.authentication.status}.`,
    ));
  }
  if (state.transport.tlsStatus !== "valid") {
    alerts.push(alert(
      "tls-validation",
      new Set(["invalid", "error"]).has(state.transport.tlsStatus) ? "critical" : "warning",
      `Validação TLS: ${state.transport.tlsStatus}.`,
    ));
  }
  if (state.transport.certificateStatus !== "valid") {
    alerts.push(alert(
      "certificate-validation",
      new Set(["expired", "error"]).has(state.transport.certificateStatus)
        ? "critical"
        : "warning",
      `Certificado do orquestrador: ${state.transport.certificateStatus}.`,
    ));
  } else if (state.transport.certificateExpiresAt) {
    const remaining = Date.parse(state.transport.certificateExpiresAt) - now.getTime();
    if (remaining <= 7 * 24 * 60 * 60 * 1000) {
      alerts.push(alert(
        "certificate-expiring",
        remaining <= 0 ? "critical" : "warning",
        remaining <= 0
          ? "O certificado do orquestrador expirou."
          : "O certificado do orquestrador expira em até sete dias.",
      ));
    }
  }
  if (state.trust.status !== "valid") {
    alerts.push(alert(
      "ed25519-chain",
      new Set(["invalid", "expired", "error"]).has(state.trust.status)
        ? "critical"
        : "warning",
      `Cadeia Ed25519 raiz → release → manifesto: ${state.trust.status}.`,
    ));
  }
}

function addWorkerAlerts(state, alerts) {
  if (new Set(["error", "update-failed", "update-required"]).has(state.worker.state)) {
    alerts.push(alert("worker-error", "critical", `Estado do worker: ${state.worker.state}.`));
  } else if (new Set(["unknown", "bootstrapping", "updating", "self-testing", "paused", "stopped"]).has(state.worker.state)) {
    alerts.push(alert("worker-not-ready", "warning", `Estado do worker: ${state.worker.state}.`));
  }
}

function addGpuAlerts(metrics, alerts) {
  if (metrics.gpu.status === "error") {
    alerts.push(alert("gpu-error", "warning", "A coleta de telemetria da GPU apresentou erro."));
  }
}

function alert(code, severity, message) {
  return { code, severity, message };
}
