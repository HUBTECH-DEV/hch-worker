import { deriveWorkerControlView } from "./control-state.js";
import { deriveBatchProgress } from "./batch-progress.js";

const refreshIntervalMilliseconds = 5_000;
let refreshTimer;
let controlCsrfToken = null;
let controlContract = null;
let latestStatus = null;
let localControlBusy = false;
let pendingControlAction = null;
let lastControlTrigger = null;

const translations = {
  healthy: "Saudável",
  warning: "Atenção",
  critical: "Crítico",
  connected: "Conectado",
  disconnected: "Desconectado",
  connecting: "Conectando",
  degraded: "Degradado",
  authenticated: "Autenticado",
  valid: "Válido",
  invalid: "Inválido",
  expiring: "Expirando",
  expired: "Expirado",
  unverified: "Não verificado",
  unavailable: "Indisponível",
  unsupported: "Não suportada",
  available: "Disponível",
  error: "Erro",
  unknown: "Desconhecido",
  pending: "Pendente",
  rejected: "Rejeitado",
  revoked: "Revogado",
  ready: "Pronto",
  idle: "Ocioso",
  processing: "Processando",
  standby: "Em espera",
  paused: "Pausado",
  stopped: "Parado",
  updating: "Atualizando",
  "self-testing": "Em autoteste",
  bootstrapping: "Preparando",
  draining: "Finalizando lote",
  "update-failed": "Falha na atualização",
  "heartbeat-only": "Somente heartbeat",
  "waiting-for-work": "Aguardando trabalho",
  "execution-authorized": "Execução autorizada",
  succeeded: "Confirmado",
  failed: "Falhou",
  starting: "Iniciando",
  responding: "Respondendo",
  finalizing: "Finalizando",
  progressing: "Progredindo",
  "awaiting-first-progress": "Aguardando primeiro progresso",
  "responding-slowly": "Respondendo lentamente",
  stalled: "Travado",
  "attestation-reset": "Reiniciado pela atestação",
  "minimum-unit-window-ignored": "Janela ignorada na unidade mínima",
  "within-window": "Dentro da janela",
  "near-window-downshift": "Downshift ao atingir o limiar",
  "already-downshifted": "Downshift já aplicado",
  "progress-advanced": "Progresso avançou",
  "progress-within-stall-grace": "Progresso dentro da tolerância",
  "finalization-in-progress": "Finalização em andamento",
  "first-progress-grace-exceeded": "Primeiro progresso excedeu a tolerância",
  "progress-stalled": "Progresso excedeu a tolerância",
  "finalization-grace-exceeded": "Finalização excedeu a tolerância",
  "near-window": "Próximo da janela",
  "over-window": "Acima da janela consultiva",
  "ignored-at-minimum": "Janela ignorada na unidade mínima",
};

function byId(id) {
  return document.getElementById(id);
}

function translated(value) {
  return translations[value] ?? value ?? "—";
}

function statusTone(value) {
  if (new Set(["healthy", "connected", "authenticated", "valid", "ready", "idle", "processing", "available", "progressing"]).has(value)) return "good";
  if (new Set(["critical", "invalid", "expired", "revoked", "rejected", "error", "update-failed", "disconnected", "stalled"]).has(value)) return "critical";
  return "warning";
}

function setStatus(element, value) {
  element.textContent = translated(value);
  element.dataset.tone = statusTone(value);
}

function formatNumber(value, maximumFractionDigits = 1) {
  if (value === null || value === undefined || !Number.isFinite(value)) return "—";
  return new Intl.NumberFormat("pt-BR", { maximumFractionDigits }).format(value);
}

function formatPercent(value) {
  return value === null || value === undefined ? "—" : `${formatNumber(value)}%`;
}

function formatBytes(value) {
  if (value === null || value === undefined || !Number.isFinite(value)) return "—";
  const units = ["B", "KB", "MB", "GB", "TB"];
  let amount = value;
  let unit = 0;
  while (amount >= 1_000 && unit < units.length - 1) {
    amount /= 1_000;
    unit += 1;
  }
  return `${formatNumber(amount, amount < 10 && unit > 0 ? 2 : 1)} ${units[unit]}`;
}

function formatDurationSeconds(value) {
  if (value === null || value === undefined || !Number.isFinite(value)) return "—";
  const seconds = Math.max(0, Math.floor(value));
  const days = Math.floor(seconds / 86_400);
  const hours = Math.floor((seconds % 86_400) / 3_600);
  const minutes = Math.floor((seconds % 3_600) / 60);
  const remaining = seconds % 60;
  if (days) return `${days}d ${hours}h`;
  if (hours) return `${hours}h ${minutes}min`;
  if (minutes) return `${minutes}min ${remaining}s`;
  return `${remaining}s`;
}

function formatDurationMilliseconds(value) {
  if (value === null || value === undefined || !Number.isFinite(value)) return "—";
  if (value >= 1_000) return formatDurationSeconds(value / 1_000);
  return `${formatNumber(value, 0)} ms`;
}

function formatTime(value) {
  if (!value) return "—";
  const date = new Date(value);
  if (!Number.isFinite(date.getTime())) return "—";
  return new Intl.DateTimeFormat("pt-BR", {
    dateStyle: "short",
    timeStyle: "medium",
  }).format(date);
}

function render(status) {
  latestStatus = status;
  setStatus(byId("overall-indicator"), status.overall);
  byId("last-refresh").textContent = `Atualizado ${formatTime(status.generatedAt)}`;
  byId("worker-title").textContent = status.worker.displayName;
  byId("worker-meta").textContent = [
    status.worker.id,
    status.worker.platform,
    status.worker.version ? `v${status.worker.version}` : null,
  ].filter(Boolean).join(" · ");
  const workerState = byId("worker-state").querySelector(".status");
  setStatus(workerState, status.worker.state);
  byId("worker-uptime").textContent = formatDurationSeconds(status.worker.uptimeSeconds);
  byId("standby-state").textContent = status.workload.standby.active
    ? `Sim · desde ${formatTime(status.workload.standby.since)}`
    : "Não";

  renderAlerts(status.alerts);
  byId("connection-status").textContent = translated(status.connection.status);
  byId("connection-detail").textContent = status.connection.lastSuccessAt
    ? `Último sucesso ${formatTime(status.connection.lastSuccessAt)}`
    : status.connection.errorCode ?? "Sem confirmação recente";
  byId("authentication-status").textContent = translated(status.security.authentication.status);
  byId("authentication-key").textContent = status.security.authentication.keyId
    ? `Chave ${status.security.authentication.keyId}`
    : "Chave —";
  byId("tls-status").textContent = `${translated(status.security.transport.tlsStatus)} · ${translated(status.security.transport.certificateStatus)}`;
  const certificateDetails = [];
  if (status.security.transport.certificateExpiresAt) {
    certificateDetails.push(`expira ${formatTime(status.security.transport.certificateExpiresAt)}`);
  }
  if (status.security.transport.certificateFingerprint) {
    certificateDetails.push(status.security.transport.certificateFingerprint);
  }
  byId("certificate-detail").textContent = certificateDetails.length
    ? `Certificado ${certificateDetails.join(" · ")}`
    : "Validade não informada";
  byId("ed25519-status").textContent = translated(status.security.ed25519Chain.status);
  byId("root-key").textContent = status.security.ed25519Chain.rootKeyId ?? "—";
  byId("release-key").textContent = status.security.ed25519Chain.releaseKeyId ?? "—";
  byId("manifest-sequence").textContent = status.security.ed25519Chain.manifestSequence ?? "—";
  byId("content-contract-hash").textContent = status.security.ed25519Chain.contentContractHash ?? "—";
  byId("policy-hash").textContent = status.security.ed25519Chain.policyHash ?? "—";

  const orchestration = status.orchestration;
  setStatus(byId("orchestration-mode"), orchestration.mode);
  byId("orchestration-mode").textContent = translated(orchestration.mode);
  byId("node-heartbeat-status").textContent = translated(orchestration.heartbeat.status);
  byId("node-heartbeat-detail").textContent = `Último ${formatTime(orchestration.heartbeat.lastSuccessAt)} · próximo ${formatTime(orchestration.heartbeat.nextHeartbeatAt)}`;
  byId("orchestration-capacity").textContent = `Concedida ${formatNumber(orchestration.capacity.grantedCapacity, 0)} · livres ${formatNumber(orchestration.capacity.availableSlots, 0)}`;
  byId("orchestration-capacity-detail").textContent = `Ativos ${formatNumber(orchestration.capacity.activeAssignments, 0)} · ${orchestration.capacity.reason ?? "sem concessão"}`;
  byId("future-work-total").textContent = formatNumber(orchestration.workload.futureTotal, 0);
  byId("future-work-detail").textContent = `Elegíveis ${formatNumber(orchestration.workload.claimable, 0)} · gerando ${formatNumber(orchestration.workload.generating, 0)}`;
  renderAdaptiveWork(status.adaptiveWork);

  byId("cpu-total").textContent = formatDurationSeconds(status.resources.cpu.totalSeconds);
  byId("cpu-average").textContent = formatPercent(status.resources.cpu.averagePercent);
  const gpu = status.resources.gpu;
  byId("gpu-total").textContent = gpu.status === "available"
    ? formatDurationSeconds(gpu.totalActiveSeconds)
    : "—";
  byId("gpu-average").textContent = gpu.status === "available"
    ? formatPercent(gpu.averagePercent)
    : "—";
  byId("gpu-status").textContent = gpu.status === "error" && gpu.errorCode
    ? `GPU: ${translated(gpu.status)} · ${gpu.errorCode}`
    : `GPU: ${translated(gpu.status)}`;
  byId("memory-average").textContent = formatBytes(status.resources.memoryPerItem.averageBytes);
  byId("memory-peak").textContent = formatBytes(status.resources.memoryPerItem.peakBytes);

  byId("processing-average").textContent = formatDurationMilliseconds(status.throughput.averageProcessingMilliseconds);
  byId("processing-total").textContent = `Tempo acumulado ${formatDurationMilliseconds(status.throughput.totalProcessingMilliseconds)}`;
  byId("volume-total").textContent = formatBytes(status.throughput.totalBytes);
  byId("volume-detail").textContent = `Entrada ${formatBytes(status.throughput.inputBytes)} · saída ${formatBytes(status.throughput.outputBytes)}`;
  const networkTotal = status.network.rxBytes + status.network.txBytes;
  byId("network-total").textContent = formatBytes(networkTotal);
  byId("network-detail").textContent = `RX ${formatBytes(status.network.rxBytes)} · TX ${formatBytes(status.network.txBytes)}`;
  byId("batches-total").textContent = formatNumber(status.workload.batchesTotal, 0);
  byId("batches-detail").textContent = `Concluídos ${formatNumber(status.workload.batchesCompleted, 0)}`;
  byId("jobs-total").textContent = formatNumber(status.workload.jobsTotal, 0);
  byId("jobs-detail").textContent = `Concluídos ${formatNumber(status.workload.jobsCompleted, 0)} · sucesso ${formatNumber(status.workload.jobsSucceeded, 0)} · falha ${formatNumber(status.workload.jobsFailed, 0)}`;
  byId("jobs-running").textContent = formatNumber(status.workload.jobsRunning, 0);
  const capacity = status.capacity;
  byId("capacity-grant").textContent = `Solicitada ${formatNumber(capacity.requestedCapacity, 0)} · concedida ${formatNumber(capacity.grantedCapacity, 0)}`;
  byId("capacity-detail").textContent = `Ativos ${formatNumber(capacity.activeAssignments, 0)} · ${capacity.capacityReason}${capacity.validUntil ? ` · até ${formatTime(capacity.validUntil)}` : ""}`;
  renderRunningJobs(status.workload.runningJobIds);
  renderBatch(status.workload.currentBatch, status.workload, status.adaptiveWork);
  renderWorkerControl(status);
  renderWorkerUpdate(status);
  byId("telemetry-meta").textContent = `Telemetria r${status.telemetry.revision} · ${status.telemetry.eventsAccepted} eventos · ${formatTime(status.telemetry.updatedAt)}`;
}

function renderWorkerUpdate(status) {
  const panel = byId("worker-update");
  const state = byId("update-state");
  const summary = byId("update-summary");
  const meta = byId("update-meta");
  const button = byId("control-update");
  const updates = status?.updates ?? {};
  const busy = localControlBusy || status?.control?.busy === true || controlContract?.busy === true;
  const canExecute = status?.control?.updateEnabled === true &&
    controlContract?.updateEnabled === true && typeof controlCsrfToken === "string";
  panel.setAttribute("aria-busy", String(busy));
  button.hidden = updates.updateAvailable !== true;
  button.disabled = updates.updateAvailable !== true || !canExecute || busy;
  if (updates.status === "error") {
    setControlState(state, "Consulta indisponível", "warning");
    summary.textContent = "Não foi possível confirmar a release mais recente agora.";
  } else if (updates.updateAvailable === true) {
    const incompatible = updates.compatibility === "incompatible" &&
      updates.contentImpact === "generated-content";
    setControlState(
      state,
      incompatible ? "Atualização incompatível disponível" : "Atualização disponível",
      "warning",
    );
    summary.textContent = incompatible
      ? `Worker ${updates.currentVersion ?? "—"}; release ${updates.latestVersion} altera o resultado do conteúdo. Novos trabalhos exigem atualização.`
      : `Worker ${updates.currentVersion ?? "—"}; release ${updates.latestVersion} disponível sem interromper o processamento atual.`;
  } else if (updates.status === "no-release") {
    setControlState(state, "Sem release", "neutral");
    summary.textContent = "O repositório ainda não possui uma release estável publicada.";
  } else {
    setControlState(state, "Atualizado", "good");
    summary.textContent = `Worker ${updates.currentVersion ?? "—"}; nenhuma versão mais nova foi encontrada.`;
  }
  meta.textContent = [
    updates.checkedAt ? `Verificado ${formatTime(updates.checkedAt)}` : null,
    updates.publishedAt ? `publicada ${formatTime(updates.publishedAt)}` : null,
    updates.compatibility && updates.compatibility !== "unspecified"
      ? `compatibilidade: ${translated(updates.compatibility)}` : null,
    updates.updateAvailable && !canExecute ? "executor administrativo não habilitado" : null,
  ].filter(Boolean).join(" · ") || "Aguardando a primeira consulta.";
}

function renderAdaptiveWork(adaptiveWork) {
  const sizing = adaptiveWork?.workSizing ?? null;
  setStatus(byId("adaptive-work-availability"), adaptiveWork?.available ? "available" : "unavailable");
  byId("adaptive-tier").textContent = sizing?.currentTier ?? "—";
  byId("adaptive-tier-detail").textContent = sizing
    ? `Perfil ${sizing.editorialProfile} · rank ${formatNumber(sizing.currentRank, 0)}`
    : "Perfil — · rank —";
  byId("adaptive-token-ceiling").textContent = sizing
    ? `${formatNumber(sizing.maxOutputTokens, 0)} tokens`
    : "—";
  byId("adaptive-minimum-unit").textContent = sizing
    ? sizing.minimumUnit
      ? "Unidade mínima · a janela total é somente informativa"
      : "Unidade mínima: não"
    : "Unidade mínima —";
  byId("adaptive-window").textContent = sizing
    ? `${formatDurationSeconds(sizing.nearWindowSeconds)} / ${formatDurationSeconds(sizing.processingWindowSeconds)}`
    : "—";
  byId("adaptive-window-detail").textContent = sizing
    ? `Primeiro progresso ${formatDurationSeconds(sizing.firstProgressGraceSeconds)} · resposta ${formatDurationSeconds(sizing.stallAfterSeconds)} · finalização ${formatDurationSeconds(sizing.finalizationGraceSeconds)}`
    : "Tolerâncias de progresso —";
  byId("adaptive-downshift-reason").textContent = sizing
    ? translated(sizing.downshiftReason)
    : "—";
  byId("adaptive-downshift-updated").textContent = sizing?.updatedAt
    ? `Atualizado ${formatTime(sizing.updatedAt)}`
    : "Atualização —";

  const list = byId("adaptive-work-list");
  list.replaceChildren();
  const items = Array.isArray(adaptiveWork?.activeWork) ? adaptiveWork.activeWork : [];
  if (items.length === 0) {
    const empty = document.createElement("p");
    empty.className = "adaptive-work-empty";
    empty.textContent = adaptiveWork?.available
      ? "Nenhum trabalho adaptativo ativo informado."
      : "O worker ainda não publicou telemetria adaptativa.";
    list.append(empty);
    return;
  }
  for (const item of items) list.append(adaptiveWorkItem(item));
}

function adaptiveWorkItem(item) {
  const article = document.createElement("article");
  article.className = "adaptive-work-item";
  article.dataset.tone = statusTone(item.livenessStatus);

  const heading = document.createElement("div");
  heading.className = "adaptive-work-heading";
  const assignment = document.createElement("p");
  assignment.className = "adaptive-assignment-id mono";
  assignment.textContent = item.assignmentId;
  const state = document.createElement("span");
  state.className = "status";
  setStatus(state, item.livenessStatus);
  const reason = document.createElement("p");
  reason.className = "metric-note";
  reason.textContent = [
    translated(item.livenessReason),
    item.windowState ? translated(item.windowState) : null,
  ].filter(Boolean).join(" · ");
  heading.append(assignment, state, reason);

  const facts = document.createElement("dl");
  facts.className = "adaptive-work-facts";
  appendAdaptiveFact(facts, "Decorrido", formatDurationSeconds(item.elapsedSeconds));
  appendAdaptiveFact(facts, "Fase", translated(item.phase));
  appendAdaptiveFact(
    facts,
    "Último progresso",
    item.lastProgressAt
      ? `${formatTime(item.lastProgressAt)} · há ${formatDurationSeconds(item.progressAgeSeconds)}`
      : "Ainda não informado",
  );
  appendAdaptiveFact(
    facts,
    "Tier / teto",
    item.tier && item.maxOutputTokens !== null
      ? `${item.tier} · ${formatNumber(item.maxOutputTokens, 0)} tokens`
      : item.tier ?? "—",
  );
  article.append(heading, facts);
  return article;
}

function appendAdaptiveFact(list, label, value) {
  const wrapper = document.createElement("div");
  const term = document.createElement("dt");
  const description = document.createElement("dd");
  term.textContent = label;
  description.textContent = value ?? "—";
  wrapper.append(term, description);
  list.append(wrapper);
}

function renderAlerts(alerts) {
  const list = byId("alerts-list");
  list.replaceChildren();
  const visibleAlerts = alerts.length
    ? alerts
    : [{ severity: "good", message: "Nenhum alerta operacional ativo." }];
  for (const alert of visibleAlerts) {
    const item = document.createElement("li");
    item.className = "alert-item";
    item.dataset.severity = alert.severity;
    const level = document.createElement("span");
    level.className = "alert-level";
    level.textContent = alert.severity === "critical"
      ? "Crítico"
      : alert.severity === "warning" ? "Atenção" : "OK";
    const message = document.createElement("span");
    message.textContent = alert.message;
    item.append(level, message);
    list.append(item);
  }
  byId("alerts-count").textContent = String(alerts.length);
}

function renderRunningJobs(jobIds) {
  const list = byId("running-job-list");
  list.replaceChildren();
  const jobs = jobIds.length ? jobIds : ["Nenhum trabalho ativo"];
  for (const job of jobs) {
    const item = document.createElement("li");
    item.textContent = job;
    list.append(item);
  }
}

function renderBatch(batch, workload, adaptiveWork) {
  const status = byId("batch-status");
  const progress = byId("batch-progress");
  const itemsProgress = byId("batch-items-progress");
  const view = deriveBatchProgress(batch, workload, adaptiveWork);
  byId("batch-item-percent").textContent = `${view.itemPercent}%`;
  byId("batch-items-ratio").textContent = `${view.runningItems}/${view.totalItems}`;
  progress.max = 100;
  progress.value = view.itemPercent;
  progress.textContent = `${view.itemPercent}%`;
  itemsProgress.max = Math.max(1, view.totalItems);
  itemsProgress.value = view.runningItems;
  itemsProgress.textContent = `${view.runningItems}/${view.totalItems}`;
  if (!batch) {
    setStatus(status, "unknown");
    status.textContent = "Sem lote";
    byId("batch-id").textContent = "—";
    byId("batch-progress-text").textContent = "Nenhum lote em andamento.";
    return;
  }
  setStatus(status, "processing");
  status.textContent = "Em andamento";
  byId("batch-id").textContent = batch.id;
  byId("batch-progress-text").textContent = `${batch.completedJobs} de ${batch.totalJobs} trabalhos · iniciado ${formatTime(batch.startedAt)}`;
}

function renderWorkerControl(status) {
  const panel = byId("worker-controls");
  const startButton = byId("control-start");
  const pauseButton = byId("control-pause");
  const stopButton = byId("control-stop");
  const parallelismInput = byId("control-parallelism");
  const parallelismButton = byId("control-apply-parallelism");
  const state = byId("control-state");
  const summary = byId("control-summary");
  const reportedControl = status?.control ?? {};
  const controlView = deriveWorkerControlView(status);
  const activeAssignments = controlView.activeAssignments;
  const contractReady = reportedControl.available === true &&
    controlContract?.available === true && typeof controlCsrfToken === "string";
  const busy = localControlBusy || reportedControl.busy === true || controlContract?.busy === true;

  panel.setAttribute("aria-busy", String(busy));
  if (reportedControl.available !== true) {
    setControlState(state, "Indisponível", "warning");
    summary.textContent = "Os controles não foram habilitados neste processo do painel.";
  } else if (!contractReady) {
    setControlState(state, "Preparando", "warning");
    summary.textContent = "Obtendo a autorização efêmera desta sessão local.";
  } else if (busy) {
    setControlState(state, "Aplicando", "warning");
    summary.textContent = "A ação local está em andamento. Aguarde a confirmação do worker.";
  } else if (controlView.mode === "invalid") {
    setControlState(state, "Controle inválido", "critical");
    summary.textContent = "O arquivo de controle local foi rejeitado. Corrija o estado antes de executar uma ação.";
  } else if (controlView.mode === "active") {
    setControlState(state, status.worker.state === "processing" ? "Processando" : "Ativo", "good");
    summary.textContent = activeAssignments > 0
      ? `${activeAssignments} assignment${activeAssignments === 1 ? "" : "s"} ativo${activeAssignments === 1 ? "" : "s"}; novos claims seguem a capacidade central.`
      : "Processamento habilitado; o próximo ciclo negociará capacidade com o orquestrador.";
  } else if (controlView.mode === "draining") {
    setControlState(state, "Finalizando", "warning");
    summary.textContent = `Pausa solicitada; ${activeAssignments} assignment${activeAssignments === 1 ? "" : "s"} segue${activeAssignments === 1 ? "" : "m"} até finalização segura.`;
  } else {
    setControlState(state, "Pausado", "neutral");
    summary.textContent = "Novos claims estão bloqueados e não há assignment ativo informado.";
  }

  startButton.disabled = !contractReady || busy || !controlView.canStart;
  pauseButton.disabled = !contractReady || busy || !controlView.canPause;
  stopButton.disabled = !contractReady || busy || !controlView.canStop;
  parallelismInput.disabled = !contractReady || busy;
  parallelismButton.disabled = !contractReady || busy;
  if (document.activeElement !== parallelismInput && Number.isInteger(controlView.requestedParallelism)) {
    parallelismInput.value = String(controlView.requestedParallelism);
  }
}

function setControlState(element, label, tone) {
  element.textContent = label;
  element.dataset.tone = tone;
}

function setControlFeedback(message, tone = "neutral", target = "control-feedback") {
  const feedback = byId(target);
  feedback.textContent = message;
  feedback.dataset.tone = tone;
}

async function refreshControlContract() {
  try {
    const response = await fetch("/api/control", {
      cache: "no-store",
      credentials: "same-origin",
      headers: { Accept: "application/json" },
    });
    if (!response.ok) throw new Error("control unavailable");
    const value = await response.json();
    if (!value || typeof value !== "object" || typeof value.available !== "boolean") {
      throw new Error("control contract invalid");
    }
    if (value.available === true &&
        (typeof value.csrfToken !== "string" || !/^[A-Za-z0-9_-]{43}$/.test(value.csrfToken))) {
      throw new Error("control token invalid");
    }
    controlContract = value;
    controlCsrfToken = value.available ? value.csrfToken : null;
  } catch {
    controlContract = { available: false, busy: false };
    controlCsrfToken = null;
  }
  if (latestStatus) {
    renderWorkerControl(latestStatus);
    renderWorkerUpdate(latestStatus);
  }
}

function requestControlConfirmation(action, trigger) {
  if (!new Set(["start", "pause", "stop", "update"]).has(action) || localControlBusy) return;
  pendingControlAction = action;
  lastControlTrigger = trigger;
  const dialog = byId("control-confirmation");
  const title = byId("control-confirmation-title");
  const description = byId("control-confirmation-description");
  const submit = byId("control-confirmation-submit");
  if (action === "start") {
    title.textContent = "Iniciar processamento?";
    description.textContent = "O worker será habilitado para negociar capacidade e solicitar novos itens ao orquestrador central.";
    submit.textContent = "Iniciar processamento";
  } else if (action === "pause") {
    title.textContent = "Pausar processamento?";
    description.textContent = "Novos claims serão bloqueados. Assignments já ativos não serão interrompidos e seguirão até uma finalização segura.";
    submit.textContent = "Pausar processamento";
  } else if (action === "stop") {
    title.textContent = "Parar e cancelar trabalhos ativos?";
    description.textContent = "Novos claims serão bloqueados. Cada gerador ativo será cancelado e a falha operator-stop-requested será relatada ao orquestrador.";
    submit.textContent = "Parar e cancelar";
  } else {
    title.textContent = "Atualizar o worker?";
    description.textContent = "O executor local bloqueará novos claims, aguardará o drain, aplicará a release e validará o worker. Em falha, deverá restaurar a versão anterior.";
    submit.textContent = "Atualizar";
  }
  if (typeof dialog.showModal === "function") {
    if (!dialog.open) dialog.showModal();
    submit.focus();
    return;
  }
  const confirmed = window.confirm(`${title.textContent}\n\n${description.textContent}`);
  if (confirmed) void performControlAction(action);
  else pendingControlAction = null;
}

function closeControlConfirmation() {
  pendingControlAction = null;
  const dialog = byId("control-confirmation");
  if (dialog.open) dialog.close();
}

async function performControlAction(action, parallelism) {
  if (!new Set(["start", "pause", "stop", "set-parallelism", "update"]).has(action) ||
      localControlBusy || typeof controlCsrfToken !== "string") return;
  localControlBusy = true;
  renderWorkerControl(latestStatus);
  renderWorkerUpdate(latestStatus);
  setControlFeedback(
    action === "start" ? "Solicitando início ao worker local…" :
      action === "pause" ? "Solicitando pausa sem interromper trabalhos ativos…" :
        action === "stop" ? "Solicitando cancelamento reportado dos trabalhos ativos…" :
          action === "update" ? "Solicitando atualização segura ao executor local…" :
            `Aplicando paralelismo ${parallelism}…`,
    "warning",
    action === "update" ? "update-feedback" : "control-feedback",
  );
  try {
    const response = await fetch("/api/control", {
      method: "POST",
      cache: "no-store",
      credentials: "same-origin",
      headers: {
        Accept: "application/json",
        "Content-Type": "application/json",
        "X-HCH-CSRF-Token": controlCsrfToken,
      },
      body: JSON.stringify(action === "set-parallelism" ? { action, parallelism } : { action }),
    });
    let result = null;
    try { result = await response.json(); } catch { result = null; }
    if (!response.ok) {
      const error = new Error("control request failed");
      error.publicCode = typeof result?.error === "string" ? result.error : null;
      error.statusCode = response.status;
      throw error;
    }
    setControlFeedback(
      action === "start"
        ? "Processamento habilitado. A capacidade será confirmada pelo orquestrador."
        : action === "pause"
          ? "Pausa aplicada. Assignments ativos continuarão até a finalização segura."
          : action === "stop"
            ? "Parada solicitada. Cancelamentos ativos serão relatados ao orquestrador."
            : action === "update"
              ? "Atualização entregue ao executor local. O painel acompanhará a nova versão após a reinicialização."
            : parallelism === 0
              ? "Paralelismo zero aplicado como pausa; trabalhos ativos foram preservados."
              : `Paralelismo ${parallelism} solicitado; a concessão efetiva permanece central.`,
      "good",
      action === "update" ? "update-feedback" : "control-feedback",
    );
  } catch (error) {
    setControlFeedback(
      controlErrorMessage(error?.publicCode, error?.statusCode),
      "critical",
      action === "update" ? "update-feedback" : "control-feedback",
    );
  } finally {
    await Promise.all([refreshControlContract(), refresh()]);
    localControlBusy = false;
    if (latestStatus) {
      renderWorkerControl(latestStatus);
      renderWorkerUpdate(latestStatus);
    }
  }
}

function controlErrorMessage(code, statusCode) {
  if (code === "worker-update-not-available") {
    return "A release foi revalidada e já não há uma atualização aplicável.";
  }
  if (code === "worker-update-unavailable") {
    return "O executor administrativo de atualização não está habilitado neste host.";
  }
  if (code === "worker-control-busy" || statusCode === 409) {
    return "Outra ação local ainda está em andamento. Aguarde e tente novamente.";
  }
  if (code === "worker-control-timeout" || statusCode === 504) {
    return "O worker não confirmou a ação dentro do limite. Consulte o estado antes de repetir.";
  }
  if (code === "worker-control-unavailable" || statusCode === 503) {
    return "Os controles locais não estão disponíveis neste processo do painel.";
  }
  if (statusCode === 403) {
    return "A autorização local expirou ou a origem foi recusada. Atualize o painel e tente novamente.";
  }
  return "Não foi possível confirmar a ação local. O processamento não será presumido como alterado.";
}

async function refresh() {
  try {
    const response = await fetch("/api/status", {
      cache: "no-store",
      headers: { Accept: "application/json" },
    });
    if (!response.ok) throw new Error("status unavailable");
    render(await response.json());
  } catch {
    setStatus(byId("overall-indicator"), "critical");
    byId("last-refresh").textContent = "Falha ao ler o estado local";
    renderAlerts([{
      severity: "critical",
      message: "O painel não conseguiu ler /api/status. Tentará novamente.",
    }]);
  }
}

async function refreshPublicIdentity() {
  try {
    const response=await fetch("/api/identity",{cache:"no-store",headers:{Accept:"application/json"}});
    if(!response.ok) throw new Error("identity unavailable");
    const identity=await response.json();
    byId("public-identity-meta").textContent=`${identity.nodeId} · ${identity.keyId} · ${identity.fingerprint}`;
    byId("public-identity-key").textContent=identity.publicKeyPem;
    byId("copy-public-identity").disabled=false;
    byId("copy-public-identity").dataset.publicKey=identity.publicKeyPem;
  } catch { byId("public-identity-meta").textContent="A identidade pública ainda não está disponível."; }
}

function scheduleRefresh() {
  clearInterval(refreshTimer);
  if (!document.hidden) {
    refreshTimer = setInterval(refresh, refreshIntervalMilliseconds);
  }
}

document.addEventListener("visibilitychange", () => {
  scheduleRefresh();
  if (!document.hidden) void Promise.all([refreshControlContract(), refresh()]);
});

byId("control-start").addEventListener("click", (event) => {
  requestControlConfirmation("start", event.currentTarget);
});
byId("copy-public-identity").addEventListener("click",async(event)=>{const value=event.currentTarget.dataset.publicKey;if(!value)return;await navigator.clipboard.writeText(value);byId("public-identity-feedback").textContent="Chave pública copiada.";});
byId("control-pause").addEventListener("click", (event) => {
  requestControlConfirmation("pause", event.currentTarget);
});
byId("control-stop").addEventListener("click", (event) => {
  requestControlConfirmation("stop", event.currentTarget);
});
byId("control-update").addEventListener("click", (event) => {
  requestControlConfirmation("update", event.currentTarget);
});
byId("control-apply-parallelism").addEventListener("click", () => {
  const value = Number(byId("control-parallelism").value);
  if (!Number.isInteger(value) || value < 0 || value > 64) {
    setControlFeedback("Informe um número inteiro entre 0 e 64.", "critical");
    return;
  }
  void performControlAction("set-parallelism", value);
});
byId("control-confirmation-cancel").addEventListener("click", closeControlConfirmation);
byId("control-confirmation-submit").addEventListener("click", () => {
  const action = pendingControlAction;
  pendingControlAction = null;
  const dialog = byId("control-confirmation");
  if (dialog.open) dialog.close();
  if (action) void performControlAction(action);
});
byId("control-confirmation").addEventListener("cancel", (event) => {
  event.preventDefault();
  closeControlConfirmation();
});
byId("control-confirmation").addEventListener("close", () => {
  lastControlTrigger?.focus();
  lastControlTrigger = null;
});

void Promise.all([refreshControlContract(), refresh(), refreshPublicIdentity()]);
scheduleRefresh();
