import { execFile as nodeExecFile } from "node:child_process";
import { lstatSync, realpathSync } from "node:fs";
import {
  basename,
  dirname,
  extname,
  isAbsolute,
  resolve,
} from "node:path";

const ACTIONS = new Set(["start", "pause", "stop", "set-parallelism"]);
const DRIVERS = new Set(["windows-powershell", "fixed-node-script"]);

export class WorkerControlExecutionError extends Error {
  constructor(code) {
    super(code);
    this.name = "WorkerControlExecutionError";
    this.code = code;
  }
}

export function resolveWorkerControlConfig(options = {}) {
  const driver = options.driver ?? (
    options.controlScriptPath || options.controlScriptRootPath
      ? "fixed-node-script"
      : "windows-powershell"
  );
  if (!DRIVERS.has(driver)) {
    throw new TypeError("Worker control driver is unsupported.");
  }
  if (driver === "fixed-node-script") return resolveFixedNodeScriptConfig(options);
  const supplied = [
    options.workerCliPath,
    options.workerConfigPath,
    options.powershellPath,
    options.workerCliRootPath,
    options.workerConfigRootPath,
    options.powershellRootPath,
  ];
  if (supplied.every((value) => value === undefined || value === null || value === "")) {
    return Object.freeze({ enabled: false });
  }
  if (supplied.some((value) => typeof value !== "string" || !value.trim())) {
    throw new TypeError(
      "Worker control requires fixed CLI, config, PowerShell, and trusted-root paths.",
    );
  }

  const workerCliRootPath = trustedCanonicalDirectory(
    options.workerCliRootPath,
    "worker CLI root",
  );
  const workerConfigRootPath = trustedCanonicalDirectory(
    options.workerConfigRootPath,
    "worker config root",
  );
  const powershellRootPath = trustedCanonicalDirectory(
    options.powershellRootPath,
    "PowerShell root",
  );
  const workerCliPath = trustedDirectChild(
    options.workerCliPath,
    "worker CLI",
    workerCliRootPath,
  );
  const workerConfigPath = trustedDirectChild(
    options.workerConfigPath,
    "worker config",
    workerConfigRootPath,
  );
  const powershellPath = trustedDirectChild(
    options.powershellPath,
    "PowerShell",
    powershellRootPath,
  );
  if (basename(workerCliPath).toLowerCase() !== "hch-worker.ps1") {
    throw new TypeError("Worker control CLI must be Hch-Worker.ps1.");
  }
  if (extname(workerConfigPath).toLowerCase() !== ".psd1") {
    throw new TypeError("Worker control config must be a PowerShell data file.");
  }
  if (basename(powershellPath).toLowerCase() !== "powershell.exe") {
    throw new TypeError("Worker control requires Windows PowerShell.");
  }

  const timeoutMilliseconds = boundedInteger(
    options.controlTimeoutMilliseconds ?? 75_000,
    "control timeout",
    10_000,
    300_000,
  );
  const controlPlaneTimeoutSeconds = boundedInteger(
    options.controlPlaneTimeoutSeconds ?? 15,
    "control-plane timeout",
    3,
    30,
  );
  return Object.freeze({
    enabled: true,
    driver: "windows-powershell",
    workerCliPath,
    workerConfigPath,
    powershellPath,
    workerCliRootPath,
    workerConfigRootPath,
    powershellRootPath,
    workingDirectory: workerCliRootPath,
    timeoutMilliseconds,
    controlPlaneTimeoutSeconds,
  });
}

export async function executeWorkerControlAction(config,request,options = {}) {
  if (!config?.enabled) throw new WorkerControlExecutionError("worker-control-unavailable");
  const { action, parallelism } = normalizeControlRequest(request);
  if (!ACTIONS.has(action)) throw new WorkerControlExecutionError("worker-control-action-invalid");
  if (config.driver === "fixed-node-script") {
    return executeFixedNodeScriptAction(config, action, parallelism, options);
  }
  // Revalidate every fixed file immediately before execution. This closes the
  // startup-to-click window in which a trusted file could be replaced by a
  // symlink or a different path entry.
  const trustedConfig = resolveWorkerControlConfig({
    driver: "windows-powershell",
    workerCliPath: config.workerCliPath,
    workerConfigPath: config.workerConfigPath,
    powershellPath: config.powershellPath,
    workerCliRootPath: config.workerCliRootPath,
    workerConfigRootPath: config.workerConfigRootPath,
    powershellRootPath: config.powershellRootPath,
    controlTimeoutMilliseconds: config.timeoutMilliseconds,
    controlPlaneTimeoutSeconds: config.controlPlaneTimeoutSeconds,
  });
  const execFileImpl = options.execFileImpl ?? nodeExecFile;
  const args = [
    "-NoLogo",
    "-NoProfile",
    "-NonInteractive",
    "-ExecutionPolicy",
    "RemoteSigned",
    "-File",
    trustedConfig.workerCliPath,
    action,
    "-ConfigPath",
    trustedConfig.workerConfigPath,
    "-ControlPlaneTimeoutSeconds",
    String(trustedConfig.controlPlaneTimeoutSeconds),
  ];
  if (action === "set-parallelism") args.push("-Parallelism", String(parallelism));
  await new Promise((resolvePromise,reject) => {
    execFileImpl(
      trustedConfig.powershellPath,
      args,
      {
        cwd: trustedConfig.workingDirectory,
        windowsHide: true,
        shell: false,
        timeout: trustedConfig.timeoutMilliseconds,
        maxBuffer: 64 * 1024,
        encoding: "utf8",
      },
      (error) => {
        if (!error) return resolvePromise();
        reject(new WorkerControlExecutionError(
          error.killed || error.code === "ETIMEDOUT"
            ? "worker-control-timeout"
            : "worker-control-failed",
        ));
      },
    );
  });
  return Object.freeze({
    ok: true,
    action,
    requestedState: requestedState(action, parallelism),
    ...(parallelism === undefined ? {} : { parallelism }),
  });
}

function resolveFixedNodeScriptConfig(options) {
  const supplied = [
    options.controlScriptPath,
    options.controlScriptRootPath,
  ];
  if (supplied.every((value) => value === undefined || value === null || value === "")) {
    return Object.freeze({ enabled: false, driver: "fixed-node-script" });
  }
  if (supplied.some((value) => typeof value !== "string" || !value.trim())) {
    throw new TypeError(
      "Fixed Node.js control requires a fixed script and trusted-root path.",
    );
  }
  const controlScriptRootPath = trustedCanonicalDirectory(
    options.controlScriptRootPath,
    "control script root",
  );
  const controlScriptPath = trustedDirectChild(
    options.controlScriptPath,
    "control script",
    controlScriptRootPath,
  );
  if (basename(controlScriptPath) !== "hch-worker-control.mjs") {
    throw new TypeError("Fixed Node.js control script must be hch-worker-control.mjs.");
  }
  const nodeExecutablePath = trustedRegularFile(
    realpathSync.native(process.execPath),
    "Node.js executable",
  );
  return Object.freeze({
    enabled: true,
    driver: "fixed-node-script",
    controlScriptPath,
    controlScriptRootPath,
    nodeExecutablePath,
    workingDirectory: controlScriptRootPath,
    timeoutMilliseconds: boundedInteger(
      options.controlTimeoutMilliseconds ?? 75_000,
      "control timeout",
      1_000,
      300_000,
    ),
  });
}

async function executeFixedNodeScriptAction(config, action, parallelism, options) {
  const trustedConfig = resolveWorkerControlConfig({
    driver: "fixed-node-script",
    controlScriptPath: config.controlScriptPath,
    controlScriptRootPath: config.controlScriptRootPath,
    controlTimeoutMilliseconds: config.timeoutMilliseconds,
  });
  if (trustedConfig.nodeExecutablePath !== config.nodeExecutablePath) {
    throw new WorkerControlExecutionError("worker-control-unavailable");
  }
  const execFileImpl = options.execFileImpl ?? nodeExecFile;
  const args = [
    "--",
    trustedConfig.controlScriptPath,
    action,
  ];
  if (action === "set-parallelism") args.push(String(parallelism));
  await executeFixedFile(execFileImpl, trustedConfig.nodeExecutablePath, args, {
    cwd: trustedConfig.workingDirectory,
    timeout: trustedConfig.timeoutMilliseconds,
    windowsHide: false,
    env: {
      PATH: "/usr/bin:/bin:/usr/sbin:/sbin",
      LANG: "C",
      LC_ALL: "C",
      ...(typeof process.env.HCH_EDITORIAL_WORKER_CONFIG === "string" &&
          process.env.HCH_EDITORIAL_WORKER_CONFIG.startsWith("/")
        ? { HCH_EDITORIAL_WORKER_CONFIG: process.env.HCH_EDITORIAL_WORKER_CONFIG }
        : {}),
    },
  });
  return Object.freeze({
    ok: true,
    action,
    requestedState: requestedState(action, parallelism),
    ...(parallelism === undefined ? {} : { parallelism }),
  });
}

function normalizeControlRequest(value) {
  const request = typeof value === "string" ? { action: value } : value;
  if (!request || typeof request !== "object" || Array.isArray(request) ||
      !ACTIONS.has(request.action)) {
    throw new WorkerControlExecutionError("worker-control-action-invalid");
  }
  if (request.action === "set-parallelism") {
    if (!Number.isSafeInteger(request.parallelism) || request.parallelism < 0 || request.parallelism > 64) {
      throw new WorkerControlExecutionError("worker-control-parallelism-invalid");
    }
    return { action: request.action, parallelism: request.parallelism };
  }
  if (request.parallelism !== undefined) {
    throw new WorkerControlExecutionError("worker-control-action-invalid");
  }
  return { action: request.action, parallelism: undefined };
}

function requestedState(action, parallelism) {
  if (action === "start") return "starting";
  if (action === "pause") return "pausing";
  if (action === "stop") return "stopping";
  return parallelism === 0 ? "pausing" : "parallelism-updating";
}

function executeFixedFile(execFileImpl, file, args, options) {
  return new Promise((resolvePromise,reject) => {
    execFileImpl(
      file,
      args,
      {
        cwd: options.cwd,
        windowsHide: options.windowsHide,
        shell: false,
        timeout: options.timeout,
        maxBuffer: 64 * 1024,
        encoding: "utf8",
        ...(options.env ? { env: options.env } : {}),
      },
      (error) => {
        if (!error) return resolvePromise();
        reject(new WorkerControlExecutionError(
          error.killed || error.code === "ETIMEDOUT"
            ? "worker-control-timeout"
            : "worker-control-failed",
        ));
      },
    );
  });
}

function trustedRegularFile(value,label) {
  if (typeof value !== "string" || !value.trim() || !isAbsolute(value)) {
    throw new TypeError(`${label} path must be absolute.`);
  }
  const candidate = resolve(value);
  let metadata;
  let canonical;
  try {
    metadata = lstatSync(candidate);
    canonical = realpathSync.native(candidate);
  } catch {
    throw new TypeError(`${label} path is unavailable.`);
  }
  if (!metadata.isFile() || metadata.isSymbolicLink() || !samePath(candidate,canonical)) {
    throw new TypeError(`${label} path must be a canonical regular file.`);
  }
  return canonical;
}

function trustedCanonicalDirectory(value,label) {
  if (typeof value !== "string" || !value.trim() || !isAbsolute(value)) {
    throw new TypeError(`${label} path must be absolute.`);
  }
  const candidate = resolve(value);
  let metadata;
  let canonical;
  try {
    metadata = lstatSync(candidate);
    canonical = realpathSync.native(candidate);
  } catch {
    throw new TypeError(`${label} path is unavailable.`);
  }
  if (!metadata.isDirectory() || metadata.isSymbolicLink() || !samePath(candidate,canonical)) {
    throw new TypeError(`${label} path must be a canonical directory.`);
  }
  return canonical;
}

function trustedDirectChild(value,label,trustedRootPath) {
  const canonical = trustedRegularFile(value,label);
  if (!samePath(dirname(canonical),trustedRootPath)) {
    throw new TypeError(`${label} path is outside its trusted directory.`);
  }
  return canonical;
}

function samePath(left,right) {
  const resolvedLeft = resolve(left);
  const resolvedRight = resolve(right);
  return process.platform === "win32"
    ? resolvedLeft.toLowerCase() === resolvedRight.toLowerCase()
    : resolvedLeft === resolvedRight;
}

function boundedInteger(value,name,minimum,maximum) {
  const number = typeof value === "string" && /^\d+$/.test(value) ? Number(value) : value;
  if (!Number.isSafeInteger(number) || number < minimum || number > maximum) {
    throw new TypeError(`${name} must be an integer between ${minimum} and ${maximum}.`);
  }
  return number;
}
