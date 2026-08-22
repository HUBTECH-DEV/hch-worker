#!/usr/bin/env node

import { dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { spawn } from "node:child_process";
import { realpathSync } from "node:fs";

import { loadWorkerConfig } from "./lib/config.mjs";
import { bootstrapWorker } from "./lib/bootstrap.mjs";
import { executeWorkerCycle } from "./lib/execute.mjs";
import { nodeHeartbeat } from "./lib/node-heartbeat.mjs";
import {
  runOnePortableAssignment,
  runPortableSupervisor,
} from "./lib/supervisor.mjs";
import {
  configureLocalWorker,
  localWorkerStatus,
  pauseLocalWorker,
  setLocalParallelism,
  startLocalWorker,
  stopLocalWorker,
  validateLocalWorker,
} from "./lib/control.mjs";
import { errorCode } from "./lib/errors.mjs";

export async function runWorkerCli(argv = process.argv.slice(2), streams = {}, options = {}) {
  const stdout = streams.stdout ?? process.stdout;
  const stderr = streams.stderr ?? process.stderr;
  try {
    const parsed = parseArguments(argv);
    const config = await loadWorkerConfig(parsed.configPath);
    const result = await runCommand(parsed, config, options);
    stdout.write(`${JSON.stringify({ ok: true, ...result })}\n`);
    return 0;
  } catch (error) {
    stderr.write(`${JSON.stringify({
      ok: false,
      code: errorCode(error),
      error: error instanceof Error ? error.message : "Worker kit failed.",
    })}\n`);
    return 1;
  }
}

async function runCommand(parsed, config, options) {
  switch (parsed.command) {
    case "bootstrap":
      return bootstrapWorker(config, { ...options, enroll: parsed.enroll });
    case "execute":
      return executeWorkerCycle(config, options);
    case "node-heartbeat":
      return nodeHeartbeat(config, options);
    case "run-one":
      return runOnePortableAssignment(config, options);
    case "supervise":
      return superviseWithDashboard(config, parsed.configPath, options);
    case "control-configure":
      return configureLocalWorker(config);
    case "control-validate":
      return validateLocalWorker(config, options);
    case "control-start":
      return startLocalWorker(config, options);
    case "control-stop":
      return stopLocalWorker(config);
    case "control-pause":
      return pauseLocalWorker(config);
    case "control-status":
      return localWorkerStatus(config, parsed.systemd);
    case "control-set-parallelism":
      return setLocalParallelism(config, parsed.parallelism);
    default:
      throw new TypeError("Unsupported worker-kit command.");
  }
}

async function superviseWithDashboard(config, configPath, options = {}) {
  const controller = new AbortController();
  const stop = () => controller.abort();
  process.once("SIGINT", stop);
  process.once("SIGTERM", stop);
  const kitRoot = dirname(fileURLToPath(import.meta.url));
  const dashboardRoot = resolve(kitRoot, "../../worker-dashboard");
  const dashboardServer = join(dashboardRoot, "server.mjs");
  const controlScript = join(kitRoot, "hch-worker-control.mjs");
  const port = /^(?:[1-9]\d{0,4})$/.test(process.env.HCH_WORKER_DASHBOARD_PORT ?? "")
    ? Number(process.env.HCH_WORKER_DASHBOARD_PORT) : 4319;
  let dashboard = null;
  let restarts = 0;
  const launchDashboard = () => {
    if (controller.signal.aborted) return;
    dashboard = spawn(process.execPath, [
      dashboardServer,
      "--host", "127.0.0.1",
      "--port", String(port),
      "--data-dir", config.stateDirectory,
      "--control-driver", "fixed-node-script",
      "--control-script", controlScript,
      "--control-script-root", kitRoot,
      "--control-timeout-ms", "75000",
    ], {
      cwd: dashboardRoot,
      stdio: "ignore",
      shell: false,
      windowsHide: true,
      env: { ...process.env, HCH_EDITORIAL_WORKER_CONFIG: configPath },
    });
    dashboard.once("exit", () => {
      dashboard = null;
      if (controller.signal.aborted || restarts >= 5) return;
      const delay = [5, 15, 60, 60, 60][restarts++] * 1_000;
      setTimeout(launchDashboard, delay).unref?.();
    });
  };
  launchDashboard();
  try {
    return await runPortableSupervisor(config, {
      ...options,
      shouldStop: () => controller.signal.aborted || options.shouldStop?.() === true,
      onWorkResult: options.onWorkResult ?? ((result) => {
        process.stdout.write(`${JSON.stringify({ ok: true, event: "assignment-result", ...result })}\n`);
      }),
      onWorkError: options.onWorkError ?? ((error) => {
        const validationCodes = validationErrorCodes(error);
        process.stderr.write(`${JSON.stringify({
          ok: false,
          event: "assignment-error",
          code: errorCode(error),
          ...(validationCodes.length ? { validationCodes } : {}),
        })}\n`);
      }),
    });
  } finally {
    process.removeListener("SIGINT", stop);
    process.removeListener("SIGTERM", stop);
    if (dashboard && !dashboard.killed) dashboard.kill("SIGTERM");
  }
}

export function validationErrorCodes(error) {
  if (!Array.isArray(error?.validation?.errors)) return [];
  return [...new Set(error.validation.errors
    .map((entry) => entry?.code)
    .filter((code) => typeof code === "string" && /^[A-Z0-9][A-Z0-9._-]{0,79}$/.test(code)))]
    .slice(0, 20);
}

function parseArguments(argv) {
  const args = [...argv];
  const command = args.shift();
  const commands = new Set([
    "bootstrap",
    "execute",
    "node-heartbeat",
    "run-one",
    "supervise",
    "control-configure",
    "control-validate",
    "control-start",
    "control-stop",
    "control-pause",
    "control-status",
    "control-set-parallelism",
  ]);
  if (!commands.has(command)) {
    throw new TypeError("Unsupported worker-kit command.");
  }
  let configPath;
  let enroll = false;
  let parallelism;
  const systemd = {};
  while (args.length) {
    const argument = args.shift();
    if (argument === "--config") {
      configPath = args.shift();
      if (!configPath) throw new TypeError("--config requires a path.");
    } else if (argument === "--enroll" && command === "bootstrap") {
      enroll = true;
    } else if (argument === "--parallelism" && command === "control-set-parallelism") {
      const value = args.shift();
      if (!/^(?:0|[1-9]|[1-5][0-9]|6[0-4])$/.test(value ?? "")) {
        throw new TypeError("--parallelism must be an integer between 0 and 64.");
      }
      parallelism = Number(value);
    } else if (
      new Set(["--timer-enabled", "--timer-active", "--service-active"]).has(argument) &&
      command === "control-status"
    ) {
      const value = args.shift();
      if (!value || !/^[a-z][a-z-]{0,31}$/.test(value)) {
        throw new TypeError(`${argument} requires a safe systemd state.`);
      }
      systemd[argument.slice(2).replace(/-([a-z])/g, (_, letter) => letter.toUpperCase())] = value;
    } else {
      throw new TypeError("Unsupported worker-kit argument.");
    }
  }
  if (!configPath) throw new TypeError("--config is required.");
  if (command === "control-set-parallelism" && parallelism === undefined) {
    throw new TypeError("control-set-parallelism requires --parallelism.");
  }
  return { command, configPath: resolve(configPath), enroll, parallelism, systemd };
}

const entrypoint = process.argv[1]
  ? pathToFileURL(realpathSync(resolve(process.argv[1]))).href
  : null;
if (entrypoint === import.meta.url) {
  process.exitCode = await runWorkerCli();
}
