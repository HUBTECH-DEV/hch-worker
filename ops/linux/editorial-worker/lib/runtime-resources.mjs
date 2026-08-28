import { readFileSync } from "node:fs";
import { availableParallelism, cpus } from "node:os";

const CGROUP_V2_CPU_MAX = "/sys/fs/cgroup/cpu.max";

export function parseCpuMax(value) {
  const [quotaText, periodText, ...extra] = String(value ?? "").trim().split(/\s+/);
  if (extra.length || !quotaText || !periodText) return null;
  const period = Number(periodText);
  if (!Number.isSafeInteger(period) || period < 1) return null;
  if (quotaText === "max") return Object.freeze({ limited: false, threads: null });
  const quota = Number(quotaText);
  if (!Number.isSafeInteger(quota) || quota < 1) return null;
  return Object.freeze({
    limited: true,
    threads: Math.max(1, Math.ceil(quota / period)),
  });
}

export function effectiveLogicalProcessors(options = {}) {
  const detected = positiveInteger(
    options.availableParallelism ?? safeAvailableParallelism(),
    cpus().length,
  );
  if ((options.platform ?? process.platform) !== "linux") return detected;
  let cpuMaxText = options.cpuMaxText;
  if (cpuMaxText === undefined) {
    try {
      cpuMaxText = readFileSync(CGROUP_V2_CPU_MAX, "utf8");
    } catch {
      return detected;
    }
  }
  const quota = parseCpuMax(cpuMaxText);
  if (!quota?.limited) return detected;
  return Math.min(detected, quota.threads);
}

export function assertLocalEngineThreadBudget(config, options = {}) {
  if (config.localEngineNumThreads === undefined) return config;
  const budget = effectiveLogicalProcessors(options);
  if (config.localEngineNumThreads > budget) {
    throw new TypeError(
      `localEngineNumThreads exceeds the effective CPU budget (${budget}).`,
    );
  }
  return config;
}

function safeAvailableParallelism() {
  try { return availableParallelism(); }
  catch { return cpus().length; }
}

function positiveInteger(value, fallback) {
  return Number.isSafeInteger(value) && value > 0 ? value : Math.max(1, fallback);
}
