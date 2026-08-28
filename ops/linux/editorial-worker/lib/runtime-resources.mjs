import { readFileSync } from "node:fs";
import { availableParallelism, cpus } from "node:os";

const CGROUP_V2_CPU_MAX = "/sys/fs/cgroup/cpu.max";
const CGROUP_V2_CPU_STAT = "/sys/fs/cgroup/cpu.stat";
const MAXIMUM_CPU_SAMPLE_INTERVAL_MICROSECONDS = 120_000_000;
let previousCpuSample = initialCpuSample();

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
    capacity: quota / period,
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

export function effectiveCpuCapacity(options = {}) {
  const detected = positiveNumber(
    options.availableParallelism ?? safeAvailableParallelism(),
    cpus().length,
  );
  if ((options.platform ?? process.platform) !== "linux") return detected;
  let cpuMaxText = options.cpuMaxText;
  if (cpuMaxText === undefined) {
    try { cpuMaxText = readFileSync(CGROUP_V2_CPU_MAX, "utf8"); }
    catch { return detected; }
  }
  const quota = parseCpuMax(cpuMaxText);
  if (!quota?.limited) return detected;
  return Math.min(detected, quota.capacity);
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

export function parseCpuStatUsage(value) {
  const entries = new Map();
  for (const line of String(value ?? "").trim().split(/\r?\n/)) {
    if (!line) continue;
    const [key, raw, ...extra] = line.trim().split(/\s+/);
    if (!key || !raw || extra.length || entries.has(key)) return null;
    const parsed = Number(raw);
    if (!Number.isSafeInteger(parsed) || parsed < 0) return null;
    entries.set(key, parsed);
  }
  return entries.has("usage_usec") ? entries.get("usage_usec") : null;
}

export function cgroupCpuUtilization(
  previous,
  current,
  logicalProcessors,
  maximumIntervalMicroseconds = MAXIMUM_CPU_SAMPLE_INTERVAL_MICROSECONDS,
) {
  if (!validCpuSample(previous) || !validCpuSample(current) ||
      current.sampledAtMicroseconds <= previous.sampledAtMicroseconds ||
      current.usageMicroseconds < previous.usageMicroseconds ||
      !Number.isFinite(logicalProcessors) || logicalProcessors <= 0 ||
      !Number.isSafeInteger(maximumIntervalMicroseconds) ||
      maximumIntervalMicroseconds < 1) return null;
  const elapsed = current.sampledAtMicroseconds - previous.sampledAtMicroseconds;
  if (elapsed > maximumIntervalMicroseconds) return null;
  const used = current.usageMicroseconds - previous.usageMicroseconds;
  return Math.min(100, Math.max(0, used / elapsed / logicalProcessors * 100));
}

export function sampleCgroupCpuPercent(options = {}) {
  if ((options.platform ?? process.platform) !== "linux") return null;
  let cpuStatText = options.cpuStatText;
  if (cpuStatText === undefined) {
    try { cpuStatText = readFileSync(CGROUP_V2_CPU_STAT, "utf8"); }
    catch { return null; }
  }
  const usageMicroseconds = parseCpuStatUsage(cpuStatText);
  if (usageMicroseconds === null) return null;
  const sampledAtMicroseconds = options.sampledAtMicroseconds ??
    Number(process.hrtime.bigint() / 1_000n);
  const current = { usageMicroseconds, sampledAtMicroseconds };
  const previous = options.previousSample ?? previousCpuSample;
  if (options.updateState !== false) previousCpuSample = current;
  return cgroupCpuUtilization(
    previous,
    current,
    options.logicalProcessors ?? effectiveCpuCapacity(options),
    options.maximumIntervalMicroseconds,
  );
}

function initialCpuSample() {
  if (process.platform !== "linux") return null;
  try {
    const usageMicroseconds = parseCpuStatUsage(readFileSync(CGROUP_V2_CPU_STAT, "utf8"));
    if (usageMicroseconds === null) return null;
    return {
      usageMicroseconds,
      sampledAtMicroseconds: Number(process.hrtime.bigint() / 1_000n),
    };
  } catch {
    return null;
  }
}

function safeAvailableParallelism() {
  try { return availableParallelism(); }
  catch { return cpus().length; }
}

function positiveInteger(value, fallback) {
  return Number.isSafeInteger(value) && value > 0 ? value : Math.max(1, fallback);
}

function positiveNumber(value, fallback) {
  return Number.isFinite(value) && value > 0 ? value : Math.max(1, fallback);
}

function validCpuSample(value) {
  return value && Number.isSafeInteger(value.usageMicroseconds) &&
    value.usageMicroseconds >= 0 && Number.isSafeInteger(value.sampledAtMicroseconds) &&
    value.sampledAtMicroseconds >= 0;
}
