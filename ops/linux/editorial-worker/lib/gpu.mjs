import { execFile as execFileCallback } from "node:child_process";
import { promisify } from "node:util";

const execFile = promisify(execFileCallback);
const NVIDIA_SMI = "/usr/bin/nvidia-smi";
const NVIDIA_QUERY_ARGS = Object.freeze([
  "--query-gpu=utilization.gpu",
  "--format=csv,noheader,nounits",
]);
const GPU_STATUSES = new Set(["available", "unsupported", "unavailable"]);
const GPU_ERROR_CODE = /^[a-z0-9._-]{1,96}$/;

export async function sampleNvidiaGpu(options = {}) {
  if ((options.platform ?? process.platform) !== "linux") {
    return unavailableGpu("unsupported", null);
  }
  const run = options.execFile ?? execFile;
  try {
    const result = await run(NVIDIA_SMI, NVIDIA_QUERY_ARGS, {
      encoding: "utf8",
      timeout: 5_000,
      maxBuffer: 4_096,
      windowsHide: true,
      env: {
        LANG: "C",
        LC_ALL: "C",
        PATH: "/usr/bin:/bin",
      },
    });
    const stdout = typeof result === "string" ? result : result?.stdout;
    const percentages = String(stdout ?? "")
      .split(/\r?\n/)
      .map((line) => line.trim())
      .filter(Boolean)
      .map(Number);
    if (!percentages.length || percentages.some((value) =>
      !Number.isFinite(value) || value < 0 || value > 100)) {
      return unavailableGpu("unavailable", "gpu-probe-invalid");
    }
    return validateGpuSample({
      available: true,
      status: "available",
      utilizationPercent: Math.max(...percentages),
      errorCode: null,
    });
  } catch (error) {
    if (error?.code === "ENOENT") return unavailableGpu("unsupported", null);
    return unavailableGpu("unavailable", "gpu-probe-failed");
  }
}

export function validateGpuSample(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new TypeError("GPU sample must be an object.");
  }
  const status = value.status;
  if (!GPU_STATUSES.has(status)) {
    throw new TypeError("GPU sample status is invalid.");
  }
  if (status === "available") {
    if (value.available !== true || value.errorCode !== null ||
        !Number.isFinite(value.utilizationPercent) ||
        value.utilizationPercent < 0 || value.utilizationPercent > 100) {
      throw new TypeError("Available GPU sample is inconsistent.");
    }
    return Object.freeze({
      available: true,
      status,
      utilizationPercent: value.utilizationPercent,
      errorCode: null,
    });
  }
  const errorCode = value.errorCode;
  if (value.available !== false || value.utilizationPercent !== null ||
      (status === "unsupported" && errorCode !== null) ||
      (status === "unavailable" &&
       (typeof errorCode !== "string" || !GPU_ERROR_CODE.test(errorCode)))) {
    throw new TypeError("Unavailable GPU sample is inconsistent.");
  }
  return Object.freeze({
    available: false,
    status,
    utilizationPercent: null,
    errorCode,
  });
}

function unavailableGpu(status, errorCode) {
  return validateGpuSample({
    available: false,
    status,
    utilizationPercent: null,
    errorCode,
  });
}
