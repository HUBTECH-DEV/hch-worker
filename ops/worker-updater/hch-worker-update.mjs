#!/usr/bin/env node

import { execFile } from "node:child_process";
import { randomUUID } from "node:crypto";
import { lstat, mkdir, open, realpath, rename, rm, writeFile } from "node:fs/promises";
import { basename, dirname, isAbsolute, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const VERSION_PATTERN = /^(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)$/;

export async function runUpdateHandoff(argv = process.argv.slice(2), options = {}) {
  const parsed = parseArguments(argv);
  const stateDirectory = await canonicalDirectory(
    options.stateDirectory ?? process.env.HCH_WORKER_UPDATE_STATE_DIR,
    "update state directory",
  );
  const backendRoot = await canonicalDirectory(
    options.backendRoot ?? process.env.HCH_WORKER_UPDATE_BACKEND_ROOT,
    "update backend root",
  );
  const backend = await canonicalDirectFile(
    options.backend ?? process.env.HCH_WORKER_UPDATE_BACKEND,
    backendRoot,
    "update backend",
  );
  if (basename(backend) === basename(fileURLToPath(import.meta.url))) {
    throw new Error("update-backend-recursion-refused");
  }
  const lockPath = join(stateDirectory, "worker-release-update.lock");
  let lock;
  try {
    lock = await open(lockPath, "wx", 0o600);
  } catch (error) {
    if (error?.code === "EEXIST") throw new Error("worker-update-busy");
    throw error;
  }
  const operationId = randomUUID();
  const writeStatus = (status, errorCode = null) => atomicJson(stateDirectory, "worker-release-update.json", {
    schema: "hch.worker-release-update/v1",
    schemaVersion: 1,
    operationId,
    targetVersion: parsed.targetVersion,
    status,
    errorCode,
    updatedAt: new Date().toISOString(),
  });
  try {
    await writeStatus("running");
    await executeBackend(options.execFileImpl ?? execFile, backend, [
      "apply",
      "--target-version",
      parsed.targetVersion,
    ], backendRoot);
    await writeStatus("succeeded");
    return { ok: true, targetVersion: parsed.targetVersion, operationId };
  } catch (error) {
    await writeStatus("failed", safeErrorCode(error));
    throw error;
  } finally {
    await lock.close();
    await rm(lockPath, { force: true });
  }
}

function parseArguments(argv) {
  if (argv.length !== 3 || argv[0] !== "apply" || argv[1] !== "--target-version" ||
      !VERSION_PATTERN.test(argv[2])) {
    throw new TypeError("usage: hch-worker-update.mjs apply --target-version X.Y.Z");
  }
  return { targetVersion: argv[2] };
}

async function canonicalDirectory(value, label) {
  if (typeof value !== "string" || !isAbsolute(value)) throw new TypeError(`${label} must be absolute.`);
  const candidate = resolve(value);
  await mkdir(candidate, { recursive: false }).catch((error) => {
    if (error?.code !== "EEXIST") throw error;
  });
  const details = await lstat(candidate);
  const canonical = await realpath(candidate);
  if (!details.isDirectory() || details.isSymbolicLink() || !samePath(canonical, candidate)) {
    throw new TypeError(`${label} must be a canonical directory.`);
  }
  return canonical;
}

async function canonicalDirectFile(value, root, label) {
  if (typeof value !== "string" || !isAbsolute(value)) throw new TypeError(`${label} must be absolute.`);
  const candidate = resolve(value);
  const details = await lstat(candidate);
  const canonical = await realpath(candidate);
  if (!details.isFile() || details.isSymbolicLink() || !samePath(canonical, candidate) ||
      !samePath(dirname(canonical), root)) {
    throw new TypeError(`${label} must be a canonical direct child of its trusted root.`);
  }
  return canonical;
}

function samePath(left, right) {
  const a = resolve(left);
  const b = resolve(right);
  return process.platform === "win32" ? a.toLowerCase() === b.toLowerCase() : a === b;
}

function executeBackend(execFileImpl, backend, args, cwd) {
  return new Promise((resolvePromise, reject) => {
    execFileImpl(backend, args, {
      cwd,
      shell: false,
      windowsHide: true,
      timeout: 60 * 60_000,
      maxBuffer: 64 * 1024,
      encoding: "utf8",
      env: {
        PATH: process.platform === "win32" ? process.env.PATH ?? "" : "/usr/bin:/bin:/usr/sbin:/sbin",
        LANG: "C",
        LC_ALL: "C",
        ...(typeof process.env.HCH_EDITORIAL_WORKER_CONFIG === "string"
          ? { HCH_EDITORIAL_WORKER_CONFIG: process.env.HCH_EDITORIAL_WORKER_CONFIG }
          : {}),
      },
    }, (error) => error ? reject(error) : resolvePromise());
  });
}

async function atomicJson(directory, filename, value) {
  const destination = join(directory, filename);
  const temporary = join(directory, `.${filename}.${process.pid}.${randomUUID()}.tmp`);
  await writeFile(temporary, `${JSON.stringify(value)}\n`, { encoding: "utf8", mode: 0o600, flag: "wx" });
  await rename(temporary, destination);
}

function safeErrorCode(error) {
  const candidate = typeof error?.message === "string" ? error.message : "worker-update-failed";
  return /^[a-z0-9][a-z0-9._:-]{0,127}$/.test(candidate) ? candidate : "worker-update-failed";
}

const entrypoint = process.argv[1] ? resolve(process.argv[1]) : null;
if (entrypoint && entrypoint === resolve(fileURLToPath(import.meta.url))) {
  try {
    const result = await runUpdateHandoff();
    process.stdout.write(`${JSON.stringify(result)}\n`);
  } catch (error) {
    process.stderr.write(`${JSON.stringify({ ok: false, code: safeErrorCode(error) })}\n`);
    process.exitCode = 1;
  }
}
