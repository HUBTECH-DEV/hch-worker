import {
  constants,
  lstat,
  mkdir,
  open,
  readFile,
  realpath,
  rename,
  rm,
  stat,
} from "node:fs/promises";
import { resolve, sep } from "node:path";
import { randomUUID } from "node:crypto";

export const STATE_FILE = "state.json";
export const WORKER_STATUS_FILE = "status.json";
export const METRICS_FILE = "metrics.json";
export const WORKER_CONTROL_FILE = "worker-control.json";
export const ORCHESTRATION_FILE = "orchestration.json";
const READABLE_FILES = new Set([
  STATE_FILE,
  WORKER_STATUS_FILE,
  METRICS_FILE,
  WORKER_CONTROL_FILE,
  ORCHESTRATION_FILE,
]);
const WRITABLE_FILES = new Set([STATE_FILE, METRICS_FILE, ORCHESTRATION_FILE]);
const DEFAULT_MAX_BYTES = 1024 * 1024;
const LOCK_FILE = ".collector.lock";

export async function ensureDataDirectory(dataDirectory) {
  const root = resolve(String(dataDirectory));
  await mkdir(root, { recursive: true, mode: 0o700 });
  const details = await stat(root);
  if (!details.isDirectory()) throw new TypeError("Dashboard data location is not a directory.");
  return root;
}

export async function safeReadJson(
  dataDirectory,
  filename,
  validator,
  options = {},
) {
  const maximumBytes = options.maximumBytes ?? DEFAULT_MAX_BYTES;
  if (!Number.isSafeInteger(maximumBytes) || maximumBytes <= 0) {
    throw new TypeError("maximumBytes must be a positive safe integer.");
  }
  const root = resolve(String(dataDirectory));
  const target = safeTarget(root, filename, READABLE_FILES);
  let handle;
  try {
    const rootReal = await realpath(root);
    const linkDetails = await lstat(target);
    if (linkDetails.isSymbolicLink()) return { ok: false, code: "unsafe-path" };
    const flags = process.platform === "win32" || !constants.O_NOFOLLOW
      ? constants.O_RDONLY
      : constants.O_RDONLY | constants.O_NOFOLLOW;
    handle = await open(target, flags);
    const details = await handle.stat();
    if (!details.isFile()) return { ok: false, code: "not-file" };
    if (details.size > maximumBytes) return { ok: false, code: "too-large" };
    const targetReal = await realpath(target);
    if (!isWithin(rootReal, targetReal)) return { ok: false, code: "unsafe-path" };
    const content = await handle.readFile({ encoding: "utf8" });
    if (Buffer.byteLength(content, "utf8") > maximumBytes) {
      return { ok: false, code: "too-large" };
    }
    let parsed;
    try {
      parsed = JSON.parse(content);
    } catch {
      return { ok: false, code: "invalid-json" };
    }
    try {
      return { ok: true, value: validator(parsed) };
    } catch {
      return { ok: false, code: "invalid-schema" };
    }
  } catch (error) {
    if (error?.code === "ENOENT") return { ok: false, code: "missing" };
    if (error?.code === "ELOOP") return { ok: false, code: "unsafe-path" };
    return { ok: false, code: "read-error" };
  } finally {
    await handle?.close().catch(() => {});
  }
}

export async function atomicWriteJson(dataDirectory, filename, value) {
  const root = await ensureDataDirectory(dataDirectory);
  const target = safeTarget(root, filename, WRITABLE_FILES);
  const temporary = resolve(
    root,
    `.${filename}.${process.pid}.${randomUUID()}.tmp`,
  );
  if (!isWithin(root, temporary)) throw new TypeError("Unsafe temporary path.");
  const serialized = `${JSON.stringify(value, null, 2)}\n`;
  let handle;
  try {
    handle = await open(temporary, constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY, 0o600);
    await handle.writeFile(serialized, { encoding: "utf8" });
    await handle.sync();
    await handle.close();
    handle = undefined;
    await replaceAtomically(temporary, target);
    await syncDirectory(root);
  } catch (error) {
    await handle?.close().catch(() => {});
    await rm(temporary, { force: true }).catch(() => {});
    throw error;
  }
}

export async function withCollectorLock(dataDirectory, operation, options = {}) {
  const root = await ensureDataDirectory(dataDirectory);
  const timeoutMilliseconds = options.timeoutMilliseconds ?? 5_000;
  const staleMilliseconds = options.staleMilliseconds ?? 30_000;
  const startedAt = Date.now();
  const lockPath = resolve(root, LOCK_FILE);
  const lockToken = randomUUID();
  let handle;
  while (!handle) {
    try {
      handle = await open(
        lockPath,
        constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY,
        0o600,
      );
      await handle.writeFile(
        JSON.stringify({
          pid: process.pid,
          acquiredAt: new Date().toISOString(),
          token: lockToken,
        }),
        "utf8",
      );
      await handle.sync();
    } catch (error) {
      if (handle) {
        await handle.close().catch(() => {});
        handle = undefined;
        await rm(lockPath, { force: true }).catch(() => {});
      }
      if (!(await isCollectorLockContention(error, lockPath))) throw error;
      await removeStaleLock(lockPath, staleMilliseconds);
      if (Date.now() - startedAt >= timeoutMilliseconds) {
        throw new Error("Timed out waiting for the dashboard collector lock.");
      }
      await new Promise((resolvePromise) => setTimeout(resolvePromise, 20));
    }
  }
  try {
    return await operation(root);
  } finally {
    await handle.close().catch(() => {});
    await removeOwnedLock(lockPath, lockToken);
  }
}

async function isCollectorLockContention(error, lockPath) {
  if (error?.code === "EEXIST") return true;
  if (process.platform !== "win32" ||
      (error?.code !== "EPERM" && error?.code !== "EACCES")) {
    return false;
  }

  // Windows may surface a sharing violation from O_CREAT | O_EXCL as EPERM or
  // EACCES while another writer is closing/removing the lock. Retry only when
  // the lock is a regular file (or vanished during this check); a real ACL
  // denial on the directory is still returned to the caller immediately.
  try {
    const details = await lstat(lockPath);
    if (details.isSymbolicLink()) {
      throw new Error("Dashboard collector lock must not be a symbolic link.");
    }
    return details.isFile();
  } catch (lockError) {
    if (lockError?.code === "ENOENT") return true;
    if (lockError?.code === "EPERM" || lockError?.code === "EACCES") return false;
    throw lockError;
  }
}

function safeTarget(root, filename, allowedFiles) {
  if (!allowedFiles.has(filename)) throw new TypeError("Unsupported dashboard data file.");
  const target = resolve(root, filename);
  if (!isWithin(root, target)) throw new TypeError("Unsafe dashboard data path.");
  return target;
}

function isWithin(root, target) {
  const normalizedRoot = resolve(root);
  const normalizedTarget = resolve(target);
  const comparisonRoot = process.platform === "win32" ? normalizedRoot.toLowerCase() : normalizedRoot;
  const comparisonTarget = process.platform === "win32" ? normalizedTarget.toLowerCase() : normalizedTarget;
  return comparisonTarget === comparisonRoot || comparisonTarget.startsWith(`${comparisonRoot}${sep}`);
}

async function removeStaleLock(lockPath, staleMilliseconds) {
  try {
    const details = await lstat(lockPath);
    if (details.isSymbolicLink()) {
      throw new Error("Dashboard collector lock must not be a symbolic link.");
    }
    if (!details.isFile() || Date.now() - details.mtimeMs <= staleMilliseconds) return;
    await rm(lockPath, { force: true });
  } catch (error) {
    if (error?.code !== "ENOENT") throw error;
  }
}

async function removeOwnedLock(lockPath, expectedToken) {
  try {
    const content = JSON.parse(await readFile(lockPath, "utf8"));
    if (content?.token === expectedToken) await rm(lockPath, { force: true });
  } catch (error) {
    if (error?.code !== "ENOENT") {
      // The lock may have been recovered as stale; never delete an unknown owner.
    }
  }
}

async function syncDirectory(directory) {
  if (process.platform === "win32") return;
  let handle;
  try {
    handle = await open(directory, constants.O_RDONLY);
    await handle.sync();
  } finally {
    await handle?.close().catch(() => {});
  }
}

async function replaceAtomically(source, target) {
  const retryable = new Set(["EACCES", "EBUSY", "EPERM"]);
  for (let attempt = 0; ; attempt += 1) {
    try {
      await rename(source, target);
      return;
    } catch (error) {
      if (
        process.platform !== "win32" ||
        !retryable.has(error?.code) ||
        attempt >= 20
      ) {
        throw error;
      }
      await new Promise((resolvePromise) =>
        setTimeout(resolvePromise, Math.min(10 + attempt * 5, 50)),
      );
    }
  }
}
