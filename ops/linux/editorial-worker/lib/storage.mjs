import {
  constants,
  lstat,
  mkdir,
  open,
  readFile,
  rename,
  rm,
} from "node:fs/promises";
import { dirname, isAbsolute, relative, resolve, sep } from "node:path";
import { randomUUID } from "node:crypto";

const MAX_JSON_BYTES = 4 * 1024 * 1024;

export async function ensurePrivateDirectory(path) {
  const directory = resolve(String(path));
  await mkdir(directory, { recursive: true, mode: 0o700 });
  const details = await lstat(directory);
  if (details.isSymbolicLink() || !details.isDirectory()) {
    throw new Error("Worker state directories must be real directories, not symlinks.");
  }
  if (process.platform !== "win32" && (details.mode & 0o077) !== 0) {
    throw new Error("Worker state directories must not grant group or other access.");
  }
  return directory;
}

export function resolveWithin(root, relativePath) {
  if (typeof relativePath !== "string" || !relativePath || isAbsolute(relativePath)) {
    throw new TypeError("State-relative path is invalid.");
  }
  const base = resolve(root);
  const target = resolve(base, relativePath);
  const difference = relative(base, target);
  if (!difference || difference === ".." || difference.startsWith(`..${sep}`) || isAbsolute(difference)) {
    throw new TypeError("State-relative path escapes the state directory.");
  }
  return target;
}

export async function atomicWriteJson(root, relativePath, value, mode = 0o600) {
  return atomicWriteFile(root, relativePath, `${JSON.stringify(value, null, 2)}\n`, mode);
}

export async function atomicWriteFile(root, relativePath, value, mode = 0o600) {
  const target = resolveWithin(root, relativePath);
  await ensurePrivateDirectory(dirname(target));
  await rejectSymlinkIfPresent(target);
  const temporary = `${target}.${process.pid}.${randomUUID()}.tmp`;
  let handle;
  try {
    handle = await open(
      temporary,
      constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY,
      mode,
    );
    await handle.writeFile(value);
    await handle.sync();
    await handle.close();
    handle = undefined;
    await renameWithRetry(temporary, target);
  } catch (error) {
    await handle?.close().catch(() => {});
    await rm(temporary, { force: true }).catch(() => {});
    throw error;
  }
}

export async function readJson(root, relativePath, options = {}) {
  const target = resolveWithin(root, relativePath);
  const bytes = await readSafeFile(target, options.maximumBytes ?? MAX_JSON_BYTES);
  try {
    return JSON.parse(bytes.toString("utf8"));
  } catch (error) {
    throw new Error(`State file ${relativePath} is not valid JSON.`, { cause: error });
  }
}

export async function readOptionalJson(root, relativePath, options = {}) {
  try {
    return await readJson(root, relativePath, options);
  } catch (error) {
    if (error?.code === "ENOENT") return null;
    throw error;
  }
}

export async function readOptionalFile(root, relativePath, maximumBytes = 100 * 1024 * 1024) {
  const target = resolveWithin(root, relativePath);
  try {
    return await readSafeFile(target, maximumBytes);
  } catch (error) {
    if (error?.code === "ENOENT") return null;
    throw error;
  }
}

export async function removeStateFile(root, relativePath) {
  const target = resolveWithin(root, relativePath);
  try {
    const details = await lstat(target);
    if (details.isSymbolicLink() || !details.isFile()) {
      throw new Error("Refusing to remove a symlink or non-regular state file.");
    }
    await rm(target);
  } catch (error) {
    if (error?.code !== "ENOENT") throw error;
  }
}

export async function readSafeText(path, maximumBytes = 1024 * 1024) {
  return (await readSafeFile(resolve(path), maximumBytes)).toString("utf8");
}

export async function readPrivateText(path, maximumBytes = 1024 * 1024) {
  const target = resolve(path);
  const details = await lstat(target);
  if (details.isSymbolicLink() || !details.isFile()) {
    throw new Error("Private key path must be a regular non-symlink file.");
  }
  if (process.platform !== "win32" && (details.mode & 0o077) !== 0) {
    throw new Error("Private key permissions must not grant group or other access.");
  }
  return readSafeText(target, maximumBytes);
}

export async function withWorkerLock(stateDirectory, operation) {
  const root = await ensurePrivateDirectory(stateDirectory);
  const lockPath = resolve(root, ".worker.lock");
  let handle;
  try {
    handle = await open(
      lockPath,
      constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY,
      0o600,
    );
    await handle.writeFile(JSON.stringify({ pid: process.pid, at: new Date().toISOString() }));
    await handle.sync();
  } catch (error) {
    if (handle) {
      await handle.close().catch(() => {});
      await rm(lockPath, { force: true }).catch(() => {});
    }
    if (error?.code === "EEXIST") {
      throw new Error("Another worker-kit operation is already in progress.");
    }
    throw error;
  }
  try {
    return await operation(root);
  } finally {
    await handle.close().catch(() => {});
    await rm(lockPath, { force: true }).catch(() => {});
  }
}

async function readSafeFile(target, maximumBytes) {
  const details = await lstat(target);
  if (details.isSymbolicLink() || !details.isFile()) {
    throw new Error("Refusing to read a symlink or non-regular state file.");
  }
  if (details.size > maximumBytes) throw new Error("State file exceeds its size limit.");
  const bytes = await readFile(target);
  if (bytes.byteLength > maximumBytes) throw new Error("State file exceeds its size limit.");
  return bytes;
}

async function rejectSymlinkIfPresent(target) {
  try {
    const details = await lstat(target);
    if (details.isSymbolicLink()) throw new Error("Refusing to replace a symlink.");
  } catch (error) {
    if (error?.code !== "ENOENT") throw error;
  }
}

async function renameWithRetry(source, target) {
  const retryable = new Set(["EACCES", "EBUSY", "EPERM"]);
  for (let attempt = 0; ; attempt += 1) {
    try {
      await rename(source, target);
      return;
    } catch (error) {
      if (!retryable.has(error?.code) || attempt >= 10) throw error;
      await new Promise((resolvePromise) => setTimeout(resolvePromise, 10 + attempt * 5));
    }
  }
}
