#!/usr/bin/env node

import { createServer } from "node:http";
import { lstat, readFile, realpath } from "node:fs/promises";
import { randomBytes, timingSafeEqual } from "node:crypto";
import { fileURLToPath, pathToFileURL } from "node:url";
import { resolve } from "node:path";

import { buildDashboardStatus } from "./lib/status.mjs";
import { createReleaseMonitor } from "./lib/releases.mjs";
import { readContributorStatus } from "./lib/contributor.mjs";
import {
  executeWorkerControlAction,
  resolveWorkerControlConfig,
  WorkerControlExecutionError,
} from "./lib/control.mjs";

const PACKAGE_DIRECTORY = fileURLToPath(new URL(".", import.meta.url));
const DEFAULT_DATA_DIRECTORY = resolve(PACKAGE_DIRECTORY, "data");
const PUBLIC_DIRECTORY = resolve(PACKAGE_DIRECTORY, "public");
const PROCESS_STARTED_AT = new Date();
const LOOPBACK_HOSTS = new Set(["127.0.0.1", "::1", "localhost"]);

const STATIC_ROUTES = new Map([
  ["/", { file: "index.html", type: "text/html; charset=utf-8" }],
  ["/app.css", { file: "app.css", type: "text/css; charset=utf-8" }],
  ["/app.js", { file: "app.js", type: "text/javascript; charset=utf-8" }],
  ["/batch-progress.js", { file: "batch-progress.js", type: "text/javascript; charset=utf-8" }],
  ["/control-state.js", { file: "control-state.js", type: "text/javascript; charset=utf-8" }],
]);

export function resolveDashboardConfig(options = {}) {
  const host = String(
    options.host ?? process.env.HCH_WORKER_DASHBOARD_HOST ?? "127.0.0.1",
  ).trim().toLowerCase();
  if (!LOOPBACK_HOSTS.has(host)) {
    throw new TypeError("Dashboard host must be a loopback address or localhost.");
  }
  const portValue = options.port ?? process.env.HCH_WORKER_DASHBOARD_PORT ?? 4319;
  const port = typeof portValue === "string" && /^\d+$/.test(portValue)
    ? Number(portValue)
    : portValue;
  if (!Number.isSafeInteger(port) || port < 0 || port > 65_535) {
    throw new TypeError("Dashboard port must be an integer between 0 and 65535.");
  }
  return {
    host,
    port,
    dataDirectory: resolve(
      options.dataDirectory ??
        process.env.HCH_WORKER_DASHBOARD_DATA_DIR ??
        DEFAULT_DATA_DIRECTORY,
    ),
    staleAfterMilliseconds: options.staleAfterMilliseconds ?? 120_000,
    releaseRepository: options.releaseRepository ??
      process.env.HCH_WORKER_RELEASE_REPOSITORY ?? "HUBTECH-DEV/hch-worker",
    releaseCheckIntervalMilliseconds: options.releaseCheckIntervalMilliseconds ??
      process.env.HCH_WORKER_RELEASE_CHECK_INTERVAL_MS ?? 15 * 60_000,
    hihPairingUrl: normalizeHihPairingUrl(
      options.hihPairingUrl ?? process.env.HCH_WORKER_HIH_PAIRING_URL ?? null,
    ),
    workerControl: resolveWorkerControlConfig({
      driver: options.controlDriver,
      workerCliPath: options.workerCliPath,
      workerConfigPath: options.workerConfigPath,
      powershellPath: options.powershellPath,
      controlScriptPath: options.controlScriptPath,
      workerCliRootPath: options.workerCliRootPath,
      workerConfigRootPath: options.workerConfigRootPath,
      powershellRootPath: options.powershellRootPath,
      controlScriptRootPath: options.controlScriptRootPath,
      updateScriptPath: options.updateScriptPath ?? process.env.HCH_WORKER_UPDATE_SCRIPT,
      updateScriptRootPath: options.updateScriptRootPath ?? process.env.HCH_WORKER_UPDATE_SCRIPT_ROOT,
      controlTimeoutMilliseconds: options.controlTimeoutMilliseconds,
      controlPlaneTimeoutSeconds: options.controlPlaneTimeoutSeconds,
    }),
  };
}

export function createDashboardServer(options = {}) {
  const config = resolveDashboardConfig(options);
  const processStartedAt = options.processStartedAt ?? PROCESS_STARTED_AT;
  const control = createControlState(config.workerControl, {
    execFileImpl: options.controlExecFile,
    now: options.controlNow,
    csrfToken: options.controlCsrfToken,
  });
  const releaseMonitor = options.releaseMonitor ?? createReleaseMonitor({
    repository: config.releaseRepository,
    intervalMilliseconds: config.releaseCheckIntervalMilliseconds,
    fetchImpl: options.releaseFetch,
    now: options.releaseNow,
  });
  const server = createServer(async (request, response) => {
    try {
      await handleRequest(request, response, {
        ...config,
        processStartedAt,
        now: options.now,
        control,
        releaseMonitor,
      });
    } catch {
      sendJson(response, 500, { error: "dashboard-internal-error" }, true);
    }
  });
  server.on("clientError", (_error, socket) => {
    if (socket.writable) socket.end("HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n");
  });
  server.headersTimeout = 5_000;
  server.requestTimeout = 10_000;
  server.keepAliveTimeout = 5_000;
  server.maxHeadersCount = 64;
  return { server, config };
}

export async function listenDashboard(options = {}) {
  const { server, config } = createDashboardServer(options);
  await new Promise((resolvePromise, reject) => {
    server.once("error", reject);
    server.listen(config.port, config.host, () => {
      server.off("error", reject);
      resolvePromise();
    });
  });
  return { server, config, address: server.address() };
}

async function handleRequest(request, response, context) {
  const method = request.method ?? "GET";
  let target;
  try {
    target = new URL(request.url ?? "/", "http://dashboard.local");
  } catch {
    sendJson(response, 400, { error: "invalid-request-target" }, true, method === "HEAD");
    return;
  }
  if (!isLoopbackClient(request) || !trustedLocalRequestOrigin(request)) {
    sendJson(response, 403, { error: "local-request-required" }, true, method === "HEAD");
    return;
  }
  const pathname = target.pathname;
  if (pathname === "/api/control") {
    if (target.search || target.hash) {
      sendJson(response, 400, { error: "invalid-request-target" }, true, method === "HEAD");
      return;
    }
    if (method === "GET" || method === "HEAD") {
      sendJson(response, 200, context.control.snapshot(true), true, method === "HEAD");
      return;
    }
    if (method === "POST") {
      await handleControlPost(request, response, context);
      return;
    }
    response.setHeader("Allow", "GET, HEAD, POST");
    sendJson(response, 405, { error: "method-not-allowed" }, true);
    return;
  }
  if (method !== "GET" && method !== "HEAD") {
    response.setHeader("Allow", "GET, HEAD");
    sendJson(response, 405, { error: "method-not-allowed" }, true, method === "HEAD");
    return;
  }
  if (pathname === "/api/status") {
    const status = await buildDashboardStatus(context.dataDirectory, {
      now: context.now,
      processStartedAt: context.processStartedAt,
      staleAfterMilliseconds: context.staleAfterMilliseconds,
    });
    const updates = await context.releaseMonitor.snapshot(status.worker.version);
    sendJson(response, 200, {
      ...status,
      updates,
      control: context.control.snapshot(false),
    }, true, method === "HEAD");
    return;
  }
  if (pathname === "/api/contributor") {
    const contributor = await readContributorStatus(context.dataDirectory, {
      now: context.now,
      pairingUrl: context.hihPairingUrl,
    });
    sendJson(response, 200, contributor, true, method === "HEAD");
    return;
  }
  if (pathname === "/api/identity") {
    const identity = await readPublicWorkerIdentity(context.dataDirectory);
    sendJson(response, identity ? 200 : 404, identity ?? { error:"worker-public-identity-unavailable" }, true, method === "HEAD");
    return;
  }
  const asset = STATIC_ROUTES.get(pathname);
  if (!asset) {
    sendJson(response, 404, { error: "not-found" }, true, method === "HEAD");
    return;
  }
  const body = await readFile(resolve(PUBLIC_DIRECTORY, asset.file));
  setSecurityHeaders(response);
  response.statusCode = 200;
  response.setHeader("Content-Type", asset.type);
  response.setHeader("Content-Length", body.byteLength);
  response.setHeader("Cache-Control", asset.file === "index.html"
    ? "no-store"
    : "public, max-age=300, must-revalidate");
  response.end(method === "HEAD" ? undefined : body);
}

async function readPublicWorkerIdentity(dataDirectory) {
  const root = await realpath(resolve(dataDirectory));
  const identityDirectory = resolve(root,"identity");
  const metadataPath = resolve(identityDirectory,"identity.json");
  const publicKeyPath = resolve(identityDirectory,"worker-public.spki.pem");
  try {
    for (const path of [metadataPath,publicKeyPath]) {
      const details=await lstat(path); if(!details.isFile()||details.isSymbolicLink()) return null;
      const canonical=await realpath(path); if(!canonical.startsWith(identityDirectory + (process.platform==="win32"?"\\":"/"))) return null;
    }
    const metadata=JSON.parse(await readFile(metadataPath,"utf8"));
    const publicKeyPem=(await readFile(publicKeyPath,"utf8")).trim();
    if(!/^-----BEGIN PUBLIC KEY-----[\s\S]+-----END PUBLIC KEY-----$/.test(publicKeyPem)) return null;
    const nodeId=String(metadata.nodeId??""); const keyId=String(metadata.keyId??""); const fingerprint=String(metadata.fingerprint??keyId);
    if(!nodeId||!keyId||!fingerprint) return null;
    return {nodeId,keyId,fingerprint,algorithm:"Ed25519",publicKeyPem};
  } catch { return null; }
}

async function handleControlPost(request, response, context) {
  try {
    assertControlRequestHeaders(request, context.control);
    const payload = await readControlPayload(request);
    if (payload.action === "start" ||
        (payload.action === "set-parallelism" && payload.parallelism > 0)) {
      const contributor = await readContributorStatus(context.dataDirectory, {
        now: context.now,
        pairingUrl: context.hihPairingUrl,
      });
      if (!contributor.readyForContribution) {
        throw new ControlHttpError(403, "contributor-not-authorized");
      }
    }
    let requested = payload;
    if (payload.action === "update") {
      const current = await buildDashboardStatus(context.dataDirectory, {
        now: context.now,
        processStartedAt: context.processStartedAt,
        staleAfterMilliseconds: context.staleAfterMilliseconds,
      });
      const updates = await context.releaseMonitor.snapshot(current.worker.version, { force: true });
      if (!updates.updateAvailable || !updates.latestVersion) {
        throw new ControlHttpError(409, "worker-update-not-available");
      }
      requested = { action: "update", targetVersion: updates.latestVersion };
    }
    const result = await context.control.run(requested);
    const status = await buildDashboardStatus(context.dataDirectory, {
      now: context.now,
      processStartedAt: context.processStartedAt,
      staleAfterMilliseconds: context.staleAfterMilliseconds,
    });
    sendJson(response, 200, {
      ok: true,
      action: result.action,
      requestedState: result.requestedState,
      ...(result.parallelism === undefined ? {} : { parallelism: result.parallelism }),
      control: context.control.snapshot(false),
      worker: { state: status.worker.state },
      capacity: status.capacity,
    }, true);
  } catch (error) {
    if (error instanceof ControlHttpError) {
      sendJson(response, error.statusCode, { error: error.code }, true);
      return;
    }
    if (error instanceof WorkerControlExecutionError) {
      const statusCode = error.code === "worker-control-unavailable" ||
        error.code === "worker-update-unavailable"
        ? 503
        : error.code === "worker-control-busy"
          ? 409
          : error.code === "worker-control-timeout" ? 504 : 502;
      sendJson(response, statusCode, { error: error.code }, true);
      return;
    }
    sendJson(response, 500, { error: "worker-control-internal-error" }, true);
  }
}

function normalizeHihPairingUrl(value) {
  if (value === null || value === undefined || String(value).trim() === "") return null;
  const text = String(value).trim();
  if (text.length > 2_048) throw new TypeError("HIH pairing URL is too long.");
  let parsed;
  try { parsed = new URL(text); }
  catch { throw new TypeError("HIH pairing URL is invalid."); }
  const loopbackHttp = parsed.protocol === "http:" && isLoopbackName(parsed.hostname);
  if ((parsed.protocol !== "https:" && !loopbackHttp) || parsed.username || parsed.password ||
      parsed.hash || parsed.search) {
    throw new TypeError("HIH pairing URL must be HTTPS without credentials, query, or fragment.");
  }
  return parsed.toString();
}

function createControlState(config, options = {}) {
  const csrfToken = options.csrfToken ?? randomBytes(32).toString("base64url");
  if (typeof csrfToken !== "string" || !/^[A-Za-z0-9_-]{43}$/.test(csrfToken)) {
    throw new TypeError("Control CSRF token is invalid.");
  }
  let busy = false;
  let lastAction = null;
  let lastActionAt = null;
  let lastOutcome = null;
  let lastErrorCode = null;
  const now = () => {
    const value = typeof options.now === "function" ? options.now() : options.now ?? new Date();
    return new Date(value).toISOString();
  };
  return {
    snapshot(includeToken) {
      return {
        available: config.enabled === true,
        updateEnabled: config.enabled === true && config.updateEnabled === true,
        busy,
        lastAction,
        lastActionAt,
        lastOutcome,
        lastErrorCode,
        csrfToken: includeToken && config.enabled ? csrfToken : null,
      };
    },
    verifyCsrf(candidate) {
      if (typeof candidate !== "string") return false;
      const expected = Buffer.from(csrfToken, "utf8");
      const observed = Buffer.from(candidate, "utf8");
      return observed.byteLength === expected.byteLength && timingSafeEqual(observed, expected);
    },
    async run(request) {
      if (!config.enabled) throw new WorkerControlExecutionError("worker-control-unavailable");
      if (busy) throw new WorkerControlExecutionError("worker-control-busy");
      busy = true;
      lastAction = request.action;
      lastActionAt = now();
      lastOutcome = "running";
      lastErrorCode = null;
      try {
        const result = await executeWorkerControlAction(config, request, {
          execFileImpl: options.execFileImpl,
        });
        lastOutcome = "succeeded";
        return result;
      } catch (error) {
        lastOutcome = "failed";
        lastErrorCode = error instanceof WorkerControlExecutionError
          ? error.code
          : "worker-control-failed";
        throw error instanceof WorkerControlExecutionError
          ? error
          : new WorkerControlExecutionError("worker-control-failed");
      } finally {
        busy = false;
        lastActionAt = now();
      }
    },
  };
}

function assertControlRequestHeaders(request, control) {
  if (!control.snapshot(false).available) {
    throw new WorkerControlExecutionError("worker-control-unavailable");
  }
  for (const name of [
    "host",
    "origin",
    "content-type",
    "content-length",
    "accept",
    "sec-fetch-site",
    "x-hch-csrf-token",
  ]) {
    if (rawHeaderCount(request, name) !== 1) {
      throw new ControlHttpError(400, "control-header-contract-invalid");
    }
  }
  const expectedOrigin = trustedLocalRequestOrigin(request);
  const observedOrigin = parseHttpOrigin(request.headers.origin);
  if (!expectedOrigin || !observedOrigin || observedOrigin !== expectedOrigin) {
    throw new ControlHttpError(403,"control-origin-rejected");
  }
  if (request.headers["sec-fetch-site"] !== "same-origin") {
    throw new ControlHttpError(403, "control-fetch-site-rejected");
  }
  if (String(request.headers["content-type"]).toLowerCase() !== "application/json" ||
      String(request.headers.accept).toLowerCase() !== "application/json" ||
      request.headers["content-encoding"] !== undefined) {
    throw new ControlHttpError(415, "control-media-type-rejected");
  }
  if (!control.verifyCsrf(request.headers["x-hch-csrf-token"])) {
    throw new ControlHttpError(403, "control-csrf-rejected");
  }
  const contentLength = String(request.headers["content-length"]);
  if (!/^[1-9]\d{0,2}$/.test(contentLength) || Number(contentLength) > 128) {
    throw new ControlHttpError(413, "control-payload-too-large");
  }
}

async function readControlPayload(request) {
  const expectedLength = Number(request.headers["content-length"]);
  const chunks = [];
  let total = 0;
  for await (const chunk of request) {
    total += chunk.byteLength;
    if (total > 128) throw new ControlHttpError(413, "control-payload-too-large");
    chunks.push(chunk);
  }
  if (total !== expectedLength) throw new ControlHttpError(400, "control-payload-length-mismatch");
  let value;
  try {
    const text = new TextDecoder("utf-8", { fatal: true }).decode(Buffer.concat(chunks));
    value = JSON.parse(text);
  } catch {
    throw new ControlHttpError(400, "control-json-invalid");
  }
  const keys = value && typeof value === "object" && !Array.isArray(value)
    ? Object.keys(value) : [];
  const simple = keys.length === 1 && new Set(["start", "pause", "stop", "update"]).has(value?.action);
  const parallel = keys.length === 2 && value?.action === "set-parallelism" &&
    keys.every((key) => new Set(["action", "parallelism"]).has(key)) &&
    Number.isSafeInteger(value.parallelism) && value.parallelism >= 0 && value.parallelism <= 64;
  if (!simple && !parallel) {
    throw new ControlHttpError(400, "control-action-invalid");
  }
  return value;
}

class ControlHttpError extends Error {
  constructor(statusCode, code) {
    super(code);
    this.statusCode = statusCode;
    this.code = code;
  }
}

function rawHeaderCount(request, name) {
  let count = 0;
  for (let index = 0; index < request.rawHeaders.length; index += 2) {
    if (request.rawHeaders[index].toLowerCase() === name) count += 1;
  }
  return count;
}

function isLoopbackClient(request) {
  return isLoopbackName(request.socket.remoteAddress);
}

function trustedLocalRequestOrigin(request) {
  const host = request.headers.host;
  if (typeof host !== "string" || rawHeaderCount(request,"host") !== 1) return null;
  let parsed;
  try { parsed = new URL(`http://${host}`); }
  catch { return null; }
  if (!isLoopbackName(parsed.hostname) || parsed.username || parsed.password) return null;
  const port = parsed.port ? Number(parsed.port) : 80;
  if (!Number.isSafeInteger(port) || port !== request.socket.localPort) return null;
  return parsed.origin;
}

function parseHttpOrigin(value) {
  if (typeof value !== "string") return null;
  try {
    const parsed = new URL(value);
    if (parsed.protocol !== "http:" || !isLoopbackName(parsed.hostname) ||
        parsed.username || parsed.password || parsed.pathname !== "/" || parsed.search || parsed.hash) {
      return null;
    }
    return parsed.origin;
  } catch { return null; }
}

function isLoopbackName(value) {
  const normalized = String(value ?? "").trim().toLowerCase()
    .replace(/^\[/,"").replace(/\]$/,"").replace(/^::ffff:/,"");
  if (normalized === "::1" || normalized === "localhost") return true;
  const parts = normalized.split(".");
  return parts.length === 4 && parts[0] === "127" && parts.every((part) => /^\d{1,3}$/.test(part) && Number(part) <= 255);
}

function sendJson(response, statusCode, value, noStore, head = false) {
  const body = Buffer.from(JSON.stringify(value));
  setSecurityHeaders(response);
  response.statusCode = statusCode;
  response.setHeader("Content-Type", "application/json; charset=utf-8");
  response.setHeader("Content-Length", body.byteLength);
  if (noStore) {
    response.setHeader("Cache-Control", "no-store, max-age=0");
    response.setHeader("Pragma", "no-cache");
    response.setHeader("Expires", "0");
  }
  response.end(head ? undefined : body);
}

function setSecurityHeaders(response) {
  response.setHeader(
    "Content-Security-Policy",
    "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; object-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'",
  );
  response.setHeader("Cross-Origin-Opener-Policy", "same-origin");
  response.setHeader("Cross-Origin-Resource-Policy", "same-origin");
  response.setHeader("Referrer-Policy", "no-referrer");
  response.setHeader("X-Content-Type-Options", "nosniff");
  response.setHeader("X-Frame-Options", "DENY");
}

function parseCliArguments(argv) {
  const options = {};
  const args = [...argv];
  while (args.length) {
    const argument = args.shift();
    if (argument === "--host") options.host = requiredValue(args, argument);
    else if (argument === "--port") options.port = requiredValue(args, argument);
    else if (argument === "--data-dir") options.dataDirectory = requiredValue(args, argument);
    else if (argument === "--worker-cli") options.workerCliPath = requiredValue(args, argument);
    else if (argument === "--worker-config") options.workerConfigPath = requiredValue(args, argument);
    else if (argument === "--control-driver") options.controlDriver = requiredValue(args, argument);
    else if (argument === "--powershell") options.powershellPath = requiredValue(args, argument);
    else if (argument === "--control-script") {
      options.controlScriptPath = requiredValue(args, argument);
    }
    else if (argument === "--worker-cli-root") {
      options.workerCliRootPath = requiredValue(args, argument);
    }
    else if (argument === "--worker-config-root") {
      options.workerConfigRootPath = requiredValue(args, argument);
    }
    else if (argument === "--powershell-root") {
      options.powershellRootPath = requiredValue(args, argument);
    }
    else if (argument === "--control-script-root") {
      options.controlScriptRootPath = requiredValue(args, argument);
    }
    else if (argument === "--update-script") {
      options.updateScriptPath = requiredValue(args, argument);
    }
    else if (argument === "--update-script-root") {
      options.updateScriptRootPath = requiredValue(args, argument);
    }
    else if (argument === "--control-timeout-ms") {
      options.controlTimeoutMilliseconds = requiredValue(args, argument);
    }
    else if (argument === "--control-plane-timeout-seconds") {
      options.controlPlaneTimeoutSeconds = requiredValue(args, argument);
    }
    else if (argument === "--release-repository") {
      options.releaseRepository = requiredValue(args, argument);
    }
    else if (argument === "--release-check-interval-ms") {
      options.releaseCheckIntervalMilliseconds = requiredValue(args, argument);
    }
    else if (argument === "--hih-pairing-url") {
      options.hihPairingUrl = requiredValue(args, argument);
    }
    else throw new TypeError("Unsupported dashboard argument.");
  }
  return options;
}

function requiredValue(args, argument) {
  const value = args.shift();
  if (!value) throw new TypeError(`${argument} requires a value.`);
  return value;
}

const entrypoint = process.argv[1]
  ? pathToFileURL(resolve(process.argv[1])).href
  : null;
if (entrypoint === import.meta.url) {
  try {
    const running = await listenDashboard(parseCliArguments(process.argv.slice(2)));
    const address = running.address;
    const shownHost = address.family === "IPv6" ? `[${address.address}]` : address.address;
    process.stdout.write(`HCH worker dashboard: http://${shownHost}:${address.port}\n`);
  } catch (error) {
    process.stderr.write(`${error instanceof Error ? error.message : "Dashboard failed to start."}\n`);
    process.exitCode = 1;
  }
}
