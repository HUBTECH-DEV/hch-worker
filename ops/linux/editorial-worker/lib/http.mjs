import {
  canonicalizeJson,
  signWorkerRequest,
} from "../crypto.mjs";
import { WorkerKitError } from "./errors.mjs";

const JSON_CONTENT_TYPE = "application/json";
const MAX_JSON_RESPONSE_BYTES = 4 * 1024 * 1024;

export function createTrafficCounter() {
  return { requestBytes: 0, responseBytes: 0 };
}

export async function enrollWorker(
  config,
  identity,
  enrollmentToken,
  options = {},
) {
  const normalizedToken = typeof enrollmentToken === "string"
    ? enrollmentToken.trim()
    : "";
  if (!normalizedToken) {
    throw new WorkerKitError(
      "enrollment-token-missing",
      `Enrollment requested but ${config.enrollmentTokenEnvironment} is not available.`,
    );
  }
  if (Buffer.byteLength(normalizedToken) > 16 * 1024 || /[\0\r\n]/.test(normalizedToken)) {
    throw new WorkerKitError(
      "enrollment-token-invalid",
      "The enrollment token is outside the accepted credential format.",
    );
  }
  const body = canonicalizeJson({
    expiresAt: null,
    keyId: identity.keyId,
    nodeId: identity.nodeId,
    publicKeyPem: identity.publicKeyPem.trim(),
  });
  return requestJson(
    new URL("/api/editorial/orchestrator/enrollment", config.orchestratorBaseUrl),
    {
      method: "POST",
      headers: {
        Authorization: `Bearer ${normalizedToken}`,
        "Content-Type": JSON_CONTENT_TYPE,
      },
      body,
    },
    config,
    options,
  );
}

export async function fetchSignedManifest(config, options = {}) {
  return requestJson(
    new URL("/api/editorial/orchestrator/manifest", config.orchestratorBaseUrl),
    { method: "GET", headers: { Accept: JSON_CONTENT_TYPE } },
    config,
    options,
  );
}

export async function signedPost(
  config,
  identity,
  { path, purpose, bodyText, requestId },
  options = {},
) {
  const target = orchestratorTarget(config, path);
  const retries = options.requestRetries ?? config.requestRetries;
  const deadlineAt = options.totalDeadlineMilliseconds === undefined
    ? null
    : Date.now() + options.totalDeadlineMilliseconds;
  let lastError;
  for (let attempt = 0; attempt <= retries; attempt += 1) {
    try {
      const challengeOptions = boundedDeadlineOptions(options, deadlineAt);
      const challenge = await requestSignedChallenge(
        config,
        identity,
        purpose,
        challengeOptions,
      );
      const now = Math.floor(Date.now() / 1000);
      const challengeExpires = Math.floor(Date.parse(challenge.expiresAt) / 1000);
      const expires = Math.min(now + 120, challengeExpires);
      if (!Number.isSafeInteger(expires) || expires <= now) {
        throw new WorkerKitError(
          "challenge-expired",
          "The operation challenge is already expired.",
          { retryable: true },
        );
      }
      const signed = await signWorkerRequest({
        method: "POST",
        authority: target.host,
        path: target.pathname,
        contentType: JSON_CONTENT_TYPE,
        body: bodyText,
        nodeId: identity.nodeId,
        keyId: identity.keyId,
        requestId,
        created: now,
        expires,
        nonce: challenge.nonce,
      }, identity.privateKeyPem);
      const operationOptions = boundedDeadlineOptions(options, deadlineAt);
      return await requestJson(target, {
        method: "POST",
        headers: signed.headers,
        body: bodyText,
      }, config, {
        ...operationOptions,
        timeoutMilliseconds:
          operationOptions.operationTimeoutMilliseconds ??
          operationOptions.timeoutMilliseconds ?? config.requestTimeoutMilliseconds,
      });
    } catch (error) {
      lastError = error;
      if (!error?.retryable || attempt >= retries) throw error;
    }
  }
  throw lastError;
}

function boundedDeadlineOptions(options, deadlineAt) {
  if (deadlineAt === null) return options;
  const remaining = deadlineAt - Date.now();
  if (remaining < 1) {
    throw new WorkerKitError(
      "heartbeat-deadline-exceeded",
      "The signed heartbeat exceeded its total cadence deadline.",
    );
  }
  return {
    ...options,
    timeoutMilliseconds: Math.min(
      options.timeoutMilliseconds ?? remaining,
      remaining,
    ),
    operationTimeoutMilliseconds: Math.min(
      options.operationTimeoutMilliseconds ?? remaining,
      remaining,
    ),
  };
}

export async function downloadArtifact(config, artifact, options = {}) {
  const url = new URL(artifact.url, config.orchestratorBaseUrl);
  const controlPlane = new URL(config.orchestratorBaseUrl);
  if (url.origin !== controlPlane.origin) {
    throw new WorkerKitError(
      "artifact-origin-refused",
      "Artifact URL is not on the configured control-plane origin.",
    );
  }
  if (!url.pathname.startsWith("/api/editorial/orchestrator/artifacts/")) {
    throw new WorkerKitError(
      "artifact-path-refused",
      "Artifact URL is outside the orchestrator artifact namespace.",
    );
  }
  const response = await performFetch(url, {
    method: "GET",
    headers: { Accept: artifact.mediaType },
  }, config, options);
  const bytes = await responseBytes(
    response,
    Math.min(config.artifactMaximumBytes, artifact.bytes),
    options.traffic,
  );
  if (!response.ok) throw responseError(response, bytes);
  return { bytes, headers: response.headers };
}

export async function queryLocalModel(config, options = {}) {
  const target = new URL("/api/tags", config.localEngineBaseUrl);
  const response = await performFetch(target, {
    method: "GET",
    headers: { Accept: JSON_CONTENT_TYPE },
  }, config, options);
  const bytes = await responseBytes(response, MAX_JSON_RESPONSE_BYTES, options.traffic);
  if (!response.ok) throw responseError(response, bytes, "local-engine-unavailable");
  let payload;
  try {
    payload = JSON.parse(bytes.toString("utf8"));
  } catch {
    throw new WorkerKitError(
      "local-engine-invalid-json",
      "The local /api/tags response is not valid JSON.",
    );
  }
  return {
    payload,
    observedEngineVersion:
      stringOrNull(payload?.version) ??
      stringOrNull(response.headers.get("x-ollama-version")) ??
      null,
  };
}

async function requestSignedChallenge(config, identity, purpose, options) {
  const bodyText = canonicalizeJson({
    keyId: identity.keyId,
    nodeId: identity.nodeId,
    purpose,
  });
  const requestId = crypto.randomUUID();
  const target = orchestratorTarget(
    config,
    "/api/editorial/orchestrator/challenge",
  );
  let lastError;
  const retries = options.requestRetries ?? config.requestRetries;
  for (let attempt = 0; attempt <= retries; attempt += 1) {
    try {
      const now = Math.floor(Date.now() / 1000);
      const signed = await signWorkerRequest({
        method: "POST",
        authority: target.host,
        path: target.pathname,
        contentType: JSON_CONTENT_TYPE,
        body: bodyText,
        nodeId: identity.nodeId,
        keyId: identity.keyId,
        requestId,
        created: now,
        expires: now + 120,
        nonce: `client-${crypto.randomUUID()}-${crypto.randomUUID()}`,
      }, identity.privateKeyPem);
      const challenge = await requestJson(target, {
        method: "POST",
        headers: signed.headers,
        body: bodyText,
      }, config, options);
      if (
        challenge?.nodeId !== identity.nodeId ||
        challenge?.keyId !== identity.keyId ||
        challenge?.purpose !== purpose ||
        typeof challenge?.nonce !== "string" ||
        challenge.nonce.length < 16 ||
        challenge.nonce.length > 512 ||
        !Number.isFinite(Date.parse(challenge.expiresAt)) ||
        challenge.signatureProfile !== "hch-editorial-worker-request/v1"
      ) {
        throw new WorkerKitError(
          "challenge-response-invalid",
          "The orchestrator returned an invalid challenge.",
        );
      }
      return challenge;
    } catch (error) {
      lastError = error;
      if (!error?.retryable || attempt >= retries) throw error;
    }
  }
  throw lastError;
}

async function requestJson(url, init, config, options) {
  const bodyLength = init.body ? Buffer.byteLength(init.body) : 0;
  if (options.traffic) options.traffic.requestBytes += bodyLength;
  const response = await performFetch(url, init, config, options);
  const bytes = await responseBytes(response, MAX_JSON_RESPONSE_BYTES, options.traffic);
  if (!response.ok) throw responseError(response, bytes);
  try {
    return JSON.parse(bytes.toString("utf8"));
  } catch {
    throw new WorkerKitError(
      "orchestrator-invalid-json",
      "The orchestrator response is not valid JSON.",
    );
  }
}

async function performFetch(url, init, config, options) {
  const fetchImpl = options.fetchImpl ?? fetch;
  const timeoutMilliseconds =
    options.timeoutMilliseconds ?? config.requestTimeoutMilliseconds;
  const timeoutSignal = options.timeoutSignalFactory ?? AbortSignal.timeout;
  let response;
  try {
    response = await fetchImpl(url, {
      ...init,
      redirect: "error",
      signal: timeoutSignal(timeoutMilliseconds),
    });
  } catch (error) {
    throw new WorkerKitError(
      "network-request-failed",
      "A network request failed before a trusted response was received.",
      { cause: error, retryable: true },
    );
  }
  if (!(response instanceof Response)) {
    throw new WorkerKitError(
      "network-response-invalid",
      "The HTTP client returned an invalid response object.",
    );
  }
  return response;
}

async function responseBytes(response, maximumBytes, traffic) {
  const declared = Number(response.headers.get("content-length"));
  if (Number.isFinite(declared) && declared > maximumBytes) {
    throw new WorkerKitError("response-too-large", "HTTP response exceeds its size limit.");
  }
  const chunks = [];
  let total = 0;
  if (response.body) {
    const reader = response.body.getReader();
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > maximumBytes) {
        await reader.cancel().catch(() => {});
        throw new WorkerKitError("response-too-large", "HTTP response exceeds its size limit.");
      }
      chunks.push(Buffer.from(value));
    }
  }
  if (traffic) traffic.responseBytes += total;
  return Buffer.concat(chunks, total);
}

function responseError(response, bytes, fallback = "orchestrator-request-rejected") {
  let code = fallback;
  try {
    const payload = JSON.parse(bytes.toString("utf8"));
    if (typeof payload?.code === "string") code = payload.code;
  } catch {
    // Remote error bodies are deliberately not surfaced.
  }
  if (!/^[a-z0-9][a-z0-9._-]{0,95}$/i.test(code)) code = fallback;
  const error = new WorkerKitError(code, `HTTP request was rejected with status ${response.status}.`, {
    retryable: response.status === 429 || response.status >= 500,
  });
  error.status = response.status;
  if (response.status === 409) {
    try {
      const payload = JSON.parse(bytes.toString("utf8"));
      if (payload && typeof payload === "object" && !Array.isArray(payload)) {
        error.responsePayload = payload;
      }
    } catch {
      // Invalid error bodies are never surfaced.
    }
  }
  return error;
}

function orchestratorTarget(config, path) {
  if (typeof path !== "string" || !path.startsWith("/") || path.includes("?") || path.includes("#")) {
    throw new TypeError("Signed request path must be an absolute pathname.");
  }
  const target = new URL(path, config.orchestratorBaseUrl);
  if (target.origin !== new URL(config.orchestratorBaseUrl).origin) {
    throw new TypeError("Signed request target left the configured origin.");
  }
  return target;
}

function stringOrNull(value) {
  return typeof value === "string" && value.trim() ? value.trim().slice(0, 160) : null;
}
