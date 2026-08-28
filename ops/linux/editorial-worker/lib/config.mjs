import { readFile } from "node:fs/promises";
import { isAbsolute, resolve } from "node:path";
import { assertLocalEngineThreadBudget } from "./runtime-resources.mjs";

const CONFIG_KEYS = new Set([
  "schemaVersion",
  "nodeId",
  "keyId",
  "orchestratorBaseUrl",
  "stateDirectory",
  "rootPublicKeyPath",
  "rootPublicKeyFingerprint",
  "rootKeyId",
  "localEngineBaseUrl",
  "localEngineNumThreads",
  "requestedCapacity",
  "artifactMaximumBytes",
  "requestTimeoutMilliseconds",
  "executeRequestTimeoutMilliseconds",
  "requestRetries",
  "enrollmentTokenEnvironment",
]);

export async function loadWorkerConfig(path) {
  const configPath = resolve(String(path));
  let parsed;
  try {
    parsed = JSON.parse(await readFile(configPath, "utf8"));
  } catch (error) {
    throw new Error("Worker config could not be read as JSON.", { cause: error });
  }
  return assertLocalEngineThreadBudget(validateWorkerConfig(parsed));
}

export function validateWorkerConfig(value) {
  const input = plainObject(value, "config");
  const unknown = Object.keys(input).find((key) => !CONFIG_KEYS.has(key));
  if (unknown) throw new TypeError(`Unsupported config field: ${unknown}.`);
  if (input.schemaVersion !== 1) throw new TypeError("config.schemaVersion must be 1.");
  const orchestrator = strictUrl(input.orchestratorBaseUrl, "orchestratorBaseUrl");
  if (orchestrator.protocol !== "https:") {
    throw new TypeError("orchestratorBaseUrl must use HTTPS.");
  }
  if (orchestrator.pathname !== "/" || orchestrator.search || orchestrator.hash) {
    throw new TypeError("orchestratorBaseUrl must contain only scheme and authority.");
  }
  const localEngine = strictUrl(input.localEngineBaseUrl, "localEngineBaseUrl");
  if (!new Set(["http:", "https:"]).has(localEngine.protocol)) {
    throw new TypeError("localEngineBaseUrl must use HTTP or HTTPS.");
  }
  if (!isLoopback(localEngine.hostname)) {
    throw new TypeError("localEngineBaseUrl must resolve explicitly to loopback.");
  }
  if (localEngine.pathname !== "/" || localEngine.search || localEngine.hash) {
    throw new TypeError("localEngineBaseUrl must contain only scheme and authority.");
  }
  const stateDirectory = absolutePath(input.stateDirectory, "stateDirectory");
  const rootPublicKeyPath = absolutePath(input.rootPublicKeyPath, "rootPublicKeyPath");
  const localEngineNumThreads = input.localEngineNumThreads === undefined
    ? null
    : integerInRange(input.localEngineNumThreads, 1, 64, "localEngineNumThreads");
  const requestedCapacity = integerInRange(input.requestedCapacity ?? 1, 0, 64, "requestedCapacity");
  const artifactMaximumBytes = integerInRange(
    input.artifactMaximumBytes ?? 10 * 1024 * 1024,
    1,
    100 * 1024 * 1024,
    "artifactMaximumBytes",
  );
  const requestTimeoutMilliseconds = integerInRange(
    input.requestTimeoutMilliseconds ?? 15_000,
    1_000,
    120_000,
    "requestTimeoutMilliseconds",
  );
  const executeRequestTimeoutMilliseconds = integerInRange(
    input.executeRequestTimeoutMilliseconds ?? 45 * 60_000,
    45 * 60_000,
    2 * 60 * 60_000,
    "executeRequestTimeoutMilliseconds",
  );
  const requestRetries = integerInRange(input.requestRetries ?? 2, 0, 5, "requestRetries");
  return Object.freeze({
    schemaVersion: 1,
    nodeId: identifier(input.nodeId, "nodeId", 128),
    keyId: identifier(input.keyId, "keyId", 160),
    orchestratorBaseUrl: orchestrator.origin,
    stateDirectory,
    rootPublicKeyPath,
    rootPublicKeyFingerprint: fingerprint(
      input.rootPublicKeyFingerprint,
      "rootPublicKeyFingerprint",
    ),
    rootKeyId: identifier(input.rootKeyId, "rootKeyId", 160),
    localEngineBaseUrl: localEngine.origin,
    ...(localEngineNumThreads === null ? {} : { localEngineNumThreads }),
    requestedCapacity,
    artifactMaximumBytes,
    requestTimeoutMilliseconds,
    executeRequestTimeoutMilliseconds,
    requestRetries,
    enrollmentTokenEnvironment: environmentName(
      input.enrollmentTokenEnvironment ?? "HCH_EDITORIAL_ENROLLMENT_TOKEN",
      "enrollmentTokenEnvironment",
    ),
  });
}

function strictUrl(value, name) {
  if (typeof value !== "string") throw new TypeError(`${name} must be a URL.`);
  let url;
  try {
    url = new URL(value);
  } catch {
    throw new TypeError(`${name} must be a URL.`);
  }
  if (url.username || url.password) throw new TypeError(`${name} must not contain credentials.`);
  return url;
}

function isLoopback(hostname) {
  const normalized = hostname.toLowerCase().replace(/^\[|\]$/g, "");
  return normalized === "localhost" || normalized === "127.0.0.1" || normalized === "::1";
}

function absolutePath(value, name) {
  if (typeof value !== "string" || !isAbsolute(value)) {
    throw new TypeError(`${name} must be an absolute path.`);
  }
  return resolve(value);
}

function identifier(value, name, maximum) {
  if (
    typeof value !== "string" ||
    !value ||
    value.length > maximum ||
    !/^[A-Za-z0-9._:@/-]+$/.test(value)
  ) {
    throw new TypeError(`${name} is not a valid identifier.`);
  }
  return value;
}

function fingerprint(value, name) {
  if (typeof value !== "string" || !/^SHA256:[A-Za-z0-9_-]{43}$/.test(value)) {
    throw new TypeError(`${name} must be an Ed25519 SHA256 fingerprint.`);
  }
  return value;
}

function environmentName(value, name) {
  if (typeof value !== "string" || !/^[A-Za-z_][A-Za-z0-9_]{0,127}$/.test(value)) {
    throw new TypeError(`${name} must be a portable environment variable name.`);
  }
  return value;
}

function integerInRange(value, minimum, maximum, name) {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    throw new TypeError(`${name} must be an integer between ${minimum} and ${maximum}.`);
  }
  return value;
}

function plainObject(value, name) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new TypeError(`${name} must be an object.`);
  }
  return value;
}
