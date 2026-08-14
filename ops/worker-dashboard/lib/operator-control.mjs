const WINDOWS_FIELDS = new Set([
  "schema",
  "schemaVersion",
  "nodeId",
  "acceptingClaims",
  "requestedParallelism",
  "lastNonZeroParallelism",
  "drainRequested",
  "updatedAt",
  "updatedBy",
]);
const PORTABLE_FIELDS = new Set([
  "schema",
  "schemaVersion",
  "nodeId",
  "workerKeyId",
  "acceptingClaims",
  "requestedCapacity",
  "lastNonZeroCapacity",
  "drainRequested",
  "updatedAt",
  "updatedBy",
]);

export function parseWorkerOperatorControl(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new TypeError("worker control must be an object");
  }
  const keys = Object.keys(value);
  const windows = exactFields(keys, WINDOWS_FIELDS);
  const portable = exactFields(keys, PORTABLE_FIELDS);
  if (!windows && !portable) {
    throw new TypeError("worker control fields are invalid");
  }
  if (value.schema !== "hch.worker-control/v1" || value.schemaVersion !== 1) {
    throw new TypeError("worker control schema is unsupported");
  }
  if (typeof value.nodeId !== "string" ||
      !/^[a-z0-9][a-z0-9._-]{2,63}$/.test(value.nodeId)) {
    throw new TypeError("worker control node is invalid");
  }
  if (typeof value.acceptingClaims !== "boolean" ||
      typeof value.drainRequested !== "boolean") {
    throw new TypeError("worker control flags are invalid");
  }
  if (portable && (typeof value.workerKeyId !== "string" ||
      !/^[A-Za-z0-9._:@/-]{1,160}$/.test(value.workerKeyId))) {
    throw new TypeError("worker control key is invalid");
  }
  const requestedParallelism = boundedInteger(
    portable ? value.requestedCapacity : value.requestedParallelism,
    0,
    64,
  );
  const lastNonZeroParallelism = boundedInteger(
    portable ? value.lastNonZeroCapacity : value.lastNonZeroParallelism,
    1,
    64,
  );
  if (value.acceptingClaims === value.drainRequested ||
      (value.acceptingClaims && requestedParallelism === 0) ||
      (requestedParallelism > 0 && requestedParallelism !== lastNonZeroParallelism)) {
    throw new TypeError("worker control state is inconsistent");
  }
  const updatedAt = normalizedTimestamp(value.updatedAt);
  if (typeof value.updatedBy !== "string" ||
      !/^[a-z0-9][a-z0-9._-]{0,63}$/.test(value.updatedBy)) {
    throw new TypeError("worker control updater is invalid");
  }
  return Object.freeze({
    nodeId: value.nodeId,
    workerKeyId: portable ? value.workerKeyId : null,
    acceptingClaims: value.acceptingClaims,
    drainRequested: value.drainRequested,
    requestedParallelism,
    lastNonZeroParallelism,
    updatedAt,
  });
}

function exactFields(keys, expected) {
  return keys.length === expected.size && keys.every((key) => expected.has(key));
}

function boundedInteger(value, minimum, maximum) {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    throw new TypeError("worker control parallelism is invalid");
  }
  return value;
}

function normalizedTimestamp(value) {
  if (typeof value !== "string" ||
      !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,7})?(?:Z|[+-]\d{2}:\d{2})$/.test(value)) {
    throw new TypeError("worker control timestamp is invalid");
  }
  const milliseconds = Date.parse(value);
  if (!Number.isFinite(milliseconds)) throw new TypeError("worker control timestamp is invalid");
  return new Date(milliseconds).toISOString();
}
