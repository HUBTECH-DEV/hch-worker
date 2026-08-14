#!/usr/bin/env node

import { randomUUID } from "node:crypto";
import { fileURLToPath, pathToFileURL } from "node:url";
import { resolve } from "node:path";

import {
  EVENT_SCHEMA_VERSION,
  aggregateMetrics,
  applyWorkerStatePatch,
  assertNoSecrets,
  defaultMetrics,
  defaultOrchestration,
  defaultWorkerState,
  parseMetrics,
  parseOrchestration,
  parseWorkerState,
} from "./lib/contracts.mjs";
import {
  METRICS_FILE,
  ORCHESTRATION_FILE,
  STATE_FILE,
  atomicWriteJson,
  safeReadJson,
  withCollectorLock,
} from "./lib/storage.mjs";

const PACKAGE_DIRECTORY = fileURLToPath(new URL(".", import.meta.url));
export const DEFAULT_DATA_DIRECTORY = resolve(PACKAGE_DIRECTORY, "data");
const MAXIMUM_CLI_INPUT_BYTES = 256 * 1024;

export async function initializeCollector(options = {}) {
  const dataDirectory = resolve(options.dataDirectory ?? DEFAULT_DATA_DIRECTORY);
  return withCollectorLock(dataDirectory, async (root) => {
    const stateRead = await safeReadJson(root, STATE_FILE, parseWorkerState);
    const metricsRead = await safeReadJson(root, METRICS_FILE, parseMetrics);
    const orchestrationRead = await safeReadJson(
      root,
      ORCHESTRATION_FILE,
      parseOrchestration,
    );
    if (stateRead.ok === false && stateRead.code !== "missing") {
      throw new Error("Existing worker state is invalid; refusing to overwrite it.");
    }
    if (metricsRead.ok === false && metricsRead.code !== "missing") {
      throw new Error("Existing metrics are invalid; refusing to overwrite them.");
    }
    if (orchestrationRead.ok === false && orchestrationRead.code !== "missing") {
      throw new Error("Existing orchestration state is invalid; refusing to overwrite it.");
    }
    if (!stateRead.ok) await atomicWriteJson(root, STATE_FILE, defaultWorkerState());
    if (!metricsRead.ok) await atomicWriteJson(root, METRICS_FILE, defaultMetrics());
    if (!orchestrationRead.ok) {
      await atomicWriteJson(root, ORCHESTRATION_FILE, defaultOrchestration());
    }
    return { dataDirectory: root, initialized: true };
  });
}

export async function updateWorkerState(patch, options = {}) {
  assertNoSecrets(patch);
  const dataDirectory = resolve(options.dataDirectory ?? DEFAULT_DATA_DIRECTORY);
  return withCollectorLock(dataDirectory, async (root) => {
    const current = await readForUpdate(
      root,
      STATE_FILE,
      parseWorkerState,
      () => defaultWorkerState(options.now),
      "worker state",
    );
    const state = applyWorkerStatePatch(current, patch, options.now ?? new Date());
    await atomicWriteJson(root, STATE_FILE, state);
    return state;
  });
}

export async function recordMetricsEvent(eventInput, options = {}) {
  assertNoSecrets(eventInput);
  const event = normalizeEventInput(eventInput, options.now ?? new Date());
  const dataDirectory = resolve(options.dataDirectory ?? DEFAULT_DATA_DIRECTORY);
  return withCollectorLock(dataDirectory, async (root) => {
    const current = await readForUpdate(
      root,
      METRICS_FILE,
      parseMetrics,
      () => defaultMetrics(options.now),
      "metrics",
    );
    const result = aggregateMetrics(current, event, options.now ?? new Date());
    if (!result.duplicate) await atomicWriteJson(root, METRICS_FILE, result.metrics);
    return { ...result, eventId: event.eventId };
  });
}

export async function updateOrchestration(snapshotInput, options = {}) {
  assertNoSecrets(snapshotInput);
  const snapshot = parseOrchestration(snapshotInput);
  const dataDirectory = resolve(options.dataDirectory ?? DEFAULT_DATA_DIRECTORY);
  return withCollectorLock(dataDirectory, async (root) => {
    await atomicWriteJson(root, ORCHESTRATION_FILE, snapshot);
    return snapshot;
  });
}

export async function readCollectorSnapshot(options = {}) {
  const dataDirectory = resolve(options.dataDirectory ?? DEFAULT_DATA_DIRECTORY);
  const [state, metrics, orchestration] = await Promise.all([
    safeReadJson(dataDirectory, STATE_FILE, parseWorkerState),
    safeReadJson(dataDirectory, METRICS_FILE, parseMetrics),
    safeReadJson(dataDirectory, ORCHESTRATION_FILE, parseOrchestration),
  ]);
  return { state, metrics, orchestration };
}

function normalizeEventInput(eventInput, now) {
  if (!eventInput || typeof eventInput !== "object" || Array.isArray(eventInput)) {
    throw new TypeError("Metrics event must be an object.");
  }
  const allowed = new Set(["schemaVersion", "eventId", "type", "occurredAt", "data"]);
  const unknown = Object.keys(eventInput).find((key) => !allowed.has(key));
  if (unknown) throw new TypeError(`Metrics event contains unsupported field ${unknown}.`);
  if (
    eventInput.schemaVersion !== undefined &&
    eventInput.schemaVersion !== EVENT_SCHEMA_VERSION
  ) {
    throw new TypeError("Unsupported metrics event schemaVersion.");
  }
  const input = { ...eventInput };
  return {
    schemaVersion: EVENT_SCHEMA_VERSION,
    eventId: input.eventId ?? randomUUID(),
    type: input.type,
    occurredAt: input.occurredAt ?? new Date(now).toISOString(),
    data: input.data,
  };
}

async function readForUpdate(root, filename, validator, fallback, label) {
  const result = await safeReadJson(root, filename, validator);
  if (result.ok) return result.value;
  if (result.code === "missing") return fallback();
  throw new Error(`Existing ${label} is invalid; refusing to overwrite it.`);
}

export async function runCollectorCli(argv = process.argv.slice(2), streams = {}) {
  const stdout = streams.stdout ?? process.stdout;
  const stderr = streams.stderr ?? process.stderr;
  const stdin = streams.stdin ?? process.stdin;
  try {
    const { command, dataDirectory, json, useStdin } = parseArguments(argv);
    let result;
    if (command === "init") {
      result = await initializeCollector({ dataDirectory });
    } else if (command === "state") {
      const input = await readJsonInput(json, useStdin, stdin);
      const state = await updateWorkerState(input, { dataDirectory });
      result = { ok: true, revision: state.revision, updatedAt: state.updatedAt };
    } else if (command === "event") {
      const input = await readJsonInput(json, useStdin, stdin);
      const recorded = await recordMetricsEvent(input, { dataDirectory });
      result = {
        ok: true,
        duplicate: recorded.duplicate,
        eventId: recorded.eventId,
        revision: recorded.metrics.revision,
      };
    } else if (command === "orchestration") {
      const input = await readJsonInput(json, useStdin, stdin);
      const snapshot = await updateOrchestration(input, { dataDirectory });
      result = {
        ok: true,
        observedAt: snapshot.observedAt,
        mode: snapshot.mode,
      };
    } else if (command === "snapshot") {
      result = await readCollectorSnapshot({ dataDirectory });
    } else {
      throw new TypeError("Unknown collector command.");
    }
    stdout.write(`${JSON.stringify(result)}\n`);
    return 0;
  } catch (error) {
    stderr.write(`${JSON.stringify({ ok: false, error: safeMessage(error) })}\n`);
    return 1;
  }
}

function parseArguments(argv) {
  const argumentsCopy = [...argv];
  const command = argumentsCopy.shift();
  if (!command || !new Set(["init", "state", "event", "orchestration", "snapshot"]).has(command)) {
    throw new TypeError("Usage: collector.mjs <init|state|event|orchestration|snapshot> [--data-dir PATH] [--json JSON|--stdin]");
  }
  let dataDirectory = process.env.HCH_WORKER_DASHBOARD_DATA_DIR ?? DEFAULT_DATA_DIRECTORY;
  let json;
  let useStdin = false;
  while (argumentsCopy.length) {
    const argument = argumentsCopy.shift();
    if (argument === "--data-dir") {
      const value = argumentsCopy.shift();
      if (!value) throw new TypeError("--data-dir requires a value.");
      dataDirectory = value;
    } else if (argument === "--json") {
      const value = argumentsCopy.shift();
      if (!value) throw new TypeError("--json requires a value.");
      json = value;
    } else if (argument === "--stdin") {
      useStdin = true;
    } else {
      throw new TypeError("Unsupported collector argument.");
    }
  }
  if (json !== undefined && useStdin) {
    throw new TypeError("Use either --json or --stdin, not both.");
  }
  if ((command === "init" || command === "snapshot") && (json !== undefined || useStdin)) {
    throw new TypeError(`${command} does not accept JSON input.`);
  }
  return { command, dataDirectory: resolve(dataDirectory), json, useStdin };
}

async function readJsonInput(json, useStdin, stdin) {
  if (json === undefined && !useStdin) {
    throw new TypeError("state, event, and orchestration commands require --json or --stdin.");
  }
  const text = useStdin ? await readBoundedStream(stdin) : json;
  if (Buffer.byteLength(text, "utf8") > MAXIMUM_CLI_INPUT_BYTES) {
    throw new TypeError("Collector input exceeds the size limit.");
  }
  let value;
  try {
    value = JSON.parse(text);
  } catch {
    throw new TypeError("Collector input is not valid JSON.");
  }
  assertNoSecrets(value);
  return value;
}

async function readBoundedStream(stream) {
  stream.setEncoding?.("utf8");
  let text = "";
  for await (const chunk of stream) {
    text += chunk;
    if (Buffer.byteLength(text, "utf8") > MAXIMUM_CLI_INPUT_BYTES) {
      throw new TypeError("Collector input exceeds the size limit.");
    }
  }
  return text;
}

function safeMessage(error) {
  return error instanceof Error ? error.message : "Collector operation failed.";
}

const entrypoint = process.argv[1]
  ? pathToFileURL(resolve(process.argv[1])).href
  : null;
if (entrypoint === import.meta.url) {
  process.exitCode = await runCollectorCli();
}
