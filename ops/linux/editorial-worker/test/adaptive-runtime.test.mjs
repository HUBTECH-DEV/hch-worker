import assert from "node:assert/strict";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import http from "node:http";
import test from "node:test";

import {
  correlateHeartbeatError,
  validateAssignment,
} from "../lib/api-client.mjs";
import {
  adaptiveWorkPolicyHash,
  createAssignmentProgress,
  verifyGenerationPlan,
} from "../lib/adaptive-work.mjs";
import {
  ollamaGenerationRequest,
  assertPublicSourceDestination,
  resolvePublicSourceDestination,
  readBoundedResponseBody,
  requestOllamaNdjson,
  requestPinnedPublicSource,
  validatePublicSourceUrl,
} from "../lib/generator.mjs";
import {
  runPortableSupervisor,
  renewReadyAttestation,
  startAssignmentHeartbeat,
  stopHeartbeatBeforeComplete,
} from "../lib/supervisor.mjs";
import { WorkerKitError } from "../lib/errors.mjs";
import { canonicalizeJson } from "../crypto.mjs";
import { createGenerationPlan, generationPlanHash } from "../../../../lib/editorial-work-sizing.mjs";

const policy = Object.freeze({
  algorithmVersion: "hch-adaptive-work-v1",
  windowMode: "advisory",
  minimumTierIgnoresWindow: true,
  livenessBasis: "progress",
  processingWindowSeconds: 2700,
  nearWindowRatio: 0.8,
  firstProgressGraceSeconds: 900,
  stallAfterSeconds: 600,
  finalizationGraceSeconds: 180,
  tiers: [
    { id: "minimum", rank: 0, maxOutputTokens: 768, editorialProfile: "EDITORIAL_MINIMUM", minimumUnit: true },
    { id: "compact", rank: 1, maxOutputTokens: 1536, editorialProfile: "EDITORIAL_COMPACT", minimumUnit: false },
    { id: "full", rank: 2, maxOutputTokens: 2400, editorialProfile: "EDITORIAL_LONG_FORM", minimumUnit: false },
  ],
});

test("portable client verifies signed policy and immutable JCS generation plan", async () => {
  const policyHash = await adaptiveWorkPolicyHash(policy);
  const plan = createGenerationPlan(policy, 1, {
    policyHash,
    editorialProfile: "EDITORIAL_COMPACT",
  });
  const hash = await generationPlanHash(plan);
  const verified = await verifyGenerationPlan(plan, hash, policy, { maxOutputTokens: 2400 });
  assert.deepEqual(verified, plan);
  await assert.rejects(
    verifyGenerationPlan({ ...plan, maxOutputTokens: 1537 }, hash, policy, { maxOutputTokens: 2400 }),
    (error) => error?.code === "generation-plan-hash-mismatch",
  );
  await assert.rejects(
    verifyGenerationPlan(plan, hash, policy, { maxOutputTokens: 1024 }),
    (error) => error?.code === "generation-plan-runtime-ceiling-exceeded",
  );
});

test("claim rejects a self-consistent RuntimeProfile that differs from applied", async () => {
  const policyHash = await adaptiveWorkPolicyHash(policy);
  const plan = createGenerationPlan(policy, 2, { policyHash, editorialProfile: "EDITORIAL_LONG_FORM" });
  const planHash = await generationPlanHash(plan);
  const applied = await runtimeProfile({ maxOutputTokens: 2400 });
  const altered = await runtimeProfile({ maxOutputTokens: 2401 });
  await assert.rejects(
    validateAssignment({
      assignmentId: "assignment-1",
      leaseToken: "lease-1",
      leaseExpiresAt: new Date(Date.now() + 60_000).toISOString(),
      status: "processing",
      inputSnapshotHash: "a".repeat(64),
      entry: {},
      runtimeProfile: altered,
      generationPlan: plan,
      generationPlanHash: planHash,
    }, policy, applied),
    (error) => error?.code === "assignment-runtime-profile-mismatch",
  );
});

test("new attempt resets counters while same-attempt progress remains cumulative", () => {
  const progress = createAssignmentProgress();
  assert.deepEqual(progress.snapshot(), {
    phase: "starting", attempt: 1, sequence: 0, contentBytes: 0,
  });
  progress.recordContent(7);
  progress.recordContent(5);
  assert.deepEqual(progress.snapshot(), {
    phase: "responding", attempt: 1, sequence: 2, contentBytes: 12,
  });
  assert.deepEqual(progress.startAttempt(2), {
    phase: "starting", attempt: 2, sequence: 0, contentBytes: 0,
  });
  assert.throws(() => progress.startAttempt(1), /cannot regress/);
});

test("Ollama request uses stream NDJSON and exact signed num_predict", () => {
  const request = ollamaGenerationRequest({
    profile: { model: "qwen", temperature: 0.2, contextWindow: 8192 },
    generationPlan: { maxOutputTokens: 768 },
    prompt: "system",
    editorialProfile: "EDITORIAL_MINIMUM",
    input: { locale: "pt-BR" },
    attempt: 1,
    lastValidation: null,
    previousCandidate: null,
  });
  assert.equal(request.stream, true);
  assert.equal(request.options.num_predict, 768);
  assert.equal(request.format.properties.paragraphs.minItems, 1);
  assert.equal(request.format.properties.paragraphs.maxItems, 1);
});

test("NDJSON progress counts only content bytes and has no total-window deadline", async () => {
  const observed = [];
  const candidate = JSON.stringify({
    title: "Título editorial válido",
    excerpt: "Resumo editorial válido para teste",
    paragraphs: ["Texto editorial mínimo suficientemente extenso para o transporte [S1]"],
  });
  const pieces = [candidate.slice(0, 20), candidate.slice(20)];
  const encoder = new TextEncoder();
  const stream = new ReadableStream({
    async start(controller) {
      // This delay exceeds the deliberately tiny advisory total window below;
      // only first/stall/finalization watchdogs govern execution.
      await delay(20);
      controller.enqueue(encoder.encode(`${JSON.stringify({ message: { content: pieces[0] }, done: false })}\n`));
      await delay(20);
      controller.enqueue(encoder.encode(`${JSON.stringify({ message: { content: pieces[1] }, done: false })}\n`));
      await delay(20);
      controller.enqueue(encoder.encode(`${JSON.stringify({ message: { content: "" }, done: true, done_reason: "stop" })}\n`));
      controller.close();
    },
  });
  const result = await requestOllamaNdjson(
    "http://127.0.0.1:11434/api/chat",
    "{}",
    {
      generationPlan: {
        processingWindowSeconds: 0.001,
        minimumUnit: true,
        firstProgressGraceSeconds: 1,
        stallAfterSeconds: 1,
        finalizationGraceSeconds: 1,
      },
      fetcher: async () => new Response(stream, {
        status: 200,
        headers: { "content-type": "application/x-ndjson" },
      }),
      onContent: (bytes) => observed.push(bytes),
    },
  );
  assert.equal(result.done, true);
  assert.deepEqual(observed, pieces.map((piece) => Buffer.byteLength(piece)));
});

test("Ollama completion requires done true and done_reason stop without exposing raw reason", async () => {
  const rawReason = "length-secret-output-fragment";
  const encoder = new TextEncoder();
  const stream = new ReadableStream({
    start(controller) {
      controller.enqueue(encoder.encode(`${JSON.stringify({
        message: { content: '{"title":"incompleto"}' },
        done: true,
        done_reason: rawReason,
      })}\n`));
      controller.close();
    },
  });
  await assert.rejects(
    requestOllamaNdjson("http://127.0.0.1:11434/api/chat", "{}", {
      generationPlan: {
        firstProgressGraceSeconds: 1,
        stallAfterSeconds: 1,
        finalizationGraceSeconds: 1,
      },
      fetcher: async () => new Response(stream, { status: 200 }),
    }),
    (error) => error?.code === "generator-output-incomplete" &&
      !String(error.message).includes(rawReason),
  );
});

test("server generator-stalled heartbeat aborts work fail-closed", async () => {
  const progress = createAssignmentProgress();
  const cancellation = new AbortController();
  const heartbeat = startAssignmentHeartbeat(
    {},
    {},
    { assignmentId: "assignment", leaseExpiresAt: new Date().toISOString() },
    progress,
    cancellation,
    {
      assignmentHeartbeatIntervalMilliseconds: 1,
      heartbeatAssignment: async () => {
        throw new WorkerKitError("generator-stalled", "stalled");
      },
    },
  );
  await delay(20);
  assert.equal(heartbeat.lost, true);
  assert.equal(heartbeat.stalled, true);
  assert.equal(cancellation.signal.aborted, true);
  assert.equal(cancellation.signal.reason.code, "generator-stalled");
  await heartbeat.stopAndWait();
});

test("forged generator-stalled 409 is rejected unless generationPlanHash correlates", async () => {
  const assignment = {
    generationPlanHash: "a".repeat(64),
  };
  const forged = new WorkerKitError("generator-stalled", "stalled");
  forged.status = 409;
  forged.responsePayload = { generationPlanHash: "b".repeat(64) };
  assert.equal(correlateHeartbeatError(forged, assignment).code, "heartbeat-response-invalid");
  forged.responsePayload = { generationPlanHash: assignment.generationPlanHash };
  assert.equal(correlateHeartbeatError(forged, assignment), forged);
});

test("external cancellation reaches the Ollama stream reader", async () => {
  const external = new AbortController();
  let cancelled = false;
  const stream = new ReadableStream({
    start(controller) {
      const timer = setTimeout(() => controller.close(), 5_000);
      external.signal.addEventListener("abort", () => {
        clearTimeout(timer);
        controller.error(external.signal.reason);
      }, { once: true });
    },
    cancel() { cancelled = true; },
  });
  const running = requestOllamaNdjson("http://127.0.0.1:11434/api/chat", "{}", {
    generationPlan: {
      firstProgressGraceSeconds: 30,
      stallAfterSeconds: 30,
      finalizationGraceSeconds: 30,
    },
    signal: external.signal,
    fetcher: async (_url, init) => {
      assert.equal(init.signal.aborted, false);
      return new Response(stream, { status: 200 });
    },
  });
  external.abort(new WorkerKitError("lease-lost-discard-result", "lease lost"));
  await assert.rejects(running, (error) => error?.code === "lease-lost-discard-result");
  assert.equal(external.signal.aborted, true);
  assert.equal(cancelled || external.signal.aborted, true);
});

test("completion gate rechecks heartbeat loss after stopAndWait", async () => {
  const heartbeat = {
    lost: false,
    async stopAndWait() { this.lost = true; },
  };
  await assert.rejects(
    stopHeartbeatBeforeComplete(heartbeat),
    (error) => error?.code === "lease-lost-discard-result",
  );
});

test("source evidence blocks private/metadata targets and DNS rebinding", async () => {
  for (const target of [
    "http://127.0.0.1/admin",
    "http://169.254.169.254/latest/meta-data",
    "http://10.0.0.1/private",
    "http://[::1]/private",
    "http://[::ffff:7f00:1]/private",
    "http://[::ffff:a00:1]/private",
    "http://[::ffff:a9fe:a9fe]/latest/meta-data",
    "http://metadata.google.internal/computeMetadata/v1/",
  ]) {
    assert.throws(() => validatePublicSourceUrl(target), (error) => error?.code === "source-url-refused");
  }
  await assert.rejects(
    assertPublicSourceDestination("https://public.example/article", async () => [
      { address: "93.184.216.34", family: 4 },
      { address: "127.0.0.1", family: 4 },
    ]),
    (error) => error?.code === "source-url-refused",
  );
  let resolutions = 0;
  const pinned = await resolvePublicSourceDestination(
    "https://public.example/article",
    async () => {
      resolutions += 1;
      return resolutions === 1
        ? [{ address: "93.184.216.34", family: 4 }]
        : [{ address: "127.0.0.1", family: 4 }];
    },
  );
  assert.equal(resolutions, 1);
  assert.equal(pinned.address, "93.184.216.34");
});

test("source evidence bounds streamed bytes before decode", async () => {
  let cancelled = false;
  const stream = new ReadableStream({
    start(controller) {
      controller.enqueue(new Uint8Array(8));
      controller.enqueue(new Uint8Array(8));
    },
    cancel() { cancelled = true; },
  });
  await assert.rejects(
    readBoundedResponseBody(new Response(stream, { status: 200 }), 10),
    (error) => error?.code === "source-too-large",
  );
  assert.equal(cancelled, true);
});

test("pinned source request cancels a 200 response whose body stops", async (t) => {
  const server = http.createServer((_request, response) => {
    response.writeHead(200, { "content-type": "text/plain" });
    response.flushHeaders();
    response.write("partial");
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(() => new Promise((resolve) => server.close(resolve)));
  const address = server.address();
  const response = await requestPinnedPublicSource(
    new URL(`http://public.example:${address.port}/source`),
    { address: "127.0.0.1", family: 4 },
    { timeoutMilliseconds: 1_000 },
  );
  await assert.rejects(
    readBoundedResponseBody(response, 100),
    (error) => new Set(["source-timeout", "source-response-aborted"]).has(error?.code),
  );
});

test("portable supervisor keeps heartbeat at capacity zero and never claims", async (t) => {
  const stateDirectory = await mkdtemp(join(tmpdir(), "hch-portable-cap0-"));
  t.after(() => rm(stateDirectory, { recursive: true, force: true }));
  let clock = 0;
  let heartbeats = 0;
  let workStarts = 0;
  const result = await runPortableSupervisor({ stateDirectory }, {
    maximumCycles: 3,
    waitForWorkOnStop: false,
    now: () => clock,
    delay: async (milliseconds) => { clock += milliseconds; },
    nodeHeartbeat: async () => {
      heartbeats += 1;
      return heartbeatSnapshot(0, false);
    },
    runAssignment: async () => { workStarts += 1; },
    bootstrapWorkerLocked: async () => ({ ready: true }),
  });
  assert.equal(result.cycles, 3);
  assert.equal(heartbeats, 3);
  assert.equal(workStarts, 0);
});

test("portable supervisor honors the orchestrator parallel-work target", async (t) => {
  const stateDirectory = await mkdtemp(join(tmpdir(), "hch-portable-single-"));
  t.after(() => rm(stateDirectory, { recursive: true, force: true }));
  let clock = 0;
  let active = 0;
  let maximumActive = 0;
  let starts = 0;
  let release;
  const held = new Promise((resolve) => { release = resolve; });
  const result = await runPortableSupervisor({ stateDirectory }, {
    maximumCycles: 3,
    waitForWorkOnStop: false,
    now: () => clock,
    delay: async (milliseconds) => {
      clock += milliseconds;
      await Promise.resolve();
    },
    nodeHeartbeat: async () => heartbeatSnapshot(3, true, 3),
    runAssignment: async () => {
      starts += 1;
      active += 1;
      maximumActive = Math.max(maximumActive, active);
      await held;
      active -= 1;
    },
    bootstrapWorkerLocked: async () => ({ ready: true }),
  });
  assert.equal(result.cycles, 3);
  assert.equal(result.activeWorkers, 3);
  assert.equal(starts, 3);
  assert.equal(maximumActive, 3);
  release();
});

test("portable readiness renewal is independent from capacity zero", async (t) => {
  const stateRoot = await mkdtemp(join(tmpdir(), "hch-portable-ready-"));
  t.after(() => rm(stateRoot, { recursive: true, force: true }));
  await writeFile(join(stateRoot, "ready.json"), JSON.stringify({
    ready: true,
    readyUntil: "2026-08-15T00:15:00.000Z",
  }));
  let renewals = 0;
  await renewReadyAttestation({ requestedCapacity: 0 }, stateRoot, {
    now: () => Date.parse("2026-08-15T00:14:00.000Z"),
    bootstrapWorkerLocked: async () => { renewals += 1; return { ready: true }; },
  });
  assert.equal(renewals, 1);
});

test("portable readiness renewal preserves an active work lifecycle", async (t) => {
  const stateRoot = await mkdtemp(join(tmpdir(), "hch-portable-active-renewal-"));
  t.after(() => rm(stateRoot, { recursive: true, force: true }));
  await writeFile(join(stateRoot, "ready.json"), JSON.stringify({
    ready: true,
    readyUntil: "2026-08-15T00:15:00.000Z",
  }));
  let receivedOptions = null;
  await renewReadyAttestation({ requestedCapacity: 1 }, stateRoot, {
    now: () => Date.parse("2026-08-15T00:14:00.000Z"),
    bootstrapWorkerLocked: async (_config, _stateRoot, options) => {
      receivedOptions = options;
      return { ready: true };
    },
  });
  assert.equal(receivedOptions.preserveLifecycle, true);
});

function heartbeatSnapshot(capacity, allowed, recommendedCount = allowed ? 1 : 0) {
  return {
    heartbeat: { status: "succeeded" },
    capacity: {
      requestedCapacity: capacity,
      grantedCapacity: capacity,
      availableSlots: capacity,
    },
    claim: { allowed, recommendedCount },
  };
}

function delay(milliseconds) {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

async function runtimeProfile(overrides = {}) {
  const core = {
    provider: "vps-local",
    engineAdapter: "ollama",
    engineAdapterVersion: "1.0.0",
    model: "qwen2.5:1.5b-instruct",
    modelDigest: "1".repeat(64),
    protocol: "ollama-chat",
    temperature: 0.2,
    contextWindow: 8192,
    maxOutputTokens: 2400,
    policyId: "policy",
    policyVersion: "1.0",
    policyHash: "2".repeat(64),
    promptConfigHash: "3".repeat(64),
    pipelineVersion: "1.3.0",
    manifestSequence: 3,
    manifestHash: "4".repeat(64),
    ...overrides,
  };
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(canonicalizeJson(core)),
  );
  const runtimeProfileHash = Buffer.from(digest).toString("hex");
  return { ...core, runtimeProfileHash };
}
