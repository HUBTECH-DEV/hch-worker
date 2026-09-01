import assert from "node:assert/strict";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
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
  generateEditorialDraft,
  generationBudgetRetryFeedback,
  modelEvidenceExcerpt,
  normalizeParagraphs,
  assertPublicSourceDestination,
  resolvePublicSourceDestination,
  readBoundedResponseBody,
  requestOllamaNdjson,
  requestPinnedPublicSource,
  validatePublicSourceUrl,
} from "../lib/generator.mjs";
import { computeEditorialMetrics } from "../../../../lib/editorial-policy.mjs";
import {
  assertClaimGate,
  markFinished,
  markProcessing,
  runClaimedPortableAssignment,
  runPortableSupervisor,
  renewReadyAttestation,
  startAssignmentHeartbeat,
  stopHeartbeatBeforeComplete,
} from "../lib/supervisor.mjs";
import { WorkerKitError } from "../lib/errors.mjs";
import { sampleNvidiaGpu, validateGpuSample } from "../lib/gpu.mjs";
import { defaultMetrics, recordGpuSample } from "../lib/local-state.mjs";
import {
  assertLocalEngineThreadBudget,
  cgroupCpuUtilization,
  effectiveCpuCapacity,
  effectiveLogicalProcessors,
  parseCpuMax,
  parseCpuStatUsage,
  sampleCgroupCpuPercent,
} from "../lib/runtime-resources.mjs";
import { withWorkerLock } from "../lib/storage.mjs";
import { canonicalizeJson } from "../crypto.mjs";
import { createGenerationPlan, generationPlanHash } from "../../../../lib/editorial-work-sizing.mjs";
import { validationErrorCodes } from "../worker.mjs";

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

test("cgroup CPU quota bounds local Ollama threads and telemetry", () => {
  assert.deepEqual(parseCpuMax("200000 100000\n"), {
    limited: true,
    capacity: 2,
    threads: 2,
  });
  assert.deepEqual(parseCpuMax("150000 100000"), {
    limited: true,
    capacity: 1.5,
    threads: 2,
  });
  assert.deepEqual(parseCpuMax("max 100000"), { limited: false, threads: null });
  assert.equal(parseCpuMax("invalid"), null);
  assert.equal(effectiveLogicalProcessors({
    platform: "linux",
    availableParallelism: 64,
    cpuMaxText: "200000 100000",
  }), 2);
  assert.equal(effectiveLogicalProcessors({
    platform: "linux",
    availableParallelism: 4,
    cpuMaxText: "max 100000",
  }), 4);
  assert.equal(effectiveCpuCapacity({
    platform: "linux",
    availableParallelism: 64,
    cpuMaxText: "150000 100000",
  }), 1.5);
  assert.throws(() => assertLocalEngineThreadBudget(
    { localEngineNumThreads: 3 },
    { platform: "linux", availableParallelism: 64, cpuMaxText: "200000 100000" },
  ), /effective CPU budget/);
  assert.equal(assertLocalEngineThreadBudget(
    { localEngineNumThreads: 2 },
    { platform: "linux", availableParallelism: 64, cpuMaxText: "200000 100000" },
  ).localEngineNumThreads, 2);
  assert.equal(parseCpuStatUsage("usage_usec 1000000\nuser_usec 800000\n"), 1_000_000);
  assert.equal(parseCpuStatUsage("usage_usec invalid"), null);
  assert.equal(cgroupCpuUtilization(
    { usageMicroseconds: 1_000_000, sampledAtMicroseconds: 2_000_000 },
    { usageMicroseconds: 1_500_000, sampledAtMicroseconds: 3_000_000 },
    2,
  ), 25);
  assert.equal(cgroupCpuUtilization(
    { usageMicroseconds: 1_000_000, sampledAtMicroseconds: 2_000_000 },
    { usageMicroseconds: 2_500_000, sampledAtMicroseconds: 3_000_000 },
    1.5,
  ), 100);
  assert.equal(cgroupCpuUtilization(
    { usageMicroseconds: 2_000_000, sampledAtMicroseconds: 2_000_000 },
    { usageMicroseconds: 1_000_000, sampledAtMicroseconds: 3_000_000 },
    2,
  ), null);
  assert.equal(cgroupCpuUtilization(
    { usageMicroseconds: 1_000_000, sampledAtMicroseconds: 2_000_000 },
    { usageMicroseconds: 1_500_000, sampledAtMicroseconds: 123_000_001 },
    2,
  ), null);
  assert.equal(sampleCgroupCpuPercent({
    platform: "linux",
    cpuStatText: "usage_usec 1500000",
    sampledAtMicroseconds: 3_000_000,
    previousSample: { usageMicroseconds: 1_000_000, sampledAtMicroseconds: 2_000_000 },
    logicalProcessors: 2,
    updateState: false,
  }), 25);
  assert.equal(sampleCgroupCpuPercent({
    platform: "linux",
    cpuStatText: "usage_usec 1500000",
    sampledAtMicroseconds: 3_000_000,
    previousSample: null,
    logicalProcessors: 2,
    updateState: false,
  }), null);
  assert.equal(sampleCgroupCpuPercent({
    platform: "linux",
    cpuStatText: "usage_usec invalid",
    updateState: false,
  }), null);
  assert.equal(sampleCgroupCpuPercent({ platform: "darwin" }), null);
});

test("NVIDIA telemetry is bounded and normalized without shell execution", async () => {
  let invocation = null;
  const sample = await sampleNvidiaGpu({
    platform: "linux",
    execFile: async (...args) => {
      invocation = args;
      return { stdout: "7\n42\n" };
    },
  });
  assert.equal(invocation[0], "/usr/bin/nvidia-smi");
  assert.deepEqual(invocation[1], [
    "--query-gpu=utilization.gpu",
    "--format=csv,noheader,nounits",
  ]);
  assert.deepEqual(invocation[2].env, {
    LANG: "C",
    LC_ALL: "C",
    PATH: "/usr/bin:/bin",
  });
  assert.deepEqual(sample, {
    available: true,
    status: "available",
    utilizationPercent: 42,
    errorCode: null,
  });
  const metrics = defaultMetrics({ nodeId: "gpu-node", keyId: "gpu-key" });
  recordGpuSample(metrics, sample, 60);
  assert.equal(metrics.resources.gpu.status, "available");
  assert.equal(metrics.resources.gpu.averageUtilizationPercent, 42);
  assert.equal(metrics.resources.gpu.totalActiveSeconds, 0);
  recordGpuSample(metrics, sample, 60);
  assert.equal(metrics.resources.gpu.totalActiveSeconds, 60);

  const unsupported = await sampleNvidiaGpu({ platform: "darwin" });
  assert.equal(unsupported.status, "unsupported");
  const failed = await sampleNvidiaGpu({
    platform: "linux",
    execFile: async () => { throw Object.assign(new Error("hidden"), { code: "EIO" }); },
  });
  assert.deepEqual(failed, {
    available: false,
    status: "unavailable",
    utilizationPercent: null,
    errorCode: "gpu-probe-failed",
  });
  assert.throws(() => validateGpuSample({
    available: false,
    status: "available",
    utilizationPercent: 42,
    errorCode: null,
  }), /inconsistent/);
  assert.throws(() => validateGpuSample({
    available: false,
    status: "unavailable",
    utilizationPercent: null,
    errorCode: "invalid error code",
  }), /inconsistent/);
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

test("Ollama request uses portable JSON mode and exact signed num_predict", () => {
  const request = ollamaGenerationRequest({
    profile: { model: "qwen", temperature: 0.2, contextWindow: 8192 },
    generationPlan: { maxOutputTokens: 768 },
    prompt: "system",
    editorialProfile: "EDITORIAL_MINIMUM",
    input: { locale: "pt-BR" },
    platform: "darwin",
    attempt: 1,
    lastValidation: null,
    previousCandidate: null,
  });
  assert.equal(request.stream, true);
  assert.equal(request.options.num_predict, 768);
  assert.equal(request.options.num_batch, 256);
  assert.equal(request.format, "json");
  const userPayload = JSON.parse(request.messages[1].content);
  assert.deepEqual(userPayload.requiredResponseKeys, ["title", "excerpt", "paragraphs"]);
  assert.deepEqual(Object.keys(userPayload.fieldRequirements), ["title", "excerpt", "paragraphs"]);
  assert.equal(userPayload.fieldRequirements.paragraphs.exactCount, 1);
  assert.equal(userPayload.fieldRequirements.paragraphs.wordRange, "50-115");
  assert.match(userPayload.responseRules.join(" "), /não renomeie title, excerpt ou paragraphs/);
  assert.match(userPayload.responseRules.join(" "), /nunca descrições, instruções ou placeholders/);

  const linuxRequest = ollamaGenerationRequest({
    profile: { model: "qwen", temperature: 0.2, contextWindow: 8192 },
    generationPlan: { maxOutputTokens: 768 },
    prompt: "system",
    editorialProfile: "EDITORIAL_MINIMUM",
    input: { locale: "pt-BR" },
    platform: "linux",
    localEngineNumThreads: 2,
    attempt: 1,
    lastValidation: null,
    previousCandidate: null,
  });
  assert.equal(Object.hasOwn(linuxRequest.options, "num_batch"), false);
  assert.equal(linuxRequest.options.num_thread, 2);
  assert.throws(() => ollamaGenerationRequest({
    profile: { model: "qwen", temperature: 0.2, contextWindow: 8192 },
    generationPlan: { maxOutputTokens: 768 },
    prompt: "system",
    editorialProfile: "EDITORIAL_MINIMUM",
    input: { locale: "pt-BR" },
    platform: "linux",
    localEngineNumThreads: 0,
    attempt: 1,
    lastValidation: null,
    previousCandidate: null,
  }), /localEngineNumThreads/);
});

test("model evidence is bounded for first-token portability", () => {
  const excerpt = modelEvidenceExcerpt(`  ${"e".repeat(4_000)}  `);
  assert.equal(excerpt.length, 2_998);
  assert.doesNotMatch(excerpt, /^\s|\s$/);
});

test("single-paragraph profiles coalesce model spillover without inventing content", () => {
  const first = Array.from({ length: 25 }, (_, index) => `alfa${index}`).join(" ");
  const second = Array.from({ length: 25 }, (_, index) => `beta${index}`).join(" ");
  const input = [`${first} [S1]`, `${second} [S1]`];
  for (const profile of ["EDITORIAL_MINIMUM", "CATALOG_SUMMARY", "EVENT_LISTING"]) {
    const [paragraph, ...extras] = normalizeParagraphs(input, profile);
    assert.equal(extras.length, 0);
    assert.match(paragraph.text, /\[S1\]$/);
    assert.equal((paragraph.text.match(/\[S1\]/g) ?? []).length, 1);
    assert.ok(paragraph.text.indexOf("alfa0") < paragraph.text.indexOf("beta0"));
    assert.match(paragraph.text, /beta24/);
  }
  const paragraphs = normalizeParagraphs(input, "EDITORIAL_MINIMUM");
  const metrics = computeEditorialMetrics(paragraphs);

  assert.equal(paragraphs.length, 1);
  assert.ok(metrics.bodyCharacters >= 320 && metrics.bodyCharacters <= 800);
  assert.ok(metrics.bodyWords >= 50 && metrics.bodyWords <= 115);
  assert.ok(metrics.minimumParagraphWords >= 50);
  const wordOverflow = Array.from({ length: 130 }, (_, index) => `w${index}`).join(" ");
  const overflowMetrics = computeEditorialMetrics(
    normalizeParagraphs([wordOverflow], "EDITORIAL_MINIMUM"),
  );
  assert.equal(overflowMetrics.bodyWords, 115);
  assert.deepEqual(normalizeParagraphs(["", { text: " " }], "EDITORIAL_MINIMUM"), []);
});

test("worker logs only bounded validation codes", () => {
  assert.deepEqual(validationErrorCodes({
    validation: { errors: [
      { code: "BODY_WORD_COUNT" },
      { code: "BODY_WORD_COUNT" },
      { code: "unsafe content" },
      { message: "missing code" },
    ] },
  }), ["BODY_WORD_COUNT"]);
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

test("Ollama completion rejects an unknown terminal reason without exposing it", async () => {
  const rawReason = "unexpected-secret-output-fragment";
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
    (error) => error?.code === "generator-output-terminal-reason-unknown" &&
      !String(error.message).includes(rawReason),
  );
});

test("Ollama completion reports safe terminal failure categories", async () => {
  const plan = {
    firstProgressGraceSeconds: 1,
    stallAfterSeconds: 1,
    finalizationGraceSeconds: 1,
  };
  const cases = [
    {
      expected: "generator-output-terminal-missing",
      response: new Response(`${JSON.stringify({
        message: { content: '{"title":"partial"}' },
        done: false,
      })}\n`, { status: 200 }),
    },
    {
      expected: "generator-output-terminal-reason-missing",
      response: ollamaCompletion('{"title":"partial"}', undefined),
    },
    {
      expected: "generator-output-empty",
      response: ollamaCompletion("", "stop"),
    },
  ];
  for (const item of cases) {
    await assert.rejects(
      requestOllamaNdjson("http://127.0.0.1:11434/api/chat", "{}", {
        generationPlan: plan,
        fetcher: async () => item.response,
      }),
      (error) => error?.code === item.expected,
    );
  }
});

test("Ollama completion rejects data after the only terminal event", async () => {
  const response = new Response([
    JSON.stringify({ message: { content: '{"title":"complete"}' }, done: true, done_reason: "stop" }),
    JSON.stringify({ message: { content: "late" }, done: false }),
    "",
  ].join("\n"), { status: 200 });
  await assert.rejects(
    requestOllamaNdjson("http://127.0.0.1:11434/api/chat", "{}", {
      generationPlan: {
        firstProgressGraceSeconds: 1,
        stallAfterSeconds: 1,
        finalizationGraceSeconds: 1,
      },
      fetcher: async () => response,
    }),
    (error) => error?.code === "local-generator-response-invalid",
  );
});

test("one budget-exhausted Ollama completion retries once with bounded feedback", () => {
  const error = new WorkerKitError(
    "generator-output-budget-exhausted",
    "raw completion details must not be copied",
  );
  assert.deepEqual(generationBudgetRetryFeedback(error, 1), {
    valid: false,
    errors: [{
      code: "GEN-OUTPUT-BUDGET-EXHAUSTED",
      message: "A resposta atingiu o limite de saída. Retorne somente o JSON final, sem raciocínio, próximo aos mínimos permitidos e preservando todos os requisitos editoriais.",
    }],
  });
  assert.equal(generationBudgetRetryFeedback(error, 2), null);
  assert.equal(generationBudgetRetryFeedback(
    new WorkerKitError("generator-output-incomplete", "hidden"),
    1,
  ), null);
  assert.equal(generationBudgetRetryFeedback(
    new WorkerKitError("generator-stalled", "hidden"),
    1,
  ), null);
});

test("full generator retries only one attested budget exhaustion", async (t) => {
  const fixture = await editorialGeneratorFixture(t);
  const requests = [];
  const attempts = [];
  const candidate = JSON.stringify({
    title: "Título editorial válido para a segunda tentativa",
    excerpt: "Resumo editorial válido para confirmar o retry controlado.",
    paragraphs: [
      "Primeiro parágrafo editorial com contexto técnico verificável.",
      "Segundo parágrafo editorial com explicação técnica verificável.",
      "Terceiro parágrafo editorial com análise técnica verificável.",
      "Quarto parágrafo editorial com limites técnicos verificáveis.",
      "Quinto parágrafo editorial com conclusão técnica verificável.",
    ],
  });
  const result = await generateEditorialDraft(
    fixture.assignment,
    fixture.stateRoot,
    "http://127.0.0.1:11434",
    {
      ...fixture.options,
      progress: {
        startAttempt(attempt) { attempts.push(attempt); },
        recordContent() {},
        beginFinalization() {},
      },
      generatorFetcher: async (_url, init) => {
        requests.push(JSON.parse(init.body));
        return requests.length === 1
          ? ollamaCompletion('{"title":"partial', "length")
          : ollamaCompletion(candidate, "stop");
      },
    },
  );

  assert.equal(result.validation.valid, true);
  assert.deepEqual(attempts, [1, 2]);
  assert.equal(requests.length, 2);
  assert.deepEqual(requests.map((request) => request.options.num_predict), [2400, 2400]);
  const firstPayload = JSON.parse(requests[0].messages[1].content);
  const secondPayload = JSON.parse(requests[1].messages[1].content);
  assert.equal(firstPayload.operation, "generate-editorial-content");
  assert.equal(secondPayload.operation, "regenerate-editorial-content");
  assert.equal(secondPayload.previousCandidate, null);
  assert.deepEqual(secondPayload.validationFeedback.map(({ code }) => code), [
    "GEN-OUTPUT-BUDGET-EXHAUSTED",
  ]);
  assert.doesNotMatch(JSON.stringify(secondPayload.validationFeedback), /partial|done_reason|length/);
});

test("full generator propagates a second budget exhaustion", async (t) => {
  const fixture = await editorialGeneratorFixture(t);
  let calls = 0;
  await assert.rejects(
    generateEditorialDraft(
      fixture.assignment,
      fixture.stateRoot,
      "http://127.0.0.1:11434",
      {
        ...fixture.options,
        generatorFetcher: async () => {
          calls += 1;
          return ollamaCompletion('{"title":"partial', "length");
        },
      },
    ),
    (error) => error?.code === "generator-output-budget-exhausted",
  );
  assert.equal(calls, 2);
});

test("budget exhaustion classification does not depend on partial content", async () => {
  await assert.rejects(
    requestOllamaNdjson("http://127.0.0.1:11434/api/chat", "{}", {
      generationPlan: {
        firstProgressGraceSeconds: 1,
        stallAfterSeconds: 1,
        finalizationGraceSeconds: 1,
      },
      fetcher: async () => ollamaCompletion("", "length"),
    }),
    (error) => error?.code === "generator-output-budget-exhausted",
  );
});

test("full generator does not retry an unknown terminal reason", async (t) => {
  const fixture = await editorialGeneratorFixture(t);
  let calls = 0;
  await assert.rejects(
    generateEditorialDraft(
      fixture.assignment,
      fixture.stateRoot,
      "http://127.0.0.1:11434",
      {
        ...fixture.options,
        generatorFetcher: async () => {
          calls += 1;
          return ollamaCompletion('{"title":"partial', "unexpected-terminal-reason");
        },
      },
    ),
    (error) => error?.code === "generator-output-terminal-reason-unknown",
  );
  assert.equal(calls, 1);
});

test("full generator does not retry HTTP rejection", async (t) => {
  const fixture = await editorialGeneratorFixture(t);
  let calls = 0;
  await assert.rejects(
    generateEditorialDraft(
      fixture.assignment,
      fixture.stateRoot,
      "http://127.0.0.1:11434",
      {
        ...fixture.options,
        generatorFetcher: async () => {
          calls += 1;
          return new Response(null, { status: 503 });
        },
      },
    ),
    (error) => error?.code === "local-generator-http-503",
  );
  assert.equal(calls, 1);
});

test("full generator does not retry a stalled generator", async (t) => {
  const fixture = await editorialGeneratorFixture(t);
  let calls = 0;
  await assert.rejects(
    generateEditorialDraft(
      fixture.assignment,
      fixture.stateRoot,
      "http://127.0.0.1:11434",
      {
        ...fixture.options,
        generatorFetcher: async () => {
          calls += 1;
          throw new WorkerKitError("generator-stalled", "hidden");
        },
      },
    ),
    (error) => error?.code === "generator-stalled",
  );
  assert.equal(calls, 1);
});

test("full generator does not retry external cancellation", async (t) => {
  const fixture = await editorialGeneratorFixture(t);
  const cancellation = new AbortController();
  cancellation.abort(new WorkerKitError("lease-lost-discard-result", "hidden"));
  let calls = 0;
  await assert.rejects(
    generateEditorialDraft(
      fixture.assignment,
      fixture.stateRoot,
      "http://127.0.0.1:11434",
      {
        ...fixture.options,
        signal: cancellation.signal,
        generatorFetcher: async (_url, init) => {
          calls += 1;
          assert.equal(init.signal.aborted, true);
          throw init.signal.reason;
        },
      },
    ),
    (error) => error?.code === "lease-lost-discard-result",
  );
  assert.equal(calls, 1);
});

test("Ollama transport and malformed streams use safe actionable codes", async () => {
  const plan = {
    firstProgressGraceSeconds: 1,
    stallAfterSeconds: 1,
    finalizationGraceSeconds: 1,
  };
  await assert.rejects(
    requestOllamaNdjson("http://127.0.0.1:11434/api/chat", "{}", {
      generationPlan: plan,
      fetcher: async () => { throw new TypeError("socket details must stay private"); },
    }),
    (error) => error?.code === "local-generator-transport-failed" &&
      !String(error.message).includes("socket details"),
  );

  const stream = new ReadableStream({
    start(controller) {
      controller.enqueue(new TextEncoder().encode("not-json\n"));
      controller.close();
    },
  });
  await assert.rejects(
    requestOllamaNdjson("http://127.0.0.1:11434/api/chat", "{}", {
      generationPlan: plan,
      fetcher: async () => new Response(stream, { status: 200 }),
    }),
    (error) => error?.code === "local-generator-response-invalid",
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

test("worker lock reclaims a proven dead PID and keeps malformed locks fail-closed", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "hch-stale-lock-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  await writeFile(
    join(root, ".worker.lock"),
    JSON.stringify({ pid: 2_147_483_647, at: new Date().toISOString() }),
    { mode: 0o600 },
  );
  assert.equal(await withWorkerLock(root, async () => "recovered"), "recovered");

  await writeFile(join(root, ".worker.lock"), "malformed", { mode: 0o600 });
  await assert.rejects(
    withWorkerLock(root, async () => "unsafe"),
    /Another worker-kit operation is already in progress/,
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
  const result = await runPortableSupervisor({ stateDirectory, requestedCapacity: 0 }, {
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

test("portable supervisor keeps node presence while a content update drains claims", async (t) => {
  const stateDirectory = await mkdtemp(join(tmpdir(), "hch-portable-drain-heartbeat-"));
  t.after(() => rm(stateDirectory, { recursive: true, force: true }));
  await writeFile(join(stateDirectory, "ready.json"), JSON.stringify({
    ready: false,
    readyUntil: null,
    code: "manifest-content-update-draining",
  }));
  let clock = 0;
  let heartbeats = 0;
  let workStarts = 0;
  let renewalErrors = 0;
  const result = await runPortableSupervisor({ stateDirectory }, {
    maximumCycles: 3,
    waitForWorkOnStop: false,
    now: () => clock,
    delay: async (milliseconds) => { clock += milliseconds; },
    nodeHeartbeat: async (_config, heartbeatOptions) => {
      heartbeats += 1;
      assert.equal(heartbeatOptions.forceDrain, true);
      return heartbeatSnapshot(4, true, 4);
    },
    runAssignment: async () => { workStarts += 1; },
    bootstrapWorkerLocked: async () => {
      throw new WorkerKitError(
        "manifest-content-update-draining",
        "Active assignments must drain before applying changed content.",
      );
    },
    onHeartbeatError: () => { renewalErrors += 1; },
  });
  assert.equal(result.cycles, 3);
  assert.equal(heartbeats, 3);
  assert.equal(workStarts, 0);
  assert.equal(renewalErrors, 3);
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
  const result = await runPortableSupervisor({ stateDirectory, requestedCapacity: 3 }, {
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

test("portable supervisor reports completed assignment results", async (t) => {
  const stateDirectory = await mkdtemp(join(tmpdir(), "hch-portable-result-"));
  t.after(() => rm(stateDirectory, { recursive: true, force: true }));
  const observed = [];
  const result = await runPortableSupervisor({ stateDirectory, requestedCapacity: 1 }, {
    maximumCycles: 1,
    now: () => 0,
    nodeHeartbeat: async () => heartbeatSnapshot(1, true, 1),
    runAssignment: async () => ({ claimed: 1, completed: 1, failed: 0, status: "pending-review" }),
    onWorkResult: (workResult) => observed.push(workResult),
    bootstrapWorkerLocked: async () => ({ ready: true }),
  });
  assert.equal(result.cycles, 1);
  assert.deepEqual(observed, [{
    claimed: 1,
    completed: 1,
    failed: 0,
    status: "pending-review",
  }]);
});

test("portable telemetry preserves three concurrent assignments across out-of-order completion", async (t) => {
  const stateDirectory = await mkdtemp(join(tmpdir(), "hch-portable-telemetry-n3-"));
  t.after(() => rm(stateDirectory, { recursive: true, force: true }));
  const config = telemetryConfig(stateDirectory, 3);
  const assignmentIds = ["assignment-c", "assignment-a", "assignment-b"];
  await Promise.all(assignmentIds.map((assignmentId, index) =>
    markProcessing(
      stateDirectory,
      config,
      { requestId: `request-${index}` },
      { assignmentId },
    )));

  let metrics = await readState(stateDirectory, "metrics.json");
  let status = await readState(stateDirectory, "status.json");
  assert.deepEqual(metrics.currentBatch.assignmentIds, [
    "assignment-a",
    "assignment-b",
    "assignment-c",
  ]);
  assert.deepEqual(status.currentBatch, metrics.currentBatch);
  assert.equal(metrics.currentBatch.jobs, 3);
  assert.equal(metrics.jobs.running, 3);
  assert.equal(metrics.jobs.claimed, 3);
  assert.equal(metrics.batches.total, 3);

  await markFinished(
    stateDirectory,
    config,
    "assignment-b",
    false,
    "generator-output-incomplete",
  );
  metrics = await readState(stateDirectory, "metrics.json");
  status = await readState(stateDirectory, "status.json");
  assert.deepEqual(metrics.currentBatch.assignmentIds, ["assignment-a", "assignment-c"]);
  assert.deepEqual(status.currentBatch, metrics.currentBatch);
  assert.equal(metrics.jobs.running, 2);
  assert.equal(metrics.jobs.failed, 1);
  assert.equal(metrics.batches.failed, 1);
  assert.equal(status.state, "processing");
  assert.equal(status.running, true);
  assert.equal(status.standby, false);

  await markFinished(stateDirectory, config, "assignment-c", true, "batch-completed");
  metrics = await readState(stateDirectory, "metrics.json");
  assert.deepEqual(metrics.currentBatch.assignmentIds, ["assignment-a"]);
  assert.equal(metrics.jobs.running, 1);

  await markFinished(stateDirectory, config, "assignment-a", true, "batch-completed");
  metrics = await readState(stateDirectory, "metrics.json");
  status = await readState(stateDirectory, "status.json");
  assert.equal(metrics.currentBatch, null);
  assert.equal(status.currentBatch, null);
  assert.equal(metrics.jobs.running, 0);
  assert.equal(metrics.jobs.completed, 2);
  assert.equal(metrics.jobs.failed, 1);
  assert.equal(metrics.batches.completed, 2);
  assert.equal(metrics.batches.failed, 1);
  assert.equal(status.state, "standby");
  assert.equal(status.running, false);
  assert.equal(status.standby, true);
});

test("portable telemetry start and finish operations are idempotent by assignment id", async (t) => {
  const stateDirectory = await mkdtemp(join(tmpdir(), "hch-portable-telemetry-idempotent-"));
  t.after(() => rm(stateDirectory, { recursive: true, force: true }));
  const config = telemetryConfig(stateDirectory, 2);
  const start = () => markProcessing(
    stateDirectory,
    config,
    { requestId: "request-idempotent" },
    { assignmentId: "assignment-idempotent" },
  );
  await Promise.all([start(), start(), start()]);

  let metrics = await readState(stateDirectory, "metrics.json");
  assert.deepEqual(metrics.currentBatch.assignmentIds, ["assignment-idempotent"]);
  assert.equal(metrics.jobs.running, 1);
  assert.equal(metrics.jobs.claimed, 1);
  assert.equal(metrics.batches.total, 1);

  const finish = () => markFinished(
    stateDirectory,
    config,
    "assignment-idempotent",
    true,
    "batch-completed",
  );
  await Promise.all([finish(), finish(), finish()]);
  metrics = await readState(stateDirectory, "metrics.json");
  const status = await readState(stateDirectory, "status.json");
  assert.equal(metrics.currentBatch, null);
  assert.equal(status.currentBatch, null);
  assert.equal(metrics.jobs.running, 0);
  assert.equal(metrics.jobs.completed, 1);
  assert.equal(metrics.batches.completed, 1);
});

test("portable telemetry compensates status when assignment start persistence fails", async (t) => {
  const stateDirectory = await mkdtemp(join(tmpdir(), "hch-portable-telemetry-rollback-"));
  t.after(() => rm(stateDirectory, { recursive: true, force: true }));
  const config = telemetryConfig(stateDirectory, 1);
  await assert.rejects(
    markProcessing(
      stateDirectory,
      config,
      { requestId: "request-persistence-failure" },
      { assignmentId: "assignment-persistence-failure" },
      {
        now: () => Date.parse("2026-08-28T12:00:00.000Z"),
        updateMetrics: async () => {
          throw new Error("injected metrics persistence failure");
        },
      },
    ),
    (error) => error?.code === "local-telemetry-start-failed",
  );
  const status = await readState(stateDirectory, "status.json");
  assert.equal(status.currentBatch, null);
  assert.equal(status.running, false);
  assert.notEqual(status.state, "processing");
  await assert.rejects(
    readFile(join(stateDirectory, "metrics.json")),
    (error) => error?.code === "ENOENT",
  );
});

test("portable claimed lifecycle stops monitors and safely fails a valid lease after local start failure", async () => {
  const stopped = [];
  const failures = [];
  const finishes = [];
  const failure = new WorkerKitError(
    "local-telemetry-start-failed",
    "injected telemetry failure",
  );
  await assert.rejects(
    runClaimedPortableAssignment(
      { localEngineBaseUrl: "http://127.0.0.1:11434", localEngineNumThreads: 2 },
      "/unused-state-root",
      { nodeId: "telemetry-node" },
      { requestId: "request-monitor-cleanup" },
      {
        assignmentId: "assignment-monitor-cleanup",
        leaseExpiresAt: "2026-08-28T12:05:00.000Z",
      },
      { adaptiveWorkPolicy: {} },
      {
        now: () => Date.parse("2026-08-28T12:00:00.000Z"),
        startAssignmentHeartbeat: () => ({
          lost: false,
          stalled: false,
          async stopAndWait() { stopped.push("heartbeat"); },
        }),
        startOperatorStopMonitor: () => ({
          requested: false,
          async stopAndWait() {
            stopped.push("operator");
            throw new Error("injected operator cleanup failure");
          },
        }),
        markProcessing: async () => { throw failure; },
        failAssignment: async (_config, _identity, _assignment, code) => {
          failures.push(code);
        },
        markFinished: async (_root, _config, assignmentId, succeeded, code) => {
          finishes.push({ assignmentId, succeeded, code });
        },
      },
    ),
    (error) => error === failure,
  );
  assert.deepEqual(failures, ["local-telemetry-start-failed"]);
  assert.deepEqual(finishes, [{
    assignmentId: "assignment-monitor-cleanup",
    succeeded: false,
    code: "local-telemetry-start-failed",
  }]);
  assert.deepEqual(stopped.sort(), ["heartbeat", "operator"]);
});

test("portable claimed lifecycle never fails a remotely completed assignment during local reconciliation", async (t) => {
  const stateDirectory = await mkdtemp(join(tmpdir(), "hch-portable-terminal-reconcile-"));
  t.after(() => rm(stateDirectory, { recursive: true, force: true }));
  const config = {
    ...telemetryConfig(stateDirectory, 1),
    localEngineBaseUrl: "http://127.0.0.1:11434",
    localEngineNumThreads: 2,
  };
  let finishAttempts = 0;
  let remoteFailCalls = 0;
  const result = await runClaimedPortableAssignment(
    config,
    stateDirectory,
    { nodeId: config.nodeId },
    { requestId: "request-terminal-reconcile" },
    {
      assignmentId: "assignment-terminal-reconcile",
      leaseExpiresAt: "2026-08-28T12:05:00.000Z",
    },
    { adaptiveWorkPolicy: {} },
    {
      now: () => Date.parse("2026-08-28T12:00:00.000Z"),
      startAssignmentHeartbeat: () => ({
        lost: false,
        stalled: false,
        async stopAndWait() {},
      }),
      startOperatorStopMonitor: () => ({
        requested: false,
        async stopAndWait() {},
      }),
      generateEditorialDraft: async () => ({ draft: { content: "accepted" } }),
      stopHeartbeatBeforeComplete: async () => {},
      completeAssignment: async () => ({ status: "pending-review" }),
      failAssignment: async () => { remoteFailCalls += 1; },
      markFinished: async (...args) => {
        finishAttempts += 1;
        if (finishAttempts === 1) {
          throw new WorkerKitError(
            "local-telemetry-write-failed",
            "injected post-completion telemetry failure",
          );
        }
        return markFinished(...args);
      },
    },
  );

  assert.deepEqual(result, {
    claimed: 1,
    completed: 1,
    failed: 0,
    assignmentId: "assignment-terminal-reconcile",
    status: "pending-review",
  });
  assert.equal(finishAttempts, 2);
  assert.equal(remoteFailCalls, 0);
  const metrics = await readState(stateDirectory, "metrics.json");
  const status = await readState(stateDirectory, "status.json");
  assert.equal(metrics.currentBatch, null);
  assert.equal(status.currentBatch, null);
  assert.equal(metrics.jobs.running, 0);
  assert.equal(metrics.jobs.completed, 1);
  assert.equal(metrics.jobs.failed, 0);
  assert.equal(metrics.batches.completed, 1);
  assert.equal(metrics.batches.failed, 0);
  assert.equal(status.state, "standby");
  assert.equal(status.code, "batch-completed");
});

test("portable telemetry adopts and finishes a legacy current batch without assignment ids", async (t) => {
  const stateDirectory = await mkdtemp(join(tmpdir(), "hch-portable-telemetry-legacy-"));
  t.after(() => rm(stateDirectory, { recursive: true, force: true }));
  const config = telemetryConfig(stateDirectory, 1);
  const legacyBatch = {
    batchId: "legacy-batch",
    jobs: 1,
    completedJobs: 0,
    startedAt: "2026-08-28T11:00:00.000Z",
  };
  const metrics = defaultMetrics(config);
  metrics.batches.total = 1;
  metrics.jobs.claimed = 1;
  metrics.jobs.running = 1;
  metrics.currentBatch = legacyBatch;
  metrics.standby = { active: false, since: null, totalMilliseconds: 0 };
  await writeFile(join(stateDirectory, "metrics.json"), JSON.stringify(metrics));
  await writeFile(join(stateDirectory, "status.json"), JSON.stringify({
    state: "processing",
    running: true,
    standby: false,
    currentBatch: legacyBatch,
    code: "assignment-processing",
  }));

  await markProcessing(
    stateDirectory,
    config,
    { requestId: "new-request-id" },
    { assignmentId: "legacy-assignment" },
    { now: () => Date.parse("2026-08-28T12:00:00.000Z") },
  );
  let currentMetrics = await readState(stateDirectory, "metrics.json");
  let status = await readState(stateDirectory, "status.json");
  assert.deepEqual(currentMetrics.currentBatch.assignmentIds, ["legacy-assignment"]);
  assert.deepEqual(status.currentBatch, currentMetrics.currentBatch);
  assert.equal(currentMetrics.currentBatch.batchId, "legacy-batch");
  assert.equal(currentMetrics.jobs.claimed, 1);
  assert.equal(currentMetrics.batches.total, 1);

  await markFinished(
    stateDirectory,
    config,
    "legacy-assignment",
    true,
    "batch-completed",
  );
  currentMetrics = await readState(stateDirectory, "metrics.json");
  status = await readState(stateDirectory, "status.json");
  assert.equal(currentMetrics.currentBatch, null);
  assert.equal(status.currentBatch, null);
  assert.equal(currentMetrics.jobs.running, 0);
  assert.equal(currentMetrics.jobs.completed, 1);
  assert.equal(status.state, "standby");
});

test("portable telemetry clears an invalid status batch instead of leaving processing forever", async (t) => {
  const stateDirectory = await mkdtemp(join(tmpdir(), "hch-portable-telemetry-invalid-"));
  t.after(() => rm(stateDirectory, { recursive: true, force: true }));
  const config = telemetryConfig(stateDirectory, 1);
  await writeFile(join(stateDirectory, "metrics.json"), JSON.stringify(defaultMetrics(config)));
  await writeFile(join(stateDirectory, "status.json"), JSON.stringify({
    state: "processing",
    running: true,
    standby: false,
    currentBatch: "invalid-current-batch",
    code: "assignment-processing",
  }));
  await markFinished(
    stateDirectory,
    config,
    "assignment-invalid-status",
    false,
    "local-telemetry-start-failed",
  );
  const status = await readState(stateDirectory, "status.json");
  assert.equal(status.currentBatch, null);
  assert.equal(status.running, false);
  assert.equal(status.state, "connection-error");
});

test("portable telemetry canonicalizes and retires sixty-four concurrent assignments", async (t) => {
  const stateDirectory = await mkdtemp(join(tmpdir(), "hch-portable-telemetry-n64-"));
  t.after(() => rm(stateDirectory, { recursive: true, force: true }));
  const config = telemetryConfig(stateDirectory, 64);
  const assignmentIds = Array.from(
    { length: 64 },
    (_, index) => `assignment-${String(64 - index).padStart(2, "0")}`,
  );
  await Promise.all(assignmentIds.map((assignmentId, index) =>
    markProcessing(
      stateDirectory,
      config,
      { requestId: `request-${index}` },
      { assignmentId },
    )));

  let metrics = await readState(stateDirectory, "metrics.json");
  assert.deepEqual(
    metrics.currentBatch.assignmentIds,
    [...assignmentIds].sort(),
  );
  assert.equal(metrics.currentBatch.jobs, 64);
  assert.equal(metrics.jobs.running, 64);
  assert.equal(metrics.jobs.claimed, 64);
  assert.equal(metrics.batches.total, 64);

  await Promise.all(assignmentIds.map((assignmentId) =>
    markFinished(stateDirectory, config, assignmentId, true, "batch-completed")));
  metrics = await readState(stateDirectory, "metrics.json");
  const status = await readState(stateDirectory, "status.json");
  assert.equal(metrics.currentBatch, null);
  assert.equal(status.currentBatch, null);
  assert.equal(metrics.jobs.running, 0);
  assert.equal(metrics.jobs.completed, 64);
  assert.equal(metrics.batches.completed, 64);
});

test("claim gate tolerates bounded control-plane clock skew", () => {
  const manifestHash = "a".repeat(64);
  const manifestSequence = 5;
  const policyHash = "b".repeat(64);
  const status = {
    ready: true,
    manifestHash,
    manifestSequence,
    trust: { manifestHash, manifestSequence, policyHash },
  };
  assert.doesNotThrow(() => assertClaimGate(
    { nodeId: "node-1" },
    { acceptingClaims: true, drainRequested: false, requestedCapacity: 1 },
    {
      ready: true,
      readyUntil: new Date(Date.now() + 60_000).toISOString(),
      manifestHash,
      manifestSequence,
      policyHash,
      workerRuntimeVersion: "3.1.0",
    },
    { manifestHash, manifestSequence, policyHash, workerRuntimeVersion: "3.1.0" },
    { manifestHash, manifestSequence, policyHash },
    status,
    {
      nodeId: "node-1",
      heartbeat: {
        status: "succeeded",
        lastSuccessAt: new Date(Date.now() + 5_000).toISOString(),
      },
      claim: { allowed: true, recommendedCount: 1 },
    },
  ));
  assert.throws(() => assertClaimGate(
    { nodeId: "node-1" },
    { acceptingClaims: true, drainRequested: false, requestedCapacity: 1 },
    {
      ready: true,
      readyUntil: new Date(Date.now() + 60_000).toISOString(),
      manifestHash,
      manifestSequence,
      policyHash,
      workerRuntimeVersion: "3.1.0",
    },
    { manifestHash, manifestSequence, policyHash, workerRuntimeVersion: "3.1.0" },
    { manifestHash, manifestSequence, policyHash },
    status,
    {
      nodeId: "node-1",
      heartbeat: {
        status: "succeeded",
        lastSuccessAt: new Date(Date.now() + 121_000).toISOString(),
      },
      claim: { allowed: true, recommendedCount: 1 },
    },
  ), (error) => error?.code === "claims-gates-closed");
});

test("claim gate rejects ready or applied state from another worker runtime", () => {
  const manifestHash = "a".repeat(64);
  const manifestSequence = 5;
  const policyHash = "b".repeat(64);
  const control = { acceptingClaims: true, drainRequested: false, requestedCapacity: 1 };
  const ready = {
    ready: true,
    readyUntil: new Date(Date.now() + 60_000).toISOString(),
    manifestHash,
    manifestSequence,
    policyHash,
    workerRuntimeVersion: "3.1.0",
  };
  const trustState = { manifestHash, manifestSequence, policyHash };
  const status = {
    ready: true,
    manifestHash,
    manifestSequence,
    trust: trustState,
  };
  const orchestration = {
    nodeId: "node-1",
    heartbeat: { status: "succeeded", lastSuccessAt: new Date().toISOString() },
    claim: { allowed: true, recommendedCount: 1 },
  };
  assert.throws(
    () => assertClaimGate(
      { nodeId: "node-1" }, control,
      { ...ready, workerRuntimeVersion: "3.0.0" },
      { manifestHash, manifestSequence, policyHash, workerRuntimeVersion: "3.1.0" },
      trustState, status, orchestration,
    ),
    (error) => error?.code === "claims-gates-closed",
  );
  assert.throws(
    () => assertClaimGate(
      { nodeId: "node-1" }, control, ready,
      { manifestHash, manifestSequence, policyHash, workerRuntimeVersion: "3.0.0" },
      trustState, status, orchestration,
    ),
    (error) => error?.code === "claims-gates-closed",
  );
});

test("claim gate and readiness renewal reject a crash window between trust and ready", async (t) => {
  const stateRoot = await mkdtemp(join(tmpdir(), "hch-portable-trust-window-"));
  t.after(() => rm(stateRoot, { recursive: true, force: true }));
  const manifestHash = "a".repeat(64);
  const policyHash = "b".repeat(64);
  const ready = {
    ready: true,
    readyUntil: "2026-08-15T00:10:00.000Z",
    manifestHash,
    manifestSequence: 5,
    policyHash,
    workerRuntimeVersion: "3.1.0",
  };
  const applied = { ...ready, ready: undefined };
  const advancedTrust = {
    manifestHash: "c".repeat(64),
    manifestSequence: 6,
    policyHash: "d".repeat(64),
  };
  await writeFile(join(stateRoot, "ready.json"), JSON.stringify(ready));
  await writeFile(join(stateRoot, "applied-manifest.json"), JSON.stringify(applied));
  await writeFile(join(stateRoot, "trust-state.json"), JSON.stringify(advancedTrust));
  let renewals = 0;
  await renewReadyAttestation({ requestedCapacity: 1 }, stateRoot, {
    now: () => Date.parse("2026-08-15T00:00:00.000Z"),
    bootstrapWorkerLocked: async () => { renewals += 1; return { ready: false }; },
  });
  assert.equal(renewals, 1);
  assert.throws(
    () => assertClaimGate(
      { nodeId: "node-1" },
      { acceptingClaims: true, drainRequested: false, requestedCapacity: 1 },
      ready,
      applied,
      advancedTrust,
      {
        ready: true,
        manifestHash,
        manifestSequence: 5,
        trust: { manifestHash, manifestSequence: 5, policyHash },
      },
      {
        nodeId: "node-1",
        heartbeat: { status: "succeeded", lastSuccessAt: new Date().toISOString() },
        claim: { allowed: true, recommendedCount: 1 },
      },
    ),
    (error) => error?.code === "claims-gates-closed",
  );
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

test("portable readiness does not renew more than five minutes early", async (t) => {
  const stateRoot = await mkdtemp(join(tmpdir(), "hch-portable-ready-window-"));
  t.after(() => rm(stateRoot, { recursive: true, force: true }));
  const stableState = {
    manifestHash: "a".repeat(64),
    manifestSequence: 5,
    policyHash: "b".repeat(64),
    workerRuntimeVersion: "3.1.0",
  };
  await writeFile(join(stateRoot, "ready.json"), JSON.stringify({
    ready: true,
    workerRuntimeVersion: "3.1.0",
    requestedCapacity: 0,
    readyUntil: "2026-08-15T00:10:00.000Z",
    ...stableState,
  }));
  await writeFile(join(stateRoot, "applied-manifest.json"), JSON.stringify(stableState));
  await writeFile(join(stateRoot, "trust-state.json"), JSON.stringify(stableState));
  await writeFile(join(stateRoot, "status.json"), JSON.stringify({
    ready: true,
    manifestHash: stableState.manifestHash,
    manifestSequence: stableState.manifestSequence,
    trust: stableState,
  }));
  let renewals = 0;
  const ready = await renewReadyAttestation({ requestedCapacity: 0 }, stateRoot, {
    now: () => Date.parse("2026-08-15T00:00:00.000Z"),
    bootstrapWorkerLocked: async () => { renewals += 1; return { ready: true }; },
  });
  assert.equal(renewals, 0);
  assert.equal(ready.requestedCapacity, 0);
});

test("portable readiness renews state produced by another worker runtime", async (t) => {
  const stateRoot = await mkdtemp(join(tmpdir(), "hch-portable-ready-runtime-"));
  t.after(() => rm(stateRoot, { recursive: true, force: true }));
  const stableState = {
    manifestHash: "a".repeat(64),
    manifestSequence: 5,
    policyHash: "b".repeat(64),
  };
  const ready = {
    ready: true,
    workerRuntimeVersion: "3.0.0",
    readyUntil: "2026-08-15T00:10:00.000Z",
    ...stableState,
  };
  await writeFile(join(stateRoot, "ready.json"), JSON.stringify(ready));
  await writeFile(join(stateRoot, "applied-manifest.json"), JSON.stringify({
    ...stableState,
    workerRuntimeVersion: "3.1.0",
  }));
  await writeFile(join(stateRoot, "trust-state.json"), JSON.stringify(stableState));
  await writeFile(join(stateRoot, "status.json"), JSON.stringify({
    ready: true,
    manifestHash: stableState.manifestHash,
    manifestSequence: stableState.manifestSequence,
    trust: stableState,
  }));
  let renewals = 0;
  await renewReadyAttestation({ requestedCapacity: 0 }, stateRoot, {
    now: () => Date.parse("2026-08-15T00:00:00.000Z"),
    bootstrapWorkerLocked: async () => { renewals += 1; return { ready: true }; },
  });
  assert.equal(renewals, 1);

  await writeFile(join(stateRoot, "ready.json"), JSON.stringify({
    ...ready,
    workerRuntimeVersion: "3.1.0",
  }));
  await writeFile(join(stateRoot, "applied-manifest.json"), JSON.stringify({
    ...stableState,
    workerRuntimeVersion: "3.0.0",
  }));
  await renewReadyAttestation({ requestedCapacity: 0 }, stateRoot, {
    now: () => Date.parse("2026-08-15T00:00:00.000Z"),
    bootstrapWorkerLocked: async () => { renewals += 1; return { ready: true }; },
  });
  assert.equal(renewals, 2);
});

test("portable readiness renewal preserves an active work lifecycle", async (t) => {
  const stateRoot = await mkdtemp(join(tmpdir(), "hch-portable-active-renewal-"));
  t.after(() => rm(stateRoot, { recursive: true, force: true }));
  await writeFile(join(stateRoot, "ready.json"), JSON.stringify({
    ready: true,
    readyUntil: "2026-08-15T00:15:00.000Z",
  }));
  await writeFile(join(stateRoot, "status.json"), JSON.stringify({
    running: true,
    currentBatch: { batchId: "active" },
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

test("portable readiness renewal resets a completed lifecycle", async (t) => {
  const stateRoot = await mkdtemp(join(tmpdir(), "hch-portable-complete-renewal-"));
  t.after(() => rm(stateRoot, { recursive: true, force: true }));
  await writeFile(join(stateRoot, "ready.json"), JSON.stringify({
    ready: true,
    readyUntil: "2026-08-15T00:15:00.000Z",
  }));
  await writeFile(join(stateRoot, "status.json"), JSON.stringify({
    running: false,
    currentBatch: null,
  }));
  let receivedOptions = null;
  await renewReadyAttestation({ requestedCapacity: 0 }, stateRoot, {
    now: () => Date.parse("2026-08-15T00:14:00.000Z"),
    bootstrapWorkerLocked: async (_config, _stateRoot, options) => {
      receivedOptions = options;
      return { ready: true };
    },
  });
  assert.equal(receivedOptions.preserveLifecycle, false);
});

test("portable assignment start leaves standby telemetry", async () => {
  const source = await readFile(new URL("../lib/supervisor.mjs", import.meta.url), "utf8");
  const markProcessing = source.slice(
    source.indexOf("export function markProcessing"),
    source.indexOf("export function markFinished"),
  );
  assert.match(markProcessing, /leaveStandby\(current\)/);
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

function telemetryConfig(stateDirectory, requestedCapacity) {
  return {
    stateDirectory,
    nodeId: "telemetry-node",
    keyId: "telemetry-key",
    requestedCapacity,
  };
}

async function readState(stateDirectory, name) {
  return JSON.parse(await readFile(join(stateDirectory, name), "utf8"));
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

async function editorialGeneratorFixture(t) {
  const stateRoot = await mkdtemp(join(tmpdir(), "hch-generator-retry-"));
  t.after(() => rm(stateRoot, { recursive: true, force: true }));
  await mkdir(join(stateRoot, "runtime/editorial"), { recursive: true });
  const profile = await runtimeProfile({ maxOutputTokens: 2400 });
  const editorialPolicy = {
    policyId: profile.policyId,
    version: profile.policyVersion,
    hash: profile.policyHash,
    citationPolicy: {
      singleSourceExceptionRequiresJustification: true,
      comparisonsAndReviewsMinimumSources: 2,
    },
    quotationPolicy: {
      maximumQuotationRatio: 0.05,
      maximumWordsPerDirectQuotation: 25,
    },
    profiles: {
      EDITORIAL_LONG_FORM: {
        minimumBodyCharacters: 1,
        maximumBodyCharacters: 100_000,
        minimumBodyWords: 1,
        maximumBodyWords: 20_000,
        minimumParagraphs: 5,
        maximumParagraphs: 5,
        minimumWordsPerParagraph: 1,
      },
    },
  };
  await Promise.all([
    writeFile(
      join(stateRoot, "runtime/editorial/policy.json"),
      JSON.stringify(editorialPolicy),
    ),
    writeFile(join(stateRoot, "runtime/editorial/prompt.md"), "System prompt de teste."),
  ]);
  const policyHash = await adaptiveWorkPolicyHash(policy);
  const generationPlan = createGenerationPlan(policy, 2, {
    policyHash,
    editorialProfile: "EDITORIAL_LONG_FORM",
  });
  return {
    stateRoot,
    assignment: {
      assignmentId: "generator-retry-assignment",
      generationPlan,
      generationPlanHash: await generationPlanHash(generationPlan),
      runtimeProfile: profile,
      entry: {
        kind: "article",
        source_url: "https://example.com/source",
        source_locale: "pt-BR",
        content_hash: "5".repeat(64),
        title: "Fonte técnica usada no teste controlado",
        summary: "Resumo ingerido da fonte técnica para o teste controlado. ".repeat(8),
        author: "Equipe de teste",
        publisher: "HCH",
        published_at: "2026-08-28T00:00:00.000Z",
      },
    },
    options: {
      adaptiveWorkPolicy: policy,
      lookup: async () => [{ address: "93.184.216.34", family: 4 }],
      fetcher: async () => { throw new Error("offline-test-source"); },
      platform: "linux",
      localEngineNumThreads: 2,
    },
  };
}

function ollamaCompletion(content, doneReason) {
  return new Response(`${JSON.stringify({
    message: { content },
    done: true,
    done_reason: doneReason,
  })}\n`, {
    status: 200,
    headers: { "content-type": "application/x-ndjson" },
  });
}
