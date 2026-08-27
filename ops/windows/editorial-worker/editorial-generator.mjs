#!/usr/bin/env node

import { createHash, randomUUID } from "node:crypto";
import {
  mkdirSync,
  readFileSync,
  renameSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import {
  computeEditorialMetrics,
  validateEditorialDraft,
} from "../../../lib/editorial-policy.mjs";
import { fitGeneratedParagraphToProfile } from "../../../lib/editorial-normalization.mjs";
import { editorialModelRelease } from "../../../lib/editorial-model-catalog.mjs";
import { canonicalizeJson } from "../../../lib/editorial-worker-signatures.mjs";
import { canonicalLfText } from "../../../lib/canonical-text.mjs";

const MAX_GENERATION_ATTEMPTS = 2;
const MAX_OLLAMA_STREAM_BYTES = 4_000_000;
const PROGRESS_WRITE_THROTTLE_MS = 1_000;
const PROGRESS_WRITE_BYTE_DELTA = 4_096;
const LOCAL_OLLAMA_HOSTS = new Set(["127.0.0.1", "[::1]", "::1", "localhost"]);
const PARAGRAPH_FUNCTIONS = Object.freeze([
  "lead",
  "source-context",
  "technical-explanation",
  "analysis-limitations",
  "conclusion-access",
  "supporting",
]);

export class WorkerGeneratorError extends Error {
  constructor(code, message = code, options) {
    super(message, options);
    this.name = "WorkerGeneratorError";
    this.code = code;
  }
}

/**
 * Loads only signed/install-time runtime material. The reusable policy,
 * normalization, model-catalog and RFC 8785 implementations are imported from
 * the repository core above; this runner does not maintain private copies.
 */
export function loadInstalledEditorialRuntime({
  runtimeRoot,
  appliedManifestPath,
  ollamaBaseUri,
  pipelineVersion,
}) {
  const root = resolveRequired(runtimeRoot, "runtime-root-required");
  const policy = readJson(resolve(root, "editorial", "policy.json"), "runtime-policy-invalid");
  const prompt = canonicalLfText(
    readText(resolve(root, "editorial", "prompt.md"), "runtime-prompt-invalid"),
  );
  const engine = readJson(resolve(root, "config", "engine.json"), "runtime-engine-config-invalid");
  const applied = appliedManifestPath
    ? readJson(resolve(appliedManifestPath), "applied-manifest-invalid")
    : null;

  assertPolicyIntegrity(policy);
  assertEngineIntegrity(engine);
  assertAdaptiveWorkPolicyIntegrity(policy, engine);
  const release = editorialModelRelease(engine.engine.model, engine.engine.protocol);
  if (
    !release ||
    release.digest !== engine.engine.modelDigest ||
    release.engineAdapter !== engine.engine.adapter ||
    release.engineAdapterVersion !== engine.engine.adapterVersion
  ) {
    throw new WorkerGeneratorError("runtime-model-release-mismatch");
  }

  const effectivePipelineVersion = String(
    pipelineVersion ?? applied?.pipelineVersion ?? "",
  ).trim();
  if (!effectivePipelineVersion) {
    throw new WorkerGeneratorError("runtime-pipeline-version-missing");
  }
  const promptConfigHash = sha256(`${prompt}\n${policy.hash}\n${effectivePipelineVersion}`);

  if (applied) {
    assertEqual(applied.manifestHash, engine.manifestHash, "runtime-applied-manifest-hash-mismatch");
    assertNumberEqual(applied.sequence, engine.manifestSequence, "runtime-applied-manifest-sequence-mismatch");
    assertEqual(applied.policyHash, policy.hash, "runtime-applied-policy-hash-mismatch");
    assertEqual(
      applied.adaptiveWorkPolicyHash,
      engine.adaptiveWorkPolicyHash,
      "runtime-applied-adaptive-work-policy-hash-mismatch",
    );
    assertEqual(applied.promptConfigHash, promptConfigHash, "runtime-applied-prompt-hash-mismatch");
    assertEqual(applied.pipelineVersion, effectivePipelineVersion, "runtime-applied-pipeline-mismatch");
    for (const [appliedName, engineName] of [
      ["provider", "provider"],
      ["engineAdapter", "adapter"],
      ["engineAdapterVersion", "adapterVersion"],
      ["model", "model"],
      ["modelDigest", "modelDigest"],
    ]) {
      assertEqual(
        applied[appliedName],
        engine.engine[engineName],
        `runtime-applied-engine-mismatch:${appliedName}`,
      );
    }
  }

  const baseUri = assertLocalOllamaBaseUri(ollamaBaseUri);
  if (String(engine.engine.generationPath ?? "") !== "/api/chat") {
    throw new WorkerGeneratorError("runtime-ollama-generation-path-invalid");
  }
  if (String(engine.engine.healthPath ?? "") !== "/api/tags") {
    throw new WorkerGeneratorError("runtime-ollama-health-path-invalid");
  }

  return {
    root,
    policy,
    prompt,
    engine,
    applied,
    release,
    pipelineVersion: effectivePipelineVersion,
    promptConfigHash,
    adaptiveWorkPolicy: engine.adaptiveWorkPolicy,
    adaptiveWorkPolicyHash: engine.adaptiveWorkPolicyHash,
    ollamaBaseUri: baseUri,
    healthEndpoint: new URL(engine.engine.healthPath, baseUri).href,
    generationEndpoint: new URL(engine.engine.generationPath, baseUri).href,
  };
}

export async function preflightInstalledEditorialRuntime(options, fetchImpl = fetch) {
  const runtime = loadInstalledEditorialRuntime(options);
  await assertInstalledOllamaModel(runtime, fetchImpl);
  return {
    valid: true,
    provider: runtime.engine.engine.provider,
    adapter: runtime.engine.engine.adapter,
    adapterVersion: runtime.engine.engine.adapterVersion,
    model: runtime.engine.engine.model,
    modelDigest: runtime.engine.engine.modelDigest,
    protocol: runtime.engine.engine.protocol,
    manifestSequence: Number(runtime.engine.manifestSequence),
    manifestHash: runtime.engine.manifestHash,
    policyHash: runtime.policy.hash,
    adaptiveWorkPolicyHash: runtime.adaptiveWorkPolicyHash,
    promptConfigHash: runtime.promptConfigHash,
    pipelineVersion: runtime.pipelineVersion,
  };
}

export async function generateEditorialDraftFromAssignment({
  assignment,
  runtimeRoot,
  appliedManifestPath,
  ollamaBaseUri,
  fetchImpl = fetch,
  now = () => new Date(),
  idFactory = randomUUID,
  progressPath,
}) {
  assertAssignmentEnvelope(assignment);
  const profile = assignment.runtimeProfile;
  const runtime = loadInstalledEditorialRuntime({
    runtimeRoot,
    appliedManifestPath,
    ollamaBaseUri,
    pipelineVersion: profile.pipelineVersion,
  });
  assertAssignmentRuntime(assignment, runtime);
  const generationPlan = assertAssignmentGenerationPlan(assignment, runtime);
  await assertInstalledOllamaModel(runtime, fetchImpl);

  const entry = assignment.entry;
  const sourceExcerpt = normalizeEvidence(`${String(entry.title ?? "")}\n\n${String(entry.summary ?? "")}`);
  if (!sourceExcerpt) throw new WorkerGeneratorError("assignment-source-evidence-empty");
  const generatedAt = now().toISOString();
  const source = {
    sourceId: "S1",
    canonicalUrl: assertHttpUrl(entry.source_url),
    title: requiredText(entry.title, "assignment-source-title-missing"),
    author: String(entry.author || "Autoria não informada pela fonte"),
    publisher: String(entry.publisher || "Publicador não informado pela fonte"),
    publishedAt: entry.published_at || null,
    retrievedAt: generatedAt,
    sourceLocale: requiredText(entry.source_locale, "assignment-source-locale-missing"),
    sourceRevisionId: requiredText(entry.content_hash, "assignment-source-revision-missing"),
    normalizedHash: sha256(sourceExcerpt),
    rightsBasis: "unknown",
    rightsEvidenceId: null,
    license: null,
    commercialUseAllowed: false,
    derivativeUseAllowed: false,
    translationAllowed: false,
    fullRepublicationAllowed: false,
  };
  const contentType = mapContentType(entry.kind);
  const editorialProfile = generationPlan.editorialProfile;
  const input = {
    contentType,
    editorialProfile,
    audience: "profissionais e estudantes de tecnologia",
    locale: "pt-BR",
    objective: "produzir conteúdo autoral e tecnicamente verificável para o HCH",
    sourceExcerpt,
    sourceEvidenceMode: "ingested-summary",
    sources: [source],
  };

  let previousCandidate = null;
  let lastValidation = null;
  let lastError = null;
  const progress = createProgressReporter(progressPath, now);
  for (let attempt = 1; attempt <= MAX_GENERATION_ATTEMPTS; attempt += 1) {
    progress.startAttempt(attempt);
    let candidate;
    try {
      const response = await fetchImpl(runtime.generationEndpoint, {
        method: "POST",
        headers: { accept: "application/json", "content-type": "application/json" },
        body: JSON.stringify(ollamaRequest({
          runtime,
          input,
          attempt,
          previousCandidate,
          validation: lastValidation,
          generationPlan,
        })),
      });
      if (!response.ok) {
        throw new WorkerGeneratorError("ollama-generation-http-error", `HTTP ${response.status}`);
      }
      candidate = extractCandidate(await readOllamaPayload(response, progress));
    } catch (error) {
      lastError = normalizeGeneratorError(error);
      if (attempt < MAX_GENERATION_ATTEMPTS) continue;
      throw lastError;
    }

    const paragraphs = normalizeParagraphs(candidate.paragraphs, editorialProfile);
    const excerpt = new Set([
      "EDITORIAL_LONG_FORM",
      "EDITORIAL_COMPACT",
      "EDITORIAL_MINIMUM",
    ]).has(editorialProfile)
      ? sanitizeGeneratedText(candidate.excerpt)
      : paragraphs[0]?.text ?? "";
    const draft = {
      schemaVersion: "1.1",
      contentId: `hch-generated-${idFactory()}`,
      contentType,
      editorialProfile,
      locale: "pt-BR",
      title: sanitizeGeneratedText(candidate.title),
      excerpt,
      sourceSelectionJustification:
        "Pauta originada de uma única fonte canônica ingerida; o texto limita fatos externos ao registro fornecido e exige conferência humana antes da publicação.",
      paragraphs,
      sources: [source],
      metrics: computeEditorialMetrics(paragraphs),
      provenance: {
        policyId: runtime.policy.policyId,
        policyVersion: runtime.policy.version,
        promptConfigHash: runtime.promptConfigHash,
        pipelineVersion: runtime.pipelineVersion,
        modelProvider: profile.provider,
        modelIdentifier: profile.model,
        generatedAt,
        generationPlanHash: normalizedHash(assignment.generationPlanHash),
        generationTier: generationPlan.tierId,
        maxOutputTokens: generationPlan.maxOutputTokens,
      },
      review: { status: "pending-editorial-review" },
    };
    const validation = validateEditorialDraft(draft, runtime.policy);
    if (validation.valid) {
      progress.finalizing(attempt);
      // A mutable local tag must still resolve to the signed digest after the
      // inference stream, immediately before a draft becomes commit-eligible.
      await assertInstalledOllamaModel(runtime, fetchImpl);
      draft.metrics = validation.metrics;
      return { draft, validation, attempts: attempt };
    }
    previousCandidate = candidate;
    lastValidation = validation;
  }

  throw new WorkerGeneratorError(
    "editorial-validation-failed",
    validationFailureMessage(lastValidation, lastError),
  );
}

function assertAssignmentEnvelope(assignment) {
  if (!assignment || typeof assignment !== "object") {
    throw new WorkerGeneratorError("assignment-invalid");
  }
  for (const field of [
    "assignmentId",
    "leaseToken",
    "leaseExpiresAt",
    "inputSnapshotHash",
    "entry",
    "runtimeProfile",
    "generationPlan",
    "generationPlanHash",
  ]) {
    if (!(field in assignment)) throw new WorkerGeneratorError(`assignment-field-missing:${field}`);
  }
  const expiry = Date.parse(String(assignment.leaseExpiresAt));
  if (!Number.isFinite(expiry) || expiry <= Date.now()) {
    throw new WorkerGeneratorError("assignment-lease-expired");
  }
  assertEqual(
    sha256(canonicalizeJson(assignment.entry)),
    normalizedHash(assignment.inputSnapshotHash),
    "assignment-input-snapshot-hash-mismatch",
  );
  const { runtimeProfileHash, ...profileCore } = assignment.runtimeProfile;
  assertEqual(
    sha256(canonicalizeJson(profileCore)),
    normalizedHash(runtimeProfileHash),
    "assignment-runtime-profile-hash-mismatch",
  );
}

function assertAssignmentGenerationPlan(assignment, runtime) {
  const plan = assignment.generationPlan;
  if (!plan || typeof plan !== "object" || Array.isArray(plan)) {
    throw new WorkerGeneratorError("assignment-generation-plan-invalid");
  }
  const expectedKeys = [
    "algorithmVersion",
    "editorialProfile",
    "finalizationGraceSeconds",
    "firstProgressGraceSeconds",
    "maxOutputTokens",
    "minimumUnit",
    "nearWindowSeconds",
    "policyHash",
    "processingWindowSeconds",
    "stallAfterSeconds",
    "tierId",
    "tierRank",
  ].sort();
  if (canonicalizeJson(Object.keys(plan).sort()) !== canonicalizeJson(expectedKeys)) {
    throw new WorkerGeneratorError("assignment-generation-plan-shape-invalid");
  }
  assertEqual(
    sha256(canonicalizeJson(plan)),
    normalizedHash(assignment.generationPlanHash),
    "assignment-generation-plan-hash-mismatch",
  );
  const policy = runtime.adaptiveWorkPolicy;
  const tier = policy.tiers.find((candidate) =>
    candidate.id === plan.tierId && Number(candidate.rank) === Number(plan.tierRank)
  );
  if (!tier) throw new WorkerGeneratorError("assignment-generation-plan-tier-invalid");
  for (const [field, expected] of [
    ["algorithmVersion", policy.algorithmVersion],
    ["maxOutputTokens", tier.maxOutputTokens],
    ["minimumUnit", tier.minimumUnit],
    ["processingWindowSeconds", policy.processingWindowSeconds],
    ["nearWindowSeconds", Math.floor(Number(policy.processingWindowSeconds) * Number(policy.nearWindowRatio))],
    ["firstProgressGraceSeconds", policy.firstProgressGraceSeconds],
    ["stallAfterSeconds", policy.stallAfterSeconds],
    ["finalizationGraceSeconds", policy.finalizationGraceSeconds],
    ["policyHash", runtime.adaptiveWorkPolicyHash],
  ]) {
    if (plan[field] !== expected) {
      throw new WorkerGeneratorError(`assignment-generation-plan-policy-mismatch:${field}`);
    }
  }
  const allowedProfile = new Set([
    String(tier.editorialProfile),
    "CATALOG_SUMMARY",
    "EVENT_LISTING",
  ]);
  if (!allowedProfile.has(String(plan.editorialProfile))) {
    throw new WorkerGeneratorError("assignment-generation-plan-profile-invalid");
  }
  const expectedProfile = assignment.entry?.kind === "event"
    ? "EVENT_LISTING"
    : assignment.entry?.kind === "radar"
      ? "CATALOG_SUMMARY"
      : String(tier.editorialProfile);
  assertEqual(
    plan.editorialProfile,
    expectedProfile,
    "assignment-generation-plan-entry-profile-mismatch",
  );
  if (!Number.isSafeInteger(Number(plan.maxOutputTokens)) || Number(plan.maxOutputTokens) < 1) {
    throw new WorkerGeneratorError("assignment-generation-plan-token-budget-invalid");
  }
  return plan;
}

function assertAssignmentRuntime(assignment, runtime) {
  const profile = assignment.runtimeProfile;
  const engine = runtime.engine.engine;
  const generation = runtime.engine.generation;
  const exactBindings = [
    ["provider", engine.provider],
    ["engineAdapter", engine.adapter],
    ["engineAdapterVersion", engine.adapterVersion],
    ["model", engine.model],
    ["modelDigest", engine.modelDigest],
    ["protocol", engine.protocol],
    ["policyId", runtime.policy.policyId],
    ["policyVersion", runtime.policy.version],
    ["policyHash", runtime.policy.hash],
    ["promptConfigHash", runtime.promptConfigHash],
    ["pipelineVersion", runtime.pipelineVersion],
    ["manifestHash", runtime.engine.manifestHash],
  ];
  for (const [name, expected] of exactBindings) {
    assertEqual(profile[name], expected, `assignment-runtime-mismatch:${name}`);
  }
  for (const [name, expected] of [
    ["temperature", generation.temperature],
    ["contextWindow", generation.contextWindow],
    ["maxOutputTokens", generation.maxOutputTokens],
    ["manifestSequence", runtime.engine.manifestSequence],
  ]) {
    assertNumberEqual(profile[name], expected, `assignment-runtime-mismatch:${name}`);
  }
  if (profile.protocol !== "ollama-chat" || engine.adapter !== "ollama") {
    throw new WorkerGeneratorError("assignment-runtime-not-local-ollama");
  }
}

function assertPolicyIntegrity(policy) {
  const declared = normalizedHash(policy?.hash);
  const { hash: _hash, ...unsigned } = policy ?? {};
  assertEqual(sha256(canonicalizeJson(unsigned)), declared, "runtime-policy-hash-mismatch");
  if (policy.hashAlgorithm !== "sha256" || policy.hashScope !== "canonical-json-without-hash") {
    throw new WorkerGeneratorError("runtime-policy-hash-contract-invalid");
  }
}

function assertEngineIntegrity(engine) {
  if (
    Number(engine?.schemaVersion) !== 2 ||
    !engine?.engine ||
    !engine?.generation ||
    !engine?.adaptiveWorkPolicy
  ) {
    throw new WorkerGeneratorError("runtime-engine-config-invalid");
  }
  for (const field of [
    "provider",
    "adapter",
    "adapterVersion",
    "model",
    "modelDigest",
    "protocol",
    "healthPath",
    "generationPath",
  ]) requiredText(engine.engine[field], `runtime-engine-field-missing:${field}`);
  for (const field of ["temperature", "contextWindow", "maxOutputTokens"]) {
    if (!Number.isFinite(Number(engine.generation[field]))) {
      throw new WorkerGeneratorError(`runtime-generation-field-invalid:${field}`);
    }
  }
  normalizedHash(engine.engine.modelDigest);
  normalizedHash(engine.manifestHash);
  if (!Number.isSafeInteger(Number(engine.manifestSequence)) || Number(engine.manifestSequence) < 1) {
    throw new WorkerGeneratorError("runtime-manifest-sequence-invalid");
  }
}

function assertAdaptiveWorkPolicyIntegrity(policy, engine) {
  const configured = engine.adaptiveWorkPolicy;
  const fromEditorialPolicy = policy?.adaptiveWorkPolicy;
  if (!configured || !fromEditorialPolicy) {
    throw new WorkerGeneratorError("runtime-adaptive-work-policy-missing");
  }
  const calculatedHash = sha256(canonicalizeJson(configured));
  assertEqual(
    calculatedHash,
    normalizedHash(engine.adaptiveWorkPolicyHash),
    "runtime-adaptive-work-policy-hash-mismatch",
  );
  assertEqual(
    canonicalizeJson(configured),
    canonicalizeJson(fromEditorialPolicy),
    "runtime-adaptive-work-policy-artifact-mismatch",
  );
  if (
    configured.algorithmVersion !== "hch-adaptive-work-v1" ||
    configured.windowMode !== "advisory" ||
    configured.minimumTierIgnoresWindow !== true ||
    configured.livenessBasis !== "progress" ||
    !Array.isArray(configured.tiers) ||
    configured.tiers.length < 1
  ) {
    throw new WorkerGeneratorError("runtime-adaptive-work-policy-invalid");
  }
  const orderedTiers = [...configured.tiers].sort((left, right) => left.rank - right.rank);
  for (let index = 0; index < orderedTiers.length; index += 1) {
    const tier = orderedTiers[index];
    const previous = orderedTiers[index - 1];
    if (
      Number(tier.rank) !== index ||
      !Number.isSafeInteger(Number(tier.maxOutputTokens)) ||
      Number(tier.maxOutputTokens) < 1 ||
      Number(tier.maxOutputTokens) > Number(engine.generation.maxOutputTokens) ||
      (previous && Number(tier.maxOutputTokens) <= Number(previous.maxOutputTokens))
    ) {
      throw new WorkerGeneratorError("runtime-adaptive-work-policy-tier-order-invalid");
    }
  }
}

async function assertInstalledOllamaModel(runtime, fetchImpl) {
  let response;
  try {
    response = await fetchImpl(runtime.healthEndpoint, {
      headers: { accept: "application/json" },
      signal: AbortSignal.timeout(15_000),
    });
  } catch (error) {
    throw new WorkerGeneratorError("ollama-health-unavailable", undefined, { cause: error });
  }
  if (!response.ok) throw new WorkerGeneratorError("ollama-health-http-error");
  let payload;
  try { payload = await response.json(); }
  catch (error) {
    throw new WorkerGeneratorError("ollama-health-response-invalid", undefined, { cause: error });
  }
  const expectedName = runtime.engine.engine.model;
  const model = Array.isArray(payload?.models)
    ? payload.models.find((item) => item?.name === expectedName || item?.model === expectedName)
    : null;
  if (!model) throw new WorkerGeneratorError("ollama-model-missing");
  assertEqual(
    normalizedHash(model.digest),
    normalizedHash(runtime.engine.engine.modelDigest),
    "ollama-model-digest-mismatch",
  );
}

function ollamaRequest({ runtime, input, attempt, previousCandidate, validation, generationPlan }) {
  const profile = input.editorialProfile;
  return {
    model: runtime.engine.engine.model,
    stream: true,
    format: candidateSchema(profile, runtime.policy),
    options: {
      temperature: Number(runtime.engine.generation.temperature),
      num_ctx: Number(runtime.engine.generation.contextWindow),
      num_predict: Number(generationPlan.maxOutputTokens),
    },
    messages: [
      {
        role: "system",
        content: `${runtime.prompt}\n\nRetorne exclusivamente o objeto JSON solicitado, sem Markdown, comentários ou blocos de código.`,
      },
      {
        role: "user",
        content: JSON.stringify({
          operation: attempt === 1
            ? "generate-editorial-content"
            : "repair-editorial-content",
          requirements: {
            ...generationRequirements(profile, runtime.policy),
            citations: "cada parágrafo deve terminar com [S1]",
            quotations: "não use citações diretas",
            originality:
              "não copie a formulação nem a estrutura da fonte; produza síntese e análise próprias",
            format:
              "use somente texto corrido em cada parágrafo, sem títulos, listas, tabelas, HTML, Markdown, links formatados, blocos de código ou quebras duplas de linha",
          },
          input,
          sourceEvidenceMode: input.sourceEvidenceMode,
          validationFeedback: validation?.errors ?? [],
          previousCandidate,
        }),
      },
    ],
  };
}

function candidateSchema(profile, policy) {
  const compactEditorial = new Set([
    "EDITORIAL_LONG_FORM",
    "EDITORIAL_COMPACT",
    "EDITORIAL_MINIMUM",
  ]).has(profile);
  const summary = !compactEditorial;
  const profilePolicy = policy.profiles?.[profile] ?? {};
  const paragraphCount = summary
    ? Number(profilePolicy.paragraphs ?? 1)
    : Number(profilePolicy.minimumParagraphs ?? 1);
  const minimum = summary ? Number(profilePolicy.minimumCharacters ?? 1) : 1;
  const maximum = summary
    ? Number(profilePolicy.maximumCharacters ?? 2_000)
    : Number(profilePolicy.maximumBodyCharacters ?? 12_000);
  return {
    type: "object",
    required: ["title", "excerpt", "paragraphs"],
    properties: {
      title: { type: "string", minLength: 8, maxLength: 160 },
      excerpt: { type: "string", minLength: 20, maxLength: summary ? maximum : 360 },
      paragraphs: {
        type: "array",
        minItems: paragraphCount,
        maxItems: paragraphCount,
        items: { type: "string", minLength: minimum, maxLength: maximum },
      },
    },
    additionalProperties: false,
  };
}

async function readOllamaPayload(response, progress) {
  if (!response.body) throw new WorkerGeneratorError("ollama-stream-missing");
  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  let buffer = "";
  let content = "";
  let receivedBytes = 0;
  let completed = false;
  let doneReason;
  const consume = (line) => {
    const trimmed = line.trim();
    if (!trimmed) return;
    let chunk;
    try { chunk = JSON.parse(trimmed); }
    catch (error) {
      throw new WorkerGeneratorError("ollama-stream-json-invalid", undefined, { cause: error });
    }
    if (typeof chunk?.error === "string" && chunk.error.trim()) {
      throw new WorkerGeneratorError("ollama-generation-error");
    }
    if (typeof chunk?.message?.content === "string" && chunk.message.content.length > 0) {
      content += chunk.message.content;
      progress.responding(Buffer.byteLength(chunk.message.content, "utf8"));
    }
    if (chunk?.done === true) {
      completed = true;
      doneReason = chunk?.done_reason;
    }
  };
  while (true) {
    const { done, value } = await reader.read();
    receivedBytes += value?.byteLength ?? 0;
    if (receivedBytes > MAX_OLLAMA_STREAM_BYTES) {
      throw new WorkerGeneratorError("ollama-stream-too-large");
    }
    buffer += decoder.decode(value, { stream: !done });
    const lines = buffer.split("\n");
    buffer = lines.pop() ?? "";
    for (const line of lines) consume(line);
    if (done) break;
  }
  consume(buffer);
  if (!content.trim()) throw new WorkerGeneratorError("ollama-stream-empty");
  if (!completed || doneReason !== "stop") {
    throw new WorkerGeneratorError("ollama-stream-incomplete");
  }
  return { message: { content } };
}

function extractCandidate(payload) {
  if (!payload || typeof payload !== "object") {
    throw new WorkerGeneratorError("ollama-candidate-invalid");
  }
  const message = payload.message && typeof payload.message === "object" ? payload.message : null;
  const value = payload.content ?? payload.output ?? payload.draft ?? message?.content ?? payload;
  if (typeof value === "string") {
    const normalized = value.replace(/^```(?:json)?\s*/i, "").replace(/\s*```$/, "");
    try {
      const parsed = JSON.parse(normalized);
      if (!parsed || typeof parsed !== "object") throw new Error("not-object");
      return parsed;
    } catch (error) {
      throw new WorkerGeneratorError("ollama-candidate-json-invalid", undefined, { cause: error });
    }
  }
  if (!value || typeof value !== "object") throw new WorkerGeneratorError("ollama-candidate-invalid");
  return value;
}

export function normalizeParagraphs(value, profile) {
  if (!Array.isArray(value)) return [];
  const normalizedValue = new Set([
    "EDITORIAL_MINIMUM",
    "CATALOG_SUMMARY",
    "EVENT_LISTING",
  ]).has(profile)
    ? coalesceSingleParagraphCandidate(value)
    : value;
  return normalizedValue.map((raw, index) => {
    const paragraph = raw && typeof raw === "object" ? raw : {};
    const rawText = typeof raw === "string" ? raw : String(paragraph.text ?? "");
    const text = fitGeneratedParagraphToProfile(
      ensureSourceCitation(sanitizeGeneratedText(rawText)),
      profile,
    );
    const claims = Array.isArray(paragraph.claims)
      ? paragraph.claims.map((rawClaim, claimIndex) => {
          const claim = rawClaim && typeof rawClaim === "object" ? rawClaim : {};
          const claimType = ["fact", "source-statement", "analysis", "inference"]
            .includes(String(claim.claimType))
            ? String(claim.claimType)
            : "analysis";
          return {
            claimId: String(claim.claimId ?? `P${index + 1}C${claimIndex + 1}`),
            text: String(claim.text ?? text),
            claimType,
            sourceIds: claimType === "fact" || claimType === "source-statement"
              ? stringArray(claim.sourceIds).filter((id) => id === "S1")
              : [],
          };
        })
      : [{
          claimId: `P${index + 1}C1`,
          text: text.replace(/\s*\[S1\]\s*$/, "").slice(0, 240),
          claimType: "source-statement",
          sourceIds: ["S1"],
        }];
    const requestedFunction = String(paragraph.function ?? "supporting");
    return {
      paragraphId: String(paragraph.paragraphId ?? `P${index + 1}`),
      function: PARAGRAPH_FUNCTIONS.includes(requestedFunction) ? requestedFunction : "supporting",
      text,
      wordCount: countWords(text),
      citationIds: ["S1"],
      claims,
    };
  });
}

function coalesceSingleParagraphCandidate(value) {
  if (value.length <= 1) return value;
  const text = value
    .map((raw) => typeof raw === "string" ? raw : raw?.text)
    .map((raw) => sanitizeGeneratedText(raw).replace(/\s*\[S1\][.!?]?\s*$/i, "").trim())
    .filter(Boolean)
    .join(" ");
  // Multiple source objects no longer describe one stable paragraph after
  // coalescing and policy truncation. Rebuild metadata from the final text in
  // normalizeParagraphs instead of retaining claims whose text may be gone.
  return text ? [text] : [];
}

function generationRequirements(profile, policy) {
  const profilePolicy = policy.profiles?.[profile] ?? {};
  if (profile === "EVENT_LISTING") {
    return {
      paragraphs: Number(profilePolicy.paragraphs ?? 1),
      characters: `${profilePolicy.minimumCharacters}-${profilePolicy.maximumCharacters}`,
      objective: "resumo factual de evento",
    };
  }
  if (profile === "CATALOG_SUMMARY") {
    return {
      paragraphs: Number(profilePolicy.paragraphs ?? 1),
      characters: `${profilePolicy.minimumCharacters}-${profilePolicy.maximumCharacters}`,
      objective: "resumo factual de catálogo",
    };
  }
  return {
    paragraphs: Number(profilePolicy.minimumParagraphs ?? 5),
    recommendedWordsPerParagraph: profilePolicy.recommendedWordsPerParagraph ?? null,
    minimumWordsPerParagraph: Number(profilePolicy.minimumWordsPerParagraph ?? 50),
    minimumBodyCharacters: Number(profilePolicy.minimumBodyCharacters ?? 3200),
    minimumBodyWords: Number(profilePolicy.minimumBodyWords ?? 450),
    maximumBodyCharacters: Number(profilePolicy.maximumBodyCharacters ?? 0) || null,
    maximumBodyWords: Number(profilePolicy.maximumBodyWords ?? 0) || null,
  };
}

function mapContentType(kind) {
  if (kind === "event") return "event";
  if (kind === "radar") return "radar";
  if (kind === "article") return "article";
  return "news";
}

function ensureSourceCitation(value) {
  if (!value) return value;
  return /\[S1\]\s*$/.test(value) ? value : `${value.replace(/\s+$/, "")} [S1]`;
}

function sanitizeGeneratedText(value) {
  return String(value ?? "")
    .replace(/&(?:amp;)*lt;[^]*?&(?:amp;)*gt;/gi, " ")
    .replace(/<[^>]+>/g, " ")
    .replace(/\[([^\]]+)\]\(https?:\/\/[^)]+\)/gi, "$1")
    .replace(/(?:\*\*|__|`{1,3})/g, "")
    .replace(/(^|\n)\s*#{1,6}\s+/g, "$1")
    .replace(/(^|\n)\s*(?:[-*+]\s+|\d+\.\s+)/g, "$1")
    .replace(/[\u201c\u201d"]/g, "'")
    .replace(/\s*\n+\s*/g, " ")
    .replace(/\s{2,}/g, " ")
    .trim();
}

function normalizeEvidence(value) {
  return String(value ?? "")
    .replace(/\r/g, "")
    .replace(/[ \t]+/g, " ")
    .replace(/\n[ \t]+/g, "\n")
    .replace(/\n{3,}/g, "\n\n")
    .trim()
    .slice(0, 8_000);
}

function normalizeGeneratorError(error) {
  if (error instanceof WorkerGeneratorError) return error;
  const message = error instanceof Error ? error.message : "";
  if (/unterminated|string|unexpected end|json/i.test(message)) {
    return new WorkerGeneratorError("ollama-candidate-json-incomplete");
  }
  if (error?.name === "TimeoutError" || error?.name === "AbortError") {
    return new WorkerGeneratorError("ollama-generation-timeout");
  }
  return new WorkerGeneratorError("ollama-generation-failed", undefined, { cause: error });
}

function validationFailureMessage(validation, error) {
  const codes = (validation?.errors ?? []).slice(0, 8).map((item) => item.code).join(",");
  return `${error?.code ?? "editorial-validation-failed"}${codes ? `:${codes}` : ""}`;
}

function assertLocalOllamaBaseUri(value) {
  let url;
  try { url = new URL(requiredText(value, "ollama-base-uri-required")); }
  catch (error) {
    if (error instanceof WorkerGeneratorError) throw error;
    throw new WorkerGeneratorError("ollama-base-uri-invalid", undefined, { cause: error });
  }
  if (
    url.protocol !== "http:" ||
    !LOCAL_OLLAMA_HOSTS.has(url.hostname.toLowerCase()) ||
    url.username ||
    url.password ||
    url.search ||
    url.hash ||
    (url.pathname !== "/" && url.pathname !== "")
  ) {
    throw new WorkerGeneratorError("ollama-base-uri-not-loopback");
  }
  return url;
}

function assertHttpUrl(value) {
  const original = String(value ?? "").trim();
  let url;
  try { url = new URL(original); }
  catch (error) {
    throw new WorkerGeneratorError("assignment-source-url-invalid", undefined, { cause: error });
  }
  if (url.protocol !== "http:" && url.protocol !== "https:") {
    throw new WorkerGeneratorError("assignment-source-url-invalid");
  }
  return original;
}

function normalizedHash(value) {
  const normalized = String(value ?? "").trim().toLowerCase();
  if (!/^[a-f0-9]{64}$/.test(normalized)) throw new WorkerGeneratorError("hash-invalid");
  return normalized;
}

function assertEqual(actual, expected, code) {
  if (String(actual ?? "") !== String(expected ?? "")) throw new WorkerGeneratorError(code);
}

function assertNumberEqual(actual, expected, code) {
  if (!Number.isFinite(Number(actual)) || Number(actual) !== Number(expected)) {
    throw new WorkerGeneratorError(code);
  }
}

function requiredText(value, code) {
  const text = String(value ?? "").trim();
  if (!text) throw new WorkerGeneratorError(code);
  return text;
}

function resolveRequired(value, code) {
  return resolve(requiredText(value, code));
}

function readText(path, code) {
  try { return readFileSync(path, "utf8"); }
  catch (error) { throw new WorkerGeneratorError(code, code, { cause: error }); }
}

function readJson(path, code) {
  try { return JSON.parse(readFileSync(path, "utf8")); }
  catch (error) { throw new WorkerGeneratorError(code, code, { cause: error }); }
}

function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}

function stringArray(value) {
  return Array.isArray(value) ? value.filter((item) => typeof item === "string") : [];
}

function countWords(value) {
  return String(value ?? "").match(/[\p{L}\p{N}][\p{L}\p{N}'’_-]*/gu)?.length ?? 0;
}

function writeJsonAtomic(path, value) {
  const target = resolve(path);
  mkdirSync(dirname(target), { recursive: true });
  const temporary = `${target}.${randomUUID()}.tmp`;
  try {
    writeFileSync(temporary, JSON.stringify(value), { encoding: "utf8", flag: "wx", mode: 0o600 });
    renameSync(temporary, target);
  } finally {
    rmSync(temporary, { force: true });
  }
}

function createProgressReporter(progressPath, now) {
  const target = progressPath ? resolve(progressPath) : null;
  let attempt = 1;
  let sequence = 0;
  let contentBytes = 0;
  let lastWrittenAt = 0;
  let lastWrittenBytes = 0;
  const persist = (phase, force = false) => {
    if (!target) return;
    const timestamp = now();
    const epoch = timestamp.getTime();
    if (
      !force &&
      epoch - lastWrittenAt < PROGRESS_WRITE_THROTTLE_MS &&
      contentBytes - lastWrittenBytes < PROGRESS_WRITE_BYTE_DELTA
    ) return;
    writeJsonAtomic(target, {
      phase,
      attempt,
      sequence,
      contentBytes,
      updatedAt: timestamp.toISOString(),
    });
    lastWrittenAt = epoch;
    lastWrittenBytes = contentBytes;
  };
  return {
    startAttempt(value) {
      attempt = value;
      sequence = 0;
      contentBytes = 0;
      lastWrittenBytes = 0;
      persist("starting", true);
    },
    responding(bytes) {
      sequence += 1;
      contentBytes += bytes;
      persist("responding", sequence === 1);
    },
    finalizing(value) {
      attempt = value;
      persist("finalizing", true);
    },
  };
}

function parseArguments(values) {
  const result = new Map();
  for (let index = 0; index < values.length; index += 1) {
    const name = values[index];
    if (!name?.startsWith("--")) throw new WorkerGeneratorError("cli-argument-invalid");
    const value = values[index + 1];
    if (value === undefined || value.startsWith("--")) throw new WorkerGeneratorError("cli-argument-value-missing");
    result.set(name.slice(2), value);
    index += 1;
  }
  return result;
}

async function runCli() {
  const [command, ...rawArguments] = process.argv.slice(2);
  const args = parseArguments(rawArguments);
  const common = {
    runtimeRoot: args.get("runtime-root"),
    appliedManifestPath: args.get("applied-manifest"),
    ollamaBaseUri: args.get("ollama-base-uri"),
  };
  if (command === "preflight") {
    const result = await preflightInstalledEditorialRuntime(common);
    process.stdout.write(`${JSON.stringify(result)}\n`);
    return;
  }
  if (command === "generate") {
    const assignment = readJson(resolveRequired(args.get("assignment"), "assignment-path-required"), "assignment-file-invalid");
    const result = await generateEditorialDraftFromAssignment({
      assignment,
      ...common,
      progressPath: resolveRequired(args.get("progress"), "progress-path-required"),
    });
    writeJsonAtomic(resolveRequired(args.get("output"), "output-path-required"), result.draft);
    process.stdout.write(`${JSON.stringify({ ok: true, attempts: result.attempts })}\n`);
    return;
  }
  throw new WorkerGeneratorError("cli-command-invalid");
}

const isMain = process.argv[1] && pathToFileURL(resolve(process.argv[1])).href === import.meta.url;
if (isMain) {
  runCli().catch((error) => {
    const code = error instanceof WorkerGeneratorError ? error.code : "worker-generator-failed";
    process.stderr.write(`${code}\n`);
    process.exitCode = 1;
  });
}
