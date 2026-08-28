import { readFile } from "node:fs/promises";
import { isIP } from "node:net";
import { lookup } from "node:dns/promises";
import http from "node:http";
import https from "node:https";

import {
  computeEditorialMetrics,
  validateEditorialDraft,
} from "../../../../lib/editorial-policy.mjs";
import { fitGeneratedParagraphToProfile } from "../../../../lib/editorial-normalization.mjs";
import { verifyRuntimeProfile } from "./runtime-profile.mjs";
import { verifyGenerationPlan } from "./adaptive-work.mjs";
import { WorkerKitError } from "./errors.mjs";

const MAX_SOURCE_BYTES = 2_000_000;
const MAX_EVIDENCE_CHARACTERS = 8_000;
const MAX_MODEL_EVIDENCE_CHARACTERS = 3_000;
const SOURCE_TIMEOUT_MS = 25_000;
const MAX_GENERATOR_RESPONSE_BYTES = 2 * 1024 * 1024;
const MAX_GENERATION_ATTEMPTS = 2;

export async function generateEditorialDraft(
  assignment,
  stateRoot,
  localEngineBaseUrl,
  options = {},
) {
  const profile = await verifyRuntimeProfile(assignment.runtimeProfile);
  const [policy, prompt] = await Promise.all([
    readJson(`${stateRoot}/runtime/editorial/policy.json`),
    readFile(`${stateRoot}/runtime/editorial/prompt.md`, "utf8"),
  ]);
  const adaptiveWorkPolicy = assignment.adaptiveWorkPolicy ?? options.adaptiveWorkPolicy;
  const generationPlan = await verifyGenerationPlan(
    assignment.generationPlan,
    assignment.generationPlanHash,
    adaptiveWorkPolicy,
    profile,
  );
  assertRuntimeArtifacts(profile, policy);
  const evidence = await fetchSourceEvidence(assignment.entry, options.fetcher, {
    lookup: options.lookup,
    signal: options.signal,
    sourceTimeoutMilliseconds: options.sourceTimeoutMilliseconds,
  });
  const sourceExcerpt = modelEvidenceExcerpt(evidence.text);
  const source = {
    sourceId: "S1",
    canonicalUrl: assignment.entry.source_url,
    title: assignment.entry.title,
    author: assignment.entry.author || "Autoria não informada pela fonte",
    publisher: assignment.entry.publisher || "Publicador não informado pela fonte",
    publishedAt: assignment.entry.published_at || null,
    retrievedAt: evidence.retrievedAt,
    sourceLocale: assignment.entry.source_locale,
    sourceRevisionId: assignment.entry.content_hash,
    normalizedHash: await sha256(sourceExcerpt),
    rightsBasis: "unknown",
    rightsEvidenceId: null,
    license: null,
    commercialUseAllowed: false,
    derivativeUseAllowed: false,
    translationAllowed: false,
    fullRepublicationAllowed: false,
  };
  const contentType = mapContentType(assignment.entry.kind);
  const editorialProfile = generationPlan.editorialProfile;
  const input = {
    contentType,
    editorialProfile,
    audience: "profissionais e estudantes de tecnologia",
    locale: "pt-BR",
    objective: "produzir conteúdo autoral e tecnicamente verificável para o HCH",
    sourceExcerpt,
    sourceEvidenceMode: evidence.mode,
    sourceLanguagePolicy: assignment.entry.source_locale === "pt-BR"
      ? "source-already-pt-br"
      : "preserve-source-language-no-unapproved-translation",
    sources: [source],
  };
  let previousCandidate = null;
  let lastValidation = null;

  for (let attempt = 1; attempt <= MAX_GENERATION_ATTEMPTS; attempt += 1) {
    options.progress?.startAttempt(attempt);
    const requestBody = JSON.stringify(ollamaGenerationRequest({
      profile,
      generationPlan,
      prompt,
      editorialProfile,
      input,
      platform: options.platform ?? process.platform,
      localEngineNumThreads: options.localEngineNumThreads,
      attempt,
      lastValidation,
      previousCandidate,
    }));

    let payload;
    try {
      payload = await requestOllamaNdjson(
        new URL("/api/chat", localEngineBaseUrl),
        requestBody,
        {
          generationPlan,
          fetcher: options.generatorFetcher,
          signal: options.signal,
          onContent: (bytes) => options.progress?.recordContent(bytes),
          maximumBytes: options.maximumGeneratorBytes,
        },
      );
    } catch (error) {
      throw normalizeGeneratorError(error);
    }
    const parsed = parseCandidateAttempt(payload);
    if (!parsed.ok) {
      previousCandidate = null;
      lastValidation = {
        valid: false,
        errors: [{ code: parsed.code, message: "O gerador não concluiu um objeto JSON válido." }],
      };
      continue;
    }
    options.progress?.beginFinalization();
    const draft = buildDraft({
      candidate: parsed.candidate,
      editorialProfile,
      contentType,
      profile,
      generationPlan,
      assignment,
      source,
      policy,
    });
    const validation = validateEditorialDraft(draft, policy);
    if (validation.valid) {
      draft.metrics = validation.metrics;
      return { draft, validation };
    }
    previousCandidate = boundedRepairCandidate(parsed.candidate);
    lastValidation = validation;
  }
  const error = new WorkerKitError(
    "editorial-validation-failed",
    "The generated draft did not pass the signed editorial policy.",
  );
  error.validation = lastValidation;
  throw error;
}

export function ollamaGenerationRequest(input) {
  const profileRequirements = requirements(input.editorialProfile);
  if (input.localEngineNumThreads !== null && input.localEngineNumThreads !== undefined &&
      (!Number.isSafeInteger(input.localEngineNumThreads) ||
       input.localEngineNumThreads < 1 || input.localEngineNumThreads > 64)) {
    throw new TypeError("localEngineNumThreads must be an integer between 1 and 64.");
  }
  return {
    model: input.profile.model,
    stream: true,
    // Ollama's JSON-schema grammar can terminate complex constrained output
    // with HTTP 500 before the worker can validate or repair the candidate.
    // JSON mode keeps transport portable; the signed editorial policy remains
    // authoritative in buildDraft/validateEditorialDraft below.
    format: "json",
    options: {
      temperature: input.profile.temperature,
      num_ctx: input.profile.contextWindow,
      // Large Darwin prefill batches can make Ollama fail with HTTP 500 under
      // memory pressure before the first progress chunk. Keep the signed
      // context/output budgets intact while lowering only the local batch.
      ...(input.platform === "darwin" ? { num_batch: 256 } : {}),
      ...(input.localEngineNumThreads === null || input.localEngineNumThreads === undefined
        ? {}
        : { num_thread: input.localEngineNumThreads }),
      // The immutable generation plan owns the exact output budget. Never
      // infer, increase, or renegotiate it locally.
      num_predict: input.generationPlan.maxOutputTokens,
    },
    messages: [
      {
        role: "system",
        content: `${input.prompt}\n\nRetorne exclusivamente o objeto JSON solicitado, sem Markdown, comentários ou blocos de código.`,
      },
      {
        role: "user",
        content: JSON.stringify({
          operation: input.attempt === 1
            ? "generate-editorial-content"
            : "repair-editorial-content",
          requiredResponseKeys: ["title", "excerpt", "paragraphs"],
          fieldRequirements: {
            title: "string final autoral em português brasileiro, com pelo menos 8 caracteres",
            excerpt: "string final autoral em português brasileiro, com pelo menos 20 caracteres",
            paragraphs: {
              type: "array de strings finais autorais",
              exactCount: profileRequirements.paragraphs,
              characterRange: profileRequirements.characters ?? null,
              wordRange: profileRequirements.words ?? null,
              minimumWordsPerParagraph: profileRequirements.minimumWordsPerParagraph ?? null,
            },
          },
          responseRules: [
            "retorne o objeto de conteúdo, não um schema ou objeto wrapper",
            "paragraphs deve ser um array de strings com a contagem exigida",
            "não renomeie title, excerpt ou paragraphs",
            "os valores devem ser o conteúdo editorial final, nunca descrições, instruções ou placeholders",
          ],
          requirements: profileRequirements,
          input: input.input,
          validationFeedback: input.lastValidation?.errors ?? [],
          previousCandidate: input.previousCandidate,
        }),
      },
    ],
  };
}

export function modelEvidenceExcerpt(value) {
  return String(value).slice(0, MAX_MODEL_EVIDENCE_CHARACTERS).trim();
}

/**
 * Reads Ollama's line-delimited JSON stream. Only non-empty
 * message.content bytes count as material progress. There is intentionally no
 * total execution timeout: near/over-window work continues while responding,
 * including the minimum tier where the advisory window is ignored.
 */
export async function requestOllamaNdjson(urlValue, requestBody, options) {
  const url = validateLoopbackOllamaUrl(urlValue);
  const generationPlan = options?.generationPlan;
  validateWatchdogPlan(generationPlan);
  const fetcher = options?.fetcher ?? fetch;
  const controller = new AbortController();
  const externalSignal = options.signal;
  let phase = "starting";
  let watchdog = armWatchdog(
    controller,
    generationPlan.firstProgressGraceSeconds,
    "generator-first-progress-timeout",
  );
  const maximumBytes = options.maximumBytes ?? MAX_GENERATOR_RESPONSE_BYTES;
  let received = 0;
  let content = "";
  let finalChunk = null;
  try {
    const signal = externalSignal
      ? AbortSignal.any([controller.signal, externalSignal])
      : controller.signal;
    const response = await fetcher(url, {
      method: "POST",
      headers: {
        Accept: "application/x-ndjson, application/json",
        "Accept-Encoding": "identity",
        "Content-Type": "application/json",
      },
      body: requestBody,
      credentials: "omit",
      redirect: "error",
      signal,
    });
    if (!response.ok) {
      throw new WorkerKitError(
        `local-generator-http-${response.status}`,
        `The local generator rejected the request with HTTP ${response.status}.`,
      );
    }
    if (!response.body || typeof response.body.getReader !== "function") {
      throw new WorkerKitError("local-generator-response-refused", "Ollama did not return a stream.");
    }
    const reader = response.body.getReader();
    const decoder = new TextDecoder("utf-8", { fatal: true });
    let buffer = "";
    const consumeLine = (line) => {
      const trimmed = line.trim();
      if (!trimmed) return;
      const chunk = JSON.parse(trimmed);
      if (typeof chunk?.error === "string" && chunk.error.trim()) {
        throw new WorkerKitError("local-generator-error", "Ollama returned an inference error.");
      }
      if (typeof chunk?.message?.content === "string" && chunk.message.content) {
        const bytes = Buffer.byteLength(chunk.message.content, "utf8");
        content += chunk.message.content;
        phase = "responding";
        clearTimeout(watchdog);
        watchdog = armWatchdog(
          controller,
          generationPlan.stallAfterSeconds,
          "generator-stalled",
        );
        options.onContent?.(bytes);
      }
      if (chunk?.done === true) finalChunk = chunk;
    };
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      received += value.byteLength;
      if (received > maximumBytes) {
        await reader.cancel().catch(() => {});
        throw new WorkerKitError("local-generator-response-too-large", "Ollama response exceeded its limit.");
      }
      buffer += decoder.decode(value, { stream: true });
      const lines = buffer.split("\n");
      buffer = lines.pop() ?? "";
      for (const line of lines) consumeLine(line);
    }
    buffer += decoder.decode();
    consumeLine(buffer);
    phase = "finalizing";
    clearTimeout(watchdog);
    watchdog = armWatchdog(
      controller,
      generationPlan.finalizationGraceSeconds,
      "generator-finalization-stalled",
    );
    if (
      !content.trim() ||
      finalChunk?.done !== true ||
      finalChunk?.done_reason !== "stop"
    ) {
      throw new WorkerKitError("generator-output-incomplete", "Ollama did not complete the response.");
    }
    const candidate = JSON.parse(content);
    clearTimeout(watchdog);
    return {
      done: true,
      done_reason: finalChunk.done_reason ?? null,
      message: { content: JSON.stringify(candidate) },
    };
  } catch (error) {
    if (externalSignal?.aborted) {
      throw new WorkerKitError(
        externalSignal.reason?.code ?? "generator-stalled",
        "The assignment heartbeat stopped the local generator fail-closed.",
      );
    }
    if (controller.signal.aborted) {
      const code = controller.signal.reason?.code ??
        (phase === "starting"
          ? "generator-first-progress-timeout"
          : phase === "finalizing"
            ? "generator-finalization-stalled"
            : "generator-stalled");
      throw new WorkerKitError(code, "The local generator stopped demonstrating progress.");
    }
    throw normalizeGeneratorError(error);
  } finally {
    clearTimeout(watchdog);
  }
}

export function parseCandidateAttempt(payload) {
  if (
    payload && typeof payload === "object" && !Array.isArray(payload) &&
    ((Object.hasOwn(payload, "done") && payload.done !== true) ||
      (typeof payload.done_reason === "string" && payload.done_reason !== "stop"))
  ) {
    return { ok: false, code: "GEN-OUTPUT-INCOMPLETE" };
  }
  const value = payload?.message?.content ?? payload?.content ?? payload?.output ?? payload;
  if (typeof value === "string") {
    try {
      const candidate = JSON.parse(
        value.replace(/^```(?:json)?\s*/i, "").replace(/\s*```$/, ""),
      );
      if (candidate && typeof candidate === "object" && !Array.isArray(candidate)) {
        return { ok: true, candidate };
      }
    } catch {
      return { ok: false, code: "GEN-JSON-INVALID" };
    }
  }
  if (value && typeof value === "object" && !Array.isArray(value)) {
    return { ok: true, candidate: value };
  }
  return { ok: false, code: "GEN-OUTPUT-INVALID" };
}

function buildDraft(input) {
  const paragraphs = normalizeParagraphs(input.candidate.paragraphs, input.editorialProfile);
  const excerpt = input.editorialProfile === "EDITORIAL_LONG_FORM"
    ? sanitize(input.candidate.excerpt)
    : paragraphs[0]?.text ?? "";
  return {
    schemaVersion: "1.1",
    contentId: `hch-generated-${crypto.randomUUID()}`,
    contentType: input.contentType,
    editorialProfile: input.editorialProfile,
    locale: "pt-BR",
    title: sanitize(input.candidate.title),
    excerpt,
    sourceSelectionJustification:
      "Pauta originada de uma única fonte canônica ingerida; fatos externos permanecem limitados ao snapshot fornecido e a publicação exige revisão humana.",
    paragraphs,
    sources: [input.source],
    metrics: computeEditorialMetrics(paragraphs),
    provenance: {
      policyId: input.profile.policyId,
      policyVersion: input.profile.policyVersion,
      promptConfigHash: input.profile.promptConfigHash,
      pipelineVersion: input.profile.pipelineVersion,
      modelProvider: input.profile.provider,
      modelIdentifier: input.profile.model,
      generatedAt: new Date().toISOString(),
      generationPlanHash: input.assignment.generationPlanHash,
      generationTier: input.generationPlan.tierId,
      maxOutputTokens: input.generationPlan.maxOutputTokens,
    },
    review: { status: "pending-editorial-review" },
  };
}

function requirements(profile) {
  const shared = {
    citations: "cada parágrafo deve terminar com [S1]",
    quotations: "não use citações diretas",
    originality: "não copie formulação nem estrutura da fonte",
    format: "texto corrido, sem Markdown, HTML, listas ou blocos de código",
  };
  if (profile === "EVENT_LISTING") return { ...shared, paragraphs: 1, characters: "220-500" };
  if (profile === "CATALOG_SUMMARY") return { ...shared, paragraphs: 1, characters: "240-480" };
  if (profile === "EDITORIAL_COMPACT") {
    return { ...shared, paragraphs: 2, characters: "900-1800", words: "130-260", minimumWordsPerParagraph: 45 };
  }
  if (profile === "EDITORIAL_MINIMUM") {
    return { ...shared, paragraphs: 1, characters: "320-800", words: "50-115", minimumWordsPerParagraph: 50 };
  }
  return { ...shared, paragraphs: 5, minimumBodyCharacters: 3200, minimumBodyWords: 450 };
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
    const requested = raw && typeof raw === "object" ? raw : {};
    const rawText = typeof raw === "string" ? raw : requested.text;
    const text = fitGeneratedParagraphToProfile(ensureCitation(sanitize(rawText)), profile);
    return {
      paragraphId: `P${index + 1}`,
      function: [
        "lead", "source-context", "technical-explanation",
        "analysis-limitations", "conclusion-access",
      ][index] ?? "supporting",
      text,
      wordCount: countWords(text),
      citationIds: ["S1"],
      claims: [{
        claimId: `P${index + 1}C1`,
        text: text.replace(/\s*\[S1\]\s*$/, "").slice(0, 240),
        claimType: "source-statement",
        sourceIds: ["S1"],
      }],
    };
  });
}

function coalesceSingleParagraphCandidate(value) {
  if (value.length <= 1) return value;
  const text = value
    .map((raw) => typeof raw === "string" ? raw : raw?.text)
    .map((raw) => sanitize(raw).replace(/\s*\[S1\][.!?]?\s*$/i, "").trim())
    .filter(Boolean)
    .join(" ");
  return text ? [text] : [];
}

export async function fetchSourceEvidence(entry, fetcher, options = {}) {
  const retrievedAt = new Date().toISOString();
  try {
    const sourceUrl = validatePublicSourceUrl(entry.source_url);
    const target = validatePublicSourceUrl(tabNewsApiUrl(sourceUrl) ?? sourceUrl.href);
    const destination = await resolvePublicSourceDestination(
      target,
      options.lookup ?? lookup,
    );
    const response = fetcher
      ? await fetcher(target, {
          headers: sourceRequestHeaders(target),
          redirect: "error",
          signal: options.signal ?? AbortSignal.timeout(
            options.sourceTimeoutMilliseconds ?? SOURCE_TIMEOUT_MS,
          ),
          // Test and embedding fetchers must honor the already validated,
          // pinned destination. Production never delegates this boundary.
          hchPinnedAddress: destination.address,
          hchPinnedFamily: destination.family,
        })
      : await requestPinnedPublicSource(target, destination, {
          signal: options.signal,
          timeoutMilliseconds: options.sourceTimeoutMilliseconds ?? SOURCE_TIMEOUT_MS,
        });
    if (!response.ok) throw new Error("source-unavailable");
    const bytes = await readBoundedResponseBody(response, MAX_SOURCE_BYTES);
    const decoded = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    if (target.pathname.includes("/api/v1/contents/")) {
      const payload = JSON.parse(decoded);
      const text = normalizeEvidence(`${payload.title ?? entry.title}\n\n${payload.body ?? ""}`);
      if (text.length >= 240) return { text, mode: "tabnews-api", retrievedAt };
    } else {
      const text = normalizeEvidence(extractHtml(decoded));
      if (text.length >= 240) return { text, mode: "canonical-html", retrievedAt };
    }
  } catch {
    // The immutable assignment snapshot is the fail-closed evidence fallback.
  }
  return {
    text: normalizeEvidence(`${entry.title}\n\n${entry.summary}`),
    mode: "ingested-summary",
    retrievedAt,
  };
}

export function validatePublicSourceUrl(value) {
  const url = value instanceof URL ? new URL(value.href) : new URL(String(value));
  if (
    !new Set(["http:", "https:"]).has(url.protocol) ||
    url.username || url.password
  ) {
    throw new WorkerKitError("source-url-refused", "Source URL must be credential-free HTTP(S).");
  }
  const hostname = url.hostname.toLowerCase().replace(/^\[|\]$/g, "").replace(/\.$/, "");
  if (
    !hostname ||
    hostname === "localhost" || hostname.endsWith(".localhost") ||
    hostname === "metadata.google.internal" || hostname.endsWith(".metadata.google.internal") ||
    hostname === "instance-data" || hostname.endsWith(".instance-data") ||
    isPrivateOrReservedIp(hostname)
  ) {
    throw new WorkerKitError("source-url-refused", "Source URL resolves to a local or reserved target.");
  }
  return url;
}

export async function assertPublicSourceDestination(urlValue, resolver = lookup) {
  await resolvePublicSourceDestination(urlValue, resolver);
  return validatePublicSourceUrl(urlValue);
}

export async function resolvePublicSourceDestination(urlValue, resolver = lookup) {
  const url = validatePublicSourceUrl(urlValue);
  const hostname = url.hostname.toLowerCase().replace(/^\[|\]$/g, "").replace(/\.$/, "");
  if (isIP(hostname)) {
    return Object.freeze({ url, address: hostname, family: isIP(hostname) });
  }
  let addresses;
  try {
    addresses = await resolver(hostname, { all: true, verbatim: true });
  } catch {
    throw new WorkerKitError("source-dns-refused", "Source hostname could not be resolved safely.");
  }
  if (!Array.isArray(addresses) || !addresses.length || addresses.some((entry) =>
    typeof entry?.address !== "string" ||
    !new Set([4, 6]).has(Number(entry?.family)) ||
    isPrivateOrReservedIp(entry.address)
  )) {
    throw new WorkerKitError("source-url-refused", "Source hostname resolves to a local or reserved target.");
  }
  const selected = addresses[0];
  return Object.freeze({
    url,
    address: selected.address,
    family: Number(selected.family),
  });
}

function sourceRequestHeaders(target) {
  return {
    Accept: target.pathname.includes("/api/v1/contents/")
      ? "application/json"
      : "text/html,application/xhtml+xml",
    "User-Agent": "Hubtech-Community-Hub-Editorial/2.2 (+https://hubtech.online)",
  };
}

export async function requestPinnedPublicSource(target, destination, options = {}) {
  const transport = target.protocol === "https:" ? https : http;
  const headers = sourceRequestHeaders(target);
  return new Promise((resolvePromise, rejectPromise) => {
    let settled = false;
    let incoming = null;
    const settle = (callback, value) => {
      if (settled) return;
      settled = true;
      clearTimeout(timeout);
      options.signal?.removeEventListener("abort", abort);
      callback(value);
    };
    const request = transport.request({
      protocol: target.protocol,
      hostname: target.hostname,
      port: target.port || undefined,
      path: `${target.pathname}${target.search}`,
      method: "GET",
      headers,
      agent: false,
      servername: target.protocol === "https:" ? target.hostname : undefined,
      lookup(_hostname, _options, callback) {
        if (_options?.all) {
          callback(null, [{ address: destination.address, family: destination.family }]);
        } else {
          callback(null, destination.address, destination.family);
        }
      },
    });
    const timeoutMilliseconds = options.timeoutMilliseconds ?? SOURCE_TIMEOUT_MS;
    const timeout = setTimeout(() => request.destroy(new WorkerKitError(
      "source-timeout",
      "Source request exceeded its bounded total deadline.",
    )), timeoutMilliseconds);
    timeout.unref?.();
    const abort = () => {
      const reason = options.signal?.reason instanceof Error
        ? options.signal.reason
        : new WorkerKitError("source-request-aborted", "Source request was aborted.");
      incoming?.destroy(reason);
      request.destroy(reason);
    };
    if (options.signal?.aborted) abort();
    else options.signal?.addEventListener("abort", abort, { once: true });
    request.once("error", (error) => {
      settle(rejectPromise, error);
    });
    request.once("response", (response) => {
      incoming = response;
      const status = Number(response.statusCode ?? 0);
      if (status < 200 || status >= 300) {
        response.destroy();
        settle(rejectPromise, new WorkerKitError(
          status >= 300 && status < 400 ? "source-redirect-refused" : "source-unavailable",
          "Source response was refused.",
        ));
        return;
      }
      resolvePromise(new Response(new ReadableStream({
        start(controller) {
          response.on("data", (chunk) => controller.enqueue(new Uint8Array(chunk)));
          response.once("end", () => {
            settle(() => {}, undefined);
            controller.close();
          });
          response.once("error", (error) => {
            settle(() => {}, undefined);
            controller.error(error);
          });
          response.once("aborted", () => {
            settle(() => {}, undefined);
            controller.error(
            new WorkerKitError("source-response-aborted", "Source response aborted."),
            );
          });
        },
        cancel() {
          response.destroy();
          settle(() => {}, undefined);
        },
      }), {
        status,
        headers: response.headers,
      }));
    });
    request.end();
  });
}

export async function readBoundedResponseBody(response, maximumBytes) {
  if (!Number.isSafeInteger(maximumBytes) || maximumBytes < 1 || !response?.body) {
    throw new TypeError("Bounded source response options are invalid.");
  }
  const declaredText = response.headers?.get?.("content-length");
  if (declaredText !== null && declaredText !== undefined && declaredText !== "") {
    if (!/^(?:0|[1-9]\d*)$/.test(declaredText.trim())) {
      throw new WorkerKitError("source-response-refused", "Source content-length is invalid.");
    }
    if (Number(declaredText) > maximumBytes) {
      throw new WorkerKitError("source-too-large", "Source body exceeds its byte limit.");
    }
  }
  const reader = response.body.getReader();
  const chunks = [];
  let received = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      received += value.byteLength;
      if (received > maximumBytes) {
        await reader.cancel().catch(() => {});
        throw new WorkerKitError("source-too-large", "Source body exceeds its byte limit.");
      }
      chunks.push(Buffer.from(value));
    }
  } finally {
    reader.releaseLock?.();
  }
  return Buffer.concat(chunks, received);
}

function isPrivateOrReservedIp(hostname) {
  const family = isIP(hostname);
  if (family === 4) {
    const octets = hostname.split(".").map(Number);
    const [a, b] = octets;
    return a === 0 || a === 10 || a === 127 ||
      (a === 100 && b >= 64 && b <= 127) ||
      (a === 169 && b === 254) ||
      (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && b === 168) ||
      (a === 192 && b === 0) ||
      (a === 192 && b === 88) ||
      (a === 198 && (b === 18 || b === 19)) ||
      (a === 198 && b === 51) ||
      (a === 203 && b === 0) ||
      a >= 224;
  }
  if (family === 6) {
    const normalized = hostname.toLowerCase();
    if (normalized === "::" || normalized === "::1") return true;
    if (/^(?:fc|fd)/.test(normalized) || /^fe[89ab]/.test(normalized) || /^ff/.test(normalized)) {
      return true;
    }
    const mappedDecimal = normalized.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/);
    if (mappedDecimal) return isPrivateOrReservedIp(mappedDecimal[1]);
    const mappedHex = normalized.match(/^::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/);
    if (mappedHex) {
      const high = Number.parseInt(mappedHex[1], 16);
      const low = Number.parseInt(mappedHex[2], 16);
      return isPrivateOrReservedIp([
        high >>> 8,
        high & 0xff,
        low >>> 8,
        low & 0xff,
      ].join("."));
    }
    return false;
  }
  return false;
}

function validateLoopbackOllamaUrl(value) {
  const url = value instanceof URL ? value : new URL(String(value));
  const hostname = url.hostname.toLowerCase().replace(/^\[|\]$/g, "");
  if (
    !new Set(["127.0.0.1", "localhost", "::1"]).has(hostname) ||
    !new Set(["http:", "https:"]).has(url.protocol) ||
    url.username || url.password || url.pathname !== "/api/chat" || url.search || url.hash
  ) {
    throw new WorkerKitError("local-generator-url-refused", "Ollama must be explicit loopback /api/chat.");
  }
  return url;
}

function validateWatchdogPlan(plan) {
  for (const field of [
    "firstProgressGraceSeconds", "stallAfterSeconds", "finalizationGraceSeconds",
  ]) {
    if (!Number.isSafeInteger(plan?.[field]) || plan[field] < 1) {
      throw new TypeError(`generationPlan.${field} is invalid.`);
    }
  }
}

function armWatchdog(controller, seconds, code) {
  const error = new WorkerKitError(code, "The generator stopped demonstrating progress.");
  const timer = setTimeout(() => controller.abort(error), seconds * 1_000);
  timer.unref?.();
  return timer;
}

function assertRuntimeArtifacts(profile, policy) {
  if (
    policy?.policyId !== profile.policyId ||
    policy?.version !== profile.policyVersion ||
    policy?.hash !== profile.policyHash
  ) throw new WorkerKitError("runtime-policy-mismatch", "Installed editorial policy is inconsistent.");
  if (profile.protocol !== "ollama-chat" || profile.engineAdapter !== "ollama") {
    throw new WorkerKitError("runtime-adapter-unsupported", "Only the attested Ollama adapter is supported.");
  }
}

function normalizeGeneratorError(error) {
  if (error?.code === "generator-stalled") return error;
  if (error?.code === "generator-first-progress-timeout") return error;
  if (error?.code === "generator-finalization-stalled") return error;
  if (error instanceof WorkerKitError) return error;
  if (error instanceof SyntaxError) {
    return new WorkerKitError(
      "local-generator-response-invalid",
      "Ollama returned an invalid streaming response.",
      { cause: error },
    );
  }
  return new WorkerKitError(
    "local-generator-transport-failed",
    "The local generator transport failed.",
    error instanceof Error ? { cause: error } : {},
  );
}

function boundedRepairCandidate(candidate) {
  const serialized = JSON.stringify(candidate);
  if (serialized.length <= 2_000) return { fragment: serialized, truncated: false };
  return { fragment: serialized.slice(0, 1_980), truncated: true };
}

function mapContentType(kind) {
  if (kind === "event") return "event";
  if (kind === "radar") return "radar";
  if (kind === "article") return "article";
  return "news";
}

function ensureCitation(value) {
  return /\[S1\]\s*$/.test(value) ? value : `${value.replace(/\s+$/, "")} [S1]`;
}

function sanitize(value) {
  return String(value ?? "")
    .replace(/<[^>]+>/g, " ")
    .replace(/\[([^\]]+)\]\(https?:\/\/[^)]+\)/gi, "$1")
    .replace(/(?:\*\*|__|`{1,3})/g, "")
    .replace(/(^|\n)\s*#{1,6}\s+/g, "$1")
    .replace(/(^|\n)\s*(?:[-*+]\s+|\d+\.\s+)/g, "$1")
    .replace(/[“”"]/g, "'")
    .replace(/\s*\n+\s*/g, " ")
    .replace(/\s{2,}/g, " ")
    .trim();
}

function tabNewsApiUrl(url) {
  if (!new Set(["www.tabnews.com.br", "tabnews.com.br"]).has(url.hostname)) return null;
  const parts = url.pathname.split("/").filter(Boolean);
  if (parts.length < 2 || parts[0] === "api") return null;
  return `https://www.tabnews.com.br/api/v1/contents/${encodeURIComponent(parts[0])}/${encodeURIComponent(parts.slice(1).join("/"))}`;
}

function extractHtml(html) {
  const clean = html
    .replace(/<!--[^]*?-->/g, " ")
    .replace(/<(script|style|noscript|svg|canvas|form|nav|footer|header|aside)[^>]*>[^]*?<\/\1>/gi, " ");
  const body = clean.match(/<article\b[^>]*>([^]*?)<\/article>/i)?.[1] ??
    clean.match(/<main\b[^>]*>([^]*?)<\/main>/i)?.[1] ?? clean;
  return decodeEntities(
    body.replace(/<br\s*\/?>/gi, "\n")
      .replace(/<\/(?:p|div|section|h[1-6]|li|blockquote)>/gi, "\n")
      .replace(/<[^>]+>/g, " "),
  );
}

function decodeEntities(value) {
  const named = { amp: "&", lt: "<", gt: ">", quot: "'", apos: "'", nbsp: " " };
  return value.replace(/&(#x?[0-9a-f]+|[a-z]+);/gi, (match, entity) => {
    if (!entity.startsWith("#")) return named[entity.toLowerCase()] ?? match;
    const hex = entity[1]?.toLowerCase() === "x";
    const code = Number.parseInt(entity.slice(hex ? 2 : 1), hex ? 16 : 10);
    return Number.isFinite(code) ? String.fromCodePoint(code) : match;
  });
}

function normalizeEvidence(value) {
  return String(value)
    .replace(/\r/g, "")
    .replace(/[ \t]+/g, " ")
    .replace(/\n[ \t]+/g, "\n")
    .replace(/\n{3,}/g, "\n\n")
    .trim()
    .slice(0, MAX_EVIDENCE_CHARACTERS);
}

function countWords(value) {
  return String(value).match(/[\p{L}\p{N}][\p{L}\p{N}'’_-]*/gu)?.length ?? 0;
}

async function sha256(value) {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  return Buffer.from(digest).toString("hex");
}

async function readJson(path) {
  return JSON.parse(await readFile(path, "utf8"));
}
