import { readFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";

const [runtimeRootArg, stateRootArg, model, modelDigest, concurrencyArg, samplesArg] =
  process.argv.slice(2);
const runtimeRoot = resolve(runtimeRootArg ?? ".");
const stateRoot = resolve(stateRootArg ?? "/var/lib/hch-editorial-worker");
const concurrency = Number(concurrencyArg ?? 1);
const samples = Number(samplesArg ?? concurrency);
if (!model || !/^[a-f0-9]{64}$/.test(modelDigest ?? "")) {
  throw new Error("usage: benchmark <runtime-root> <state-root> <model> <digest> <concurrency> <samples>");
}
if (!Number.isSafeInteger(concurrency) || concurrency < 1 || concurrency > 64) {
  throw new Error("concurrency must be between 1 and 64");
}
if (!Number.isSafeInteger(samples) || samples < concurrency || samples > 256) {
  throw new Error("samples must be between concurrency and 256");
}

const moduleAt = (relativePath) => import(pathToFileURL(join(runtimeRoot, relativePath)).href);
const [{ generateEditorialDraft }, { canonicalizeJson, sha256Hex }, sizing] = await Promise.all([
  moduleAt("ops/linux/editorial-worker/lib/generator.mjs"),
  moduleAt("ops/linux/editorial-worker/crypto.mjs"),
  moduleAt("lib/editorial-work-sizing.mjs"),
]);
const applied = JSON.parse(await readFile(join(stateRoot, "applied-manifest.json"), "utf8"));
const profileCore = {
  ...Object.fromEntries(Object.entries(applied.runtimeProfile).filter(([key]) => key !== "runtimeProfileHash")),
  model,
  modelDigest,
};
const runtimeProfile = {
  ...profileCore,
  runtimeProfileHash: await sha256Hex(canonicalizeJson(profileCore)),
};
const generationPlan = sizing.createGenerationPlan(applied.adaptiveWorkPolicy, 2, {
  policyHash: applied.adaptiveWorkPolicyHash,
  editorialProfile: "EDITORIAL_LONG_FORM",
});
const generationPlanHash = await sizing.generationPlanHash(generationPlan);
const sourceText = `
Uma plataforma distribuída de processamento editorial precisa equilibrar vazão, qualidade e rastreabilidade. O uso de uma GPU acelera a inferência, mas o ganho real depende de o modelo produzir conteúdo que satisfaça os critérios editoriais sem reparos sucessivos. A orquestração deve medir resultados válidos por unidade de tempo, preservar o isolamento entre trabalhos e manter os registros locais coerentes com o estado remoto.

Cada execução recebe uma fonte imutável, uma política assinada e um plano de geração. O worker valida os artefatos antes de iniciar, mantém heartbeats durante o processamento e envia o resultado para revisão humana. Quando várias tarefas são executadas ao mesmo tempo, os identificadores ativos precisam permanecer visíveis até que cada tarefa alcance um estado terminal, inclusive quando as conclusões chegam em ordem diferente.

A capacidade ótima não corresponde necessariamente ao maior número configurável de processos. Concorrência excessiva pode aumentar respostas incompletas, reparos e reprovações editoriais. Por isso o ajuste deve avançar em degraus, comparar a quantidade de rascunhos aprovados pelo validador e recuar quando a taxa de sucesso ou a vazão válida cair.

O benchmark isolado usa a mesma política, o mesmo prompt, o mesmo orçamento de saída e a mesma fonte para todos os modelos. Os resultados não são publicados nem enviados ao orquestrador. Apenas contagens, latências e códigos de falha são agregados, permitindo selecionar o modelo e o paralelismo antes de alterar o manifesto de produção.

Depois da escolha, uma ativação controlada confirma que o comportamento observado no ensaio também ocorre com atribuições reais. A promoção só é considerada operacional quando o worker mantém heartbeats, conclui rascunhos válidos, atualiza a telemetria sem perder trabalhos concorrentes e continua reversível.
`.trim();
const html = `<html><body><article><h1>Eficiência de workers editoriais com GPU</h1><p>${sourceText.replaceAll("\n\n", "</p><p>")}</p></article></body></html>`;

function assignment(index) {
  return {
    assignmentId: `benchmark-${model.replaceAll(/[^a-z0-9]/gi, "-")}-${index}`,
    runtimeProfile,
    adaptiveWorkPolicy: applied.adaptiveWorkPolicy,
    generationPlan,
    generationPlanHash,
    entry: {
      source_url: "https://example.com/hch-gpu-benchmark",
      title: "Eficiência de workers editoriais com GPU",
      summary: sourceText,
      author: "HubTech Benchmark",
      publisher: "HubTech",
      published_at: "2026-08-28T00:00:00.000Z",
      source_locale: "pt-BR",
      content_hash: "b".repeat(64),
      kind: "article",
    },
  };
}

const started = performance.now();
let cursor = 0;
const outcomes = [];
async function runner() {
  while (cursor < samples) {
    const index = cursor;
    cursor += 1;
    const sampleStarted = performance.now();
    try {
      await generateEditorialDraft(assignment(index), stateRoot, "http://127.0.0.1:11434", {
        localEngineNumThreads: 2,
        lookup: async () => [{ address: "93.184.216.34", family: 4 }],
        fetcher: async () => new Response(html, {
          status: 200,
          headers: { "content-type": "text/html; charset=utf-8" },
        }),
      });
      outcomes.push({ ok: true, milliseconds: performance.now() - sampleStarted });
    } catch (error) {
      const validationCodes = Array.isArray(error?.validation?.errors)
        ? error.validation.errors.map((item) => String(item?.code ?? "unknown")).sort()
        : [];
      outcomes.push({
        ok: false,
        milliseconds: performance.now() - sampleStarted,
        code: String(error?.code ?? error?.name ?? "unknown"),
        validationCodes,
      });
    }
  }
}
await Promise.all(Array.from({ length: concurrency }, () => runner()));
const wallMilliseconds = performance.now() - started;
const successes = outcomes.filter((item) => item.ok);
const failures = outcomes.filter((item) => !item.ok);
const failureCodes = {};
for (const failure of failures) {
  const key = [failure.code, ...failure.validationCodes].join(":");
  failureCodes[key] = (failureCodes[key] ?? 0) + 1;
}
console.log(JSON.stringify({
  schemaVersion: 1,
  model,
  modelDigest,
  concurrency,
  samples,
  successes: successes.length,
  failures: failures.length,
  wallSeconds: Number((wallMilliseconds / 1000).toFixed(3)),
  validPerMinute: Number((successes.length * 60000 / wallMilliseconds).toFixed(3)),
  averageSampleSeconds: Number((outcomes.reduce((sum, item) => sum + item.milliseconds, 0) / outcomes.length / 1000).toFixed(3)),
  failureCodes,
}, null, 2));
