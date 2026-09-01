import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import {
  cpSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import { execFileSync } from "node:child_process";

import {
  WorkerGeneratorError,
  generateEditorialDraftFromAssignment,
  loadInstalledEditorialRuntime,
  normalizeParagraphs,
} from "../editorial-generator.mjs";
import { validateEditorialDraft } from "../../../../lib/editorial-policy.mjs";
import { canonicalizeJson } from "../../../../lib/editorial-worker-signatures.mjs";
import { canonicalLfText } from "../../../../lib/canonical-text.mjs";

const kitRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const repositoryRoot = resolve(kitRoot, "../../..");
const policySource = join(repositoryRoot, ".promptsConfig", "editorial-generation-policy.json");
const promptSource = join(repositoryRoot, "prompts", "third-party-editorial-generation.prompt.md");
const model = "qwen2.5:1.5b-instruct";
const modelDigest = "65ec06548149b04c096a120e4a6da9d4017ea809c91734ea5631e89f96ddc57b";
const manifestHash = "a".repeat(64);
const pipelineVersion = "1.2.0";

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
  const [structured] = normalizeParagraphs([{
    paragraphId: "source-a",
    function: "analysis-limitations",
    text: `${first} [S1]`,
    claims: [{ claimId: "analysis-a", text: "Análise A", claimType: "analysis", sourceIds: [] }],
  }, {
    paragraphId: "source-b",
    function: "conclusion-access",
    text: `${second} [S1]`,
    claims: [{ claimId: "source-b", text: "Fato B", claimType: "source-statement", sourceIds: ["S1"] }],
  }], "EDITORIAL_MINIMUM");
  assert.equal(structured.paragraphId, "P1");
  assert.equal(structured.function, "supporting");
  assert.deepEqual(structured.claims.map((claim) => claim.claimType), ["source-statement"]);
  assert.equal(structured.claims.some((claim) => claim.claimId === "source-b"), false);
  const [truncated] = normalizeParagraphs([{
    text: `${Array.from({ length: 100 }, () => "alfa").join(" ")} [S1]`,
    claims: [{ claimId: "claim-a", text: "A", claimType: "analysis", sourceIds: [] }],
  }, {
    text: `${Array.from({ length: 100 }, () => "beta").join(" ")} [S1]`,
    claims: [{ claimId: "claim-b", text: "B", claimType: "source-statement", sourceIds: ["S1"] }],
  }], "EDITORIAL_MINIMUM");
  assert.equal(truncated.wordCount, 115);
  assert.deepEqual(truncated.claims.map((claim) => claim.claimId), ["P1C1"]);
  assert.deepEqual(normalizeParagraphs(["", { text: " " }], "EDITORIAL_MINIMUM"), []);
});

test("local Ollama generator emits the canonical pending-review draft", async (context) => {
  const fixture = runtimeFixture(context);
  const calls = [];
  const fetchImpl = fakeOllama(calls, [longCandidate()]);
  const result = await generateEditorialDraftFromAssignment({
    assignment: fixture.assignment,
    runtimeRoot: fixture.runtimeRoot,
    appliedManifestPath: fixture.appliedPath,
    ollamaBaseUri: "http://127.0.0.1:11434",
    fetchImpl,
    now: () => new Date("2026-08-11T23:00:00.000Z"),
    idFactory: () => "00000000-0000-4000-8000-000000000001",
  });

  assert.equal(result.attempts, 1);
  assert.equal(calls.filter((call) => call.url.endsWith("/api/tags")).length, 2);
  assert.equal(calls.filter((call) => call.url.endsWith("/api/chat")).length, 1);
  assert.equal(result.draft.review.status, "pending-editorial-review");
  assert.equal("reviewedBy" in result.draft.review, false);
  assert.equal(result.draft.sources[0].sourceRevisionId, fixture.assignment.entry.content_hash);
  assert.equal(result.draft.provenance.policyId, fixture.policy.policyId);
  assert.equal(result.draft.provenance.policyVersion, fixture.policy.version);
  assert.equal(result.draft.provenance.promptConfigHash, fixture.promptConfigHash);
  assert.equal(result.draft.provenance.pipelineVersion, pipelineVersion);
  assert.equal(result.draft.provenance.modelProvider, fixture.assignment.runtimeProfile.provider);
  assert.equal(result.draft.provenance.modelIdentifier, model);
  assert.equal(result.draft.schemaVersion, "1.1");
  assert.equal(
    result.draft.provenance.generationPlanHash,
    fixture.assignment.generationPlanHash,
  );
  assert.equal(result.draft.provenance.generationTier, "full");
  assert.equal(result.draft.provenance.maxOutputTokens, 2400);
  assert.deepEqual(result.validation, validateEditorialDraft(result.draft, fixture.policy));
  assert.equal(result.validation.valid, true);
  assert.equal(JSON.stringify(result.draft).includes("approved"), false);
  assert.equal("publicationStatus" in result.draft, false);
  assert.equal("automaticPublication" in result.draft, false);
  const request = JSON.parse(calls.find((call) => call.url.endsWith("/api/chat")).options.body);
  assert.equal(request.stream, true);
  assert.equal(request.options.num_predict, fixture.assignment.generationPlan.maxOutputTokens);
});

test("stream progress is atomic metadata and reaches finalizing without a wall-clock deadline", async (context) => {
  const fixture = runtimeFixture(context);
  const progressPath = join(fixture.directory, "progress.json");
  const calls = [];
  await generateEditorialDraftFromAssignment({
    assignment: fixture.assignment,
    runtimeRoot: fixture.runtimeRoot,
    appliedManifestPath: fixture.appliedPath,
    ollamaBaseUri: "http://127.0.0.1:11434",
    fetchImpl: fakeOllama(calls, [longCandidate()]),
    progressPath,
  });
  const progress = JSON.parse(readFileSync(progressPath, "utf8"));
  assert.equal(progress.phase, "finalizing");
  assert.equal(progress.attempt, 1);
  assert.equal(progress.sequence, 2);
  assert.ok(progress.contentBytes >= 1);
  assert.deepEqual(Object.keys(progress).sort(), [
    "attempt", "contentBytes", "phase", "sequence", "updatedAt",
  ]);
  const generationOptions = calls.find((call) => call.url.endsWith("/api/chat")).options;
  assert.equal("signal" in generationOptions, false);
});

test("a plan with a non-canonical hash is rejected before Ollama", async (context) => {
  const fixture = runtimeFixture(context);
  fixture.assignment.generationPlan.maxOutputTokens -= 1;
  let calls = 0;
  await assert.rejects(
    generateEditorialDraftFromAssignment({
      assignment: fixture.assignment,
      runtimeRoot: fixture.runtimeRoot,
      appliedManifestPath: fixture.appliedPath,
      ollamaBaseUri: "http://127.0.0.1:11434",
      fetchImpl: async () => { calls += 1; return jsonResponse({}); },
    }),
    (error) => error instanceof WorkerGeneratorError &&
      error.code === "assignment-generation-plan-hash-mismatch",
  );
  assert.equal(calls, 0);
});

test("an editorial profile incompatible with the entry kind is rejected", async (context) => {
  const fixture = runtimeFixture(context, "event");
  fixture.assignment.generationPlan.editorialProfile = "EDITORIAL_LONG_FORM";
  fixture.assignment.generationPlanHash = sha256(
    canonicalizeJson(fixture.assignment.generationPlan),
  );
  let calls = 0;
  await assert.rejects(
    generateEditorialDraftFromAssignment({
      assignment: fixture.assignment,
      runtimeRoot: fixture.runtimeRoot,
      appliedManifestPath: fixture.appliedPath,
      ollamaBaseUri: "http://127.0.0.1:11434",
      fetchImpl: async () => { calls += 1; return jsonResponse({}); },
    }),
    (error) => error instanceof WorkerGeneratorError &&
      error.code === "assignment-generation-plan-entry-profile-mismatch",
  );
  assert.equal(calls, 0);
});

for (const [tierId, expectedProfile, expectedTokens] of [
  ["compact", "EDITORIAL_COMPACT", 1536],
  ["minimum", "EDITORIAL_MINIMUM", 768],
]) {
  test(`${tierId} plan controls both editorial profile and exact token budget`, async (context) => {
    const fixture = runtimeFixture(context);
    setGenerationTier(fixture, tierId);
    const calls = [];
    const candidate = adaptiveCandidate(fixture.policy.profiles[expectedProfile]);
    const result = await generateEditorialDraftFromAssignment({
      assignment: fixture.assignment,
      runtimeRoot: fixture.runtimeRoot,
      appliedManifestPath: fixture.appliedPath,
      ollamaBaseUri: "http://127.0.0.1:11434",
      fetchImpl: fakeOllama(calls, [candidate]),
    });
    const request = JSON.parse(calls.find((call) => call.url.endsWith("/api/chat")).options.body);
    assert.equal(request.options.num_predict, expectedTokens);
    assert.equal(result.draft.editorialProfile, expectedProfile);
    assert.equal(result.validation.valid, true);
  });
}

test("validation feedback drives exactly one repair attempt", async (context) => {
  const fixture = runtimeFixture(context);
  const progressPath = join(fixture.directory, "repair-progress.json");
  const calls = [];
  const fetchImpl = fakeOllama(calls, [
    { title: "Curto demais", excerpt: "curto", paragraphs: ["curto"] },
    longCandidate(),
  ]);
  const result = await generateEditorialDraftFromAssignment({
    assignment: fixture.assignment,
    runtimeRoot: fixture.runtimeRoot,
    appliedManifestPath: fixture.appliedPath,
    ollamaBaseUri: "http://127.0.0.1:11434",
    fetchImpl,
    progressPath,
  });
  assert.equal(result.attempts, 2);
  const chatCalls = calls.filter((call) => call.url.endsWith("/api/chat"));
  assert.equal(chatCalls.length, 2);
  const repairMessage = JSON.parse(JSON.parse(chatCalls[1].options.body).messages[1].content);
  assert.equal(repairMessage.operation, "repair-editorial-content");
  assert.ok(repairMessage.validationFeedback.length > 0);
  assert.ok(repairMessage.previousCandidate);
  const progress = JSON.parse(readFileSync(progressPath, "utf8"));
  assert.equal(progress.attempt, 2);
  assert.equal(progress.phase, "finalizing");
  assert.equal(progress.sequence, 2);
  assert.ok(progress.contentBytes >= 1);
});

for (const [kind, expectedProfile, candidate] of [
  ["event", "EVENT_LISTING", summaryCandidate(280)],
  ["radar", "CATALOG_SUMMARY", summaryCandidate(300)],
]) {
  test(`${kind} uses the canonical one-paragraph profile`, async (context) => {
    const fixture = runtimeFixture(context, kind);
    const result = await generateEditorialDraftFromAssignment({
      assignment: fixture.assignment,
      runtimeRoot: fixture.runtimeRoot,
      appliedManifestPath: fixture.appliedPath,
      ollamaBaseUri: "http://127.0.0.1:11434",
      fetchImpl: fakeOllama([], [candidate]),
    });
    assert.equal(result.draft.editorialProfile, expectedProfile);
    assert.equal(result.draft.paragraphs.length, 1);
    assert.equal(result.validation.valid, true);
  });
}

test("an Ollama stream without done=true is rejected after two bounded attempts", async (context) => {
  const fixture = runtimeFixture(context);
  const calls = [];
  const fetchImpl = fakeOllama(calls, [longCandidate(), longCandidate()], { done: false });
  await assert.rejects(
    generateEditorialDraftFromAssignment({
      assignment: fixture.assignment,
      runtimeRoot: fixture.runtimeRoot,
      appliedManifestPath: fixture.appliedPath,
      ollamaBaseUri: "http://127.0.0.1:11434",
      fetchImpl,
    }),
    (error) => error instanceof WorkerGeneratorError && error.code === "ollama-stream-incomplete",
  );
  assert.equal(calls.filter((call) => call.url.endsWith("/api/chat")).length, 2);
});

for (const [label, doneReason] of [["missing done_reason", null], ["non-stop done_reason", "length"]]) {
  test(`an Ollama stream with ${label} is rejected fail-closed`, async (context) => {
    const fixture = runtimeFixture(context);
    await assert.rejects(
      generateEditorialDraftFromAssignment({
        assignment: fixture.assignment,
        runtimeRoot: fixture.runtimeRoot,
        appliedManifestPath: fixture.appliedPath,
        ollamaBaseUri: "http://127.0.0.1:11434",
        fetchImpl: fakeOllama([], [longCandidate(), longCandidate()], { doneReason }),
      }),
      (error) => error instanceof WorkerGeneratorError && error.code === "ollama-stream-incomplete",
    );
  });
}

test("a model digest change after inference blocks the draft", async (context) => {
  const fixture = runtimeFixture(context);
  let healthCalls = 0;
  const fetchImpl = async (url, options = {}) => {
    if (String(url).endsWith("/api/tags")) {
      healthCalls += 1;
      return jsonResponse({ models: [{ name: model, digest: healthCalls === 1 ? modelDigest : "b".repeat(64) }] });
    }
    return ollamaResponse(longCandidate());
  };
  await assert.rejects(
    generateEditorialDraftFromAssignment({
      assignment: fixture.assignment,
      runtimeRoot: fixture.runtimeRoot,
      appliedManifestPath: fixture.appliedPath,
      ollamaBaseUri: "http://127.0.0.1:11434",
      fetchImpl,
    }),
    (error) => error instanceof WorkerGeneratorError && error.code === "ollama-model-digest-mismatch",
  );
  assert.equal(healthCalls, 2);
});

test("tampered prompt, profile and non-loopback engine fail before inference", async (context) => {
  const fixture = runtimeFixture(context);
  writeFileSync(join(fixture.runtimeRoot, "editorial", "prompt.md"), "tampered", "utf8");
  assert.throws(
    () => loadInstalledEditorialRuntime({
      runtimeRoot: fixture.runtimeRoot,
      appliedManifestPath: fixture.appliedPath,
      ollamaBaseUri: "http://127.0.0.1:11434",
      pipelineVersion,
    }),
    (error) => error instanceof WorkerGeneratorError && error.code === "runtime-applied-prompt-hash-mismatch",
  );

  const clean = runtimeFixture(context);
  assert.throws(
    () => loadInstalledEditorialRuntime({
      runtimeRoot: clean.runtimeRoot,
      appliedManifestPath: clean.appliedPath,
      ollamaBaseUri: "http://192.168.1.20:11434",
      pipelineVersion,
    }),
    (error) => error instanceof WorkerGeneratorError && error.code === "ollama-base-uri-not-loopback",
  );

  clean.assignment.runtimeProfile.model = "mutable:latest";
  clean.assignment.runtimeProfile.runtimeProfileHash = runtimeProfileHash(clean.assignment.runtimeProfile);
  let fetchCalls = 0;
  await assert.rejects(
    generateEditorialDraftFromAssignment({
      assignment: clean.assignment,
      runtimeRoot: clean.runtimeRoot,
      appliedManifestPath: clean.appliedPath,
      ollamaBaseUri: "http://127.0.0.1:11434",
      fetchImpl: async () => { fetchCalls += 1; return jsonResponse({ models: [] }); },
    }),
    (error) => error instanceof WorkerGeneratorError && error.code === "assignment-runtime-mismatch:model",
  );
  assert.equal(fetchCalls, 0);
});

test("installed prompt configuration is invariant across LF and CRLF", (context) => {
  const fixture = runtimeFixture(context);
  const promptPath = join(fixture.runtimeRoot, "editorial", "prompt.md");
  const canonicalPrompt = canonicalLfText(readFileSync(promptPath, "utf8"));
  writeFileSync(promptPath, canonicalPrompt.replaceAll("\n", "\r\n"), "utf8");

  const runtime = loadInstalledEditorialRuntime({
    runtimeRoot: fixture.runtimeRoot,
    appliedManifestPath: fixture.appliedPath,
    ollamaBaseUri: "http://127.0.0.1:11434",
    pipelineVersion,
  });

  assert.equal(runtime.prompt, canonicalPrompt);
  assert.equal(runtime.prompt.includes("\r"), false);
  assert.equal(runtime.promptConfigHash, fixture.promptConfigHash);
});

test("cycle, persistent Windows Service and CLI are opt-in and fail closed by static contract", () => {
  const moduleSource = readFileSync(join(kitRoot, "Hch.EditorialWorker.psm1"), "utf8");
  const cycleSource = readFileSync(join(kitRoot, "Run-WorkerCycle.ps1"), "utf8");
  const serviceSource = readFileSync(join(kitRoot, "service", "HchEditorialWorkerService.cs"), "utf8");
  const serviceInstallerSource = readFileSync(join(kitRoot, "Install-HchWorkerService.ps1"), "utf8");
  const cliSource = readFileSync(join(kitRoot, "Hch-Worker.ps1"), "utf8");
  const dashboardLauncherSource = readFileSync(join(kitRoot, "Start-WorkerDashboard.ps1"), "utf8");
  const dashboardTaskSource = readFileSync(join(kitRoot, "Install-WorkerDashboardTask.ps1"), "utf8");
  const dashboardControlSource = readFileSync(
    join(repositoryRoot, "ops", "worker-dashboard", "lib", "control.mjs"),
    "utf8",
  );
  assert.match(moduleSource, /requestedCapacity\s*=\s*\$RequestedCapacity/);
  assert.match(moduleSource, /\$response\.capacity/);
  assert.match(moduleSource, /Get-HchWorkerCapacityPressure/);
  assert.match(moduleSource, /capacityPolicyHash/);
  assert.match(moduleSource, /adaptiveWorkPolicyHash/);
  assert.match(moduleSource, /generationPlanHash/);
  assert.match(moduleSource, /Assert-HchAssignmentProgress/);
  assert.match(moduleSource, /Assert-HchGeneratorStalledResponse/);
  assert.match(moduleSource, /bootstrap\.lock/);
  assert.match(moduleSource, /FileShare\]::None/);
  assert.match(moduleSource, /orchestrator-generator-stalled-plan-mismatch/);
  assert.match(moduleSource, /orchestrator-claim-capacity-contract-required/);
  assert.match(moduleSource, /commitAccepted/);
  assert.match(moduleSource, /automaticApproval/);
  assert.match(moduleSource, /automaticPublication/);
  assert.match(cycleSource, /FileShare\]::None/);
  assert.match(cycleSource, /commit-unknown/);
  assert.match(cycleSource, /Invoke-HchItemHeartbeat[\s\S]+Invoke-HchWorkerComplete/);
  assert.match(cycleSource, /leaseExpiresAt\s*=\s*\[string\]\$heartbeat\.leaseExpiresAt/);
  assert.match(cycleSource, /Stop-HchGeneratorProcesses/);
  assert.match(cycleSource, /Stop-HchGeneratorWhenStalled/);
  assert.match(cycleSource, /--progress/);
  assert.match(cycleSource, /firstProgressGraceSeconds/);
  assert.match(cycleSource, /stallAfterSeconds/);
  assert.match(cycleSource, /finalizationGraceSeconds/);
  assert.match(cycleSource, /validated\.attempt -eq \[int\]\$Item\.LastProgressAttempt/);
  assert.match(cycleSource, /minimum-unit job may run indefinitely while/);
  assert.match(
    cycleSource,
    /Test-HchGeneratorStalledError[\s\S]+Invoke-HchWorkerFail[\s\S]+-ErrorCode 'generator-stalled'/,
  );
  assert.doesNotMatch(cycleSource, /processingWindowSeconds/);
  assert.doesNotMatch(cycleSource, /processingWindowSeconds[\s\S]{0,120}(?:Kill|Stop-Process)/);
  assert.match(cycleSource, /capacityPolicy\.absoluteRequestedMaximum/);
  assert.match(cycleSource, /claim\.capacity\.availableSlots/);
  const readinessRenewal = cycleSource.indexOf("Invoke-HchWorkerBootstrap -Config $config");
  const drainBoundary = cycleSource.indexOf("drain-no-new-claims");
  assert.ok(readinessRenewal >= 0 && readinessRenewal < drainBoundary);
  const finalClaimBoundary = cycleSource.slice(
    cycleSource.indexOf("[void](Invoke-HchGeneratorPreflight)"),
    cycleSource.indexOf("$claim = Invoke-HchWorkerClaim"),
  );
  assert.match(finalClaimBoundary, /Get-HchWorkerControl/);
  assert.match(finalClaimBoundary, /drain-before-claim/);
  assert.doesNotMatch(cycleSource, /maximumParallelAssignments/);
  assert.doesNotMatch(cycleSource, /\/approve|\/publish/i);
  assert.equal(existsSync(join(kitRoot, "Install-WorkerCycleTask.ps1")), false);
  assert.match(serviceSource, /:\s*ServiceBase/);
  assert.match(serviceSource, /CreateNoWindow\s*=\s*true/);
  assert.match(serviceSource, /UseShellExecute\s*=\s*false/);
  assert.match(serviceInstallerSource, /start=', 'delayed-auto'/);
  assert.match(serviceInstallerSource, /Unregister-ScheduledTask/);
  assert.match(serviceInstallerSource, /Export-ScheduledTask/);
  assert.doesNotMatch(serviceInstallerSource, /New-ScheduledTask(?:Action|Trigger|Principal|SettingsSet)|Enable-ScheduledTask/);
  for (const command of ["configure", "validate", "start", "pause", "stop", "status", "set-parallelism"]) {
    assert.match(cliSource, new RegExp(command));
  }
  const validateBlock = cliSource.slice(
    cliSource.indexOf("function Invoke-HchLocalValidate"),
    cliSource.indexOf("function Get-HchCliStatus"),
  );
  assert.doesNotMatch(validateBlock, /Invoke-HchWorkerClaim|\/claim/);
  assert.match(cliSource, /\$Parallelism -eq 0/);
  assert.match(cliSource, /ControlPlaneTimeoutSeconds/);
  assert.match(cliSource, /Invoke-HchWorkerNodeHeartbeat -Config \$config -RequestedCapacity 0/);
  assert.doesNotMatch(cycleSource, /Invoke-HchWorkerClaim[\s\S]{0,160}RequestedCapacity 0/);
  assert.match(moduleSource, /ValidateRange\(1, 64\)\]\[int\]\$RequestedCapacity/);
  assert.match(moduleSource, /Purpose 'claim'/);
  assert.match(cycleSource, /drain-active-assignments/);
  const terminalCatch = cycleSource.slice(cycleSource.lastIndexOf("} catch {"));
  assert.match(
    terminalCatch,
    /\$failureCode -eq 'worker-bootstrap-already-running'[\s\S]+Write-HchCycleSummary -State 'deferred'/,
  );
  const bootstrapContention = terminalCatch.slice(
    terminalCatch.indexOf("$failureCode -eq 'worker-bootstrap-already-running'"),
    terminalCatch.indexOf("if ($failureCode -notmatch"),
  );
  assert.doesNotMatch(bootstrapContention, /Set-HchWorkerStatus|ConnectionState 'error'/);

  const startBlock = cliSource.slice(
    cliSource.indexOf("  'start' {"),
    cliSource.indexOf("  'pause' {"),
  );
  assert.match(startBlock, /worker-processing-service-not-running/);
  assert.doesNotMatch(startBlock, /Start-Service|Start-ScheduledTask/);
  assert.match(startBlock, /start-requested-awaiting-server-capacity/);

  const stopBlock = cliSource.slice(
    cliSource.indexOf("  'stop' {"),
    cliSource.indexOf("  'set-parallelism' {"),
  );
  const localDrainIndex = stopBlock.indexOf("Set-HchWorkerControl");
  const notifyServerIndex = stopBlock.indexOf("Invoke-HchServerDrainNotification");
  assert.ok(localDrainIndex >= 0 && notifyServerIndex > localDrainIndex);
  assert.match(stopBlock, /operator-stop-requested/);
  assert.match(cycleSource, /Stop-HchItemsByOperatorRequest/);
  assert.match(cycleSource, /Invoke-HchWorkerFail[\s\S]{0,240}operator-stop-requested/);

  for (const argument of ["--worker-cli", "--worker-config", "--powershell", "--control-plane-timeout-seconds"]) {
    assert.match(dashboardLauncherSource, new RegExp(argument));
  }
  assert.match(dashboardLauncherSource, /'--host' '127\.0\.0\.1'/);
  assert.match(serviceSource, /RunDashboardSupervisor/);
  assert.match(serviceSource, /"--host", "127\.0\.0\.1"/);
  assert.match(dashboardControlSource, /shell:\s*false/);
  assert.match(dashboardControlSource, /new Set\(\["start", "pause", "stop", "set-parallelism", "update"\]\)/);
  assert.doesNotMatch(dashboardControlSource, /shell:\s*true|"-Command"|'\-Command'/);
});

test("PowerShell control state supports drain zero and a configurable local N", (context) => {
  if (process.platform !== "win32") return context.skip("Windows PowerShell integration test");
  const directory = mkdtempSync(join(tmpdir(), "hch-worker-control-"));
  context.after(() => rmSync(directory, { recursive: true, force: true }));
  const escaped = (value) => value.replaceAll("'", "''");
  const modulePath = join(kitRoot, "Hch.EditorialWorker.psm1");
  const script = `
    Import-Module '${escaped(modulePath)}' -Force
    $config=@{NodeId='windows-worker-01';StateRoot='${escaped(directory)}';InstallRoot='${escaped(join(directory,"runtime"))}';LocalParallelismLimit=8}
    $initial=Get-HchWorkerControl -Config $config
    $five=Set-HchWorkerControl -Config $config -Parallelism 5 -AcceptingClaims $false
    $zero=Set-HchWorkerControl -Config $config -Parallelism 0 -AcceptingClaims $false
    $reloaded=Get-HchWorkerControl -Config $config
    [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes((@{initial=$initial;five=$five;zero=$zero;reloaded=$reloaded}|ConvertTo-Json -Depth 20 -Compress)))
  `;
  const output = BunlessExecPowerShell(script);
  const result = JSON.parse(Buffer.from(output, "base64").toString("utf8"));
  assert.equal(result.initial.requestedParallelism, 1);
  assert.equal(result.initial.acceptingClaims, false);
  assert.equal(result.five.requestedParallelism, 5);
  assert.equal(result.zero.requestedParallelism, 0);
  assert.equal(result.zero.lastNonZeroParallelism, 5);
  assert.equal(result.reloaded.drainRequested, true);
});

test("PowerShell validates the signed adaptive capacity decision, pressure and drain", (context) => {
  if (process.platform !== "win32") return context.skip("Windows PowerShell integration test");
  const directory = mkdtempSync(join(tmpdir(), "hch-worker-capacity-"));
  context.after(() => rmSync(directory, { recursive: true, force: true }));
  const escaped = (value) => value.replaceAll("'", "''");
  const policyJson = JSON.stringify(adaptiveCapacityPolicy()).replaceAll("'", "''");
  const script = `
    $m=Import-Module '${escaped(join(kitRoot, "Hch.EditorialWorker.psm1"))}' -Force -PassThru
    $config=@{NodeId='windows-worker-01';StateRoot='${escaped(directory)}';InstallRoot='${escaped(join(directory,"runtime"))}';NodePath='${escaped(process.execPath)}';MinimumNodeMajor=22;ClockSkewSeconds=60}
    $policy=ConvertFrom-Json '${policyJson}'
    $pressure=[pscustomobject][ordered]@{cpuPercent=25.5;memoryPercent=42.75}
    $serverTime=[DateTimeOffset]::UtcNow.ToString('o')
    $grantedUntil=[DateTimeOffset]::Parse($serverTime).AddSeconds(120).ToString('o')
    $capacity=[pscustomobject][ordered]@{algorithmVersion='hch-adaptive-capacity-v1';requestedCapacity=5;grantedCapacity=4;availableSlots=3;activeAssignments=1;globalActiveAssignments=3;globalAvailableBeforeGrant=20;capacityClass='standard';nodeCeiling=16;reason='pressure-soft-reduction';grantedUntil=$grantedUntil;pressure=$pressure}
    $valid=& $m {param($c,$d,$p,$x,$t) Assert-HchClaimCapacityDecision -Config $c -Capacity $d -RequestedCapacity 5 -Policy $p -ExpectedPressure $x -NewAssignmentCount 3 -ServerTime $t} $config $capacity $policy $pressure $serverTime
    $drain=[pscustomobject][ordered]@{algorithmVersion='hch-adaptive-capacity-v1';requestedCapacity=0;grantedCapacity=0;availableSlots=0;activeAssignments=2;globalActiveAssignments=4;globalAvailableBeforeGrant=20;capacityClass='standard';nodeCeiling=16;reason='drain-requested';grantedUntil=$grantedUntil;pressure=$pressure}
    $drained=& $m {param($c,$d,$p,$x,$t) Assert-HchClaimCapacityDecision -Config $c -Capacity $d -RequestedCapacity 0 -Policy $p -ExpectedPressure $x -NewAssignmentCount 0 -ServerTime $t} $config $drain $policy $pressure $serverTime
    $mismatch=$null
    try {& $m {param($c,$d,$p,$t) Assert-HchClaimCapacityDecision -Config $c -Capacity $d -RequestedCapacity 5 -Policy $p -ExpectedPressure ([pscustomobject]@{cpuPercent=99}) -NewAssignmentCount 3 -ServerTime $t} $config $capacity $policy $serverTime|Out-Null} catch {$mismatch=$_.Exception.Message}
    [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes((@{valid=$valid;drained=$drained;mismatch=$mismatch}|ConvertTo-Json -Depth 20 -Compress)))
  `;
  const output = BunlessExecPowerShell(script);
  const result = JSON.parse(Buffer.from(output, "base64").toString("utf8"));
  assert.equal(result.valid.requestedCapacity, 5);
  assert.equal(result.valid.grantedCapacity, 4);
  assert.equal(result.valid.activeAssignments, 4);
  assert.equal(result.drained.requestedCapacity, 0);
  assert.equal(result.drained.grantedCapacity, 0);
  assert.equal(result.drained.activeAssignments, 2);
  assert.equal(result.mismatch, "orchestrator-claim-capacity-pressure-mismatch");
});

function runtimeFixture(context, kind = "article") {
  const directory = mkdtempSync(join(tmpdir(), "hch-worker-generator-"));
  context.after(() => rmSync(directory, { recursive: true, force: true }));
  const runtimeRoot = join(directory, "runtime");
  mkdirSync(join(runtimeRoot, "editorial"), { recursive: true });
  mkdirSync(join(runtimeRoot, "config"), { recursive: true });
  cpSync(policySource, join(runtimeRoot, "editorial", "policy.json"));
  cpSync(promptSource, join(runtimeRoot, "editorial", "prompt.md"));
  const policy = JSON.parse(readFileSync(policySource, "utf8"));
  const prompt = canonicalLfText(readFileSync(promptSource, "utf8"));
  const promptConfigHash = sha256(`${prompt}\n${policy.hash}\n${pipelineVersion}`);
  const engine = {
    schemaVersion: 2,
    engine: {
      provider: "vps-local",
      adapter: "ollama",
      adapterVersion: "1.0.0",
      model,
      modelDigest,
      protocol: "ollama-chat",
      healthPath: "/api/tags",
      generationPath: "/api/chat",
    },
    generation: {
      temperature: 0.2,
      contextWindow: 4096,
      maxOutputTokens: 2400,
    },
    capacityPolicy: adaptiveCapacityPolicy(),
    adaptiveWorkPolicy: policy.adaptiveWorkPolicy,
    adaptiveWorkPolicyHash: sha256(canonicalizeJson(policy.adaptiveWorkPolicy)),
    manifestSequence: 7,
    manifestHash,
  };
  writeFileSync(join(runtimeRoot, "config", "engine.json"), JSON.stringify(engine));
  const applied = {
    schemaVersion: 2,
    sequence: 7,
    manifestHash,
    policyHash: policy.hash,
    promptConfigHash,
    pipelineVersion,
    provider: engine.engine.provider,
    engineAdapter: engine.engine.adapter,
    engineAdapterVersion: engine.engine.adapterVersion,
    model,
    modelDigest,
    adaptiveWorkPolicyHash: engine.adaptiveWorkPolicyHash,
  };
  const appliedPath = join(directory, "applied-manifest.json");
  writeFileSync(appliedPath, JSON.stringify(applied));
  const entry = {
    id: "source-1",
    source_id: "source-1",
    external_key: "fixture-1",
    kind,
    title: "Arquitetura distribuída para comunidades técnicas",
    summary: "O registro ingerido descreve uma arquitetura verificável, seus limites operacionais e a necessidade de revisão humana.",
    author: "Equipe da fonte",
    publisher: "Fonte técnica",
    source_url: "https://example.com/source-1",
    source_locale: "pt-BR",
    published_at: "2026-08-11T20:00:00.000Z",
    event_starts_at: null,
    event_ends_at: null,
    location: null,
    topics: ["arquitetura"],
    reproduction_mode: "reference-only",
    moderation_status: "review",
    content_hash: "c".repeat(64),
    first_seen_at: "2026-08-11T20:01:00.000Z",
    last_seen_at: "2026-08-11T20:02:00.000Z",
  };
  const profile = {
    provider: engine.engine.provider,
    engineAdapter: engine.engine.adapter,
    engineAdapterVersion: engine.engine.adapterVersion,
    model,
    modelDigest,
    protocol: engine.engine.protocol,
    temperature: engine.generation.temperature,
    contextWindow: engine.generation.contextWindow,
    maxOutputTokens: engine.generation.maxOutputTokens,
    policyId: policy.policyId,
    policyVersion: policy.version,
    policyHash: policy.hash,
    promptConfigHash,
    pipelineVersion,
    manifestSequence: engine.manifestSequence,
    manifestHash,
  };
  profile.runtimeProfileHash = sha256(canonicalizeJson(profile));
  const tier = policy.adaptiveWorkPolicy.tiers.find((candidate) => candidate.id === "full");
  const adaptivePolicyHash = sha256(canonicalizeJson(policy.adaptiveWorkPolicy));
  const generationPlan = {
    algorithmVersion: policy.adaptiveWorkPolicy.algorithmVersion,
    tierId: tier.id,
    tierRank: tier.rank,
    maxOutputTokens: tier.maxOutputTokens,
    editorialProfile: kind === "event"
      ? "EVENT_LISTING"
      : kind === "radar" ? "CATALOG_SUMMARY" : tier.editorialProfile,
    minimumUnit: tier.minimumUnit,
    processingWindowSeconds: policy.adaptiveWorkPolicy.processingWindowSeconds,
    nearWindowSeconds: Math.floor(
      policy.adaptiveWorkPolicy.processingWindowSeconds * policy.adaptiveWorkPolicy.nearWindowRatio,
    ),
    firstProgressGraceSeconds: policy.adaptiveWorkPolicy.firstProgressGraceSeconds,
    stallAfterSeconds: policy.adaptiveWorkPolicy.stallAfterSeconds,
    finalizationGraceSeconds: policy.adaptiveWorkPolicy.finalizationGraceSeconds,
    policyHash: adaptivePolicyHash,
  };
  const assignment = {
    assignmentId: "00000000-0000-4000-8000-000000000007",
    leaseToken: "00000000-0000-4000-8000-000000000008",
    leaseExpiresAt: new Date(Date.now() + 10 * 60_000).toISOString(),
    status: "processing",
    inputSnapshotHash: sha256(canonicalizeJson(entry)),
    entry,
    runtimeProfile: profile,
    generationPlan,
    generationPlanHash: sha256(canonicalizeJson(generationPlan)),
  };
  return { directory, runtimeRoot, appliedPath, policy, promptConfigHash, assignment };
}

function runtimeProfileHash(profile) {
  const { runtimeProfileHash: _current, ...core } = profile;
  return sha256(canonicalizeJson(core));
}

function longCandidate() {
  const seed = [
    "A análise técnica apresenta contexto verificável e explica como decisões de arquitetura afetam segurança desempenho operação governança qualidade rastreabilidade manutenção integração observabilidade capacidade disponibilidade revisão humana fontes limites riscos controles equipes serviços dados modelos políticas mudanças testes incidentes aprendizado contínuo.",
    "O desenho também separa fatos registrados de interpretações editoriais para preservar clareza responsabilidade coerência precisão utilidade pública transparência autoria originalidade acesso sustentável colaboração comunitária documentação evolução tecnológica compatibilidade validação implantação monitoramento recuperação auditoria futura.",
  ].join(" ");
  let paragraph = seed;
  while (wordCount(paragraph) < 100) paragraph += ` ${seed}`;
  paragraph = paragraph.split(/\s+/).slice(0, 100).join(" ") + ".";
  return {
    title: "Arquitetura distribuída com rastreabilidade editorial",
    excerpt: "Uma leitura técnica sobre coordenação, segurança e revisão humana em ambientes editoriais distribuídos.",
    paragraphs: Array.from({ length: 5 }, (_, index) => `${paragraph} A seção ${index + 1} mantém foco próprio e conexão com a evidência fornecida.`),
  };
}

function summaryCandidate(targetLength) {
  const phrase = "O registro apresenta contexto técnico verificável, limites operacionais claros e revisão humana obrigatória para preservar qualidade, segurança e rastreabilidade editorial. ";
  let text = "";
  while (text.length < targetLength) text += phrase;
  text = text.slice(0, targetLength).replace(/\s+\S*$/, "").trim() + ".";
  return {
    title: "Síntese técnica do registro canônico",
    excerpt: text,
    paragraphs: [text],
  };
}

function adaptiveCandidate(profile) {
  const paragraphCount = Number(profile.minimumParagraphs);
  const words = Number(profile.minimumWordsPerParagraph);
  const seed = "arquitetura técnica verificável segurança desempenho operação governança qualidade rastreabilidade manutenção integração observabilidade capacidade disponibilidade revisão humana fontes limites riscos controles equipes serviços dados modelos políticas mudanças testes incidentes aprendizagem contínua";
  let paragraph = seed;
  while (wordCount(paragraph) < words) paragraph += ` ${seed}`;
  paragraph = paragraph.split(/\s+/).slice(0, words).join(" ") + ".";
  const minimumTotalWords = Number(profile.minimumBodyWords ?? words * paragraphCount);
  const minimumWordsPerParagraph = Math.ceil(minimumTotalWords / paragraphCount);
  while (wordCount(paragraph) < minimumWordsPerParagraph) paragraph += ` ${seed}`;
  paragraph = paragraph.split(/\s+/).slice(0, minimumWordsPerParagraph).join(" ") + ".";
  return {
    title: "Síntese técnica adaptada ao plano assinado",
    excerpt: "Resumo autoral e verificável conforme o orçamento editorial assinado.",
    paragraphs: Array.from({ length: paragraphCount }, () => paragraph),
  };
}

function setGenerationTier(fixture, tierId) {
  const tier = fixture.policy.adaptiveWorkPolicy.tiers.find((candidate) => candidate.id === tierId);
  Object.assign(fixture.assignment.generationPlan, {
    tierId: tier.id,
    tierRank: tier.rank,
    maxOutputTokens: tier.maxOutputTokens,
    editorialProfile: tier.editorialProfile,
    minimumUnit: tier.minimumUnit,
  });
  fixture.assignment.generationPlanHash = sha256(
    canonicalizeJson(fixture.assignment.generationPlan),
  );
}

function fakeOllama(calls, candidates, options = {}) {
  let generationIndex = 0;
  return async (url, requestOptions = {}) => {
    calls.push({ url: String(url), options: requestOptions });
    if (String(url).endsWith("/api/tags")) {
      return jsonResponse({ models: [{ name: model, digest: modelDigest }] });
    }
    const candidate = candidates[Math.min(generationIndex, candidates.length - 1)];
    generationIndex += 1;
    const doneReason = Object.hasOwn(options, "doneReason") ? options.doneReason : "stop";
    return ollamaResponse(candidate, options.done !== false, doneReason);
  };
}

function ollamaResponse(candidate, done = true, doneReason = "stop") {
  const content = JSON.stringify(candidate);
  const middle = Math.floor(content.length / 2);
  const lines = [
    JSON.stringify({ message: { content: content.slice(0, middle) }, done: false }),
    JSON.stringify({
      message: { content: content.slice(middle) },
      done,
      ...(done && doneReason !== null ? { done_reason: doneReason } : {}),
    }),
  ];
  return new Response(`${lines.join("\n")}\n`, {
    status: 200,
    headers: { "content-type": "application/x-ndjson" },
  });
}

function jsonResponse(value) {
  return new Response(JSON.stringify(value), {
    status: 200,
    headers: { "content-type": "application/json" },
  });
}

function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}

function wordCount(value) {
  return String(value).match(/[\p{L}\p{N}][\p{L}\p{N}'’_-]*/gu)?.length ?? 0;
}

function BunlessExecPowerShell(script) {
  return execFileSync(
    "powershell.exe",
    ["-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script],
    { encoding: "utf8" },
  ).trim();
}

function adaptiveCapacityPolicy() {
  return {
    algorithmVersion: "hch-adaptive-capacity-v1",
    absoluteRequestedMaximum: 64,
    defaultNodeCeiling: 16,
    globalAssignmentCeiling: 32,
    grantTtlSeconds: 120,
    telemetryMayOnlyReduce: true,
    classCeilings: { constrained: 4, standard: 16, accelerated: 32 },
    platformClasses: { linux: "standard", macos: "standard", windows: "standard" },
    nodeClasses: { "vps-primary": "standard" },
    nodeCeilings: { "vps-primary": 16 },
    pressure: { softLimitPercent: 80, hardLimitPercent: 92, softReductionFactor: 0.5 },
  };
}
