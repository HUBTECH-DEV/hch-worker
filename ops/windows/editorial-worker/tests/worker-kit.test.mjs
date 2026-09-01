import assert from "node:assert/strict";
import { createHash, generateKeyPairSync } from "node:crypto";
import { execFileSync, spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import {
  canonicalizeJson,
  createContentDigest,
  manifestContentContractHash,
  signManifestEnvelope,
  signReleaseKeyDelegation,
  signWorkerRequest,
  workerPublicKeyFingerprint,
} from "../../../../lib/editorial-worker-signatures.mjs";

const testDirectory = dirname(fileURLToPath(import.meta.url));
const kitRoot = resolve(testDirectory, "..");
const repositoryRoot = resolve(kitRoot, "../../..");
const helper = join(kitRoot, "crypto", "hch-ed25519.mjs");
const modulePath = join(kitRoot, "Hch.EditorialWorker.psm1");

test("all JSON schemas are valid JSON", () => {
  const schemaDirectory = join(kitRoot, "schemas");
  for (const name of readdirSync(schemaDirectory).filter((entry) => entry.endsWith(".json"))) {
    const schema = JSON.parse(readFileSync(join(schemaDirectory, name), "utf8"));
    assert.equal(schema.$schema, "https://json-schema.org/draft/2020-12/schema");
  }
});

test("assignment and manifest schemas require immutable engine identity", () => {
  const assignment = JSON.parse(
    readFileSync(join(kitRoot, "schemas", "worker-assignment-v1.schema.json"), "utf8"),
  );
  const manifest = JSON.parse(
    readFileSync(join(kitRoot, "schemas", "manifest-payload-v2.schema.json"), "utf8"),
  );
  const attestation = JSON.parse(
    readFileSync(join(kitRoot, "schemas", "worker-bootstrap-attestation-v2.schema.json"), "utf8"),
  );
  for (const field of ["provider", "engineAdapter", "engineAdapterVersion"]) {
    assert.ok(assignment.properties.runtimeProfile.required.includes(field));
    assert.ok(assignment.properties.runtimeProfile.properties[field]);
  }
  for (const field of ["provider", "adapter", "adapterVersion"]) {
    assert.ok(manifest.properties.engine.required.includes(field));
    assert.ok(manifest.properties.engine.properties[field]);
  }
  assert.ok(manifest.required.includes("capacityPolicy"));
  assert.equal(
    manifest.properties.capacityPolicy.properties.algorithmVersion.const,
    "hch-adaptive-capacity-v1",
  );
  assert.equal(
    manifest.properties.adaptiveWorkPolicy.properties.algorithmVersion.const,
    "hch-adaptive-work-v1",
  );
  assert.ok(manifest.properties.compatibility.properties.contentContractHash);
  for (const field of ["generationPlan", "generationPlanHash"]) {
    assert.ok(assignment.required.includes(field));
    assert.ok(assignment.properties[field]);
  }
  assert.equal(assignment.properties.runtimeProfile.additionalProperties, false);
  for (const field of ["provider", "engineAdapter", "engineAdapterVersion"]) {
    assert.ok(attestation.required.includes(field));
    assert.ok(attestation.properties[field]);
  }
  assert.ok(attestation.required.includes("adaptiveWorkPolicyHash"));
  assert.ok(attestation.required.includes("contentContractHash"));
  assert.equal(attestation.required.includes("engineVersion"), false);
  assert.equal(attestation.properties.engineVersion, undefined);
});

test("helper generates a unique Ed25519 identity and signs raw bytes", () => {
  const directory = mkdtempSync(join(tmpdir(), "hch-worker-identity-"));
  const privatePath = join(directory, "private.pem");
  const publicPath = join(directory, "public.pem");
  const inputPath = join(directory, "input.bin");
  writeFileSync(inputPath, Buffer.from("HCH worker proof\n", "utf8"));

  const generated = runHelper("generate", "--private", privatePath, "--public", publicPath);
  assert.equal(generated.algorithm, "Ed25519");
  assert.match(generated.keyId, /^SHA256:[A-Za-z0-9_-]{43}$/);
  assert.match(readFileSync(privatePath, "utf8"), /BEGIN PRIVATE KEY/);
  assert.match(readFileSync(publicPath, "utf8"), /BEGIN PUBLIC KEY/);

  const signature = runHelper("sign", "--private", privatePath, "--input", inputPath);
  const verified = runHelper(
    "verify", "--public", publicPath, "--input", inputPath, "--signature", signature.value,
  );
  assert.equal(verified.valid, true);
  assert.equal(Buffer.from(signature.value, "base64").length, 64);
});

test("helper verifies the canonical root to release to manifest chain", async () => {
  const directory = mkdtempSync(join(tmpdir(), "hch-worker-chain-"));
  const root = generateKeyPairSync("ed25519");
  const release = generateKeyPairSync("ed25519");
  const rootPrivate = root.privateKey.export({ type: "pkcs8", format: "pem" });
  const rootPublic = root.publicKey.export({ type: "spki", format: "pem" });
  const releasePrivate = release.privateKey.export({ type: "pkcs8", format: "pem" });
  const releasePublic = release.publicKey.export({ type: "spki", format: "pem" });
  const rootPath = join(directory, "root.pem");
  const envelopePath = join(directory, "envelope.json");
  const outputPath = join(directory, "manifest.json");
  writeFileSync(rootPath, rootPublic);

  const now = Math.floor(Date.now() / 1000);
  const rootKeyId = "hch-root-test";
  const releaseKeyId = "hch-release-test";
  const delegation = await signReleaseKeyDelegation(releasePublic, rootPrivate, {
    rootKeyId,
    releaseKeyId,
    created: now - 1,
    notBefore: now - 1,
    expires: now + 3600,
    sequence: 7,
  });
  const unsignedPayload = {
    schemaVersion: "2.0",
    sequence: 1,
    releaseId: "test.1",
    issuedAt: new Date((now - 1) * 1000).toISOString(),
    expiresAt: new Date((now + 1800) * 1000).toISOString(),
    previousManifestHash: null,
    minimumAcceptedSequence: 1,
    runtime: { workerVersion: "2.0.0" },
    engine: { model: "qwen2.5:1.5b-instruct" },
    editorial: { policyHash: "a".repeat(64) },
    actions: [],
    artifacts: [],
    endpoints: {},
  };
  const hash = createHash("sha256").update(canonicalizeJson(unsignedPayload)).digest("hex");
  const payload = { ...unsignedPayload, hashAlgorithm: "sha256", hash };
  const manifest = await signManifestEnvelope(payload, releasePrivate, {
    keyId: releaseKeyId,
    created: now,
    expires: now + 1200,
  });
  writeFileSync(envelopePath, JSON.stringify({
    manifest,
    delegation,
    rootKeyId,
    rootPublicKeyFingerprint: await workerPublicKeyFingerprint(rootPublic),
  }));

  const result = runHelper(
    "verify-chain", "--root", rootPath, "--envelope", envelopePath,
    "--output", outputPath, "--clock-skew", "60",
  );
  assert.equal(result.valid, true);
  assert.equal(result.delegationSequence, 7);
  assert.equal(
    result.delegationHash,
    createHash("sha256").update(canonicalizeJson(delegation)).digest("hex"),
  );
  assert.equal(result.manifestHash, hash);
  assert.equal(result.contentContractHash, await manifestContentContractHash(payload));
  assert.deepEqual(JSON.parse(readFileSync(outputPath, "utf8")), payload);
});

test("helper refuses an unapplied manifest when only the delegation is expired", async () => {
  const directory = mkdtempSync(join(tmpdir(), "hch-worker-expired-chain-"));
  const root = generateKeyPairSync("ed25519");
  const release = generateKeyPairSync("ed25519");
  const rootPrivate = root.privateKey.export({ type: "pkcs8", format: "pem" });
  const rootPublic = root.publicKey.export({ type: "spki", format: "pem" });
  const releasePrivate = release.privateKey.export({ type: "pkcs8", format: "pem" });
  const releasePublic = release.publicKey.export({ type: "spki", format: "pem" });
  const rootPath = join(directory, "root.pem");
  const envelopePath = join(directory, "envelope.json");
  writeFileSync(rootPath, rootPublic);
  const now = Math.floor(Date.now() / 1000);
  const rootKeyId = "hch-root-expired-test";
  const releaseKeyId = "hch-release-expired-test";
  const delegation = await signReleaseKeyDelegation(releasePublic, rootPrivate, {
    rootKeyId,
    releaseKeyId,
    created: now - 600,
    notBefore: now - 600,
    expires: now - 300,
    sequence: 8,
  });
  const unsignedPayload = {
    schemaVersion: "2.0",
    sequence: 8,
    releaseId: "test.expired.8",
    issuedAt: new Date((now - 500) * 1000).toISOString(),
    expiresAt: new Date((now + 1800) * 1000).toISOString(),
    previousManifestHash: "a".repeat(64),
    minimumAcceptedSequence: 1,
    runtime: { workerVersion: "2.0.0" },
    engine: { model: "qwen2.5:1.5b-instruct" },
    editorial: { policyHash: "b".repeat(64) },
    actions: [],
    artifacts: [],
    endpoints: {},
  };
  const hash = createHash("sha256").update(canonicalizeJson(unsignedPayload)).digest("hex");
  const payload = { ...unsignedPayload, hashAlgorithm: "sha256", hash };
  const manifest = await signManifestEnvelope(payload, releasePrivate, {
    keyId: releaseKeyId,
    created: now - 500,
    expires: now - 350,
  });
  writeFileSync(envelopePath, JSON.stringify({
    manifest,
    delegation,
    rootKeyId,
    rootPublicKeyFingerprint: await workerPublicKeyFingerprint(rootPublic),
  }));

  assert.throws(
    () => runHelper(
      "verify-chain", "--root", rootPath, "--envelope", envelopePath,
      "--output", join(directory, "rejected.json"), "--clock-skew", "60",
      "--allow-expired-hash", "f".repeat(64),
    ),
    /manifest-expired-update-refused/,
  );
  const accepted = runHelper(
    "verify-chain", "--root", rootPath, "--envelope", envelopePath,
    "--output", join(directory, "accepted.json"), "--clock-skew", "60",
    "--allow-expired-hash", hash,
  );
  assert.equal(accepted.expiredFallback, true);
  assert.equal(accepted.manifestHash, hash);
});

test("PowerShell persists delegation anchors and rejects rollback or equivocation", async (context) => {
  if (process.platform !== "win32") return context.skip("Windows PowerShell integration test");
  const directory = mkdtempSync(join(tmpdir(), "hch-worker-delegation-"));
  const stateRoot = join(directory, "state");
  const root = generateKeyPairSync("ed25519");
  const release = generateKeyPairSync("ed25519");
  const rootPrivate = root.privateKey.export({ type: "pkcs8", format: "pem" });
  const rootPublic = root.publicKey.export({ type: "spki", format: "pem" });
  const releasePrivate = release.privateKey.export({ type: "pkcs8", format: "pem" });
  const releasePublic = release.publicKey.export({ type: "spki", format: "pem" });
  const rootPath = join(directory, "root.pem");
  writeFileSync(rootPath, rootPublic);

  const now = Math.floor(Date.now() / 1000);
  const rootKeyId = "hch-root-rollback-test";
  const releaseKeyId = "hch-release-rollback-test";
  const unsignedPayload = {
    schemaVersion: "2.0",
    sequence: 1,
    releaseId: "delegation-test.1",
    issuedAt: new Date((now - 1) * 1000).toISOString(),
    expiresAt: new Date((now + 1200) * 1000).toISOString(),
    previousManifestHash: null,
    minimumAcceptedSequence: 1,
    runtime: { workerVersion: "2.0.0" },
    engine: {
      provider: "vps-local",
      adapter: "ollama",
      adapterVersion: "1.0.0",
      model: "qwen2.5:1.5b-instruct",
      modelDigest: "d".repeat(64),
      protocol: "ollama-chat",
    },
    generation: { temperature: 0.2, contextWindow: 8192, maxOutputTokens: 2048 },
    capacityPolicy: adaptiveCapacityPolicy(),
    adaptiveWorkPolicy: adaptiveWorkPolicy(),
    editorial: {
      policyHash: "a".repeat(64),
      promptConfigHash: "b".repeat(64),
      pipelineVersion: "2.0.0",
    },
    actions: [],
    rootActionCapabilities: [],
    artifacts: [],
    endpoints: {},
    security: { authorizationByIp: false, arbitraryRemoteCommands: false },
    safety: {},
  };
  const manifestHash = createHash("sha256")
    .update(canonicalizeJson(unsignedPayload))
    .digest("hex");
  const payload = { ...unsignedPayload, hashAlgorithm: "sha256", hash: manifestHash };
  const manifest = await signManifestEnvelope(payload, releasePrivate, {
    keyId: releaseKeyId,
    created: now,
    expires: now + 1200,
  });
  const invalidUnsignedPayload = {
    ...unsignedPayload,
    security: { authorizationByIp: true, arbitraryRemoteCommands: false },
  };
  const invalidManifestHash = createHash("sha256")
    .update(canonicalizeJson(invalidUnsignedPayload))
    .digest("hex");
  const invalidManifest = await signManifestEnvelope(
    { ...invalidUnsignedPayload, hashAlgorithm: "sha256", hash: invalidManifestHash },
    releasePrivate,
    { keyId: releaseKeyId, created: now, expires: now + 1200 },
  );
  const delegationOptions = (sequence, expires) => ({
    rootKeyId,
    releaseKeyId,
    created: now - 10,
    notBefore: now - 10,
    expires,
    sequence,
  });
  const delegations = {
    accepted: await signReleaseKeyDelegation(
      releasePublic, rootPrivate, delegationOptions(2, now + 3600),
    ),
    older: await signReleaseKeyDelegation(
      releasePublic, rootPrivate, delegationOptions(1, now + 3600),
    ),
    equivocated: await signReleaseKeyDelegation(
      releasePublic, rootPrivate, delegationOptions(2, now + 3500),
    ),
    newer: await signReleaseKeyDelegation(
      releasePublic, rootPrivate, delegationOptions(3, now + 3700),
    ),
    rejectedAfterSignature: await signReleaseKeyDelegation(
      releasePublic, rootPrivate, delegationOptions(4, now + 3800),
    ),
  };
  const rootPublicKeyFingerprint = await workerPublicKeyFingerprint(rootPublic);
  const envelopePaths = {};
  for (const [name, delegation] of Object.entries(delegations)) {
    const path = join(directory, `${name}.json`);
    writeFileSync(path, JSON.stringify({
      manifest: name === "rejectedAfterSignature" ? invalidManifest : manifest,
      delegation,
      rootKeyId,
      rootPublicKeyFingerprint,
    }));
    envelopePaths[name] = path;
  }
  const acceptedHash = createHash("sha256")
    .update(canonicalizeJson(delegations.accepted))
    .digest("hex");
  const newerHash = createHash("sha256")
    .update(canonicalizeJson(delegations.newer))
    .digest("hex");
  const escaped = (value) => value.replaceAll("'", "''");
  const script = `
    $m=Import-Module '${escaped(modulePath)}' -Force -PassThru
    $config=@{
      NodeId='windows-worker-01'
      StateRoot='${escaped(stateRoot)}'
      InstallRoot='${escaped(join(directory, "runtime"))}'
      RootPublicKeyPath='${escaped(rootPath)}'
      NodePath='${escaped(process.execPath)}'
      MinimumNodeMajor=22
      ClockSkewSeconds=60
    }
    $accepted=Test-HchSignedManifest -Config $config -Envelope (Get-Content -Raw -LiteralPath '${escaped(envelopePaths.accepted)}'|ConvertFrom-Json)
    $initial=Get-Content -Raw -LiteralPath (Join-Path $config.StateRoot 'trust-state.json')|ConvertFrom-Json
    $rollback=$null
    try {[void](Test-HchSignedManifest -Config $config -Envelope (Get-Content -Raw -LiteralPath '${escaped(envelopePaths.older)}'|ConvertFrom-Json))} catch {$rollback=$_.Exception.Message}
    $afterRollback=Get-Content -Raw -LiteralPath (Join-Path $config.StateRoot 'trust-state.json')|ConvertFrom-Json
    $equivocation=$null
    try {[void](Test-HchSignedManifest -Config $config -Envelope (Get-Content -Raw -LiteralPath '${escaped(envelopePaths.equivocated)}'|ConvertFrom-Json))} catch {$equivocation=$_.Exception.Message}
    $afterEquivocation=Get-Content -Raw -LiteralPath (Join-Path $config.StateRoot 'trust-state.json')|ConvertFrom-Json
    $newer=Test-HchSignedManifest -Config $config -Envelope (Get-Content -Raw -LiteralPath '${escaped(envelopePaths.newer)}'|ConvertFrom-Json)
    $afterNewer=Get-Content -Raw -LiteralPath (Join-Path $config.StateRoot 'trust-state.json')|ConvertFrom-Json
    $incompleteVerification=$null
    try {[void](Test-HchSignedManifest -Config $config -Envelope (Get-Content -Raw -LiteralPath '${escaped(envelopePaths.rejectedAfterSignature)}'|ConvertFrom-Json))} catch {$incompleteVerification=$_.Exception.Message}
    $final=Get-Content -Raw -LiteralPath (Join-Path $config.StateRoot 'trust-state.json')|ConvertFrom-Json
    [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes((@{
      acceptedSequence=$accepted.DelegationSequence
      acceptedHash=$accepted.DelegationHash
      initial=$initial
      rollback=$rollback
      afterRollback=$afterRollback
      equivocation=$equivocation
      afterEquivocation=$afterEquivocation
      newerSequence=$newer.DelegationSequence
      newerHash=$newer.DelegationHash
      afterNewer=$afterNewer
      incompleteVerification=$incompleteVerification
      final=$final
    }|ConvertTo-Json -Depth 20 -Compress)))
  `;
  const encoded = execFileSync(
    "powershell.exe",
    ["-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script],
    { encoding: "utf8" },
  ).trim();
  const result = JSON.parse(Buffer.from(encoded, "base64").toString("utf8"));
  assert.equal(result.acceptedSequence, 2);
  assert.equal(result.acceptedHash, acceptedHash);
  assert.equal(result.initial.delegationSequence, 2);
  assert.equal(result.initial.delegationHash, acceptedHash);
  assert.equal(result.rollback, "delegation-rollback-detected");
  assert.equal(result.afterRollback.delegationSequence, 2);
  assert.equal(result.afterRollback.delegationHash, acceptedHash);
  assert.equal(result.equivocation, "delegation-equivocation-detected");
  assert.equal(result.afterEquivocation.delegationSequence, 2);
  assert.equal(result.afterEquivocation.delegationHash, acceptedHash);
  assert.equal(result.newerSequence, 3);
  assert.equal(result.newerHash, newerHash);
  assert.equal(result.afterNewer.delegationSequence, 3);
  assert.equal(result.afterNewer.delegationHash, newerHash);
  assert.equal(result.incompleteVerification, "manifest-security-boundary-invalid");
  assert.equal(result.final.delegationSequence, 3);
  assert.equal(result.final.delegationHash, newerHash);
});

test("PowerShell files parse under the Windows PowerShell 5.1 grammar", (context) => {
  const powershell = process.platform === "win32" ? "powershell.exe" : "pwsh";
  const probe = spawnSync(powershell, ["-NoProfile", "-Command", "$PSVersionTable.PSVersion.Major"], {
    encoding: "utf8",
  });
  if (probe.error) return context.skip(`${powershell} is not installed`);
  const paths = [
    modulePath,
    ...readdirSync(kitRoot)
      .filter((name) => name.endsWith(".ps1"))
      .map((name) => join(kitRoot, name)),
  ];
  for (const path of paths) {
    const escaped = path.replaceAll("'", "''");
    const script = [
      "$tokens=$null;$errors=$null",
      `[void][Management.Automation.Language.Parser]::ParseFile('${escaped}',[ref]$tokens,[ref]$errors)`,
      "if($errors.Count){$errors|%{$_.Message};exit 1}",
    ].join(";");
    const result = spawnSync(powershell, ["-NoProfile", "-Command", script], { encoding: "utf8" });
    assert.equal(result.status, 0, `${path}: ${result.stdout}${result.stderr}`);
  }
});

test("PowerShell produces the canonical HTTP Message Signature base", async (context) => {
  if (process.platform !== "win32") return context.skip("Windows PowerShell integration test");
  const pair = generateKeyPairSync("ed25519");
  const privatePem = pair.privateKey.export({ type: "pkcs8", format: "pem" });
  const body = "{}";
  const request = {
    method: "POST",
    authority: "hubtech.online",
    path: "/api/editorial/orchestrator/claim",
    contentType: "application/json",
    body,
    nodeId: "windows-worker-01",
    keyId: "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    requestId: "0123456789abcdef0123456789abcdef",
    created: 1_800_000_000,
    expires: 1_800_000_120,
    nonce: "01234567-89ab-cdef-0123-456789abcdef",
  };
  const canonical = await signWorkerRequest(request, privatePem);
  const digest = await createContentDigest(body);
  const escapedModule = modulePath.replaceAll("'", "''");
  const script = `
    $m=Import-Module '${escapedModule}' -Force -PassThru
    $h=@{
      'content-digest'='${digest}';'content-type'='application/json';
      'x-hch-node-id'='${request.nodeId}';'x-hch-key-id'='${request.keyId}';
      'x-hch-request-id'='${request.requestId}';'x-hch-created'='${request.created}';
      'x-hch-expires'='${request.expires}';'x-hch-nonce'='${request.nonce}'
    }
    $r=& $m { param($headers) Get-HchRequestSignatureBase -Method POST -Uri ([Uri]'https://hubtech.online/api/editorial/orchestrator/claim') -Headers $headers -Created ${request.created} -Expires ${request.expires} -KeyId '${request.keyId}' } $h
    [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($r.Base))
  `;
  const encoded = execFileSync(
    "powershell.exe",
    ["-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script],
    { encoding: "utf8" },
  ).trim();
  assert.equal(Buffer.from(encoded, "base64").toString("utf8"), canonical.signatureBase);
});

test("updateReceipt separates the canonical receipt hash from the local journal hash", (context) => {
  if (process.platform !== "win32") return context.skip("Windows PowerShell integration test");
  const directory = mkdtempSync(join(tmpdir(), "hch-worker-receipt-"));
  const stateRoot = join(directory, "state");
  const backupRoot = join(directory, "backup");
  const escaped = (value) => value.replaceAll("'", "''");
  const manifestHash = "b".repeat(64);
  const artifactHash = "a".repeat(64);
  const script = `
    $m=Import-Module '${escaped(modulePath)}' -Force -PassThru
    New-Item -ItemType Directory -Path '${escaped(stateRoot)}','${escaped(backupRoot)}' -Force|Out-Null
    $config=@{NodeId='windows-worker-01';StateRoot='${escaped(stateRoot)}';InstallRoot='${escaped(join(directory, "runtime"))}';NodePath='${escaped(process.execPath)}';MinimumNodeMajor=22}
    $identity=[pscustomobject]@{keyId='SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'}
    $manifest=[pscustomobject]@{ManifestHash='${manifestHash}';ContentContractHash='${manifestHash}';Payload=[pscustomobject]@{artifacts=@([pscustomobject]@{name='policy';sha256='${artifactHash}'})}}
    $transaction=[pscustomobject]@{Id='tx-test';BackupDirectory='${escaped(backupRoot)}';Journal=[Collections.ArrayList]::new()}
    $receipt=& $m {param($c,$i,$mf,$tx) New-HchUpdateReceipt -Config $c -Identity $i -Manifest $mf -Transaction $tx -Result applied} $config $identity $manifest $transaction
    $persisted=Get-Content -Raw -LiteralPath (Join-Path '${escaped(backupRoot)}' 'update-receipt.json')|ConvertFrom-Json
    [IO.File]::WriteAllText((Join-Path '${escaped(stateRoot)}' 'applied-manifest.json'),
      (@{manifestHash='${manifestHash}'}|ConvertTo-Json -Compress),[Text.UTF8Encoding]::new($false))
    $legacyBackup='${escaped(join(directory, "legacy-backup"))}'
    New-Item -ItemType Directory -Path $legacyBackup -Force|Out-Null
    $legacyTransaction=[pscustomobject]@{Id='tx-legacy';BackupDirectory=$legacyBackup;Journal=[Collections.ArrayList]::new()}
    $legacyReceipt=& $m {param($c,$i,$mf,$tx) New-HchUpdateReceipt -Config $c -Identity $i -Manifest $mf -Transaction $tx -Result no-change} $config $identity $manifest $legacyTransaction
    [IO.File]::WriteAllText((Join-Path '${escaped(stateRoot)}' 'applied-manifest.json'),
      (@{manifestHash=('c'*64)}|ConvertTo-Json -Compress),[Text.UTF8Encoding]::new($false))
    $mismatchCode=try {
      & $m {param($c,$i,$mf,$tx) New-HchUpdateReceipt -Config $c -Identity $i -Manifest $mf -Transaction $tx -Result no-change} $config $identity $manifest $legacyTransaction|Out-Null
      'accepted'
    } catch { $_.Exception.Message }
    [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes((@{receipt=$receipt;localLog=$persisted.localLog;legacyReceipt=$legacyReceipt;mismatchCode=$mismatchCode}|ConvertTo-Json -Depth 20 -Compress)))
  `;
  const encoded = execFileSync(
    "powershell.exe",
    ["-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script],
    { encoding: "utf8" },
  ).trim();
  const persisted = JSON.parse(Buffer.from(encoded, "base64").toString("utf8"));
  const { receipt, localLog } = persisted;
  const { receiptHash, localAuditHash, ...core } = receipt;
  const expectedReceiptHash = createHash("sha256").update(canonicalizeJson(core)).digest("hex");
  const expectedLocalAuditHash = createHash("sha256").update(canonicalizeJson(localLog)).digest("hex");
  assert.equal(receiptHash, expectedReceiptHash);
  assert.equal(localAuditHash, expectedLocalAuditHash);
  assert.deepEqual(receipt.artifactHashes, { policy: artifactHash });
  assert.equal(receipt.targetManifestHash, manifestHash);
  assert.equal(receipt.rollbackPerformed, false);
  assert.equal(persisted.legacyReceipt.result, "no-change");
  assert.equal(persisted.legacyReceipt.previousManifestHash, manifestHash);
  assert.equal(
    persisted.mismatchCode,
    "update-receipt-result-manifest-consistency-invalid",
  );
});

test("assignment input and runtime profile hashes are verified before use", (context) => {
  if (process.platform !== "win32") return context.skip("Windows PowerShell integration test");
  const directory = mkdtempSync(join(tmpdir(), "hch-worker-assignment-"));
  const entry = { id: "source-1", kind: "article", title: "Canonical source", content_hash: "c".repeat(64) };
  const adaptiveWorkPolicy = {
    algorithmVersion: "hch-adaptive-work-v1",
    processingWindowSeconds: 2700,
    nearWindowRatio: 0.8,
    firstProgressGraceSeconds: 900,
    stallAfterSeconds: 600,
    finalizationGraceSeconds: 600,
    windowMode: "advisory",
    minimumTierIgnoresWindow: true,
    livenessBasis: "progress",
    tiers: [{ id: "full", rank: 0, minimumUnit: true, maxOutputTokens: 2048, editorialProfile: "EDITORIAL_LONG_FORM" }],
  };
  const adaptiveWorkPolicyHash = createHash("sha256")
    .update(canonicalizeJson(adaptiveWorkPolicy)).digest("hex");
  const generationPlan = {
    algorithmVersion: adaptiveWorkPolicy.algorithmVersion,
    tierId: "full",
    tierRank: 0,
    maxOutputTokens: 2048,
    editorialProfile: "EDITORIAL_LONG_FORM",
    minimumUnit: true,
    processingWindowSeconds: 2700,
    nearWindowSeconds: 2160,
    firstProgressGraceSeconds: 900,
    stallAfterSeconds: 600,
    finalizationGraceSeconds: 600,
    policyHash: adaptiveWorkPolicyHash,
  };
  const profileCore = {
    provider: "vps-local",
    engineAdapter: "ollama",
    engineAdapterVersion: "1.0.0",
    model: "qwen2.5:1.5b-instruct",
    modelDigest: "d".repeat(64),
    protocol: "ollama",
    temperature: 0.2,
    contextWindow: 8192,
    maxOutputTokens: 2048,
    policyId: "hch-editorial",
    policyVersion: "2.0.0",
    policyHash: "e".repeat(64),
    promptConfigHash: "f".repeat(64),
    pipelineVersion: "2.0.0",
    manifestSequence: 2,
    manifestHash: "a".repeat(64),
  };
  const assignment = {
    assignmentId: "01234567-89ab-cdef-0123-456789abcdef",
    leaseToken: "01234567-89ab-cdef-0123-456789abcdef",
    leaseExpiresAt: new Date(Date.now() + 600_000).toISOString(),
    status: "processing",
    inputSnapshotHash: createHash("sha256").update(canonicalizeJson(entry)).digest("hex"),
    entry,
    runtimeProfile: {
      ...profileCore,
      runtimeProfileHash: createHash("sha256").update(canonicalizeJson(profileCore)).digest("hex"),
    },
    generationPlan,
    generationPlanHash: createHash("sha256").update(canonicalizeJson(generationPlan)).digest("hex"),
  };
  const assignmentPath = join(directory, "assignment.json");
  writeFileSync(assignmentPath, JSON.stringify(assignment));
  const escaped = (value) => value.replaceAll("'", "''");
  const script = `
    $m=Import-Module '${escaped(modulePath)}' -Force -PassThru
    $config=@{NodeId='windows-worker-01';StateRoot='${escaped(join(directory, "state"))}';InstallRoot='${escaped(join(directory, "runtime"))}';NodePath='${escaped(process.execPath)}';MinimumNodeMajor=22}
    Write-HchJsonAtomic -Path (Join-Path (Join-Path $config.InstallRoot 'config') 'engine.json') -Value ([ordered]@{
      schemaVersion=2
      engine=[ordered]@{provider='vps-local';adapter='ollama';adapterVersion='1.0.0'}
      manifestSequence=2
      manifestHash='${"a".repeat(64)}'
      adaptiveWorkPolicy=ConvertFrom-Json -InputObject '${JSON.stringify(adaptiveWorkPolicy)}'
      adaptiveWorkPolicyHash='${adaptiveWorkPolicyHash}'
      generation=[ordered]@{maxOutputTokens=2048}
    })
    Write-HchJsonAtomic -Path (Join-Path $config.StateRoot 'applied-manifest.json') -Value ([ordered]@{adaptiveWorkPolicyHash='${adaptiveWorkPolicyHash}'})
    Write-HchJsonAtomic -Path (Join-Path $config.StateRoot 'ready.json') -Value ([ordered]@{adaptiveWorkPolicyHash='${adaptiveWorkPolicyHash}'})
    $assignment=Get-Content -Raw -LiteralPath '${escaped(assignmentPath)}'|ConvertFrom-Json
    $valid=Assert-HchAssignmentIntegrity -Config $config -Assignment $assignment
    $assignment.entry.title='tampered'
    $entryRejected=$null
    try {[void](Assert-HchAssignmentIntegrity -Config $config -Assignment $assignment)} catch {$entryRejected=$_.Exception.Message}
    $assignment.entry.title='Canonical source'
    $assignment.runtimeProfile.provider='other-local'
    $hashRejected=$null
    try {[void](Assert-HchAssignmentIntegrity -Config $config -Assignment $assignment)} catch {$hashRejected=$_.Exception.Message}
    $profileCore=[ordered]@{}
    foreach($property in $assignment.runtimeProfile.PSObject.Properties){
      if([string]$property.Name -ne 'runtimeProfileHash'){$profileCore[[string]$property.Name]=$property.Value}
    }
    $assignment.runtimeProfile.runtimeProfileHash=& $m {param($c,$v) Get-HchCanonicalSha256 -Config $c -Value $v} $config $profileCore
    $engineRejected=$null
    try {[void](Assert-HchAssignmentIntegrity -Config $config -Assignment $assignment)} catch {$engineRejected=$_.Exception.Message}
    [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes((@{
      valid=$valid.valid;entryRejected=$entryRejected;hashRejected=$hashRejected;engineRejected=$engineRejected
    }|ConvertTo-Json -Compress)))
  `;
  const encoded = execFileSync(
    "powershell.exe",
    ["-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script],
    { encoding: "utf8" },
  ).trim();
  const result = JSON.parse(Buffer.from(encoded, "base64").toString("utf8"));
  assert.equal(result.valid, true);
  assert.equal(result.entryRejected, "assignment-input-snapshot-hash-mismatch");
  assert.equal(result.hashRejected, "assignment-runtime-profile-hash-mismatch");
  assert.equal(result.engineRejected, "assignment-runtime-profile-engine-mismatch:provider");
});

test("pending operations preserve request id and body digest for idempotent retry", (context) => {
  if (process.platform !== "win32") return context.skip("Windows PowerShell integration test");
  const directory = mkdtempSync(join(tmpdir(), "hch-worker-idempotency-"));
  const escaped = (value) => value.replaceAll("'", "''");
  const script = `
    $m=Import-Module '${escaped(modulePath)}' -Force -PassThru
    $config=@{NodeId='windows-worker-01';StateRoot='${escaped(directory)}';InstallRoot='${escaped(join(directory, "runtime"))}';NodePath='${escaped(process.execPath)}';MinimumNodeMajor=22}
    $body=[ordered]@{nodeId='windows-worker-01';workerKeyId='SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';requested=1}
    $one=& $m {param($c,$b) Get-HchOperationRequestId -Config $c -OperationKey 'claim-request' -Target 'POST:/api/editorial/orchestrator/claim' -Body $b} $config $body
    $two=& $m {param($c,$b) Get-HchOperationRequestId -Config $c -OperationKey 'claim-request' -Target 'POST:/api/editorial/orchestrator/claim' -Body $b} $config $body
    $conflict=$null
    try {& $m {param($c) Get-HchOperationRequestId -Config $c -OperationKey 'claim-request' -Target 'POST:/api/editorial/orchestrator/claim' -Body ([ordered]@{requested=2})} $config|Out-Null} catch {$conflict=$_.Exception.Message}
    & $m {param($c,$id) Complete-HchOperationRequest -Config $c -OperationKey 'claim-request' -RequestId $id} $config $one
    $three=& $m {param($c,$b) Get-HchOperationRequestId -Config $c -OperationKey 'claim-request' -Target 'POST:/api/editorial/orchestrator/claim' -Body $b} $config $body
    [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes((@{one=$one;two=$two;three=$three;conflict=$conflict}|ConvertTo-Json -Compress)))
  `;
  const encoded = execFileSync(
    "powershell.exe",
    ["-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script],
    { encoding: "utf8" },
  ).trim();
  const result = JSON.parse(Buffer.from(encoded, "base64").toString("utf8"));
  assert.equal(result.one, result.two);
  assert.notEqual(result.one, result.three);
  assert.equal(result.conflict, "idempotency-operation-conflict:claim-request");
});

test("a signed node heartbeat repairs only stale connection status", (context) => {
  if (process.platform !== "win32") return context.skip("Windows PowerShell integration test");
  const directory = mkdtempSync(join(tmpdir(), "hch-worker-heartbeat-status-"));
  context.after(() => rmSync(directory, { recursive: true, force: true }));
  const escaped = (value) => value.replaceAll("'", "''");
  const contentContractHash = "c".repeat(64);
  const script = `
    $m=Import-Module '${escaped(modulePath)}' -Force -PassThru
    $config=@{
      NodeId='windows-worker-01';StateRoot='${escaped(directory)}'
      InstallRoot='${escaped(join(directory, "runtime"))}';LocalParallelismLimit=8
      NodeHeartbeatIntervalSeconds=60;NodeHeartbeatRequestTimeoutSeconds=10
    }
    Write-HchJsonAtomic -Path (Join-Path $config.StateRoot 'ready.json') -Value ([ordered]@{
      readyUntil=[DateTimeOffset]::UtcNow.AddHours(1).ToString('o')
      rootKeyId='root-v1';releaseKeyId='release-v1';manifestSequence=5
      manifestHash='${"a".repeat(64)}';contentContractHash='${contentContractHash}'
      policyHash='${"b".repeat(64)}';trustVerifiedAt=[DateTimeOffset]::UtcNow.ToString('o')
    })
    $connectionFailureAt=[DateTimeOffset]::UtcNow.ToString('o')
    Write-HchJsonAtomic -Path (Join-Path $config.StateRoot 'status.json') -Value ([ordered]@{
      state='standby';code='worker-bootstrap-already-running';currentBatch=$null
      connection=[ordered]@{
        api='error';lastSuccessAt=$null;lastFailureAt=$connectionFailureAt
        lastErrorCode='worker-bootstrap-already-running'
      }
      transport=[ordered]@{
        tlsStatus='verified';certificateStatus='valid';certificateExpiresAt=$null
        certificateFingerprint=$null;errorCode=$null
      }
      trust=[ordered]@{
        status='verified';rootKeyId='root-v1';releaseKeyId='release-v1';manifestSequence=5
        manifestHash='${"a".repeat(64)}';contentContractHash='${contentContractHash}'
        policyHash='${"b".repeat(64)}';lastVerifiedAt=$connectionFailureAt;errorCode=$null
      }
    })
    $result=& $m { param($c)
      function Get-HchWorkerIdentity {
        [pscustomobject]@{keyId='SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'}
      }
      function Get-HchChallenge { 'nonce' }
      function Invoke-HchSignedJsonRequest { [pscustomobject]@{} }
      function Assert-HchNodeHeartbeatResponse {
        [pscustomobject]@{
          capacity=[pscustomobject]@{
            requestedCapacity=0;grantedCapacity=0;activeAssignments=0
            reason='operator-paused';grantedUntil=$null
          }
          workload=[pscustomobject]@{};claim=[pscustomobject]@{}
        }
      }
      function Write-HchNodeHeartbeatSnapshot { [pscustomobject]@{} }
      [void](Invoke-HchWorkerNodeHeartbeat -Config $c -RequestedCapacity 0)
      $healed=Read-HchJsonFile -Path (Join-Path $c.StateRoot 'status.json')
      $healedSnapshot=$healed|ConvertTo-Json -Depth 20 -Compress|ConvertFrom-Json
      $healed.state='update-failed';$healed.code='artifact-self-test-failed'
      $healed.connection.api='error';$healed.connection.auth='pending'
      $healed.connection.ed25519=$false;$healed.connection.lastErrorCode='orchestrator-timeout'
      Write-HchJsonAtomic -Path (Join-Path $c.StateRoot 'status.json') -Value $healed
      [void](Invoke-HchWorkerNodeHeartbeat -Config $c -RequestedCapacity 0)
      $preserved=Read-HchJsonFile -Path (Join-Path $c.StateRoot 'status.json')
      [pscustomobject]@{healed=$healedSnapshot;preserved=$preserved}
    } $config
    [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes(
      ($result|ConvertTo-Json -Depth 20 -Compress)))
  `;
  const encoded = execFileSync(
    "powershell.exe",
    ["-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script],
    { encoding: "utf8" },
  ).trim();
  const result = JSON.parse(Buffer.from(encoded, "base64").toString("utf8"));
  assert.equal(result.healed.state, "standby");
  assert.equal(result.healed.connection.api, "connected");
  assert.equal(result.healed.connection.auth, "ed25519");
  assert.equal(result.healed.connection.lastErrorCode, null);
  assert.equal(result.healed.code, "");
  assert.equal(result.healed.contentContractHash, contentContractHash);
  assert.equal(result.healed.trust.contentContractHash, contentContractHash);
  assert.equal(result.preserved.state, "update-failed");
  assert.equal(result.preserved.code, "artifact-self-test-failed");
  assert.equal(result.preserved.connection.api, "connected");
  assert.equal(result.preserved.connection.lastErrorCode, null);
});

test("worker kit is fail-closed and contains no remote shell execution path", () => {
  const source = readFileSync(modulePath, "utf8");
  for (const forbidden of [
    /Invoke-Expression/i,
    /ScriptBlock\]::Create/i,
    /cmd(?:\.exe)?\s+\/c/i,
    /powershell(?:\.exe)?\s+-Command/i,
    /Start-Process/i,
  ]) {
    assert.doesNotMatch(source, forbidden);
  }
  assert.match(source, /root-action-refused-no-canonical-authorization/);
  assert.match(source, /rootActionCapabilities/);
  assert.match(source, /requires-separate-root-envelope/);
  assert.match(source, /manifest-rollback-detected/);
  assert.match(source, /manifest-equivocation-detected/);
  assert.match(source, /delegation-rollback-detected/);
  assert.match(source, /delegation-equivocation-detected/);
  assert.match(source, /worker-not-ready-bootstrap-required/);
  assert.match(source, /result-rejected-and-discarded-policy-stale/);
  assert.match(source, /runtimeProfileHash/);
  for (const field of ["provider", "engineAdapter", "engineAdapterVersion"]) {
    assert.match(source, new RegExp(field));
  }
  assert.match(source, /updateReceipt = \$updateReceipt/);
  for (const field of [
    "previousManifestHash", "targetManifestHash", "artifactHashes", "rollbackPerformed", "receiptHash", "localAuditHash",
  ]) assert.match(source, new RegExp(field));
  assert.match(source, /hch-editorial-worker-request\/v1/);
  assert.match(source, /control-plane-request-origin-mismatch/);
  assert.match(source, /AllowAutoRedirect = \$false/);
  assert.match(source, /assignment-input-snapshot-hash-mismatch/);
  assert.match(source, /assignment-runtime-profile-hash-mismatch/);
  assert.match(source, /assignment-runtime-profile-engine-mismatch/);
  assert.match(source, /hch-adaptive-capacity-v1/);
  assert.match(source, /installed-capacity-policy-hash-mismatch/);
  const nodeHeartbeatStart = source.indexOf("function Invoke-HchWorkerNodeHeartbeat");
  const nodeHeartbeatEnd = source.indexOf("function Get-HchRemainingBatch", nodeHeartbeatStart);
  const nodeHeartbeatSource = source.slice(nodeHeartbeatStart, nodeHeartbeatEnd);
  assert.match(nodeHeartbeatSource, /\$body\.pressure = \$normalizedPressure/);
  assert.match(
    nodeHeartbeatSource,
    /Set-HchWorkerStatus[\s\S]+-ConnectionState 'connected'/,
  );
  assert.match(nodeHeartbeatSource, /\$currentState -eq 'connection-error'/);
  assert.match(nodeHeartbeatSource, /worker-not-ready-bootstrap-required/);
  assert.match(source, /inputSnapshotHash = \[string\]\$assignmentIntegrity\.inputSnapshotHash/);
  assert.match(source, /\$receiptResult = 'no-change'/);
  assert.match(source, /hch\.pending-operation\/v1/);
  assert.match(source, /AddHours\(24\)/);
  assert.match(source, /-RequestId \$requestId/);
  const claimStart = source.indexOf("function Invoke-HchWorkerClaim");
  const claimEnd = source.indexOf("function Get-HchRemainingBatch");
  const claimSource = source.slice(claimStart, claimEnd);
  assert.doesNotMatch(claimSource, /manifestSequence\s*=/);
  assert.doesNotMatch(claimSource, /policyHash\s*=/);
  assert.doesNotMatch(claimSource, /\$body\.pressure|pressure\s*=\s*\$pressureSnapshot/);
  const attestationStart = source.indexOf("$attestation = [ordered]@{");
  const attestationEnd = source.indexOf("$attestationPath", attestationStart);
  const attestationSource = source.slice(attestationStart, attestationEnd);
  for (const field of ["provider", "engineAdapter", "engineAdapterVersion"]) {
    assert.match(attestationSource, new RegExp(`${field}\\s*=`));
  }
  assert.match(attestationSource, /adaptiveWorkPolicyHash\s*=/);
  assert.match(attestationSource, /contentContractHash\s*=/);
  assert.doesNotMatch(attestationSource, /\bengineVersion\s*=/);
});

test("dashboard files use the provisional schemas and exclude secrets", () => {
  const source = readFileSync(modulePath, "utf8");
  assert.match(source, /hch\.worker-status\/v1/);
  assert.match(source, /hch\.worker-metrics\/v1/);
  assert.match(source, /Write-HchJsonAtomic -Path \$statusPath/);
  assert.match(source, /Write-HchJsonAtomic -Path \$metricsPath/);
  assert.match(source, /Get-NetAdapterStatistics/);
  assert.match(source, /Win32_PerfFormattedData_GPUPerformanceCounters_GPUEngine/);
  assert.match(source, /totalActiveSeconds/);
  assert.match(source, /totalMilliseconds/);
  assert.match(source, /certificateFingerprint/);
  assert.match(source, /rootKeyId/);
  const statusSchema = JSON.parse(
    readFileSync(join(kitRoot, "schemas", "worker-status-v1.schema.json"), "utf8"),
  );
  assert.ok(statusSchema.properties.state.enum.includes("update-required"));
  const telemetrySection = source.slice(
    source.indexOf("function Set-HchWorkerStatus"),
    source.indexOf("function Disable-HchWorkerReady"),
  );
  assert.doesNotMatch(telemetrySection, /privateKeyPath\s*=/);
  assert.doesNotMatch(telemetrySection, /leaseToken\s*=/);
  assert.doesNotMatch(telemetrySection, /Bearer\s+/);
});

test("kit consumes the repository canonical signature module", () => {
  const helperSource = readFileSync(helper, "utf8");
  assert.match(helperSource, /lib\/editorial-worker-signatures\.mjs/);
  assert.match(helperSource, /verifyManifestWithDelegation/);
  assert.ok(readFileSync(join(repositoryRoot, "lib", "editorial-worker-signatures.mjs"), "utf8").length > 1000);
});

function runHelper(...args) {
  return JSON.parse(execFileSync(process.execPath, [helper, ...args], { encoding: "utf8" }));
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

function adaptiveWorkPolicy() {
  return {
    algorithmVersion: "hch-adaptive-work-v1",
    processingWindowSeconds: 2700,
    nearWindowRatio: 0.8,
    firstProgressGraceSeconds: 900,
    stallAfterSeconds: 600,
    finalizationGraceSeconds: 180,
    windowMode: "advisory",
    minimumTierIgnoresWindow: true,
    livenessBasis: "progress",
    tiers: [
      { id: "minimum", rank: 0, minimumUnit: true, maxOutputTokens: 768, editorialProfile: "EDITORIAL_MINIMUM" },
      { id: "compact", rank: 1, minimumUnit: false, maxOutputTokens: 1536, editorialProfile: "EDITORIAL_COMPACT" },
      { id: "full", rank: 2, minimumUnit: false, maxOutputTokens: 2400, editorialProfile: "EDITORIAL_LONG_FORM" },
    ],
  };
}
