import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";

import {
  manifestContentContractHash,
  signManifestEnvelope,
  signReleaseKeyDelegation,
  verifyManifestContentCompatibility,
  verifyManifestWithDelegation,
} from "../lib/editorial-worker-signatures.mjs";

test("contentContractHash matches the orchestrator projection and ignores operational metadata", async () => {
  const manifest = manifestFixture();
  const expectedContract = {
    adaptiveWorkPolicy: manifest.adaptiveWorkPolicy,
    artifacts: manifest.artifacts,
    editorial: {
      pipelineVersion: manifest.editorial.pipelineVersion,
      policyHash: manifest.editorial.policyHash,
      promptConfigHash: manifest.editorial.promptConfigHash,
    },
    engine: {
      adapter: manifest.engine.adapter,
      adapterVersion: manifest.engine.adapterVersion,
      model: manifest.engine.model,
      modelDigest: manifest.engine.modelDigest,
      protocol: manifest.engine.protocol,
      provider: manifest.engine.provider,
    },
    generation: manifest.generation,
  };
  const expected = createHash("sha256")
    .update(orchestratorStableJson(expectedContract))
    .digest("hex");

  assert.equal(await manifestContentContractHash(manifest), expected);

  const metadataOnly = structuredClone(manifest);
  metadataOnly.runtime.workerVersion = "9.9.9";
  metadataOnly.capacityPolicy.defaultNodeCeiling = 32;
  metadataOnly.sequence += 1;
  metadataOnly.expiresAt = "2031-01-01T00:00:00.000Z";
  assert.equal(await manifestContentContractHash(metadataOnly), expected);

  const contentChange = structuredClone(manifest);
  contentChange.generation.maxOutputTokens += 1;
  assert.notEqual(await manifestContentContractHash(contentChange), expected);
});

test("bootstrap 2.3.0 requires a truthful content compatibility declaration", async () => {
  const manifest = manifestFixture();

  const missing = await verifyManifestContentCompatibility(manifest);
  assert.equal(missing.ok, false);
  assert.equal(missing.code, "manifest-compatibility-missing");

  manifest.compatibility = await compatibilityFor(manifest);
  assert.equal((await verifyManifestContentCompatibility(manifest)).ok, true);

  manifest.compatibility.minimumWorkerVersion = "future";
  assert.equal(
    (await verifyManifestContentCompatibility(manifest)).code,
    "manifest-compatibility-invalid",
  );

  manifest.compatibility = await compatibilityFor(manifest);
  manifest.compatibility.minimumWorkerVersion = "4.0.0";
  assert.equal(
    (await verifyManifestContentCompatibility(manifest)).code,
    "manifest-compatibility-invalid",
  );

  manifest.compatibility = await compatibilityFor(manifest);
  manifest.compatibility.classification = "initial";
  manifest.compatibility.previousContentContractHash = null;
  assert.equal((await verifyManifestContentCompatibility(manifest)).ok, true);

  manifest.compatibility.previousContentContractHash =
    manifest.compatibility.contentContractHash;
  const falseInitial = await verifyManifestContentCompatibility(manifest);
  assert.equal(falseInitial.ok, false);
  assert.equal(falseInitial.code, "manifest-compatibility-invalid");

  manifest.compatibility = await compatibilityFor(manifest);
  manifest.compatibility.previousContentContractHash = "a".repeat(64);
  const falseCompatible = await verifyManifestContentCompatibility(manifest);
  assert.equal(falseCompatible.ok, false);
  assert.equal(falseCompatible.code, "manifest-compatibility-invalid");

  manifest.compatibility = await compatibilityFor(manifest);
  manifest.compatibility.classification = "content-incompatible";
  manifest.compatibility.previousContentContractHash = "a".repeat(64);
  manifest.compatibility.contentImpact = "generated-content";
  assert.equal((await verifyManifestContentCompatibility(manifest)).ok, true);

  manifest.compatibility = await compatibilityFor(manifest);
  manifest.compatibility.contentContractHash = "0".repeat(64);
  manifest.compatibility.previousContentContractHash = "0".repeat(64);
  const mismatch = await verifyManifestContentCompatibility(manifest);
  assert.equal(mismatch.ok, false);
  assert.equal(mismatch.code, "manifest-content-contract-hash-mismatch");
});

test("the shared signature chain rejects a signed but untruthful content hash", async () => {
  const now = Math.floor(Date.now() / 1_000);
  const root = await crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"]);
  const release = await crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"]);
  const delegation = await signReleaseKeyDelegation(
    release.publicKey,
    root.privateKey,
    {
      rootKeyId: "hch-root-test",
      releaseKeyId: "hch-release-test",
      sequence: 1,
      created: now - 10,
      notBefore: now - 10,
      expires: now + 3_600,
    },
  );
  const manifest = manifestFixture();
  manifest.compatibility = await compatibilityFor(manifest);
  manifest.compatibility.contentContractHash = "f".repeat(64);
  manifest.compatibility.previousContentContractHash = "f".repeat(64);
  const envelope = await signManifestEnvelope(manifest, release.privateKey, {
    keyId: "hch-release-test",
    created: now,
    expires: now + 1_800,
  });

  const result = await verifyManifestWithDelegation(
    envelope,
    delegation,
    root.publicKey,
    { expectedKeyId: "hch-root-test", now },
  );
  assert.equal(result.ok, false);
  assert.equal(result.code, "manifest-content-contract-hash-mismatch");
});

async function compatibilityFor(manifest) {
  const contentContractHash = await manifestContentContractHash(manifest);
  return {
    classification: "compatible",
    contentContractHash,
    previousContentContractHash: contentContractHash,
    minimumWorkerVersion: "2.2.0",
    testedThroughWorkerVersion: "3.1.0",
    contentImpact: "none",
  };
}

function manifestFixture() {
  return {
    bootstrapVersion: "2.3.0",
    sequence: 7,
    issuedAt: "2030-01-01T00:00:00.000Z",
    expiresAt: "2030-02-01T00:00:00.000Z",
    runtime: {
      workerVersion: "3.1.0",
      supportedPlatforms: ["linux", "macos", "windows"],
    },
    engine: {
      provider: "vps-local",
      adapter: "ollama-chat",
      adapterVersion: "1.0.0",
      model: "qwen2.5:1.5b-instruct",
      modelDigest: "b".repeat(64),
      protocol: "ollama-chat",
    },
    generation: {
      temperature: 0.2,
      contextWindow: 8_192,
      maxOutputTokens: 2_400,
    },
    capacityPolicy: {
      defaultNodeCeiling: 16,
    },
    adaptiveWorkPolicy: {
      algorithmVersion: "hch-adaptive-work-v1",
      processingWindowSeconds: 2_700,
    },
    editorial: {
      pipelineVersion: "editorial-v1",
      policyHash: "c".repeat(64),
      promptConfigHash: "d".repeat(64),
    },
    artifacts: [
      {
        name: "editorial-policy.json",
        sha256: "e".repeat(64),
      },
    ],
  };
}

// Independent copy of the orchestrator's stable JSON projection used only as
// a protocol parity oracle for this test.
function orchestratorStableJson(value) {
  if (Array.isArray(value)) {
    return `[${value.map(orchestratorStableJson).join(",")}]`;
  }
  if (value && typeof value === "object") {
    return `{${Object.keys(value).sort().map((key) =>
      `${JSON.stringify(key)}:${orchestratorStableJson(value[key])}`
    ).join(",")}}`;
  }
  return JSON.stringify(value) ?? "null";
}
