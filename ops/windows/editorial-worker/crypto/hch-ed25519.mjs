#!/usr/bin/env node

import {
  createHash,
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  sign,
  verify,
} from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import {
  canonicalizeJson,
  manifestContentContractHash,
  verifyManifestWithDelegation,
  workerPublicKeyFingerprint,
} from "../../../../lib/editorial-worker-signatures.mjs";

const [command, ...rawArguments] = process.argv.slice(2);
const argumentsByName = parseArguments(rawArguments);

try {
  switch (command) {
    case "generate":
      generateIdentity(required("private"), required("public"));
      break;
    case "fingerprint":
      print({ keyId: fingerprint(readPublicKey(required("public"))) });
      break;
    case "sign":
      signBytes(required("private"), required("input"));
      break;
    case "verify":
      verifyBytes(required("public"), required("input"), required("signature"));
      break;
    case "canonicalize":
      canonicalizeFile(required("input"), required("output"));
      break;
    case "verify-chain":
      await verifyManifestChain(
        required("root"),
        required("envelope"),
        required("output"),
        Number(argumentsByName.get("clock-skew") ?? 60),
        argumentsByName.get("allow-expired-hash") ?? null,
      );
      break;
    default:
      throw new Error("usage: hch-ed25519.mjs <generate|fingerprint|sign|verify|canonicalize|verify-chain> [options]");
  }
} catch (error) {
  process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
  process.exitCode = 1;
}

function generateIdentity(privatePath, publicPath) {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const privatePem = privateKey.export({ type: "pkcs8", format: "pem" });
  const publicPem = publicKey.export({ type: "spki", format: "pem" });
  writeFileSync(privatePath, privatePem, { encoding: "utf8", flag: "wx", mode: 0o600 });
  try {
    writeFileSync(publicPath, publicPem, { encoding: "utf8", flag: "wx", mode: 0o644 });
  } catch (error) {
    // The PowerShell caller owns cleanup and ACL application. Never print key material.
    throw error;
  }
  print({
    algorithm: "Ed25519",
    privateKeyFormat: "PKCS8-PEM",
    publicKeyFormat: "SPKI-PEM",
    keyId: fingerprint(publicKey),
  });
}

function signBytes(privatePath, inputPath) {
  const privateKey = createPrivateKey(readFileSync(privatePath));
  assertEd25519(privateKey);
  const signature = sign(null, readFileSync(inputPath), privateKey);
  print({ algorithm: "Ed25519", format: "raw", value: signature.toString("base64") });
}

function verifyBytes(publicPath, inputPath, signatureValue) {
  const publicKey = readPublicKey(publicPath);
  const signature = Buffer.from(signatureValue, "base64");
  if (signature.length !== 64) throw new Error("invalid-ed25519-signature-length");
  const valid = verify(null, readFileSync(inputPath), publicKey, signature);
  print({ algorithm: "Ed25519", format: "raw", valid });
  if (!valid) process.exitCode = 2;
}

function canonicalizeFile(inputPath, outputPath) {
  const value = JSON.parse(readFileSync(inputPath, "utf8"));
  writeFileSync(outputPath, canonicalizeJson(value), { encoding: "utf8", flag: "wx", mode: 0o600 });
  print({ canonicalized: true });
}

async function verifyManifestChain(
  rootPath,
  envelopePath,
  outputPath,
  clockSkewSeconds,
  allowExpiredHash,
) {
  if (!Number.isSafeInteger(clockSkewSeconds) || clockSkewSeconds < 0 || clockSkewSeconds > 300) {
    throw new Error("invalid-clock-skew");
  }
  const outer = JSON.parse(readFileSync(envelopePath, "utf8"));
  if (!outer || typeof outer !== "object" || !outer.manifest || !outer.delegation) {
    throw new Error("manifest-envelope-invalid");
  }
  const rootPem = readFileSync(rootPath, "utf8");
  const rootKey = readPublicKey(rootPath);
  const rootKeyId = String(outer.rootKeyId ?? "");
  if (!rootKeyId) throw new Error("root-key-id-missing");
  const rootFingerprint = await workerPublicKeyFingerprint(rootPem);
  if (outer.rootPublicKeyFingerprint !== rootFingerprint) {
    throw new Error("pinned-root-fingerprint-mismatch");
  }
  const verified = await verifyManifestWithDelegation(
    outer.manifest,
    outer.delegation,
    rootPem,
    {
    expectedReleaseKeyId: undefined,
    clockSkewSeconds,
    allowExpired: allowExpiredHash !== null,
  });
  if (!verified.ok) throw new Error(`manifest-chain-invalid:${verified.code}`);
  if (verified.delegationProtectedHeader.kid !== rootKeyId) {
    throw new Error("root-key-id-mismatch");
  }
  const delegated = verified.delegation;
  const payload = verified.payload;
  const delegationHash = createHash("sha256")
    .update(canonicalizeJson(outer.delegation))
    .digest("hex");
  if (payload?.schemaVersion !== "2.0") throw new Error("manifest-schema-unsupported");
  const expiryBoundary = Date.now() - clockSkewSeconds * 1000;
  const payloadExpired = Date.parse(payload.expiresAt) <= expiryBoundary;
  const chainExpired = payloadExpired ||
    verified.protectedHeader.exp * 1000 <= expiryBoundary ||
    delegated.expires * 1000 <= expiryBoundary;
  if (payloadExpired && allowExpiredHash === null) {
    throw new Error("manifest-payload-expired");
  }
  const { hash, ...unsignedPayload } = payload;
  const hashAlgorithm = payload.hashAlgorithm;
  if (hashAlgorithm !== "sha256" || !/^[a-f0-9]{64}$/.test(String(hash ?? ""))) {
    throw new Error("manifest-payload-hash-invalid");
  }
  const calculated = createHash("sha256").update(canonicalizeJson(unsignedPayload)).digest("hex");
  // Release 3.0 manifests produced before the hash contract was aligned did
  // not include hashAlgorithm in the inner digest. Their signed envelope is
  // still authoritative, so accept that legacy digest during the transition.
  const { hashAlgorithm: _legacyAlgorithm, ...legacyUnsignedPayload } = unsignedPayload;
  const legacyCalculated = createHash("sha256")
    .update(canonicalizeJson(legacyUnsignedPayload)).digest("hex");
  if (calculated !== hash && legacyCalculated !== hash) {
    throw new Error("manifest-payload-hash-mismatch");
  }
  if (chainExpired && String(hash).toLowerCase() !== String(allowExpiredHash).toLowerCase()) {
    throw new Error("manifest-expired-update-refused");
  }
  const contentContractHash = await manifestContentContractHash(payload);
  writeFileSync(outputPath, canonicalizeJson(payload), { encoding: "utf8", flag: "wx", mode: 0o600 });
  print({
    valid: true,
    delegationHash,
    delegationSequence: delegated.sequence,
    manifestHash: hash,
    manifestSequence: payload.sequence,
    contentContractHash,
    expiredFallback: chainExpired,
    releaseKeyId: delegated.releaseKeyId,
    rootKeyId,
    rootFingerprint,
  });
}

function fingerprint(key) {
  const der = key.export({ type: "spki", format: "der" });
  return `SHA256:${createHash("sha256").update(der).digest("base64url")}`;
}

function readPublicKey(path) {
  const key = createPublicKey(readFileSync(path));
  assertEd25519(key);
  return key;
}

function assertEd25519(key) {
  if (key.asymmetricKeyType !== "ed25519") throw new Error("key-is-not-ed25519");
}

function parseArguments(values) {
  const parsed = new Map();
  for (let index = 0; index < values.length; index += 2) {
    const name = values[index];
    if (!name?.startsWith("--") || values[index + 1] === undefined) {
      throw new Error(`invalid-argument:${name ?? "missing"}`);
    }
    parsed.set(name.slice(2), values[index + 1]);
  }
  return parsed;
}

function required(name) {
  const value = argumentsByName.get(name);
  if (!value) throw new Error(`missing-argument:${name}`);
  return value;
}

function print(value) {
  process.stdout.write(`${JSON.stringify(value)}\n`);
}
