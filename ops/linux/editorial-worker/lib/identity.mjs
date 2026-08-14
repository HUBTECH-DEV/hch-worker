import { lstat } from "node:fs/promises";

import {
  signWorkerRequest,
  workerPublicKeyFingerprint,
} from "../crypto.mjs";
import {
  atomicWriteFile,
  atomicWriteJson,
  readOptionalJson,
  readPrivateText,
  readSafeText,
} from "./storage.mjs";
import { WorkerKitError } from "./errors.mjs";

const PRIVATE_PATH = "identity/worker-private.pk8.pem";
const PUBLIC_PATH = "identity/worker-public.spki.pem";
const IDENTITY_PATH = "identity/identity.json";

export async function ensureWorkerIdentity(config, stateRoot) {
  const privateAbsolute = `${stateRoot}/identity/worker-private.pk8.pem`;
  const publicAbsolute = `${stateRoot}/identity/worker-public.spki.pem`;
  const [privateExists, publicExists] = await Promise.all([
    exists(privateAbsolute),
    exists(publicAbsolute),
  ]);
  if (privateExists !== publicExists) {
    throw new WorkerKitError(
      "identity-incomplete",
      "Worker identity is incomplete; refusing to replace either key.",
    );
  }
  if (!privateExists) await generateIdentity(config, stateRoot);

  const [privateKeyPem, publicKeyPem, metadata] = await Promise.all([
    readPrivateText(privateAbsolute),
    readSafeText(publicAbsolute),
    readOptionalJson(stateRoot, IDENTITY_PATH),
  ]);
  const fingerprint = await workerPublicKeyFingerprint(publicKeyPem);
  if (
    !metadata ||
    metadata.schemaVersion !== 1 ||
    metadata.nodeId !== config.nodeId ||
    metadata.keyId !== config.keyId ||
    metadata.fingerprint !== fingerprint
  ) {
    throw new WorkerKitError(
      "identity-metadata-mismatch",
      "Worker identity metadata does not match the configured node and public key.",
    );
  }
  await proveKeyPair(privateKeyPem, publicKeyPem, config);
  return {
    nodeId: config.nodeId,
    keyId: config.keyId,
    fingerprint,
    privateKeyPem,
    publicKeyPem,
  };
}

async function generateIdentity(config, stateRoot) {
  const pair = await crypto.subtle.generateKey(
    { name: "Ed25519" },
    true,
    ["sign", "verify"],
  );
  const [pkcs8, spki] = await Promise.all([
    crypto.subtle.exportKey("pkcs8", pair.privateKey),
    crypto.subtle.exportKey("spki", pair.publicKey),
  ]);
  const privateKeyPem = toPem(pkcs8, "PRIVATE KEY");
  const publicKeyPem = toPem(spki, "PUBLIC KEY");
  const fingerprint = await workerPublicKeyFingerprint(publicKeyPem);
  await atomicWriteFile(stateRoot, PRIVATE_PATH, privateKeyPem, 0o600);
  await atomicWriteFile(stateRoot, PUBLIC_PATH, publicKeyPem, 0o644);
  await atomicWriteJson(stateRoot, IDENTITY_PATH, {
    schemaVersion: 1,
    nodeId: config.nodeId,
    keyId: config.keyId,
    algorithm: "Ed25519",
    fingerprint,
    createdAt: new Date().toISOString(),
  });
}

async function proveKeyPair(privateKeyPem, publicKeyPem, config) {
  const now = Math.floor(Date.now() / 1000);
  const body = "{}";
  const signed = await signWorkerRequest({
    method: "POST",
    authority: "identity.local",
    path: "/proof",
    contentType: "application/json",
    body,
    nodeId: config.nodeId,
    keyId: config.keyId,
    requestId: `identity-${crypto.randomUUID()}`,
    created: now,
    expires: now + 60,
    nonce: `identity-${crypto.randomUUID()}`,
  }, privateKeyPem);
  const publicKey = await crypto.subtle.importKey(
    "spki",
    pemBytes(publicKeyPem, "PUBLIC KEY"),
    { name: "Ed25519" },
    false,
    ["verify"],
  );
  const signatureText = signed.headers.Signature;
  const match = /^hch=:(.+):$/.exec(signatureText);
  const valid = match && await crypto.subtle.verify(
    "Ed25519",
    publicKey,
    Buffer.from(match[1], "base64"),
    new TextEncoder().encode(signed.signatureBase),
  );
  if (!valid) {
    throw new WorkerKitError(
      "identity-keypair-mismatch",
      "Worker private and public keys do not form a valid Ed25519 pair.",
    );
  }
}

function toPem(der, label) {
  const base64 = Buffer.from(der).toString("base64");
  const lines = base64.match(/.{1,64}/g)?.join("\n") ?? "";
  return `-----BEGIN ${label}-----\n${lines}\n-----END ${label}-----\n`;
}

function pemBytes(pem, label) {
  const expression = new RegExp(
    `^-----BEGIN ${label}-----\\s+([A-Za-z0-9+/=\\s]+?)\\s+-----END ${label}-----$`,
  );
  const match = expression.exec(pem.trim());
  if (!match) throw new TypeError(`Invalid ${label} PEM.`);
  return Buffer.from(match[1].replace(/\s/g, ""), "base64");
}

async function exists(path) {
  try {
    await lstat(path);
    return true;
  } catch (error) {
    if (error?.code === "ENOENT") return false;
    throw error;
  }
}
