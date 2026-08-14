const encoder = new TextEncoder();
const decoder = new TextDecoder("utf-8", { fatal: true });

export const MANIFEST_SIGNATURE_TYPE = "hch-editorial-manifest/v2";
export const RELEASE_DELEGATION_SIGNATURE_TYPE =
  "hch-editorial-release-key-delegation/v1";
export const WORKER_REQUEST_SIGNATURE_TAG =
  "hch-editorial-worker-request/v1";
export const WORKER_REQUEST_SIGNATURE_LABEL = "hch";

const MANIFEST_PROTECTED_TYPE = "application/hch+jws+jcs";
const REQUEST_COMPONENTS = Object.freeze([
  "@method",
  "@authority",
  "@path",
  "content-digest",
  "content-type",
  "x-hch-node-id",
  "x-hch-key-id",
  "x-hch-request-id",
  "x-hch-created",
  "x-hch-expires",
  "x-hch-nonce",
]);

/**
 * Canonicalizes the I-JSON subset accepted by HCH using the serialization and
 * UTF-16 property ordering required by RFC 8785 (JCS).
 */
export function canonicalizeJson(value) {
  return canonicalize(value, new Set());
}

/** Returns an RFC 9530 sha-256 Content-Digest field value. */
export async function createContentDigest(body) {
  const digest = await subtle().digest("SHA-256", bodyBytes(body));
  return `sha-256=:${bytesToBase64(new Uint8Array(digest))}:`;
}

/**
 * Returns a stable fingerprint over the Ed25519 SubjectPublicKeyInfo bytes.
 * The output follows the familiar `SHA256:<base64url>` presentation.
 */
export async function workerPublicKeyFingerprint(publicKey) {
  const key = await importEd25519PublicKey(publicKey);
  let spki;
  try {
    spki = await subtle().exportKey("spki", key);
  } catch (error) {
    throw new TypeError(
      "The Ed25519 public key must be extractable to calculate its fingerprint.",
      { cause: error },
    );
  }
  const digest = await subtle().digest("SHA-256", spki);
  return `SHA256:${bytesToBase64Url(new Uint8Array(digest))}`;
}

/**
 * Creates a flattened, JWS-like envelope. The Ed25519 signature is calculated
 * over `base64url(JCS(protected)).base64url(JCS(manifest))`.
 */
export async function signManifestEnvelope(manifest, privateKey, options) {
  const keyId = requiredIdentifier(options?.keyId, "keyId", 256);
  const created = epochSeconds(options?.created, "created");
  const expires = epochSeconds(options?.expires, "expires");
  requireIncreasingWindow(created, expires);

  const protectedHeader = {
    alg: "EdDSA",
    c14n: "RFC8785",
    cty: "application/json",
    exp: expires,
    hch: MANIFEST_SIGNATURE_TYPE,
    iat: created,
    kid: keyId,
    role: "release",
    typ: MANIFEST_PROTECTED_TYPE,
  };
  return signJcsEnvelope(protectedHeader, manifest, privateKey);
}

/**
 * Verifies a manifest envelope and its validity interval. It never trusts an
 * unsigned copy of the manifest. Failure is returned as a discriminated
 * result instead of throwing on attacker-controlled input.
 */
export async function verifyManifestEnvelope(envelope, publicKey, options = {}) {
  return verifyJcsEnvelope(envelope, publicKey, {
    ...options,
    expectedRole: "release",
    expectedType: MANIFEST_SIGNATURE_TYPE,
    maxLifetimeSeconds: options.maxLifetimeSeconds ?? 31 * 24 * 60 * 60,
  });
}

/**
 * Signs an Ed25519 release-key delegation using the offline root key. Only the
 * public release key is embedded in the signed payload.
 */
export async function signReleaseKeyDelegation(
  releasePublicKey,
  rootPrivateKey,
  options,
) {
  const rootKeyId = requiredIdentifier(options?.rootKeyId, "rootKeyId", 256);
  const releaseKeyId = requiredIdentifier(
    options?.releaseKeyId,
    "releaseKeyId",
    256,
  );
  const created = epochSeconds(options?.created, "created");
  const notBefore = epochSeconds(options?.notBefore ?? created, "notBefore");
  const expires = epochSeconds(options?.expires, "expires");
  const sequence = positiveSafeInteger(options?.sequence ?? 1, "sequence");
  requireIncreasingWindow(created, expires);
  if (notBefore < created || notBefore >= expires) {
    throw new TypeError("notBefore must be at or after created and before expires.");
  }

  const publicJwk = await normalizedPublicJwk(releasePublicKey);
  const fingerprint = await workerPublicKeyFingerprint(publicJwk);
  const payload = {
    expires,
    fingerprint,
    notBefore,
    permissions: ["sign-editorial-manifest"],
    publicKey: publicJwk,
    releaseKeyId,
    sequence,
    type: RELEASE_DELEGATION_SIGNATURE_TYPE,
    version: 1,
  };
  const protectedHeader = {
    alg: "EdDSA",
    c14n: "RFC8785",
    cty: "application/json",
    exp: expires,
    hch: RELEASE_DELEGATION_SIGNATURE_TYPE,
    iat: created,
    kid: rootKeyId,
    role: "root",
    typ: MANIFEST_PROTECTED_TYPE,
  };
  return signJcsEnvelope(protectedHeader, payload, rootPrivateKey);
}

/** Verifies a root-signed release-key delegation. */
export async function verifyReleaseKeyDelegation(
  envelope,
  rootPublicKey,
  options = {},
) {
  const verified = await verifyJcsEnvelope(envelope, rootPublicKey, {
    ...options,
    expectedRole: "root",
    expectedType: RELEASE_DELEGATION_SIGNATURE_TYPE,
    maxLifetimeSeconds: options.maxLifetimeSeconds ?? 366 * 24 * 60 * 60,
  });
  if (!verified.ok) return verified;

  try {
    const delegation = validateDelegationPayload(verified.payload);
    if (
      options.expectedReleaseKeyId &&
      !sameText(delegation.releaseKeyId, options.expectedReleaseKeyId)
    ) {
      return failure("release-key-id-mismatch", "Unexpected release key id.");
    }
    const fingerprint = await workerPublicKeyFingerprint(delegation.publicKey);
    if (!sameText(fingerprint, delegation.fingerprint)) {
      return failure(
        "release-key-fingerprint-mismatch",
        "The delegated release key fingerprint does not match its public key.",
      );
    }
    const now = nowSeconds(options.now);
    const skew = nonNegativeInteger(options.clockSkewSeconds ?? 30, "clockSkewSeconds");
    if (delegation.notBefore > now + skew) {
      return failure("delegation-not-yet-valid", "The release delegation is not active yet.");
    }
    if (delegation.expires < now - skew) {
      return failure("delegation-expired", "The release delegation has expired.");
    }
    return {
      ...verified,
      delegation,
      releaseKeyId: delegation.releaseKeyId,
      releasePublicKey: delegation.publicKey,
    };
  } catch (error) {
    return failure("malformed-delegation", safeErrorMessage(error));
  }
}

/**
 * Verifies the complete root -> release -> manifest chain. The manifest must
 * have been signed while the delegated release key was valid.
 */
export async function verifyManifestWithDelegation(
  manifestEnvelope,
  delegationEnvelope,
  rootPublicKey,
  options = {},
) {
  const delegationResult = await verifyReleaseKeyDelegation(
    delegationEnvelope,
    rootPublicKey,
    options,
  );
  if (!delegationResult.ok) return delegationResult;

  const manifestResult = await verifyManifestEnvelope(
    manifestEnvelope,
    delegationResult.releasePublicKey,
    {
      ...options,
      expectedKeyId: delegationResult.releaseKeyId,
    },
  );
  if (!manifestResult.ok) return manifestResult;

  const delegation = delegationResult.delegation;
  const manifestCreated = manifestResult.protectedHeader.iat;
  const manifestExpires = manifestResult.protectedHeader.exp;
  if (
    manifestCreated < delegation.notBefore ||
    manifestCreated > delegation.expires ||
    manifestExpires > delegation.expires
  ) {
    return failure(
      "manifest-outside-delegation-window",
      "The manifest validity is outside the release key delegation window.",
    );
  }
  if (!delegation.permissions.includes("sign-editorial-manifest")) {
    return failure(
      "delegation-permission-denied",
      "The release key is not authorized to sign editorial manifests.",
    );
  }
  return {
    ...manifestResult,
    delegation,
    delegationProtectedHeader: delegationResult.protectedHeader,
  };
}

/**
 * Produces the fixed HCH HTTP Message Signatures profile. The returned headers
 * are ready to merge into a request. The private key never leaves the caller.
 */
export async function signWorkerRequest(request, privateKey) {
  const normalized = await normalizeSigningRequest(request);
  const signatureParams = requestSignatureParams(normalized);
  const signatureBase = requestSignatureBase(normalized, signatureParams);
  const key = await importEd25519PrivateKey(privateKey);
  const signature = new Uint8Array(
    await subtle().sign("Ed25519", key, encoder.encode(signatureBase)),
  );

  return {
    algorithm: "Ed25519",
    contentDigest: normalized.contentDigest,
    headers: {
      "Content-Digest": normalized.contentDigest,
      "Content-Type": normalized.contentType,
      "Signature-Input": `${WORKER_REQUEST_SIGNATURE_LABEL}=${signatureParams}`,
      Signature: `${WORKER_REQUEST_SIGNATURE_LABEL}=:${bytesToBase64(signature)}:`,
      "X-HCH-Created": String(normalized.created),
      "X-HCH-Expires": String(normalized.expires),
      "X-HCH-Key-Id": normalized.keyId,
      "X-HCH-Node-Id": normalized.nodeId,
      "X-HCH-Nonce": normalized.nonce,
      "X-HCH-Request-Id": normalized.requestId,
    },
    signatureBase,
  };
}

/**
 * Verifies an incoming worker request. `method`, `authority`, and `path` must
 * come from the actual HTTP request, not from client-controlled metadata.
 * Replay storage is supplied by the caller through `consumeReplayToken`.
 */
export async function verifyWorkerRequestSignature(
  request,
  publicKey,
  options = {},
) {
  try {
    const headers = request?.headers;
    const supplied = {
      authority: normalizeAuthority(request?.authority),
      contentDigest: requiredHeader(headers, "content-digest"),
      contentType: normalizeHeaderValue(requiredHeader(headers, "content-type")),
      created: epochSeconds(requiredHeader(headers, "x-hch-created"), "x-hch-created"),
      expires: epochSeconds(requiredHeader(headers, "x-hch-expires"), "x-hch-expires"),
      keyId: requiredIdentifier(
        requiredHeader(headers, "x-hch-key-id"),
        "x-hch-key-id",
        256,
      ),
      method: normalizeMethod(request?.method),
      nodeId: requiredIdentifier(
        requiredHeader(headers, "x-hch-node-id"),
        "x-hch-node-id",
        128,
      ),
      nonce: requiredIdentifier(
        requiredHeader(headers, "x-hch-nonce"),
        "x-hch-nonce",
        256,
        16,
      ),
      path: normalizePath(request?.path),
      requestId: requiredIdentifier(
        requiredHeader(headers, "x-hch-request-id"),
        "x-hch-request-id",
        128,
        8,
      ),
    };
    requireIncreasingWindow(supplied.created, supplied.expires);

    if (options.expectedNodeId && !sameText(supplied.nodeId, options.expectedNodeId)) {
      return failure("node-id-mismatch", "Unexpected worker node id.");
    }
    if (options.expectedKeyId && !sameText(supplied.keyId, options.expectedKeyId)) {
      return failure("key-id-mismatch", "Unexpected worker key id.");
    }
    if (options.expectedNonce && !sameText(supplied.nonce, options.expectedNonce)) {
      return failure("nonce-mismatch", "The challenge nonce does not match.");
    }

    const timeFailure = validateTimeWindow(supplied.created, supplied.expires, {
      ...options,
      maxLifetimeSeconds: options.maxLifetimeSeconds ?? 5 * 60,
    });
    if (timeFailure) return timeFailure;

    const calculatedDigest = await createContentDigest(request?.body);
    if (!sameText(supplied.contentDigest, calculatedDigest)) {
      return failure(
        "content-digest-mismatch",
        "Content-Digest does not match the received request body.",
      );
    }

    const signatureParams = requestSignatureParams(supplied);
    const expectedSignatureInput =
      `${WORKER_REQUEST_SIGNATURE_LABEL}=${signatureParams}`;
    const suppliedSignatureInput = normalizeHeaderValue(
      requiredHeader(headers, "signature-input"),
    );
    if (!sameText(suppliedSignatureInput, expectedSignatureInput)) {
      return failure(
        "signature-input-mismatch",
        "Signature-Input does not match the required HCH profile.",
      );
    }

    const signature = parseSignatureHeader(requiredHeader(headers, "signature"));
    const signatureBase = requestSignatureBase(supplied, signatureParams);
    const key = await importEd25519PublicKey(publicKey);
    const valid = await subtle().verify(
      "Ed25519",
      key,
      signature,
      encoder.encode(signatureBase),
    );
    if (!valid) {
      return failure("invalid-signature", "The worker request signature is invalid.");
    }

    if (options.consumeReplayToken) {
      const accepted = await options.consumeReplayToken({
        created: supplied.created,
        expires: supplied.expires,
        keyId: supplied.keyId,
        nodeId: supplied.nodeId,
        nonce: supplied.nonce,
        requestId: supplied.requestId,
      });
      if (!accepted) {
        return failure(
          "replay-detected",
          "The request id or nonce has already been consumed.",
        );
      }
    }

    return {
      ok: true,
      algorithm: "Ed25519",
      contentDigest: supplied.contentDigest,
      created: supplied.created,
      expires: supplied.expires,
      keyId: supplied.keyId,
      nodeId: supplied.nodeId,
      nonce: supplied.nonce,
      requestId: supplied.requestId,
      signatureBase,
    };
  } catch (error) {
    return failure("malformed-request-signature", safeErrorMessage(error));
  }
}

async function signJcsEnvelope(protectedHeader, payload, privateKey) {
  const protectedValue = bytesToBase64Url(
    encoder.encode(canonicalizeJson(protectedHeader)),
  );
  const payloadValue = bytesToBase64Url(encoder.encode(canonicalizeJson(payload)));
  const signingInput = `${protectedValue}.${payloadValue}`;
  const key = await importEd25519PrivateKey(privateKey);
  const signature = await subtle().sign(
    "Ed25519",
    key,
    encoder.encode(signingInput),
  );
  return {
    payload: payloadValue,
    protected: protectedValue,
    signature: bytesToBase64Url(new Uint8Array(signature)),
  };
}

async function verifyJcsEnvelope(envelope, publicKey, options) {
  try {
    if (!isPlainObject(envelope)) {
      return failure("malformed-envelope", "The signed envelope must be an object.");
    }
    const protectedValue = requiredBase64Url(envelope.protected, "protected");
    const payloadValue = requiredBase64Url(envelope.payload, "payload");
    const signatureValue = requiredBase64Url(envelope.signature, "signature");
    const protectedHeader = parseCanonicalJson(protectedValue, "protected");
    const payload = parseCanonicalJson(payloadValue, "payload");
    validateProtectedHeader(protectedHeader, options);

    if (
      options.expectedKeyId &&
      !sameText(protectedHeader.kid, options.expectedKeyId)
    ) {
      return failure("key-id-mismatch", "Unexpected signing key id.");
    }
    const timeFailure = validateTimeWindow(
      protectedHeader.iat,
      protectedHeader.exp,
      options,
    );
    if (timeFailure) return timeFailure;

    const key = await importEd25519PublicKey(publicKey);
    const valid = await subtle().verify(
      "Ed25519",
      key,
      base64UrlToBytes(signatureValue),
      encoder.encode(`${protectedValue}.${payloadValue}`),
    );
    if (!valid) {
      return failure("invalid-signature", "The envelope signature is invalid.");
    }

    const payloadDigest = await subtle().digest(
      "SHA-256",
      encoder.encode(canonicalizeJson(payload)),
    );
    return {
      ok: true,
      keyId: protectedHeader.kid,
      payload,
      payloadHash: `sha256:${bytesToBase64Url(new Uint8Array(payloadDigest))}`,
      protectedHeader,
    };
  } catch (error) {
    return failure("malformed-envelope", safeErrorMessage(error));
  }
}

function validateProtectedHeader(header, options) {
  if (!isPlainObject(header)) throw new TypeError("Protected header must be an object.");
  if (header.alg !== "EdDSA") throw new TypeError("Only EdDSA envelopes are accepted.");
  if (header.c14n !== "RFC8785") throw new TypeError("Only RFC8785 JCS is accepted.");
  if (header.cty !== "application/json") throw new TypeError("Unexpected payload type.");
  if (header.typ !== MANIFEST_PROTECTED_TYPE) throw new TypeError("Unexpected envelope type.");
  if (header.hch !== options.expectedType) throw new TypeError("Unexpected HCH signature type.");
  if (header.role !== options.expectedRole) throw new TypeError("Unexpected signing-key role.");
  requiredIdentifier(header.kid, "kid", 256);
  epochSeconds(header.iat, "iat");
  epochSeconds(header.exp, "exp");
  requireIncreasingWindow(header.iat, header.exp);
}

function validateDelegationPayload(payload) {
  if (!isPlainObject(payload)) throw new TypeError("Delegation payload must be an object.");
  if (payload.type !== RELEASE_DELEGATION_SIGNATURE_TYPE || payload.version !== 1) {
    throw new TypeError("Unsupported release-key delegation payload.");
  }
  const publicKey = normalizePublicJwkValue(payload.publicKey);
  const permissions = Array.isArray(payload.permissions)
    ? payload.permissions.map((permission) => requiredIdentifier(permission, "permission", 128))
    : null;
  if (!permissions) throw new TypeError("Delegation permissions must be an array.");
  return {
    expires: epochSeconds(payload.expires, "delegation expires"),
    fingerprint: requiredIdentifier(payload.fingerprint, "fingerprint", 256),
    notBefore: epochSeconds(payload.notBefore, "notBefore"),
    permissions,
    publicKey,
    releaseKeyId: requiredIdentifier(payload.releaseKeyId, "releaseKeyId", 256),
    sequence: positiveSafeInteger(payload.sequence, "sequence"),
    type: payload.type,
    version: payload.version,
  };
}

async function normalizeSigningRequest(request) {
  const created = epochSeconds(request?.created, "created");
  const expires = epochSeconds(request?.expires, "expires");
  requireIncreasingWindow(created, expires);
  return {
    authority: normalizeAuthority(request?.authority),
    contentDigest: await createContentDigest(request?.body),
    contentType: requiredHeaderText(request?.contentType, "contentType", 256),
    created,
    expires,
    keyId: requiredIdentifier(request?.keyId, "keyId", 256),
    method: normalizeMethod(request?.method),
    nodeId: requiredIdentifier(request?.nodeId, "nodeId", 128),
    nonce: requiredIdentifier(request?.nonce, "nonce", 256, 16),
    path: normalizePath(request?.path),
    requestId: requiredIdentifier(request?.requestId, "requestId", 128, 8),
  };
}

function requestSignatureParams(request) {
  const covered = REQUEST_COMPONENTS.map((component) => `"${component}"`).join(" ");
  return `(${covered});created=${request.created};expires=${request.expires};keyid=${structuredFieldString(request.keyId)};alg="ed25519";tag="${WORKER_REQUEST_SIGNATURE_TAG}"`;
}

function requestSignatureBase(request, signatureParams) {
  const values = {
    "@authority": request.authority,
    "@method": request.method,
    "@path": request.path,
    "content-digest": request.contentDigest,
    "content-type": request.contentType,
    "x-hch-created": String(request.created),
    "x-hch-expires": String(request.expires),
    "x-hch-key-id": request.keyId,
    "x-hch-node-id": request.nodeId,
    "x-hch-nonce": request.nonce,
    "x-hch-request-id": request.requestId,
  };
  return [
    ...REQUEST_COMPONENTS.map(
      (component) => `"${component}": ${values[component]}`,
    ),
    `"@signature-params": ${signatureParams}`,
  ].join("\n");
}

function parseSignatureHeader(value) {
  const normalized = normalizeHeaderValue(value);
  const match = /^hch=:([A-Za-z0-9+/]+={0,2}):$/.exec(normalized);
  if (!match) throw new TypeError("Malformed HCH Signature header.");
  const bytes = base64ToBytes(match[1]);
  if (bytes.length !== 64) throw new TypeError("An Ed25519 signature must be 64 bytes.");
  return bytes;
}

function validateTimeWindow(created, expires, options) {
  const now = nowSeconds(options.now);
  const skew = nonNegativeInteger(options.clockSkewSeconds ?? 30, "clockSkewSeconds");
  const maxLifetime = positiveSafeInteger(
    options.maxLifetimeSeconds,
    "maxLifetimeSeconds",
  );
  if (created > now + skew) {
    return failure("not-yet-valid", "The signature creation time is in the future.");
  }
  if (expires < now - skew) {
    return failure("expired", "The signature has expired.");
  }
  if (expires - created > maxLifetime) {
    return failure("lifetime-too-long", "The signature validity interval is too long.");
  }
  return null;
}

function parseCanonicalJson(value, name) {
  const bytes = base64UrlToBytes(value);
  const text = decoder.decode(bytes);
  const parsed = JSON.parse(text);
  if (canonicalizeJson(parsed) !== text) {
    throw new TypeError(`${name} is not canonical RFC8785 JSON.`);
  }
  return parsed;
}

async function normalizedPublicJwk(publicKey) {
  const key = await importEd25519PublicKey(publicKey);
  let exported;
  try {
    exported = await subtle().exportKey("jwk", key);
  } catch (error) {
    throw new TypeError("The release public key must be extractable.", { cause: error });
  }
  return normalizePublicJwkValue(exported);
}

function normalizePublicJwkValue(value) {
  if (!isPlainObject(value)) throw new TypeError("Ed25519 public JWK must be an object.");
  if (value.kty !== "OKP" || value.crv !== "Ed25519") {
    throw new TypeError("Only an Ed25519 OKP public JWK is accepted.");
  }
  const x = requiredBase64Url(value.x, "JWK x");
  if (base64UrlToBytes(x).length !== 32) {
    throw new TypeError("An Ed25519 public JWK x value must be 32 bytes.");
  }
  return { crv: "Ed25519", kty: "OKP", x };
}

async function importEd25519PublicKey(value) {
  if (isCryptoKey(value)) {
    assertCryptoKey(value, "public", "verify");
    return value;
  }
  if (typeof value === "string") {
    const der = pemToDer(value, "PUBLIC KEY");
    return subtle().importKey("spki", der, { name: "Ed25519" }, true, ["verify"]);
  }
  const jwk = normalizePublicJwkValue(value);
  return subtle().importKey("jwk", jwk, { name: "Ed25519" }, true, ["verify"]);
}

async function importEd25519PrivateKey(value) {
  if (isCryptoKey(value)) {
    assertCryptoKey(value, "private", "sign");
    return value;
  }
  if (typeof value === "string") {
    const der = pemToDer(value, "PRIVATE KEY");
    return subtle().importKey("pkcs8", der, { name: "Ed25519" }, false, ["sign"]);
  }
  if (!isPlainObject(value) || value.kty !== "OKP" || value.crv !== "Ed25519") {
    throw new TypeError("Only an Ed25519 OKP private JWK is accepted.");
  }
  requiredBase64Url(value.d, "JWK d");
  requiredBase64Url(value.x, "JWK x");
  return subtle().importKey("jwk", value, { name: "Ed25519" }, false, ["sign"]);
}

function assertCryptoKey(key, type, usage) {
  if (key.type !== type || key.algorithm?.name !== "Ed25519" || !key.usages.includes(usage)) {
    throw new TypeError(`Expected an Ed25519 ${type} CryptoKey with ${usage} usage.`);
  }
}

function isCryptoKey(value) {
  return Boolean(
    value &&
      typeof value === "object" &&
      typeof value.type === "string" &&
      value.algorithm &&
      Array.isArray(value.usages),
  );
}

function pemToDer(pem, expectedLabel) {
  const expression = new RegExp(
    `^-----BEGIN ${expectedLabel}-----\\s+([A-Za-z0-9+/=\\s]+?)\\s+-----END ${expectedLabel}-----$`,
  );
  const match = expression.exec(pem.trim());
  if (!match) throw new TypeError(`Expected a PEM encoded ${expectedLabel}.`);
  return base64ToBytes(match[1].replace(/\s/g, ""));
}

function canonicalize(value, ancestors) {
  if (value === null) return "null";
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "string") {
    assertWellFormed(value, "JSON string");
    return JSON.stringify(value);
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new TypeError("JCS does not allow non-finite numbers.");
    return JSON.stringify(value);
  }
  if (typeof value !== "object") {
    throw new TypeError(`JCS does not allow values of type ${typeof value}.`);
  }
  if (ancestors.has(value)) throw new TypeError("JCS does not allow cyclic values.");
  ancestors.add(value);
  try {
    if (Array.isArray(value)) {
      const serialized = [];
      for (let index = 0; index < value.length; index += 1) {
        if (!Object.hasOwn(value, index)) {
          throw new TypeError("JCS does not allow sparse arrays.");
        }
        serialized.push(canonicalize(value[index], ancestors));
      }
      return `[${serialized.join(",")}]`;
    }
    if (!isPlainObject(value)) {
      throw new TypeError("JCS accepts only plain JSON objects.");
    }
    if (Object.getOwnPropertySymbols(value).length) {
      throw new TypeError("JCS does not allow symbol properties.");
    }
    const keys = Object.keys(value).sort();
    return `{${keys
      .map((key) => {
        assertWellFormed(key, "JSON property name");
        const descriptor = Object.getOwnPropertyDescriptor(value, key);
        if (!descriptor || !("value" in descriptor)) {
          throw new TypeError("JCS does not allow accessor properties.");
        }
        return `${JSON.stringify(key)}:${canonicalize(descriptor.value, ancestors)}`;
      })
      .join(",")}}`;
  } finally {
    ancestors.delete(value);
  }
}

function assertWellFormed(value, name) {
  if (typeof value.isWellFormed === "function" ? !value.isWellFormed() : hasLoneSurrogate(value)) {
    throw new TypeError(`${name} contains an unpaired Unicode surrogate.`);
  }
}

function hasLoneSurrogate(value) {
  for (let index = 0; index < value.length; index += 1) {
    const unit = value.charCodeAt(index);
    if (unit >= 0xd800 && unit <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (next < 0xdc00 || next > 0xdfff) return true;
      index += 1;
    } else if (unit >= 0xdc00 && unit <= 0xdfff) {
      return true;
    }
  }
  return false;
}

function normalizeMethod(value) {
  const method = requiredIdentifier(value, "method", 32).toUpperCase();
  if (!/^[A-Z!#$%&'*+.^_`|~-]+$/.test(method)) {
    throw new TypeError("Invalid HTTP method.");
  }
  return method;
}

function normalizeAuthority(value) {
  const authority = requiredIdentifier(value, "authority", 255).toLowerCase();
  if (/[/\\?#@\s\x00-\x1f\x7f]/.test(authority)) {
    throw new TypeError("Invalid HTTP authority.");
  }
  return authority;
}

function normalizePath(value) {
  const path = requiredIdentifier(value, "path", 2048);
  if (!path.startsWith("/") || /[?#\r\n]/.test(path)) {
    throw new TypeError(
      "The signed path must be an absolute path without a query or fragment.",
    );
  }
  return path;
}

function normalizeHeaderValue(value) {
  const text = String(value);
  if (/[\r\n\x00]/.test(text)) throw new TypeError("HTTP header value contains controls.");
  const normalized = text.trim().replace(/[\t ]+/g, " ");
  if (!normalized) throw new TypeError("HTTP header value must not be empty.");
  return normalized;
}

function requiredHeader(headers, name) {
  if (!headers) throw new TypeError(`Missing ${name} header.`);
  let value;
  if (typeof headers.get === "function") {
    value = headers.get(name);
  } else if (isPlainObject(headers)) {
    const matched = Object.keys(headers).find((key) => key.toLowerCase() === name);
    value = matched ? headers[matched] : undefined;
  }
  if (typeof value !== "string" || !value.trim()) {
    throw new TypeError(`Missing ${name} header.`);
  }
  return value;
}

function requiredIdentifier(value, name, maximum, minimum = 1) {
  if (typeof value !== "string") throw new TypeError(`${name} must be a string.`);
  const normalized = value.trim();
  if (
    normalized.length < minimum ||
    normalized.length > maximum ||
    /[\x00-\x20\x7f]/.test(normalized)
  ) {
    throw new TypeError(`${name} has an invalid length or contains whitespace/control characters.`);
  }
  assertWellFormed(normalized, name);
  return normalized;
}

function requiredHeaderText(value, name, maximum) {
  if (typeof value !== "string" || value.length > maximum) {
    throw new TypeError(`${name} must be a string no longer than ${maximum} characters.`);
  }
  return normalizeHeaderValue(value);
}

function structuredFieldString(value) {
  if (!/^[\x20-\x7e]+$/.test(value)) {
    throw new TypeError("HTTP Signature keyId must contain printable ASCII only.");
  }
  return `"${value.replace(/\\/g, "\\\\").replace(/"/g, '\\"')}"`;
}

function epochSeconds(value, name) {
  const number =
    typeof value === "string" && /^\d+$/.test(value) ? Number(value) : value;
  if (!Number.isSafeInteger(number) || number < 0) {
    throw new TypeError(`${name} must be a non-negative Unix timestamp in whole seconds.`);
  }
  return number;
}

function nowSeconds(value) {
  if (value === undefined) return Math.floor(Date.now() / 1000);
  if (value instanceof Date) return Math.floor(value.getTime() / 1000);
  return epochSeconds(value, "now");
}

function requireIncreasingWindow(created, expires) {
  if (expires <= created) throw new TypeError("expires must be greater than created.");
}

function positiveSafeInteger(value, name) {
  if (!Number.isSafeInteger(value) || value <= 0) {
    throw new TypeError(`${name} must be a positive safe integer.`);
  }
  return value;
}

function nonNegativeInteger(value, name) {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new TypeError(`${name} must be a non-negative integer.`);
  }
  return value;
}

function requiredBase64Url(value, name) {
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]+$/.test(value)) {
    throw new TypeError(`${name} must be unpadded base64url.`);
  }
  base64UrlToBytes(value);
  return value;
}

function bodyBytes(value) {
  if (value === undefined) return new Uint8Array();
  if (typeof value === "string") return encoder.encode(value);
  if (value instanceof ArrayBuffer) return new Uint8Array(value);
  if (ArrayBuffer.isView(value)) {
    return new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
  }
  throw new TypeError("The signed body must be a string, ArrayBuffer, or byte view.");
}

function bytesToBase64(bytes) {
  let binary = "";
  for (let offset = 0; offset < bytes.length; offset += 0x8000) {
    binary += String.fromCharCode(...bytes.subarray(offset, offset + 0x8000));
  }
  return btoa(binary);
}

function base64ToBytes(value) {
  let binary;
  try {
    binary = atob(value);
  } catch (error) {
    throw new TypeError("Invalid base64 value.", { cause: error });
  }
  const bytes = Uint8Array.from(binary, (character) => character.charCodeAt(0));
  if (bytesToBase64(bytes) !== value) throw new TypeError("Non-canonical base64 value.");
  return bytes;
}

function bytesToBase64Url(bytes) {
  return bytesToBase64(bytes).replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
}

function base64UrlToBytes(value) {
  if (!/^[A-Za-z0-9_-]+$/.test(value)) throw new TypeError("Invalid base64url value.");
  const remainder = value.length % 4;
  if (remainder === 1) throw new TypeError("Invalid base64url length.");
  const padded = value.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - remainder) % 4);
  const bytes = base64ToBytes(padded);
  if (bytesToBase64Url(bytes) !== value) throw new TypeError("Non-canonical base64url value.");
  return bytes;
}

function sameText(left, right) {
  const first = encoder.encode(String(left));
  const second = encoder.encode(String(right));
  if (first.length !== second.length) return false;
  let difference = 0;
  for (let index = 0; index < first.length; index += 1) {
    difference |= first[index] ^ second[index];
  }
  return difference === 0;
}

function isPlainObject(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function subtle() {
  if (!globalThis.crypto?.subtle) {
    throw new Error("Web Crypto is required (Node.js 22 or a compatible runtime).");
  }
  return globalThis.crypto.subtle;
}

function failure(code, message) {
  return { ok: false, code, message };
}

function safeErrorMessage(error) {
  return error instanceof Error ? error.message : "Signature verification failed.";
}
