import { safeReadJson, CONTRIBUTOR_AUTH_FILE } from "./storage.mjs";

export const CONTRIBUTOR_AUTH_SCHEMA = "hch.worker-contributor-auth/v1";
export const CONTRIBUTOR_AUTH_SCHEMA_VERSION = 1;

const PAIRING_STATES = new Set([
  "paired",
  "unpaired",
  "expired",
  "revoked",
  "unavailable",
]);
const ELIGIBILITY_STATES = new Set(["eligible", "ineligible", "unknown"]);
const CONSENT_STATES = new Set(["accepted", "required", "revoked", "unknown"]);
const REASON_CODE = /^[a-z][a-z0-9-]{0,63}$/;
const PAIRWISE_BINDING_ID = /^hchbind_[A-Za-z0-9_-]{22,86}$/;

export function parseContributorAuth(value) {
  object(value, "contributor auth");
  exactKeys(value, [
    "schema",
    "schemaVersion",
    "observedAt",
    "pairing",
    "eligibility",
    "consent",
    "bindingId",
  ], "contributor auth");
  if (value.schema !== CONTRIBUTOR_AUTH_SCHEMA ||
      value.schemaVersion !== CONTRIBUTOR_AUTH_SCHEMA_VERSION) {
    throw new TypeError("Unsupported contributor auth schema.");
  }

  const pairing = parsePairing(value.pairing);
  const eligibility = parseEligibility(value.eligibility);
  const consent = parseConsent(value.consent);
  const bindingId = value.bindingId;
  if (bindingId !== null &&
      (typeof bindingId !== "string" || !PAIRWISE_BINDING_ID.test(bindingId))) {
    throw new TypeError("Invalid pairwise bindingId.");
  }
  if (pairing.status === "paired" && bindingId === null) {
    throw new TypeError("Paired bindingId is required.");
  }
  if (pairing.status === "paired" &&
      (pairing.pairedAt === null || pairing.expiresAt === null ||
       Date.parse(pairing.expiresAt) <= Date.parse(pairing.pairedAt))) {
    throw new TypeError("Paired timestamps are invalid.");
  }
  if (pairing.status !== "paired" && bindingId !== null) {
    throw new TypeError("Unpaired bindingId must not be retained.");
  }
  if (pairing.status !== "paired" &&
      (pairing.pairedAt !== null || pairing.expiresAt !== null)) {
    throw new TypeError("Unpaired timestamps must not be retained.");
  }
  if (eligibility.status === "eligible" && eligibility.checkedAt === null) {
    throw new TypeError("Eligible check timestamp is required.");
  }
  if (consent.status === "accepted" &&
      (consent.version === null || consent.acceptedAt === null)) {
    throw new TypeError("Accepted consent evidence is required.");
  }

  return {
    schema: CONTRIBUTOR_AUTH_SCHEMA,
    schemaVersion: CONTRIBUTOR_AUTH_SCHEMA_VERSION,
    observedAt: timestamp(value.observedAt, "observedAt"),
    pairing,
    eligibility,
    consent,
    bindingId,
  };
}

export async function readContributorStatus(dataDirectory, options = {}) {
  const clock = typeof options.now === "function" ? options.now() : options.now;
  const now = new Date(clock ?? Date.now());
  if (!Number.isFinite(now.getTime())) throw new TypeError("Contributor clock is invalid.");
  const staleAfterMilliseconds = options.staleAfterMilliseconds ?? 5 * 60_000;
  if (!Number.isSafeInteger(staleAfterMilliseconds) || staleAfterMilliseconds < 1_000) {
    throw new TypeError("Contributor staleness window is invalid.");
  }
  const read = await safeReadJson(
    dataDirectory,
    CONTRIBUTOR_AUTH_FILE,
    parseContributorAuth,
    { maximumBytes: 32 * 1024 },
  );
  const pairingContract = browserPairingContract(options.pairingUrl);
  if (!read.ok) return unavailableContributorStatus(now, read.code, pairingContract);

  const state = read.value;
  const observedAge = now.getTime() - Date.parse(state.observedAt);
  if (observedAge > staleAfterMilliseconds || observedAge < -60_000) {
    return unavailableContributorStatus(now, "stale", pairingContract);
  }
  const expired = state.pairing.status === "paired" &&
    state.pairing.expiresAt !== null &&
    Date.parse(state.pairing.expiresAt) <= now.getTime();
  const pairingStatus = expired ? "expired" : state.pairing.status;
  const blockingReasons = [];
  if (pairingStatus !== "paired") blockingReasons.push("hih-browser-pairing-required");
  if (state.eligibility.status !== "eligible") blockingReasons.push("complete-profile-required");
  if (state.consent.status !== "accepted") blockingReasons.push("contribution-consent-required");
  const readyForContribution = blockingReasons.length === 0;

  return {
    schema: CONTRIBUTOR_AUTH_SCHEMA,
    schemaVersion: CONTRIBUTOR_AUTH_SCHEMA_VERSION,
    observedAt: state.observedAt,
    sourceStatus: "valid",
    pairing: { ...state.pairing, status: pairingStatus },
    eligibility: state.eligibility,
    consent: state.consent,
    readyForContribution,
    blockingReasons,
    browserPairing: pairingContract,
  };
}

function unavailableContributorStatus(now, sourceStatus, pairingContract) {
  return {
    schema: CONTRIBUTOR_AUTH_SCHEMA,
    schemaVersion: CONTRIBUTOR_AUTH_SCHEMA_VERSION,
    observedAt: now.toISOString(),
    sourceStatus,
    pairing: { status: "unavailable", pairedAt: null, expiresAt: null },
    eligibility: { status: "unknown", checkedAt: null, reasonCodes: [] },
    consent: { status: "required", version: null, acceptedAt: null },
    readyForContribution: false,
    blockingReasons: [
      "hih-browser-pairing-required",
      "complete-profile-required",
      "contribution-consent-required",
    ],
    browserPairing: pairingContract,
  };
}

function browserPairingContract(value) {
  return value
    ? { available: true, url: value, method: "browser-session-one-time-code-ed25519" }
    : { available: false, url: null, method: "browser-session-one-time-code-ed25519" };
}

function parsePairing(value) {
  object(value, "pairing");
  exactKeys(value, ["status", "pairedAt", "expiresAt"], "pairing");
  if (!PAIRING_STATES.has(value.status)) throw new TypeError("Invalid pairing status.");
  return {
    status: value.status,
    pairedAt: nullableTimestamp(value.pairedAt, "pairedAt"),
    expiresAt: nullableTimestamp(value.expiresAt, "expiresAt"),
  };
}

function parseEligibility(value) {
  object(value, "eligibility");
  exactKeys(value, ["status", "checkedAt", "reasonCodes"], "eligibility");
  if (!ELIGIBILITY_STATES.has(value.status)) throw new TypeError("Invalid eligibility status.");
  if (!Array.isArray(value.reasonCodes) || value.reasonCodes.length > 16 ||
      value.reasonCodes.some((code) => typeof code !== "string" || !REASON_CODE.test(code))) {
    throw new TypeError("Invalid eligibility reason codes.");
  }
  return {
    status: value.status,
    checkedAt: nullableTimestamp(value.checkedAt, "checkedAt"),
    reasonCodes: [...new Set(value.reasonCodes)],
  };
}

function parseConsent(value) {
  object(value, "consent");
  exactKeys(value, ["status", "version", "acceptedAt"], "consent");
  if (!CONSENT_STATES.has(value.status)) throw new TypeError("Invalid consent status.");
  if (value.version !== null &&
      (typeof value.version !== "string" || !/^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/.test(value.version))) {
    throw new TypeError("Invalid consent version.");
  }
  return {
    status: value.status,
    version: value.version,
    acceptedAt: nullableTimestamp(value.acceptedAt, "acceptedAt"),
  };
}

function object(value, label) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new TypeError(`${label} must be an object.`);
  }
}

function exactKeys(value, expected, label) {
  const keys = Object.keys(value).sort();
  const allowed = [...expected].sort();
  if (keys.length !== allowed.length || keys.some((key, index) => key !== allowed[index])) {
    throw new TypeError(`${label} has unsupported fields.`);
  }
}

function nullableTimestamp(value, label) {
  return value === null ? null : timestamp(value, label);
}

function timestamp(value, label) {
  if (typeof value !== "string" || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$/.test(value) ||
      !Number.isFinite(Date.parse(value))) {
    throw new TypeError(`Invalid ${label}.`);
  }
  return new Date(value).toISOString();
}
