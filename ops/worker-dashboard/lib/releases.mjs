const DEFAULT_REPOSITORY = "HUBTECH-DEV/hch-worker";
const DEFAULT_INTERVAL_MILLISECONDS = 15 * 60_000;
const VERSION_PATTERN = /^(?:v)?(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-([0-9A-Za-z.-]+))?$/;

export function createReleaseMonitor(options = {}) {
  const repository = normalizeRepository(options.repository ?? DEFAULT_REPOSITORY);
  const fetchImpl = options.fetchImpl ?? globalThis.fetch;
  if (typeof fetchImpl !== "function") throw new TypeError("Release monitor requires fetch.");
  const intervalMilliseconds = boundedInteger(
    options.intervalMilliseconds ?? DEFAULT_INTERVAL_MILLISECONDS,
    30_000,
    24 * 60 * 60_000,
    "release check interval",
  );
  const now = () => new Date(typeof options.now === "function" ? options.now() : options.now ?? Date.now());
  let lastCheckedAt = null;
  let release = null;
  let errorCode = null;
  let pending = null;

  async function refresh(force = false) {
    const currentTime = now();
    if (!force && lastCheckedAt && currentTime.getTime() - Date.parse(lastCheckedAt) < intervalMilliseconds) {
      return;
    }
    if (pending) return pending;
    pending = (async () => {
      try {
        const response = await fetchImpl(`https://api.github.com/repos/${repository}/releases/latest`, {
          headers: {
            Accept: "application/vnd.github+json",
            "User-Agent": "hch-worker-dashboard",
            "X-GitHub-Api-Version": "2022-11-28",
          },
          redirect: "error",
          signal: AbortSignal.timeout(10_000),
        });
        if (response.status === 404) {
          release = null;
          errorCode = null;
          return;
        }
        if (!response.ok) throw new ReleaseCheckError("release-check-http-error");
        release = validateRelease(await response.json(), repository);
        errorCode = null;
      } catch (error) {
        errorCode = error instanceof ReleaseCheckError
          ? error.code
          : "release-check-unavailable";
      } finally {
        lastCheckedAt = currentTime.toISOString();
        pending = null;
      }
    })();
    return pending;
  }

  return Object.freeze({
    async snapshot(currentVersion, options = {}) {
      await refresh(options.force === true);
      const current = normalizeVersion(currentVersion);
      const latest = release?.version ?? null;
      return Object.freeze({
        repository,
        channel: "stable",
        currentVersion: current,
        latestVersion: latest,
        updateAvailable: current !== null && latest !== null && compareVersions(latest, current) > 0,
        compatibility: release?.compatibility ?? "unspecified",
        contentImpact: release?.contentImpact ?? "unspecified",
        releaseUrl: release?.htmlUrl ?? null,
        publishedAt: release?.publishedAt ?? null,
        checkedAt: lastCheckedAt,
        status: errorCode ? "error" : release ? "checked" : "no-release",
        errorCode,
      });
    },
  });
}

export function compareVersions(left, right) {
  const a = parseVersion(left);
  const b = parseVersion(right);
  for (let index = 0; index < 3; index += 1) {
    if (a.numbers[index] !== b.numbers[index]) return a.numbers[index] > b.numbers[index] ? 1 : -1;
  }
  if (a.prerelease === b.prerelease) return 0;
  if (a.prerelease === null) return 1;
  if (b.prerelease === null) return -1;
  return a.prerelease.localeCompare(b.prerelease, "en", { numeric: true });
}

function validateRelease(value, repository) {
  if (!value || typeof value !== "object" || Array.isArray(value) ||
      value.draft !== false || value.prerelease !== false) {
    throw new ReleaseCheckError("release-metadata-invalid");
  }
  const version = normalizeVersion(value.tag_name);
  if (!version) throw new ReleaseCheckError("release-version-invalid");
  const expectedPrefix = `https://github.com/${repository}/releases/tag/`;
  if (typeof value.html_url !== "string" || !value.html_url.startsWith(expectedPrefix)) {
    throw new ReleaseCheckError("release-url-invalid");
  }
  const publishedAt = normalizedTimestamp(value.published_at);
  const compatibility = releaseMarker(
    value.body,
    "HCH-Worker-Compatibility",
    new Set(["compatible", "incompatible"]),
  );
  const contentImpact = releaseMarker(
    value.body,
    "HCH-Worker-Content-Impact",
    new Set(["none", "generated-content"]),
  );
  if (compareVersions(version, "3.2.0") >= 0 && (!compatibility || !contentImpact)) {
    throw new ReleaseCheckError("release-compatibility-declaration-missing");
  }
  if (
    (compatibility === "incompatible") !== (contentImpact === "generated-content")
  ) {
    throw new ReleaseCheckError("release-compatibility-declaration-invalid");
  }
  return Object.freeze({
    version,
    htmlUrl: value.html_url,
    publishedAt,
    compatibility: compatibility ?? "unspecified",
    contentImpact: contentImpact ?? "unspecified",
  });
}

function releaseMarker(body, name, allowed) {
  if (typeof body !== "string") return null;
  const match = new RegExp(`(?:^|\\n)${name}:\\s*([a-z-]+)\\s*(?:\\n|$)`, "i").exec(body);
  if (!match) return null;
  const value = match[1].toLowerCase();
  if (!allowed.has(value)) throw new ReleaseCheckError("release-compatibility-declaration-invalid");
  return value;
}

function normalizeRepository(value) {
  if (typeof value !== "string" || !/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(value)) {
    throw new TypeError("Release repository is invalid.");
  }
  return value;
}

function normalizeVersion(value) {
  if (typeof value !== "string") return null;
  try { return parseVersion(value).normalized; } catch { return null; }
}

function parseVersion(value) {
  const match = VERSION_PATTERN.exec(String(value));
  if (!match) throw new TypeError("Worker version is invalid.");
  return {
    normalized: `${match[1]}.${match[2]}.${match[3]}${match[4] ? `-${match[4]}` : ""}`,
    numbers: [Number(match[1]), Number(match[2]), Number(match[3])],
    prerelease: match[4] ?? null,
  };
}

function normalizedTimestamp(value) {
  if (typeof value !== "string" || !Number.isFinite(Date.parse(value))) {
    throw new ReleaseCheckError("release-published-at-invalid");
  }
  return new Date(value).toISOString();
}

function boundedInteger(value, minimum, maximum, label) {
  const number = typeof value === "string" && /^\d+$/.test(value) ? Number(value) : value;
  if (!Number.isSafeInteger(number) || number < minimum || number > maximum) {
    throw new TypeError(`${label} must be an integer between ${minimum} and ${maximum}.`);
  }
  return number;
}

class ReleaseCheckError extends Error {
  constructor(code) {
    super(code);
    this.code = code;
  }
}
