const DEFAULT_REPOSITORY = "HUBTECH-DEV/hch-worker";
const DEFAULT_INTERVAL_MILLISECONDS = 15 * 60_000;
const RELEASE_PAGE_SIZE = 100;
const MAX_RELEASE_PAGES = 10;
const VERSION_PATTERN = /^(?:v)?(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-([0-9A-Za-z.-]+))?$/;
const RELEASE_PLATFORMS = Object.freeze(["windows", "linux", "macos"]);

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
  let releases = [];
  let refreshErrorCode = null;
  let pending = null;

  async function refresh(force = false) {
    const currentTime = now();
    if (!force && lastCheckedAt && currentTime.getTime() - Date.parse(lastCheckedAt) < intervalMilliseconds) {
      return;
    }
    if (pending) return pending;
    pending = (async () => {
      try {
        releases = await fetchReleasePages(fetchImpl, repository);
        refreshErrorCode = null;
      } catch (error) {
        refreshErrorCode = error instanceof ReleaseCheckError
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
      let selected = null;
      let errorCode = refreshErrorCode;
      if (!errorCode) {
        try {
          selected = selectRelease(releases, repository, options.platform);
        } catch (error) {
          errorCode = error instanceof ReleaseCheckError
            ? error.code
            : "release-metadata-invalid";
        }
      }
      const latest = selected?.version ?? null;
      return Object.freeze({
        repository,
        channel: "stable",
        currentVersion: current,
        latestVersion: latest,
        updateAvailable: current !== null && latest !== null && compareVersions(latest, current) > 0,
        compatibility: selected?.compatibility ?? "unspecified",
        contentImpact: selected?.contentImpact ?? "unspecified",
        releaseUrl: selected?.htmlUrl ?? null,
        publishedAt: selected?.publishedAt ?? null,
        checkedAt: lastCheckedAt,
        status: errorCode ? "error" : selected ? "checked" : "no-release",
        errorCode,
      });
    },
  });
}

async function fetchReleasePages(fetchImpl, repository) {
  const values = [];
  for (let page = 1; page <= MAX_RELEASE_PAGES; page += 1) {
    const response = await fetchImpl(
      `https://api.github.com/repos/${repository}/releases?per_page=${RELEASE_PAGE_SIZE}&page=${page}`,
      {
        headers: {
          Accept: "application/vnd.github+json",
          "User-Agent": "hch-worker-dashboard",
          "X-GitHub-Api-Version": "2022-11-28",
        },
        redirect: "error",
        signal: AbortSignal.timeout(10_000),
      },
    );
    if (response.status === 404 && page === 1) return [];
    if (!response.ok) throw new ReleaseCheckError("release-check-http-error");
    const payload = await response.json();
    if (!Array.isArray(payload)) throw new ReleaseCheckError("release-list-invalid");
    values.push(...payload);
    if (payload.length < RELEASE_PAGE_SIZE) return values;
  }
  throw new ReleaseCheckError("release-list-limit-exceeded");
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

function selectRelease(values, repository, platformValue) {
  const platform = normalizePlatform(platformValue);
  const candidates = [];
  for (const value of values) {
    if (!value || typeof value !== "object" || Array.isArray(value)) {
      throw new ReleaseCheckError("release-metadata-invalid");
    }
    if (value.draft === true || value.prerelease === true) continue;
    const descriptor = classifyReleaseTag(value.tag_name, platform);
    if (descriptor === null) continue;
    if (value.draft !== false || value.prerelease !== false || descriptor.prerelease !== null) {
      throw new ReleaseCheckError("release-metadata-invalid");
    }
    candidates.push({ value, descriptor });
  }
  candidates.sort((left, right) => {
    const comparison = compareVersions(right.descriptor.version, left.descriptor.version);
    if (comparison !== 0) return comparison;
    return Number(right.descriptor.platform !== null) - Number(left.descriptor.platform !== null);
  });
  if (candidates.length === 0) return null;
  return validateRelease(candidates[0].value, repository, candidates[0].descriptor);
}

function classifyReleaseTag(value, selectedPlatform) {
  if (typeof value !== "string") throw new ReleaseCheckError("release-version-invalid");
  for (const platform of RELEASE_PLATFORMS) {
    const prefix = `${platform}-`;
    if (!value.startsWith(prefix)) continue;
    if (selectedPlatform === null || selectedPlatform !== platform) return null;
    const versionText = value.slice(prefix.length);
    try {
      const parsed = parseVersion(versionText);
      if (!versionText.startsWith("v")) throw new TypeError("Platform release tag requires v prefix.");
      return { ...parsed, platform, tag: value, version: parsed.normalized };
    } catch {
      throw new ReleaseCheckError("release-version-invalid");
    }
  }
  try {
    const parsed = parseVersion(value);
    if (!value.startsWith("v") || compareVersions(parsed.normalized, "3.1.1") > 0) return null;
    return { ...parsed, platform: null, tag: value, version: parsed.normalized };
  } catch {
    if (/^v?\d/.test(value)) throw new ReleaseCheckError("release-version-invalid");
    return null;
  }
}

function validateRelease(value, repository, descriptor) {
  const expectedUrl = `https://github.com/${repository}/releases/tag/${descriptor.tag}`;
  if (typeof value.html_url !== "string" || value.html_url !== expectedUrl) {
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
  if (compareVersions(descriptor.version, "3.1.1") >= 0 && (!compatibility || !contentImpact)) {
    throw new ReleaseCheckError("release-compatibility-declaration-missing");
  }
  if ((compatibility === "incompatible") !== (contentImpact === "generated-content")) {
    throw new ReleaseCheckError("release-compatibility-declaration-invalid");
  }
  return Object.freeze({
    version: descriptor.version,
    platform: descriptor.platform,
    htmlUrl: value.html_url,
    publishedAt,
    compatibility: compatibility ?? "unspecified",
    contentImpact: contentImpact ?? "unspecified",
  });
}

function releaseMarker(body, name, allowed) {
  if (typeof body !== "string") return null;
  const matches = [...body.matchAll(
    new RegExp(`(?:^|\\r?\\n)[ \\t]*${name}:[ \\t]*([a-z-]+)[ \\t]*(?=\\r?\\n|$)`, "gi"),
  )];
  if (matches.length === 0) return null;
  if (matches.length !== 1) throw new ReleaseCheckError("release-compatibility-declaration-invalid");
  const value = matches[0][1].toLowerCase();
  if (!allowed.has(value)) throw new ReleaseCheckError("release-compatibility-declaration-invalid");
  return value;
}

function normalizeRepository(value) {
  if (typeof value !== "string" || !/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(value)) {
    throw new TypeError("Release repository is invalid.");
  }
  return value;
}

function normalizePlatform(value) {
  if (value === undefined || value === null || value === "") return null;
  const normalized = String(value).trim().toLowerCase();
  if (normalized === "windows" || normalized.startsWith("windows-") || normalized.startsWith("win32")) return "windows";
  if (normalized === "linux" || normalized.startsWith("linux-")) return "linux";
  if (normalized === "macos" || normalized === "darwin" || normalized.startsWith("darwin-")) return "macos";
  throw new ReleaseCheckError("release-platform-invalid");
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
