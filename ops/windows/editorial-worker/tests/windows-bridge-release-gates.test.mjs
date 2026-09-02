import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import test from "node:test";
import { gzipSync } from "node:zlib";

const repositoryRoot = resolve(import.meta.dirname, "../../../..");
const gatePath = join(repositoryRoot, "scripts/windows/Test-HchWorkerBridgeRelease.ps1");
const shell = process.platform === "win32" ? "powershell.exe" : "pwsh";
const sourceCommit = "a".repeat(40);
const signerSha1 = "b".repeat(40);
const signerSha256 = "c".repeat(64);
const version = "3.1.1";
const packages = [
  `HCH-Worker-Setup-${version}-x64.exe`,
  `HCH-Worker-${version}-linux-x64.tar.gz`,
  `HCH-Worker-${version}-macos-universal.tar.gz`,
];
const assetNames = [...packages, "SHA256SUMS.txt", "SHA256SUMS.p7s"];

function writeTarString(header, offset, length, value) {
  const encoded = Buffer.from(value, "utf8");
  assert.ok(encoded.length <= length, `tar field is too long: ${value}`);
  encoded.copy(header, offset);
}

function writeTarOctal(header, offset, length, value) {
  const encoded = `${value.toString(8).padStart(length - 1, "0")}\0`;
  assert.equal(encoded.length, length);
  writeTarString(header, offset, length, encoded);
}

function splitTarName(name) {
  if (Buffer.byteLength(name) <= 100) return { name, prefix: "" };
  for (let index = name.lastIndexOf("/"); index > 0; index = name.lastIndexOf("/", index - 1)) {
    const prefix = name.slice(0, index);
    const basename = name.slice(index + 1);
    if (Buffer.byteLength(prefix) <= 155 && Buffer.byteLength(basename) <= 100) {
      return { name: basename, prefix };
    }
  }
  throw new Error(`tar path is too long: ${name}`);
}

function tarEntry({ name, content = "", mode = 0o644, type = "0", linkName = "" }) {
  const payload = type === "0" ? Buffer.from(content) : Buffer.alloc(0);
  const header = Buffer.alloc(512);
  const splitName = splitTarName(name);
  writeTarString(header, 0, 100, splitName.name);
  writeTarOctal(header, 100, 8, mode);
  writeTarOctal(header, 108, 8, 0);
  writeTarOctal(header, 116, 8, 0);
  writeTarOctal(header, 124, 12, payload.length);
  writeTarOctal(header, 136, 12, 0);
  header.fill(0x20, 148, 156);
  writeTarString(header, 156, 1, type);
  writeTarString(header, 157, 100, linkName);
  writeTarString(header, 257, 6, "ustar\0");
  writeTarString(header, 263, 2, "00");
  writeTarString(header, 265, 32, "root");
  writeTarString(header, 297, 32, "root");
  writeTarString(header, 345, 155, splitName.prefix);
  const checksum = header.reduce((total, byte) => total + byte, 0);
  writeTarString(header, 148, 8, `${checksum.toString(8).padStart(6, "0")}\0 `);
  const padding = Buffer.alloc((512 - (payload.length % 512)) % 512);
  return Buffer.concat([header, payload, padding]);
}

function writeTarGz(path, entries) {
  const tar = Buffer.concat([
    ...entries.map(tarEntry),
    Buffer.alloc(1024),
  ]);
  writeFileSync(path, gzipSync(tar, { level: 9 }));
}

function archiveEntries(platform, overrides = {}) {
  const entries = [
    { name: "hch-worker/VERSION", content: `${overrides.version ?? version}\n` },
    {
      name: "hch-worker/ops/linux/editorial-worker/worker.mjs",
      content: "#!/usr/bin/env node\nexport {};\n",
      mode: overrides.workerMode ?? 0o755,
    },
    {
      name: "hch-worker/ops/worker-dashboard/server.mjs",
      content: "export {};\n",
    },
  ];
  if (platform === "linux") {
    entries.push(
      {
        name: "hch-worker/scripts/hch-editorial-workerctl",
        content: "#!/bin/sh\nexit 0\n",
        mode: 0o755,
      },
      {
        name: "hch-worker/ops/systemd/hch-editorial-worker.service",
        content: "[Service]\nExecStart=/usr/bin/node worker.mjs\n",
      },
    );
  } else {
    entries.push(
      {
        name: "hch-worker/ops/macos/editorial-worker/hch-editorial-workerctl",
        content: "#!/bin/sh\nexit 0\n",
        mode: 0o755,
      },
      {
        name: "hch-worker/ops/macos/editorial-worker/install-launch-agents.sh",
        content: "#!/bin/sh\nexit 0\n",
        mode: 0o755,
      },
      {
        name: "hch-worker/ops/macos/editorial-worker/launchd/online.hubtech.hch.editorial-worker.cycle.plist.in",
        content: "<?xml version=\"1.0\"?><plist/>",
      },
    );
  }
  return entries;
}

function refreshIntegrity(state) {
  const checksumLines = packages.map((name) => {
    const digest = createHash("sha256").update(readFileSync(join(state.assets, name))).digest("hex");
    return `${digest}  ${name}`;
  });
  writeFileSync(join(state.assets, "SHA256SUMS.txt"), `${checksumLines.join("\n")}\n`);
  for (const name of assetNames) {
    const size = readFileSync(join(state.assets, name)).length;
    state.latest.assets.find((asset) => asset.name === name).size = size;
    state.tagged.assets.find((asset) => asset.name === name).size = size;
  }
}

function replaceArchive(state, platform, entries) {
  const packageIndex = platform === "linux" ? 1 : 2;
  writeTarGz(join(state.assets, packages[packageIndex]), entries);
  refreshIntegrity(state);
}

function fixture(mutator = () => {}) {
  const root = mkdtempSync(join(tmpdir(), "hch-bridge-release-"));
  const assets = join(root, "assets");
  mkdirSync(assets);
  writeFileSync(join(assets, packages[0]), "MZ-hch-worker-bridge-fixture\n");
  writeTarGz(join(assets, packages[1]), archiveEntries("linux"));
  writeTarGz(join(assets, packages[2]), archiveEntries("macos"));
  const checksumLines = packages.map((name) => {
    const digest = createHash("sha256").update(readFileSync(join(assets, name))).digest("hex");
    return `${digest}  ${name}`;
  });
  writeFileSync(join(assets, "SHA256SUMS.txt"), `${checksumLines.join("\n")}\n`);
  writeFileSync(join(assets, "SHA256SUMS.p7s"), "offline-signature-placeholder");

  const release = {
    databaseId: 311,
    id: "RE_release_311",
    tagName: "v3.1.1",
    isDraft: false,
    isPrerelease: false,
    isImmutable: true,
    publishedAt: "2026-08-01T00:00:00Z",
    body: "Stable bridge.\nHCH-Worker-Compatibility: compatible\nHCH-Worker-Content-Impact: none\n",
    assets: assetNames.map((name, index) => ({
      id: `RA_${index}`,
      name,
      size: readFileSync(join(assets, name)).length,
    })),
  };
  const state = {
    root,
    assets,
    latest: structuredClone(release),
    tagged: structuredClone(release),
    tagType: "tag",
    tagCommit: sourceCommit,
    ancestor: "true",
  };
  mutator(state);
  const latestPath = join(root, "latest.json");
  const taggedPath = join(root, "tagged.json");
  writeFileSync(latestPath, JSON.stringify(state.latest));
  writeFileSync(taggedPath, JSON.stringify(state.tagged));
  return { ...state, latestPath, taggedPath };
}

function runGate(state, extra = [], environment = {}) {
  const args = [
    "-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
    "-File", gatePath,
    "-BridgeSourceCommit", sourceCommit,
    "-CmsSignerSha1", signerSha1,
    "-CmsSignerSha256", signerSha256,
    "-TestMode",
    "-LatestReleaseJsonPath", state.latestPath,
    "-TaggedReleaseJsonPath", state.taggedPath,
    "-AssetDirectory", state.assets,
    "-OfflineTagObjectType", state.tagType,
    "-OfflineTagCommit", state.tagCommit,
    "-OfflineCommitIsMainAncestor", state.ancestor,
    "-SkipCmsVerification",
    "-SkipAttestationVerification",
    "-SkipAuthenticodeVerification",
    ...extra,
  ];
  return spawnSync(shell, args, {
    cwd: repositoryRoot,
    encoding: "utf8",
    env: { ...process.env, GITHUB_ACTIONS: "", ...environment },
  });
}

function expectRejected(mutator, code, extra = [], environment = {}) {
  const state = fixture(mutator);
  try {
    const result = runGate(state, extra, environment);
    assert.notEqual(result.status, 0, result.stdout);
    assert.match(`${result.stdout}\n${result.stderr}`, new RegExp(code));
  } finally {
    rmSync(state.root, { recursive: true, force: true });
  }
}

test("bridge release gate accepts an exact mature stable offline fixture", () => {
  const state = fixture();
  try {
    const result = runGate(state);
    assert.equal(result.status, 0, result.stderr);
    const output = JSON.parse(result.stdout.trim().split(/\r?\n/).at(-1));
    assert.equal(output.status, "verified");
    assert.equal(output.testMode, true);
    assert.equal(output.sourceCommit, sourceCommit);
    assert.equal(output.assetCount, 5);
    assert.ok(output.assetTotalBytes > 0);
  } finally {
    rmSync(state.root, { recursive: true, force: true });
  }
});

test("bridge release gate rejects release identity and stability drift", () => {
  expectRejected((state) => { state.latest.id = "RE_other"; }, "latest-tag-identity-mismatch");
  expectRejected((state) => { state.tagged.isDraft = true; }, "not-stable");
  expectRejected((state) => { state.tagged.isPrerelease = true; }, "not-stable");
  expectRejected((state) => { state.latest.isImmutable = false; }, "not-immutable");
  expectRejected((state) => { delete state.tagged.isImmutable; }, "not-immutable");
  expectRejected((state) => {
    state.latest.publishedAt = state.tagged.publishedAt = new Date().toISOString();
  }, "too-recent");
});

test("bridge release gate requires exact compatibility notes", () => {
  expectRejected((state) => {
    state.latest.body = state.tagged.body = "HCH-Worker-Content-Impact: none";
  }, "notes-contract-invalid");
  expectRejected((state) => {
    state.latest.body += "HCH-Worker-Compatibility: compatible\n";
    state.tagged.body = state.latest.body;
  }, "notes-contract-duplicated");
  expectRejected((state) => {
    state.latest.body += "  hch-worker-compatibility: compatible  \n";
    state.tagged.body = state.latest.body;
  }, "notes-contract-duplicated");
  expectRejected((state) => {
    state.latest.body = state.latest.body.replace("none", "editorial");
    state.tagged.body = state.latest.body;
  }, "notes-contract-invalid");
});

test("bridge release gate rejects asset additions, metadata drift, and size drift", () => {
  expectRejected((state) => {
    state.latest.assets.push({ id: "RA_extra", name: "worker.exe", size: 1 });
    state.tagged.assets.push({ id: "RA_extra", name: "worker.exe", size: 1 });
  }, "asset-inventory-invalid");
  expectRejected((state) => { state.latest.assets[0].id = "RA_changed"; }, "asset-metadata-mismatch");
  expectRejected((state) => { state.tagged.assets[0].size += 1; }, "asset-metadata-mismatch");
  expectRejected((state) => {
    state.latest.assets[0].size += 1;
    state.tagged.assets[0].size += 1;
  }, "downloaded-size-mismatch");
});

test("bridge release gate rejects zero, per-asset, and aggregate metadata sizes before content checks", () => {
  expectRejected((state) => {
    writeFileSync(join(state.assets, packages[0]), Buffer.alloc(0));
    state.latest.assets[0].size = 0;
    state.tagged.assets[0].size = 0;
  }, "asset-size-zero");
  expectRejected((state) => {
    state.latest.assets[1].size = 512 * 1024 * 1024 + 1;
    state.tagged.assets[1].size = 512 * 1024 * 1024 + 1;
  }, "asset-size-limit-exceeded");
  expectRejected((state) => {
    for (const index of [0, 1, 2]) {
      state.latest.assets[index].size = 500 * 1024 * 1024;
      state.tagged.assets[index].size = 500 * 1024 * 1024;
    }
  }, "asset-total-size-limit-exceeded");
});

test("bridge release gate rejects checksum drift and extra checksum entries", () => {
  expectRejected((state) => {
    writeFileSync(join(state.assets, packages[0]), "tampered\n");
    const size = readFileSync(join(state.assets, packages[0])).length;
    state.latest.assets[0].size = size;
    state.tagged.assets[0].size = size;
  }, "checksum-mismatch");
  expectRejected((state) => {
    const checksum = join(state.assets, "SHA256SUMS.txt");
    writeFileSync(checksum, `${readFileSync(checksum, "utf8")}${"d".repeat(64)}  extra.exe\n`);
    const asset = state.latest.assets.find(({ name }) => name === "SHA256SUMS.txt");
    const tagged = state.tagged.assets.find(({ name }) => name === "SHA256SUMS.txt");
    asset.size = tagged.size = readFileSync(checksum).length;
  }, "checksum-count-invalid");
  expectRejected((state) => {
    const checksum = join(state.assets, "SHA256SUMS.txt");
    const value = readFileSync(checksum, "utf8").replace(packages[0], packages[0].toLowerCase());
    writeFileSync(checksum, value);
    const asset = state.latest.assets.find(({ name }) => name === "SHA256SUMS.txt");
    const tagged = state.tagged.assets.find(({ name }) => name === "SHA256SUMS.txt");
    asset.size = tagged.size = readFileSync(checksum).length;
  }, "checksum-inventory-invalid");
});

test("bridge release gate requires an annotated exact tag on main", () => {
  expectRejected((state) => { state.tagType = "commit"; }, "tag-not-annotated");
  expectRejected((state) => { state.tagCommit = "e".repeat(40); }, "tag-commit-mismatch");
  expectRejected((state) => { state.ancestor = "false"; }, "commit-not-main-ancestor");
});

test("bridge release gate rejects empty and malformed gzip tar packages", () => {
  expectRejected((state) => {
    writeFileSync(join(state.assets, packages[1]), Buffer.alloc(0));
    refreshIntegrity(state);
  }, "asset-size-zero");
  expectRejected((state) => {
    writeTarGz(join(state.assets, packages[1]), []);
    refreshIntegrity(state);
  }, "archive-empty");
  expectRejected((state) => {
    writeFileSync(join(state.assets, packages[1]), "not-a-gzip-tar");
    refreshIntegrity(state);
  }, "archive-gzip-invalid");
  expectRejected((state) => {
    writeFileSync(join(state.assets, packages[1]), gzipSync(Buffer.from("not-a-tar")));
    refreshIntegrity(state);
  }, "native-command-failed");
});

test("bridge release gate rejects traversal, absolute, duplicate, and linked entries", () => {
  expectRejected((state) => {
    replaceArchive(state, "linux", [
      ...archiveEntries("linux"),
      { name: "../escape", content: "escape\n" },
    ]);
  }, "archive-entry-name-unsafe");
  expectRejected((state) => {
    replaceArchive(state, "linux", [
      ...archiveEntries("linux"),
      { name: "/absolute", content: "escape\n" },
    ]);
  }, "archive-entry-name-unsafe");
  expectRejected((state) => {
    replaceArchive(state, "linux", [
      ...archiveEntries("linux"),
      { name: "hch-worker/VERSION", content: `${version}\n` },
    ]);
  }, "archive-entry-duplicate");
  expectRejected((state) => {
    replaceArchive(state, "linux", [
      ...archiveEntries("linux"),
      { name: "hch-worker/version", content: `${version}\n` },
    ]);
  }, "archive-entry-duplicate");
  expectRejected((state) => {
    replaceArchive(state, "linux", [
      ...archiveEntries("linux"),
      { name: "hch-worker/NUL", content: "unsafe\n" },
    ]);
  }, "archive-entry-name-unsafe");
  expectRejected((state) => {
    replaceArchive(state, "linux", [
      ...archiveEntries("linux"),
      {
        name: "hch-worker/linked-worker",
        type: "2",
        mode: 0o777,
        linkName: "ops/linux/editorial-worker/worker.mjs",
      },
    ]);
  }, "archive-link-or-special-entry");
});

test("bridge release gate requires exact version, platform layout, dashboard, and executable entrypoints", () => {
  expectRejected((state) => {
    replaceArchive(state, "linux", archiveEntries("linux", { version: "3.1.0" }));
  }, "archive-version-invalid");
  expectRejected((state) => {
    replaceArchive(
      state,
      "linux",
      archiveEntries("linux").filter(({ name }) => name !== "hch-worker/ops/worker-dashboard/server.mjs"),
    );
  }, "archive-layout-invalid");
  expectRejected((state) => {
    replaceArchive(
      state,
      "macos",
      archiveEntries("macos").filter(
        ({ name }) => name !== "hch-worker/ops/macos/editorial-worker/install-launch-agents.sh",
      ),
    );
  }, "archive-layout-invalid");
  expectRejected((state) => {
    replaceArchive(state, "linux", archiveEntries("linux", { workerMode: 0o644 }));
  }, "archive-entrypoint-not-executable");
});

test("bridge release gate forbids every offline bypass in GitHub Actions", () => {
  expectRejected(() => {}, "test-mode-forbidden-in-actions", [], { GITHUB_ACTIONS: "true" });
});

test("online path statically pins provenance, CMS policy, and the exact target", () => {
  const source = readFileSync(gatePath, "utf8");
  assert.match(source, /HUBTECH-DEV\/hch-worker/);
  assert.match(source, /Version -cne '3\.1\.1'/);
  assert.match(source, /--source-digest', \$ExpectedCommit/);
  assert.match(source, /--source-ref', 'refs\/heads\/main'/);
  assert.match(source, /--signer-workflow', "\$Repository\/\.github\/workflows\/bridge-package\.yml"/);
  assert.match(source, /Assert-WindowsPackageAuthenticode/);
  assert.match(source, /TimeStamperCertificate/);
  assert.match(source, /bridge-release-windows-authenticode-sha256-pin-mismatch/);
  assert.match(source, /--deny-self-hosted-runners/);
  assert.match(source, /cat-file', '-t'/);
  assert.match(source, /merge-base --is-ancestor/);
  assert.match(source, /SignedCms/);
  assert.match(source, /cms\.SignerInfos\.Count -ne 1/);
  assert.match(source, /1\.3\.6\.1\.5\.5\.7\.3\.3/);
  assert.match(source, /GetCertHash\(\[Security\.Cryptography\.HashAlgorithmName\]::SHA256\)/);
  assert.match(source, /bridge-release-test-bypass-forbidden-online/);
  assert.match(source, /Assert-AssetMetadataLimits/);
  assert.match(source, /Assert-GzipTarPackage/);
  assert.match(source, /archive-link-or-special-entry/);
  assert.match(source, /archive-entrypoint-not-executable/);
});
