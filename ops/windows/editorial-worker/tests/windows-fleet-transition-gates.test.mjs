import assert from "node:assert/strict";
import { createHash, randomUUID } from "node:crypto";
import { spawnSync } from "node:child_process";
import {
  closeSync,
  ftruncateSync,
  mkdtempSync,
  openSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "../../../..");
const validator = join(
  root,
  "scripts/windows/Test-HchWorkerFleetTransitionEvidence.ps1",
);
const signer = join(
  root,
  "scripts/windows/Sign-HchWorkerFleetTransitionEvidence.ps1",
);
const commit = "a".repeat(40);
const releaseId = "123456";
const heartbeatGapMilliseconds = 120_000;

const ps = (args) =>
  spawnSync("pwsh", ["-NoLogo", "-NoProfile", "-File", ...args], {
    encoding: "utf8",
  });
const iso = (date) => date.toISOString();
const sha = (value) => createHash("sha256").update(value).digest("hex");

function derivedSnapshotId(inventorySnapshotSha256) {
  const digest = sha(
    [
      "schema=hch.worker-fleet-inventory-snapshot-id/v1",
      `inventorySnapshotSha256=${inventorySnapshotSha256}`,
      "",
    ].join("\n"),
  );
  const uuidHex = `${digest.slice(0, 12)}8${digest.slice(13, 16)}8${digest.slice(17, 32)}`;
  return [
    uuidHex.slice(0, 8),
    uuidHex.slice(8, 12),
    uuidHex.slice(12, 16),
    uuidHex.slice(16, 20),
    uuidHex.slice(20, 32),
  ].join("-");
}

function derivedNodeId(value, inventoryMemberIndex) {
  return sha(
    [
      "schema=hch.worker-fleet-node-pseudonym/v1",
      `inventorySnapshotId=${value.inventorySnapshotId}`,
      `inventorySnapshotSha256=${value.inventorySnapshotSha256}`,
      `inventoryMemberIndex=${inventoryMemberIndex}`,
      "",
    ].join("\n"),
  );
}

function heartbeatReceipt(node, heartbeat) {
  const milliseconds = Date.parse(heartbeat.serverTime);
  return sha(
    [
      "schema=hch.worker-fleet-receipt/v1",
      "kind=accepted-bridge-heartbeat",
      `nodeIdHash=${node.nodeIdHash}`,
      `platform=${node.platform}`,
      `version=${node.version}`,
      `releaseDiscoveryProtocol=${node.releaseDiscoveryProtocol}`,
      `heartbeatRequestId=${heartbeat.requestId}`,
      `heartbeatServerTime=${milliseconds}`,
      "",
    ].join("\n"),
  );
}

function membershipReceipt(value, node) {
  return sha(
    [
      "schema=hch.worker-fleet-inventory-membership/v1",
      `inventorySnapshotId=${value.inventorySnapshotId}`,
      `inventorySnapshotSha256=${value.inventorySnapshotSha256}`,
      `inventoryMemberIndex=${node.inventoryMemberIndex}`,
      `nodeIdHash=${node.nodeIdHash}`,
      `platform=${node.platform}`,
      "",
    ].join("\n"),
  );
}

function inventoryProjection(value) {
  const members = value.nodes
    .map(
      (node) =>
        `${node.inventoryMemberIndex}|${node.nodeIdHash}|${node.platform}|${node.inventoryMembershipReceiptSha256}`,
    )
    .sort();
  return sha(
    [
      "schema=hch.worker-fleet-inventory-projection/v1",
      `inventorySnapshotId=${value.inventorySnapshotId}`,
      `inventorySnapshotSha256=${value.inventorySnapshotSha256}`,
      ...members.map((member) => `member=${member}`),
      "",
    ].join("\n"),
  );
}

function heartbeatSamples(node, startedAt, completedAt) {
  const samples = [];
  for (
    let timestamp = startedAt.getTime();
    timestamp < completedAt.getTime();
    timestamp += heartbeatGapMilliseconds
  ) {
    const heartbeat = {
      requestId: randomUUID(),
      serverTime: iso(new Date(timestamp)),
      receiptSha256: "",
    };
    heartbeat.receiptSha256 = heartbeatReceipt(node, heartbeat);
    samples.push(heartbeat);
  }
  if (
    samples.length === 0 ||
    Date.parse(samples.at(-1).serverTime) !== completedAt.getTime()
  ) {
    const heartbeat = {
      requestId: randomUUID(),
      serverTime: iso(completedAt),
      receiptSha256: "",
    };
    heartbeat.receiptSha256 = heartbeatReceipt(node, heartbeat);
    samples.push(heartbeat);
  }
  return samples;
}

function replaceNodeWindow(node, startedAt, completedAt) {
  node.heartbeatSamples = heartbeatSamples(node, startedAt, completedAt);
}

function evidence() {
  const commonEnd = new Date(Date.now() - 120_000);
  const commonStart = new Date(
    commonEnd.getTime() - 7 * 86_400_000 - 3_600_000,
  );
  const inventorySnapshotSha256 = sha(
    "authoritative-confidential-inventory",
  );
  const value = {
    schema: "hch.worker-fleet-transition/v1",
    status: "passed",
    sanitized: true,
    repository: "HUBTECH-DEV/hch-worker",
    bridgeTag: "v3.1.1",
    bridgeReleaseId: Number(releaseId),
    bridgeSourceCommit: commit,
    windowStartedAtUtc: iso(commonStart),
    windowCompletedAtUtc: iso(commonEnd),
    inventorySnapshotId: derivedSnapshotId(inventorySnapshotSha256),
    inventorySnapshotSha256,
    inventoryProjectionSha256: "",
    eligibleWorkerCount: 3,
    observedWorkerCount: 3,
    legacyLatestOnlyWorkerCount: 0,
    nodes: ["windows", "linux", "macos"].map((platform, index) => ({
      inventoryMemberIndex: index,
      nodeIdHash: "",
      inventoryMembershipReceiptSha256: "",
      platform,
      version: "3.1.1",
      releaseDiscoveryProtocol: "platform-release-list/v1",
      heartbeatSamples: [],
    })),
  };

  value.nodes.forEach((node, index) => {
    node.nodeIdHash = derivedNodeId(value, node.inventoryMemberIndex);
    node.inventoryMembershipReceiptSha256 = membershipReceipt(value, node);
    const startedAt = new Date(commonStart.getTime() - index * 60_000);
    const completedAt = new Date(commonEnd.getTime() + index * 30_000);
    replaceNodeWindow(node, startedAt, completedAt);
  });
  value.inventoryProjectionSha256 = inventoryProjection(value);
  return value;
}

function certificate(keyUsage = "DigitalSignature") {
  const script = `$c=New-SelfSignedCertificate -Subject 'CN=HCH Fleet Test ${randomUUID()}' -Type Custom -KeyAlgorithm RSA -KeyLength 2048 -HashAlgorithm SHA256 -KeyExportPolicy NonExportable -CertStoreLocation Cert:\\CurrentUser\\My -NotAfter (Get-Date).AddDays(2) -KeyUsage ${keyUsage} -TextExtension @('2.5.29.37={text}1.3.6.1.5.5.7.3.3'); $sha=[Convert]::ToHexString($c.GetCertHash([Security.Cryptography.HashAlgorithmName]::SHA256)); Write-Output "$($c.Thumbprint)|$sha"`;
  const result = spawnSync(
    "pwsh",
    ["-NoLogo", "-NoProfile", "-Command", script],
    { encoding: "utf8" },
  );
  assert.equal(result.status, 0, result.stderr);
  const [thumbprint, sha256] = result.stdout.trim().split("|");
  return { thumbprint, sha256 };
}

function removeCertificate(thumbprint) {
  spawnSync("pwsh", [
    "-NoLogo",
    "-NoProfile",
    "-Command",
    `Remove-Item -LiteralPath 'Cert:\\CurrentUser\\My\\${thumbprint}' -Force`,
  ]);
}

function signedRun(directory, value, cert) {
  const json = join(directory, `${randomUUID()}.json`);
  const signature = join(directory, `${randomUUID()}.p7s`);
  writeFileSync(json, JSON.stringify(value), "utf8");
  const sign = ps([
    signer,
    "-EvidencePath",
    json,
    "-EvidenceSignaturePath",
    signature,
    "-TelemetryAuthorityThumbprint",
    cert.thumbprint,
    "-ExpectedTelemetryAuthorityCertificateSha256",
    cert.sha256,
  ]);
  assert.equal(sign.status, 0, sign.stderr || sign.stdout);
  return {
    result: validateEvidence(json, signature, cert),
    json,
    signature,
  };
}

function validateEvidence(json, signature, cert) {
  return ps([
    validator,
    "-EvidencePath",
    json,
    "-EvidenceSignaturePath",
    signature,
    "-ExpectedTelemetryAuthorityThumbprint",
    cert.thumbprint,
    "-ExpectedTelemetryAuthorityCertificateSha256",
    cert.sha256,
    "-ExpectedBridgeReleaseId",
    releaseId,
    "-ExpectedBridgeSourceCommit",
    commit,
  ]);
}

function validateMutatedEvidence(directory, value, signature, cert) {
  const json = join(directory, `${randomUUID()}.json`);
  writeFileSync(json, JSON.stringify(value), "utf8");
  return validateEvidence(json, signature, cert);
}

test("fleet transition gate rejects oversized evidence before reading it", () => {
  const directory = mkdtempSync(join(tmpdir(), "hch-fleet-size-gate-"));
  try {
    const json = join(directory, "oversized.json");
    const signature = join(directory, "signature.p7s");
    const descriptor = openSync(json, "w");
    try {
      ftruncateSync(descriptor, 128 * 1024 * 1024 + 1);
    } finally {
      closeSync(descriptor);
    }
    writeFileSync(signature, "x", "utf8");
    const result = ps([
      validator,
      "-EvidencePath",
      json,
      "-EvidenceSignaturePath",
      signature,
      "-ExpectedTelemetryAuthorityThumbprint",
      "0".repeat(40),
      "-ExpectedTelemetryAuthorityCertificateSha256",
      "0".repeat(64),
      "-ExpectedBridgeReleaseId",
      releaseId,
      "-ExpectedBridgeSourceCommit",
      commit,
    ]);
    assert.notEqual(result.status, 0);
    assert.match(result.stderr + result.stdout, /between 1 byte and 134217728 bytes/i);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test(
  "fleet transition gate derives a real seven-day window for every inventoried node",
  (context) => {
    if (process.platform !== "win32") {
      return context.skip("Windows certificate store is required");
    }
    const probe = spawnSync(
      "pwsh",
      [
        "-NoLogo",
        "-NoProfile",
        "-Command",
        "Get-Command New-SelfSignedCertificate | Out-Null",
      ],
      { encoding: "utf8" },
    );
    if (probe.status !== 0) {
      return context.skip("certificate cmdlets unavailable");
    }

    const directory = mkdtempSync(join(tmpdir(), "hch-fleet-gate-"));
    const cert = certificate();
    context.after(() => {
      removeCertificate(cert.thumbprint);
      rmSync(directory, { recursive: true, force: true });
    });

    const signed = signedRun(directory, evidence(), cert);
    assert.equal(signed.result.status, 0, signed.result.stderr || signed.result.stdout);
    assert.match(signed.result.stdout, /3 derived workers/);
    assert.match(signed.result.stdout, /accepted heartbeats/);

    const failures = [
      [
        (value) => {
          value.legacyLatestOnlyWorkerCount = 1;
        },
        /counts.*no latest-only/i,
      ],
      [
        (value) => {
          value.nodes[0].heartbeatSamples[0].receiptSha256 = "0".repeat(64);
        },
        /Heartbeat receipt digest mismatch/i,
      ],
      [
        (value) => {
          value.nodes.pop();
          value.eligibleWorkerCount = 2;
          value.observedWorkerCount = 2;
        },
        /covering all platforms|Missing platform coverage/i,
      ],
      [
        (value) => {
          value.nodes[0].releaseDiscoveryProtocol = "latest-only";
        },
        /did not prove bridge discovery/i,
      ],
      [
        (value) => {
          value.nodes[0].heartbeatSamples =
            value.nodes[0].heartbeatSamples.slice(31);
        },
        /Every node.*at least seven days/i,
      ],
      [
        (value) => {
          const samples = value.nodes[0].heartbeatSamples;
          samples.splice(Math.floor(samples.length / 2), 1);
        },
        /stale gap greater than 120 seconds/i,
      ],
      [
        (value) => {
          const samples = value.nodes[0].heartbeatSamples;
          value.nodes[0].heartbeatSamples = [samples[0], samples.at(-1)];
        },
        /stale gap greater than 120 seconds/i,
      ],
      [
        (value) => {
          const samples = value.nodes[0].heartbeatSamples;
          // The root still claims the original seven-day fleet window, while
          // this node is represented only by its final observation.
          value.nodes[0].heartbeatSamples = [samples.at(-1)];
        },
        /between 2 and 20000 heartbeat samples|at least two samples/i,
      ],
      [
        (value) => {
          const shiftedStart = new Date(
            Date.parse(value.windowStartedAtUtc) - 2 * 3_600_000,
          );
          const shiftedEnd = new Date(
            Date.parse(value.windowCompletedAtUtc) - 2 * 3_600_000,
          );
          replaceNodeWindow(value.nodes[0], shiftedStart, shiftedEnd);
        },
        /derived common fleet window.*at least seven days/i,
      ],
      [
        (value) => {
          value.windowStartedAtUtc = iso(
            new Date(Date.parse(value.windowStartedAtUtc) - 1_000),
          );
        },
        /Declared fleet window.*derived/i,
      ],
      [
        (value) => {
          value.windowStartedAtUtc = value.windowStartedAtUtc.replace(
            /Z$/,
            "+00:00",
          );
        },
        /windowStartedAtUtc must be a JSON string exactly yyyy-MM-ddTHH:mm:ss\.fffZ/i,
      ],
      [
        (value) => {
          const heartbeat = value.nodes[0].heartbeatSamples[0];
          heartbeat.serverTime = heartbeat.serverTime.replace(/Z$/, "+00:00");
        },
        /heartbeatSamples\[0\]\.serverTime must be a JSON string exactly yyyy-MM-ddTHH:mm:ss\.fffZ/i,
      ],
      [
        (value) => {
          value.nodes[0].inventoryMembershipReceiptSha256 = "0".repeat(64);
        },
        /Inventory membership receipt digest mismatch/i,
      ],
      [
        (value) => {
          value.inventoryProjectionSha256 = "0".repeat(64);
        },
        /Inventory projection digest mismatch/i,
      ],
      [
        (value) => {
          value.inventorySnapshotSha256 = sha("different-snapshot");
        },
        /inventorySnapshotId must be the UUIDv8 derived/i,
      ],
      [
        (value) => {
          value.inventorySnapshotId = randomUUID();
        },
        /inventorySnapshotId must be the UUIDv8 derived/i,
      ],
      [
        (value) => {
          value.nodes[0].nodeIdHash = "0".repeat(64);
        },
        /nodeIdHash must be derived/i,
      ],
      [
        (value) => {
          value.nodes[1].inventoryMemberIndex = 0;
        },
        /Duplicate inventoryMemberIndex/i,
      ],
      [
        (value) => {
          value.nodes[0].inventoryMemberIndex = "0";
        },
        /inventoryMemberIndex must be an exact JSON integer/i,
      ],
      [
        (value) => {
          value.nodes = Array.from({ length: 65 }, () => ({}));
        },
        /nodes exceeds the maximum of 64 entries/i,
      ],
      [
        (value) => {
          value.nodes[0].heartbeatSamples = Array.from(
            { length: 20_001 },
            () => ({}),
          );
        },
        /between 2 and 20000 heartbeat samples/i,
      ],
      [
        (value) => {
          value.bridgeReleaseId = releaseId;
        },
        /bridgeReleaseId must be an exact JSON integer/i,
      ],
      [
        (value) => {
          value.eligibleWorkerCount = "3";
        },
        /eligibleWorkerCount must be an exact JSON integer/i,
      ],
      [
        (value) => {
          value.nodes[1].heartbeatSamples[0].receiptSha256 =
            value.nodes[0].heartbeatSamples[0].receiptSha256;
        },
        /Duplicate heartbeat receiptSha256/i,
      ],
      [
        (value) => {
          value.Schema = value.schema;
          delete value.schema;
        },
        /Unexpected or missing property/i,
      ],
      [
        (value) => {
          value.nodes[0].nodeId = "raw-node-id-must-not-be-accepted";
        },
        /Unexpected or missing property/i,
      ],
      [
        (value) => {
          const sample = value.nodes[0].heartbeatSamples[0];
          sample.ServerTime = sample.serverTime;
          delete sample.serverTime;
        },
        /Unexpected or missing property/i,
      ],
    ];

    for (const [mutate, expected] of failures) {
      const value = evidence();
      mutate(value);
      // Semantic validation intentionally precedes CMS validation. Reusing the
      // valid detached signature keeps this exhaustive negative matrix fast;
      // the exact expected diagnostic proves the semantic gate fired before
      // the inevitable signature mismatch.
      const result = validateMutatedEvidence(
        directory,
        value,
        signed.signature,
        cert,
      );
      assert.notEqual(result.status, 0);
      assert.match(result.stderr + result.stdout, expected);
    }

    const tamperedJson = join(directory, `${randomUUID()}.json`);
    writeFileSync(tamperedJson, JSON.stringify(evidence()), "utf8");
    const rejected = validateEvidence(
      tamperedJson,
      signed.signature,
      cert,
    );
    assert.notEqual(rejected.status, 0);
    assert.match(
      rejected.stderr + rejected.stdout,
      /does not authenticate exact evidence bytes/i,
    );
  },
);

test(
  "fleet transition signer rejects a certificate without digital-signature Key Usage",
  (context) => {
    if (process.platform !== "win32") {
      return context.skip("Windows certificate store is required");
    }
    const probe = spawnSync(
      "pwsh",
      [
        "-NoLogo",
        "-NoProfile",
        "-Command",
        "Get-Command New-SelfSignedCertificate | Out-Null",
      ],
      { encoding: "utf8" },
    );
    if (probe.status !== 0) {
      return context.skip("certificate cmdlets unavailable");
    }

    const directory = mkdtempSync(join(tmpdir(), "hch-fleet-key-usage-"));
    const cert = certificate("KeyEncipherment");
    context.after(() => {
      removeCertificate(cert.thumbprint);
      rmSync(directory, { recursive: true, force: true });
    });
    const json = join(directory, "fleet.json");
    const signature = join(directory, "fleet.p7s");
    writeFileSync(json, JSON.stringify(evidence()), "utf8");
    const result = ps([
      signer,
      "-EvidencePath",
      json,
      "-EvidenceSignaturePath",
      signature,
      "-TelemetryAuthorityThumbprint",
      cert.thumbprint,
      "-ExpectedTelemetryAuthorityCertificateSha256",
      cert.sha256,
    ]);
    assert.notEqual(result.status, 0);
    assert.match(
      result.stderr + result.stdout,
      /Key Usage does not allow digital signatures/i,
    );
  },
);
