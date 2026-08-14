import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { once } from "node:events";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

const testDirectory = dirname(fileURLToPath(import.meta.url));
const kitRoot = resolve(testDirectory, "..");
const modulePath = join(kitRoot, "Hch.EditorialWorker.psm1");
const fixturePath = join(testDirectory, "fixtures", "stalling-transport-server.mjs");

test("control-plane HTTP operations share one cancellable wall-clock deadline", async (context) => {
  if (process.platform !== "win32") return context.skip("Windows PowerShell integration test");
  const fixture = spawn(process.execPath, [fixturePath], {
    stdio: ["ignore", "pipe", "pipe"],
    windowsHide: true,
  });
  try {
    const endpoints = JSON.parse(await firstLine(fixture.stdout));
    for (const path of ["stalled-headers", "stalled-body"]) {
      const result = invokePrivatePowerShell(`
        $timer=[Diagnostics.Stopwatch]::StartNew()
        $errorCode=$null
        try {
          & $m { param($uri) Invoke-HchHttpJson -Method POST -Uri $uri -TimeoutSeconds 1 } ([Uri]'http://127.0.0.1:${endpoints.httpPort}/${path}') | Out-Null
        } catch { $errorCode=$_.Exception.Message }
        $timer.Stop()
        @{ errorCode=$errorCode; elapsedMilliseconds=$timer.ElapsedMilliseconds }
      `);
      assert.equal(result.errorCode, "http-request-timeout");
      assert.ok(result.elapsedMilliseconds >= 700, `${path} returned too early`);
      assert.ok(result.elapsedMilliseconds < 4_000, `${path} exceeded its wall-clock deadline`);
    }
  } finally {
    fixture.kill("SIGTERM");
    await Promise.race([once(fixture, "exit"), delay(2_000)]);
    if (fixture.exitCode === null) fixture.kill("SIGKILL");
  }
});

test("TLS observation cancels a handshake that stops after TCP connect", async (context) => {
  if (process.platform !== "win32") return context.skip("Windows PowerShell integration test");
  const fixture = spawn(process.execPath, [fixturePath], {
    stdio: ["ignore", "pipe", "pipe"],
    windowsHide: true,
  });
  try {
    const endpoints = JSON.parse(await firstLine(fixture.stdout));
    const result = invokePrivatePowerShell(`
      $timer=[Diagnostics.Stopwatch]::StartNew()
      $observation=& $m { param($uri) Get-HchTlsObservation -Uri $uri -TimeoutSeconds 1 } ([Uri]'https://127.0.0.1:${endpoints.tlsPort}/')
      $timer.Stop()
      @{ observation=$observation; elapsedMilliseconds=$timer.ElapsedMilliseconds }
    `);
    assert.equal(result.observation.tlsStatus, "error");
    assert.equal(result.observation.errorCode, "tls-handshake-timeout");
    assert.ok(result.elapsedMilliseconds >= 700, "TLS handshake returned too early");
    assert.ok(result.elapsedMilliseconds < 4_000, "TLS handshake exceeded its wall-clock deadline");
  } finally {
    fixture.kill("SIGTERM");
    await Promise.race([once(fixture, "exit"), delay(2_000)]);
    if (fixture.exitCode === null) fixture.kill("SIGKILL");
  }
});

test("artifact streaming is cancelled when the body stops making progress", async (context) => {
  if (process.platform !== "win32") return context.skip("Windows PowerShell integration test");
  const fixture = spawn(process.execPath, [fixturePath], {
    stdio: ["ignore", "pipe", "pipe"],
    windowsHide: true,
  });
  try {
    const endpoints = JSON.parse(await firstLine(fixture.stdout));
    const destination = join(mkdtempSync(join(tmpdir(), "hch-http-timeout-")), "artifact.partial");
    const escapedDestination = destination.replaceAll("'", "''");
    const result = invokePrivatePowerShell(`
      $timer=[Diagnostics.Stopwatch]::StartNew()
      $errorCode=$null
      try {
        & $m { param($uri,$destination) Save-HchRemoteFile -Uri $uri -Destination $destination -TimeoutSeconds 1 } ([Uri]'http://127.0.0.1:${endpoints.httpPort}/stalled-body') '${escapedDestination}'
      } catch { $errorCode=$_.Exception.Message }
      $timer.Stop()
      @{ errorCode=$errorCode; elapsedMilliseconds=$timer.ElapsedMilliseconds }
    `);
    assert.equal(result.errorCode, "artifact-download-timeout");
    assert.ok(result.elapsedMilliseconds >= 700, "artifact download returned too early");
    assert.ok(result.elapsedMilliseconds < 4_000, "artifact download exceeded its wall-clock deadline");
  } finally {
    fixture.kill("SIGTERM");
    await Promise.race([once(fixture, "exit"), delay(2_000)]);
    if (fixture.exitCode === null) fixture.kill("SIGKILL");
  }
});

test("GET sends no entity headers while POST keeps its canonical JSON body", async (context) => {
  if (process.platform !== "win32") return context.skip("Windows PowerShell integration test");
  const fixture = spawn(process.execPath, [fixturePath], {
    stdio: ["ignore", "pipe", "pipe"],
    windowsHide: true,
  });
  try {
    const endpoints = JSON.parse(await firstLine(fixture.stdout));
    const result = invokePrivatePowerShell(`
      $uri=[Uri]'http://127.0.0.1:${endpoints.httpPort}/echo'
      $get=& $m { param($uri) Invoke-HchHttpJson -Method GET -Uri $uri -TimeoutSeconds 2 } $uri
      $postBytes=[Text.Encoding]::UTF8.GetBytes('{"value":"unchanged"}')
      $post=& $m { param($uri,$bytes) Invoke-HchHttpJson -Method POST -Uri $uri -BodyBytes $bytes -TimeoutSeconds 2 } $uri $postBytes
      @{ get=$get; post=$post }
    `);
    assert.deepEqual(result.get, { method: "GET", body: "", contentType: null });
    assert.deepEqual(result.post, {
      method: "POST",
      body: '{"value":"unchanged"}',
      contentType: "application/json",
    });
  } finally {
    fixture.kill("SIGTERM");
    await Promise.race([once(fixture, "exit"), delay(2_000)]);
    if (fixture.exitCode === null) fixture.kill("SIGKILL");
  }
});

test("all Windows control-plane and artifact paths forward bounded timeouts", () => {
  const source = readFileSync(modulePath, "utf8");
  const unsignedStart = source.indexOf("function Invoke-HchUnsignedJsonRequest");
  const unsignedEnd = source.indexOf("function Get-HchChallenge", unsignedStart);
  const artifactStart = source.indexOf("function Save-HchRemoteFile");
  const artifactEnd = source.indexOf("function Stage-HchManifestArtifacts", artifactStart);
  assert.match(source.slice(unsignedStart, unsignedEnd), /-TimeoutSeconds \$TimeoutSeconds -ControlPlaneTransport/);
  assert.match(source, /AuthenticateAsClientAsync/);
  assert.doesNotMatch(source, /\.AuthenticateAsClient\(/);
  assert.match(source.slice(artifactStart, artifactEnd), /CopyToAsync\([^\n]+\$cancellation\.Token\)/);
  assert.match(source, /ArtifactDownloadTimeoutSeconds/);
  assert.match(source, /control-plane-request-timeout/);
  assert.match(source, /if \(\$Method -eq 'POST'\) \{/);
  assert.match(source, /http-get-body-refused/);
});

function invokePrivatePowerShell(body) {
  const escapedModule = modulePath.replaceAll("'", "''");
  const script = `
    $ErrorActionPreference='Stop'
    $m=Import-Module '${escapedModule}' -Force -PassThru
    $result=& {
      ${body}
    }
    [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes(($result|ConvertTo-Json -Depth 20 -Compress)))
  `;
  const execution = spawnSync(
    "powershell.exe",
    ["-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script],
    { encoding: "utf8", timeout: 10_000, windowsHide: true },
  );
  assert.equal(execution.status, 0, `${execution.stdout}${execution.stderr}`);
  return JSON.parse(Buffer.from(execution.stdout.trim(), "base64").toString("utf8"));
}

async function firstLine(stream) {
  let buffered = "";
  for await (const chunk of stream) {
    buffered += chunk.toString("utf8");
    const newline = buffered.indexOf("\n");
    if (newline >= 0) return buffered.slice(0, newline);
  }
  throw new Error("transport fixture exited before reporting its ports");
}

function delay(milliseconds) {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}
