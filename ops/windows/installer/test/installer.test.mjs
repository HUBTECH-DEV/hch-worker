import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");

test("Setup keeps enrollment secrets out of process arguments", () => {
  const source = readFileSync(join(root, "HchWorkerSetup.cs"), "utf8");
  assert.match(source, /WritePrivateFile\(responsePath/);
  const argumentsBlock = source.slice(source.indexOf("Arguments ="), source.indexOf("UseShellExecute"));
  assert.doesNotMatch(argumentsBlock, /token|enrollment/i);
  assert.match(source, /FileSystemRights\.FullControl/);
  assert.match(source, /Confio na HUBTECH como publicadora/);
});

test("package installer always removes the machine enrollment token", () => {
  const source = readFileSync(join(root, "Install-HchWorkerPackage.ps1"), "utf8");
  assert.match(source, /finally\s*\{[\s\S]*SetEnvironmentVariable\('HCH_EDITORIAL_ENROLLMENT_TOKEN', \$priorToken/);
  assert.match(source, /Remove-Item -LiteralPath \$responseFile/);
  assert.match(source, /-Parallelism 0/);
  assert.match(source, /TrustedPublisher/);
});

test("build requires signed Node and emits a winget SHA-256 manifest", () => {
  const source = readFileSync(join(root, "Build-HchWorkerSetup.ps1"), "utf8");
  assert.match(source, /nodeSignature\.Status.*Valid/);
  assert.match(source, /InstallerSha256: \$sha256/);
  assert.match(source, /Hubtech\.HCHWorker/);
  assert.ok(existsSync(join(root, "HchWorkerSetup.exe.manifest")));
});
