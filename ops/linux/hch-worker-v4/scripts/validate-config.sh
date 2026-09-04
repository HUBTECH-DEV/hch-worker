#!/bin/sh
set -eu

config=${1:-/etc/hch-worker/config.json}

if [ ! -f "$config" ]; then
  echo "configuration not found: $config" >&2
  exit 1
fi

python3 - "$config" <<'PY'
import json
import pathlib
import re
import sys
from urllib.parse import urlsplit

path = pathlib.Path(sys.argv[1])
try:
    raw = path.read_bytes()
    if len(raw) > 1024 * 1024:
        raise ValueError("configuration exceeds 1 MiB")
    value = json.loads(raw)
except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
    raise SystemExit(f"invalid configuration: {exc}")

expected = {
    "schemaVersion", "nodeId", "workerName", "keyId", "ownerSid",
    "rootKeyId", "rootPublicKeyFingerprint", "rootPublicKeyPath",
    "orchestratorBaseUri", "ollamaBaseUri", "lastNonZeroMaxConcurrentJobs",
    "claimBatchSize", "manifestCapacityLimit", "localResourceLimit", "stateRoot",
}
if not isinstance(value, dict) or set(value) != expected:
    raise SystemExit("invalid configuration: fields do not match schema v1")
if value["schemaVersion"] != 1:
    raise SystemExit("invalid configuration: schemaVersion must be 1")

identifier = re.compile(r"^[A-Za-z0-9._:/-]+$")
for field, maximum in (("nodeId", 128), ("keyId", 256)):
    item = value[field]
    if not isinstance(item, str) or not item or len(item) > maximum or not identifier.fullmatch(item):
        raise SystemExit(f"invalid configuration: {field}")
if value["nodeId"].startswith("REPLACE_") or value["keyId"].startswith("REPLACE_"):
    raise SystemExit("invalid configuration: enrollment placeholders remain")
if not isinstance(value["workerName"], str) or not value["workerName"].strip() or len(value["workerName"]) > 160:
    raise SystemExit("invalid configuration: workerName")
if value["ownerSid"] is not None:
    raise SystemExit("invalid configuration: ownerSid must be null on Linux")

orchestrator = urlsplit(value["orchestratorBaseUri"])
if orchestrator.scheme != "https" or not orchestrator.hostname or orchestrator.username or orchestrator.password or orchestrator.path != "/" or orchestrator.query or orchestrator.fragment:
    raise SystemExit("invalid configuration: orchestratorBaseUri must be an HTTPS origin")
ollama = urlsplit(value["ollamaBaseUri"])
if ollama.scheme != "http" or ollama.hostname not in {"127.0.0.1", "::1", "localhost"} or ollama.username or ollama.password or ollama.path != "/" or ollama.query or ollama.fragment:
    raise SystemExit("invalid configuration: Ollama must be loopback HTTP")

for field in ("lastNonZeroMaxConcurrentJobs", "claimBatchSize", "manifestCapacityLimit", "localResourceLimit"):
    if type(value[field]) is not int or not 1 <= value[field] <= 64:
        raise SystemExit(f"invalid configuration: {field}")
if value["lastNonZeroMaxConcurrentJobs"] != 1 or value["claimBatchSize"] != 1:
    raise SystemExit("unsafe candidate configuration: initial concurrency and claim batch must be 1")
if value["stateRoot"] != "/var/lib/hch-worker/state":
    raise SystemExit("invalid configuration: stateRoot must use the managed FHS path")

trust = [value["rootKeyId"], value["rootPublicKeyFingerprint"], value["rootPublicKeyPath"]]
if any(item is not None for item in trust):
    if any(item is None for item in trust):
        raise SystemExit("invalid configuration: root trust pins are all-or-none")
    if not isinstance(trust[0], str) or not trust[0] or len(trust[0]) > 160 or not identifier.fullmatch(trust[0]):
        raise SystemExit("invalid configuration: rootKeyId")
    if not isinstance(trust[1], str) or not re.fullmatch(r"SHA256:[A-Za-z0-9_-]{43}", trust[1]):
        raise SystemExit("invalid configuration: rootPublicKeyFingerprint")
    if trust[2] != "/etc/hch-worker/trust/orchestrator-root.pem":
        raise SystemExit("invalid configuration: rootPublicKeyPath must use the managed trust path")

print(f"configuration valid: {path}")
PY
