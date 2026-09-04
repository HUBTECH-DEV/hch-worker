#!/bin/sh
set -eu

bundle=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
tmp=$(mktemp -d)
trap 'rm -rf -- "$tmp"' EXIT HUP INT TERM

for script in "$bundle"/scripts/*.sh; do
  sh -n "$script"
done

grep -q '^Environment=HCH_WORKER_CONFIG_PATH=/etc/hch-worker/config.json$' "$bundle/systemd/hch-worker.service"
grep -q '^User=hch-worker$' "$bundle/systemd/hch-worker.service"
grep -q '^NoNewPrivileges=yes$' "$bundle/systemd/hch-worker.service"
grep -q '^ProtectSystem=strict$' "$bundle/systemd/hch-worker.service"
grep -q '^CapabilityBoundingSet=$' "$bundle/systemd/hch-worker.service"
grep -q '^ReadWritePaths=/var/lib/hch-worker /run/hch-worker /var/log/hch-worker$' "$bundle/systemd/hch-worker.service"

if command -v systemd-analyze >/dev/null 2>&1; then
  "$bundle/scripts/validate-unit.sh" "$bundle/systemd/hch-worker.service"
fi

if "$bundle/scripts/validate-config.sh" "$bundle/config/config.example.json" >/dev/null 2>&1; then
  echo "example with enrollment placeholders was unexpectedly accepted" >&2
  exit 1
fi

sed 's/REPLACE_WITH_ENROLLED_NODE_ID/test-node/; s/REPLACE_WITH_WORKER_PUBLIC_KEY_ID/test-key/' \
  "$bundle/config/config.example.json" >"$tmp/config.json"
"$bundle/scripts/validate-config.sh" "$tmp/config.json"

python3 - "$tmp/config.json" "$tmp/unsafe.json" <<'PY'
import json, sys
value = json.load(open(sys.argv[1], encoding="utf-8"))
value["claimBatchSize"] = 2
json.dump(value, open(sys.argv[2], "w", encoding="utf-8"))
PY
if "$bundle/scripts/validate-config.sh" "$tmp/unsafe.json" >/dev/null 2>&1; then
  echo "unsafe initial concurrency was unexpectedly accepted" >&2
  exit 1
fi

echo "Linux packaging static tests passed"
