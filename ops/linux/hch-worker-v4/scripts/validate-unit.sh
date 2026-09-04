#!/bin/sh
set -eu

command -v systemd-analyze >/dev/null 2>&1 || {
  echo "systemd-analyze is required to validate the unit" >&2
  exit 1
}

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
unit=${1:-"$script_dir/../systemd/hch-worker.service"}
[ -f "$unit" ] || { echo "unit not found: $unit" >&2; exit 1; }

staging=$(mktemp -d)
trap 'rm -rf -- "$staging"' EXIT HUP INT TERM

# systemd-analyze checks whether an absolute ExecStart exists on the validating
# host. Replace only the known staged payload path; all other directives remain
# byte-for-byte equivalent for syntax and dependency validation.
sed 's|/opt/hch-worker/current/Hch.Worker.Service|/bin/true|g' \
  "$unit" >"$staging/hch-worker.service"

if cmp -s "$unit" "$staging/hch-worker.service"; then
  echo "unit does not contain the expected staged ExecStart path" >&2
  exit 1
fi

systemd-analyze verify "$staging/hch-worker.service"
echo "systemd unit valid (ExecStart substituted only for staging validation)"
