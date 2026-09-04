#!/bin/sh
set -eu

root=${HCH_INSTALL_ROOT:-}
prefix() { printf '%s%s' "$root" "$1"; }

config=$(prefix /etc/hch-worker/config.json)
unit=$(prefix /etc/systemd/system/hch-worker.service)
current=$(prefix /opt/hch-worker/current)
state=$(prefix /var/lib/hch-worker)

[ -f "$unit" ] || { echo "unit missing: $unit" >&2; exit 1; }
[ -f "$config" ] || { echo "configuration missing: $config" >&2; exit 1; }
[ -L "$current" ] || { echo "current release link missing: $current" >&2; exit 1; }
[ -x "$current/Hch.Worker.Service" ] || { echo "worker executable missing" >&2; exit 1; }
[ -d "$state" ] || { echo "state directory missing" >&2; exit 1; }

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
"$script_dir/validate-config.sh" "$config"

if [ -z "$root" ] && command -v systemd-analyze >/dev/null 2>&1; then
  systemd-analyze verify "$unit"
fi

echo "installation layout valid"
