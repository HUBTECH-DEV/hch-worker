#!/bin/sh
set -eu

[ "$(id -u)" -eq 0 ] || { echo "uninstall must run as root" >&2; exit 1; }
[ "${1:-}" = "--preserve-state" ] || {
  echo "usage: $0 --preserve-state" >&2
  echo "destructive state removal is intentionally unsupported" >&2
  exit 2
}

systemctl disable --now hch-worker.service 2>/dev/null || true
rm -f -- /etc/systemd/system/hch-worker.service
systemctl daemon-reload

echo "service unit removed; /opt/hch-worker, /etc/hch-worker and /var/lib/hch-worker were preserved"
