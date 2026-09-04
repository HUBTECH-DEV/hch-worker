#!/bin/sh
set -eu
umask 077

[ "$(id -u)" -eq 0 ] || { echo "rollback must run as root" >&2; exit 1; }
[ "$#" -eq 1 ] || { echo "usage: $0 VERSION" >&2; exit 2; }
version=$1
printf '%s\n' "$version" | grep -Eq '^4\.0\.0(-[A-Za-z0-9][A-Za-z0-9.-]*)?$' || {
  echo "invalid rollback version" >&2
  exit 1
}
target=/opt/hch-worker/releases/$version
[ -x "$target/Hch.Worker.Service" ] || { echo "rollback target is not installed" >&2; exit 1; }

if systemctl is-active --quiet hch-worker.service; then
  echo "refusing rollback while worker is active; first place it in Paused/Drain and stop the service" >&2
  exit 1
fi

previous=$(readlink /opt/hch-worker/current 2>/dev/null || true)
link_tmp=/opt/hch-worker/.current.$$
trap 'rm -f -- "$link_tmp"' EXIT HUP INT TERM
ln -s -- "releases/$version" "$link_tmp"
mv -Tf -- "$link_tmp" /opt/hch-worker/current
trap - EXIT HUP INT TERM

echo "current release changed from ${previous:-unknown} to releases/$version"
echo "state and configuration were preserved; start only after validating Paused/Drain"
