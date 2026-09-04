#!/bin/sh
set -eu
umask 077

usage() {
  echo "usage: $0 --payload DIR --version 4.0.0[-suffix] --config FILE [--enable-now]" >&2
  exit 2
}

payload= version= config= enable_now=no
while [ "$#" -gt 0 ]; do
  case $1 in
    --payload) [ "$#" -ge 2 ] || usage; payload=$2; shift 2 ;;
    --version) [ "$#" -ge 2 ] || usage; version=$2; shift 2 ;;
    --config) [ "$#" -ge 2 ] || usage; config=$2; shift 2 ;;
    --enable-now) enable_now=yes; shift ;;
    *) usage ;;
  esac
done

[ "$(id -u)" -eq 0 ] || { echo "install must run as root" >&2; exit 1; }
[ -n "$payload" ] && [ -d "$payload" ] || usage
[ -n "$config" ] && [ -f "$config" ] || usage
printf '%s\n' "$version" | grep -Eq '^4\.0\.0(-[A-Za-z0-9][A-Za-z0-9.-]*)?$' || {
  echo "version must be a 4.0.0 candidate" >&2
  exit 1
}
[ -x "$payload/Hch.Worker.Service" ] || { echo "payload lacks executable Hch.Worker.Service" >&2; exit 1; }
if find "$payload" -type l -print -quit | grep -q .; then
  echo "payload must not contain symbolic links" >&2
  exit 1
fi

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
bundle_dir=$(CDPATH= cd -- "$script_dir/.." && pwd)
"$script_dir/validate-config.sh" "$config"
if [ -e /etc/hch-worker/config.json ]; then
  "$script_dir/validate-config.sh" /etc/hch-worker/config.json
fi
if systemctl is-active --quiet hch-worker.service 2>/dev/null; then
  echo "refusing install while worker is active; first place it in Paused/Drain and stop the service" >&2
  exit 1
fi

if ! getent group hch-worker >/dev/null 2>&1; then
  groupadd --system hch-worker
fi
if ! getent passwd hch-worker >/dev/null 2>&1; then
  useradd --system --gid hch-worker --home-dir /var/lib/hch-worker --shell /usr/sbin/nologin hch-worker
fi

install -d -o root -g root -m 0755 /opt/hch-worker /opt/hch-worker/releases
install -d -o root -g hch-worker -m 0750 /etc/hch-worker /etc/hch-worker/trust
install -d -o hch-worker -g hch-worker -m 0700 /var/lib/hch-worker /var/lib/hch-worker/state /var/log/hch-worker

release=/opt/hch-worker/releases/$version
[ ! -e "$release" ] || { echo "release already exists: $release" >&2; exit 1; }
staging=/opt/hch-worker/releases/.$version.staging.$$
link_tmp=/opt/hch-worker/.current.$$
cleanup() { rm -rf -- "$staging"; rm -f -- "$link_tmp"; }
trap cleanup EXIT HUP INT TERM
install -d -o root -g root -m 0755 "$staging"
cp -a -- "$payload/." "$staging/"
chown -R root:root "$staging"
find "$staging" -type d -exec chmod 0755 {} +
find "$staging" -type f -exec chmod go-w {} +
chmod 0755 "$staging/Hch.Worker.Service"
mv -- "$staging" "$release"

if [ -e /etc/hch-worker/config.json ]; then
  echo "existing configuration preserved" >&2
else
  install -o root -g hch-worker -m 0640 "$config" /etc/hch-worker/config.json
fi
if [ ! -e /etc/hch-worker/environment ]; then
  install -o root -g hch-worker -m 0640 "$bundle_dir/config/environment" /etc/hch-worker/environment
fi
install -o root -g root -m 0644 "$bundle_dir/systemd/hch-worker.service" /etc/systemd/system/hch-worker.service
install -d -o root -g root -m 0755 /usr/share/doc/hch-worker
install -o root -g root -m 0644 "$bundle_dir/README.md" /usr/share/doc/hch-worker/README.md

ln -s -- "releases/$version" "$link_tmp"
mv -Tf -- "$link_tmp" /opt/hch-worker/current
trap - EXIT HUP INT TERM

systemctl daemon-reload
if [ "$enable_now" = yes ]; then
  systemctl enable --now hch-worker.service
else
  echo "installed but not enabled; validate Paused/Drain before activation"
fi
