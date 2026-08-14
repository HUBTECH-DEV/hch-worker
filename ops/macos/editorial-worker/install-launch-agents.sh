#!/bin/sh
set -eu

kit_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
runtime_root=${HCH_RUNTIME_ROOT:-}
config_path=${HCH_WORKER_CONFIG:-}
node_bin=${HCH_NODE_BIN:-}

usage() {
  echo "usage: HCH_RUNTIME_ROOT=/absolute/runtime HCH_WORKER_CONFIG=/absolute/config HCH_NODE_BIN=/absolute/node ./install-launch-agents.sh" >&2
  exit 2
}

case "${runtime_root}" in /*) ;; *) usage ;; esac
case "${config_path}" in /*) ;; *) usage ;; esac
case "${node_bin}" in /*) ;; *) usage ;; esac
test -d "${runtime_root}"
test -r "${config_path}"
test -x "${node_bin}"
case "${runtime_root}${config_path}${node_bin}${HOME}" in
  *[!A-Za-z0-9_./\ -]*) echo "paths-contain-unsupported-characters" >&2; exit 2 ;;
esac

agents_dir="${HOME}/Library/LaunchAgents"
logs_dir="${HOME}/Library/Logs/HCH"
mkdir -p "${agents_dir}" "${logs_dir}"
chmod 700 "${agents_dir}" 2>/dev/null || true

runtime_xml=${runtime_root}
config_xml=${config_path}
node_xml=${node_bin}
logs_xml=${logs_dir}
domain="gui/$(id -u)"

for template in "${kit_dir}"/launchd/online.hubtech.hch.editorial-worker.bootstrap.plist.in \
                "${kit_dir}"/launchd/online.hubtech.hch.editorial-worker.cycle.plist.in; do
  name=$(basename "${template}" .in)
  destination="${agents_dir}/${name}"
  patch_file=$(mktemp "${TMPDIR:-/tmp}/hch-launchd.XXXXXX")
  trap 'rm -f "${patch_file}"' EXIT HUP INT TERM
  sed \
    -e "s|__HCH_RUNTIME_ROOT__|${runtime_xml}|g" \
    -e "s|__HCH_CONFIG_PATH__|${config_xml}|g" \
    -e "s|__HCH_NODE_BIN__|${node_xml}|g" \
    -e "s|__HCH_LOG_ROOT__|${logs_xml}|g" \
    "${template}" > "${patch_file}"
  chmod 600 "${patch_file}"
  /usr/bin/plutil -lint "${patch_file}" >/dev/null
  mv "${patch_file}" "${destination}"
  trap - EXIT HUP INT TERM
  label=$(basename "${name}" .plist)
  /bin/launchctl bootout "${domain}/${label}" >/dev/null 2>&1 || true
  /bin/launchctl bootstrap "${domain}" "${destination}"
done

# Since 3.1.0 the long-lived cycle process owns presence heartbeats. Retire the
# legacy standalone agent so one node never publishes competing heartbeats.
legacy_label=online.hubtech.hch.editorial-worker.heartbeat
/bin/launchctl bootout "${domain}/${legacy_label}" >/dev/null 2>&1 || true
rm -f "${agents_dir}/${legacy_label}.plist"

printf '%s\n' '{"ok":true,"state":"installed-draining","automaticPublication":false}'
