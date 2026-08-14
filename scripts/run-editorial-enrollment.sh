#!/bin/sh
set -eu
PATH=/usr/sbin:/usr/bin:/sbin:/bin

HCH_EDITORIAL_NODE_BIN=${HCH_EDITORIAL_NODE_BIN:-/usr/local/libexec/hch-node}
HCH_EDITORIAL_WORKER_ENTRYPOINT=${HCH_EDITORIAL_WORKER_ENTRYPOINT:-/usr/local/libexec/hch-editorial-runtime/ops/linux/editorial-worker/worker.mjs}
HCH_EDITORIAL_WORKER_CONFIG=${HCH_EDITORIAL_WORKER_CONFIG:-/etc/hch-editorial-worker/config.json}
HCH_EDITORIAL_WORKER_USER=${HCH_EDITORIAL_WORKER_USER:-hch-editorial-worker}
HCH_EDITORIAL_WORKER_GROUP=${HCH_EDITORIAL_WORKER_GROUP:-hch-editorial-worker}
HCH_EDITORIAL_RUNUSER_BIN=${HCH_EDITORIAL_RUNUSER_BIN:-/usr/sbin/runuser}
HCH_EDITORIAL_ENV_BIN=${HCH_EDITORIAL_ENV_BIN:-/usr/bin/env}
runtime_directory=/run/hch-editorial-worker
credential_path=
echo_disabled=0

cleanup() {
  if [ "${echo_disabled}" -eq 1 ]; then
    stty echo 2>/dev/null || true
    echo_disabled=0
  fi
  if [ -n "${credential_path}" ]; then
    rm -f -- "${credential_path}"
  fi
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

if [ "$(id -u)" -ne 0 ]; then
  echo "enrollment-requires-root" >&2
  exit 1
fi
test -x "${HCH_EDITORIAL_NODE_BIN}"
test -f "${HCH_EDITORIAL_WORKER_ENTRYPOINT}"
test -r "${HCH_EDITORIAL_WORKER_CONFIG}"
test -x "${HCH_EDITORIAL_RUNUSER_BIN}"
test -x "${HCH_EDITORIAL_ENV_BIN}"

install -d -m 0700 -o "${HCH_EDITORIAL_WORKER_USER}" -g "${HCH_EDITORIAL_WORKER_GROUP}" \
  "${runtime_directory}"
credential_path=$(mktemp "${runtime_directory}/enrollment-token.XXXXXXXX")
chmod 0600 "${credential_path}"

if [ -t 0 ]; then
  printf 'Enrollment token: ' >&2
  stty -echo
  echo_disabled=1
fi
IFS= read -r enrollment_token
if [ "${echo_disabled}" -eq 1 ]; then
  stty echo
  echo_disabled=0
  printf '\n' >&2
fi
if [ -z "${enrollment_token}" ]; then
  echo "enrollment-token-missing" >&2
  exit 1
fi
printf '%s' "${enrollment_token}" > "${credential_path}"
unset enrollment_token
credential_bytes=$(wc -c < "${credential_path}")
if [ "${credential_bytes}" -gt 16384 ]; then
  echo "enrollment-token-too-large" >&2
  exit 1
fi
chown "${HCH_EDITORIAL_WORKER_USER}:${HCH_EDITORIAL_WORKER_GROUP}" "${credential_path}"

"${HCH_EDITORIAL_RUNUSER_BIN}" --user "${HCH_EDITORIAL_WORKER_USER}" -- \
  "${HCH_EDITORIAL_ENV_BIN}" HCH_EDITORIAL_ENROLLMENT_TOKEN_FILE="${credential_path}" \
  "${HCH_EDITORIAL_NODE_BIN}" "${HCH_EDITORIAL_WORKER_ENTRYPOINT}" bootstrap \
  --config "${HCH_EDITORIAL_WORKER_CONFIG}" --enroll
