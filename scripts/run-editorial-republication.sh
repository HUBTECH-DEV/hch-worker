#!/bin/sh
set -eu

HCH_EDITORIAL_NODE_BIN=${HCH_EDITORIAL_NODE_BIN:-/usr/local/libexec/hch-node}
HCH_EDITORIAL_WORKER_ENTRYPOINT=${HCH_EDITORIAL_WORKER_ENTRYPOINT:-/usr/local/libexec/hch-editorial-runtime/ops/linux/editorial-worker/worker.mjs}
HCH_EDITORIAL_WORKER_CONFIG=${HCH_EDITORIAL_WORKER_CONFIG:-/etc/hch-editorial-worker/config.json}

test -x "${HCH_EDITORIAL_NODE_BIN}"
test -f "${HCH_EDITORIAL_WORKER_ENTRYPOINT}"
test -r "${HCH_EDITORIAL_WORKER_CONFIG}"

# The portable queue lifecycle is claim -> progress heartbeats -> complete/fail.
# The retired VPS /execute adapter must never be used by current workers.
exec "${HCH_EDITORIAL_NODE_BIN}" "${HCH_EDITORIAL_WORKER_ENTRYPOINT}" run-one \
  --config "${HCH_EDITORIAL_WORKER_CONFIG}"
