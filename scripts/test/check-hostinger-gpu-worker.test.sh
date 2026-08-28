#!/usr/bin/env bash

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
subject="$repo_root/scripts/check-hostinger-gpu-worker.sh"
test_root="$(mktemp -d "${TMPDIR:-/tmp}/hch-hostinger-preflight-test.XXXXXX")"
shim_root="$test_root/bin"
fixture_root="$test_root/fixtures"
output_root="$test_root/output"
secret_canary='HCH_TEST_SECRET_CANARY_7e58f6'

cleanup() {
  rm -rf -- "$test_root"
}
trap cleanup EXIT

mkdir -p "$shim_root" "$fixture_root" "$output_root"

cat >"$shim_root/ssh" <<'SHIM'
#!/usr/bin/env bash
set -euo pipefail
port=""
for argument in "$@"; do
  port="$argument"
done
: >"$HCH_TEST_SSH_MARKER"
remote_script="${HCH_TEST_SSH_MARKER}.remote.sh"
/bin/cat >"$remote_script"
if ! /bin/bash -n "$remote_script"; then
  nl -ba "$remote_script" >&2
  exit 2
fi
HCH_TEST_REMOTE=1 exec /bin/bash "$remote_script" "$port"
SHIM

cat >"$shim_root/node" <<'SHIM'
#!/usr/bin/env bash
set -euo pipefail
if [ "$HCH_TEST_CASE" = tunnel_stale ]; then
  exit 1
fi
exit 0
SHIM

cat >"$shim_root/date" <<'SHIM'
#!/usr/bin/env bash
set -euo pipefail
case "${1:-}" in
  +%s)
    printf '%s\n' 2000000000
    ;;
  --utc)
    if [ "${2:-}" = '--iso-8601=seconds' ]; then
      printf '%s\n' '2033-05-18T03:33:20+00:00'
    else
      exit 1
    fi
    ;;
  --date=2033-05-18T03:32:50Z)
    [ "${2:-}" = '+%s' ] || exit 1
    printf '%s\n' 1999999970
    ;;
  --date=2033-05-18T03:16:40Z)
    [ "${2:-}" = '+%s' ] || exit 1
    printf '%s\n' 1999999000
    ;;
  --date=2033-05-18T03:43:20Z)
    [ "${2:-}" = '+%s' ] || exit 1
    printf '%s\n' 2000000600
    ;;
  *)
    exit 1
    ;;
esac
SHIM

cat >"$shim_root/nvidia-smi" <<'SHIM'
#!/usr/bin/env bash
set -euo pipefail
if [ "$HCH_TEST_CASE" = gpu_empty ]; then
  exit 0
fi
printf '%s\n' 'NVIDIA A100 80GB PCIe, 580.173.02, 81920, 1024, 25'
SHIM

cat >"$shim_root/systemctl" <<'SHIM'
#!/usr/bin/env bash
set -euo pipefail
case "${1:-}" in
  is-active) printf '%s\n' active ;;
  show)
    case "$*" in
      *--property=SubState*) printf '%s\n' running ;;
      *--property=NRestarts*)
        if [ "$HCH_TEST_CASE" = restart_nonzero ]; then
          printf '%s\n' 1
        else
          printf '%s\n' 0
        fi
        ;;
      *) exit 1 ;;
    esac
    ;;
  *) exit 1 ;;
esac
SHIM

cat >"$shim_root/ss" <<'SHIM'
#!/usr/bin/env bash
set -euo pipefail
case "$*" in
  *':11434'*) port=11434 ;;
  *':4320'*) port=4320 ;;
  *) exit 1 ;;
esac
if [ "$HCH_TEST_CASE" = wildcard_listener ] && [ "$port" = 11434 ]; then
  address=0.0.0.0
else
  address=127.0.0.1
fi
printf 'LISTEN 0 128 %s:%s 0.0.0.0:*\n' "$address" "$port"
SHIM

cat >"$shim_root/cut" <<'SHIM'
#!/usr/bin/env bash
set -euo pipefail
case "$*" in
  *'/proc/uptime'*) printf '%s\n' 12345 ;;
  *) exec /usr/bin/cut "$@" ;;
esac
SHIM

cat >"$shim_root/curl" <<'SHIM'
#!/usr/bin/env bash
set -euo pipefail
url=""
previous=""
noproxy_all=0
for argument in "$@"; do
  if [ "$previous" = --noproxy ] && [ "$argument" = '*' ]; then
    noproxy_all=1
  fi
  previous="$argument"
  url="$argument"
done
case "$url" in
  */api/tags) cat "$HCH_TEST_TAGS_JSON" ;;
  http://127.0.0.1:*/api/status)
    if [ "${HCH_TEST_REMOTE:-0}" = 1 ]; then
      cat "$HCH_TEST_DASHBOARD_JSON"
      exit 0
    fi
    [ "$noproxy_all" -eq 1 ] || exit 64
    if [ "$HCH_TEST_CASE" = tunnel_down ]; then
      exit 22
    fi
    cat "$HCH_TEST_TUNNEL_DASHBOARD_JSON"
    ;;
  *) exit 22 ;;
esac
SHIM

cat >"$shim_root/sudo" <<'SHIM'
#!/usr/bin/env bash
set -euo pipefail
arguments=("$@")
index=0
while [ "$index" -lt "${#arguments[@]}" ]; do
  case "${arguments[$index]}" in
    -n) index=$((index + 1)) ;;
    -u) index=$((index + 2)) ;;
    *) break ;;
  esac
done
command_name="${arguments[$index]:-}"
index=$((index + 1))
command_arguments=("${arguments[@]:$index}")

case "$command_name" in
  test)
    exit 0
    ;;
  /bin/cat)
    case "${command_arguments[0]:-}" in
      */applied-manifest.json) exec /bin/cat "$HCH_TEST_APPLIED_JSON" ;;
      */runtime/config/engine.json) exec /bin/cat "$HCH_TEST_ENGINE_JSON" ;;
      */status.json) exec /bin/cat "$HCH_TEST_STATUS_JSON" ;;
      *) exit 1 ;;
    esac
    ;;
  jq)
    jq_arguments=("${command_arguments[@]}")
    last_index=$((${#jq_arguments[@]} - 1))
    jq_arguments[$last_index]="$HCH_TEST_STATUS_JSON"
    exec /usr/bin/jq "${jq_arguments[@]}"
    ;;
  *)
    exit 1
    ;;
esac
SHIM

chmod +x "$shim_root"/*

fresh='2033-05-18T03:32:50Z'
stale='2033-05-18T03:16:40Z'
future='2033-05-18T03:43:20Z'
model_name='qwen2.5:1.5b-instruct'
model_digest='aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'

write_base_fixtures() {
  /usr/bin/jq -n \
    --arg fresh "$fresh" \
    --arg secret "$secret_canary" \
    '{
      schemaVersion: 1,
      generatedAt: $fresh,
      worker: {id: "hostinger-gpu-01", state: "draining", version: "3.1.0"},
      connection: {status: "connected"},
      security: {
        authentication: {status: "authenticated"},
        transport: {tlsStatus: "valid", certificateStatus: "valid"},
        ed25519Chain: {
          status: "valid",
          manifestSequence: 5,
          manifestHash: "manifest-sha",
          policyHash: "policy-sha"
        }
      },
      resources: {gpu: {status: "available", name: "NVIDIA A100 80GB PCIe"}},
      adaptiveWork: {activeWork: []},
      workload: {jobsRunning: 0, currentBatch: null},
      capacity: {requestedCapacity: 0, grantedCapacity: 0, activeAssignments: 0},
      orchestration: {
        mode: "heartbeat-only",
        observedAt: $fresh,
        heartbeat: {status: "succeeded", lastSuccessAt: $fresh},
        capacity: {
          requestedCapacity: 0,
          grantedCapacity: 0,
          activeAssignments: 0,
          availableSlots: 0
        },
        workload: {generating: 0},
        claim: {allowed: false, recommendedCount: 0}
      },
      operatorControl: {
        status: "valid",
        acceptingClaims: false,
        drainRequested: true,
        requestedParallelism: 0
      },
      internal: {enrollmentToken: $secret}
    }' >"$fixture_root/dashboard.json"

  /usr/bin/jq -n \
    --arg fresh "$fresh" \
    --arg future "$future" \
    --arg secret "$secret_canary" \
    '{
      schema: "hch.worker-status/v1",
      schemaVersion: 1,
      observedAt: $fresh,
      readyUntil: $future,
      nodeId: "hostinger-gpu-01",
      kitVersion: "3.1.0",
      state: "draining",
      running: false,
      ready: true,
      connection: {api: "connected", tls: "verified", auth: "ed25519", ed25519: true},
      trust: {status: "verified", manifestSequence: 5, manifestHash: "manifest-sha"},
      manifestSequence: 5,
      manifestHash: "manifest-sha",
      capacity: {
        requestedCapacity: 0,
        grantedCapacity: 0,
        effectiveGrantedCapacity: 0,
        activeAssignments: 0
      },
      currentBatch: null,
      code: "worker-draining",
      internal: {privateKey: $secret}
    }' >"$fixture_root/status.json"

  /usr/bin/jq -n \
    --arg model "$model_name" \
    --arg digest "$model_digest" \
    '{
      schemaVersion: 1,
      manifestHash: "manifest-sha",
      model: $model,
      modelDigest: $digest
    }' >"$fixture_root/applied.json"

  /usr/bin/jq -n \
    --arg model "$model_name" \
    --arg digest "$model_digest" \
    '{
      schemaVersion: 1,
      sourceManifestHash: "manifest-sha",
      model: $model,
      modelDigest: $digest
    }' >"$fixture_root/engine.json"

  /usr/bin/jq -n \
    --arg model "$model_name" \
    --arg digest "$model_digest" \
    --arg secret "$secret_canary" \
    '{models: [{name: $model, model: $model, digest: $digest, internal: $secret}]}' \
    >"$fixture_root/tags.json"
}

prepare_case() {
  case_name="$1"
  write_base_fixtures
  case "$case_name" in
    green|gpu_empty|wildcard_listener|restart_nonzero|tunnel_custom_port) ;;
    global_workload_active)
      /usr/bin/jq '.orchestration.workload.generating = 4' \
        "$fixture_root/dashboard.json" >"$fixture_root/dashboard.next"
      mv "$fixture_root/dashboard.next" "$fixture_root/dashboard.json"
      ;;
    global_workload_invalid)
      /usr/bin/jq '.orchestration.workload.generating = -1' \
        "$fixture_root/dashboard.json" >"$fixture_root/dashboard.next"
      mv "$fixture_root/dashboard.next" "$fixture_root/dashboard.json"
      ;;
    stale)
      /usr/bin/jq --arg stale "$stale" '.generatedAt = $stale' \
        "$fixture_root/dashboard.json" >"$fixture_root/dashboard.next"
      mv "$fixture_root/dashboard.next" "$fixture_root/dashboard.json"
      ;;
    disconnected)
      /usr/bin/jq '.connection.status = "disconnected"' \
        "$fixture_root/dashboard.json" >"$fixture_root/dashboard.next"
      mv "$fixture_root/dashboard.next" "$fixture_root/dashboard.json"
      ;;
    active_work)
      /usr/bin/jq '.adaptiveWork.activeWork = [{assignmentId: "assignment-1"}]' \
        "$fixture_root/dashboard.json" >"$fixture_root/dashboard.next"
      mv "$fixture_root/dashboard.next" "$fixture_root/dashboard.json"
      ;;
    grant_nonzero)
      /usr/bin/jq '.capacity.grantedCapacity = 1' \
        "$fixture_root/dashboard.json" >"$fixture_root/dashboard.next"
      mv "$fixture_root/dashboard.next" "$fixture_root/dashboard.json"
      ;;
    claim_allowed)
      /usr/bin/jq '.orchestration.claim.allowed = true' \
        "$fixture_root/dashboard.json" >"$fixture_root/dashboard.next"
      mv "$fixture_root/dashboard.next" "$fixture_root/dashboard.json"
      ;;
    model_absent)
      printf '%s\n' '{"models":[]}' >"$fixture_root/tags.json"
      ;;
    model_digest_wrong)
      /usr/bin/jq '.models[0].digest = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"' \
        "$fixture_root/tags.json" >"$fixture_root/tags.next"
      mv "$fixture_root/tags.next" "$fixture_root/tags.json"
      ;;
    invalid_json)
      printf '%s\n' '{invalid-json' >"$fixture_root/dashboard.json"
      ;;
    tunnel_identity_mismatch)
      ;;
    tunnel_down|tunnel_stale)
      ;;
    *)
      printf 'unknown test case: %s\n' "$case_name" >&2
      exit 2
      ;;
  esac
  cp "$fixture_root/dashboard.json" "$fixture_root/tunnel-dashboard.json"
  if [ "$case_name" = tunnel_identity_mismatch ]; then
    /usr/bin/jq '.worker.id = "another-worker"' \
      "$fixture_root/tunnel-dashboard.json" >"$fixture_root/tunnel-dashboard.next"
    mv "$fixture_root/tunnel-dashboard.next" "$fixture_root/tunnel-dashboard.json"
  fi
}

run_case() {
  case_name="$1"
  expected_result="$2"
  output_file="$output_root/$case_name.log"
  ssh_marker="$output_root/$case_name.ssh"
  tunnel_url=http://127.0.0.1:4320
  if [ "$case_name" = tunnel_custom_port ]; then
    tunnel_url=http://127.0.0.1:54321
  fi

  prepare_case "$case_name"
  if PATH="$shim_root:$PATH" \
    HCH_TEST_CASE="$case_name" \
    HCH_TEST_DASHBOARD_JSON="$fixture_root/dashboard.json" \
    HCH_TEST_TUNNEL_DASHBOARD_JSON="$fixture_root/tunnel-dashboard.json" \
    HCH_TEST_APPLIED_JSON="$fixture_root/applied.json" \
    HCH_TEST_ENGINE_JSON="$fixture_root/engine.json" \
    HCH_TEST_TAGS_JSON="$fixture_root/tags.json" \
    HCH_TEST_STATUS_JSON="$fixture_root/status.json" \
    HCH_TEST_SSH_MARKER="$ssh_marker" \
    HCH_GPU_SSH_ALIAS=hostinger-gpu-test \
    HCH_GPU_DASHBOARD_PORT=4320 \
    HCH_GPU_TUNNEL_DASHBOARD_URL="$tunnel_url" \
    /bin/bash "$subject" >"$output_file" 2>&1; then
    actual_result=pass
  else
    actual_result=blocked
  fi

  [ -f "$ssh_marker" ] || {
    printf 'FAIL %s: fake ssh did not execute the remote heredoc\n' "$case_name" >&2
    return 1
  }
  if [ "$actual_result" != "$expected_result" ]; then
    printf 'FAIL %s: expected %s, got %s\n' \
      "$case_name" "$expected_result" "$actual_result" >&2
    sed -n '1,240p' "$output_file" >&2
    return 1
  fi
  if [ "$expected_result" = pass ]; then
    grep -q '^preflight=pass$' "$output_file" || return 1
    grep -q '^tunnel_dashboard=verified$' "$output_file" || return 1
  else
    grep -q '^preflight=blocked$' "$output_file" || return 1
  fi
  case "$case_name" in
    tunnel_down) grep -q '^tunnel_dashboard=unreachable$' "$output_file" || return 1 ;;
    tunnel_identity_mismatch) grep -q '^tunnel_dashboard=identity-mismatch$' "$output_file" || return 1 ;;
    tunnel_stale) grep -q '^tunnel_dashboard=stale$' "$output_file" || return 1 ;;
  esac
  if grep -qF "$secret_canary" "$output_file"; then
    printf 'FAIL %s: secret canary leaked to output\n' "$case_name" >&2
    return 1
  fi
  printf 'ok - %s -> %s\n' "$case_name" "$expected_result"
}

run_invalid_url_case() {
  case_name="$1"
  tunnel_url="$2"
  output_file="$output_root/$case_name.log"
  ssh_marker="$output_root/$case_name.ssh"
  if PATH="$shim_root:$PATH" \
    HCH_TEST_CASE="$case_name" \
    HCH_TEST_SSH_MARKER="$ssh_marker" \
    HCH_GPU_SSH_ALIAS=hostinger-gpu-test \
    HCH_GPU_DASHBOARD_PORT=4320 \
    HCH_GPU_TUNNEL_DASHBOARD_URL="$tunnel_url" \
    /bin/bash "$subject" >"$output_file" 2>&1; then
    printf 'FAIL %s: invalid tunnel URL passed\n' "$case_name" >&2
    return 1
  fi
  [ ! -e "$ssh_marker" ] || {
    printf 'FAIL %s: invalid URL reached SSH\n' "$case_name" >&2
    return 1
  }
  grep -q 'tunnel dashboard' "$output_file" || return 1
  printf 'ok - %s -> rejected-before-ssh\n' "$case_name"
}

run_case green pass
run_case tunnel_custom_port pass
run_case global_workload_active pass
run_case global_workload_invalid blocked
run_case stale blocked
run_case disconnected blocked
run_case active_work blocked
run_case grant_nonzero blocked
run_case claim_allowed blocked
run_case gpu_empty blocked
run_case wildcard_listener blocked
run_case restart_nonzero blocked
run_case model_absent blocked
run_case model_digest_wrong blocked
run_case tunnel_down blocked
run_case tunnel_identity_mismatch blocked
run_case tunnel_stale blocked
run_case invalid_json blocked
run_invalid_url_case tunnel_external http://192.0.2.10:4320
run_invalid_url_case tunnel_https https://127.0.0.1:4320
run_invalid_url_case tunnel_localhost http://localhost:4320
run_invalid_url_case tunnel_no_port http://127.0.0.1
run_invalid_url_case tunnel_nonnumeric http://127.0.0.1:abc
run_invalid_url_case tunnel_port_overflow http://127.0.0.1:65536

printf '1..24\n'
