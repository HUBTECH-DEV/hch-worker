#!/usr/bin/env bash

set -euo pipefail

ssh_alias="${HCH_GPU_SSH_ALIAS:-hostinger-gpu}"
dashboard_port="${HCH_GPU_DASHBOARD_PORT:-4320}"
public_dashboard_port="${HCH_GPU_PUBLIC_DASHBOARD_PORT:-20001}"

case "$ssh_alias" in
  -*|*[!A-Za-z0-9._-]*|'')
    printf 'invalid SSH alias: %s\n' "$ssh_alias" >&2
    exit 2
    ;;
esac

case "$dashboard_port" in
  *[!0-9]*|'')
    printf 'invalid dashboard port: %s\n' "$dashboard_port" >&2
    exit 2
    ;;
esac

if [ "$dashboard_port" -lt 1 ] || [ "$dashboard_port" -gt 65535 ]; then
  printf 'dashboard port is outside 1..65535: %s\n' "$dashboard_port" >&2
  exit 2
fi

case "$public_dashboard_port" in
  *[!0-9]*|'')
    printf 'invalid public dashboard port: %s\n' "$public_dashboard_port" >&2
    exit 2
    ;;
esac

if [ "$public_dashboard_port" -lt 1 ] || [ "$public_dashboard_port" -gt 65535 ]; then
  printf 'public dashboard port is outside 1..65535: %s\n' \
    "$public_dashboard_port" >&2
  exit 2
fi

for local_command in ssh curl jq node shasum awk sed grep; do
  if ! command -v "$local_command" >/dev/null 2>&1; then
    printf 'local prerequisite unavailable: %s\n' "$local_command" >&2
    exit 2
  fi
done

run_remote_preflight() {
  ssh \
  -o BatchMode=yes \
  -o ConnectTimeout=10 \
  -o ServerAliveInterval=5 \
  -o ServerAliveCountMax=3 \
  "$ssh_alias" \
    /usr/bin/timeout --signal=TERM 45 /bin/bash -s -- "$dashboard_port" <<'REMOTE'
set -euo pipefail

dashboard_port="$1"
state_root=/var/lib/hch-editorial-worker
gate_failed=0

is_fresh_timestamp() {
  local value="$1"
  local maximum_age_seconds="$2"
  local observed_epoch now_epoch age_seconds
  [[ "$value" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]{1,9})?(Z|[+-][0-9]{2}:[0-9]{2})$ ]] || return 1
  observed_epoch="$(date --date="$value" +%s 2>/dev/null)" || return 1
  now_epoch="$(date +%s)"
  age_seconds=$((now_epoch - observed_epoch))
  [ "$age_seconds" -ge -30 ] && [ "$age_seconds" -le "$maximum_age_seconds" ]
}

is_future_timestamp() {
  local value="$1"
  local observed_epoch now_epoch
  [[ "$value" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]{1,9})?(Z|[+-][0-9]{2}:[0-9]{2})$ ]] || return 1
  observed_epoch="$(date --date="$value" +%s 2>/dev/null)" || return 1
  now_epoch="$(date +%s)"
  [ "$observed_epoch" -gt "$now_epoch" ]
}

printf 'host=%s\n' "$(hostname)"
printf 'observed_at=%s\n' "$(date --utc --iso-8601=seconds)"
printf 'uptime_seconds=%s\n' "$(cut -d. -f1 /proc/uptime)"

if command -v nvidia-smi >/dev/null 2>&1 && \
   gpu_status="$(nvidia-smi \
    --query-gpu=name,driver_version,memory.total,memory.used,utilization.gpu \
    --format=csv,noheader,nounits 2>/dev/null)" && \
   [ -n "$gpu_status" ]; then
  printf '%s\n' "$gpu_status" | sed 's/^/gpu=/'
else
  printf 'gpu=probe-unavailable\n'
  gate_failed=1
fi

for service in hch-editorial-worker.service ollama.service; do
  active_state="$(systemctl is-active "$service" 2>/dev/null || true)"
  sub_state="$(systemctl show "$service" --property=SubState --value 2>/dev/null || true)"
  restart_count="$(systemctl show "$service" --property=NRestarts --value 2>/dev/null || true)"
  printf 'service=%s active=%s sub=%s restarts=%s\n' \
    "$service" "${active_state:-unknown}" "${sub_state:-unknown}" "${restart_count:-unknown}"
  if [ "$active_state" != active ] || [ "$sub_state" != running ]; then
    gate_failed=1
  fi
done

for port in 11434 "$dashboard_port"; do
  listener_rows="$(ss -ltnH "sport = :$port" 2>/dev/null || true)"
  listener_addresses="$(printf '%s\n' "$listener_rows" | awk 'NF >= 4 { print $4 }')"
  listener_scope=loopback
  if [ -z "$listener_addresses" ]; then
    listener_scope=down
  else
    while IFS= read -r listener_address; do
      case "$listener_address" in
        "127.0.0.1:$port"|"[::1]:$port"|"::1:$port") ;;
        *) listener_scope=non-loopback ;;
      esac
    done <<EOF
$listener_addresses
EOF
  fi
  if [ "$listener_scope" = loopback ]; then
    printf 'listener_%s=loopback\n' "$port"
  elif [ "$listener_scope" = down ]; then
    printf 'listener_%s=down\n' "$port"
    gate_failed=1
  else
    printf 'listener_%s=non-loopback\n' "$port"
    gate_failed=1
  fi
done

applied_json=""
engine_json=""
status_json=""
for runtime_file in \
  "$state_root/applied-manifest.json" \
  "$state_root/runtime/config/engine.json" \
  "$state_root/status.json"; do
  if ! sudo -n -u hch-editorial-worker test -r "$runtime_file" 2>/dev/null; then
    gate_failed=1
  fi
done
if [ "$gate_failed" -eq 0 ]; then
  applied_json="$(sudo -n -u hch-editorial-worker /bin/cat \
    "$state_root/applied-manifest.json")" || gate_failed=1
  engine_json="$(sudo -n -u hch-editorial-worker /bin/cat \
    "$state_root/runtime/config/engine.json")" || gate_failed=1
  status_json="$(sudo -n -u hch-editorial-worker /bin/cat \
    "$state_root/status.json")" || gate_failed=1
fi

applied_model=""
applied_digest=""
applied_manifest_hash=""
engine_model=""
engine_digest=""
engine_manifest_hash=""
if [ -n "$applied_json" ] && [ -n "$engine_json" ] && \
   command -v jq >/dev/null 2>&1; then
  applied_model="$(printf '%s\n' "$applied_json" | jq -er \
    'select(.schemaVersion == 1) | .model | select(type == "string" and length > 0 and length <= 160)')" || gate_failed=1
  applied_digest="$(printf '%s\n' "$applied_json" | jq -er \
    '.modelDigest | select(type == "string") | ascii_downcase | sub("^sha256:"; "") | select(test("^[a-f0-9]{64}$"))')" || gate_failed=1
  applied_manifest_hash="$(printf '%s\n' "$applied_json" | jq -er \
    '.manifestHash | select(type == "string" and length > 0)')" || gate_failed=1
  engine_model="$(printf '%s\n' "$engine_json" | jq -er \
    'select(.schemaVersion == 1) | .model | select(type == "string" and length > 0 and length <= 160)')" || gate_failed=1
  engine_digest="$(printf '%s\n' "$engine_json" | jq -er \
    '.modelDigest | select(type == "string") | ascii_downcase | sub("^sha256:"; "") | select(test("^[a-f0-9]{64}$"))')" || gate_failed=1
  engine_manifest_hash="$(printf '%s\n' "$engine_json" | jq -er \
    '.sourceManifestHash | select(type == "string" and length > 0)')" || gate_failed=1
  if [ "$applied_model" != "$engine_model" ] || \
     [ "$applied_digest" != "$engine_digest" ] || \
     [ "$applied_manifest_hash" != "$engine_manifest_hash" ]; then
    gate_failed=1
  fi
else
  gate_failed=1
fi

ollama_tags_json=""
if command -v curl >/dev/null 2>&1 && \
   ollama_tags_json="$(curl --fail --silent --show-error --max-time 5 \
     http://127.0.0.1:11434/api/tags)"; then
  if [ -n "$applied_model" ] && [ -n "$applied_digest" ] && \
     printf '%s\n' "$ollama_tags_json" | jq -e \
       --arg model "$applied_model" --arg digest "$applied_digest" '
       (.models | type == "array") and
       ([.models[] | select(
         ((.name == $model) or (.model == $model)) and
         ((.digest | type) == "string") and
         ((.digest | ascii_downcase | sub("^sha256:"; "")) == $digest)
       )] | length == 1)
     ' >/dev/null; then
    printf 'ollama_http=up model=verified\n'
  else
    printf 'ollama_http=up model=unverified\n'
    gate_failed=1
  fi
else
  printf 'ollama_http=down model=unverified\n'
  gate_failed=1
fi

dashboard_json=""
dashboard_identity_sha256=""
if command -v curl >/dev/null 2>&1 && \
   dashboard_json="$(curl --fail --silent --show-error --max-time 5 \
     "http://127.0.0.1:${dashboard_port}/api/status")"; then
  printf 'dashboard_http=up\n'
  if command -v jq >/dev/null 2>&1; then
    if ! printf '%s\n' "$dashboard_json" | jq -e \
      --arg appliedManifestHash "$applied_manifest_hash" '
      .schemaVersion == 1 and
      (.worker.id | type == "string" and length > 0) and
      (.worker.state == "draining") and
      (.connection.status == "connected") and
      (.security.authentication.status == "authenticated") and
      (.security.transport.tlsStatus == "valid") and
      (.security.transport.certificateStatus == "valid") and
      (.security.ed25519Chain.status == "valid") and
      (.security.ed25519Chain.manifestSequence | type == "number") and
      (.security.ed25519Chain.manifestHash | type == "string" and length > 0) and
      (.security.ed25519Chain.manifestHash == $appliedManifestHash) and
      (.security.ed25519Chain.policyHash | type == "string" and length > 0) and
      (.resources.gpu.status == "available") and
      (.adaptiveWork.activeWork | type == "array" and length == 0) and
      (.workload.jobsRunning == 0) and
      (.workload.currentBatch == null) and
      (.capacity.requestedCapacity == 0) and
      (.capacity.grantedCapacity == 0) and
      (.capacity.activeAssignments == 0) and
      (.orchestration.mode == "heartbeat-only") and
      (.orchestration.heartbeat.status == "succeeded") and
      (.orchestration.capacity.requestedCapacity == 0) and
      (.orchestration.capacity.grantedCapacity == 0) and
      (.orchestration.capacity.activeAssignments == 0) and
      (.orchestration.capacity.availableSlots == 0) and
      (.orchestration.workload.generating == 0) and
      (.orchestration.claim.allowed == false) and
      (.orchestration.claim.recommendedCount == 0) and
      (.operatorControl.status == "valid") and
      (.operatorControl.acceptingClaims == false) and
      (.operatorControl.drainRequested == true) and
      (.operatorControl.requestedParallelism == 0)
    ' >/dev/null; then
      gate_failed=1
    fi
    for timestamp_path in generatedAt orchestration.observedAt orchestration.heartbeat.lastSuccessAt; do
      timestamp_value="$(printf '%s\n' "$dashboard_json" | jq -er ".$timestamp_path")" || {
        gate_failed=1
        continue
      }
      if ! is_fresh_timestamp "$timestamp_value" 180; then
        gate_failed=1
      fi
    done
    if dashboard_summary="$(printf '%s\n' "$dashboard_json" | jq -c '{
      worker: {
        id: .worker.id,
        state: .worker.state,
        version: .worker.version
      },
      connection: .connection.status,
      authentication: .security.authentication.status,
      transport: {
        tls: .security.transport.tlsStatus,
        certificate: .security.transport.certificateStatus
      },
      trust: .security.ed25519Chain.status,
      capacity: .capacity,
      activeWorkCount: (.adaptiveWork.activeWork | length),
      jobsRunning: .workload.jobsRunning,
      gpu: .resources.gpu,
      orchestration: {
        mode: .orchestration.mode,
        heartbeat: .orchestration.heartbeat.status,
        claimAllowed: .orchestration.claim.allowed
      },
      operatorControl: {
        status: .operatorControl.status,
        acceptingClaims: .operatorControl.acceptingClaims,
        drainRequested: .operatorControl.drainRequested,
        requestedParallelism: .operatorControl.requestedParallelism
      }
    }')"; then
      printf '%s\n' "$dashboard_summary"
    else
      printf 'dashboard_json=invalid\n'
      gate_failed=1
    fi
    if dashboard_identity="$(printf '%s\n' "$dashboard_json" | jq -ceS '{
      workerId: .worker.id,
      manifestSequence: .security.ed25519Chain.manifestSequence,
      manifestHash: .security.ed25519Chain.manifestHash,
      policyHash: .security.ed25519Chain.policyHash
    }')" && command -v sha256sum >/dev/null 2>&1; then
      dashboard_identity_sha256="$(printf '%s' "$dashboard_identity" | \
        sha256sum | awk '{ print $1 }')"
      if [[ ! "$dashboard_identity_sha256" =~ ^[a-f0-9]{64}$ ]]; then
        gate_failed=1
      fi
    else
      gate_failed=1
    fi
  else
    printf 'dashboard_json=unvalidated-jq-missing\n'
    gate_failed=1
  fi
else
  printf 'dashboard_http=down\n'
  gate_failed=1
fi

if [ -n "$status_json" ] && command -v jq >/dev/null 2>&1; then
  if worker_status="$(printf '%s\n' "$status_json" | jq -c '{
    schema,
    observedAt,
    nodeId,
    kitVersion,
    state,
    running,
    ready,
    connection: .connection.api,
    trust: .trust.status,
    capacity: {
      requestedCapacity: .capacity.requestedCapacity,
      grantedCapacity: .capacity.grantedCapacity,
      activeAssignments: .capacity.activeAssignments
    },
    currentBatch,
    code
  }')"; then
    printf '%s\n' "$worker_status"
  else
    printf 'worker_status=invalid\n'
    gate_failed=1
  fi
  if ! printf '%s\n' "$status_json" | jq -e \
    --arg appliedManifestHash "$applied_manifest_hash" '
    .schema == "hch.worker-status/v1" and
    .schemaVersion == 1 and
    .ready == true and
    (.readyUntil | type == "string" and length > 0) and
    .state == "draining" and
    .running == false and
    .currentBatch == null and
    .connection.api == "connected" and
    .connection.tls == "verified" and
    .connection.auth == "ed25519" and
    .connection.ed25519 == true and
    .trust.status == "verified" and
    (.manifestSequence | type == "number") and
    (.manifestHash | type == "string" and length > 0) and
    .manifestHash == $appliedManifestHash and
    .trust.manifestSequence == .manifestSequence and
    .trust.manifestHash == .manifestHash and
    .capacity.requestedCapacity == 0 and
    .capacity.grantedCapacity == 0 and
    .capacity.effectiveGrantedCapacity == 0 and
    .capacity.activeAssignments == 0
  ' >/dev/null; then
    gate_failed=1
  fi
  status_observed_at="$(printf '%s\n' "$status_json" | jq -er '.observedAt')" || gate_failed=1
  status_ready_until="$(printf '%s\n' "$status_json" | jq -er '.readyUntil')" || gate_failed=1
  if [ -n "${status_observed_at:-}" ] && \
     ! is_fresh_timestamp "$status_observed_at" 180; then
    gate_failed=1
  fi
  if [ -n "${status_ready_until:-}" ] && \
     ! is_future_timestamp "$status_ready_until"; then
    gate_failed=1
  fi
else
  printf 'worker_status=unreadable\n'
  gate_failed=1
fi

if [ "$gate_failed" -ne 0 ]; then
  printf 'remote_preflight=blocked\n'
  exit 1
fi
printf 'dashboard_identity_sha256=%s\n' "$dashboard_identity_sha256"
printf 'remote_preflight=pass\n'
REMOTE
}

remote_output="$(run_remote_preflight)" || {
  remote_status=$?
  printf '%s\n' "$remote_output"
  printf 'public_dashboard=not-checked\n'
  printf 'preflight=blocked\n'
  exit "$remote_status"
}

printf '%s\n' "$remote_output"
remote_dashboard_sha256="$(printf '%s\n' "$remote_output" | \
  sed -n 's/^dashboard_identity_sha256=\([a-f0-9]\{64\}\)$/\1/p')"
if [ "$(printf '%s\n' "$remote_dashboard_sha256" | grep -c .)" -ne 1 ]; then
  printf 'public_dashboard=identity-unavailable\n'
  printf 'preflight=blocked\n'
  exit 1
fi

ssh_hostname="$(ssh -G "$ssh_alias" 2>/dev/null | \
  awk '$1 == "hostname" { print $2; exit }')"
if [[ ! "$ssh_hostname" =~ ^[A-Za-z0-9][A-Za-z0-9.-]{0,252}$ ]]; then
  printf 'public_dashboard=hostname-invalid\n'
  printf 'preflight=blocked\n'
  exit 1
fi

public_dashboard_json=""
if ! public_dashboard_json="$(curl --fail --silent --show-error --max-time 10 \
  "http://${ssh_hostname}:${public_dashboard_port}/api/status" 2>/dev/null)"; then
  printf 'public_dashboard=unreachable\n'
  printf 'preflight=blocked\n'
  exit 1
fi

if ! printf '%s\n' "$public_dashboard_json" | jq -e '
  .schemaVersion == 1 and
  (.generatedAt | type == "string" and length > 0) and
  (.worker.state == "draining") and
  (.connection.status == "connected") and
  (.security.authentication.status == "authenticated") and
  (.security.transport.tlsStatus == "valid") and
  (.security.transport.certificateStatus == "valid") and
  (.security.ed25519Chain.status == "valid") and
  (.resources.gpu.status == "available") and
  (.adaptiveWork.activeWork | type == "array" and length == 0) and
  (.capacity.requestedCapacity == 0) and
  (.capacity.grantedCapacity == 0) and
  (.capacity.activeAssignments == 0) and
  (.operatorControl.acceptingClaims == false) and
  (.operatorControl.drainRequested == true)
' >/dev/null; then
  printf 'public_dashboard=invalid\n'
  printf 'preflight=blocked\n'
  exit 1
fi

public_generated_at="$(printf '%s\n' "$public_dashboard_json" | jq -er '.generatedAt')"
if [[ ! "$public_generated_at" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]{1,9})?(Z|[+-][0-9]{2}:[0-9]{2})$ ]] || \
   ! node -e '
     const observed = Date.parse(process.argv[1]);
     const age = Date.now() - observed;
     process.exit(Number.isFinite(observed) && age >= -30000 && age <= 180000 ? 0 : 1);
   ' "$public_generated_at"; then
  printf 'public_dashboard=stale\n'
  printf 'preflight=blocked\n'
  exit 1
fi

public_dashboard_identity="$(printf '%s\n' "$public_dashboard_json" | jq -ceS '{
  workerId: .worker.id,
  manifestSequence: .security.ed25519Chain.manifestSequence,
  manifestHash: .security.ed25519Chain.manifestHash,
  policyHash: .security.ed25519Chain.policyHash
}')"
public_dashboard_sha256="$(printf '%s' "$public_dashboard_identity" | \
  shasum -a 256 | awk '{ print $1 }')"
if [ "$public_dashboard_sha256" != "$remote_dashboard_sha256" ]; then
  printf 'public_dashboard=identity-mismatch\n'
  printf 'preflight=blocked\n'
  exit 1
fi

printf 'public_dashboard=verified\n'
printf 'preflight=pass\n'
