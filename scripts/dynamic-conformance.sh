#!/usr/bin/env sh
set -eu

cd "$(dirname "$0")/.."

iterations=${1:-5}
cases=${KAHEA_DYNAMIC_CASES:-12}
base_seed=${KAHEA_DYNAMIC_SEED:-$(date +%s)}
fault=${KAHEA_DYNAMIC_FAULT:-none}

case "$iterations" in
  ''|*[!0-9]*) echo "iterations must be a positive integer" >&2; exit 2 ;;
esac
case "$cases" in
  ''|*[!0-9]*) echo "KAHEA_DYNAMIC_CASES must be a positive integer" >&2; exit 2 ;;
esac
if [ "$iterations" -lt 1 ] || [ "$cases" -lt 2 ] || [ "$cases" -gt 256 ]; then
  echo "iterations must be positive and cases must be between 2 and 256" >&2
  exit 2
fi

if [ "${KAHEA_DYNAMIC_SKIP_BUILD:-0}" != "1" ]; then
  cargo build -p kahea -p kahea-test-server
fi

kahea=target/debug/kahea
server=target/debug/kahea-test-server
run_root=${KAHEA_DYNAMIC_ARTIFACTS:-$(mktemp -d)}
mkdir -p "$run_root"
server_pid=

cleanup() {
  if [ -n "$server_pid" ]; then
    kill "$server_pid" 2>/dev/null || true
    wait "$server_pid" 2>/dev/null || true
  fi
}
trap cleanup EXIT INT TERM

fail() {
  echo "dynamic conformance failed: $1" >&2
  echo "replay artifacts: $run_root" >&2
  exit 1
}

iteration=0
while [ "$iteration" -lt "$iterations" ]; do
  seed=$((base_seed + iteration))
  iteration_dir="$run_root/iteration-$iteration-seed-$seed"
  mkdir -p "$iteration_dir"
  manifest="$iteration_dir/manifest.json"
  source="$iteration_dir/openapi.json"

  "$server" \
    --seed "$seed" \
    --fault "$fault" \
    --write-openapi "$source" \
    --write-manifest "$manifest" \
    >"$iteration_dir/server.stdout.ndjson" \
    2>"$iteration_dir/server.stderr.log" &
  server_pid=$!

  attempts=0
  while [ ! -s "$manifest" ] && [ "$attempts" -lt 100 ]; do
    if ! kill -0 "$server_pid" 2>/dev/null; then
      fail "server exited before readiness for seed $seed"
    fi
    sleep 0.05
    attempts=$((attempts + 1))
  done
  [ -s "$manifest" ] || fail "server readiness timed out for seed $seed"
  jq -e '.kind == "kahea-dynamic-test-server" and (.operations | length >= 3)' "$manifest" >/dev/null \
    || fail "manifest is invalid for seed $seed"

  expected_requests=0
  jq -r '.operations[]' "$manifest" >"$iteration_dir/operations.txt"
  while IFS= read -r operation; do
    operation_dir="$iteration_dir/$operation"
    store="$operation_dir/state"
    mkdir -p "$operation_dir"
    "$kahea" inspect "$source" --match "$operation" >"$operation_dir/inspect.json" \
      || fail "inspect failed for seed $seed operation $operation"
    "$kahea" conform "$source" "$operation" \
      --cases "$cases" \
      --seed "$seed" \
      --mode mixed \
      --max-failures 1 \
      --store "$store" \
      >"$operation_dir/campaign.json" \
      || fail "campaign planning failed for seed $seed operation $operation"
    campaign=$(jq -er '.id' "$operation_dir/campaign.json") \
      || fail "campaign handle is missing for seed $seed operation $operation"
    jq -r '.required_grants[]' "$operation_dir/campaign.json" >"$operation_dir/grants.txt"

    set -- "$kahea" invoke "$campaign" --store "$store"
    while IFS= read -r grant; do
      set -- "$@" --grant "$grant"
    done <"$operation_dir/grants.txt"
    if ! "$@" >"$operation_dir/observation.json"; then
      fail "campaign found a conformance failure for seed $seed operation $operation"
    fi
    jq -e '.kind == "conformance-observation" and .exit == 0 and .failed == 0 and .passed == .executed' \
      "$operation_dir/observation.json" >/dev/null \
      || fail "campaign observation is not successful for seed $seed operation $operation"
    executed=$(jq -er '.executed' "$operation_dir/observation.json")
    expected_requests=$((expected_requests + executed))
  done <"$iteration_dir/operations.txt"

  diagnostics_url=$(jq -er '.diagnostics_url' "$manifest")
  curl -fsS "$diagnostics_url" >"$iteration_dir/diagnostics.json" \
    || fail "diagnostics request failed for seed $seed"
  jq -e --argjson expected "$expected_requests" \
    '.requests == $expected and .valid > 0 and .invalid > 0 and ([.by_operation[].valid > 0] | all) and ([.by_operation[].invalid > 0] | all)' \
    "$iteration_dir/diagnostics.json" >/dev/null \
    || fail "runtime diagnostics do not match the lifecycle for seed $seed"

  shutdown_url=$(jq -er '.shutdown_url' "$manifest")
  control_token=$(jq -er '.control_token' "$manifest")
  curl -fsS -X POST -H "X-Kahea-Control: $control_token" "$shutdown_url" \
    >"$iteration_dir/shutdown.json" \
    || fail "graceful shutdown failed for seed $seed"
  wait "$server_pid" || fail "server exited unsuccessfully for seed $seed"
  server_pid=

  echo "dynamic conformance iteration $((iteration + 1))/$iterations passed (seed=$seed, requests=$expected_requests)"
  iteration=$((iteration + 1))
done

echo "dynamic conformance passed ($iterations startup lifecycles); artifacts: $run_root"
