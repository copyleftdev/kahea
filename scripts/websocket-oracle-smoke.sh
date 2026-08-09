#!/usr/bin/env sh
set -eu

cd "$(dirname "$0")/.."

kahea=${KAHEA_WEBSOCKET_KAHEA:-target/release/kahea}
server=${KAHEA_WEBSOCKET_ORACLE_SERVER:-target/release/kahea-test-server}
run_root=${KAHEA_WEBSOCKET_ORACLE_ARTIFACTS:-$(mktemp -d)}
mkdir -p "$run_root"
manifest="$run_root/manifest.json"
oracle_observation="$run_root/oracle-observation.json"
source="$run_root/session.json"
store="$run_root/state"
server_pid=

cleanup() {
  if [ -n "$server_pid" ]; then
    kill "$server_pid" 2>/dev/null || true
    wait "$server_pid" 2>/dev/null || true
  fi
}
trap cleanup EXIT INT TERM

fail() {
  echo "WebSocket oracle smoke failed: $1" >&2
  echo "replay artifacts: $run_root" >&2
  exit 1
}

"$server" \
  --protocol websocket \
  --seed 42 \
  --write-manifest "$manifest" \
  --write-observation "$oracle_observation" \
  >"$run_root/server.stdout.ndjson" \
  2>"$run_root/server.stderr.log" &
server_pid=$!

attempts=0
while [ ! -s "$manifest" ] && [ "$attempts" -lt 100 ]; do
  if ! kill -0 "$server_pid" 2>/dev/null; then
    fail "server exited before publishing readiness"
  fi
  sleep 0.05
  attempts=$((attempts + 1))
done
[ -s "$manifest" ] || fail "readiness manifest timed out"
jq -e '.kind == "kahea-websocket-oracle" and .seed == 42 and .case_id == "ws-000000000000002a-none"' "$manifest" >/dev/null \
  || fail "readiness manifest is invalid"
url=$(jq -er '.url' "$manifest") || fail "manifest URL is missing"

jq -n --arg url "$url" '{
  kind:"websocket-session",
  version:1,
  operationId:"oracleSession",
  url:$url,
  risk:"write",
  origin:"https://oracle.kahea.test",
  subprotocols:["kahea.oracle.002a"],
  limits:{
    connect_timeout_ms:2000,
    action_timeout_ms:1000,
    idle_timeout_ms:2000,
    close_timeout_ms:1000,
    total_timeout_ms:5000,
    max_frame_bytes:65536,
    max_message_bytes:65536,
    max_inbound_frames:32,
    max_outbound_frames:32,
    max_inbound_messages:16,
    max_outbound_messages:16,
    max_inbound_bytes:262144,
    max_outbound_bytes:262144
  },
  actions:[
    {type:"send-text",text:"client-000000000000002a"},
    {type:"expect-text",equals:"server-000000000000002a",timeout_ms:1000},
    {type:"send-binary",payload_base64:"AAAAAAAAACo="},
    {type:"expect-binary",payload_base64:"KgAAAAAAAAA=",timeout_ms:1000},
    {type:"expect-text",equals:"seeded-000000000000002a",timeout_ms:1000},
    {type:"expect-close",codes:[1000],reason:"oracle-complete",timeout_ms:1000}
  ]
}' >"$source"

"$kahea" inspect "$source" >"$run_root/inspect.json" \
  || fail "oracle source inspection failed"
"$kahea" plan "$source" oracleSession --store "$store" >"$run_root/plan.json" \
  || fail "oracle session planning failed"
plan=$(jq -er '.id' "$run_root/plan.json") || fail "plan handle is missing"
jq -r '.required_grants[]' "$run_root/plan.json" >"$run_root/grants.txt"

set -- "$kahea" invoke "$plan" --store "$store"
while IFS= read -r grant; do
  set -- "$@" --grant "$grant"
done <"$run_root/grants.txt"
"$@" >"$run_root/observation.json" \
  || fail "oracle session invocation failed"
jq -e '.kind == "websocket-observation" and .exit == 0 and .terminal_cause == "completed"' "$run_root/observation.json" >/dev/null \
  || fail "client observation is not successful"

attempts=0
while kill -0 "$server_pid" 2>/dev/null && [ "$attempts" -lt 100 ]; do
  sleep 0.05
  attempts=$((attempts + 1))
done
kill -0 "$server_pid" 2>/dev/null \
  && fail "oracle did not exit after the session; observation: $oracle_observation"
wait "$server_pid" || fail "oracle exited unsuccessfully"
server_pid=
jq -e '.kind == "kahea-websocket-oracle-observation" and .seed == 42 and .case_id == "ws-000000000000002a-none" and .outcome == "completed" and .completed_steps == 8' "$oracle_observation" >/dev/null \
  || fail "oracle observation is invalid"

echo "WebSocket oracle smoke passed (seed=42, case=ws-000000000000002a-none)"
