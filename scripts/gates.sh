#!/usr/bin/env sh
set -eu

cd "$(dirname "$0")/.."

cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo build --release -p kahea -p kahea-test-server
scripts/validate-distribution.sh
scripts/validate-site.sh

binary=target/release/kahea
bytes=$(wc -c < "$binary")
if [ "$bytes" -gt 62914560 ]; then
  echo "release binary is $bytes bytes; limit is 62914560" >&2
  exit 1
fi

"$binary" describe | jq -e '.protocol == "kahea/k1" and .features.invoke.available and .features.conformance.available' >/dev/null
"$binary" schema plan | jq -e '.kind == "schema" and .name == "plan"' >/dev/null
"$binary" inspect fixtures/corpus/swagger-petstore-3.0.json | jq -e '.operations | length > 0' >/dev/null
"$binary" inspect fixtures/imports/postman-v3 | jq -e '.operations | length == 3' >/dev/null
"$binary" inspect fixtures/workflows/billing.arazzo.yaml | jq -e '.operations[0][3] == "createAndReadInvoice"' >/dev/null

temporary=$(mktemp -d)
trap 'rm -rf "$temporary"' EXIT INT TERM
"$binary" plan fixtures/billing.openapi.yaml createInvoice \
  --input @fixtures/billing.create-invoice.input.json \
  --store "$temporary/first" > "$temporary/first.json"
"$binary" plan fixtures/billing.openapi.yaml createInvoice \
  --input @fixtures/billing.create-invoice.input.json \
  --store "$temporary/second" > "$temporary/second.json"
cmp "$temporary/first.json" "$temporary/second.json"

"$binary" conform fixtures/conformance/widgets.openapi.yaml updateWidget \
  --cases 8 --seed 42 --store "$temporary/conformance-first" > "$temporary/conformance-first.json"
"$binary" conform fixtures/conformance/widgets.openapi.yaml updateWidget \
  --cases 8 --seed 42 --store "$temporary/conformance-second" > "$temporary/conformance-second.json"
cmp "$temporary/conformance-first.json" "$temporary/conformance-second.json"
jq -e '.kind == "conformance-plan" and (.cases | length == 8) and (.required_grants | contains(["conformance:execute:8", "conformance:negative"]))' "$temporary/conformance-first.json" >/dev/null

KAHEA_WEBSOCKET_ORACLE_ARTIFACTS="$temporary/websocket-oracle" \
  scripts/websocket-oracle-smoke.sh

KAHEA_DYNAMIC_ARTIFACTS="$temporary/dynamic" \
KAHEA_DYNAMIC_CASES=4 \
KAHEA_DYNAMIC_SEED=424242 \
  scripts/dynamic-conformance.sh 1

if KAHEA_DYNAMIC_ARTIFACTS="$temporary/dynamic-fault" \
  KAHEA_DYNAMIC_CASES=4 \
  KAHEA_DYNAMIC_SEED=424242 \
  KAHEA_DYNAMIC_FAULT=accept-invalid \
  KAHEA_DYNAMIC_SKIP_BUILD=1 \
  scripts/dynamic-conformance.sh 1 >"$temporary/dynamic-fault.log" 2>&1; then
  echo "dynamic conformance accepted an intentionally faulty server" >&2
  exit 1
fi
fault_operation=$(jq -er '.operations[0]' "$temporary/dynamic-fault/iteration-0-seed-424242/manifest.json")
jq -e '.kind == "conformance-observation" and .exit == 1 and .failed > 0' \
  "$temporary/dynamic-fault/iteration-0-seed-424242/$fault_operation/observation.json" >/dev/null

if command -v cargo-audit >/dev/null 2>&1; then
  cargo audit --deny warnings
else
  echo "cargo-audit is not installed; dependency audit skipped" >&2
fi

echo "Kāhea gates passed ($bytes-byte stripped release binary)"
