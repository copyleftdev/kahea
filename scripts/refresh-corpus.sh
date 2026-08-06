#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
corpus_dir="${root_dir}/fixtures/corpus"

fetch() {
  local url="$1"
  local output="$2"
  curl --fail --location --proto '=https' --tlsv1.2 \
    --output "${corpus_dir}/${output}.new" "${url}"
  mv "${corpus_dir}/${output}.new" "${corpus_dir}/${output}"
}

fetch "https://petstore3.swagger.io/api/v3/openapi.json" "swagger-petstore-3.0.json"
fetch "https://generator3.swagger.io/openapi.json" "swagger-generator-3.0.json"
fetch "https://raw.githubusercontent.com/PokeAPI/pokeapi/master/openapi.yml" "pokeapi-3.1.yaml"
fetch "https://raw.githubusercontent.com/openai/openai-openapi/master/openapi.yaml" "openai-3.1.yaml"
fetch "https://httpbin.org/spec.json" "httpbin-swagger-2.0.json"

sha256sum "${corpus_dir}"/*.{json,yaml}
echo "Update manifest.json hashes and expected operation counts before committing refreshed snapshots."

