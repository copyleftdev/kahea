#!/usr/bin/env sh
set -eu

cd "$(dirname "$0")/.."
mkdir -p artifacts

if ! cargo cyclonedx --version >/dev/null 2>&1; then
  echo "install cargo-cyclonedx to generate the release SBOM" >&2
  exit 1
fi

cargo cyclonedx \
  --manifest-path crates/kahea/Cargo.toml \
  --format json \
  --all \
  --target all \
  --override-filename kahea.cdx
mv crates/kahea/kahea.cdx.json artifacts/kahea.cdx.json
for generated in crates/*/kahea.cdx.json; do
  rm -f "$generated"
done
echo "wrote artifacts/kahea.cdx.json"
