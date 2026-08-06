#!/usr/bin/env sh
set -eu

cd "$(dirname "$0")/.."
mkdir -p artifacts

if ! cargo cyclonedx --version >/dev/null 2>&1; then
  echo "install cargo-cyclonedx to generate the release SBOM" >&2
  exit 1
fi

cargo cyclonedx --format json --all --override-filename kahea.cdx
mv kahea.cdx.json artifacts/kahea.cdx.json
echo "wrote artifacts/kahea.cdx.json"
