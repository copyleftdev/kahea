#!/usr/bin/env sh
set -eu

cd "$(dirname "$0")/.."

for file in \
  site/index.html \
  site/styles.css \
  site/app.js \
  site/robots.txt \
  site/sitemap.xml \
  site/assets/kahea-crest.svg \
  site/assets/kahea-primary.svg \
  site/assets/kahea-social.png \
  site/assets/fonts/gabarito-latin.woff2 \
  site/assets/fonts/gabarito-latin-ext.woff2 \
  site/assets/fonts/source-serif-4-latin.woff2 \
  site/assets/fonts/source-serif-4-latin-ext.woff2; do
  test -s "$file"
done

for command in \
  "claude plugin marketplace add copyleftdev/kahea" \
  "claude plugin install kahea@kahea" \
  "codex plugin marketplace add copyleftdev/kahea" \
  "codex plugin add kahea@kahea" \
  "kahea mcp serve --stdio" \
  "gh attestation verify kahea-ARCHIVE --repo copyleftdev/kahea"; do
  grep -F "$command" README.md >/dev/null
  grep -F "$command" site/index.html >/dev/null
done

grep -F "io.github.copyleftdev/kahea" README.md >/dev/null
grep -F "io.github.copyleftdev/kahea" site/index.html >/dev/null
grep -F "https://copyleftdev.github.io/kahea/" README.md >/dev/null

if grep -E 'background-clip:[[:space:]]*text|border-(left|right):[[:space:]]*[2-9]' site/styles.css >/dev/null; then
  echo "Site contains a prohibited visual pattern" >&2
  exit 1
fi

node --check site/app.js

echo "GitHub Pages install pathways are synchronized"
