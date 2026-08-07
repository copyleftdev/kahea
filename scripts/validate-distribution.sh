#!/usr/bin/env sh
set -eu

cd "$(dirname "$0")/.."

json_files="
.agents/plugins/marketplace.json
.claude-plugin/marketplace.json
plugins/kahea/.codex-plugin/plugin.json
plugins/kahea/.claude-plugin/plugin.json
plugins/kahea/.mcp.json
packaging/mcpb/manifest.json
server.json
"

for file in $json_files; do
  jq empty "$file"
done

version=$(cargo metadata --no-deps --format-version 1 |
  jq -er '.packages[] | select(.name == "kahea") | .version')

for file in \
  plugins/kahea/.codex-plugin/plugin.json \
  plugins/kahea/.claude-plugin/plugin.json \
  packaging/mcpb/manifest.json \
  server.json; do
  jq -e --arg version "$version" '.version == $version' "$file" >/dev/null
done

jq -e --arg version "$version" \
  '.plugins[] | select(.name == "kahea") | .version == $version' \
  .claude-plugin/marketplace.json >/dev/null

jq -e '
  .name == "io.github.copyleftdev/kahea" and
  (.description | length <= 100) and
  .repository.source == "github" and
  .repository.id == "1325401405"
' server.json >/dev/null

jq -e '
  .mcpServers.kahea.command == "kahea" and
  .mcpServers.kahea.args == ["mcp", "serve", "--stdio"]
' plugins/kahea/.mcp.json >/dev/null

jq -e '
  .manifest_version == "0.3" and
  .server.type == "binary" and
  .server.mcp_config.args == ["mcp", "serve", "--stdio"] and
  ([.tools[].name] == [
    "kahea_inspect",
    "kahea_plan",
    "kahea_invoke",
    "kahea_explain"
  ])
' packaging/mcpb/manifest.json >/dev/null

test -f plugins/kahea/skills/kahea/SKILL.md
test -f plugins/kahea/skills/kahea/agents/openai.yaml
test -f plugins/kahea/skills/kahea/assets/kahea-crest.svg
test -f plugins/kahea/skills/kahea/assets/kahea-primary.svg

if command -v claude >/dev/null 2>&1; then
  claude plugin validate plugins/kahea --strict
  claude plugin validate . --strict
fi

echo "Distribution metadata is valid for Kāhea $version"
