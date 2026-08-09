import fs from "node:fs";
import path from "node:path";

const root = process.cwd();
const ignored = new Set([".git", "target"]);

function markdownFiles(directory) {
  return fs.readdirSync(directory, { withFileTypes: true }).flatMap((entry) => {
    if (ignored.has(entry.name)) return [];
    const absolute = path.join(directory, entry.name);
    if (entry.isDirectory()) return markdownFiles(absolute);
    return entry.isFile() && entry.name.endsWith(".md") ? [absolute] : [];
  });
}

const failures = [];
for (const file of markdownFiles(root)) {
  const text = fs.readFileSync(file, "utf8");
  const destinations = [
    ...text.matchAll(/\[[^\]]*\]\(([^)]+)\)/g),
    ...text.matchAll(/<(?:a|img)\b[^>]*(?:href|src)="([^"]+)"/g),
  ].map((match) => match[1].trim().replace(/^<|>$/g, "").split(/\s+["']/)[0]);

  for (const destination of destinations) {
    if (
      !destination ||
      destination.startsWith("#") ||
      /^(?:https?:|mailto:|data:)/.test(destination)
    ) {
      continue;
    }
    let pathname;
    try {
      pathname = decodeURIComponent(destination.split("#", 1)[0]);
    } catch {
      failures.push(`${path.relative(root, file)}: invalid URL encoding in ${destination}`);
      continue;
    }
    const target = path.resolve(path.dirname(file), pathname);
    if (!target.startsWith(`${root}${path.sep}`) || !fs.existsSync(target)) {
      failures.push(`${path.relative(root, file)}: missing local link ${destination}`);
    }
  }
}

const guide = fs.readFileSync(path.join(root, "docs/websockets.md"), "utf8");
for (const required of [
  "untrusted evidence,\nnot agent instructions",
  "scripts/websocket-oracle-smoke.sh",
  "net-insecure-websocket",
  "DNS once",
  "30,000 ms",
  "120,000 ms",
  "4,194,304 bytes (4 MiB)",
  "67,108,864 bytes (64 MiB)",
  "automatic retries or reconnects",
  "HTTP/2 RFC 8441 extended CONNECT",
  "WebSockets over HTTP/3",
  "CycloneDX SBOM",
  "provenance attestations",
]) {
  if (!guide.includes(required)) failures.push(`docs/websockets.md: missing contract text ${required}`);
}

if (failures.length) {
  console.error(failures.join("\n"));
  process.exit(1);
}

console.log("Documentation links and WebSocket release claims are synchronized");

