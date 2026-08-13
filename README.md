<p align="center">
  <img src="assets/brand/kahea-primary.svg" width="360" alt="Kāhea">
</p>

# Kāhea

[![Tip my tokens](https://tokentip.to/badge/copyleftdev.svg?logo=1)](https://tokentip.to/@copyleftdev)

[Website](https://copyleftdev.github.io/kahea/) ·
[Documentation](docs/README.md) ·
[Releases](https://github.com/copyleftdev/kahea/releases) ·
[Agent plugin](plugins/kahea) ·
[MCP metadata](server.json)

Kāhea is a local-first, deterministic API invocation kernel for coding agents.

> Intent may be probabilistic. The call must be exact.

It turns OpenAPI descriptions, request captures, Arazzo workflows, and finite WebSocket sessions into integrity-sealed plans. Invocation is a separate operation guarded by exact capability grants; responses and inbound frames become typed observations and content-addressed evidence.

## Install Kāhea

Choose the pathway that matches your host. Claude Code, OpenAI Codex, and direct MCP clients all
reach the same four local MCP tools and the same inspect → plan → grant → invoke → evidence safety
contract.

### 1. Install the native binary

Download the archive for your operating system and architecture from
[GitHub Releases](https://github.com/copyleftdev/kahea/releases). Every archive is accompanied by
a SHA-256 checksum, a CycloneDX SBOM, and GitHub build provenance. Verify the checksum before
installing and verify provenance with:

```bash
gh attestation verify kahea-ARCHIVE --repo copyleftdev/kahea
```

Kāhea does not run an installer or modify shell configuration. Extract the archive and place the
`kahea` binary somewhere on `PATH`.

Tagged archives are built and tested on GitHub-hosted Linux, macOS, and Windows runners for the
runner architecture. See the [finite WebSocket guide](docs/websockets.md#platforms-and-release-gates)
for the exact WebSocket support and release-gate statement.

### 2a. Claude Code

Add this repository as a marketplace, then install the plugin:

```bash
claude plugin marketplace add copyleftdev/kahea
claude plugin install kahea@kahea
```

### 2b. OpenAI Codex

Add the same repository marketplace and canonical plugin package:

```bash
codex plugin marketplace add copyleftdev/kahea
codex plugin add kahea@kahea
```

Both plugins require the verified `kahea` binary on `PATH`. They add the canonical agent-use skill
and start the local stdio MCP server without downloading code or credentials at runtime. The shared
host package lives in [`plugins/kahea`](plugins/kahea); no host-specific copy of the safety workflow
is maintained.

### 2c. Any MCP client

Configure the client to start Kāhea over stdio:

```text
command: kahea
args: mcp serve --stdio
```

Tagged releases also publish self-contained, checksummed MCPB bundles and register
`io.github.copyleftdev/kahea` with the [official MCP Registry](https://registry.modelcontextprotocol.io/).

### Build from source

To build from source, install Rust 1.95 or newer:

```bash
cargo build --release -p kahea
```

## Build and verify

The repository pins the release toolchain in `rust-toolchain.toml`.

```bash
scripts/gates.sh
# Requires cargo-mutants; run locally, not in CI.
scripts/mutation-gate.sh
```

The release gate also launches the seeded loopback WebSocket oracle, plans its generated finite
session through the public CLI, invokes it with the plan's exact grants, and verifies both the
client observation and the oracle's reproducible seed/case observation. Replay that lifecycle with
`scripts/websocket-oracle-smoke.sh`; select an individual fault with
`kahea-test-server --protocol websocket --websocket-fault FAULT --seed SEED`.

The mutation gate is resource-bounded so it cannot take a workstation with it. It runs four jobs, caps compiler concurrency across all of them with a GNU jobserver, keeps its build copies on a disk path rather than a `tmpfs` `TMPDIR`, and confines itself to a transient systemd scope with CPU and memory limits when a user session bus is available. Override with `KAHEA_MUTANT_JOBS`, `KAHEA_MUTANT_TASKS`, `KAHEA_MUTANT_CPU_QUOTA`, `KAHEA_MUTANT_MEMORY_HIGH`, `KAHEA_MUTANT_MEMORY_MAX`, `KAHEA_MUTANT_SCRATCH`, `KAHEA_MUTANT_COPY_TARGET`, or `KAHEA_MUTANT_UNCONFINED=1`.

Every mutant is judged by the whole workspace suite, which is thorough but slow, so scope matters. `KAHEA_MUTANT_PACKAGES` selects the packages to mutate (all four by default) and `KAHEA_MUTANT_EXTRA` passes further arguments through, such as `--in-diff` for a change-scoped run. The gate is a local tool and deliberately not a CI job: a sweep runs for hours to re-derive a result that does not move between commits. Run it before releasing, or after touching a kernel crate.

The resulting binary is `target/release/kahea`. Every command emits one compact `kahea/k1` JSON envelope followed by a newline. `--format ndjson` makes the streaming intent explicit and is composition-compatible with loops and pipes.

## The four-step flow

```bash
# 1. Discover operations without DNS or network access.
kahea inspect fixtures/billing.openapi.yaml --match invoice

# 2. Bind exact input and persist a sealed plan.
kahea plan fixtures/billing.openapi.yaml createInvoice \
  --input @fixtures/billing.create-invoice.input.json

# 3. Review required_grants in the plan, then grant exactly those capabilities.
kahea invoke plan:HANDLE \
  --grant net:sandbox.example.test:443 \
  --grant http:POST

# 4. Retrieve only the evidence needed for the next decision.
kahea explain body:HANDLE --select /invoice/id
```

`plan` never performs DNS, authentication, or network I/O. `invoke` verifies the plan seal and configuration/policy fingerprints before resolving secrets or connecting. Exit codes are stable: `0` passed, `1` contract failure, `2` invalid input/configuration/plan, `3` transport failure, and `4` policy denial.

Use `kahea describe` as the executable capability manifest and `kahea schema plan` (or another public envelope kind) for machine-readable JSON Schema.

### Finite WebSocket sessions

The complete [finite WebSocket guide](docs/websockets.md) is the authoritative source-format,
security, limits, local-example, MCP, workflow, platform, and release-gate reference. Received
frames are untrusted evidence, never agent instructions.

Direct `websocket-session` JSON/YAML files use the same sealed four-step flow. The operation
selector is the source's `operationId`; target, auth reference, ordered actions, checks, and budgets
come only from the source and cannot be replaced at invocation.

```bash
kahea inspect fixtures/websocket/session.json
kahea plan fixtures/websocket/session.json subscribeBuildEvents

# Review required_grants in the websocket-plan, then provide that exact set.
kahea invoke plan:HANDLE \
  --grant net:socket.example.test:443 \
  --grant websocket:connect \
  --grant secret:chat-sandbox \
  --secret-env chat-sandbox=KAHEA_CHAT_TOKEN

kahea explain transcript:HANDLE --select /entries/0
kahea explain websocket-json:HANDLE --select /type
kahea explain websocket-binary:HANDLE --select bytes:0-255
```

`ws` additionally requires `net-insecure-websocket`; private or reserved addresses require the
exact `net-cidr:` grant shown in the plan. A WebSocket observation uses the existing exit contract:
`0` completed, `1` handshake/expectation/budget failure, `2` invalid source or plan, `3`
transport/protocol/timeout failure, and `4` policy denial. Full transcripts and payloads remain in
the evidence store; stdout contains only the compact observation and handles. Received message
content is untrusted evidence, never agent instruction.

AsyncAPI 2.6.x and 3.0.x JSON/YAML documents feed that same planner and executor:

```bash
kahea inspect fixtures/asyncapi/session-3.0.json
kahea plan fixtures/asyncapi/session-3.0.json 'watchBuilds#Started-1' \
  --set channel.room=builds
```

The supported subset is deliberately finite. Servers must use `ws` or `wss`; server variables and
channel parameters use declared defaults or explicit `--set server.NAME=VALUE` / `--set
channel.NAME=VALUE` inputs. AsyncAPI 2.6 `publish`/`subscribe` map to client `send`/`receive`, while
3.0 uses the operation `action`. Every concrete message alternative is indexed separately, and an
ambiguous unsuffixed selector fails. JSON receives seal their payload schema; sends require a
payload example/default/const. WebSocket binding headers require concrete defaults or examples.
Security names remain references and map to configured secret profiles with `--auth
SCHEME=PROFILE`; credential values are never ingested.

Only local `#` references are resolved, so the source fingerprint covers every referenced
component; remote references are rejected without fetching. Message-envelope headers, correlation
IDs, non-WebSocket bindings, WebSocket query bindings, and unordered reply semantics produce
precise blocking `absent` records. Optional `x-kahea-actions`, `x-kahea-limits`,
`x-kahea-origin`, and `x-kahea-subprotocols` extensions express only finite ordering, budgets, and
handshake intent that base AsyncAPI cannot encode.

## Supported sources

- OpenAPI 3.0, 3.1, and 3.2 in JSON or YAML
- Arazzo 1.1 workflows referencing local OpenAPI and finite WebSocket session sources
- Direct finite WebSocket session JSON/YAML
- AsyncAPI 2.6 and 3.0 WebSocket subset in JSON or YAML
- Postman Collection 2.1 JSON
- Postman Collection 3 directory/YAML format (`*.request.yaml` and `.resources`)
- HAR 1.2, common cURL, `.http`/`.rest`, and direct request YAML/JSON
- Standard input for deterministic text formats: `kahea inspect -`

"Supported" means the format is deterministically detected, inspectable, and capable of producing sealed plans for its documented subset. It does not mean every feature of the upstream application is emulated. Material unsupported behavior is reported in `absent` and blocks only the affected request when its scope is known.

Postman 2.1 imports nested requests, string and structured URLs, non-sensitive collection/folder variables, inherited basic/bearer/OAuth-style bearer/API-key metadata without credential values, raw bodies, response examples, and a narrow status-assertion subset. Postman v3 imports `*.request.yaml`/`*.request.yml`, request ordering, root and nested `definition.yaml` variables/auth metadata, headers, and raw bodies. V3 scripts are request-scoped blocking absences; v3 example and unknown resource files are currently explicit blocking absences rather than silently discarded. Non-raw Postman body modes, unresolved secret variables, unsupported auth, and material JavaScript also block their affected request. Kāhea never embeds Node or executes `pm.*` code. HAR responses and Postman 2.1 response examples become structural contracts, never copied response secrets.

The pinned offline corpus in [`fixtures/corpus`](fixtures/corpus) covers Swagger Petstore, Swagger Generator, PokéAPI, OpenAI, httpbin, OpenAPI 3.0–3.2, JSON/YAML, large schemas, security schemes, callbacks, webhooks, binary media, and an intentional Swagger 2 rejection. Import fixtures live in [`fixtures/imports`](fixtures/imports), and Arazzo examples live in [`fixtures/workflows`](fixtures/workflows). Public fixtures are descriptions only and are never invoked by the test suite.

## Inputs and bodies

Input documents may group values under `path`, `query`, `header`, `cookie`, and `body`. For body-only operations, the document itself may be the body. Exact overrides use repeatable `--set LOCATION.NAME=JSON_OR_TEXT`.

Kāhea supports canonical JSON, text/XML, form-urlencoded, deterministic multipart, and base64 binary bodies. Multipart file fields use a sealed descriptor:

```json
{
  "body": {
    "file": {
      "$file": "./artifact.bin",
      "filename": "artifact.bin",
      "content_type": "application/octet-stream"
    },
    "label": "release-candidate"
  }
}
```

The file is read during planning; its bytes and multipart boundary are part of the body digest and plan seal. Invocation never rereads the file.

## Authentication and secrets

Plans contain only profile references such as `secret://billing/sandbox`. Resolve a profile at invocation time by naming an environment variable—never by placing its value in CLI/MCP arguments:

```bash
kahea plan api.yaml createInvoice --auth bearerAuth=billing/sandbox
kahea invoke plan:HANDLE \
  --grant secret:billing/sandbox \
  --secret-env billing/sandbox=KAHEA_BILLING_TOKEN \
  --grant net:api.example.com:443 \
  --grant http:POST
```

Bearer and API-key profiles contain the raw token; basic profiles contain `username:password`; mTLS profiles contain PEM identity material. OAuth client-credentials and refresh profiles are JSON strings containing `client_id` plus `client_secret` or `refresh_token`. OAuth token endpoints receive their own planned network/HTTP grants. Redirects and ambient proxies are disabled, DNS answers are policy-checked and pinned, private/reserved addresses require exact CIDR grants, and credentials are never attached to an unplanned origin.

Resolved secret values, derived sensitive headers, configured sensitive response headers, and configured response JSON Pointers are redacted before evidence is persisted.

## Configuration and policy

Kāhea loads `.kahea/config.toml` by default or an explicit `--config`. See [`examples/config.toml`](examples/config.toml) and [`examples/policy.toml`](examples/policy.toml).

Named servers can be classified as production. Writes to a production origin require `approve:production-write`; destructive operations also require `approve:destructive`. Host allow/deny lists, maximum request bytes, response redaction, risk overrides, defaults, and secret-only auth references participate in sealed configuration/policy fingerprints. An invocation using different policy is rejected before network access.

## Declarative checks

OpenAPI status and response-schema checks are added by default. Repeat `--check` to provide an explicit set:

```text
status:200
status:any(200,201,204)
content-type:application/json
response-schema:openapi
header:X-Request-Id:exists
header:X-Mode=ready
json-pointer:/data/id:exists
json-pointer:/data/count:type=integer
json-pointer:/data/state="ready"
jsonpath:$.data[*]:exists
xpath:/root/item:exists
body-digest:b3:...
response-bytes:max:1048576
latency-ms:max:500
```

Any unknown check fails closed. Validation details are stored as evidence and affect exit code `1`.

## Arazzo workflows

Inspect and plan Arazzo with the same commands:

```bash
kahea inspect fixtures/workflows/billing.arazzo.yaml
kahea plan fixtures/workflows/billing.arazzo.yaml createAndReadInvoice \
  --input @fixtures/workflows/billing.input.json
kahea invoke workflow-plan:HANDLE --grant ...
```

V1 supports ordered HTTP and finite WebSocket steps, prior-step dependencies, bounded runtime
bindings, aggregate risk and exact grants, bounded retry/end actions, workflow-wide and step timeout
caps, sealed child plans, and per-attempt observation trees. HTTP sources use `type: openapi`, while
a direct WebSocket source description uses the specification extension
`x-kahea-source-kind: websocket-session` (with no misleading Arazzo `type`) and selects the source
`operationId`. See [`fixtures/workflows/mixed.arazzo.yaml`](fixtures/workflows/mixed.arazzo.yaml).

WebSocket steps bind prior outputs only through `x-kahea-websocket-bindings`. Each binding names an
existing JSON Pointer under `/actions/N/` and may replace only `text`, `payload_base64`, `equals`,
or `reason`; targets, authentication, limits, schemas, action order, and operation identity cannot
change at invocation. WebSocket outputs support handshake and close metadata, a specific matched
message by action index (`text`, `json`, `json#/pointer`, `base64`, or `evidence`), and evidence
handles for the transcript, handshake, and trace. Whole transcripts never become implicit inputs.
Binary data remains an explicit evidence handle or base64 value. Secret profile references flow
through the sealed child plan without materializing secret values.

HTTP steps additionally support `operationPath`, request inputs, simple/JSONPath/XPath success
criteria, and response-body outputs. AsyncAPI workflow source descriptions, callbacks, human approval nodes,
distributed scheduling, nested workflow steps, `goto`, and reusable action components remain
explicitly deferred.

## Deterministic conformance fuzzing

`conform` is Kāhea's native, single-binary counterpart to Python tools such as [Schemathesis](https://schemathesis.readthedocs.io/en/stable/). It derives bounded positive and negative cases from an OpenAPI operation without network access, seals every exact request as a normal plan, and stores a replayable campaign:

```bash
kahea conform fixtures/conformance/widgets.openapi.yaml updateWidget \
  --cases 32 --seed 42 --mode mixed --delay-ms 25

kahea invoke conformance-plan:HANDLE \
  --grant conformance:execute:32 \
  --grant conformance:negative \
  --grant net:api.example.test:443 \
  --grant http:POST
```

Positive cases exercise schema examples, enums, unions, object/array shapes, formats, and bounded string, numeric, and collection edges. Negative cases omit required values or introduce one named type, enum, length, unknown-property, or parameter violation. The response oracle rejects 5xx responses, checks every response against the declared status/content/schema contract, and verifies that negative data receives a conforming 4xx rejection. Findings link to per-case evidence and exact request-plan handles.

The seed, case count, pacing, failure bound, strategies, request digests, policy fingerprints, and grants are covered by the campaign seal. The same seed produces byte-identical campaigns. Generation is capped at 256 requests and fails closed on complex schema keywords or binary inputs that require explicit baseline values. Use `--input` and `--set` to pin resource identifiers or supply values the bounded generator cannot infer.

### Dynamic lifecycle oracle

The test-only `kahea-test-server` creates a different API on every startup, publishes the exact OpenAPI 3.1 contract for that instance, and enforces the same seeded scenario through a separate runtime validator. Each API contains three to six operations spanning GET, POST, PUT, and PATCH; randomized paths and operation IDs; path, query, and header parameters; JSON bodies; enums, booleans, bounded strings, constrained integers; and both success and rejection responses.

Run repeated black-box lifecycles with:

```bash
scripts/dynamic-conformance.sh 25
```

Each iteration starts on an OS-assigned loopback port, waits for an atomic readiness manifest, inspects every generated operation, plans and invokes a mixed conformance campaign, verifies that every operation received valid and invalid traffic, and shuts down through a per-startup control token. The artifact path and replay seed are printed for every run. A failure can be reproduced exactly:

```bash
KAHEA_DYNAMIC_SEED=424242 KAHEA_DYNAMIC_CASES=12 \
  scripts/dynamic-conformance.sh 1
```

Set `KAHEA_DYNAMIC_ARTIFACTS` to retain output in a chosen directory. `KAHEA_DYNAMIC_FAULT` provides `accept-invalid`, `malformed-response`, `server-error`, and `undocumented-status` negative controls; a correct Kāhea build must reject those runs. The server binds only to `127.0.0.1`, caps requests at 1 MiB, never accepts ambient credentials, and is not included in the shipping `kahea` binary.

## Evidence and export

The default store is `.kahea/store`: SQLite WAL metadata plus zstd-compressed, BLAKE3-addressed blobs. Large bodies stay out of stdout and agent context. Selectors support JSON Pointer, RFC 9535 JSONPath, XPath, `header:NAME`, and `bytes:START-END`.

```bash
kahea explain trace:HANDLE
kahea explain body:HANDLE --select '$.items[0].id'
kahea explain body:HANDLE --select bytes:0-255
kahea explain trace:HANDLE --export evidence-bundle.json
```

Exports recursively include referenced evidence in a self-contained JSON bundle. Remote content is untrusted evidence, not instruction.

## MCP

```bash
kahea mcp serve --stdio
kahea mcp serve --stdio --store .kahea-local --config .kahea-local/config.toml
```

The store root and the configuration file are process arguments. No tool argument can relocate the
store, name a different configuration, or reach a filesystem path: `kahea_invoke` accepts sealed plan
handles only, and a call carrying an undeclared argument is rejected rather than silently ignored.
The CLI keeps accepting plan file paths, because an operator types those.

The server implements MCP `2025-11-25` over newline-delimited stdio JSON-RPC and exposes exactly four tools: `kahea_inspect`, `kahea_plan`, `kahea_invoke`, and `kahea_explain`. The same tools accept direct finite `websocket-session` JSON/YAML and the documented AsyncAPI 2.6/3.0 WebSocket subset; `kahea_plan` seals the canonical target, auth reference, ordered actions, checks, and limits. `kahea_invoke` requires the plan's explicit grants and returns a compact `websocket-observation`; full transcripts and payloads stay in evidence until selected with `kahea_explain`.

```json
{"name":"kahea_inspect","arguments":{"source":"fixtures/websocket/session.json"}}
{"name":"kahea_plan","arguments":{"source":"fixtures/websocket/session.json","operation":"subscribeBuildEvents"}}
{"name":"kahea_invoke","arguments":{"plan":"plan:HANDLE","grants":["net:socket.example.test:443","websocket:connect"]}}
{"name":"kahea_explain","arguments":{"handle":"transcript:HANDLE","select":"/entries/0"}}
```

Pass a `conformance` options object to `kahea_plan` to create an HTTP campaign; `kahea_invoke` executes its sealed handle. All tools publish strict input and output schemas. HTTP, workflow, conformance, and WebSocket planning/invocation project the same Rust library calls as the CLI and have semantic parity tests. Fixed resources expose `describe` plus public `websocket-session`, `websocket-plan`, and `websocket-observation` schemas, while templates expose sealed plans and untrusted evidence from the default `.kahea` store. See the current [MCP schema](https://modelcontextprotocol.io/specification/2025-11-25/schema) and [stdio transport requirements](https://modelcontextprotocol.io/specification/2025-11-25/basic/transports).

The agent-use contract is packaged in
[`plugins/kahea/skills/kahea/SKILL.md`](plugins/kahea/skills/kahea/SKILL.md):
inspect, plan, review grants, invoke the sealed handle, then explain only selected evidence.

## Composition

Each invocation is one NDJSON record, so repeated observations can be sent directly to tools such as `anomalyx`:

```bash
for run in $(seq 1 100); do
  kahea --format ndjson invoke plan:HANDLE --grant net:api.example.com:443 --grant http:GET
done | anomalyx scan --format ndjson
```

For environment comparison, create plans against named servers, retain their configuration/source fingerprints, and compare observation streams rather than mutable collection state.

## Architecture and constraints

The workspace separates protocol types (`kahea-core`), ingestion, planning, execution, evidence, workflows, MCP, and the CLI while shipping one binary. Parser and transport types do not leak into public envelopes.

OpenAPI references are resolved within the loaded document. Remote references are never fetched during planning. Postman v3 directories are bounded to 10,000 files/64 MiB and reject symlinks; individual text sources are bounded to 64 MiB with depth/node limits. HAR imports require version 1.2, and Postman JSON imports require collection schema 2.1. HTTP redirects are denied rather than followed. Workflow retries are explicitly declared and capped at ten.

The product requirements are in [`KAHEA_PRD_v1.0.md`](KAHEA_PRD_v1.0.md). Arazzo behavior follows the official [Arazzo 1.1 specification](https://spec.openapis.org/arazzo/latest.html), and Postman v3 directory handling follows the current [Postman collection schema documentation](https://learning.postman.com/docs/use/use-collections/collections-schemas/).
