# Changelog

## 0.3.0 - 2026-08-13

- **Breaking (`kahea/k1`):** a close frame the plan does not accept is reported as
  `expectation-failed` even when the peer resets the connection while the close is being
  acknowledged. Previously that reset replaced the verdict with `io-failure`, so a server rejecting a
  session with an unacceptable close code and hanging up was reported as a local I/O problem.
  `io-failure` is now reported only when there is no verdict of its own to report
  ([#34](https://github.com/copyleftdev/kahea/issues/34)).
- **Breaking (MCP surface):** removed the `store` and `config` tool arguments. The store root and
  the configuration file are now process arguments of `kahea mcp serve --store/--config`, defaulting
  to the previous `.kahea` and `.kahea/config.toml`, so a tool call can no longer relocate the store
  or choose the policy its plans are measured against. The CLI is unchanged.
- **Breaking (MCP surface):** `kahea_invoke` and the `kahea://plan/{handle}` resource accept sealed
  plan handles only. Filesystem paths are rejected before any read, a resolved handle is confined to
  the pinned store through canonicalization, and every unresolved reference returns one message that
  does not report whether the target existed, parsed, or verified. `kahea invoke <plan.json>` on the
  CLI still accepts a path.
- **Breaking (MCP surface):** a tool call carrying an argument the tool does not declare is now
  rejected instead of silently ignored, so calls written against the previous schema fail loudly.
- The MCP configuration is read once at startup and held for the process lifetime, so a write inside
  the store cannot widen policy between a plan and its invocation, and an unreadable `--config` stops
  the server with `invalid-configuration` instead of failing every tool call. Changing policy now
  requires restarting the server.
- Recorded [ADR-0002](docs/architecture/0002-mcp-filesystem-boundary.md) and closed the reported
  `kahea_invoke.plan` to `fs::read` path ([#32](https://github.com/copyleftdev/kahea/issues/32)).
- Removed a class of wall-clock test flakes that intermittently blocked required checks on all three
  platforms: budgets a test does not assert are now generous, temporary stores are removed without
  failing a passing test, and CI caps intra-binary test parallelism
  ([#36](https://github.com/copyleftdev/kahea/issues/36)).

## 0.2.0 - 2026-08-09

- Added a complete finite WebSocket release guide covering the direct session format, controlled
  local CLI lifecycle, equivalent MCP calls, AsyncAPI and workflow entry points, security model,
  every default policy maximum, explicit non-goals, supported platforms, and release gates.
- Added deterministic finite WebSocket plans, exact grants, policy-gated `ws`/`wss` transport,
  bounded ordered execution, redacted transcript evidence, CLI/MCP/workflow parity, and the seeded
  controlled fault oracle.
- Added AsyncAPI 2.6/3.0 WebSocket ingestion into the canonical session planner with deterministic
  message selection, local references, variables, parameters, schemas, binding headers, auth
  references, structured absences, and no second executor.

## 0.1.0 - 2026-08-07

- Added a lightweight, kinetic GitHub Pages site with synchronized Claude Code, OpenAI Codex, direct MCP, and native-binary installation pathways; the static experience scores 100 across all four Lighthouse categories.
- Packaged Kāhea as one canonical Claude Code and OpenAI Codex plugin, added repository marketplace metadata, and added official MCP Registry discovery metadata plus checksummed, attested, platform-specific MCPB release publishing.
- Added a tag-driven GitHub Release pipeline for native Linux, macOS, and Windows binaries with SHA-256 checksums, CycloneDX SBOMs, third-party license notices, and signed build provenance.
- Added public-project release hygiene: a pinned and verified Rust 1.95 MSRV, non-publishable workspace crates, license and source policy, full-history secret scanning, Dependabot, issue forms, contribution/support/conduct guidance, and an explicit security-reporting policy.
- Added a schema-conformance suite for the case generator: every positive body and parameter is validated against the declared contract by an independent checker, declared bounds are shown to be explored across seeds, and every negative case is proven to violate the schema in the way its strategy names.
- Added a cookie-parameter fixture and contracts for it: cookies reach the wire as one sorted header, omitting or corrupting one cookie leaves its neighbour untouched, dropping one required query parameter keeps the others, and a server as strict as the contract agrees with every generated case. Cookie mutation had no fixture anywhere and had never executed.
- Added a generator-surface fixture and two byte-exact campaign goldens covering every schema construct the bounded generator supports, plus the optional-inclusion and supplied-baseline paths a single golden cannot reach. Goldens regenerate with `KAHEA_UPDATE_GOLDEN=1` and report the case that drifted rather than only a changed digest.
- Added generator edge contracts: self-referential schemas stop at the depth limit through each construct's own cycle, array and property-count bounds hold at their exact edges and fail closed beyond them, readOnly properties are never generated even to satisfy `minProperties`, string lengths hold at the 1024-character limit, an explicit override supplies values the bounded generator cannot infer, and negative cases accumulate across positive plans instead of stopping at the first.
- Added numeric generator contracts covering default and declared bounds, exclusive bounds that must be approached but never touched, single-value ranges that must generate rather than fail, `multipleOf` validation and application, multiples that land exactly on a bound, and fail-closed behaviour for inverted bounds and multiples with no admissible value.
- Widened the mutation gate to `kahea-conformance` and `kahea-ingest`, and made it actually run the workspace suite: cargo-mutants 27 silently ignores `--test-workspace` and `--test-package`, so each mutant was judged by its own crate's tests alone. Injecting `--workspace` into every cargo invocation raises the tests behind a mutant from 7 to 113.
- Bounded the mutation gate's resource use with a job-parallelism cap, a GNU jobserver task cap, a disk-backed scratch path instead of a `tmpfs` `TMPDIR`, and an optional transient systemd scope carrying CPU and memory limits.
- Added an in-process dynamic lifecycle test covering all four injected server faults, so `accept-invalid`, `server-error`, `undocumented-status`, and `malformed-response` are negative controls under `cargo test` rather than only under `scripts/dynamic-conformance.sh`.
- Added campaign contracts for seed reproducibility across a seed sweep, exact execution-grant accounting, per-mode generation and grant separation, seal coverage of seed/case count/pacing/failure bound, rejection of substituted or corrupt case plans before any request, configuration and policy fingerprint mismatch, and fail-closed generation for schema constructs the bounded generator cannot infer.
- Added cross-format ingestion contracts: content-driven detection independent of file name, byte-stable loading and content-addressed fingerprints for every advertised family, a credential-leak sweep across all capture formats, pagination as a faithful partition, case-insensitive query filtering, operation resolution by handle, operation id, and method-path, and a fail-closed matrix for malformed, oversized, and unsupported sources.
- Added deterministic, schema-aware OpenAPI conformance campaigns with positive and negative generation, replay seeds, policy-gated request counts, response oracles, per-case evidence, and CLI/MCP parity.
- Added a seeded, high-entropy loopback API oracle with per-startup OpenAPI contracts, independent runtime validation, lifecycle diagnostics, authenticated shutdown, fault injection, and replayable multi-iteration testing.
- Fixed negative path-parameter mutation so matching path segments are replaced without corrupting identical text in the URL authority.
- Added an inspect-to-plan compatibility matrix for every advertised input family, all OpenAPI 3.0–3.2 JSON/YAML combinations, and Arazzo JSON/YAML.
- Fixed imported open-schema request bodies, labeled multi-request HTTP files, HTTP-file CLI dispatch and standard-input detection, and HAR/Postman version enforcement.
- Expanded Postman import with structured URLs, inherited authentication, nested v3 folder variables, operation-scoped script/resource absences, raw-body planning, and explicit diagnostics for unsupported body modes and v3 resources.
- Introduced the stable `kahea/k1` describe, schema, operation-index, plan, observation, denial, evidence, explanation, and workflow envelopes.
- Added deterministic OpenAPI 3.0–3.2 inspection and request planning with provenance, sealed plans, project policy, named servers, common authentication, and exact grants.
- Added bounded HTTP execution with DNS pinning, SSRF protections, redirect denial, secret redaction, OpenAPI/declarative response checks, and content-addressed evidence.
- Added Postman 2.1 and v3 directory, HAR, cURL, HTTP-file, direct request, and Arazzo 1.1 ingestion.
- Added ordered Arazzo workflows with dependencies, deferred outputs, success criteria, retry/end actions, timeouts, derived subplans, and observation trees.
- Added the current MCP stdio projection, agent skill, fixture corpus, byte-exact cross-platform plan golden, release gates, mutation gate, and cross-platform CI.
