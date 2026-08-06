---
title: "KĀHEA"
subtitle: "The Agentic Invocation Kernel"
author: "Product Requirements Document · Don Johnson / copyleftdev"
date: "Version 1.0 · Final · August 5, 2026"
---

> **MANTRA**  
> **Intent may be probabilistic. The call must be exact.**

**One-line promise:** Give any coding agent an API description, captured request, or workflow, and Kāhea will discover, plan, authorize, invoke, verify, preserve, and explain the call through one deterministic executable contract.

**Product category:** Local-first agentic API invocation kernel  
**Executable:** `kahea`  
**Wire/output protocol:** `kahea/k1`  
**Canonical implementation:** Single Rust binary  
**Primary interfaces:** CLI and a thin MCP projection

---

# Contents

| Foundations and Contract | Execution and Delivery |
|---|---|
| 1. Executive Decision | 14. Security Model |
| 2. Executive Summary | 15. Determinism and Reproducibility |
| 3. Background and Opportunity | 16. Integration with `anomalyx` |
| 4. Vision | 17. Performance and Operational Requirements |
| 5. Users and Jobs to Be Done | 18. Quality and Test Strategy |
| 6. Goals and Non-Goals | 19. MVP Scope |
| 7. Product Principles and Invariants | 20. V1 Acceptance Criteria |
| 8. Core Conceptual Model | 21. Success Metrics |
| 9. CLI Contract | 22. Risks and Mitigations |
| 10. Functional Requirements | 23. Future Direction |
| 11. Machine Protocol: `kahea/k1` | 24. Launch Positioning |
| 12. MCP Interface | 25. Decision Log |
| 13. Architecture | 26. Final Product Definition |

# 1. Executive Decision

## 1.1 Final name

**Kāhea** is the final product name. The ASCII executable, repository slug, package name, and machine protocol use `kahea`; the human-facing brand retains the kahakō: **Kāhea**.

In ʻōlelo Hawaiʻi, *kāhea* means to call out, cry out, invoke, greet, or name.[^name-meaning] This is not decorative naming. It identifies the irreducible act beneath HTTP, REST, GraphQL, gRPC, Postman collections, SDKs, and MCP tools: **an invocation of a named capability**.

A traditional *mele kāhea* can be used to announce presence and seek permission to enter a new space; a response establishes whether entry is granted.[^mele-kahea] That call-and-response shape is unusually close to the semantics Kāhea must enforce:

1. Identify the intended place or capability.
2. Declare the purpose and required inputs.
3. Request permission under explicit rules.
4. Enter only when authorized.
5. Preserve the answer and its evidence.

The cultural analogy will be used respectfully and narrowly. Kāhea will not claim to reproduce or digitize Hawaiian protocol. Before commercial branding, the name, pronunciation, and narrative should be reviewed with a fluent ʻōlelo Hawaiʻi speaker or cultural practitioner.

## 1.2 The genesis of an API call

An endpoint is only a location. A schema is only a shape. Authentication is only permission. Transport is only movement. None of those independently constitutes an API call.

The universal primitive is an **invocation**:

```text
Invocation = target + operation + inputs + authority + expectations
```

- **Target** answers where or which service.
- **Operation** names the capability being requested.
- **Inputs** supply the arguments.
- **Authority** determines whether the caller may act.
- **Expectations** define what counts as a valid outcome.

Kāhea exists to turn that invocation from an agent’s probabilistic intent into an exact, sealed, inspectable execution artifact.

## 1.3 Product thesis

> **The agent chooses the intent. Kāhea owns the call.**

The model may reason, search, compare, and decide. It must not be responsible for silently inventing URLs, interpolating secrets, guessing encodings, mutating request bodies, deciding whether a side effect is acceptable, or parsing enormous responses from prose.

Kāhea is not “Postman in a terminal.” It is the execution kernel beneath any agent that needs to use an API safely.

## 1.4 Final product decisions

| Decision | Final choice |
|---|---|
| Product name | **Kāhea** |
| Product descriptor | **The Agentic Invocation Kernel** |
| Mantra | **Intent may be probabilistic. The call must be exact.** |
| Canonical interface | Machine-readable CLI |
| Agent integration | Thin local MCP server over the same core library |
| Runtime | One Rust binary; no required daemon or cloud account |
| Execution model | Explicit two-phase `plan → invoke` |
| State model | Content-addressed local evidence store; no hidden workspace state |
| Core unit | Addressable operation and sealed request plan, not collection or folder |
| Default output | Versioned JSON envelope with evidence handles |
| Scripting | Declarative assertions only in v1; no embedded Node/JavaScript runtime |
| Workflow interchange | Arazzo 1.1 for multi-call workflows |
| API description baseline | OpenAPI 3.0–3.2 |
| Safety model | Capability grants, policy evaluation, risk classification, sealed plans |
| Composition | Unix pipes, NDJSON, MCP, and direct process execution |

# 2. Executive Summary

Kāhea is a local-first, agent-native API invocation kernel. It ingests API descriptions and request artifacts, normalizes them into a typed `ApiGraph`, exposes compact operation discovery, produces a deterministic `RequestPlan`, enforces security policy, executes the sealed plan, validates the response, stores large evidence outside the model context, and returns a compact `Observation` that an agent can trust.

Current API tools are generally optimized around human workspaces, tabs, collections, environment editors, dashboards, and collaboration surfaces. Postman’s current CLI is collection-oriented, and Postman Agent Mode operates across Postman resources such as collections, workspaces, environments, tests, mocks, and flows.[^postman-cli][^postman-agent] Those are valuable product surfaces for human API lifecycle work. Kāhea deliberately chooses a different abstraction:

```text
Agent → ApiGraph → RequestPlan → policy gate → invocation → Observation → evidence
```

The product is designed for Claude Code, Codex, terminal agents, CI systems, QA automation, security tooling, and any process that can execute a local binary or consume MCP tools. Claude Code supports local stdio MCP servers, making a single local binary a natural deployment model.[^claude-mcp]

The v1 release focuses on HTTP APIs and supports OpenAPI 3.0 through 3.2, Postman collection import, HAR, raw cURL, `.http` request files, and Arazzo 1.1 workflows. OpenAPI 3.2.0 is the current published OpenAPI specification, while Arazzo 1.1.0 defines machine-readable sequences of API calls and their dependencies.[^openapi][^arazzo]

# 3. Background and Opportunity

## 3.1 Why this product now

Coding agents can already run shell commands, read API specifications, generate code, and connect to MCP servers. The missing primitive is not another conversational layer. It is a compact executable contract that gives an agent the power of a full API client without giving the model uncontrolled ownership of transport, credentials, side effects, or response interpretation.

A human can often notice that a generated URL is wrong, a secret leaked into output, a destructive method targets production, or an environment variable came from the wrong scope. An agent needs these concerns made explicit and machine-verifiable.

## 3.2 Failure modes in the current agent workflow

### Request construction by prose

The model reads documentation and constructs a cURL command or SDK call. It may choose the wrong server, omit required encoding, invent a field, or silently use an example value.

### Hidden environment state

Human-oriented API clients often make environment inheritance convenient. For an agent, invisible precedence and mutable variables create non-reproducible behavior.

### Side effects without a stable review boundary

An agent may display one request, then reconstruct a slightly different request at execution time. Approval attaches to prose rather than to exact bytes.

### Unbounded context consumption

Raw responses, traces, binary payloads, and validation trees can flood the model context. The agent needs a summary and addressable evidence, not every byte by default.

### Weak provenance

When a header or body field is wrong, the caller often cannot determine whether it came from the specification, an environment, a default, a workflow output, a secret provider, or model-generated input.

### False completeness

Imports may ignore unsupported scripts, authentication modes, or collection behavior. An agent interprets a partial import as complete unless absence is represented explicitly.

### Platform coupling

A full SaaS workspace may be inappropriate for local development, air-gapped work, CI, temporary sandboxes, or organizations that want the executable—not a hosted collaboration model—to be the contract.

# 4. Vision

## 4.1 Vision statement

**Any agent should be able to use any well-described API safely through one small, deterministic, local executable.**

Kāhea becomes the layer between probabilistic reasoning and irreversible external action. The agent says what it wants. Kāhea identifies the exact operation, resolves inputs, proves the resulting request, enforces policy, performs the invocation, verifies the outcome, and preserves evidence.

## 4.2 Product promise

Given the same source bytes, explicit inputs, environment fingerprint, policy version, and configuration version, Kāhea produces a byte-identical request plan.

Remote systems remain nondeterministic. Kāhea does not pretend otherwise. It separates:

- **Deterministic planning:** what will be sent and why.
- **Controlled invocation:** whether it is permitted to be sent.
- **Observed execution:** what actually occurred.

## 4.3 Product positioning

**Postman is an API workspace. Kāhea is an API kernel.**

**cURL sends bytes. Kāhea proves the invocation.**

**Generated SDKs expose one API. Kāhea normalizes many API artifacts into one agent contract.**

**MCP exposes tools. Kāhea gives those tools a transport, policy, evidence, and determinism spine.**

# 5. Users and Jobs to Be Done

## 5.1 Primary user: coding agent

When an agent needs to call an API, it must be able to:

- Discover relevant operations without consuming an entire specification.
- Ask for the exact schema and required inputs of one operation.
- Produce a side-effect-free plan.
- Know whether the operation is read, write, destructive, or unknown risk.
- Request only the capabilities required for that plan.
- Invoke the exact reviewed plan without reconstructing it.
- Validate the result against the declared contract.
- Drill into a response or trace through handles.

## 5.2 QA and systems tester

When testing an API, the user must be able to:

- Import existing OpenAPI or Postman assets.
- Execute deterministic positive, negative, and boundary cases.
- Preserve request and response evidence.
- Compare environments without copying mutable collections.
- Export observations into `anomalyx` for drift and anomaly detection.
- Reproduce a failure from a sealed plan and evidence handle.

## 5.3 Platform and API engineer

When publishing or maintaining an API, the user must be able to:

- Verify that a specification is executable.
- Detect missing or contradictory request information.
- Exercise workflows from Arazzo.
- Validate responses against OpenAPI schemas.
- Run the same invocation locally and in CI.
- Share plans without sharing secrets.

## 5.4 Security and reliability engineer

When permitting an agent to interact with an API, the user must be able to:

- Restrict hosts, methods, networks, redirects, and secret scopes.
- Require explicit approval for write or destructive plans.
- Audit exactly what was sent.
- Confirm that secrets were not emitted.
- Deny SSRF, private-network access, dangerous redirects, oversized bodies, or excessive retries.

# 6. Goals and Non-Goals

## 6.1 Goals

1. Convert heterogeneous API artifacts into one typed, stable `ApiGraph`.
2. Make operation discovery compact and deterministic.
3. Separate planning from execution with a sealed plan boundary.
4. Expose exact provenance for every resolved request value.
5. Enforce capability-based safety before network access.
6. Validate responses and return machine-readable observations.
7. Preserve large or sensitive evidence outside agent context.
8. Work as a standalone CLI and as a thin local MCP server.
9. Remain local-first, composable, and useful without an account.
10. Provide explicit absence for unsupported imported behavior.
11. Integrate naturally with the user’s existing `anomalyx` philosophy and toolchain.

## 6.2 Non-goals for v1

- A graphical API client.
- A hosted workspace or team collaboration platform.
- A cloud synchronization service.
- API design governance, documentation hosting, or portal management.
- A mock-server platform.
- A monitoring scheduler.
- A load-testing platform.
- A general-purpose programming runtime.
- Full emulation of Postman’s JavaScript `pm.*` environment.
- Automatic LLM selection of operations inside the binary.
- Silent repair of malformed specifications.
- Support for every protocol in the first release.

# 7. Product Principles and Invariants

## 7.1 The model chooses; the binary proves

Semantic reasoning belongs to the agent. URL construction, parameter binding, encoding, authentication application, schema validation, and policy enforcement belong to Kāhea.

## 7.2 Plan before invoke

Every network operation must originate from a sealed `RequestPlan`. `invoke` accepts a plan handle or plan file; it does not accept ad hoc method/URL/body arguments in agent mode.

A separate human convenience command may be introduced later, but it must internally create and expose the plan before execution.

## 7.3 Same inputs, same plan

The plan contains no wall-clock timestamp, random identifier, resolved secret material, live DNS result, or network-derived value. Canonical serialization and stable ordering guarantee byte-identical output for identical inputs.

## 7.4 Approval binds to bytes

The plan fingerprint covers the canonical URL, method, headers excluding secret material, body digest, operation identity, source fingerprints, policy version, configuration version, and required grants. Invocation refuses a mutated plan.

## 7.5 Every value has provenance

Every path segment, query item, header, cookie, and body field can be explained as originating from one of:

- Explicit user or agent input.
- Workflow output.
- Source example explicitly selected by the caller.
- Schema default.
- Project configuration.
- Secret reference.
- Protocol-required generated value.

Unknown provenance is an error.

## 7.6 Secrets are references, never plan values

Plans carry identifiers such as `secret://billing/sandbox`, not the credential. Secret material is resolved at invocation time and redacted before evidence serialization.

## 7.7 Absence is data

Unsupported scripts, authentication modes, protocol features, and unresolved references appear in an `absent` array with reason, source location, severity, and whether the absence blocks invocation.

## 7.8 Compact by default

Large bodies, traces, certificates, and validation trees are stored and returned as handles. Agent output defaults to the smallest envelope that permits correct next action.

## 7.9 No hidden mutable workspace state

All state affecting a plan must be represented by explicit files, command arguments, source fingerprints, policy fingerprints, or secret references.

## 7.10 Local-first and composable

The canonical product is one binary. No account, browser login, daemon, or cloud service is required. JSON and NDJSON compose with shell tools and agent runtimes.

# 8. Core Conceptual Model

```text
API artifact(s)
    │
    ▼
SourceSet ──normalize──▶ ApiGraph
                           │
                           ├── discover ──▶ OperationSummary
                           │
                           └── bind ──────▶ RequestPlan
                                               │
                              policy evaluate ─┤
                                               ▼
                                           Invocation
                                               │
                                               ▼
                                           Observation
                                               │
                                               ▼
                                          EvidenceStore
```

## 8.1 `SourceSet`

The immutable set of source bytes and metadata provided for inspection. Every source receives a content fingerprint and parser result.

## 8.2 `ApiGraph`

A protocol-neutral graph containing:

- Services and servers.
- Operations.
- Parameters and request schemas.
- Response schemas.
- Authentication requirements.
- Examples.
- Workflows.
- Source provenance.
- Explicit unsupported or unresolved features.

The graph never preserves a third-party library type as its public contract.

## 8.3 `Operation`

An addressable capability with a stable identity. For HTTP, identity is derived from canonical source identity, method, normalized path template, and operation metadata. Display names and array positions do not define identity.

Example:

```text
op:9e4c2f7d6d8a
```

## 8.4 `RequestPlan`

A deterministic, side-effect-free artifact that declares the exact invocation and required permissions.

```json
{
  "protocol": "kahea/k1",
  "kind": "plan",
  "id": "plan:91ab7e0f",
  "operation": "op:9e4c2f7d6d8a",
  "target": "https://sandbox.example.com/v1/invoices",
  "method": "POST",
  "risk": "write",
  "required_grants": [
    "net:sandbox.example.com:443",
    "http:POST",
    "secret:billing/sandbox"
  ],
  "secret_refs": ["secret://billing/sandbox"],
  "body": {
    "media_type": "application/json",
    "bytes": 184,
    "blake3": "6c11…"
  },
  "checks": [
    "status:201",
    "response-schema:openapi"
  ],
  "valid": true,
  "fingerprint": "b3:19f4…"
}
```

## 8.5 `Invocation`

The runtime act of resolving approved secret references, enforcing network policy, sending the sealed request, and collecting response evidence.

## 8.6 `Observation`

A compact statement of what happened:

```json
{
  "protocol": "kahea/k1",
  "kind": "observation",
  "plan": "plan:91ab7e0f",
  "outcome": "passed",
  "status": 201,
  "response_schema": "passed",
  "latency_ms": 84.31,
  "response_bytes": 918,
  "body": "body:329cc8d1",
  "trace": "trace:6de211a0",
  "exit": 0
}
```

## 8.7 `EvidenceHandle`

An immutable address into the local content-addressed evidence store:

```text
body:329cc8d1
trace:6de211a0
schema-error:f8110a7c
request-derivation:cc6712b4
certificate:8da10f2e
```

# 9. CLI Contract

## 9.1 Command surface

```text
kahea describe
kahea schema [graph|plan|observation|evidence]
kahea inspect <SOURCE...> [--match QUERY] [--limit N]
kahea plan <SOURCE...> <OPERATION> [INPUT OPTIONS]
kahea invoke <PLAN> [POLICY OPTIONS]
kahea explain <HANDLE> [--select SELECTOR]
kahea mcp serve [--stdio]
```

The six public nouns and verbs are intentionally small. The CLI must not grow into a mirrored GUI hierarchy.

## 9.2 `describe`

Returns protocol version, supported formats, supported authentication modes, safety controls, output kinds, exit codes, configuration keys, and explicit feature availability.

```bash
kahea describe
```

This is the executable operating manual for an agent.

## 9.3 `schema`

Returns JSON Schema for any public envelope:

```bash
kahea schema plan
kahea schema observation
```

Agents validate output rather than infer field meaning.

## 9.4 `inspect`

Parses and normalizes sources, then emits a compact operation catalog.

```bash
kahea inspect openapi.yaml --match invoice
```

Example:

```json
{
  "protocol": "kahea/k1",
  "kind": "operation-index",
  "source": "src:12b781e0",
  "operations": [
    ["op:9e4c2f7d6d8a", "POST", "/v1/invoices", "createInvoice", "write"],
    ["op:188ccb4a1c90", "GET", "/v1/invoices/{id}", "getInvoice", "read"]
  ],
  "next": null,
  "absent": []
}
```

`--match` is deterministic text and metadata matching. The binary does not embed an LLM. The agent performs semantic selection.

## 9.5 `plan`

Binds explicit inputs to one operation and creates a sealed request plan without network access.

```bash
kahea plan openapi.yaml op:9e4c2f7d6d8a \
  --server sandbox \
  --input @invoice.json \
  --auth billing/sandbox
```

Planning must:

- Resolve the selected operation.
- Validate all path, query, header, cookie, and body inputs.
- Reject unknown inputs unless the operation explicitly permits them.
- Apply explicit defaults and record provenance.
- Select content type deterministically.
- Resolve an exact server from explicit input or unambiguous source definition.
- Classify operation risk.
- Determine required grants.
- Record secret references without reading secret material.
- Generate request body bytes and digest.
- Validate the request against the source contract.
- Evaluate plan-time policy.
- Produce a canonical fingerprint.
- Perform zero DNS, authentication, or network operations.

## 9.6 `invoke`

Executes a sealed plan:

```bash
kahea invoke plan:91ab7e0f \
  --grant net:sandbox.example.com:443 \
  --grant http:POST \
  --grant secret:billing/sandbox
```

Invocation must:

- Load and verify the plan fingerprint.
- Confirm policy and configuration compatibility.
- Resolve secret references.
- Re-evaluate runtime conditions such as target address policy.
- Enforce timeout, redirect, retry, body-size, and response-size limits.
- Send exactly the planned non-secret bytes.
- Capture request and response evidence with redaction.
- Validate declared checks.
- Return one compact observation.

## 9.7 `explain`

Resolves handles and supports targeted selection:

```bash
kahea explain body:329cc8d1 --select /invoice/id
kahea explain request-derivation:cc6712b4
kahea explain schema-error:f8110a7c
```

Selectors supported in v1:

- JSON Pointer.
- RFC 9535 JSONPath.
- XPath for XML evidence.
- Header name selection.
- Byte ranges for binary evidence.

## 9.8 `mcp serve`

Starts a local stdio MCP server exposing the same core operations:

```bash
claude mcp add kahea -- kahea mcp serve
```

The MCP adapter must not duplicate planning or execution logic. It is a serialization and transport projection over the canonical Rust libraries.

# 10. Functional Requirements

## 10.1 Source ingestion and normalization

### V1 required sources

| Source | Required support |
|---|---|
| OpenAPI | 3.0.x, 3.1.x, 3.2.x; JSON and YAML |
| Arazzo | 1.1.x workflows referencing supported OpenAPI sources |
| Postman | Collection 2.1 JSON and collection v3 YAML import |
| HAR | Request and response capture import |
| cURL | Common generated cURL request syntax |
| HTTP files | `.http` and `.rest` request documents |
| Direct descriptor | Kāhea request YAML/JSON for APIs without a formal spec |
| Standard input | All text formats where deterministic detection is possible |

### Parser requirements

1. Content fingerprint before parsing.
2. Deterministic format resolution using explicit type, extension, then content signature.
3. Full document parse before reference resolution.
4. Stable source locations for every imported field.
5. Structured diagnostics for malformed, ambiguous, and unsupported content.
6. No silent dropping of scripts or authentication behavior.
7. Parser libraries must be hidden behind `kahea-core` types.

### Postman compatibility policy

Kāhea imports requests, variables, examples, authentication metadata, and statically recognizable assertions. It does **not** embed Node or execute arbitrary collection JavaScript in v1.

Unsupported pre-request or post-response scripts are represented as:

```json
{
  "capability": "postman-script",
  "reason": "arbitrary JavaScript execution is not supported",
  "location": "collection.items[4].event[0]",
  "blocking": true
}
```

A strict import blocks invocation when unsupported behavior can materially alter the request or verdict. An explicit `--allow-absent` may permit non-material absence, but never silently.

## 10.2 Operation discovery

Kāhea must support:

- Filter by operation ID, method, path, tag, source, risk, and authentication requirement.
- Stable pagination.
- Compact summaries with handles to detailed schemas.
- Exact lookup by operation handle.
- Detection of duplicate or conflicting operation IDs.
- Source provenance for operation metadata.

Kāhea should not rank operations with an embedded generative model. An optional future adapter may provide embeddings, but deterministic matching remains canonical.

## 10.3 Input binding

### Precedence

The binding precedence is fixed:

```text
explicit CLI field
→ explicit input document
→ workflow output
→ selected example
→ project configuration
→ schema default
→ absent/error
```

Environment variables are not ambient fallbacks. They are read only through explicit mappings such as:

```toml
[bindings]
account_id = "env://BILLING_ACCOUNT_ID"
```

### Binding requirements

- Unknown input keys are errors by default.
- Missing required values are errors.
- Null and absent remain distinct.
- Numeric coercion is never implicit unless authorized by source semantics.
- URL encoding follows the source contract exactly.
- Duplicate query parameter behavior is explicit.
- Cookies and headers are case-aware according to protocol rules.
- Body serialization is deterministic.
- Multipart boundaries are generated at invocation while the plan fingerprints the logical parts and deterministic content digests.

## 10.4 Server and target resolution

- Server selection is explicit when multiple valid servers exist.
- Source variables must be fully resolved before a plan is valid.
- Relative URLs are resolved against explicit source identity.
- Production-like hosts can be tagged by policy, not guessed from names alone.
- The final origin appears in the plan and required grants.
- IP literals, loopback, link-local, private, multicast, and metadata-service ranges are denied unless explicitly granted.

## 10.5 Authentication and secrets

### V1 authentication

- API key in header, query, or cookie.
- HTTP Basic.
- Bearer token.
- OAuth 2.0 client credentials.
- OAuth 2.0 refresh-token exchange through an explicit credential profile.
- Mutual TLS through certificate references.

### Deferred authentication

- Interactive authorization code and device code UX.
- AWS SigV4.
- NTLM and Kerberos.
- Vendor-specific signing schemes.

### Secret providers

- Explicit environment reference.
- OS keyring.
- Encrypted local secret file.
- External command provider with strict JSON output and timeout.

Example:

```toml
[auth.billing-sandbox]
type = "bearer"
token = "secret://billing/sandbox"

[secrets.billing-sandbox]
provider = "command"
command = ["op", "read", "op://Engineering/Billing Sandbox/token"]
```

Rules:

1. Secret values never enter a plan.
2. Secret values never appear in stdout, logs, traces, or error strings.
3. Secret provider output is size-limited and treated as sensitive memory.
4. Evidence records the reference and optional provider revision, not the value.
5. Authentication refresh is observable and separately evidenced.

## 10.6 Risk classification

Every operation receives one of:

- `read`
- `write`
- `destructive`
- `unknown`

Method-derived defaults are advisory. Source annotations and project policy may override classification. Unknown is never treated as safe.

Example policy:

```toml
[risk]
"POST /v1/search" = "read"
"POST /v1/accounts/{id}/close" = "destructive"
```

## 10.7 Policy and capabilities

A plan declares all required capabilities. Invocation grants must cover them exactly.

Capability families:

```text
net:<host>:<port>
net-cidr:<cidr>
http:<method>
secret:<profile>
filesystem-read:<path>
filesystem-write:<path>
redirect:<host>
tls-client-cert:<profile>
```

Policy can be supplied by:

1. Built-in secure defaults.
2. User policy.
3. Project policy.
4. Invocation grants.

More restrictive policy wins. A project cannot weaken a user-level denial without an explicit user grant.

## 10.8 HTTP execution

### Required protocol support

- HTTP/1.1 and HTTP/2.
- HTTPS with certificate validation enabled.
- JSON, XML, text, form-urlencoded, multipart, and binary bodies.
- File upload and streaming download.
- Compression negotiation.
- Cookie handling only when explicitly enabled by plan.
- Proxy configuration only through explicit policy.

### Runtime controls

- Connect timeout.
- Overall timeout.
- Maximum redirects.
- Redirect origin policy.
- Maximum request bytes.
- Maximum response bytes retained in memory.
- Streaming threshold.
- Retry count and retryable conditions.
- Concurrency limits for workflows.

Retries are disabled by default for non-idempotent operations. Source or policy may declare an idempotency key and safe retry behavior.

## 10.9 Response validation

V1 checks:

- Allowed or exact status code.
- Header existence and value predicate.
- Content type.
- OpenAPI response schema.
- JSON Schema.
- JSON Pointer equality, existence, and type.
- RFC 9535 JSONPath predicate.
- XPath predicate.
- Body digest.
- Response byte budget.
- Latency budget.
- Explicit expected-error assertions.

No arbitrary JavaScript assertion runtime is included. A small declarative expression language may be added only if JSON Pointer, JSONPath, XPath, and typed predicates are insufficient.

## 10.10 Workflows

Arazzo 1.1 is the canonical workflow interchange format.

V1 workflow support includes:

- Ordered OpenAPI steps.
- Inputs and outputs.
- Step dependencies.
- Runtime expression binding.
- Success criteria.
- Retry and end actions.
- Step-level timeout.
- Workflow observation tree.
- Evidence handles per step.

Deferred:

- AsyncAPI send/receive steps.
- Long-running external callbacks.
- Human approval nodes inside a workflow.
- Distributed workflow scheduling.

A workflow is planned before execution. The plan exposes all known operations and grants; values dependent on prior responses are represented as typed deferred bindings. Each step receives a derived sealed sub-plan when its dependencies resolve.

## 10.11 Evidence store

Default local layout:

```text
.kahea/
  config.toml
  policy.toml
  store/
    index.sqlite
    blobs/
    plans/
    observations/
```

Requirements:

- SQLite metadata index.
- BLAKE3 content addressing.
- Zstandard compression for eligible blobs.
- Atomic writes.
- Stream large bodies directly to disk.
- Configurable retention.
- Redaction before persistence.
- Optional encryption at rest.
- Garbage collection by reachability and retention policy.
- Export of a self-contained, redacted evidence bundle.

## 10.12 Explainability

Every plan must be explainable at field level.

Example derivation:

```json
{
  "field": "body.currency",
  "value": "USD",
  "source": "schema-default",
  "source_location": "openapi.yaml#/components/schemas/Invoice/properties/currency/default",
  "transformations": []
}
```

For encoded fields:

```json
{
  "field": "query.filter",
  "logical_value": "status:open AND owner:me",
  "wire_value": "status%3Aopen%20AND%20owner%3Ame",
  "source": "input:/filter",
  "encoding": "form-explode-false"
}
```

# 11. Machine Protocol: `kahea/k1`

## 11.1 Envelope requirements

Every stdout JSON object includes:

- `protocol`
- `kind`
- `version`
- `config_fingerprint`
- `source_fingerprints` where applicable
- `exit`

Human-readable explanations go to stderr only when requested. Default agent mode emits no ANSI color and no decorative prose.

## 11.2 Canonical serialization

- UTF-8 JSON.
- Stable key ordering.
- Stable array ordering where order is semantic.
- Canonical number formatting.
- No timestamps in deterministic artifacts.
- BLAKE3 fingerprints over canonical bytes.
- Public schema changes require protocol versioning.

## 11.3 Output sizing

- Default operation index limit: 50.
- Default inline body limit: 4 KiB for text and JSON.
- Default validation detail limit: 20 errors.
- Larger values become handles.
- MCP responses target fewer than 8,000 tokens and should normally remain far below that.

## 11.4 Exit codes

| Code | Meaning |
|---:|---|
| 0 | Invocation completed and all declared checks passed |
| 1 | Remote response received, but one or more contract checks failed |
| 2 | Invalid source, configuration, input, plan, or internal tool error |
| 3 | Transport, DNS, TLS, timeout, or connection failure |
| 4 | Policy denied the plan or invocation |

Exit codes are stable protocol commitments.

# 12. MCP Interface

## 12.1 Tools

The MCP server exposes exactly four operational tools:

```text
kahea_inspect
kahea_plan
kahea_invoke
kahea_explain
```

Meta-capabilities such as schemas and descriptions are exposed as resources to minimize tool count.

## 12.2 Resources

```text
kahea://describe
kahea://schema/plan
kahea://schema/observation
kahea://operation/op:9e4c2f7d6d8a
kahea://plan/plan:91ab7e0f
kahea://evidence/body:329cc8d1
```

## 12.3 Tool behavior

- `kahea_inspect` is read-only and performs no network activity.
- `kahea_plan` is read-only and performs no network activity.
- `kahea_invoke` may have side effects and always returns risk and grant information.
- `kahea_explain` reads local evidence only.

## 12.4 Agent skill

The release includes a concise `SKILL.md` that teaches agents:

- When to inspect versus plan.
- Why they must never reconstruct a planned request.
- How to interpret exit codes.
- How to request evidence selectively.
- How to handle policy denial.
- How to avoid placing secrets in arguments.

# 13. Architecture

## 13.1 Repository layout

```text
crates/
  kahea-core       domain types, handles, protocol envelopes, canonicalization
  kahea-ingest     OpenAPI, Arazzo, Postman, HAR, cURL, HTTP-file adapters
  kahea-plan       binding, provenance, risk, capabilities, policy, plan sealing
  kahea-exec       HTTP transport, auth, validation, runtime safety
  kahea-evidence   SQLite index, content-addressed blobs, redaction, retention
  kahea-mcp        thin MCP adapter over public library calls
  kahea             CLI binary and command routing
```

This is one product and one process, not seven services. Crate boundaries protect contracts and keep parser and transport dependencies out of the core.

## 13.2 Dependency direction

```text
kahea-core
   ▲      ▲
   │      │
 ingest  evidence
   ▲      ▲
   └─ plan ──▶ exec
          ▲      ▲
          └── mcp│
               kahea CLI
```

No parser type leaks into planning. No transport type leaks into observations. MCP imports the same public functions used by the CLI.

## 13.3 Configuration

Project configuration is explicit and versioned:

```toml
version = 1

[defaults]
source = "openapi.yaml"
server = "sandbox"
policy = ".kahea/policy.toml"

[servers.sandbox]
url = "https://sandbox.example.com"
classification = "non-production"

[servers.production]
url = "https://api.example.com"
classification = "production"

[auth.billing-sandbox]
type = "bearer"
token = "secret://billing/sandbox"
```

Configuration fingerprint participates in plan identity.

## 13.4 No daemon by default

CLI commands start, perform one bounded task, and exit. `mcp serve` is the only long-lived mode and runs locally over stdio by default.

## 13.5 Release security

- Reproducible release builds where practical.
- Signed release artifacts.
- SBOM generation.
- Dependency audit in CI.
- Minimal default feature set.
- No install-time scripts.

# 14. Security Model

## 14.1 Threat model

Kāhea assumes:

- API descriptions may be malicious or malformed.
- Agents may be prompt-injected by API content.
- Responses may contain hostile instructions.
- Redirects may attempt credential exfiltration.
- DNS can resolve to unsafe networks.
- Local project configuration may be untrusted.
- Secret providers may fail or return malformed data.
- A valid API operation may still be destructive.

## 14.2 Required protections

### SSRF and network boundaries

- Deny loopback, link-local, metadata-service, private, multicast, and reserved ranges by default.
- Resolve and validate every redirect target.
- Re-check resolved addresses at connection time.
- Restrict URL schemes.
- Disallow userinfo in URLs by default.
- Normalize internationalized hostnames before policy evaluation.

### Header and credential safety

- Reject CR/LF injection.
- Strip authorization on cross-origin redirect unless explicitly allowed.
- Redact configured sensitive headers and JSON paths.
- Never attach credentials to an unplanned origin.

### Body and resource safety

- Bound parser depth, document size, request size, response size, decompression ratio, and selector complexity.
- Stream large responses.
- Limit workflow steps and retries.
- Detect recursive references and cycles.

### Agent-content boundary

Remote response text is evidence, not instruction. The MCP adapter labels response bodies as untrusted data and returns handles by default rather than injecting large bodies directly into agent context.

## 14.3 Policy-denial experience

A denial returns the exact missing or conflicting grant:

```json
{
  "protocol": "kahea/k1",
  "kind": "denial",
  "plan": "plan:91ab7e0f",
  "reason": "production write requires explicit approval",
  "required": "approve:production-write",
  "policy": "policy:b81f…",
  "exit": 4
}
```

The agent can ask the human for the narrow grant rather than asking for generic permission.

# 15. Determinism and Reproducibility

## 15.1 Deterministic boundary

The following must be deterministic:

- Source fingerprints.
- Normalized graph.
- Operation handles.
- Input binding.
- Request body serialization.
- Planned URL and non-secret headers.
- Required grants.
- Risk classification under a fixed policy.
- Plan fingerprint.

The following are observations and may vary:

- DNS answers.
- TCP/TLS behavior.
- Remote timestamps and identifiers.
- Response content.
- Latency.
- Server-selected compression.
- Authentication token material.

## 15.2 Reproducibility statement

Every observation records:

- Plan fingerprint.
- Tool version.
- Configuration fingerprint.
- Policy fingerprint.
- Source fingerprints.
- Runtime platform summary.
- Resolved origin and protocol.
- Secret references used, without values.

A user can determine whether two invocations used the same intended request even when remote results differ.

# 16. Integration with `anomalyx`

Kāhea owns protocol correctness. `anomalyx` owns statistical and structural anomaly detection over observation corpora.

Kāhea emits one observation per invocation and supports NDJSON:

```bash
for i in $(seq 1 500); do
  kahea invoke plan:91ab7e0f --format ndjson
 done | anomalyx scan \
  --columns status,latency_ms,response_bytes,schema_error_count
```

Potential anomaly classes:

- Latency outliers.
- Response-size outliers.
- Status-code distribution shifts.
- Schema drift between environments.
- Error-rate regime changes.
- Multivariate changes across latency, size, and status.
- Suspicious request or callback cadence.

Kāhea must not reimplement `anomalyx` detectors. The composition is the product advantage.

# 17. Performance and Operational Requirements

These are release targets, not existing claims.

| Area | V1 target |
|---|---|
| Binary | Single stripped binary under 60 MB for default build |
| Cold start | `describe` and `schema` p95 under 50 ms on a modern developer laptop |
| OpenAPI inspect | 5 MB document p95 under 500 ms |
| Plan generation | p95 under 100 ms after source parse; under 600 ms cold |
| Runtime overhead | Under 10 ms excluding DNS, TLS, and remote network time |
| MCP idle memory | Under 50 MB |
| Inline output | Typical plan or observation under 8 KiB |
| Large response handling | Bounded memory with streaming to evidence store |
| Determinism | 100% byte-identical plans for identical test vectors |
| Cross-platform | Linux, macOS, and Windows release artifacts |

# 18. Quality and Test Strategy

## 18.1 Contract tests

- Golden JSON envelopes.
- Public JSON Schema validation.
- Exit-code tests.
- Backward-compatibility fixtures.
- Stable handle tests.

## 18.2 Property-based tests

- Canonicalization invariance.
- Order-independent source maps.
- URL encoding round trips.
- Input binding precedence.
- Secret nonappearance.
- Plan fingerprint stability.
- Selector bounds.

## 18.3 Mutation testing

`kahea-core` and `kahea-plan` must pass a zero-surviving-mutant gate for covered production code, with only individually documented equivalent mutants excluded.

## 18.4 Fuzzing

Fuzz targets:

- OpenAPI and JSON Reference parsing.
- YAML alias and depth limits.
- Postman collection import.
- HAR import.
- cURL tokenization.
- HTTP header construction.
- URL parsing and redirect policy.
- JSONPath and XPath selectors.

## 18.5 Adversarial security suite

- SSRF to metadata services.
- DNS rebinding.
- Cross-origin credential redirect.
- Header injection.
- Path traversal in file references.
- Decompression bombs.
- Recursive references.
- Oversized secret provider output.
- Prompt injection in API descriptions and response bodies.
- Unicode hostname confusion.

## 18.6 Deterministic integration server

The repository includes a Rust test server with seedable behavior for:

- Status and schema faults.
- Slow responses.
- Connection resets.
- Redirect chains.
- Malformed compression.
- Partial bodies.
- Retry and idempotency scenarios.

The core test suite does not depend on public internet services.

# 19. MVP Scope

## 19.1 Release 0: contract spine

Deliver:

- `kahea-core` public types.
- `kahea/k1` envelopes and schemas.
- Handles and canonical fingerprints.
- `describe`, `schema`, and basic `inspect`.
- OpenAPI 3.0–3.2 normalization.
- Golden and property tests.

Exit criterion: one OpenAPI operation can be normalized into a stable operation handle and schema.

## 19.2 Release 1: safe HTTP invocation

Deliver:

- `plan`, `invoke`, and `explain`.
- HTTP/1.1 and HTTP/2.
- API key, Basic, Bearer, and OAuth client credentials.
- Capability policy.
- Secret references.
- Response validation.
- Evidence store.
- Security test suite.

Exit criterion: an agent can safely complete a single-operation task end to end without constructing HTTP manually.

## 19.3 Release 2: import and agent integration

Deliver:

- Postman collection import.
- HAR, cURL, and `.http` import.
- MCP server.
- `SKILL.md`.
- Project configuration.
- Evidence bundle export.

Exit criterion: Claude Code can install Kāhea as a local MCP server, import common existing assets, and perform inspect-plan-invoke-explain.

## 19.4 Release 3: workflows and composition

Deliver:

- Arazzo 1.1 workflow execution for OpenAPI steps.
- Workflow observation tree.
- NDJSON mode.
- Environment comparison helpers.
- Documented `anomalyx` composition examples.

Exit criterion: a multi-step business outcome can be planned, policy-reviewed, executed, and explained without collection scripts.

# 20. V1 Acceptance Criteria

Kāhea v1 is complete only when all of the following are true:

1. **Discovery:** Given a supported OpenAPI document, `inspect` returns stable operation handles and compact summaries.
2. **No-network planning:** `plan` produces no DNS or network traffic.
3. **Exactness:** Identical inputs produce byte-identical plan bytes and fingerprints.
4. **Validation:** Unknown fields, missing required fields, and invalid body values fail before invocation.
5. **Provenance:** Every wire value can be traced to its source.
6. **Secret safety:** Secret material never appears in plan files, stdout, stderr, logs, or persisted evidence.
7. **Policy:** A write to a production-classified origin is denied without the exact required grant.
8. **Sealing:** Invocation rejects a plan whose canonical bytes no longer match its fingerprint.
9. **Execution:** A permitted plan sends the intended request and returns a typed observation.
10. **Contract checks:** Status, content type, and OpenAPI response schema can affect exit code 1.
11. **Evidence:** Large bodies and validation trees are returned as handles and can be selectively explained.
12. **Absence:** Unsupported Postman scripts are reported and block strict execution when material.
13. **MCP parity:** CLI and MCP produce semantically identical plan and observation envelopes.
14. **Security:** The adversarial suite demonstrates SSRF, redirect credential leakage, and header injection are denied by default.
15. **Cross-platform:** The same golden plans are generated on Linux, macOS, and Windows.
16. **Mutation gate:** Core and planning mutation tests have zero unexplained survivors.
17. **Documentation:** A new agent can use `describe`, schemas, and `SKILL.md` without reading implementation code.

# 21. Success Metrics

## 21.1 Product metrics

- **Agent task completion:** At least 90% of benchmark tasks completed without the agent constructing a raw HTTP request.
- **Plan correctness:** Zero benchmark cases where invoked bytes differ from approved planned bytes, excluding resolved secret material and protocol-generated transport details.
- **Reproducibility:** 100% stable plan fingerprints across supported operating systems for golden vectors.
- **Secret leakage:** Zero leaked secret values in automated adversarial tests.
- **Import transparency:** 100% of unsupported material behavior represented in `absent` diagnostics.
- **Context efficiency:** Median agent-visible output at least 80% smaller than returning full bodies and validation traces inline on the benchmark corpus.
- **Explainability:** At least 95% of failed benchmark invocations diagnosable using one observation plus no more than two `explain` calls.

## 21.2 Adoption signals

- Used directly from Claude Code, shell scripts, and CI without separate product configuration.
- Community examples add new APIs without custom Rust code.
- Users compose Kāhea with `anomalyx` rather than asking Kāhea to become a monitoring platform.
- Imported Postman assets are used as migration inputs, while new automation is stored as OpenAPI, Arazzo, explicit inputs, and policy.

# 22. Risks and Mitigations

| Risk | Impact | Mitigation |
|---|---|---|
| Name collision | `KAHEA` is used by a Hawaiʻi nonprofit and `Kahea.ai` by a telecom/AI company | Treat **Kāhea** as the final product/codename while requiring formal trademark and commercial-name clearance before monetized launch; use the full descriptor **Kāhea — The Agentic Invocation Kernel** |
| Cultural misuse | Hawaiian language becomes superficial branding | Preserve correct diacritics and pronunciation, keep the analogy narrow, seek fluent/cultural review, avoid sacred imagery or invented etymology |
| Spec ambiguity | OpenAPI documents can be incomplete or contradictory | Fail closed, expose ambiguity, require explicit server/content-type/example selection |
| Authentication sprawl | Vendor-specific auth can dominate scope | Ship a small common set and use explicit external credential helpers; add adapters only from real demand |
| Postman script incompatibility | Existing collections rely on arbitrary JavaScript | Statically translate a narrow safe subset, report all other behavior as absent, never embed Node in v1 |
| Protocol sprawl | GraphQL, gRPC, WebSocket, AsyncAPI, SOAP, and MCP create a platform | Establish adapter interfaces now; prove HTTP first; add protocols only behind the same plan/observation contract |
| False determinism | Users may assume remote responses are reproducible | Document and encode the planning/observation boundary; never fingerprint volatile response fields as planned truth |
| Agent overreach | A model may repeatedly seek broad grants | Return narrow required grants, maintain user policy ceilings, and require explicit production/destructive approval |
| Sensitive evidence | Response bodies may contain secrets or regulated data | Redaction, retention policy, encryption at rest, selective handles, explicit export controls |
| CLI growth | Feature pressure recreates a large workspace product | Protect the six-verb contract and compose specialized tools rather than absorbing them |

# 23. Future Direction

The following are eligible only after v1 acceptance criteria are met:

- GraphQL schema and operation support.
- gRPC protobuf and reflection support.
- HTTP/3.
- SSE and WebSocket sessions.
- AsyncAPI operations and Arazzo asynchronous steps.
- SOAP/WSDL adapter where commercially justified.
- Replay and differential environment comparison.
- Declarative boundary-case generation.
- WASM assertion modules with explicit capability isolation.
- Remote execution workers using signed plans.
- Organization policy bundles and attestations.
- IDE adapters that call the CLI rather than recreate its logic.

# 24. Launch Positioning

## 24.1 Primary description

> **Kāhea is the deterministic API invocation kernel for coding agents. It turns OpenAPI, Postman, HAR, cURL, and Arazzo into sealed, policy-scoped calls with typed observations and addressable evidence.**

## 24.2 Short description

> **The agent chooses the intent. Kāhea proves the call.**

## 24.3 README opening

```text
Kāhea gives coding agents an API call they do not have to invent.

Inspect the contract. Seal the plan. Grant the minimum authority.
Invoke the exact call. Explain any byte of evidence.
```

## 24.4 Example agent workflow

```bash
# Discover the capability
kahea inspect openapi.yaml --match "create invoice"

# Produce a no-network, sealed plan
kahea plan openapi.yaml op:9e4c2f7d6d8a \
  --server sandbox \
  --input @invoice.json \
  --auth billing/sandbox

# Invoke exactly what was planned
kahea invoke plan:91ab7e0f \
  --grant net:sandbox.example.com:443 \
  --grant http:POST \
  --grant secret:billing/sandbox

# Retrieve only the value needed next
kahea explain body:329cc8d1 --select /invoice/id
```

# 25. Decision Log

| Topic | Decision |
|---|---|
| Root primitive | Invocation of a named, addressable capability |
| Name | Kāhea |
| Mantra | Intent may be probabilistic. The call must be exact. |
| Core boundary | Plan is deterministic; observation records nondeterministic reality |
| Agent role | Select intent and operation; never own wire construction or safety policy |
| Execution approval | Binds to sealed plan fingerprint |
| Secrets | References in plans; values resolved only at invocation |
| Output | Compact versioned JSON with handles |
| Workflow standard | Arazzo 1.1 |
| Embedded AI | None in canonical binary |
| Embedded scripting | None in v1 beyond declarative checks |
| Cloud requirement | None |
| UI | None in v1 |
| Integration | CLI first, MCP thin adapter |
| Statistical analysis | Compose with anomalyx; do not absorb it |

# 26. Final Product Definition

**Kāhea is a single Rust executable that translates probabilistic agent intent into a deterministic, policy-scoped API invocation. It ingests existing API artifacts, normalizes them into a typed graph, seals exact request plans, resolves authority only at execution, validates the result, and preserves addressable evidence.**

Its enduring contract is:

```text
inspect → plan → invoke → explain
```

Its enduring boundary is:

```text
The agent may decide.
The plan must prove.
The policy must permit.
The invocation must match.
The evidence must remain.
```

And its mantra is:

> **Intent may be probabilistic. The call must be exact.**

[^name-meaning]: [Hawaiʻi Public Radio, “Kāhea,” Hawaiian Word of the Day, April 28, 2026](https://www.hawaiipublicradio.org/hawaiian-word-of-the-day-april-28th), and [Hawaiʻi State Public Library System, “Hawaiian words”](https://www.librarieshawaii.org/learn/brain-games/hawaiian-words/). Both define *kāhea* as calling or crying out; HPR also lists invoke, greet, and name.

[^mele-kahea]: [Kamehameha Schools](https://www.ksbe.edu/article/kamehameha-schools-students-steward-hokulea-ceremonies-at-sacred-sites) describes a *mele kāhea* used to seek permission to enter a new space.

[^postman-cli]: [Postman documentation, “Run a collection with the Postman CLI”](https://learning.postman.com/docs/postman-cli/postman-cli-run-collection), describes the CLI primarily through collection execution and notes current protocol and authentication constraints.

[^postman-agent]: [Postman documentation, “Agent Mode overview”](https://learning.postman.com/docs/use/agent-mode/overview), describes Agent Mode as operating across collections, tests, workspaces, environments, monitors, Spec Hub, flows, and related Postman resources.

[^claude-mcp]: [Anthropic documentation, “Connect Claude Code to tools via MCP”](https://docs.anthropic.com/en/docs/claude-code/mcp), describes local stdio MCP servers and the `claude mcp add` workflow.

[^openapi]: [OpenAPI Initiative, OpenAPI Specification v3.2.0](https://spec.openapis.org/oas/v3.2.0.html), published September 19, 2025.

[^arazzo]: [OpenAPI Initiative, Arazzo Specification v1.1.0](https://spec.openapis.org/arazzo/latest.html), published May 17, 2026; defines sequences of API calls and dependencies.
