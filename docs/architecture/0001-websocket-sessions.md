# ADR-0001: Deterministic finite WebSocket sessions

- Status: Accepted
- Date: 2026-08-07
- Tracking: [#6](https://github.com/copyleftdev/kahea/issues/6), [#7](https://github.com/copyleftdev/kahea/issues/7)

## Context

Kāhea currently seals and invokes finite HTTP requests. A WebSocket begins with an HTTP/1.1
upgrade, then becomes a bidirectional stream whose message ordering, control frames, close behavior,
and resource use affect the result. Treating that stream as an HTTP method would leave important
behavior outside the plan. Treating it as an indefinite client would violate Kāhea's one-shot,
bounded execution model.

The WebSocket contract must preserve the existing boundary:

```text
inspect -> plan -> review exact grants -> invoke the sealed plan -> explain bounded evidence
```

It must also preserve byte compatibility for existing `kahea/k1` HTTP plans and observations.

## Decision

Kāhea will execute **finite, strictly ordered WebSocket sessions**. Every application-level send,
expectation, close condition, and resource limit is present in a sealed plan. The executor performs
one session and exits. It will not provide an interactive client, subscription daemon, reconnect
loop, or unbounded stream.

The MVP uses RFC 6455 over HTTP/1.1 for `ws` and `wss`. RFC 8441 extended CONNECT, HTTP/3,
redirects, proxies, negotiated extensions, and automatic reconnects are outside the MVP.

### Separate public envelopes preserve `kahea/k1`

The current flat `RequestPlan` remains the public `kind: "plan"` envelope and keeps its serialized
field layout. WebSockets add sibling public envelopes:

- `kind: "websocket-plan"`
- `kind: "websocket-observation"`

Both retain `protocol: "kahea/k1"`. They use the existing `plan:` handle domain because the kind
and fingerprint material separate their identities. Public schema names are `websocket-plan` and
`websocket-observation`.

Stored-plan loading dispatches on `kind`. CLI and MCP routing may use an internal enum, but no enum
tag is inserted into existing HTTP JSON. Existing `plan` and `observation` schemas, golden bytes,
handles, and resource URIs remain unchanged. A future incompatible change to an existing public
schema requires a protocol version change; adding these new kinds is an additive `kahea/k1`
extension.

### Direct session source

The first implementation accepts a local JSON or YAML `websocket-session` source. AsyncAPI will be
a later ingestion adapter into the same plan type, not another executor. Planning never performs
DNS, TLS, authentication, or network access.

The equivalent contract fixtures at
[`fixtures/websocket/session.json`](../../fixtures/websocket/session.json) and
[`fixtures/websocket/session.yaml`](../../fixtures/websocket/session.yaml) show the accepted source
spellings. Their relevant fields are:

- `operationId`: the addressable operation name used by inspect and plan.
- `url`: a `ws` or `wss` target without userinfo or fragment.
- `risk`: optional declared risk. A data-send action raises an absent, `unknown`, or `read` source
  declaration to `write`; a configuration risk override is authoritative. A receive-only session
  with no declaration remains `unknown` rather than being inferred as `read`.
- `headers`: non-secret handshake headers. Protocol-owned headers cannot be supplied here.
- `auth`: an auth-profile reference, never secret material.
- `origin` and `subprotocols`: ordered handshake intent.
- `limits`: requested bounds that policy may only tighten.
- `actions`: the ordered finite session.

### Workflow projection

Arazzo workflows may reference a local direct session through the source-description extension
`x-kahea-source-kind: websocket-session`. It omits the fixed `type` field rather than mislabeling a
direct session as OpenAPI, AsyncAPI, or Arazzo. The workflow plan embeds the canonical sealed WebSocket child plan,
adds its risk and exact grants to the workflow aggregates, and separately seals the WebSocket
policy fingerprint. HTTP-only workflow serialization remains unchanged.

Prior-step values may bind only through explicit `x-kahea-websocket-bindings` that select an
existing bounded action field. A binding cannot change the target, auth reference, limits, action
order, schema, or operation identity. Invocation materializes those declared values, calls the
canonical WebSocket planner and executor, and records the resulting child-plan handle. Outputs can
select handshake or close metadata, one matched action payload, an encoded binary value, or an
evidence handle. A whole transcript is never an implicit workflow value. The invocation timeout is
an outer deadline across all steps and retries; each step's own timeout can only tighten it.

A session has exactly one terminal `close` or `expect-close` action, and it is last. The MVP action
vocabulary is:

| Action | Meaning |
|---|---|
| `send-text` | Flush one exact UTF-8 text message. |
| `send-binary` | Decode canonical padded base64 and flush those exact bytes. |
| `expect-text` | Require the next complete data message to be text and exactly equal. |
| `expect-binary` | Require the next complete data message to be binary and byte-equal. |
| `expect-json` | Require text JSON, optionally select by JSON Pointer, then check equality and/or a sealed local schema. |
| `ping` | Send one ping with a base64 payload of at most 125 bytes. |
| `expect-pong` | Require a pong with the exact sealed payload. |
| `close` | Send the sealed close code/reason and require the peer close handshake. |
| `expect-close` | Require peer close with an allowed code and optional exact reason. |

Action names and field names use kebab-case in JSON. #8 may choose Rust type names freely as long
as their serialized representation follows this contract.

### Planned shape

The planner normalizes the source into this conceptual envelope. Fingerprints and handles below are
symbolic because #8 will make the byte-exact golden after the public Rust types exist.

```json
{
  "protocol": "kahea/k1",
  "kind": "websocket-plan",
  "version": "0.2.0",
  "config_fingerprint": "b3:<config>",
  "policy_fingerprint": "b3:<policy>",
  "source_fingerprints": ["b3:<source>"],
  "id": "plan:<seal>",
  "operation": "op:<operation>",
  "target": "wss://socket.example.test/v1/events",
  "risk": "write",
  "required_grants": [
    "net:socket.example.test:443",
    "secret:chat-sandbox",
    "websocket:connect"
  ],
  "secret_refs": ["chat-sandbox"],
  "headers": [{"name": "X-Client", "value": "kahea-contract"}],
  "auth": {"scheme": "bearer", "profile": "chat-sandbox", "placement": "header"},
  "origin": "https://client.example.test",
  "subprotocols": ["kahea.events.v1"],
  "handshake_checks": [
    "status:101",
    "subprotocol:kahea.events.v1",
    "extensions:none"
  ],
  "limits": {
    "connect_timeout_ms": 5000,
    "action_timeout_ms": 2000,
    "idle_timeout_ms": 5000,
    "close_timeout_ms": 2000,
    "total_timeout_ms": 15000,
    "max_frame_bytes": 1048576,
    "max_message_bytes": 4194304,
    "max_inbound_frames": 64,
    "max_outbound_frames": 64,
    "max_inbound_messages": 32,
    "max_outbound_messages": 32,
    "max_inbound_bytes": 16777216,
    "max_outbound_bytes": 16777216
  },
  "actions": [
    {
      "type": "send-text",
      "text": "{\"type\":\"subscribe\",\"topic\":\"builds\"}"
    },
    {
      "type": "expect-json",
      "pointer": "/type",
      "equals": "subscribed",
      "timeout_ms": 2000
    },
    {"type": "ping", "payload_base64": "a2FoZWE="},
    {
      "type": "expect-pong",
      "payload_base64": "a2FoZWE=",
      "timeout_ms": 2000
    },
    {"type": "close", "code": 1000, "reason": "complete"}
  ],
  "sensitive_headers": ["authorization", "cookie", "set-cookie"],
  "redact_response_json_pointers": ["/token"],
  "valid": true,
  "fingerprint": "b3:<seal>",
  "exit": 0
}
```

The exact required capabilities are:

- `net:{normalized-host}:{effective-port}`
- `websocket:connect`
- `net-insecure-websocket` for `ws`
- existing `net-cidr:*` grants for otherwise denied literal or resolved networks
- existing `secret:*`, `tls-client-cert:*`, and approval grants when applicable

Protocol data sends do not create an override grant: their side-effect boundary is expressed by the
sealed actions and plan risk. A receive-only session with absent risk is `unknown`; data sends
default to at least `write`, and `destructive` is only explicit or policy-configured.

### Policy configuration

WebSocket planning reuses the existing host, sensitive-header, redaction, production-write, auth,
and risk policy. The optional WebSocket-specific policy is nested under `websocket` in a standalone
policy TOML file:

```toml
[websocket]
allowed_origins = ["https://client.example.test"]
allowed_subprotocols = ["kahea.events.v1"]

[websocket.max_limits]
connect_timeout_ms = 30000
action_timeout_ms = 30000
idle_timeout_ms = 30000
close_timeout_ms = 10000
total_timeout_ms = 120000
max_frame_bytes = 4194304
max_message_bytes = 16777216
max_inbound_frames = 4096
max_outbound_frames = 4096
max_inbound_messages = 2048
max_outbound_messages = 2048
max_inbound_bytes = 67108864
max_outbound_bytes = 67108864
```

Empty origin or subprotocol lists allow any otherwise valid value. Every maximum is finite and
positive; requested limits are materialized after being tightened to these maxima. Contradictory
timeout or frame/message maxima fail closed. The WebSocket policy has a separate fingerprint so
its settings affect WebSocket seals without changing existing HTTP plan bytes.

### Canonicalization and sealing

The WebSocket plan follows the existing sealing process: clear `id` and `fingerprint`, serialize the
normalized struct as compact UTF-8 JSON, BLAKE3-hash those bytes, then derive the `plan:` handle from
the fingerprint.

Normalization rules are part of the contract:

- Struct field order is fixed by the public type and covered by byte-exact golden tests.
- Header names are validated, sorted case-insensitively, and duplicates that change semantics are
  rejected. Header values containing CR or LF are rejected.
- The executor owns `Host`, `Upgrade`, `Connection`, `Sec-WebSocket-Key`,
  `Sec-WebSocket-Version`, `Sec-WebSocket-Protocol`, `Sec-WebSocket-Extensions`,
  `Content-Length`, and `Transfer-Encoding`; a source cannot override them.
- Subprotocol order is preserved because it expresses preference. Empty or duplicate tokens are
  rejected.
- Action order is preserved and participates in the seal.
- Binary and control payloads use RFC 4648 standard base64 with padding. Non-canonical encodings are
  rejected rather than normalized silently.
- Object-valued JSON equality inputs and schemas are recursively key-sorted before sealing. Array
  order and JSON number spelling remain significant; `1` and `1.0` are not equal.
- Text comparison is exact after RFC 6455 UTF-8 validation. No Unicode normalization, trimming, or
  case folding occurs.
- All effective limits are materialized in the plan; runtime defaults do not exist outside it.

RFC-mandated entropy is an observed transport detail, not unsealed intent. The executor generates a
fresh `Sec-WebSocket-Key` and fresh client masking keys at invocation. Those values do not affect
logical messages, checks, grants, or plan identity, and are not persisted. This is the same side of
the deterministic boundary as TCP sequence numbers and TLS nonces.

### Strict execution state machine

The public API and the MVP executor remain synchronous. `kahea-exec` may add private transport
traits, but it will not expose async runtime types or spawn a background session. The MVP uses
bounded socket reads/writes and processes at most one plan in the calling thread. A future internal
async implementation must preserve the same state machine and synchronous library contract.

After a successful upgrade, actions run in order:

1. A send action writes and flushes one complete logical message, then advances without an
   opportunistic read. Bytes already waiting in the socket are therefore evaluated by the next
   action, not by a scheduler-dependent race between send and receive.
2. An expectation reads and consumes the next relevant protocol event. Data expectations never scan
   ahead or skip a mismatching data message.
3. When a read is required for a control or close action, a data message is an immediate failed
   expectation. It is not queued for a later action.
4. Fragmented data frames are reassembled into one message within both frame and message limits.
5. Ping is accepted at any point, recorded, and answered with an identical pong. The automatic pong
   counts against outbound frame and byte budgets.
6. A pong satisfies only the current `expect-pong` when its payload matches. Other pongs are
   recorded and ignored within the control-frame budgets.
7. A peer close satisfies only the current terminal `expect-close`, or the peer response to `close`.
   Any earlier close is a failed expectation. TCP EOF without a valid close frame is a transport
   error.
8. Every success, failure, denial, timeout, cancellation, or protocol error closes the socket and
   returns exactly one observation or denial.

`expect-json` accepts only a text message containing valid JSON. JSON Pointer selection uses the
existing bounded selector rules. Equality is structural after the canonicalization above. A schema
check uses a schema sealed into the plan, resolves no remote references, and is subject to existing
depth and error-count bounds.

### Resource limits

Every plan contains finite positive limits for connection, each expectation, idle time, close time,
and total session duration. It also contains maximum frame bytes, message bytes, inbound/outbound
frames, inbound/outbound messages, and aggregate inbound/outbound bytes.

The total deadline includes DNS, TCP, TLS, upgrade, actions, and close. The idle deadline resets only
when bytes are successfully read or written; a partial frame cannot keep a session alive forever.
The earliest applicable deadline wins. Counts include control frames and automatically generated
pongs. Payload bytes are counted after frame decoding but before redaction; wire overhead is bounded
indirectly by frame-count limits.

Planning rejects a session whose sealed outbound actions already exceed any policy-tightened limit.
Invocation stops reading before allocating beyond a limit. No receive or send queue is unbounded.

### Outcomes and exit codes

Existing exit-code meanings remain unchanged:

| Condition | Outcome | Exit | Terminal cause |
|---|---|---:|---|
| All actions and the terminal close complete | `passed` | 0 | `completed` |
| Handshake status/header/subprotocol check fails | `failed` | 1 | `handshake-check-failed` |
| Data/control/close expectation mismatches | `failed` | 1 | `expectation-failed` |
| Peer exceeds a sealed frame/message/byte count | `failed` | 1 | `budget-exhausted` |
| Invalid source, impossible limits, bad seal, or incompatible kind | error envelope | 2 | not applicable |
| DNS, TCP, TLS, I/O, protocol violation, EOF without close, or timeout | `error` | 3 | a transport cause |
| Missing grant or runtime policy denial | denial envelope | 4 | not applicable |

An unexpected valid close frame is a remote result and therefore a failed expectation. An invalid
or missing close frame is a protocol/transport error. Local cancellation, if exposed by a future
library API, maps to exit 3 and still emits a bounded observation.

### Observation and evidence

A successful or attempted network session returns a compact `websocket-observation`. It includes
the plan handle, outcome, handshake status, negotiated subprotocol, handshake and total duration,
resolved origin, HTTP version, message/frame/byte counters, redacted close data, terminal cause,
secret references used, runtime summary, and evidence handles.

```json
{
  "protocol": "kahea/k1",
  "kind": "websocket-observation",
  "version": "0.2.0",
  "config_fingerprint": "b3:<config>",
  "policy_fingerprint": "b3:<policy>",
  "source_fingerprints": ["b3:<source>"],
  "tool_version": "0.2.0",
  "plan": "plan:<seal>",
  "outcome": "passed",
  "handshake_status": 101,
  "negotiated_subprotocol": "kahea.events.v1",
  "handshake_latency_ms": 8.4,
  "session_duration_ms": 31.7,
  "transcript": "transcript:<handle>",
  "handshake": "handshake:<handle>",
  "trace": "trace:<handle>",
  "close": {"initiator": "client", "code": 1000, "reason": "complete"},
  "terminal_cause": "completed",
  "counters": {
    "inbound_frames": 4,
    "outbound_frames": 4,
    "inbound_messages": 1,
    "outbound_messages": 1,
    "inbound_bytes": 29,
    "outbound_bytes": 52
  },
  "resolved_origin": "203.0.113.10:443",
  "http_version": "1.1",
  "secret_refs": ["chat-sandbox"],
  "runtime": "<bounded platform summary>",
  "exit": 0
}
```

The transcript is content-addressed evidence with monotonic sequence numbers, direction, logical
message/control kind, byte count, digest or payload handle, associated action index, and check
result. Large text and all binary payloads remain outside the observation. `explain` retrieves only
selected, bounded values. Handshake evidence never stores protocol entropy or unredacted sensitive
headers.

Secret values are resolved only after seal and grant verification. Redaction occurs before any
trace, observation, transcript, error, or evidence write. Received text is untrusted evidence, never
agent instruction.

### Handshake and network security

Runtime target evaluation reuses the HTTP executor's host policy, unsafe-address denial, DNS
resolution, address pinning, original hostname for Host and TLS SNI, userinfo rejection, and secret
redaction. `wss` is the safe default. `ws` requires `net-insecure-websocket`.

Redirects are never followed. The executor validates status 101 and the required Upgrade,
Connection, and Sec-WebSocket-Accept semantics. A selected subprotocol must have been offered and
must satisfy the sealed check. The MVP does not offer extensions; any selected extension fails
closed. Authentication is attached only to the sealed origin after its secret and network grants
pass.

### Dependency selection gate

Issue `#9` may select a WebSocket dependency only after a small proof against `#16` demonstrates:

- correct RFC 6455 masking, fragmentation, control-frame, UTF-8, and close validation;
- caller-supplied TCP streams or equivalent address pinning so the library cannot re-resolve DNS;
- Rustls compatibility with the workspace's current TLS trust behavior;
- blocking operation with enforceable read/write deadlines and no hidden reconnects;
- no proxy or redirect behavior enabled implicitly;
- maximum message/frame configuration before allocation;
- clean cancellation/drop behavior and no background threads after return;
- maintained Rust 1.95 support, acceptable advisory history, license compatibility, and a bounded
  dependency tree.

If no blocking dependency passes those gates, the executor may use a private async implementation,
but the ADR must be amended before adding an async runtime boundary.

#### Selection record for #9

The transport uses `tungstenite` 0.30 for the RFC 6455 frame codec and protocol state, with its
redirecting/DNS convenience client disabled. Kāhea supplies a single already-resolved and
policy-checked `TcpStream`, owns the HTTP/1.1 upgrade validation, and constructs Rustls 0.23 over
that same stream for `wss`. This keeps DNS pinning, Host/SNI, deadlines, trust roots, mutual TLS,
redirect denial, and evidence redaction inside the executor boundary.

The workspace enables tungstenite's public `rustls-tls-native-roots` feature only to expose its
Rustls stream adapter; Kāhea still builds and supplies the TLS configuration itself. The private
`__rustls-tls` feature is deliberately avoided. The exact tungstenite release is lockfile-pinned,
compiled on every supported CI platform, and included in the advisory and dependency-policy gates;
upgrades must rerun those gates.

The dependency proof is executable in `kahea-exec` tests. It covers loopback IPv4 and IPv6,
single-resolution address pinning with the original hostname preserved, RFC token handling,
subprotocol selection, extension rejection, bad accept keys, redirects, silent-peer deadlines,
controlled TLS roots, hostname validation, and secret/entropy-free evidence. Frame fragmentation,
control-frame, UTF-8, close, and aggregate session-budget cases remain owned by #12 and the
controlled oracle in #16. `tungstenite` is blocking, accepts caller-owned streams, configures frame
and message limits before reads, creates no runtime or background thread, supports Rust versions
older than the workspace's Rust 1.95 floor, and is MIT/Apache-2.0 licensed.

### Controlled conformance oracle

`kahea-test-server --protocol websocket` binds IPv4 loopback by default and accepts an explicit
IPv4 or IPv6 loopback through `--websocket-interface` before it publishes its readiness manifest.
The programmatic `start_websocket_oracle_on(interface, ...)` API enforces the same loopback-only
boundary. A seed determines the path, Origin, subprotocol, ordered
text/binary/control/fragment/close script, and stable case identity. Plaintext and generated,
explicitly trusted TLS endpoints use the same script. The terminal oracle observation records the
seed, case ID, connection count, handshake state, completed step count, selected fault, and outcome.

The fault surface is explicit and replayable: bad accept key/status/upgrade headers, redirects,
extension negotiation, invalid UTF-8, masked server frames, reserved opcode/RSV bits, fragmented
control frames, invalid close payload/code, truncated and oversized frames, unexpected messages,
abrupt close, and silence during handshake/frame/close phases. The executor test matrix asserts the
stable failure class for every fault. `scripts/websocket-oracle-smoke.sh` proves the public CLI path
against seed `42`; `scripts/gates.sh` runs it alongside the existing HTTP dynamic conformance gate.
No oracle mode binds a non-loopback interface or requires public network access.

## Alternatives considered

### Add optional WebSocket fields to `RequestPlan`

Rejected. Optional HTTP and WebSocket fields create invalid combinations, make schema consumers
reason about hidden modes, and risk changing byte-stable HTTP plans.

### Replace `RequestPlan` with a tagged transport enum

Rejected for `kahea/k1`. It is structurally clean in Rust but inserts a new tag or nesting layer
into every existing plan and breaks stored plans, golden bytes, schemas, MCP clients, and resource
readers. An internal enum may still dispatch sibling public types.

### Model WebSockets as HTTP GET plus post-upgrade options

Rejected. The messages and terminal condition, not the GET, are the invocation. Keeping them outside
the plan would let execution diverge from approval.

### Provide an interactive or streaming client

Rejected. It cannot be fully sealed, bounded, replay-audited, or returned as one compact observation.
Long-lived event processing belongs in a separate product surface if it is ever introduced.

### Ingest AsyncAPI first

Rejected. AsyncAPI can describe many protocols and often does not define one finite conversation.
The direct session contract must stabilize before an adapter maps a supported WebSocket subset into
it.

## Consequences

- HTTP `kahea/k1` compatibility is preserved at the cost of two additional public schemas and
  dispatch paths.
- A finite strict script is less flexible than a general client, but its behavior and authority are
  reviewable before network access.
- Mandatory limits and strict FIFO matching intentionally reject some noisy real-world servers.
  Later matching policies must be new sealed semantics, never executor heuristics.
- Runtime entropy prevents byte-identical WebSocket wire captures, but logical plan bytes, actions,
  grants, checks, and evidence structure remain deterministic.
- #8 owns byte-exact public types and goldens; #10 owns binding, policy, and defaults; #9 and #12 own
  transport and state-machine implementation; #13 owns durable transcript details.
