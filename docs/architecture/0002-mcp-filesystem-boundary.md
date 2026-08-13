# ADR-0002: The MCP surface does not accept filesystem paths

- Status: Accepted
- Date: 2026-08-12
- Tracking: [#32](https://github.com/copyleftdev/kahea/issues/32)

## Context

The MCP adapter was written as a thin projection of the CLI, and it inherited the CLI's argument
shape along with its library calls. Three CLI affordances became tool arguments:

- `store`, the root every call reads and writes.
- `config`, the configuration whose policy fingerprint a plan is measured against.
- `plan`, documented as "sealed plan handle or local sealed plan file path".

On a terminal those are operator affordances: a person types the path they meant. On the MCP
surface the same strings are written by a model, and a projection of the CLI is not automatically a
projection of the CLI's trust assumptions.

Public scanning flagged the narrowest edge of this: `kahea_invoke.plan` reaching `fs::read` in
`stored_plan_kind`. Read alone, that is a low-severity path oracle — the read file yields only its
`kind` field, failures are swallowed, and `verify_seal` still stands between a file and execution.

The composition is what matters. `RequestPlan::seal` is a keyless BLAKE3 digest over the plan, so it
certifies integrity, not authenticity: any file a caller can write is a validly sealed plan. Grants
arrive as call arguments. The configuration that supplies `policy.allowed_hosts` and the fingerprint
the plan is checked against arrives as a call argument too, and both plan and invoke can name the
same one, so the fingerprints agree. The runtime boundary in `evaluate_runtime_target` is sound and
still evaluates grants against a policy the caller selected.

Kāhea has no write primitive of its own, so none of this is reachable through Kāhea alone. It is
reachable for an agent holding any other filesystem-write tool in the same session, which is the
normal MCP host configuration.

## Decision

The MCP surface treats the filesystem as server configuration, not as call data.

### The store root and the configuration path are process arguments

`kahea mcp serve` accepts `--store` and `--config`. They default to `.kahea` and, when it exists,
`.kahea/config.toml`, so existing launch manifests are unaffected. Both are removed from every tool
input schema. One server process has one store and one policy for its lifetime.

The configuration is read once, at startup, and held. Reading it per call would leave the trust
anchor mutable for the lifetime of the process: anything able to write inside the store could widen
`allowed_hosts` between a plan and its invocation, and both fingerprints would still agree because
both were derived from the widened file. Reading once also reports a bad `--config` to the operator
who set it, instead of once per tool call to an agent that cannot fix it. The cost is that changing
policy requires a restart.

### Plan references are handles

`kahea_invoke` and the `kahea://plan/{handle}` resource accept `plan:`, `workflow-plan:`, and
`conformance-plan:` handles with the existing twelve-hex-digit suffix grammar. A filesystem path is
rejected before anything is read. The CLI continues to accept a path, because an operator typed it.

### A validated handle is still confined

A handle resolves to `{store}/store/plans/{handle}.json`, and both the store root and the resolved
file are canonicalized and compared before use. The handle grammar already forbids separators, so
this catches the case the grammar cannot: a symlink planted inside the store.

### Undeclared arguments are rejected

Tool schemas already declare `additionalProperties: false`, but a schema is advisory to a client.
The server now enforces it. A call written against the old schema, carrying `store` or `config`,
fails with a message naming the argument instead of silently executing against the pinned store —
the failure mode where a caller believes it wrote to one place and the server used another.

### Failure to resolve a plan is one message

Absence, unreadability, malformed JSON, and a broken seal all return
`plan handle does not resolve to a sealed plan in this store`. Distinguishing them answers questions
about the filesystem that a caller should not be able to ask. The CLI keeps full diagnostics, since
its errors go to the operator who owns the store.

## Consequences

Breaking, on the MCP surface only:

- A tool call passing `store` or `config` now fails. Move the value to `kahea mcp serve --store` or
  `--config`.
- A tool call passing a plan file path now fails. Pass the handle returned by `kahea_plan`.
- One server process can no longer address multiple stores. Run one process per store.

Unchanged: every `kahea/k1` envelope, every handle, every schema name, the CLI, and the packaged
launch manifests, which use the defaults.

## Residual risk

The plan seal remains a keyless digest, so it certifies integrity and not origin. Confinement narrows
the reachable set to files inside the pinned store; it does not authenticate them. Anything able to
write inside that store — the same other-tool assumption that motivates this decision — can mint a
plan whose seal verifies. **The store is trusted.** An operator who points `--store` at a directory
other software can write to gets no protection from this change.

What confinement does buy is that the trusted set is now a directory an operator chose, rather than
every path the process can read, and that the set is the same at check time and at load time.

Replacing the digest with a MAC under a store-local key — so `verify_seal` means "this store minted
it" — is the decision that would close the remaining gap. It is separate: it carries its own
compatibility cost, and existing plans do not carry the new material.
