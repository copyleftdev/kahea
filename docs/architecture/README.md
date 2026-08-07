# Architecture decisions

Kāhea records decisions that change its deterministic planning, execution, or evidence contract in
this directory. The product requirements document remains the product baseline; these records make
post-v1 extensions reviewable without rewriting that historical document.

| Decision | Status | Tracking issue |
|---|---|---|
| [ADR-0001: Deterministic finite WebSocket sessions](0001-websocket-sessions.md) | Accepted | [#7](https://github.com/copyleftdev/kahea/issues/7) |

An accepted decision fixes user-visible semantics. Implementation issues may choose internal types
and dependencies only within those boundaries. If implementation reveals that a boundary is not
workable, amend or supersede the decision before shipping a different public contract.
