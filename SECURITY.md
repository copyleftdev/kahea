# Security

## Supported versions

| Version | Supported |
|---|---|
| Latest GitHub release | Yes |
| Older releases and unreleased commits | Best effort |

Report suspected vulnerabilities through
[GitHub private vulnerability reporting](https://github.com/copyleftdev/kahea/security/advisories/new).
Do not open a public issue for a suspected vulnerability. Do not include live credentials, customer
response bodies, or exploit traffic against systems you do not own.

Maintainers will acknowledge a report within five business days, keep the reporter informed while
validating it, and coordinate disclosure after a fix is available. No bounty is currently offered.

Kāhea treats API descriptions, configuration, DNS, redirects, remote responses, and inbound
WebSocket frames as untrusted. Planning is no-network; invocation requires sealed plans and exact
grants. Redirects and ambient proxies are disabled, resolved addresses are pinned after policy
evaluation, and secret material is resolved only at invocation. See the
[finite WebSocket security model](docs/websockets.md#security-model) and limitations before
deploying Kāhea with sensitive APIs.

Conformance campaigns can multiply writes and intentionally send schema-invalid requests. Every campaign seals its maximum request count and requires an exact `conformance:execute:N` grant; campaigns containing negative cases additionally require `conformance:negative`. Existing network, method, production-write, destructive, secret, timeout, response-size, and evidence-redaction controls continue to apply to every case.

The dynamic conformance server is test infrastructure, not a production service. It binds only to IPv4 loopback, limits requests to 1 MiB, uses a fresh seeded shutdown token, and receives generated data only. Its manifest contains the control token and must be treated as a local ephemeral artifact. Fault-injection modes intentionally violate the advertised contract and should only be used by the lifecycle harness on an isolated development or CI host.

When reporting an issue, include the Kāhea version, operating system, the smallest redacted source/plan that reproduces it, the observed envelope, and whether any network connection occurred before denial.
