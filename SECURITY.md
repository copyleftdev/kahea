# Security

Please report suspected vulnerabilities privately to the repository maintainers. Do not include live credentials, customer response bodies, or exploit traffic against systems you do not own.

Kāhea treats API descriptions, configuration, DNS, redirects, and remote responses as untrusted. Planning is no-network; invocation requires sealed plans and exact grants. Redirects and ambient proxies are disabled, resolved addresses are pinned after policy evaluation, and secret material is resolved only at invocation. See the security model and limitations in the README before deploying Kāhea with sensitive APIs.

Conformance campaigns can multiply writes and intentionally send schema-invalid requests. Every campaign seals its maximum request count and requires an exact `conformance:execute:N` grant; campaigns containing negative cases additionally require `conformance:negative`. Existing network, method, production-write, destructive, secret, timeout, response-size, and evidence-redaction controls continue to apply to every case.

The dynamic conformance server is test infrastructure, not a production service. It binds only to IPv4 loopback, limits requests to 1 MiB, uses a fresh seeded shutdown token, and receives generated data only. Its manifest contains the control token and must be treated as a local ephemeral artifact. Fault-injection modes intentionally violate the advertised contract and should only be used by the lifecycle harness on an isolated development or CI host.

When reporting an issue, include the Kāhea version, operating system, the smallest redacted source/plan that reproduces it, the observed envelope, and whether any network connection occurred before denial.
