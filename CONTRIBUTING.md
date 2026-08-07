# Contributing to Kāhea

Kāhea welcomes focused bug reports, documentation improvements, new fixtures, and changes that
strengthen deterministic planning, policy enforcement, or evidence integrity.

## Before opening a change

- Use a public issue for bugs and feature proposals. Use private vulnerability reporting for
  security issues.
- Keep changes scoped. A source-format feature should include its normalization and failure-mode
  contracts; a protocol change should include byte-stable envelope coverage.
- Never commit credentials, captured customer payloads, or fixtures that contact public services.

## Development setup

Install Rust 1.95 or newer, `jq`, and `cargo-audit`. The repository toolchain file installs the
required Rust version, rustfmt, and Clippy.

```bash
scripts/gates.sh
```

Changes to `kahea-core`, `kahea-plan`, `kahea-conformance`, or `kahea-ingest` should also run the
resource-bounded mutation gate:

```bash
scripts/mutation-gate.sh
```

The full mutation sweep is intentionally local because it is expensive. Narrow iterations with
`KAHEA_MUTANT_PACKAGES` or `KAHEA_MUTANT_EXTRA`, then run the complete affected package before
requesting review.

## Pull requests

- Explain the user-visible contract, the failure mode, and how it was verified.
- Update `CHANGELOG.md` for user-visible behavior.
- Keep formatting and Clippy warning-free.
- Contributions are licensed under Apache-2.0 as described by the repository license.

By participating, you agree to follow the project code of conduct.
