# Contributing to Entanglement

Entanglement is an open, capability-isolated plugin runtime for local-first AI
infrastructure. We welcome contributions from the community.

## Project mission

Provide a secure, verifiable plugin execution environment where every capability
access is explicit, auditable, and deny-by-default — eliminating ambient authority
from AI agent workloads. See spec §1 for the full mission statement:
`docs/superpowers/specs/2026-04-29-entanglement-architecture-v6.md`

## Find the spec first

Every contribution — code, docs, or tests — should reference a `§section` from the
architecture spec. If your change touches something not covered by the spec, open an
issue to discuss the design before submitting a PR.

## Local dev setup

**Prerequisites**: Rust (stable via `rust-toolchain.toml`), `cargo`, `git`.

```bash
# Build the entire workspace
cargo build --workspace

# Run all tests
cargo test --workspace

# Check for lints (required before submitting)
cargo clippy --workspace -- -D warnings

# Verify docs build clean (required before submitting)
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps
```

## ATC tests (spec §16)

Every spec change must add an **Acceptance-Test Contract** (ATC) ID and a
corresponding test. Format:

```
/// §16 ATC-<DOMAIN>-<N>: <one-line description>
#[test]
fn atc_<domain>_<n>_<description>() { ... }
```

See `crates/entangle-broker/tests/atc_spec.rs` for examples.

## Code review

- PRs require **1 maintainer approval** (Phase 1).
- Phase 2+ security-sensitive paths (signing, mesh transport) may require 2 approvals.
- Every PR must pass `cargo test --workspace`, `cargo clippy`, and rustdoc.
- Breaking changes require a migration guide in `docs/` before merging.

## Commit style

Conventional commits are encouraged but not required:
`feat:`, `fix:`, `docs:`, `refactor:`, `test:`, `chore:`

Commit signing is recommended for all contributors and **required** for
`release-lead` PRs. See `docs/maintainers/release-lead.md`.

## Code of conduct

All participants are expected to follow our
[Code of Conduct](CODE_OF_CONDUCT.md) (Contributor Covenant 2.1).

## Maintainer roles

See `docs/maintainers/roles.toml` for the current roster and
`docs/maintainers/<role>.md` for per-role responsibilities.
