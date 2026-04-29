# Core Runtime Lead

## Responsibilities

You own the kernel: `entangle-runtime`, `entangle-host`, `entangle-broker`, `entangle-types`. Every change to the plugin lifecycle, capability enforcement, manifest schema, or wasm host integration ends up on your desk.

You also own the §16 ATC suite for these crates. If a spec change adds an acceptance criterion, you own the test that proves it.

## Onboarding

Read in order:
1. [Architecture spec v6](../superpowers/specs/2026-04-29-entanglement-architecture-v6.md) — sections §0, §1, §2, §3, §4, §5, §7.1, §7.5, §10, §11, §16.
2. [REPORT.md](../../REPORT.md) — the architectural decisions in plain English.
3. The crates you own. Read every public item's docstring. Run `cargo doc --workspace --no-deps --open`.
4. Pair with the existing core-runtime-lead on at least one PR before merging anything solo.

## Decisions you can make solo

- Internal refactors that don't change public crate APIs.
- New private helpers, error variants behind `#[non_exhaustive]`, dependency upgrades that don't change the trust footprint table (§10.1).
- Test additions.

## Decisions that need quorum (≥2 core-runtime-leads + 1 security-lead)

- Public API breaking changes in the four owned crates.
- Trust footprint additions (any new dep at L0/L1).
- Changes to capability enforcement semantics (broker logic, deny-by-default invariant).
- Adding `unsafe` to a crate currently `#![forbid(unsafe_code)]`.

## Escalation

Architectural disputes that the role-quorum can't resolve within 7 days escalate to a project-wide RFC ticket. RFCs follow the spec template (problem → proposed change → alternatives → migration plan).
