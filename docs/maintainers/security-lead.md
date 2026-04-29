# Security Lead

## Responsibilities

You own `entangle-signing`, the threat model (spec §11), the audit log policy (`entangle-broker::audit`), the supply-chain story (§10.1 trust footprint, sigstore release attestation), and SECURITY.md vulnerability response.

You're the standing co-signer for any change that touches a tier-5 capability, adds a new dependency at L0/L1, modifies sandbox parity rules, or relaxes any acceptance test.

## Onboarding

1. Spec §11 entire threat model, every numbered entry. You should be able to recite #16 (allowlist startup invariant) and #19 (false-attribution closure via chunk signing) from memory.
2. Spec §10.1 — every L0/L1 dep and its provenance posture.
3. Run `cargo audit` and `cargo deny check` against the workspace. Resolve every finding before any release.
4. Read OpenBSD pledge/unveil, WASI Preview 2 capabilities, and the Sandstorm powerbox paper for the philosophy.

## Decisions you can make solo

- Documentation in SECURITY.md.
- Triaging incoming reports.
- Adding new test cases that tighten existing invariants.
- Updating dependency advisories without changing the public API.

## Decisions that need quorum (≥2 security-leads + 1 core-runtime-lead OR mesh-lead OR agent-lead, depending on scope)

- Loosening any §11 invariant or any §16 acceptance criterion.
- Approving a new L0/L1 dependency or upgrading wasmtime, biscuit-auth, ed25519-dalek to a major version.
- Adding `unsafe` code anywhere.
- Disclosing a vulnerability outside the 90-day target.
- Releasing without sigstore attestation (when sigstore release is wired in Phase 1.x).

## Escalation

Coordinate with the impacted role-lead. For cross-cutting issues (e.g., a kernel bug that's also a vulnerability), call a joint quorum.
