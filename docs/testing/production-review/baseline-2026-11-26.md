# Architecture acceptance scorecard

This is a semantic review of the 34 **defined** ATC propositions in
[architecture §15](../architecture.md#15-acceptance-criteria-phase-1-deliverables-written-as-testable-contracts).
The subsections are numbered 16.1–16.10 in that document. Its summary says 35,
but lists six integrity criteria while only five are defined. No requirement
below is relaxed to match the implementation. **Partial** means useful related
behavior exists but the full stated contract or its evidence is missing;
**planned** means the required flow or acceptance test is not present;
**external gate** means operational evidence and actions are still needed.
Passing a similarly named test alone does not establish acceptance.

| Criterion | Status | Evidence and remaining contract |
|---|---|---|
| MAN-1 | Partial | [Manifest test](../../crates/entangle-manifest/tests/atc_spec.rs) rejects tier 1 with a tier 3 `net.lan` capability, reporting the offending capability and tiers as `TierBelowCapability`; the contract names the error `TierUnderDeclared`. |
| MAN-2 | Implemented and tested | [Manifest test](../../crates/entangle-manifest/tests/atc_spec.rs) accepts a tier 5 native manifest declaring only tier 1 private storage and asserts the implied and effective tiers. |
| MAN-3 | Implemented and tested | [Host loading](../../crates/entangle-host/src/plugin.rs) rejects ELF bytes as `RuntimeKindMismatch`; the [acceptance test](../../crates/entangle-host/tests/runtime_kind.rs) asserts declared and observed kinds and E0507 using an ELF header. |
| MAN-4 | Partial | [CLI integration test](../../crates/entangle-cli/tests/catalog.rs) verifies tier 3 install under ceiling 2 fails with E0043 before package or keyring mutation, and direct local load also fails. The command is `entangle plugins install`, not the specified `entangle install`; `--no-load` deliberately permits packaging for another node, so the contract as written does not hold for every install mode. |
| PKG-1 | Planned | [Package implementation](../../crates/entangle-cli/src/cmd/package.rs) signs a Wasm package; the specified serial `.tar.zst` reproducibility workflow is absent. |
| PKG-2 | Planned | No specified cross-host reproducibility workflow or matching artifact hash evidence is present. |
| PKG-3 | Planned | The specified `cargo entangle package` missing-lockfile rejection and its test are absent. |
| PKG-4 | Planned | The specified `cargo entangle verify --rebuild` and published artifact rebuild test are absent. |
| BRG-1 | Partial | [Bridge test](../../crates/entangle-biscuits/tests/bridge.rs) verifies all five facts via `verify_bridge_cap` in `entangle-biscuits`; the named `entangle-signing::verify_bridge` API differs from the contract. |
| BRG-2 | Partial | The [missing-rate test](../../crates/entangle-biscuits/tests/bridge.rs) rejects the token, but returns `BridgeError::AttenuationMissing` / E0420 rather than the specified E0118. Its test name is `atc_brg_3`, not `atc_brg_2`. |
| BRG-3 | Partial | The [destination mismatch test](../../crates/entangle-biscuits/tests/bridge.rs) rejects a different destination, but uses E0424 rather than E0119. Its test name is `atc_brg_9`. |
| BRG-4 | Partial | [General biscuit expiry verification](../../crates/entangle-biscuits/src/verifier.rs) and its [round-trip test](../../crates/entangle-biscuits/tests/roundtrip.rs) reject expired tokens; the bridge-specific test and specified E0120 contract are not established. |
| BRG-5 | Partial | The [missing-total-bytes test](../../crates/entangle-biscuits/tests/bridge.rs) rejects the token with E0420, not E0122; it is named `atc_brg_4`. |
| BRG-6 | Planned | [Bridge verification](../../crates/entangle-biscuits/src/bridge.rs) validates the cap fact; no specified bridge receiver cumulative-byte accounting test is present. |
| INT-1 | Planned | [Deferred verifier-locality test](../../crates/entangle-types/tests/atc_spec.rs) is ignored; [runtime tests](../../crates/entangle-runtime/tests/integrity.rs) named INT-1 test deterministic hashes, not the stated metric locality. |
| INT-2 | Planned | The [metric-keyring acceptance test](../../crates/entangle-types/tests/atc_spec.rs) is ignored; the same-named runtime test checks replica availability instead. |
| INT-3 | Planned | The [policy mutation acceptance test](../../crates/entangle-types/tests/atc_spec.rs) is ignored; [runtime integrity tests](../../crates/entangle-runtime/tests/integrity.rs) check trusted executors, not signed policy immutability. |
| INT-4 | Planned | The [streaming submit-time rejection test](../../crates/entangle-types/tests/atc_spec.rs) is ignored; an unrelated same-named test checks a trusted executor. |
| INT-5 | Partial | [Remote dispatch](../../crates/entangle-scheduler/src/remote.rs) bounds outputs and refuses unsupported semantic-equivalence policies. The specified metric-instantiation, telemetry and reputation acceptance test is [ignored](../../crates/entangle-types/tests/atc_spec.rs). |
| STR-1, STR-2, STR-3 | Planned | [Acceptance placeholders](../../crates/entangle-types/tests/atc_spec.rs) for credit stall, heartbeat closure and signed chunks are ignored. Active type-default tests with overlapping IDs do not exercise these flows. |
| WRP-1, WRP-2, WRP-3 | Planned | The wrapper warning, disable and shadowing Bats tests named in the architecture are absent; the [CLI command modules](../../crates/entangle-cli/src/cmd/) do not provide that wrapper flow. |
| MAX-1, MAX-2, MAX-3 | Partial | [Broker policy](../../crates/entangle-broker/src/policy.rs) implements a tier ceiling; the specified interactive reload, force-unload audit and cancel/revert flows and Bats tests are absent. |
| MIR-1, MIR-2 | Planned | [OCI crate](../../crates/entangle-oci/src/lib.rs) remains a scaffold; the mirror-specific artifact and listing verification tests are absent. |
| REL-1 | Partial | [Release workflow](../../.github/workflows/release.yml) signs assets with Sigstore, and [verification script](../../scripts/verify-release.sh) checks a Sigstore bundle; the specified `entangle release verify` dual publisher-Ed25519 and Rekor verification test is absent. |
| REL-2 | External gate | The specified key ceremony record and two-of-three reconstruction test are absent; real custody and rehearsal evidence must come from maintainers. |
| BUS-1 | External gate | [Scheduled bus-factor workflow](../../.github/workflows/bus-factor.yml) invokes the [governance checker](../../scripts/check-release-governance.py), which checks roster, ownership and recent merge activity. The [roster](../maintainers/roles.toml) currently lists one holder per role, below the required two; live GitHub history and P0 issue creation must also succeed. |
| BUS-2 | External gate | The [release workflow](../../.github/workflows/release.yml) invokes the [governance checker](../../scripts/check-release-governance.py), which requires a rotation note within 35 days. `docs/governance/rotations.md` is currently absent; maintainers must supply an authentic review. |

The [name inventory](../../crates/entangle-atc-matrix/tests/matrix.rs) is
informational and does not verify these semantics. Run it with
`cargo test --locked -p entangle-atc-matrix -- --ignored --nocapture`. It
reports 34 definitions, 8 active-only name matches, 1 ignored-only match,
7 mixed active/ignored matches, and 18 without a matching name. These counts
are not a measure of passing acceptance criteria. The acceptance contract says
Phase 1 is done only when all stated propositions pass on CI.
