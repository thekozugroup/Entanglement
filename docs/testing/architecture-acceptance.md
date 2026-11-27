# Architecture acceptance scorecard

This is a semantic review of the 34 **defined** ATC propositions in
[architecture §15](../architecture.md#15-acceptance-criteria-phase-1-deliverables-written-as-testable-contracts).
The subsections are numbered 16.1–16.10 in that document. Its summary says 35,
but lists six integrity criteria while only five are defined. No requirement
below is relaxed to match the implementation. **Partial** means useful related
behavior exists but the full stated contract or its evidence is missing;
**planned** means the required flow or acceptance test is not present;
**external gate** means operational evidence and actions are still needed.
**Candidate tested** means the described focused test passed during development;
it is not a claim that the final source snapshot has passed the entire contract.
Passing a similarly named test alone does not establish acceptance.

| Criterion | Status | Evidence and remaining contract |
|---|---|---|
| MAN-1 | Implemented and tested | The public validator emits `TierUnderDeclared` with the offending capability, its required tier and the declared tier. The existing module-level validator retains its original diagnostic. [Manifest tests](../../crates/entangle-manifest/tests/atc_spec.rs) |
| MAN-2 | Implemented and tested | [Manifest test](../../crates/entangle-manifest/tests/atc_spec.rs) accepts a tier 5 native manifest declaring only tier 1 private storage and asserts the implied and effective tiers. |
| MAN-3 | Implemented and tested | The manifest accepts `[runtime] kind = "wasm-component"` and rejects conflicting declarations. Host compilation rejects an ELF header with `RuntimeKindMismatch`, reporting the declared and observed kinds. [Manifest tests](../../crates/entangle-manifest/tests/atc_spec.rs) · [Host test](../../crates/entangle-host/tests/runtime_kind.rs) |
| MAN-4 | Implemented | The top-level installer checks the configured ceiling before persisting any package. The CLI regression supplies a tier 3 manifest to a tier 2 profile, checks typed `TierExceeded` and verifies the profile contents. [Install test](../../crates/entangle-cli/tests/distribution.rs) |
| PKG-1 | Implemented and tested | The [serial packaging fixture](../../crates/cargo-entangle/tests/verify_rebuild.rs) ran two `cargo entangle package` builds in separate temporary paths and asserted identical SHA-256 digests on Linux. |
| PKG-2 | Partial | The [reproducibility workflow](../../.github/workflows/reproducibility.yml) compares digests across Ubuntu 22.04, Ubuntu 24.04 and macOS 14. A hosted run with matching digests is pending. |
| PKG-3 | Implemented and tested | The [missing-lockfile fixture](../../crates/cargo-entangle/tests/package.rs) verifies a committed source without `Cargo.lock` fails before building. |
| PKG-4 | Partial | The [signed rebuild fixture](../../crates/cargo-entangle/tests/verify_rebuild.rs) authenticates the archive, independently rebuilds signed source in another Git checkout and compares the digest. The published-artifact rebuild is pending. |
| BRG-1 | Candidate tested | [Signed-vector test](../../crates/entangle-signing/tests/bridge_attenuation.rs) calls `entangle_signing::verify_bridge` and asserts all five facts; rerun on the final source snapshot is pending. |
| BRG-2 | Candidate tested | [Missing-rate vector](../../crates/entangle-signing/tests/bridge_attenuation.rs) requires E0118 from `verify_bridge`; final-source rerun pending. |
| BRG-3 | Candidate tested | [Wrong-destination vector](../../crates/entangle-signing/tests/bridge_attenuation.rs) requires E0119; final-source rerun pending. |
| BRG-4 | Candidate tested | [Expired-TTL vector](../../crates/entangle-signing/tests/bridge_attenuation.rs) requires E0120; final-source rerun pending. |
| BRG-5 | Candidate tested | [Missing-total-bytes vector](../../crates/entangle-signing/tests/bridge_attenuation.rs) requires E0122; final-source rerun pending. |
| BRG-6 | Candidate tested | [Receiver test](../../crates/entangle-signing/tests/total_bytes_cap.rs) delivers 1024 bytes, reopens the ledger and rejects one more byte as `BridgeBudgetExhausted`. The tested receiver and live bridge have candidate evidence; final-source rerun pending. |
| INT-1 | Candidate tested | [Three-worker signed semantic test](../../crates/entangle-scheduler/tests/cases/semantic.rs) asserts zero worker metric instantiations and three submitter instantiations for the three pair comparisons; final-source rerun pending. |
| INT-2 | Candidate tested | The [semantic test](../../crates/entangle-scheduler/tests/cases/semantic.rs) removes the metric publisher from the submitter keyring and asserts `MetricNotInKeyring` before dispatch; final-source rerun pending. |
| INT-3 | Partial | [Semantic test](../../crates/entangle-scheduler/tests/cases/semantic.rs) rejects a mid-flight policy mutation and checks each receipt against an independently calculated H for signed semantic replicas. The older v1 one-shot policies do not yet carry the signed immutable envelope, so the broader stated policy invariant is not established. |
| INT-4 | Candidate tested | [Streaming test](../../crates/entangle-scheduler/tests/cases/stream.rs) rejects deterministic streaming before routing with `InvalidIntegrityForStreaming`; final-source rerun pending. |
| INT-5 | Candidate tested | [Semantic test](../../crates/entangle-scheduler/tests/cases/semantic.rs) injects a 2048-byte result against 1024, checks rejection before another metric instantiation, the structured peer/size warning and reputation decrease; final-source rerun pending. |
| STR-1, STR-2, STR-3 | Candidate tested | [QUIC streaming tests](../../crates/entangle-scheduler/tests/cases/stream.rs) assert a 5-second credit stall and resumption, a 15-second three-ping timeout, and valid versus forged chunk signatures. These passed in an intermediate run; independent final-source rerun and physical-network evidence remain pending. |
| WRP-1, WRP-2, WRP-3 | Partial | [Wrapper tests](../../crates/entangle-cli/tests/wrapper.rs) cover Bash and Zsh warning/arguments/exit and explicit Fish-source behavior; install offers opt-in. A focused test confirms disabling silences a function already loaded in the same shell. The full interactive install opt-in path still needs direct evidence. [Doctor](../../crates/entangle-cli/src/cmd/wrapper.rs) detects an unmarked environment with a reachable binary; a child cannot inspect all aliases/functions in its parent shell, so general shadow detection remains incomplete. |
| MAX-1, MAX-2, MAX-3 | Partial | [Live daemon harness](../../scripts/tests/max-tier.py) exercises interactive default unload, cancel/revert, forced unload and per-plugin audit on a 5→2 lowering. The specified 5→3 scenario and final-source rerun still need direct evidence. |
| MIR-1, MIR-2 | Implemented and tested locally | Both transports authenticate component and manifest with the publisher keyring. Archives also require the same publisher on the compressed bytes. Signed tag enumeration verifies the mirror separately and reports its fingerprint. OCI Distribution v3 served a real signed package by tag and manifest digest, followed by daemon invocation and rejection of a revoked publisher. The production mirror has no supplied endpoint or verification receipt. [Boundary tests](../../crates/entangle-oci/tests/distribution.rs) · [Registry test](../../scripts/tests/oci-registry.py) |
| REL-1 | Partial | [Release verifier](../../crates/entangle-cli/src/cmd/release.rs) and [harness](../../scripts/tests/release-verify.sh) exercise dual verification using genuine historical Sigstore proof and an independent ephemeral Ed25519 signer. A published 1.0 RC signed by both production identities remains external and unverified. |
| REL-2 | External gate | The specified real release-key ceremony record and two-of-three reconstruction rehearsal remain unavailable; synthetic cryptographic tests cannot substitute for maintainer custody evidence. |
| BUS-1 | External gate | [Scheduled bus-factor workflow](../../.github/workflows/bus-factor.yml) invokes the [governance checker](../../scripts/check-release-governance.py), which checks roster, ownership and recent merge activity. The [roster](../maintainers/roles.toml) currently lists one holder per role, below the required two; live GitHub history and P0 issue creation must also succeed. |
| BUS-2 | External gate | The [release workflow](../../.github/workflows/release.yml) invokes the [governance checker](../../scripts/check-release-governance.py), which requires a rotation note within 35 days. `docs/governance/rotations.md` is currently absent; maintainers must supply an authentic review. |

The [name inventory](../../crates/entangle-atc-matrix/tests/matrix.rs) is
informational and does not verify these semantics. Run it with
`cargo test --locked -p entangle-atc-matrix -- --ignored --nocapture`. It
reports 34 definitions, 8 active-only name matches, 1 ignored-only match,
7 mixed active/ignored matches, and 18 without a matching name. These counts
are not a measure of passing acceptance criteria. The acceptance contract says
Phase 1 is done only when all stated propositions pass on CI.
