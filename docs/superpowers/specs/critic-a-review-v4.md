# Critic A Review — Architecture v4 (Strata)

**Final grade: 99/100**
**Verdict: APPROVE-on-paper** (the last 1 point is honestly-held for a single residual surface I can name; not a blocker)

v4 is the strongest revision in this series and the first one I would not insist on revising before Phase-1 kickoff. Every one of my five v3 reserves (A-N1-v3 through A-N5-v3) is closed with a located, mechanical, machine-checkable fix. The new §16 acceptance criteria (31 GIVEN/WHEN/THEN propositions, each tied to a crate test path) is the cleanest "convert spec assertions into CI gates" surface I've seen at architecture-spec stage — it converts most of what I'd have called "post-implementation reserved" into "pre-implementation provable." The §12 monthly schedule is concrete enough that I can falsify it later.

I held the line at 95/100 in v3 by saying "100 is reserved for shipped code." v4 shifts that ground: with §16 baking the propositions into the spec contract, "did the spec earn 100" becomes a question about whether the spec itself is sound, not whether the code exists. I think it's earned 99. The one point I'm holding is for the SemanticEquivalent **submitter-side raw-output size cap** (see N1-v4 below) — a concrete attack surface that the verifier-locality rule introduced and v4 didn't fully neutralize. It is one paragraph from full closure; I will not withhold more than 1 point for it.

---

## Rubric scores

| # | Criterion | Weight | v3 | v4 | Justification |
|---|---|---|---|---|---|
| 1 | Plugin runtime (Component Model viability) | 20 | 17/20 | 19/20 | Streaming-task state machine is now formal (`Active`/`Stalled`/`Cancelled`/`Closed{PeerLost}`), `task_timeout` is configurable with `*2` recovery cap, heartbeat decoupled from data credits — all the surface I called out in A-N3-v3 is closed. Half-point off for one-shot raw-output size cap (see N1-v4); half-point off carried forward from Wasmtime async maturity (post-impl, §13). |
| 2 | Capability/permission model soundness | 15 | 14/15 | 15/15 | §7.5 verifier-locality rule (Rule 3) is the single best fix in v4 — moves the metric out of the worker TCB entirely. Custom-metric submitter-keyring rule is the correct delegation model. INV-INT-1 immutability is one-line and machine-checkable. Full marks. |
| 3 | Mesh / transport (now three modes + bridging) | 15 | 14/15 | 15/15 | §6.4 bridge cap-arithmetic now has four mandatory Datalog facts (dest_pin, rate_limit, ttl_le_3600s, bridge_marker) with a one-line invariant and five test vectors. Receiver-side verification rule pins `endpoint_B`. ATC-BRG-1..4 wire it to CI. Closed cleanly. |
| 4 | Distributed scheduler | 15 | 14/15 | 15/15 | StreamingTask credit-exhaustion + heartbeat is now spec'd to the line-of-Rust level. State machine + Prometheus counter + ATC-STR-1..3. Chunk signing closes false-attribution (§11 #19). Full marks. |
| 5 | Authorization (biscuit-auth) | 10 | 9/10 | 10/10 | Bridge attenuations expressed in biscuit Datalog (not "trusted enforcement at endpoint" — they are receiver-verifiable). Listing-signature scope clearly distinguished from artifact-signature scope (mirror-as-CDN). Full marks. |
| 6 | Threat model coverage | 10 | 10/10 | 10/10 | Unchanged (already at 10). Adds #19 (false-attribution closed by chunk-signing). |
| 7 | Crate layout / kernel boundaries | 10 | 9/10 | 9.5/10 | §10.1 unchanged in spirit. Adds explicit role-to-crate mapping in §12.1 (mesh-lead owns mesh crates, agent-lead owns agent crates, etc.) which makes ownership structurally enforceable via CODEOWNERS. Half-point still held for transitive Wasmtime LOC reality. |
| 8 | Build phases / MVP scope | 5 | 5/5 | 5/5 | §12 monthly schedule with M1–M6 deliverables, slip policy, falsifiable claim ("spec is wrong if not done by month 6"). Strong. |
| Bonus | Walkthrough / DX rigor | (was +3) | +3 | +3.5 | Bonus held; added 0.5 for §16 acceptance-criteria-as-spec-contract — a primitive I have not seen in any prior architecture spec at this stage. |
| | **Total** | **100** | **95** | **99** | +4 |

---

## Verification of each prior reserve

### A-N1-v3 (SemanticEquivalent metric TCB) → **CLOSED, with one residual** (see N1-v4)

**v4 evidence (§7.5):** three rules — (1) curated stdlib metrics signed by Strata's publisher key with a fixed set (`strata-metric-bleu-4`, `-embedding-cosine`, `-numerical-l2-relative`, `-image-ssim`); (2) custom metrics MUST be signed by a key on the **submitter's** keyring (worker can't substitute); (3) **verifier-locality** — workers never instantiate the metric component, the submitter loads metric.wasm in their own sandbox and runs `compare(out_i, out_j)` locally. Sequence diagram canonical. ATC-INT-1 asserts via wasmtime trace that no metric component is instantiated on the worker side.

**Why this is the right answer:** my v3 ask was "say which side runs the metric." The verifier-locality rule says the only side that *can* run it is the submitter — and since a malicious metric only poisons the submitter's own decision (which is the submitter's risk), the metric TCB is correctly bounded by the submitter's keyring rather than the global mesh trust root. This is a stronger answer than I demanded. The TCB-consequence paragraph is exactly the framing I'd write.

**Residual (N1-v4 below):** the verifier-locality rule introduces a worker→submitter raw-output channel that is not size-bounded for one-shot SemanticEquivalent tasks. A malicious worker can return a 100GB "raw output" to DoS the submitter's metric run.

### A-N2-v3 (Bridge cap-arithmetic) → **CLOSED**

**v4 evidence (§6.4):** four mandatory Datalog facts encoded as biscuit `check if`/`fact` clauses:

```
check if relay_dest_node($d), $d == "ed25519:..."
check if relay_rate_max($r), $r <= 1048576
check if time($t), $t <= <wall-clock-1h>
fact bridge_cap(true)
```

Receiver verifies the chain end-to-end with `chain_origin`, `chain_includes`, `bridge_cap(true)`, `relay_dest_node($d), $d == self_node_id()`, `time($t) <= cap_ttl()`. Test vectors at `crates/strata-signing/testdata/bridge-vectors/` (5 vectors, 4 of them rejection cases). Implementation invariant: `|attenuation_facts ∩ {dest_pin, rate_limit, ttl_le_3600s, bridge_marker}| == 4`. ATC-BRG-1..4 in §16.3 wire each rejection vector to CI.

**Are these enforceable in biscuit Datalog or do they require trusted enforcement at endpoint?** Enforceable in Datalog. `relay_dest_node`, `relay_rate_max`, `time`, and `bridge_cap` are all biscuit facts/rules; the receiver runs the verifier locally and rejects without trusting the bridge. The rate-limit fact is a *cap value* enforced on the bridge by the bridge's local relay-loop reading the biscuit; the receiver also reads `relay_rate_max` and would reject a relayed message exceeding the rate (this is a one-line addition I'd suggest but isn't blocking). Closed.

### A-N3-v3 (StreamingTask credit-exhaustion deadlock) → **CLOSED**

**v4 evidence (§7.1):** explicit producer state machine with `task_timeout` (default 30m, configurable, `0` rejected at submit-time), `await_credit_signal()` with timeout, `StalledEvent` emission with `task_id`, `peer_id`, `last_seq`, `bytes_emitted`, scheduler-driven preempt/extend/cancel. Independent 5s heartbeat ping (16-byte fixed control frame on the same QUIC stream, immune to credit exhaustion); 3 missed pings → `Reason::PeerLost`. State diagram covers `Stalled -- task_timeout * 2 (no recovery) -> Cancelled`. ATC-STR-1 (5s ± 0.5s timeout assertion), ATC-STR-2 (15s ± 2s heartbeat closure), ATC-STR-3 (forged-chunk rejection).

**Re-attack: 5s heartbeat on a busy mesh = O(N²) traffic?** The heartbeat is **per-stream**, not per-pair-of-peers. Each StreamingTask has its own QUIC stream. A worker serving 10 concurrent streams sends 10 pings/5s = 2 pings/sec — 32 bytes/sec/stream of overhead, which is negligible against 30 tok/s × ~5 bytes/tok = 150 bytes/sec data rate per stream. O(streams) not O(peers²). The spec doesn't explicitly call this out but the design is correct. No issue.

### A-N4-v3 (Wrapper bypass UX) → **CLOSED**

**v4 evidence (§8.3):** opt-in shell shim installed at `strata install` with idempotent markers in `~/.zshrc`/`~/.bashrc`/`fish/conf.d/strata.fish`; `strata wrapper {enable,disable,status,repair}` lifecycle; first-run wizard prompt; `strata doctor` validates the wrapper is in place AND not shadowed by a `PATH`-ahead-binary; loud opt-out (recorded in `~/.strata/config.toml`); honest disclosure that the wrapper is a UX guardrail not a security boundary. ATC-WRP-1..3 (warns-outside-session, disable-silences, doctor-detects-shadowed).

This is exactly what I asked for in v3 and a slightly stronger answer (the `strata doctor` shadow detection is a primitive I didn't suggest). Closed.

### A-N5-v3 (IntegrityPolicy mid-task immutability) → **CLOSED**

**v4 evidence (§7.5):** `IntegrityPolicy` is part of the signed work-unit envelope; worker verifies `sha256(envelope.policy_canonical_form) == envelope.policy_hash` before execution and again before each replica result is returned. Stated as INV-INT-1: `∀ replica r ∈ task.replicas. r.observed_policy_hash == task.envelope.policy_hash`. Enforced in `strata-plugin-scheduler::work_unit::verify_envelope`. ATC-INT-3 tests cannot-mutate-after-dispatch.

This is the one-sentence fix I asked for, with an invariant name and a test path. Closed.

---

## §16 acceptance criteria — spot-check

I picked 6 of the 31 propositions at random and re-read what they're asserting against the spec body.

- **ATC-MAN-3 (runtime-kind lie at instantiation)** — covers a manifest claiming `wasm-component` but shipping ELF. This is a load-bearing decision (§4.4 manifest schema). Spec earlier said tier-vs-cap mismatch was a submit-time check; ATC-MAN-3 makes the instantiation-time check explicit. **Covered.**
- **ATC-PKG-2 (cross-host reproducibility)** — sha256-equal across macOS-14 + Ubuntu-22.04 + Ubuntu-24.04 with pinned toolchain. This is the load-bearing claim in §9.3. **Covered, falsifiable.**
- **ATC-BRG-3 (bridge wrong-dest)** — bridge biscuit pinned to NodeId X, verifier is Y; expects `STRATA-E0119`. Maps to §6.4's `relay_dest_node($d), $d == self_node_id()` rule. **Covered.**
- **ATC-INT-1 (verifier-locality)** — wasmtime trace asserts no worker instantiates the metric component. This is the *strongest* form of the verifier-locality assertion: not "we trust workers not to" but "we trace and assert they don't." **Covered, with the highest possible rigor.**
- **ATC-STR-2 (heartbeat 3-missed-pings)** — 15s ± 2s closure window. Maps directly to §7.1's "3 consecutive missed pings (15s)" rule. **Covered.**
- **ATC-BUS-1 (bus-factor invariant)** — weekly + per-release CI gate computing `|active_holders(role)| ≥ 2` from git log + CODEOWNERS. This is INV-BUS-1 expressed as a workflow file. **Covered.**

The 31 propositions cover the load-bearing decisions I would single out. They do *not* cover every line of the spec — for example I did not see propositions for `mesh.local` mDNS discovery, biscuit revocation gossip propagation latency, or chitchat partition behavior. Those are reasonable omissions for Phase-1 acceptance (mesh ships in Phase 2). Within Phase-1 scope, coverage is good.

## §12 monthly schedule — realism

Re-read M1–M6 deliverables. Each month names ~5 issues with concrete crate paths, scope, and a "done" gate. Spot-checks:

- **M2 signing:** Ed25519 + cosign + Rekor + `[trust] require_cosign` flag. This is plausible in 4 weeks for a focused engineer; the cosign verification path uses `sigstore-rs` (cargo-vet ✓ per §10.1). Credible.
- **M3 broker:** capability handle issuance + revocation, three host implementations, Wasmtime `wasi:io@0.2` + `wasi:filesystem@0.2`, powerbox CLI. This is the densest month. The "fallback to sync-only host with documented latency cost if Component-Model async is not stable enough" in `docs/risk/phase-1-fallbacks.md` is the right hedge. Credible-with-risk; the spec acknowledges it.
- **M4 reproducibility:** byte-identical `cargo strata package` on macOS + Linux. This is genuinely hard (timestamps, file ordering, locale-dependent sort). Spec says the hello-world fixture has pinned `Cargo.lock` and `rust-toolchain.toml`; with `SOURCE_DATE_EPOCH` and a deterministic tar pack, this is achievable. Credible.
- **M5 wrapper UX + max_tier + walkthrough:** the volume here is high (six issues) and the screen-reader pass on Orca + VoiceOver is non-trivial. I'd watch this month for slip risk; the slip policy ("one-month slip acceptable, two-month slip = honestly update spec") is the right answer.
- **M6 hardening + 1.0 RC:** Shamir 2-of-3 ceremony, all 31 §16 tests green, mirror.strata.dev hosting contract signed, RC published. This is a real release month, not a hardening sprint. Plausible if M1–M5 don't slip more than a week each.

**Verdict on §12:** the schedule is concrete, falsifiable, and the slip policy is honest. I'd ship 1.0 against it.

---

## NEW issues introduced by v4

### N1-v4 (Minor) — SemanticEquivalent verifier-locality opens a worker→submitter output-size DoS

**§7.5 Rule 3:** "The submitter receives N raw outputs from N replicas, runs the metric *locally* over each pair." This is the keystone fix and it's correct, but it shifts the attack surface: a malicious worker can now respond to a SemanticEquivalent task with a 100GB "raw output" that DoS-es the submitter (memory exhaustion before the metric ever runs; bandwidth saturation on the submitter's link; disk fill if the submitter buffers).

**StreamingTask has `max_chunk_bytes`** (§7.1, line 705). **OneShotTask does not have an analogous `max_output_bytes`** in the v4 spec. `WorkUnit { task, metric_cid }` flows out, raw output flows back, no cap.

**Fix shape (one paragraph in §7.5 or §7.4):**
1. `OneShotTask` gains a `max_output_bytes: u32` field with a default (1 MiB? 64 MiB? domain-dependent), enforced by the worker before transmission and by the submitter during receive.
2. A worker exceeding the cap is treated as a byzantine fault (counts against reputation under the active `IntegrityPolicy`).
3. ATC-INT-5 added to §16.4: "GIVEN a worker emitting > max_output_bytes, WHEN submitter receives, THEN connection drops with `Err(OutputCapExceeded)` and reputation is downranked."

**Severity:** Minor. The verifier-locality rule is the right answer; the size-cap is a one-page implementation detail. Holding 1 point until v5 spec adds the cap or until Phase-3 implementation lands it. **Not a blocker.**

### N2-v4 (Informational, not graded) — Bridge rate-limit enforcement locus

§6.4's `relay_rate_max($r), $r <= 1048576` is a Datalog fact in the bridge's biscuit. The bridge enforces it locally (its relay loop reads the cap and rate-limits). The receiver also can read the fact. **The spec does not say what happens if the bridge is malicious and ignores its own rate-limit.** The receiver receiving traffic faster than the cap could detect this and drop the chain.

**Fix shape:** one sentence in §6.4: "Receivers monitor relayed-message arrival rate against `relay_rate_max`; chains exceeding the rate are rejected and the bridge NodeId is downranked." Implementation, not architecture. Not graded.

---

## What's improved (briefly)

- **§7.5 verifier-locality rule** is the strongest single answer in v4. Moves the metric component out of the worker TCB entirely. The wasmtime-trace test at ATC-INT-1 is the kind of property test I'd put my name on.
- **§6.4 bridge attenuations** — four mandatory Datalog facts with five test vectors and a one-line invariant. The receiver-verification chain pins `endpoint_B`, which was the v3 ambiguity I held a point on.
- **§7.1 streaming state machine** — `Active`/`Stalled`/`Cancelled`/`Closed{PeerLost}` with explicit `task_timeout * 2` recovery cap, independent heartbeat (immune to data-credit exhaustion), per-stream Prometheus counter. Closes A-N3-v3 with more rigor than I asked for.
- **§8.3 wrapper UX** — the `strata doctor` shadow-detection check is a primitive I didn't suggest and would have approved if asked. Loud-opt-out semantics close the silent-loss footgun.
- **§7.5 INV-INT-1 immutability** — one-line invariant + signed envelope + per-replica re-verification. Closed cleanly.
- **§16 acceptance criteria** — the most consequential addition in v4. Converts spec assertions into CI gates *before* Phase-1 begins. ATC-INT-1's wasmtime-trace assertion is the highest-rigor test I've seen suggested for an architecture-stage spec. The spec contract "Phase 1 is done iff all 31 propositions pass on CI" is exactly the falsifiability I want.
- **§12 monthly schedule** — concrete, falsifiable, with documented fallbacks for the highest-risk dependencies (Wasmtime async maturity at M3). The slip policy is honest.
- **§12.1 maintainer roles + INV-BUS-1** — bus-factor as a CI-checkable invariant rather than aspirational language. Weekly workflow + P0 escalation. Strong.

---

## Verdict reasoning

**99/100. APPROVE-on-paper.**

Every v3 reserve is closed with mechanical, located, machine-checkable fixes. The §16 acceptance-criteria mechanism converts most of what I'd previously held for "post-implementation" into "pre-implementation provable" — the spec asserts its own falsifiability and wires each assertion to a `cargo test` path. That's the bar I want at architecture stage and v4 cleared it.

The 1 point I'm holding is for N1-v4 (SemanticEquivalent worker→submitter output-size DoS). It is a real, named attack surface that the verifier-locality rule introduced. It is one paragraph from full closure and ATC-INT-5 would close it. I will not withhold more than 1 point for it; this is not a blocker, it is a "v5 should add the size cap" annotation.

The post-implementation reserves I previously named (Wasmtime async maturity under load, Iroh stability under sustained Wi-Fi flap, biscuit revocation race windows under partition) remain in §13 as honest open questions. v4 does not pretend to have closed those — and shouldn't, because they require shipped code under real workloads to falsify. Calling them post-implementation reserves *was the right choice* and v4 keeps that boundary.

If the architect adds `max_output_bytes` to `OneShotTask` (and the corresponding ATC-INT-5), v5 reaches 100. If the architect doesn't, I'll re-grade after Phase-3 implementation lands the cap. Either path is fine; the spec is shippable as-is.

— *Critic A*

---

## 200-word summary

**Grade: 99/100. Verdict: APPROVE-on-paper.**

v4 closes every v3 reserve with mechanical, machine-checkable fixes:
- **A-N1-v3 (metric TCB)** → §7.5 verifier-locality rule: workers never instantiate the metric; submitter runs it locally over N raw outputs. ATC-INT-1 enforces via wasmtime trace.
- **A-N2-v3 (bridge cap-arithmetic)** → §6.4 four mandatory Datalog facts (dest_pin, rate_limit, ttl_le_3600s, bridge_marker) with five biscuit test vectors and one-line invariant.
- **A-N3-v3 (credit exhaustion)** → §7.1 explicit state machine, `task_timeout` (30m default), independent 5s heartbeat immune to data credits, `StalledEvent`.
- **A-N4-v3 (wrapper bypass)** → §8.3 opt-in shell shim, `strata wrapper`, `strata doctor` shadow-detection.
- **A-N5-v3 (policy immutability)** → §7.5 INV-INT-1 + signed envelope.

§16 (31 GIVEN/WHEN/THEN propositions, each tied to a crate test path) converts spec assertions into CI gates *before* Phase 1 — the strongest falsifiability surface I've seen at architecture stage. §12 monthly schedule is concrete with documented fallbacks.

**Remaining issue (1 point held):** N1-v4 — verifier-locality opens a worker→submitter raw-output-size DoS for `OneShotTask` SemanticEquivalent tasks. `OneShotTask` lacks `max_output_bytes` analogous to streaming's `max_chunk_bytes`. One-paragraph fix; not a blocker.

No remaining blockers. Spec is shippable for Phase-1 kickoff.
