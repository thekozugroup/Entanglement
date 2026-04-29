# Critic A Review — Architecture v3 (Strata)

**Final grade: 95/100**
**Verdict: REVISE → APPROVE-on-paper** (100 remains reserved for post-implementation, per my v2.1 framing)

v3 is a substantively complete answer. Every prior blocker, significant, and minor I raised in v2 has a concrete, located fix. The `IntegrityPolicy` taxonomy (§7.5) is the answer I asked for in v2 N1 — not a hand-wave, a sum type with submit-time validation and per-variant defaults wired to each named workload. The Tailscale liveness FSM (§6.1.1) is more rigorous than I demanded. The `init` wizard / allowlist invariant (§9.2) is now coherent across three layers (wizard, config validation, daemon start). The transitive-dep trust footprint (§10.1) is honest about Wasmtime. I'm raising **9 points** to 95. I'm holding **5 points** because (a) the `SemanticEquivalent` metric variant introduces a new TCB element (the metric plugin itself) that the spec under-specifies, (b) the disjoint-transport bridging in §6.4 has a residual cap-arithmetic concern, (c) §8.3's "user runs claude-code outside Strata's wrapper" disclosure is honest but creates a security model the user must understand, and (d) `StreamingTask` backpressure under credit exhaustion has an unstated deadlock window. None of these are blockers; all are addressable in v3.1 or surface as Phase-2/3 implementation findings.

---

## Rubric scores

| # | Criterion | Weight | v1 | v2.1 | v3 | Justification |
|---|---|---|---|---|---|---|
| 1 | Plugin runtime (Component Model viability) | 20 | 11/20 | 15/20 | 17/20 | Unchanged in shape; gains `StreamingTask` (§7.1) which is new runtime surface. CreditBased backpressure is the right primitive but the credit-exhaustion deadlock window is not specified. |
| 2 | Capability/permission model soundness | 15 | 12/15 | 13/15 | 14/15 | §4.4.1 three-case worked example (under/over/lie) closes the v2.1 ambiguity. `max_tier_allowed` (§9.4.1) gives operators the global lever they actually need. Residual: `SemanticEquivalent` metric plugin is itself a capability-bearing component whose authority is undelegated in §7.5. |
| 3 | Mesh / transport (now three modes + bridging) | 15 | 9/15 | 12/15 | 14/15 | §6.1.1 Tailscale FSM is genuinely good. §6.4 default-no-bridging with dual-side biscuit delegation is the right shape. Bridging cap arithmetic concern below. |
| 4 | Distributed scheduler | 15 | 9/15 | 12/15 | 14/15 | §7.5 taxonomy + submit-time validation + per-variant reputation is the answer. `Attested` reserved-but-rejected is good forward-compat hygiene. Half-point off for `SemanticEquivalent` metric trust model. |
| 5 | Authorization (biscuit-auth) | 10 | 6/10 | 8/10 | 9/10 | Unchanged; gains transport-agnostic explicit framing in §6.4. Partition-window race remains acknowledged in §13 #8. |
| 6 | Threat model coverage | 10 | 5/10 | 8/10 | 10/10 | New §11 #17 (host tailscale binary supply chain) and #18 (hostile control plane) close the v2 N5/N6 gaps cleanly. Three-domain trust split now first-class. |
| 7 | Crate layout / kernel boundaries | 10 | 6/10 | 8/10 | 9/10 | §10.1 transitive-dep table is the honest framing I asked for. Wasmtime vendored is the right call. Half-point off because 25k LOC budget is still hardened-daemon-sized; framing now matches reality. |
| 8 | Build phases / MVP scope | 5 | 3/5 | 5/5 | 5/5 | §12.1 bus-factor mitigations (2-of-3 Shamir signing, mirror.strata.dev kill-switch, named maintainer roster) are Phase-1 deliverables, not aspirational. Strong. |
| Bonus | Walkthrough / DX rigor | (was unscored) | — | — | +3 | §9.3 CI-tested hello-world, §9.1.1 failure-mode ladder, §9.4.2 a11y/i18n stance — these are deliverables most architecture specs hand-wave. |
| | **Total** | **100** | **64** | **86** | **95** | +9 |

---

## Status of each prior issue

### A-N1 (Critical, was PARTIAL) — Non-deterministic compute integrity policy → **FIXED**

**v3 evidence:** §7.5 introduces `enum IntegrityPolicy { Deterministic, SemanticEquivalent { metric, threshold }, TrustedExecutor { allowlist }, Attested { tee }, None }`. §7.0 Workload A explicitly defaults to `TrustedExecutor { allowlist: <user's own NodeIds> }` with `replication=1`. §7.1 `StreamingTask` rejects `Deterministic` and `SemanticEquivalent` at submit-time. §7.5 quoted error message:

> `error: task uses StreamingTask + Integrity::Deterministic`
> `Streaming tasks cannot be hash-replicated (chunked outputs do not support quorum across replicas). Use Integrity::TrustedExecutor.`

**Score on the fix:** this is exactly what I asked for. The taxonomy covers the workload spectrum (deterministic Wasm, semantically-equivalent LLM batch eval, trusted-own-hardware streaming, future TEE, opt-out). Submit-time validation makes mismatches impossible to ship. Per-variant reputation tracking is preserved. The default-policy table in §7.5 wires Workload A → `TrustedExecutor`, B → `Deterministic`, C → `Deterministic`, federated eval → `SemanticEquivalent`. North-star workload is no longer aspirational. **FIXED.**

### A-N2 (Significant) — Tailscale daemon liveness → **FIXED**

**v3 evidence:** §6.1.1 specifies a 5-second poll loop with 2-poll hysteresis, three terminal states (`tailnet-active`, `tailnet-installed-but-stopped`, `tailnet-uninstalled`), structured warning per *transition* (not per poll — explicit anti-spam), Prometheus metrics (`strata_mesh_tailscale_state{state="..."}`), and a degradation path that re-routes peers with multiple transports. Biscuit caps survive logout because they're signed by Strata's Ed25519 key not Tailscale's WireGuard key (§9.1.1 post-pairing logout paragraph). 30-second tolerance for auto-update restarts kills the most common false positive. **FIXED.**

### A-N3 (Significant) — Disjoint-transport reachability bridging → **FIXED**

**v3 evidence:** §6.4 specifies default-no-bridging with intersection-based reachability matrix, the `strata mesh routes` user-facing surface with prescriptive hints (literal commands), and opt-in bridging gated by `[mesh.bridge] enabled = true` PLUS dual-side biscuit delegation of `mesh.relay`. Biscuits are explicitly transport-agnostic. **FIXED** (new concern in §"New issues" below — N1-v3 — about cap arithmetic on a malicious bridge).

### A-N4 (Significant) — Init-wizard vs §11 #16 allowlist contradiction → **FIXED**

**v3 evidence:** §9.2 introduces a single-node-vs-multi-node branch (step 4) and a "pair the first peer now or later" step (step 7). Pair-later mode adds the local node's *own* fingerprint to `[trust] strata.peers` so the allowlist is non-empty (satisfying the invariant) and prints clear next-steps. The daemon's startup check re-validates the invariant. §11 #16 sharpened to clarify "single-node mode is the only empty-allowlist exception." Three-layer enforcement (wizard, config validation, daemon start). **FIXED.**

### A-trust-footprint — Trust footprint with transitive deps → **FIXED**

**v3 evidence:** §10.1 publishes a full transitive-dep table per L1/L2 crate. Wasmtime is **vendored** as a git subtree (so CVE patching is on Strata's schedule). biscuit-auth has internal audit notes beyond cargo-vet. ed25519-dalek/sigstore/minisign-verify are cargo-vet ✓. rustls everywhere; no openssl in trust path. Honest framing paragraph: "the *first-party* L1+L2 LOC budget (<25k) is small. The *real* trust footprint, including transitive deps, is dominated by Wasmtime (~hundreds of kLOC of Cranelift + WASI implementations). We don't pretend otherwise." **FIXED.**

### A-N5 (Minor, v2) — Hostile Headscale control plane → **FIXED**

**v3 evidence:** new §11 #18 — "MagicDNS provides rendezvous, not authentication." Strata's TOFU + `[trust] strata.peers` + biscuits remain the security primitive. `strata-on-top` ACL mode default. Documented in install wizard. **FIXED.**

### A-N6 (Minor, v2) — Host `tailscale` binary supply chain → **FIXED**

**v3 evidence:** new §11 #17 — minimum supported Tailscale version pinned (`>= 1.62.0`), checked at boot; detected version logged on every state transition; user-facing surface in init wizard names the trust dep ("Strata trusts the local Tailscale binary..."); we explicitly do NOT verify the binary signature ourselves (OS package manager does that, re-implementing would be redundant — correct call). **FIXED.**

---

## NEW issues introduced by v3

### N1-v3 (Significant) — `SemanticEquivalent` metric plugin trust model under-specified

**§7.5** says the metric is "a Wasm component (interface `strata:integrity/metric@0.1.0`) whose `compare(a, b) -> f64` returns a pairwise distance" and "supplied by the submitter and signed by a publisher in the user's trust root." The metric plugin is now part of the integrity decision — a malicious or buggy metric plugin can:
- Always return distance 0 (everything passes quorum, byzantine workers undetected).
- Always return distance ∞ (DoS legitimate jobs).
- Return distances biased toward outputs from a specific NodeId.

The spec doesn't say:
- Does the metric plugin run on the **submitter** (verifies others) or on **each worker** (and we hash-quorum the *distance scores*)? If the former, a compromised submitter trivially defeats the policy. If the latter, the spec doesn't say so.
- Is the metric plugin's tier? `min_tier`? It's reading task outputs from N peers — that's a data-flow capability that should be declared.
- Is there a curated registry of audited metric plugins? The §10 `metrics-plugins/` directory lists `strata-metric-bleu`, `-embedding-cosine`, `-logprob-kl` but doesn't say whether arbitrary publisher metrics are accepted.

**Fix shape:** §7.5 needs one paragraph clarifying that (a) the metric runs on the submitter side over results received from N replicas (this is the only model that doesn't require trusting the workers), (b) the metric plugin runs in its own Wasmtime instance with no capabilities beyond the input pair, (c) for federated public LLM eval the metric publisher is treated as part of the TCB and named explicitly. Significant, not blocker.

### N2-v3 (Significant) — Bridging cap arithmetic on a malicious bridge

**§6.4** specifies dual-side biscuit delegation: "a relayed message carries a biscuit chain `endpoint_A -> bridge -> endpoint_B`." A malicious bridge cannot fabricate the chain (biscuits are unforgeable), but the spec doesn't say:
- Does the bridge attenuate the cap (narrow it) on relay, or pass it through verbatim? If verbatim, the bridge holds a copy of `endpoint_A`'s cap and could replay it directly to `endpoint_B` outside the relay context. If attenuated, the spec needs to define the attenuation (e.g. `relay_only = true` clause).
- What's the rate-limit on the bridge? A bridge can amplify A's outbound bandwidth — the spec mentions logging but no `mesh.relay { max_bytes_per_sec }` parameter.
- Biscuits include nonces (§11 #8); a relayed message has a single nonce — the bridge can't replay the same message twice, but can it redirect to a peer not named in `endpoint_B`? The chain pins `endpoint_B` at delegation time, but the spec doesn't show that pinning explicitly.

**Fix shape:** §6.4 should specify that (a) the bridge's `mesh.relay` cap is attenuated to the specific `(endpoint_A, endpoint_B)` pair at delegation time, (b) bridging includes a `max_bytes_per_sec` and `max_chunks_per_sec` parameter, (c) the receiver verifies the relayed biscuit's `endpoint_B` clause matches its own NodeId. Significant; the security primitive is in place but the surface details are not.

### N3-v3 (Minor) — `StreamingTask` credit exhaustion behavior

**§7.1** specifies `BackpressureMode::CreditBased { window: u32 }`. The example shows `Submitter -> Worker: Credit { add: 32 }` to refill. The spec doesn't say what happens when:
- The submitter never sends `Credit`. Does the worker block forever? `idle_timeout: Duration` exists but the spec doesn't say whether idle-timeout fires on the worker side when waiting for credit (should it? — yes, but say so).
- The submitter is malicious and sends `Credit { add: u32::MAX }` on every chunk. Does the worker apply unbounded buffering? Nothing in §7.1 caps the credit window.
- The transport flaps mid-stream and the credit accounting goes inconsistent. The spec doesn't define a recovery path.

**Fix shape:** §7.1 should say (a) `idle_timeout` fires when the worker has produced a chunk but not received a `Credit` for `idle_timeout`, treating as `StreamClosed { reason: BackpressureStarved }`; (b) the worker enforces a maximum window size independent of submitter requests (e.g. `min(submitter_window, server_max=128)`); (c) on transport flap, the worker resumes with `seq = last_acked + 1` if the submitter reconnects with a `StreamResume { task_id, last_seq_received }`. Minor; this is implementation detail but it's load-bearing for Workload A and worth specifying.

### N4-v3 (Minor) — §8.3 "user bypasses Strata's wrapper" creates a confusing security model

**§8.3** is honest: "Running `claude-code` directly bypasses Strata, by design — your existing workflow is preserved. Tier-5 audit only applies to Strata-launched sessions." This is the correct answer (we cannot prevent a user from running an unwrapped binary), but it creates a UX trap:

- The user installs `agent-host-claude-code` thinking they get audit. They run `claude-code` (muscle memory) instead of `strata agent run claude-code`. They get no audit. The threat model in §11 #10 ("tier-5 agent escapes via Node.js exploit") presupposes the gateway is in the path.
- A defensive-aware user expects `strata agent uninstall` to disable the agent — but uninstall removes the wrapper, not Node.js or `~/.claude/`.

**Fix shape:** §8.3 should add a one-paragraph operator-runbook entry: "If audit is required, document organizationally that Claude Code must be launched only via `strata agent run`. Strata cannot block the unwrapped invocation. A future hardening: replace `~/.claude/` with a directory the user can't write to without `strata agent run`, but this is intrusive and not Phase-5 scope." This is documentation, not architecture, hence Minor.

### N5-v3 (Minor) — `IntegrityPolicy` mid-task downgrade

The spec doesn't explicitly say `IntegrityPolicy` is **immutable** for the task lifetime. A submitter who can re-attach to an in-flight task could (in theory) change the policy from `Deterministic { 3, 2 }` to `None` after seeing one peer's result. The fix is one sentence — "`IntegrityPolicy` is signed as part of the task envelope and any modification invalidates the signature; workers refuse to honor mid-flight policy changes" — but it's not stated in §7.5.

---

## What's improved (briefly)

- §7.5 `IntegrityPolicy` taxonomy + per-workload defaults + submit-time validation is the right design and exactly what I asked for in v2 N1.
- §6.1.1 Tailscale FSM with three states + 2-poll hysteresis + biscuit-survives-logout is more rigorous than my v2 N2 demanded.
- §9.2 init-wizard pair-the-first-peer step + §11 #16 sharpened "single-node is the only empty-allowlist exception" makes the invariant coherent across three layers.
- §10.1 transitive-dep table with Wasmtime-vendored, ed25519-dalek/sigstore/minisign-verify cargo-vet ✓, biscuit-auth internal audit, rustls everywhere is the honest framing my v2 N7 asked for.
- §12.1 bus-factor mitigations (2-of-3 Shamir on signing keys, `mirror.strata.dev` kill-switch with 5-year prepaid hosting + IPFS pin, named maintainer roster) are Phase-1 deliverables — survival not aspiration.
- §8.3 configuration-adapter model + per-session HTTP gateway is more honest than v2.1's fd-injection claim, even if it creates the §"N4-v3" UX trap.
- §9.4.1 `[security] max_tier_allowed` gives operators the global tier-disable lever I noted as missing in v2 (B-S-NEW-2).
- §9.1.1 failure-mode ladder for `strata init --transport tailscale` (six conditions, six exit codes, six remedies) mirrors §6.3's pairing-UX rigor.
- New threat-model entries §11 #17 (host tailscale binary) and #18 (hostile Headscale) close my v2 N5/N6.

---

## Verdict reasoning

**95/100. APPROVE-on-paper.**

v3 is the strongest architecture spec I've reviewed in this series. Every prior blocker has a located fix; the byzantine-policy taxonomy is the answer; the Tailscale FSM is more rigorous than I demanded; the transitive-dep trust footprint is honest. I would ship beta on this design with high confidence and would actively recommend it.

The 5 points I'm holding back are not blockers; they're surface-area items that surface during implementation contact:
- Metric-plugin trust model (N1-v3) — the `SemanticEquivalent` policy widens the TCB; one paragraph fixes it.
- Bridge cap-arithmetic (N2-v3) — dual-side delegation is the right primitive but attenuation/rate-limit/pinning details are missing.
- StreamingTask credit-exhaustion behavior (N3-v3) — the right primitive, missing the failure-mode details.
- Wrapper-bypass UX (N4-v3) — operator-runbook documentation, not architecture.
- IntegrityPolicy mid-task immutability (N5-v3) — one sentence in §7.5.

The remaining 5 points to 100 are reserved (per my v2 framing) for **post-implementation**: Wasmtime async maturity, Iroh stability under sustained Wi-Fi flap, biscuit revocation race windows under partition. v3 acknowledges these in §13. APPROVE at 100 should mean "Phase 1 shipped and the first byzantine-resilient compute job ran across the mesh." That's what I said in v2.1 and I'm holding to it.

If the architect addresses N1-v3 and N2-v3 mechanically, v3.1 reaches 97. The rest waits for code.

— *Critic A*

---

## 200-word summary

**Grade: 95/100. Verdict: REVISE → APPROVE-on-paper.** v3 lands every prior blocker.

**Prior issues, all FIXED:**
- A-N1 (non-deterministic compute integrity): `IntegrityPolicy` taxonomy with `Deterministic`, `SemanticEquivalent { metric, threshold }`, `TrustedExecutor { allowlist }`, `Attested`, `None`. Workload A defaults to `TrustedExecutor`. Submit-time validation rejects mismatches.
- A-N2 (Tailscale liveness): 5s poll with 2-poll hysteresis, three terminal states, structured warning per transition, biscuit caps survive logout.
- A-N3 (disjoint-transport bridging): default-no-bridging, opt-in with dual-side `mesh.relay` biscuit delegation, transport-agnostic biscuits.
- A-N4 (init-wizard/allowlist contradiction): single-node-vs-multi-node branch, pair-the-first-peer step, three-layer enforcement.
- A-trust-footprint, A-N5, A-N6: §10.1 transitive-dep table; new §11 #17 (host tailscale binary) and #18 (hostile Headscale).

**New non-blocker issues:** N1-v3 `SemanticEquivalent` metric plugin trust model under-specified (TCB widening); N2-v3 bridge cap-arithmetic missing attenuation/rate-limit/pinning details; N3-v3 StreamingTask credit exhaustion deadlock window; N4-v3 wrapper-bypass UX trap; N5-v3 IntegrityPolicy mid-task immutability not stated.

None are blockers. APPROVE at 100 remains reserved for post-implementation, exactly as I framed in v2.1. v3 closes the spec gap; the remaining 5 points wait for shipped code.
