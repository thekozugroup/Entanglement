# Critic A Review — Architecture v2.1 (Strata)

**Final grade: 86/100**
**Verdict: REVISE** (only APPROVE at 100)

This is a substantively better document than v1. Most of my critical issues received concrete, mechanical answers — not hand-waving — and the Tailscale patch is a genuinely smart trade (it gives away code the architect didn't want to own and replaces it with a tool the target audience already runs). I'm raising 22 points. I'm not raising 36, because (a) the byzantine fix has a non-deterministic-output gap the spec does not address, (b) the tailnet-multitenant fix has one operationally important edge case still open, (c) the trust-footprint claim has improved framing but the LOC budget alone does not yet *prove* a smaller trust surface, and (d) several Phase-2 deliverables now stack on top of "Tailscale daemon is reliable on the host" without any detection/degradation story for when it isn't. None of these are fatal; all are addressable in v2.2.

---

## Rubric scores

| # | Criterion | Weight | v1 | v2.1 | Justification |
|---|---|---|---|---|---|
| 1 | Plugin runtime (Component Model viability) | 20 | 11/20 | 15/20 | WASI 0.2 / Wasmtime story unchanged, but Phase 4 (WASI-GFX) is now explicitly fenced; agent-host honestly committed to tier-5 (§8.1). Component-Model async still a real risk (§13 #2). |
| 2 | Capability/permission model soundness | 15 | 12/15 | 13/15 | §4.3 replaces hand-rolled ladder with declarative `min_tier` + property test — clean. §4.6 closes headless powerbox. Tier-as-ceiling + caps-as-gates is coherent (walk-throughs below confirm). One residual: cross-plugin side-channels (§11 #13) is plumbed but not specified concretely. |
| 3 | Mesh / transport (now three modes) | 15 | 9/15 | 12/15 | Three first-class mixable transports answers the UDP-hostile case the right way. Strong points: §6.1.1 trust framing, §11 #16. Soft points: no "tailscaled went down" detection/degradation; per-pair reachability matrix when nodes participate in disjoint transports is asserted but not specified. |
| 4 | Distributed scheduler | 15 | 9/15 | 12/15 | §7.5 layered defense is the right shape. Replication+quorum+reputation is conventional and adequate. **Gap:** non-deterministic outputs (LLM inference — workload A!) cannot be hash-quorum-compared; spec doesn't say what `IntegrityPolicy` means for them. This is in the north-star workload — non-trivial. |
| 5 | Authorization (biscuit-auth) | 10 | 6/10 | 8/10 | §6.5 revocation-gossip with monotonic counters + §6.6 templates close the major gaps from v1. Residual partition-window risk acknowledged in §13 #8 honestly. |
| 6 | Threat model coverage | 10 | 5/10 | 8/10 | Now includes byzantine, key compromise, side-channels, registry compromise, recovery UX, tailnet-multitenant. Cleanly framed three-domain trust split (§11). Missing: malicious *Tailscale control plane* (Headscale operator is hostile) and missing supply-chain entry for the host `tailscale` binary itself. |
| 7 | Crate layout / kernel boundaries | 10 | 6/10 | 8/10 | Real reduction: §2 names three responsibilities; §10 splits broker/manifest/signing/oci/host/ipc into separate crates; §2.3 lays out L1+L2+L3 with a CI LOC budget. **Concern:** the budget is 25k LOC across L1+L2 — that's still a hardened-daemon-sized trust footprint, not a microkernel, and the marketing should match. |
| 8 | Build phases / MVP scope | 5 | 3/5 | 5/5 | §12 is the kind of phasing review I wanted: explicit cuts, "1.0 = end of Phase 1," named timelines, transport-phasing table, and an explicit Phase-3 reservation for `tsnet`-embedded. Honest. |
| | **Total** | **100** | **64/100** | **86/100** | +22 |

---

## Status of v1 critical issues

### #1 Byzantine workers — **PARTIAL**
**v2 evidence:** §7.5 — "`IntegrityPolicy { replication: 3, quorum: 2 }` runs the task on three workers; results compared by hash; majority wins; disagreement → all results discarded, task re-scheduled with disagreers downranked." Plus §11 #11 and the trust-domain split in §11.

**Score on the fix:** good for deterministic Wasm. Layer 1+2+3 is the textbook answer and I asked for exactly this. Reputation EWMA with three thresholds (0.95/0.90/0.80) is concrete, not aspirational.

**Why PARTIAL not FIXED:** Workload A (the *north-star* in §7.0) is **LLM inference**. LLM inference is non-deterministic by default (sampling), and even greedy decoding diverges across hardware (different GPU kernels, different math precision). Hash-comparison quorum **does not work** on non-deterministic outputs. The spec does not say:
- whether `IntegrityPolicy` is rejected at submit-time for non-deterministic workloads (`pure: false`),
- whether there's a semantic-similarity quorum for LLM outputs (cosine over embeddings? a separate plugin?),
- whether non-deterministic compute is simply *out of scope* for replication and the user must manually allowlist correctness-trusted peers.

This is the Workload A acceptance criterion (§7.0 line 1). Either say "no replication for non-deterministic workloads; correctness rests on `compute.peers` allowlist" out loud, or design the semantic quorum. Hand-waving here fails the same pattern as v1 §3.1's agent-host punt.

### #2 Single-Iroh transport — **FIXED**
**v2 evidence:** §6.1 — three first-class mixable modes (`mesh.local`, `mesh.iroh`, `mesh.tailscale`); §6.1.1 details Tailscale specifics; §12 ships all three in Phase 2; §0.2 Tailscale-availability matrix. The "honestly unsupported" disclosure ("Networks blocking UDP outbound AND not running Tailscale AND with no LAN peers: not supported") is exactly the kind of marketing honesty I asked for.

**Score on the fix:** strong. The decision to *not* embed `tsnet` in MVP (§6.1.1) and shell out to `tailscale status --json` is operationally correct — it avoids Go-runtime-in-Rust-binary, avoids dual identity, keeps trust footprint small. v2.1 traded code-the-team-would-own-forever for a dependency that already exists on the target machines.

**Concern (does not unfix):** "What if `tailscaled` stops running mid-session?" is not specified. The detection is opt-in at boot; there's no "tailscale daemon health check" loop, no degradation path, no UX for "your tailnet went away, here's what's still reachable." Not a critical gap, but a Phase-2 must-design.

### #3 Agent-host JS runtime decision — **FIXED**
**v2 evidence:** §8.1 — "Claude Code, Codex, OpenCode, Aider, Cline, and Continue run as tier-5 subprocess plugins. Bundling a Node.js runtime as a Wasm-embedded JS engine is rejected." §8.3 specifies MCP gateway interposition with FD injection at spawn; §8.5 owns the residual risk ("a Node 0day + a Landlock bypass is fatal. Documented honestly.").

**Score on the fix:** this is the right answer and I asked for exactly this commitment. The install prompt in §8.1 ("Tier: 5 (Native subprocess) … Why this is tier-5 …") is the kind of honest UX that doesn't oversell.

**Sub-concern:** "subprocess agent host on Windows" — §0.2 says WSL2 only until Phase 5. For the Node-based agent threat model (an agent that escapes Node into the host) WSL2 is **adequate**: WSL2 is a separate kernel/VM, the agent escaping Node doesn't get out of WSL2 short of a hypervisor escape. So yes, WSL2 is sufficient for MVP — the sandboxing claim holds, the limitation is just "it's not a native Windows experience." Marketing is honest.

### #4 Kernel god-object — **PARTIAL**
**v2 evidence:** §2 lists three responsibilities for `strata-core`. §10 splits to 13 workspace crates. §2.3 layered diagram with L1+L2+L3+L4. §10 trust-footprint CI check: "<25k LOC excluding tests."

**Score on the fix:** real progress. The crate split is genuine, not a rename. Renaming "kernel" to "core runtime" (Critic B M3) lowers the marketing claim to match.

**Why PARTIAL not FIXED:** the *trust footprint* is L1+L2 — `strata-core` + `strata-broker` + `strata-manifest` + `strata-signing` + `strata-oci` + `strata-https-fetch` + `strata-host` + `strata-ipc`. That is **eight crates** all running unsandboxed in `stratad`. The 25k-LOC budget is generous (Wasmtime-the-engine alone is ~hundreds of kLOC of transitive deps; the budget excludes deps). The "core is small" claim is now structurally honest because it's three things, but the **trust surface a security review will use** is still the entire trusted layer including dependencies. Recommend: state the trust footprint **with transitive deps** (Wasmtime, biscuit-auth, oci crates, ed25519) somewhere in the spec — that's the real attack surface.

### #5 Mesh-as-plugin chicken-and-egg — **FIXED**
**v2 evidence:** §2.3 L3 — "Built-in plugins (shipped in binary, swappable)." §10 — `mesh-local`, `mesh-iroh`, `mesh-tailscale` ship in `plugins/` but are baked into the binary at first boot. `strata plugin replace` is the swap path.

**Score on the fix:** this is the bootstrap framing I asked for — explicit "shipped-in-binary vs fetched-from-registry." The `mesh.tailscale` plugin's special status (shells out to host binary; does not increase trust LOC) is documented in §10. Done.

---

## Status of v1 significant issues

### #6 Biscuit revocation — **FIXED**
§6.5 — "signed revocation gossip on membership channel with monotonic counters; receiving peers add the revocation to their local set; a compromised publisher key leaks into a kill-list within seconds." §11 #12. §13 #8 owns the partition-window race honestly.

### #7 Tier function policy ladder — **FIXED**
§4.3 — `fn implied_tier(caps: &CapSet) -> u8 { caps.iter().map(|c| c.min_tier).max().unwrap_or(1) }`, with property test, with `min_tier` constants in WIT package metadata. This is exactly the declarative replacement I asked for.

### #8 Subprocess sandbox parity — **FIXED**
§3.5 honest table per OS; §0.2 defers Windows native to Phase 5; install prompt shows the actual sandbox primitive. Marketing matches reality.

### #9 SWIM under Wi-Fi — **FIXED**
§6.4 commits to chitchat-on-iroh-gossip with `home`/`lan-stable` profiles. (Phase-2 prototype risk noted in §13 #5 — acceptable.)

### #10 MCP gateway SPOF — **FIXED**
§8.3 — "We shard one gateway per active agent session." Explicit.

### #11 OCI distribution — **FIXED**
§3.6 — two paths (OCI **and** signed HTTPS tarball) against the same Ed25519 trust root; `strata pack` for sneakernet/airgap. Closes the registry-compromise threat (§11 #14) by making registry orthogonal to trust.

### #12 Single-binary panic — **PARTIAL**
§2.1 commits to `catch_unwind` + supervisor restart with state-on-disk continuity. Tradeoff documented (§13 #6). I would have preferred a daughter-process model for `strata-host` (Wasmtime panics are not zero), but the architect made the case for operational simplicity and owns the risk. Acceptable.

---

## Tier + capability coherence — three-plugin walk-through

The architect claims tier-as-ceiling + capability-as-gate is coherent. Walk-through:

**Plugin A — `math-kernel` (tier 1):** declares `tier = 1`, no capabilities beyond local data. `implied_tier(∅) = 1`. Install: auto-load. Runtime: every host call has nothing to gate; tier flag is "1 ≤ user's global cap N." Coherent. No double-counting.

**Plugin B — `scheduler` (tier 3):** declares `tier = 3`, capabilities `{compute.cpu, mesh.peer, storage.local}`. Suppose `min_tier` of `mesh.peer` is 3. `implied_tier = 3`. Install: powerbox prompts for each cap with rationale. Runtime: capability handle gates each call; tier flag enforces "user hasn't disabled tier ≥ 3 globally." If user revokes powerbox grant for `mesh.peer`, plugin loses the handle (capability gate); tier doesn't change. Coherent.

**Plugin C — `agent-host-claude-code` (tier 5):** declares `tier = 5`, subprocess runtime, capabilities `{net.wan(api.anthropic.com), storage.local, agent.invoke}`. `min_tier` of `agent.invoke` and `net.wan` wildcard is 5. `implied_tier = 5`. Install: hard prompt + per-session re-confirm. Runtime: MCP gateway intercepts every tool call; capability handles still gate; OS sandbox enforces `net.wan` allowlist at syscall level. Three layers of enforcement, no ambient leak. Coherent.

**No double-counting** because tiers don't replace caps — they're an additional gate at install (tier ≤ user's global limit) and at runtime (kernel can suspend tier-N plugins globally). **No ambient authority** because plugins still get nothing without explicit capability handles.

The "tier as first-class" addition does not re-introduce the v1 ambient-policy concern. Critic B's request and my soundness invariant are *both* honored. Good design.

---

## NEW issues introduced by v2/v2.1

### N1 (Critical) — Non-deterministic compute and the byzantine policy
**§7.0 Workload A** is LLM inference. **§7.5 Layer 1** quorum compares by **hash**. LLM inference output is not hash-comparable across peers (sampling, kernel-precision variance, batch effects). The spec does not say:
- Is `IntegrityPolicy { replication: 3, quorum: 2 }` rejected at submit-time when the work unit has `pure: false`?
- Is there a separate `IntegrityPolicy::SemanticQuorum { threshold: 0.97 }` plumbed for non-deterministic workloads?
- Does the user fall back entirely to `compute.peers` allowlist trust (correctness-trust narrow) for non-deterministic compute?

This is a one-paragraph fix in §7.5 ("for non-deterministic workloads, replication is not available; correctness trust must come from the `compute.peers` allowlist; the scheduler refuses `replication > 1` on `pure: false` tasks"). But it's missing and this is the *north-star* workload. **Blocker.**

### N2 (Significant) — Tailscale daemon health
§6.1.1 says "shells out to `tailscale status --json`." There is no recurring health check. If `tailscaled` exits/crashes/loses auth mid-session, what happens?
- Strata's `mesh.tailscale` peers go silent — Strata sees connection failures but doesn't know the cause.
- Does the broker reroute to alternate transports if a peer is also reachable via `mesh.iroh`?
- Does the operator see "tailnet down" diagnostic in `strata diag mesh`?
- What's the user-facing message?

§9.6 mentions `strata diag mesh` for reachability triage but the integration with Tailscale daemon liveness is not specified. **Phase-2 design must-have**, not a blocker for v2.1 grade but I want it on the record.

### N3 (Significant) — Disjoint-transport reachability matrix
§6.1 says "modes are not mutually exclusive within a deployment (some nodes can be `mesh.iroh`-only, others `mesh.tailscale`-only, others both; the broker computes per-pair reachability from the union)." The negotiation rule is sketched ("`mesh.local` → `mesh.tailscale` → `mesh.iroh`"). What's not specified:
- A node `mesh.iroh`-only and a node `mesh.tailscale`-only have **zero shared transport**. The broker correctly returns "not reachable." But is there a per-peer hint to the user ("this peer is reachable only over Tailscale; install Tailscale to talk to them")?
- What does `chitchat` do when only a subset of nodes can hear each other? Does the gossip topology bridge across transports if some nodes participate in two? (It should, but the spec doesn't confirm.)
- Capability tokens (biscuits) are transport-agnostic — confirmed implicitly. Worth saying explicitly.

This is gossip-protocol design; not blocking, but Phase 2 must specify.

### N4 (Significant) — Tailnet ACL "strata-on-top" default — install wizard force
§6.1.1 sets default `acl-mode = "strata-on-top"` and §11 #16 says "the daemon refuses to start in tailscale-mode without an allowlist." Good. But §9.2 init wizard step 4 ("Detects whether `tailscale status --json` succeeds. If yes: offers `mesh.tailscale` …") does not require populating the allowlist before the daemon starts. So a user who runs `strata init --transport tailscale`, accepts defaults, has an empty `[trust] strata.peers` — does the daemon refuse to start (§11 #16) or does it start with zero peers and prompt later? Resolve. If the former, §9.2 needs to walk the user through populating the allowlist (typically: one entry, the local node itself). If the latter, the §11 #16 claim is overstated.

### N5 (Minor) — Headscale / hostile control plane
§6.1.1 says "Headscale (self-hosted Tailscale control plane) works by virtue of being protocol-compatible." Threat model (§11) does not enumerate "compromised Headscale operator can rewrite MagicDNS to point peers at attacker nodes." Mitigation already exists (Strata layers its own TOFU on top — §6.1.1), but say so explicitly in §11 alongside #16. One-line addition.

### N6 (Minor) — Host `tailscale` binary supply chain
The host `tailscale` binary is now in Strata's trust path (we shell out to it; we trust its `--json` output for peer enumeration; we trust its WireGuard transport for confidentiality). §11 doesn't have an entry for "compromised host `tailscale` binary." Realistic mitigations: pin a min version (`tailscale version >= 1.x`), document expected provenance, recommend Tailscale's own auto-update. Add a row.

### N7 (Minor) — Trust footprint includes transitive deps
§10's "<25k LOC excluding tests" budget for L1+L2 first-party crates is a useful guard, but Wasmtime, tokio, biscuit-auth, ed25519-dalek, oci-spec are all in the trust footprint at runtime. The number a security review uses includes those. State the *real* number with a note that "we minimize first-party trust LOC; the transitive trust footprint is dominated by Wasmtime and is reviewed against Wasmtime's own security disclosures." Honest framing closes the criticism for good.

### N8 (Minor) — `strata pair` over Tailscale rendezvous
§6.3 step 1 says pairing uses "LAN mDNS first; pkarr or MagicDNS-tailnet lookup if the two devices are on different networks but share `mesh.iroh` or `mesh.tailscale`." MagicDNS-tailnet lookup for pairing rendezvous works only if both devices are on the same tailnet *before* pairing — meaning they trust each other at the tailnet level already. That's fine, but also means the 6-digit code becomes a discriminator, not a security primitive. State it: "On a shared tailnet, pairing leans on tailnet membership for rendezvous; the 6-digit code is for disambiguation, not authentication. Mutual fingerprint TOFU is still the security primitive."

---

## What's improved (briefly)

- §4.3 declarative `min_tier` + property test is genuinely the right way.
- §6.1.1 trust framing ("on my tailnet ≠ trusted Strata peer") is exactly the right granularity.
- §7.5 layered byzantine defense + the §11 trust-domain split (connectivity / correctness / code) is conceptually clean.
- §3.6 two-path distribution (OCI + tarball, same key) is a real win for hobbyist publishing without compromising security.
- §8.3 per-session MCP gateway sharding closes the SPOF cleanly.
- §12 phasing is the kind of honest scope statement that v1 was missing — "1.0 = Phase 1" is a strong promise.
- §0.1 rename to **Strata** is correct on SEO and on conceptual fit.
- §14 traceability table is genuinely useful for a re-review — every objection points at a fix.

---

## Verdict reasoning

**86/100. REVISE (not APPROVE).**

I'd ship a beta on this design. I would not yet bet my reputation on production at scale.

The one critical gap is N1 — non-deterministic compute (LLM inference, the *north-star* workload) does not have a defined `IntegrityPolicy`. Hash-quorum doesn't work for sampled outputs. Either say "non-deterministic ⇒ no replication, correctness rests on allowlist" out loud, or design semantic quorum. This is Workload A; it can't be missing.

Significant gaps are operational: Tailscale daemon liveness (N2), disjoint-transport reachability bridging (N3), and the install-wizard allowlist enforcement gap (N4). All Phase-2 design — none stop a v2.2 sign-off.

Minor gaps (N5–N8) are documentation hygiene: enumerate the new dependencies in the threat model, state the real trust footprint including transitive deps, and clarify that pairing over a tailnet still rests on TOFU.

If the architect addresses N1 substantively and N2–N4 mechanically, v2.2 lands at 92–95. APPROVE remains reserved for a design that has survived implementation contact (Phase 1 ship + the first byzantine-resilient compute job actually running across the mesh). That's correct: 100 should mean "it shipped and didn't blow up," not "the document is unusually thorough."

— *Critic A*

---

## 200-word summary

**Grade: 86/100. Verdict: REVISE.**

v2.1 is a substantive improvement over v1's 64. Of my four critical issues, three are FIXED: single-Iroh transport (now three mixable modes including Tailscale), agent-host JS runtime (committed to tier-5 subprocess + per-session MCP gateway), and mesh chicken-and-egg (built-in plugins shipped in binary, swappable). Byzantine workers is PARTIAL — replication+quorum+reputation is the right shape, but the policy is hash-comparison-based and Workload A (LLM inference, the north-star) is non-deterministic. This needs explicit handling. Kernel god-object is PARTIAL — the crate split is real and the rename to "core runtime" is honest, but the trust footprint with transitive deps (Wasmtime, biscuit, oci) should be stated. All five significant v1 issues are FIXED.

**New blockers:** N1 — non-deterministic compute integrity policy is undefined; this is the marketed flagship workload. Significant: N2 Tailscale daemon liveness/degradation, N3 disjoint-transport reachability spec, N4 init-wizard allowlist enforcement contradicts the §11 #16 "daemon refuses to start" claim.

Tier + capability coherence walk-through (three plugins) checks out — no double-counting, no ambient authority. Address N1 substantively and v2.2 reaches 92+. APPROVE is reserved for post-implementation.
