# Critic A Review — Architecture v1

**Final grade: 64/100**
**Verdict: REVISE**

This is a competent v1 by someone who has clearly read the prior art. It is not 100, and it would be malpractice to pretend it is. Multiple load-bearing decisions rest on stacks that are not production-stable in 2026-04, the agent-host story is dodging an unforced decision, the kernel scope claim contradicts the surface area, and several "open questions" the spec lists are actually MVP blockers, not future polish.

---

## Rubric scores

| # | Criterion | Weight | Score | Justification |
|---|---|---|---|---|
| 1 | Plugin runtime (Component Model viability) | 20 | 11/20 | WASI 0.2 + Wasmtime is real for CPU tasks. WASI-GFX is draft; agent-host streaming async is known-rough by the spec's own admission. Wagering the GPU and agent stories on phase-2 standards is "draw the rest of the owl" for Phase 4. |
| 2 | Capability/permission model soundness | 15 | 12/15 | Capabilities-as-primitive is genuinely capability-secure on the wasm side. But §4.3's hand-rolled `if/else` ladder reintroduces ambient policy decisions in Rust, and §4.4 powerbox is under-specified for headless/CI mode (no rationale-less consent path defined). |
| 3 | Mesh / transport (single-Iroh bet) | 15 | 9/15 | Iroh is a defensible primary. "Single transport" is the bet that loses on locked-down corporate / hotel / mobile-carrier networks where DERP TCP-443 is also unreachable, and the spec offers no fallback at all. No graceful-degradation story for partition or DERP outage. |
| 4 | Distributed scheduler | 15 | 9/15 | Greedy multi-criteria placement is fine. **Byzantine handling is essentially absent** — workers verify *the work unit's signature*, not the *result's correctness*. A lying worker returns `exit_code=0` with garbage. No replication, no quorum, no result attestation. §13 doesn't even list it. |
| 5 | Authorization (biscuit-auth) | 10 | 6/10 | Short-TTL biscuits + nonce tracking is reasonable for replay. Datalog debuggability is acknowledged as a smell but unmitigated. **Revocation is undefined** beyond expiry — what happens at 03:00 when a key is compromised and you have valid 60-second tokens floating? No CRL, no kill-list gossip. |
| 6 | Threat model coverage | 10 | 5/10 | Top-10 table covers the obvious. Missing: DoS via plugin resource exhaustion of the broker; cross-plugin side channels through shared resources (CPU pool, blobs cache); registry compromise (no separation between trust roots and OCI hosts); compromise-recovery UX for the per-user keyring. Side channels are waved off as out-of-scope, which is fine for HW Spectre but not for plugin-to-plugin. |
| 7 | Crate layout / kernel boundaries | 10 | 6/10 | Claim: kernel owns 5 things. Reality: §10 lists `kernel`, `host`, `broker`, `manifest`, `signing`, `oci`, `ipc`, `wit`, `sdk`, plus 13 capability surfaces in `centrifuge-wit`. Either the kernel includes `host`+`broker`+`oci`+`signing`+`ipc` (then it's not 5 things), or those are "outside the kernel" (then how do they bootstrap before the broker exists?). The dependency graph in §10 has `centrifuge-kernel` depending on all of them — it's a god lib in a trench coat. |
| 8 | Build phases / MVP scope | 5 | 3/5 | Phases 0–3 in 1.0 is plausible-aggressive if "Phase 1" assumes mature wit-bindgen async. The spec admits this is a bet (§13 #2). Phase 4 has explicit fallback (good). Phase 2 collapses signing infra + mesh + biscuit + chitchat into one milestone — that's two milestones disguised as one. |
| | **Total** | **100** | **64/100** | |

---

## Critical issues (must fix to advance)

### 1. Byzantine workers can poison results and the spec does not defend against it
- **Attack:** A peer holds a valid `mesh.peer` biscuit, accepts a job, returns `exit_code: 0, stdout: <attacker-chosen>`. Submitter has no way to detect. In a federated mesh of "household devices and friends," the trust boundary for *correctness* is wider than the trust boundary for *connectivity*. This is the difference between "Aunt Carol's laptop is on my mesh" and "Aunt Carol's laptop should compute my bank-statement parser."
- **Spec evidence:** §7.4 specifies *publisher-signature verification on the Wasm* and *biscuit verification for authorization*. Neither addresses result integrity. §11 threat model omits result poisoning entirely. §13 lists 10 weak points, none of them this one.
- **Required mitigation:** (a) Per-job replication policy (`replicate: n, quorum: m` in `ResourceSpec`), with disagreement → discard + downrank; (b) optional deterministic-replay attestation for pure-compute jobs (re-run on submitter or a third peer if cheap); (c) per-peer correctness reputation, not just liveness; (d) explicit doc that "trust your scheduler peers" is a hard prerequisite if (a)–(c) are off.

### 2. Single-Iroh-everywhere has no fallback for UDP-hostile networks
- **Attack:** Corporate firewall blocks UDP outbound (common); blocks DERP TCP-443 by SNI rule (Cloudflare's WARP gets this treatment routinely); mobile carrier triple-NAT defeats hole-punching. Two Centrifuge nodes on the same office Wi-Fi cannot connect. The "household" story holds; the "team-of-engineers-at-Acme-Corp" story does not.
- **Spec evidence:** §6.1 lists DERP TCP relay as the fallback and stops there. Rejection list dismisses Tailscale, libp2p, raw QUIC. No HTTPS-only or WebSocket-tunnel transport. The "even the mesh is a plugin" framing exists (§6) but no second transport plugin is specified, scoped, or tested.
- **Required mitigation:** (a) Specify a second transport — `mesh-https` over WebSocket-to-rendezvous — as a *required Phase 2 deliverable*, not future-work; (b) define how nodes negotiate transport when Iroh fails (gossip only via DERP? what if DERP is also blocked?); (c) document the exact firewall configurations Centrifuge does *not* support, so the marketing story is honest.

### 3. Agent-host plugin punts on the JS runtime decision
- **Attack:** Claude Code is a Node.js application. The spec wants every agent inside a kernel-managed sandbox (per research-04 §4) and inside the Wasm Component Model (per §3.1). Pick a poison: (a) ship a Node-on-wasm runtime — currently impractical; (b) ship Node *bundled* — bloats the "single static binary" claim and creates a JS-runtime supply-chain surface inside the kernel; (c) run Claude Code as a tier-5 subprocess — abandons the capability model exactly where it matters most (the agent has the broadest tool surface). The spec lists Claude Code as a target plugin (§8) without committing to which.
- **Spec evidence:** §8 says "agents ship as separate plugins sharing a common WIT contract." It does not say in what runtime Claude Code's actual JS executes. §3.5 (subprocess escape hatch) is the only candidate, but tier-5 contradicts §11 #10 ("agent exfiltrates via tool calls") which assumes kernel-injected `before_tool` hooks — those work only if tool invocations transit the WIT boundary, not if the agent is a black-box subprocess.
- **Required mitigation:** Force the decision in §8.x: either (a) "Claude Code runs as a tier-5 subprocess plugin and `before_tool` is enforced via MCP-gateway interposition, not in-process hooks" — which then needs the MCP gateway hardened against agent bypass; or (b) "Centrifuge does not support Claude Code at MVP, only WIT-native agents" — then drop it from §8's list. Hand-waving is unacceptable for a Top-10 threat-model entry.

### 4. The kernel is a god-object; the "5 things" claim is marketing
- **Attack:** §1 says the kernel owns five things. §5 lists 13 capability surfaces all implemented in `centrifuge-host`, which `centrifuge-kernel` depends on directly. Add `centrifuge-broker`, `centrifuge-signing`, `centrifuge-oci`, `centrifuge-ipc`, `centrifuge-manifest` — also direct deps of the kernel crate. By the trust-domain definition (anything compiled into the trusted single binary that runs unsandboxed), the kernel is everything in `centrifuge-bin`. That's the actual trust footprint a security review will use, and it's huge.
- **Spec evidence:** §1 vs §5 contradiction quoted above. §10 dependency table makes `centrifuge-kernel` a fan-out hub. §6 claims "even the mesh is a plugin" but Phase 0–2 builds it inside the kernel binary; the plugin-ification is aspirational.
- **Required mitigation:** Either (a) make the boundary real — `centrifuge-host`, `centrifuge-oci`, `centrifuge-signing` are workspace crates the *binary* assembles, with the *kernel* exposing only the supervisor/broker traits, and have a CI check on the trust footprint LOC; or (b) drop the "tiny kernel" framing and call it what it is (a hardened daemon with a plugin host inside).

### 5. Mesh-as-plugin chicken-and-egg unresolved
- **Attack:** §6 says the mesh is a plugin. To install a plugin from OCI (§3.4), you need network. To get network from the mesh plugin, you need the mesh plugin. Sandstorm-style "ship one initial bundle" works if `mesh-iroh` is included in the binary — but then it isn't really a plugin, it's a built-in pretending to be a plugin to satisfy a slogan. Centrifuge will need a different bootstrap story for "first time on this device."
- **Spec evidence:** §6 opens with "This entire section describes the `mesh-iroh` plugin, not the kernel." §12 Phase-2 lists `mesh-iroh` as a deliverable but not as a "shipped-in-binary vs fetched-from-registry" decision.
- **Required mitigation:** Document the bootstrap explicitly: which plugins are baked into the binary (likely: `mesh-iroh`, `storage-local`, `system-clock`), what their upgrade path is independent of the kernel, and how a user disables a baked-in plugin without rebuilding. Otherwise §6's framing is dishonest.

---

## Significant issues (should fix)

### 6. Biscuit revocation under key compromise is undefined
- 60-second TTL is replay-resistance, not revocation. If a publisher key leaks at 03:00:00, valid biscuits live until 03:01:00 and *new* ones can be minted indefinitely until you push a key-revocation update. There is no specified mechanism (CRL? gossip kill-list? trust-store push?) for telling the mesh "publisher P is compromised, reject everything signed by them after T." This is a non-trivial design in a serverless mesh.

### 7. Tier function (§4.3) is a hand-rolled policy ladder in trusted code
- The spec acknowledges this is a smell. It is more than a smell: it is policy code in the kernel with no formal property, no tests cited, no monotonicity proof. New capabilities will land in PRs that update the `if/else` block and ship without anyone noticing the tier dropped. Either prove monotonicity in the type system (capabilities have an associated `min_tier: u8` constant; tier = max over the set) or generate the function from a declarative table reviewed by security.

### 8. Subprocess sandbox parity is overstated
- §3.5 says seccomp on Linux, sandbox-exec on macOS, AppContainer on Windows. These are not equivalent. `sandbox-exec` is private API Apple has been deprecating for years; AppContainer is hostile to non-store apps. "Profile derived from declared capabilities" is the entire problem — encoding a single capability set into three different constraint dialects without exploitable gaps is research-grade work and the spec gives it one paragraph.

### 9. SWIM on consumer Wi-Fi is a known bad time and the spec admits it
- §13 #4 acknowledges this and proposes "chitchat-on-top-of-iroh-gossip instead of plain SWIM" as a maybe. For an MVP that ships Phase 2, "maybe" is not a plan. Either (a) tune SWIM and document the flap rate you accept, or (b) commit to chitchat and update §6.

### 10. MCP gateway is a single point of failure for all agent tool calls
- §13 #7 admits this. With Claude Code as a marquee target plugin, an MCP-gateway crash takes down every agent. No isolation, no failover, no per-agent gateway.

### 11. OCI distribution + offline + pull-through-cache is not specified
- §3.4 says "OCI artifacts." It does not say which registry, whether Centrifuge runs one, whether `ghcr.io` is acceptable for plugin distribution (legal? rate-limited?), or how an offline / air-gapped node updates plugins. "Per-user keyring" is a trust *model*; it is not a distribution *plan*.

### 12. Single-binary panic is total-availability loss
- Wasm sandbox catches plugin faults, but a panic in `centrifuge-broker` or `centrifuge-host` (a Wasmtime engine bug, an `unwrap()` in the OCI fetch path) takes the entire daemon down. No supervisor process, no fault isolation between subsystems. The "single static binary" story trades operational simplicity for a thinner blast radius than typical microkernel designs imply.

---

## Minor issues

- §6.1 cites `iroh ≥0.34` — Iroh's 1.0 stability story is still maturing; pin a known version with a tested API.
- §7.3 placement scoring uses unbounded `score` with subtracted cost — possible negative score; spec doesn't define tie-break.
- §4.4 powerbox prompts assume an interactive UI; no headless / `centrifuged` daemon mode is specified for first-boot consent.
- "Continuous perf measurement (`perf.iroh.computer`)" reuses Iroh's *infrastructure* benchmark domain as a justification — that's marketing latency, not your-mesh latency.
- `wit-bindgen` async ergonomics being "rough" affects every plugin SDK; spec admits this in §13 #2 but Phase 1 SDK milestones don't budget for the workarounds.

---

## Things the spec does well (briefly)

- Correct primitive: capability handles, no ambient authority. The §4.1–4.2 separation is genuinely capability-secure on the wasm boundary.
- Honest §13 "Open Questions" section. Most v1 specs hide their dirty laundry; this one airs it. (Though: several items in §13 are MVP blockers, not future polish — see Critical Issues.)
- Component-Model + WASI-NN choice is the right swing for Centrifuge's scope; the alternatives surveyed in research-02 are correctly rejected.
- ALPN multiplexing on a single Iroh connection (§6.6) is clean and avoids the "five sockets per peer" mess.
- Tier-as-computed-UX is the *right idea*, even if the implementation in §4.3 is sloppy — the kernel-doesn't-match-on-tier rule is the correct invariant.
- OCI + cosign + minisign for signing is conventional and unambitious; that's a compliment for an MVP.
- Threat-model #10 (`before_tool` hooks for agent exfil) shows the architect is thinking about the right adversary, even if the implementation depends on resolving Critical Issue #3.

---

## Verdict reasoning

**64/100. REVISE.** The spec is the work of someone who has done their reading and is making real decisions, not waving hands — but it has four hard contradictions (kernel scope, mesh bootstrap, agent runtime, byzantine workers) that block MVP acceptance, and a "single transport, single binary, single MCP gateway, single keyring" pattern of single-points-of-failure that needs an explicit answer to "what happens when this fails?" before any code lands.

I would not bet my reputation on this design as written. I *would* bet on the v2 if Critical Issues 1–5 are addressed materially (not "we'll figure it out") and Significant Issues 6–8 get concrete proposals. Aim for 80+ on v2; 100 is reserved for designs that have survived implementation contact.

— *Critic A*
