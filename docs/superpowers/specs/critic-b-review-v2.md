# Critic B Review — Architecture v2.1 (Strata)

**Final grade: 86/100**
**Verdict: REVISE** (APPROVE requires 100; this is a strong v2 that earns most of the grade-cap fixes but introduces one new significant issue and leaves three from v1 partial.)

This is what a v2 should look like. The author read both reviews and walked the spec from kernel-poetry into product-shape: a real install matrix, a real pairing flow, a real hello-world, a real operator chapter, a real threat model, a renamed product, a re-scoped MVP that admits the original "<6 months" was wishful thinking, and — credit where due — a clean Tailscale-as-transport patch in v2.1 that **deletes** the `mesh-https` plugin rather than carrying both. Subtraction is harder than addition; the architect did the right thing.

What it isn't yet: 100. The hello-world walkthrough still has gaps a real user will trip on; the rename is *defensible* but not slam-dunk; the agent-host UX is committed but the per-session-MCP-gateway promise is hand-wavier than the rest of v2; and the new Tailscale path quietly assumes the user already has a tailnet paired on the device with no error-UX ladder for "tailscale not logged in." Two of these are blockers for a real 100. None of them is grade-capping the way v1's missing install story was.

---

## Rubric scores

| # | Area | Weight | v1 | v2 | Weighted | Δ |
|---|---|---|---|---|---|---|
| 1 | Install + first-run UX | 20 | 5/20 | 17/20 | 17 | +12 |
| 2 | Plugin author DX | 15 | 9/15 | 12/15 | 12 | +3 |
| 3 | Operator DX | 15 | 7/15 | 13/15 | 13 | +6 |
| 4 | Permission/grant UX (powerbox) | 10 | 7/10 | 9/10 | 9 | +2 |
| 5 | Mesh onboarding | 10 | 3/10 | 8/10 | 8 | +5 |
| 6 | Project scope realism (<6 mo, small team) | 10 | 3/10 | 8/10 | 8 | +5 |
| 7 | Differentiation | 10 | 6/10 | 8/10 | 8 | +2 |
| 8 | Naming / mental model | 5 | 3/5 | 4/5 | 4 | +1 |
| 9 | Spec/document clarity | 5 | 4/5 | 7/5* | 7 | +3 |
| **Total** | | **100** | **47** | | **86** | **+39** |

*Clarity gets a +2 over the cap because v2's §14 changelog mapping every objection to a section is the kind of artifact senior eng orgs ask for and rarely get. I'm not above paying for it.

The 11-point grace bump I gave v1 for §13 honesty is not stacked here — v2 *earned* its grade, so the grace is unnecessary. v2 raw = 86; v1 raw was 47 + 11 grace = 58.

---

## Prior-issues status

### Critical issues from v1

#### C1 — No install story → **FIXED**
§9.1 ships `brew`, `curl|sh`, `apt`/`dnf`/`pacman`, `winget`, `docker run`, AND a Tailscale quickstart. §9.2 walks the wizard. §0.2 has a per-OS table with sandbox primitive per OS. Quote: *"`curl -fsSL https://get.strata.dev | sh` # script: downloads signed binary + SHA256SUMS.sig, verifies, installs to /usr/local/bin/strata, creates strata user, installs systemd unit."* Concrete enough that a new user can act. **17/20**, withholding 3 points because (a) the brew tap `thekozugroup/strata/strata` requires a third-party tap which is friction (not just `brew install strata`), and (b) the Linux script trusts `get.strata.dev` over TLS but the spec doesn't show how the user verifies the *script itself* before piping to sh — bootstrap-of-trust gap. Minor.

#### C2 — Mesh onboarding undocumented → **FIXED**
§6.3 has the full `strata pair 734-291` flow with 6-digit code + fingerprint + mutual TOFU + three named failure modes (code expired, fingerprint mismatch, no reachability) + recovery via `strata diag pair`. §6.5 covers identity rotation, key compromise revocation gossip, backup/restore. Quote: *"User confirms on both sides (mutual TOFU). Either side can reject."* Real product behavior. **8/10**, withholding 2 because: (a) "*Fingerprint mismatch: hard error with a link to 'what this means' docs*" — the docs aren't sketched in the spec, and *this* is the high-stakes UX moment (literal MITM possibility) and it deserves a worked-through page in the spec body; (b) no recovery flow when one device is online and the other is offline at pair-time — does the code expire? Can it be re-issued? Spec is silent.

#### C3 — MVP scope unrealistic → **FIXED (and refreshingly honest)**
§12 says 1.0 = end of Phase 1 = 4–6 months for a 3-person team and explicitly cuts mesh, scheduler, agent host, GPU/NPU, and native Windows from 1.0. Quote: *"Shippable '1.0': end of Phase 1 (4–6 months). It is small but real... Mesh, scheduler, agent host are genuine 1.x releases. This is honest. If we ship faster, great; we don't promise it."* This is the right answer. **8/10**, withholding 2 because: even Phase 1 alone is plausibly tight for 3 people. Phase 1 still wants signing (Ed25519 + cosign + minisign + biscuit-auth integration), OCI fetch, tarball fetch, install wizard, hello-world walkthrough, full operator DX (logs/metrics/tracing/upgrade/backup), powerbox with headless queueing, AND production-grade Wasmtime embedding. That's 18–22 weeks of work for a small team if everything goes right; calling it "4–6 months" leaves no slack for Wasmtime async maturity slippage (§13 #2 still flags this). I'd write 6–9 months for Phase 1 alone. Not grade-capping, but it's still an optimism tax.

#### C4 — Agent-host elephant → **FIXED in commitment, PARTIAL in mechanism**
§8 commits explicitly: *"Claude Code, Codex, OpenCode, Aider, Cline, and Continue run as tier-5 subprocess plugins. Bundling a Node.js runtime as a Wasm-embedded JS engine is rejected."* Excellent. The §8.1 install prompt UI is good — owns the "TIER 5" reality. §8.3 commits to MCP gateway interception with per-session sharding.

What's still hand-wavy is **how** §8.3 actually works: *"the subprocess is configured to talk to a per-session Strata-hosted MCP gateway socket (file descriptor injected at spawn). Every MCP tool call from the agent goes through the gateway."* For Claude Code specifically, Claude Code's MCP servers are configured by the *user* via `~/.claude/settings.json` and similar — Strata can't just fd-inject a single MCP socket and expect Claude Code to route all tool calls through it. Claude Code launches its own MCP server subprocesses via stdio. To intercept *every* tool call, Strata would need to either (a) be in the MCP server-launch path (rewrite Claude Code's settings so all MCP servers are Strata-proxied), or (b) intercept stdio between Claude Code and each MCP server it launches, which is a man-in-the-middle on every agent tool plugin. Neither is impossible but neither is "fd injected at spawn." The spec elides the choice. **§13 #7 honestly admits this is "subtle when the agent reconnects"** — but the subtlety is bigger than that. Marked PARTIAL; cost: 1 point off Operator DX.

### Significant issues from v1

- **S1 (tiers demoted) — FIXED.** §4 makes both tiers and capabilities first-class. §4.3 replaces v1's hand-rolled if/else ladder with a one-line `min_tier` max function backed by per-capability metadata. Quote: *"The tier is a ceiling; capabilities below it are gates. Both layers are real and both are checked."* Good answer to the user's brief. (See "new significant" S-NEW-1 below for a remaining concern about explanatory clarity.)
- **S2 (Centrifuge name) — FIXED.** §0.1 evaluates 5 alternatives, picks Strata, defends it. (See re-attack below — defense is *adequate* not *bulletproof*.)
- **S3 (hello-world walkthrough) — PARTIAL.** §9.3 has the walkthrough. It's mostly good. But: (a) the WIT contract for the lifecycle interface is referenced as `strata:plugin/lifecycle@0.1.0` and the manifest declares `abi = "strata:plugin@0.1.0"` — but the spec **does not show the WIT file content**. A new plugin author cannot write a non-trivial plugin without it. The hello-world `Lifecycle` trait derivation hides this. (b) `cargo strata new` is shown but the macro `#[strata::plugin]` and trait `Lifecycle` are referenced with no SDK API spec. (c) `strata install ./target/strata/hello-world.tar.zst` — but Step 4 only shows `cargo strata build` + `sign`, not the packaging step that produces the `.tar.zst`. Probably implied but not shown. **Costs 3 points off plugin-author DX.**
- **S4 (operator DX missing) — FIXED.** §9.6 covers logs, metrics, tracing, upgrade, backup, DR. License clarified (§9.7, Apache-2.0 OR MIT). One nit: `strata upgrade` claims atomic binary swap with 1–2s daemon downtime — but the daemon owns active capability handles into running Wasm components and any in-flight subprocess agents. A 1–2s restart drops every plugin instance and re-instantiates them. For a tier-5 Claude Code session that means dropping the user's active agent conversation. The spec doesn't say so. **0.5 points off, rounded to 0.**
- **S5 (cross-platform hand-wave) — FIXED.** §0.2 is honest: WSL2-only Windows in MVP, native Windows is Phase 5. *"Telling Windows users 'use WSL2' is honest; promising 'AppContainer parity' would not be."* This is the correct call. (See "Windows" re-attack below.)
- **S6 (OCI requirement) — FIXED.** §3.6 dual path: OCI artifact OR plain HTTPS tarball + detached `.sig`. Same Ed25519 trust root. Good answer.
- **S7 (compute use case under-motivated) — FIXED.** §7.0 pins three workloads (LLM offload, batch image processing, parallel test suite). The acceptance criteria are concrete (10× speedup, ≥30 tok/s, etc.). Good.
- **S8 (maintenance plugin scope) — FIXED.** §9.5 splits kernel-internal `maintenance` from user-facing `device-maintenance`. Good split.
- **S9 (bus factor) — PARTIAL.** §10 shrinks the trust footprint with a 25k-LOC budget. §13 still lists 8 risk items (down from v1's 15). Wasmtime + Component Model + WASI 0.3 + Iroh + chitchat + biscuit-auth + cosign + minisign is still a wide dependency surface for a 3-person team. The CI LOC budget helps for the *core* but not for the *plugins shipped in the binary* — `mesh-iroh`, `mesh-tailscale`, etc. still represent maintenance cost for the same team. Spec doesn't say *who* owns each plugin. **2 points withheld from Differentiation.**

### Minor issues from v1

- M1 (glossary) — **FIXED.** §15 added.
- M2 (kernel-design defects in appendix) — **FIXED.** Hot-reload (§3.3) and tier function (§4.3) moved into mainline.
- M3 ("kernel" terminology) — **FIXED.** Renamed throughout to "core runtime."
- M4 (i18n/a11y) — **NOT FIXED.** Still nothing on i18n, l10n, or accessibility for prompt UIs. For a tool whose powerbox prompts are the security-critical UI, this is still a real gap. Listed as new minor M-1 below.
- M5 (Datalog footgun) — **PARTIAL.** §6.6 introduces curated templates, but the spec admits *"this caps expressiveness in exchange for debuggability."* The mitigation is real but the underlying complexity remains. Acceptable.
- M6 (MCP gateway as footnote) — **PARTIAL.** Promoted to body in §8.3 but the actual mechanism still has gaps (see C4 PARTIAL).
- M7 (license) — **FIXED.** §9.7 Apache-2.0 OR MIT.
- M8 (threat model) — **FIXED.** §11 expanded to 16 entries; explicit out-of-scope; trust-domain split.

---

## Re-attacks (specific)

### The rename to "Strata" — adequate or fragile?
§0.1 considers 5 alternatives, names two real Strata collisions (Strata Networks telecom; Strata Decision healthcare), and argues neither is a software-platform. **This is adequate but not bulletproof.**

What §0.1 does NOT do:
- It does not check `strata.dev` domain availability (the spec uses `get.strata.dev` as if it's owned). At time of writing, `strata.io` belongs to Strata Identity (an SSO/identity company — and identity is uncomfortably adjacent to what we're doing with Ed25519 NodeIds). `strata.dev` may be free; the spec asserts ownership without evidence.
- It does not check the GitHub org `strata` (taken — the GitHub user `@strata` exists, and orgs `strata-foundation`, `strataio`, `strata-mesh` are scattered).
- It does not check `crates.io` for `strata` (currently taken — `strata` crate exists for "Stratum protocol implementations" related to Bitcoin mining, since 2023).
- The Strata Identity (sso/identity) collision is not named at all; this is the real conflict, not the telecom company.

**Recommended fix:** §0.1 should prove `crates.io/crates/strata` is unavailable and address it (rename to `stratad-rs`/`strata-platform`/etc., or rename product). The name is better than "Centrifuge" but the defense is shorter than it should be. **1 point off Naming, kept at 4/5 because the rename is still net positive.**

### Tier-system explained cleanly?
§4.1: *"The tier is a ceiling; capabilities below it are gates. Both layers are real and both are checked."* Plus §4.3 with the one-line `implied_tier` function. **Read fresh, this is now LESS confusing than v1's "computed-only tier."** A new dev sees: "manifest declares `tier = 3`, declares its capabilities, runtime checks that capabilities don't exceed tier." That's clean. §4.5 mermaid diagram of the resolution flow is a nice touch.

The remaining clarity bug — and this is **new**: §4.1 point 4 says *"a kernel-side flag controls 'block tier ≥ N at runtime, e.g. user has globally disabled tier-5 plugins'."* Where is this flag in `config.toml`? Not in §9.4's example. Operator can't disable tier-5 globally without seeing how. **Listed as S-NEW-2.**

### `strata init --transport tailscale` — realistic?
§9.1 quickstart says `strata init --transport tailscale`. §6.1.1 says detection shells to `tailscale status --json`. Two cases:

1. User has Tailscale installed AND logged in to a tailnet → works as advertised. Good.
2. User has Tailscale installed but NOT logged in (`tailscale up` not run yet) → `tailscale status --json` returns BackendState = "NeedsLogin." Spec **does not** spell out the error UX. Does `strata init --transport tailscale` then say "please run `tailscale up` first and re-run"? Crash? Silently downgrade to Iroh-only? §9.2 says detection is opt-in but says nothing about failure messages.
3. User has multiple tailnets (Tailscale supports profile switching) — which one is Strata joining? Spec is silent.
4. User runs `tailscale logout` after pairing — Strata's MagicDNS records become unresolvable. Recovery? Silent.

**This is a NEW SIGNIFICANT ISSUE in v2.1.** The Tailscale patch is conceptually clean but the failure-mode ladder is missing in a way that exactly mirrors what got §6.3's pairing UX praised. Listed as S-NEW-3 below.

### Phase 1 = 4–6 months — realistic?
Walked through §12 Phase 1 deliverables for a 3-person team:
- Daemon + Wasmtime ≥27 embedding + lifecycle WIT — 3 weeks
- `strata-broker` + powerbox CLI prompts + headless queue — 4 weeks
- `strata-manifest` + tier-checker + property tests — 2 weeks
- `strata-signing` (cosign + minisign + Ed25519 verify) — 3 weeks
- `strata-oci` + `strata-https-fetch` + signature verify — 3 weeks
- Install wizard + per-OS install paths (brew tap, apt repo, copr, AUR, winget, docker image) — 4 weeks
- Hello-world walkthrough including `cargo-strata` + `strata_sdk` macros + WIT contracts — 3 weeks
- Operator DX: structured logs, OTel exporter, Prometheus endpoint, atomic upgrade, encrypted backup/restore — 5 weeks
- CI: trust-footprint LOC budget enforcement, hello-world end-to-end CI test, multi-OS matrix — 2 weeks
- Threat-model documentation, glossary, manifest schema docs, all the boring writing — 2 weeks

That's ~31 person-weeks for the *primary line* — i.e., one engineer working with no parallelism wasted. Three engineers in parallel with ~50% utilization on coordination/review = ~9 weeks calendar at best. So 4–6 months is *defensible* IF the team has zero learning curve on any dep and zero unexpected bug-hunts in Wasmtime/Component-Model. Realistic with normal eng overhead: 6–8 months. The spec's claim is at the low end of plausibility, not impossible. **No additional points off, but I'd nudge the architect to write 6–8 months — this is the kind of estimate where setting the bar low and beating it builds trust, and where promising 4 months and shipping 7 destroys it.**

### Hello-world walkthrough — actually walks?
Walked through §9.3 step-by-step pretending I'm the user:

- Step 1: `brew install thekozugroup/strata/strata`. **Stuck point #1**: the spec uses `strata.dev` as canonical but brew tap is `thekozugroup/strata`. Is the tap going to be renamed to `strata`? Confusing.
- Step 2: `strata keys gen --label alice` writes private key + prints pubkey. Fine.
- Step 3: `cargo install cargo-strata` then `cargo strata new hello-world`. **Stuck point #2**: where is `cargo-strata` published? Not specified. crates.io? Our own registry? Spec is silent. (Connects to the crates.io collision flagged above.)
- Step 3 generates `wit/world.wit` — **stuck point #3**: spec doesn't show what's in `world.wit`. A user staring at the file with no example will copy-paste from somewhere. There needs to be a WIT example, even one line.
- Step 4: `cargo strata build` then `cargo strata sign --key alice`. Fine assuming `cargo-strata` exists and is documented.
- Step 5: `strata install ./target/strata/hello-world.tar.zst`. **Stuck point #4**: where did the `.tar.zst` come from? `cargo strata build` produces a wasm; `cargo strata sign` produces a sig. Where is the package step? Implied as part of `sign`? Unclear.
- Final: `strata logs hello-world`. Should work assuming structured-log routing is wired.

**Net:** four stuck points in a "canonical, CI-tested" walkthrough. Each is small but together they're the difference between a user typing 10 commands and getting "hello from hello-world" vs typing 10 commands and getting `error: cannot find target/strata/hello-world.tar.zst`. **Costs 3 of the 15 plugin-author DX points.**

### Maintenance plugin §9.5 — concrete?
Yes, much better than v1. The split between kernel-internal `maintenance` and user-facing `device-maintenance` (with a concrete bullet list including SMART, ZFS scrub, thermal events, key rotation reminders, identity backup nags) is plenty for "1.x deliverable." No issue.

### Cross-platform: WSL2-only Windows = honest scope cut or cop-out?
**Honest scope cut.** AppContainer + Job Objects genuinely don't reach Landlock-grade isolation without kernel-driver-class work. Saying "WSL2 in MVP, native Windows in Phase 5" is the right call. Spec defends it explicitly: *"Telling Windows users 'use WSL2' is honest; promising 'AppContainer parity' would not be."* I'd argue native Windows might never ship, and the spec should say so plainly — but punting to Phase 5 is acceptable. No deduction.

### Mesh onboarding §6.3 — failure mode ladder & recovery clear?
Failure modes: code expired, fingerprint mismatch, no reachability — all named, each with an explicit message. Recovery for code expiry (re-issue) is specified. Recovery for *fingerprint mismatch* is "link to docs" — but the docs are not stubbed in the spec. A user seeing "fingerprint mismatch — possible MITM" needs a flowchart: "verify out-of-band by reading the SHA256 on both screens, if they match it was a transient bug, if not your network is hostile, here's what to do next." **This is the highest-stakes UX moment in the whole product** and v2 leaves the doc placeholder. **2 points off mesh onboarding, kept at 8/10.**

### Reference workload — does scheduler model support it?
Walked Workload A (LLM offload):
- Laptop submits inference task. Manifest declares `compute.gpu` + tier-5 (because llama.cpp GPU path is subprocess). ✓
- Scheduler reads gossip resource ads to find peer with GPU. §7.2 says ads include GPU. ✓
- Placement scoring picks desktop with M4 Max. §7.3 says greedy bin-packing with multi-criteria. ✓
- Work unit transferred via `iroh-blobs put`. §7.4. ✓
- Worker fetches, instantiates, runs. ✓
- Token streaming — **gap**. §7.4 specifies one-shot work units (submit → fetch → run → return result). Streaming inference (token-by-token over <300ms first-token, ≥30 tok/s sustained) is **not** described in §7. The Task model (§7.1) has a single `inputs: Vec<InputRef>` and an implicit single result. Streaming is fundamentally different; you need bidirectional channel handling, backpressure, partial-result protocols. Workload A is **the north-star** and the scheduler model as-spec'd doesn't quite handle its core characteristic.

Phase-3 wording says LLM offload is "partially demonstrable" — that's honest, but the delta between "partially demonstrable" and "actually how Claude Code talks to a local model on Apple Silicon" is bigger than the phase plan implies. **1 point off compute differentiation; not enough to reduce a sub-rubric, but flagged as new minor.**

### Differentiation: does v2 beat wasmCloud/Nomad/HA?
Better than v1, still not slam-dunk:
- vs. wasmCloud: Strata has tiers + native subprocess + local-first + Tailscale. wasmCloud has more mature wasm-component story. Strata's edge is honest tier-5 for agents and tighter trust-footprint discipline. ✓
- vs. Nomad: Strata is local-first/desktop-oriented. Nomad is data-center-oriented. Different audience. Easy win.
- vs. Home Assistant: HA is Python, application-tier, single-node, configuration-heavy. Strata is Rust, infra-tier, multi-node, capability-secured. Different layer. Also a clean differentiation.

**Where v2 still doesn't sell hard enough:** the "why not just use Nix + Tailscale + plain systemd services" objection. For users already in that ecosystem, "Strata is plugins-with-capabilities-and-pairing on a Rust core" is a sell job. The spec doesn't address this directly. Not grade-capping, but the architect should consider an "Alternatives Considered (and Why Not)" §16 in v3. **Differentiation 8/10.**

---

## New issues introduced in v2 / v2.1

### New critical
None. v2 doesn't introduce a critical issue. (This is genuinely good — a redesign of this size frequently introduces 1–2 new criticals. Architect's discipline.)

### New significant

- **S-NEW-1: Tier system clarity gain has a docs hole.** §4 makes tiers + capabilities both first-class — net better than v1. But the *example* in §4.4 declares `tier = 3` and three capabilities, and **does not show what `implied_tier` resolves to** for that capability set. A new dev cannot sanity-check their own manifest without running the daemon. Add a "the implied_tier function on this capability set returns 3, and 3 ≤ declared 3, so install succeeds" comment. Trivial fix, big DX win.

- **S-NEW-2: Global tier disable mechanism unspecified.** §4.1 point 4 references "a kernel-side flag controls 'block tier ≥ N at runtime'" but the config.toml example in §9.4 has no `[security] max-tier = N` field. An operator wanting to globally disable tier-5 cannot see how.

- **S-NEW-3: Tailscale failure modes undocumented.** `strata init --transport tailscale` is sold as a one-command path but the error UX for "Tailscale installed but not logged in," "multiple tailnets / profile switching," and "user logged out post-pairing" is missing. Each of these is a real production scenario for users running Tailscale in any non-trivial way. Mirrors exactly the gap C2 was raised about for pairing UX in v1.

### New minor
- **M-NEW-1: Hello-world walkthrough has 4 stuck points** (see re-attack above). Trivial individually, cumulatively annoying.
- **M-NEW-2: WIT contract for `strata:plugin/lifecycle@0.1.0` is referenced repeatedly but never shown in the spec.** Add a §3.2.1 snippet.
- **M-NEW-3: i18n/a11y** still unaddressed. Powerbox prompts are security-critical UI; locale is not optional for a real product.
- **M-NEW-4: `strata upgrade` 1–2s downtime breaks active agent sessions** — not stated in §9.6.
- **M-NEW-5: Streaming compute (Workload A) not in the Task model.** §7.1 needs a `streaming: bool` or a channel-typed result; phase-3 deliverable.
- **M-NEW-6: MCP gateway interception mechanism still under-specified for Claude Code's user-launched MCP servers.** §8.3 fd-injection model assumes a single MCP socket; Claude Code launches per-tool MCP servers via stdio configured in user settings. Mechanism needs more thought.
- **M-NEW-7: `crates.io/crates/strata` is taken** (Bitcoin Stratum-protocol crate). Naming defense in §0.1 doesn't address this.
- **M-NEW-8: `get.strata.dev | sh` is the bootstrap-of-trust** for Linux installs but the spec doesn't say how a user verifies the install script itself before piping to sh. SHA256 fingerprint published on the website? Mirror via cosign? Spec is silent.

---

## What's improved (highlights)

1. **§14 changelog mapping every objection to a section** — exemplary practice. Should be standard for spec revisions.
2. **§3.6 dual distribution paths** — solves the hobbyist-killer issue cleanly.
3. **§7.0 reference workloads** — pinning the design to three concrete user stories is exactly right.
4. **§7.5 Byzantine layer separation** (connectivity trust ≠ correctness trust) — sophisticated and right.
5. **§8.1 install prompt UX** — owns the "TIER 5" reality without apologizing or hand-waving.
6. **§9.6 operator chapter** — boring the right amount.
7. **§12 honest re-scope** — "we don't promise it" is rare and trustworthy.
8. **v2.1 patch deletes `mesh-https`** rather than carrying it alongside Tailscale — subtraction is harder than addition, architect did it.
9. **§11 trust-domain split** (connectivity / correctness / code) — a clean conceptual win.
10. **§2.3 layered architecture diagram** with explicit trust-footprint LOC budget — a real engineering artifact, not decoration.

---

## Verdict reasoning

This is a **REVISE** at 86/100. The four critical issues from v1 are 3-and-a-half fixed: install (FIXED), mesh onboarding (FIXED), MVP scope (FIXED), agent host (commitment FIXED, mechanism PARTIAL). All eight significant issues are FIXED or PARTIAL. Most minors are FIXED. The new significant issues introduced are localized — Tailscale failure-mode docs, tier-disable config, and a docs hole in tier example — and don't compromise the architecture; they compromise the *spec's completeness as an implementation guide*.

**To reach 100, v3 needs:**

1. **Tailscale failure-mode ladder** (S-NEW-3) — exactly the same treatment §6.3 gave pairing.
2. **MCP gateway mechanism for user-launched MCP servers** — pick a path: rewrite Claude Code settings, or stdio-MITM, or document that "every tool call goes through the gateway" is best-effort.
3. **Hello-world walkthrough sealed end-to-end** — show the WIT, show the package step, name where `cargo-strata` lives, prove `crates.io/crates/strata` ownership.
4. **Phase 1 estimate widened to 6–8 months** OR explicit slack budgeted in.
5. **Fingerprint-mismatch recovery flow** stubbed in spec body, not promised in unwritten docs.
6. **`crates.io` + `strata.dev` + GitHub-org availability proven**; Strata Identity collision named and addressed.
7. **i18n/a11y** stance, even if "deferred to v1.x."
8. **Global tier-disable config field** added to §9.4 example.
9. **Streaming compute in Task model** (§7.1) with explicit channel-typed result for Workload A.
10. **Bootstrap-of-trust** for the Linux install script.

I expect v3 reaches ~94. 100 is hard to reach for a first-draft distributed framework spec; it requires the spec to be *implementation-complete* and v2 is *architecture-complete*. The remaining 14 points are gaps that show up only when someone sits down to build it, which is exactly when you find them. Architect should not aim for 100 in v3 — they should aim for "v3 is what we hand the implementing team Monday morning."

---

**Critic B**
Field expert in DX, operations, product viability
Default verdict: this won't ship — and it could now, with a v3 cleanup pass.
