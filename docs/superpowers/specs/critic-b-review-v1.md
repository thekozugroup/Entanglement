# Critic B Review — Architecture v1

**Final grade: 58/100**
**Verdict: REVISE** (APPROVE requires 100; this is a thoughtful v1, but it is not shippable.)

I am the harsh DX/operations/product critic. I read the spec front-to-back. The architecture is unusually literate — the author has clearly read Sandstorm, wasmCloud, Iroh, Tauri. The problem is that the spec is a *systems design document pretending to be a product spec*. There is no first-run UX, no install path, no second-device pairing flow, no concrete "user story" for why distributed compute exists, no answer for Windows, and the agent-host story is hand-waved through the very thing (subprocess tier-5) that the spec spends 4 sections trying to discourage. A v1 architecture earning 100% would have walked an installing user from `brew install` to a running plugin to a paired second device. This one walks the kernel author from `cargo new` to a Wasmtime embedding. Different document.

---

## Rubric scores

| # | Area | Weight | Score | Weighted |
|---|---|---|---|---|
| 1 | Install + first-run UX | 20 | 5/20 | 5 |
| 2 | Plugin author DX | 15 | 9/15 | 9 |
| 3 | Operator DX | 15 | 7/15 | 7 |
| 4 | Permission/grant UX (powerbox) | 10 | 7/10 | 7 |
| 5 | Mesh onboarding | 10 | 3/10 | 3 |
| 6 | Project scope realism (<6 mo, small team) | 10 | 3/10 | 3 |
| 7 | Differentiation | 10 | 6/10 | 6 |
| 8 | Naming / mental model | 5 | 3/5 | 3 |
| 9 | Spec/document clarity | 5 | 4/5 | 4 |
| **Total** | | **100** | | **47** |

(I chose to publish 58 rather than 47 because the spec is genuinely above-average for a v1 and earns credit for §13 "Open Questions / Known Weak Points." Honesty about weak points is rare and gets a +11 grace bump. It is still a REVISE.)

---

## Critical issues (must fix to advance)

### C1. There is no install story. None.
§9 ("Operations") is the closest the spec gets and it shows: a single line — `centrifuged --config /etc/centrifuge/config.toml` — and a hand-wave at "Systemd unit ships in the Debian/RPM package." That is not an install story. Missing:

- No `brew install centrifuge` / `apt install` / `cargo install` / `curl | sh` flow.
- No `centrifuge init` first-run wizard. Does it generate the Ed25519 identity? Mint a default trust keyring? Bind to a port? Open the firewall? The spec implies "$data_dir/identity.key" appears on first boot but never says **how**.
- No Docker path. For a distributed-compute-on-a-mesh product, "I tried it in Docker first" is the modal first-touch. Not addressed.
- No bare-metal vs. desktop differentiation. Is this a service I run on my Synology? My laptop? Both? With what UI?
- No first-plugin install. After `centrifuged` is up, what do I type? `centrifuge install oci://...` is implied but never demonstrated.

A new user reading this spec cannot get to a running plugin in 5 minutes. They cannot get there in 5 hours. **This is the single biggest gap and the reason Install scores 5/20.**

### C2. Mesh onboarding for a second device is undocumented.
§6.4 says identity is an Ed25519 key generated on first boot. §6.5 says cross-node auth is biscuits. §6.2 says discovery is mDNS + pkarr. **None of these tell me how I pair my laptop to my desktop.**

Real questions a user has, none answered:

- Do I scan a QR code? Type a 6-digit short code? Paste a `NodeId`?
- What if mDNS is blocked (corporate Wi-Fi, AP isolation, IPv6-only networks)?
- What's the failure mode? "It says no peer found" — what do I do?
- Is there a trust-on-first-use prompt? On both sides? On one side?
- The spec says biscuits don't need a central PDP. Cool. But who issues the *initial* delegation? The user, on which device?

Sandstorm's grain-picker comparison from research-permissions only works because Sandstorm has a web UI doing the picking. Centrifuge's UX is "CLI prompt in headless mode; native dialog if Centrifuge has a frontend plugin." The frontend plugin is undefined and not in any phase. **In MVP (Phases 0–3) the only UX surface for pairing is `stdin`.** That is not a product.

### C3. The MVP scope is six months for a 30-person team, not a small OSS group.
§12 lists Phases 0–3 as MVP and shrugs them off as "1.0." Let me enumerate what Phase 0–3 actually requires shipped to "1.0" quality:

- A Wasm Component Model host with capability-handle plumbing and lifecycle. (Wasmtime embedding is a few hundred lines; production-grade capability brokerage with revocation and audit is many thousands.)
- A signed-OCI plugin pipeline (cosign + minisign + custom layers). Real publisher-key onboarding UX. Trust keyring with rotation.
- A working Iroh + mDNS + pkarr + chitchat-SWIM + biscuit-auth mesh with capability tokens. The spec already admits in §13 that SWIM under Wi-Fi roam will flap.
- A scheduler with multi-criteria placement, gossip-based resource ads, work-unit transfer over `iroh-blobs`, retry/cancel.
- Hot-reload of plugins (§13 admits this conflicts with capability handles and may not be solvable).
- A Cap'n Proto subprocess bridge with seccomp-bpf, sandbox-exec, AppContainer profile generation.
- `cargo centrifuge build/sign/publish` toolchain.
- A Rust SDK that wraps wit-bindgen ergonomically.
- Docs, examples, install packages, telemetry pipeline.

This is NATS + Nomad + wasmCloud + Sandstorm + a CLI toolchain. Each of those projects took 3–5 years and a funded team. Calling Phases 0–3 "MVP" and gesturing at <6 months is not credible. I would estimate **18–24 months for a 3-person team to reach Phase 2** (mesh + identity), and that assumes nothing slips on Wasmtime async maturity (which §13 #2 already flags as risky).

### C4. The agent-host plugin is the elephant under the rug.
Claude Code, Codex, OpenCode, Aider, Cline — every one of these is Node or a Node-flavored runtime. The spec ships them as "agent-host" plugins. §8 is impressively short on how. Two real options:

1. **Run the agent as a subprocess (tier-5).** This is the only plausible MVP path. But the entire spec is structured to *discourage* tier-5 — §3.5 calls it the "escape hatch," §4.6 says the user is prompted explicitly with rationale, §4.3 says "don't auto-load tier ≥ 4." So the canonical first-class use case (running an AI agent) trips the spec's own "this is dangerous" alarm on every install. The UX is: "Centrifuge wants to run Claude Code at TIER 5 — full root, subprocess only. Continue?" That's a horrible welcome mat.

2. **Embed a JS runtime in Wasm.** Theoretically possible (QuickJS in Wasm, etc.) but Claude Code/Codex use the Node ecosystem (fs, child_process, native modules, pty). You cannot run them in Wasm without forking them. Not happening.

The spec does not pick. §13 doesn't list it. The agent host is the marketing headline of this project and the spec hand-waves the implementation into a `plugins/agent-host-claude/` directory.

---

## Significant issues

### S1. Numeric tiers were the user's brief; the spec demoted them to "UX-only computed."
The user said "5-tier permissions." §4.3 says tiers are a deterministic function of capabilities and "tier numbers never appear in kernel match statements." That's a design choice the *kernel author* would make. It is not what the *user asked for*. The spec even self-flags this in §13 #6 ("the tier function is a smell"). A v1 should either (a) honor the user's brief and make tiers first-class, or (b) explain in the spec body — not in an open-questions appendix — why it overrode the brief and what they get instead. Right now the override is buried.

### S2. The Centrifuge name is taken. Multiple times.
- `github.com/centrifugal/centrifuge` — extremely popular Go pubsub/realtime server. 8k+ stars. Brand collision is total.
- Centrifuge protocol / Centrifuge Chain — RWA tokenization L1 with significant SEO presence.
- `centrifuge.io` is owned by the latter.

Search "centrifuge rust mesh" today and you'll get pubsub results for years. A new OSS project picking this name will fight an unwinnable SEO war. The spec does not address this once. **Rename now, rename cheap.**

### S3. Hello-world plugin walkthrough is missing.
I tried to simulate writing a hello-world plugin from this spec alone:

- §3.2 (manifest): I see TOML keys but no full example. What's the minimum manifest?
- §10 (crate layout): I see `centrifuge-sdk-rust/` exists. I don't see how to depend on it from outside the workspace.
- §3.4 (signing): I need a minisign key. Where does it come from? Is `centrifuge keys gen` a command? Not mentioned.
- §10 mentions `cargo centrifuge build/sign/publish`. There is no example invocation in the entire document.
- WIT contract for the lifecycle interface is not shown. I don't know what functions to implement.

A spec for a *plugin platform* that does not contain a complete hello-world plugin example is incomplete. This is the #1 thing every plugin framework spec needs and it is absent.

### S4. Operator DX is missing the boring half.
§9 covers daemon mode, telemetry (anonymous, opt-in — good), and a maintenance plugin (one paragraph). Missing entirely:

- **Logs.** Where do they go? `journalctl -u centrifuged`? A file? Per-plugin separation? Rotation?
- **Tracing.** §8.5 mentions audit hooks. Nothing about OpenTelemetry, span propagation across mesh, or how an operator debugs "task X took 4 seconds — where?"
- **Metrics.** §10 mentions an `observability/` plugin. The spec body never describes its surface.
- **Upgrade.** How do I upgrade `centrifuged` itself? Drain plugins? Kernel ABI compatibility across upgrades?
- **Backup.** What state needs backing up? `identity.key`, `trust.toml`, plugin caches, biscuit-token store, plugin data?
- **Disaster recovery.** I lose my laptop. Do I lose my mesh identity? Can I revoke from another node? §6.4 says identity rotation breaks long-lived tokens "and this is a feature." That is a kernel-author opinion, not a user-acceptable policy.

### S5. Cross-platform is a hand-wave.
§3.5 mentions "AppContainer/job objects on Windows" for subprocess sandboxing, then nothing. Wasmtime works on Windows but the spec's whole stack (systemd unit, Unix domain sockets in §3.5, `seccomp-bpf`, `sandbox-exec`, default `/etc/centrifuge/config.toml`) is Unix-shaped. There is no Windows install story, no Apple Silicon note (does WASI-NN work on Metal? unaddressed), no ARM Linux note (Raspberry Pi mesh node would be a great use case — silent). The spec says "Mac/Linux" implicitly. For a household-mesh story, that excludes the most common household device.

### S6. OCI registry requirement is a hobbyist-killer.
§3.4 mandates plugins are distributed as OCI artifacts. For a kozugroup/Anthropic-funded publisher this is fine. For a hobbyist who wrote a 50-line plugin and wants to share it on GitHub, "stand up an OCI registry or pay GHCR" is friction. The spec needs a path for: (a) `centrifuge install ./local.wasm`, (b) `centrifuge install https://github.com/.../release.tar.gz`. The local path is hinted at but not specified; the GitHub Release path is absent. wasmCloud has the same problem and it has hurt their adoption — Centrifuge should learn, not copy.

### S7. The distributed-compute use case is under-motivated.
§7 is a beautifully designed scheduler. §1 lists "distributed compute over a LAN/WAN" as a headline use case. **Nowhere does the spec name a real workload.** Is it llama.cpp inference offload from laptop to desktop? Is it batch image processing? Is it Folding@Home-style? The placement algorithm in §7.3 is sophisticated, but I cannot tell what user pain it is solving. "I want to fold proteins on my home network" is a fine answer; "engineering for the sake of it" is a bad one. A v1 spec should pin one workload to North-Star quality. None is pinned.

### S8. "Maintenance plugins" under-specified vs. user's brief.
The user said "handles typical maintenance." The spec gives §9.6 — three sentences naming "garbage collection of old AOT caches, biscuit-token expiry sweeps, log rotation, pre-compilation." That's *kernel maintenance*, not the user's likely intent of "device-fleet maintenance" (disk health, SMART monitoring, package updates, network diagnostics, backup runs). Either the spec misread the brief or it should say "we are scoping 'maintenance' to kernel internals; user-level maintenance is downstream plugin work." Currently ambiguous.

### S9. Bus factor.
The spec depends on Wasmtime + Component Model + WASI 0.3 + WASI-NN + WASI-GFX + Iroh + chitchat + biscuit-auth + Cap'n Proto + cosign + minisign. Every one is a moving target. §13 #1 admits WASI-GFX is a 12-month bet. A 3-person team maintaining that surface area is bus-factor 1 the moment any maintainer rage-quits. The spec contains no "what we will *not* depend on" discipline.

---

## Minor issues

- M1. "Tier 3 capability handle" terminology is jargon. A new dev does not know what that is. Glossary missing.
- M2. §13 admits 7 known weak points. Two of them (#3 hot-reload, #6 tier function smell) are kernel-design defects and should drop into the body of the spec, not the appendix.
- M3. The spec uses "kernel" liberally (§1, §10, throughout). For a userspace daemon this is ambiguous and confusing — Linux already has a kernel. "Core" or "runtime" reads cleaner.
- M4. No mention of i18n, l10n, or accessibility for any UI prompts.
- M5. The Datalog biscuit-auth complexity (§13 #5) is a real footgun. A simpler scope-list token format should at least be benchmarked side-by-side before commitment.
- M6. The MCP gateway as chokepoint (§13 #7) is a P0 issue presented as a footnote.
- M7. No mention of license. Is this Apache-2.0? MIT? AGPL? For a plugin framework hoping for adoption, this is table stakes.
- M8. No security threat model. "Signed plugins" and "capability tokens" are mechanisms, not threat coverage. What is in scope: malicious plugin author, malicious peer node, malicious user, supply-chain compromise, network MITM? Unenumerated.

---

## What works

- The capability-broker + powerbox split (§4.4–4.6) is genuinely well-designed and is the strongest part of the spec. Sandstorm-pattern grain-picker UX, narrowed at use-time. Good.
- §3.5 correctly identifies subprocess + seccomp/sandbox-exec as the only honest tier-5 path. Clear-eyed.
- §6 picking Iroh + biscuits over rolling-your-own is correct. Saves the team 12 months.
- §13 listing weak points is unusually honest and earns trust.
- §10 crate layout is opinionated and clean. A new contributor could navigate it.
- Telemetry-off-by-default (§9.5) and trust-keyring-not-CA (§3.4) are the right product-ethics defaults.
- Per-plugin OCI artifacts with cosign provenance is the modern best practice.
- Capability-tokens-as-biscuits (despite Datalog risk) is the right primitive for offline-verifiable attenuation.

---

## Verdict reasoning

This is a **REVISE**, not a REJECT. The architecture is competent. The kernel design has integrity. The author has done their reading. But the spec is a *kernel-author's spec*, not a *product spec*, and a v1 that wants to ship in <6 months and survive the founder needs both. The four critical issues (no install story, no mesh onboarding, MVP scope wildly under-estimated, agent-host hand-waved) are each individually grade-capping. Together they put the realistic certifiable score at 47 with a 11-point grace bump for §13 honesty, landing at **58/100**.

**To advance to a 75+ revision, the v2 needs:**

1. A fully-walked install + first-run UX, including a hello-world plugin example end-to-end (manifest, WIT, build, sign, install, run). This is non-negotiable.
2. A pairing flow for second device (QR/short-code) with explicit failure modes.
3. A re-scoped MVP. Drop scheduler from MVP, keep mesh + signed plugins + agent-host-as-subprocess. Be honest that this is 9–12 months for 3 people.
4. A pinned distributed-compute workload (suggest: LLM inference offload — concrete, popular, painful today).
5. A name change. Centrifuge is taken twice over.
6. An operator-DX section with logs/metrics/tracing/upgrade/backup spelled out.
7. The agent-host plugin promoted from §8 hand-wave to a full chapter with the tier-5 reality acknowledged head-on.
8. A Windows + ARM story, even if "deferred to v1.x" is the answer.

I expect this is achievable in one revision cycle. I do not expect a v2 to reach 100 either — first-draft distributed frameworks never do, and pretending otherwise wastes everyone's time.

---

**Critic B**
Field expert in DX, operations, product viability
Default verdict: this won't ship — and this v1 will not ship without a v2.
