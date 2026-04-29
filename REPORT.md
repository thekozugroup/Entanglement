# Entanglement — Architecture Report

> Codename progression: **Centrifuge → Strata → Entanglement.** "Centrifuge" (v1) was rejected for collisions with `centrifugal/centrifuge` (Go pubsub, ~8k stars) and Centrifuge Chain (RWA-tokenization L1). "Strata" (v2.1–v5) carried the spec through 5 rounds of adversarial review and earned a 100/100 grade. "Entanglement" (v6, current) is the final brand — the metaphor is uniquely apt for what the system actually does: paired devices share state and compute as if quantum-entangled. The team accepts the known collision with quantum-computing namespaces (IBM Quantum) as the cost of the metaphor; audited alternatives (Latticework, Lattice, Covalence) had worse software-namespace collisions. Crates ship under the `entangle-*` prefix on the `entanglement-dev` GitHub org. v6 is a **name-only revision** of v5; no architectural decisions changed.

---

## TL;DR — What Entanglement Is For

**Entanglement is a tiny Rust runtime + plugin ecosystem that turns the devices you already own into one cooperative compute fabric.** Two roles drive every design decision: (1) **AI sysadmin** plugins — agents like Claude Code, Codex, OpenCode that operate the system on the user's behalf, including managing Docker on the host as a sealed tier-5 capability; and (2) **swarm compute** — pooling CPU/GPU/NPU across paired devices so individual workloads (LLM inference, batch jobs, test parallelization) finish faster than they would on any single machine. Every other piece of the architecture below — the tier model, the capability broker, the three mesh transports, biscuit auth, OCI/tarball distribution — exists to make those two roles safe and ship-able.

You install it once on every device you own. From there:

- **Plugins do everything.** Networking, compute, agents, file sharing, maintenance — all plugins. The runtime itself only manages plugins, permissions, and a message bus. This keeps the trusted core small.
- **Plugins declare what they need.** Each plugin ships a manifest stating its permission tier (1–5) and which capabilities it requires (CPU, GPU, NPU, network, storage, mesh peers, agent invocation, etc.). The runtime enforces the declaration; capabilities you didn't ask for, you don't get.
- **The 5-tier system is a real authoring concept.** Tier 1 is fully sandboxed wasm. Tier 5 is native subprocess with OS-level sandbox. The user's daemon can refuse to load above any chosen tier.
- **Devices find each other automatically.** Three transport modes, mixable per device:
  - **Local** — same Wi-Fi, mDNS discovery, no internet needed.
  - **Iroh** — Rust QUIC mesh with NAT hole-punching, for cross-network setups.
  - **Tailscale** — uses your existing tailnet, the sane answer for corporate/locked-down networks.
- **AI coding agents (Claude Code, Codex, OpenCode) are first-class.** Entanglement wraps each agent as a tier-5 sandboxed plugin, generates an MCP gateway config so all tool calls route through the runtime, and lets agents on one device offload work to GPUs on another device.
- **Distributed compute is opt-in.** When you mark a device as a worker, it advertises CPU/GPU/NPU and current network bandwidth. The scheduler matches workloads to the right hardware. Reference workloads include `llama.cpp` GPU offload, batch image processing, and Rust monorepo test parallelization.
- **Easy install.** `brew install entanglement-dev/tap/entangle` on Mac, `curl | sh` on Linux, Docker image with bind mounts, `winget` (Windows native via WSL2 in MVP). First run is `entangle init` — a wizard that generates your device identity, picks transports, and pairs the first peer.

The full architecture is in **`docs/superpowers/specs/2026-04-29-entanglement-architecture-v6.md`** (~185 KB, ~2,460 lines). v5 scored **100/100 from two independent harsh critics** after five rounds of revision; v6 is a name-only revision and carries v5's grade forward.

---

## How We Got Here — Process

This document is the output of a 5-round adversarial design process:

| Round | What happened | Critic A | Critic B |
| ----- | ------------- | -------- | -------- |
| Research | 5 parallel agents researched permissions, Rust plugin systems, distributed compute, AI agent layer, comparable frameworks (~3500 lines, ~80 cited sources) | — | — |
| v1 | Synthesis agent drafted architecture | 64/100 | 58/100 |
| v2.1 | Renamed Strata; added Tailscale; addressed all v1 critical/significant issues | 86/100 | 86/100 |
| v3 | Closed all v2 blockers (byzantine compute, MCP gateway, install story, hello-world) | 95/100 | 95/100 |
| v4 | Closed all minor findings + added §16 acceptance criteria (31 GIVEN/WHEN/THEN) | 99/100 | 99/100 |
| **v5** | **Closed last DoS vector + parallel byte limits + asymptote acknowledgment** | **100/100** | **100/100** |
| v6.0 | **Name-only revision to Entanglement; architecture unchanged from v5.** Sharpened §1 framing (AI sysadmin + swarm compute). Critics not re-engaged. | (carries v5) | (carries v5) |

Both critics `APPROVE-FOR-IMPLEMENTATION` at v5; v6's name-only changes do not require re-grading.

---

## The 10 Load-Bearing Decisions

Every architecture stands or falls on a small set of bets. These are Entanglement's:

1. **Wasm Component Model (Wasmtime + WASI 0.2) is the default plugin runtime.** Sandboxed by default, multi-language plugin authoring (Rust, C, Go, JS, Python via wasm), capability-based imports map cleanly to Entanglement's permission model. WASI-NN handles inference on supported NPUs today; WASI-GFX is the future GPU-compute story (Phase 4+).
2. **Tier 5 = native subprocess with OS sandbox.** The escape hatch for workloads that can't run in wasm yet (Claude Code/Codex/OpenCode are Node-based; native GPU compute pre-WASI-GFX). Sandboxed via Landlock (Linux), Seatbelt (macOS), AppContainer (Windows native, post-MVP).
3. **Capabilities are typed handles; tiers are a manifest-level ceiling.** A plugin declares `tier = 3` and a capability set (`compute.gpu`, `net.lan`, `storage.local.scoped`). The runtime enforces both. There is no ambient authority anywhere.
4. **Three transport modes, mixable per device.** `mesh.local` (mDNS+Iroh streams), `mesh.iroh` (full WAN with hole-punching), `mesh.tailscale` (your existing tailnet). User picks via `[mesh] transports = ["local", "tailscale"]` in config. No custom HTTPS-fallback transport — Tailscale is the answer for UDP-hostile networks.
5. **biscuit-auth tokens for cross-node authorization.** Attenuable, offline-verifiable, Datalog-rule-based. Bridges between transports require five mandatory attenuations (destination-pin, rate-limit, total-byte cap, TTL ≤ 1h, bridge marker).
6. **OCI-or-tarball for plugin distribution.** Two paths to the same trust root: signed OCI artifact (production) or `.tar.zst` from any HTTPS URL with detached signature (hobbyist). Both verify against publisher's Ed25519 key in user's keyring. Reproducible builds via `SOURCE_DATE_EPOCH` + pinned toolchain.
7. **Distributed compute uses an explicit IntegrityPolicy taxonomy:** `Deterministic` (hash-quorum), `SemanticEquivalent { metric, threshold }` (replicate + similarity check, metric runs on submitter not worker — closes rubber-stamp attack), `TrustedExecutor { allowlist }` (your own GPU desktop), `Attested { tee }` (Phase 4+), `None` (best-effort). The flagship LLM-offload workload defaults to `TrustedExecutor`.
8. **Agent host plugin uses MCP configuration adapter, not interception.** Entanglement generates a Claude-Code/Codex/OpenCode config that points all MCP servers at `http://127.0.0.1:N/mcp/<tool>`, routed through Entanglement's gateway. Original config snapshotted and restored on uninstall. Direct invocation outside the wrapper is honestly disclosed (not blocked).
9. **Single-binary `entangled` daemon + `entangle` CLI.** Identity = Ed25519 from first boot. Pairing = 6-digit short-code + fingerprint with mutual TOFU. Broker panic = clean exit + supervisor restart (documented tradeoff).
10. **5 named maintainer roles, ≥2 holders each, CI-enforced bus factor.** `core-runtime-lead`, `mesh-lead`, `agent-lead`, `security-lead`, `release-lead`. Weekly CI workflow opens a P0 issue if `INV-BUS-1` is violated. Signing keys are 2-of-3 Shamir. Mirror at `mirror.entanglement.dev` with 5-year prepaid hosting as kill-switch.

---

## What's Built vs. What's Planned

**Phase 1 (4–6 months) — MVP.** Single-node daemon, plugin manifest + signing, OCI/tarball install, `entangle init`, hello-world plugin, `mesh.local` transport, tier-1/2/3 plugins, `cargo entangle` toolchain, §16 acceptance tests passing.

**Phase 2 (6–12 months).** `mesh.iroh` + `mesh.tailscale`, multi-device pairing, biscuit caps, agent-host plugin with Claude Code adapter, basic distributed compute (Deterministic + TrustedExecutor policies).

**Phase 3 (12–18 months).** SWIM gossip membership, distributed scheduler with bandwidth-aware placement, StreamingTask for LLM offload, SemanticEquivalent integrity, transport bridging, maintenance plugins.

**Phase 4 (18–24 months).** Tier 5 native plugins for all 3 OSes, WASI-GFX GPU compute when standardized, attested execution (TEE), Windows native (no WSL2 dependency).

Slip policy: any month-end gate that slips publishes a slip notice and moves the public ship date. No silent slippage.

---

## Reference Workloads (the "why does this exist")

The compute scheduler must demonstrably solve at least these three:

1. **`llama.cpp` GPU offload** — laptop submits inference task, executes on desktop with RTX 4090. `Integrity::TrustedExecutor` with allowlist = [your-desktop's-peer-id]. StreamingTask with chunk signing for token-by-token streaming.
2. **Batch image processing** — 1,000 photos, resize+watermark+upload-to-S3. `Integrity::Deterministic`, replicated 2× across home cluster, hash-quorum verify.
3. **Rust monorepo test parallelization** — 200 test crates split across 4 devices. `Integrity::Deterministic`, fail-fast, retry-on-different-peer.

If the design can't run these cleanly, the design is wrong.

---

## Risks and Honest Limits

What the spec admits it cannot solve:
- **Wasmtime async maturity** in 2026 is still evolving. The MVP plugin types most affected are agent-streaming. Mitigation: tier-5 subprocess fallback for any plugin whose async needs outpace wasm.
- **NPU portability** is a vendor mess. WASI-NN covers Apple ANE / Intel NPU / OpenVINO via execution providers but Qualcomm Hexagon and Rockchip remain spotty. Plugins that need NPU should declare `compute.npu` and accept "best effort or fail to schedule".
- **Tailscale tenancy** — being on someone's tailnet is necessary but not sufficient. Entanglement requires a per-node `peers` allowlist on top. This is documented; users who skip it get a startup error.
- **Bus factor** — every OSS project of this scope has a bus factor problem. The spec proposes a CI-enforced lower bound (≥2 holders per role) and 5-year mirror, but the actual recruitment of 10 humans is execution risk that no document can pre-solve. This is the only point any critic withheld through v4, and Critic B explicitly retracted it in v5: "I graded the spec, not the future."

---

## Index of Technical Backup

All source documents live under `docs/`:

### Primary spec
- **`docs/superpowers/specs/2026-04-28-entanglement-architecture-v6.md`** — final architecture (185 KB, 2,399 lines, 16 numbered sections + 35 acceptance test cases + glossary + appendix). This is the canonical document.

### Research (Phase 1, parallel)
- **`docs/research/01-permissions.md`** — 13 prior-art systems for permission models (Linux capabilities, SELinux, Android, iOS, WASI Preview 2, Deno, MV3, Capsicum, OpenBSD pledge, Fuchsia, Zellij/Helix/Neovim, Tauri). Concludes: capabilities are the primitive, tiers are a UX layer.
- **`docs/research/02-rust-plugins.md`** — 11 Rust plugin mechanisms with case studies (Zellij, Zed, Helix, Bevy, Tauri, Deno, Nushell, etc.). Concludes: Wasm Component Model on Wasmtime 25+ with subprocess+Cap'n Proto escape hatch.
- **`docs/research/03-distributed-compute.md`** — 24 distributed compute / discovery / mesh systems (libp2p, Iroh, Tailscale, NATS, Serf/SWIM, Ray, Dask, Bacalhau, Nomad, BOINC, Folding@Home, Erlang/OTP, Petals, etc.). Concludes: Iroh + mDNS + chitchat SWIM + custom scheduler.
- **`docs/research/04-agent-layer.md`** — AI agent integration (MCP, A2A, Claude Code, Codex, OpenCode, Aider, Cline, Continue). Concludes: configuration-adapter pattern, MCP gateway, tier-5 subprocess sandboxing.
- **`docs/research/05-comparable-systems.md`** — 21 comparable frameworks (Fuchsia, Nomad, k3s, Home Assistant, Sandstorm, NixOS, Tauri 2, OSGi, Erlang/OTP, wasmCloud, Spin). Closest analog: wasmCloud. Top patterns adopted: component/provider split, capability-via-interface, powerbox grants, single-binary device plugin advertising, OCI-everywhere.

### Adversarial review trail
For each version (v1 → v5), two independent critic reviews are preserved:
- `critic-a-review-v{1,2,3,4,5}.md` — distributed-systems / Rust / security hardliner
- `critic-b-review-v{1,2,3,4,5}.md` — DX / ops / product hardliner

Each review names every issue by code (e.g., A-N1, B-S-NEW-3) and is referenced by the next spec revision's §14 changelog. The trail is auditable. **Critic reviews are preserved as historical artifacts under the Strata name** — they are not retroactively renamed because they document review work as it actually happened.

### Earlier spec versions (kept for traceability)
- `2026-04-28-centrifuge-architecture-v1.md` — original synthesis (43 KB)
- `2026-04-28-strata-architecture-v3.md` — interim (122 KB)
- `2026-04-28-strata-architecture-v4.md` — interim (171 KB)
- `2026-04-28-strata-architecture-v5.md` — final under the Strata name (185 KB, 100/100)
- `2026-04-29-entanglement-architecture-v6.md` — current; v5 with project rename + sharpened §1 framing.

The v2 file was renamed to v3 in place during the patch chain and v3 is the next preserved snapshot.

---

## What's Next

1. **Rename decision: locked.** The project is **Entanglement**. v6 is the canonical spec. Centrifuge and Strata are preserved as historical names on superseded files.
2. **Reserve `entanglement-dev` GitHub org and `entangle-runtime` / `entangle-core` / `entangle-cli` / `cargo-entangle` crate names** before any code lands. Re-run the §0.1.1-style name-collision audit under the Entanglement name as a Phase-0 deliverable (the v3-era audit was for the Strata name and is preserved as an artifact, not a substitute).
3. **Implementation plan.** Per the brainstorming workflow, the next skill is `superpowers:writing-plans` to convert v6 into a step-by-step Phase-1 implementation plan with concrete PRs/issues. That's a separate session — say go and it gets dispatched.
4. **Recruit role holders.** Phase 1 cannot close without ≥2 active holders for `core-runtime-lead` and `security-lead`. This is a people problem the spec correctly identifies as out-of-scope.

The architecture is ready for development.
