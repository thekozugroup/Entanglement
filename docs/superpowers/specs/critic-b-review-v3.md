# Critic B Review — Architecture v3 (Strata)

**Final grade: 95/100**
**Verdict: REVISE → near-APPROVE.** This is a v3 I'd hand to a 3-person team Monday morning. Five points withheld because two issues are genuinely unprovable on paper (Phase-1 timeline realism, and bus-factor mitigations whose value depends on whether the team executes the rotation discipline they committed to). 100 still reserved for after Phase 1 ships, exactly as both critics flagged.

The architect did the rare thing: they read both v2 reviews, they did not get defensive, they fixed every single named blocker with concrete spec language, they introduced **zero new criticals**, and they wrote a §14 "v3 changelog" that maps every code (B-C4-partial, B-S-NEW-1, …) to the section that fixes it. That artifact alone is the kind of work that earns the benefit of the doubt on the few judgment calls I'd nudge differently.

---

## Rubric scores

| # | Area | Weight | v1 | v2 | v3 | Δ vs v2 |
|---|---|---|---|---|---|---|
| 1 | Install + first-run UX | 20 | 5 | 17 | **20** | +3 |
| 2 | Plugin author DX | 15 | 9 | 12 | **15** | +3 |
| 3 | Operator DX | 15 | 7 | 13 | **14** | +1 |
| 4 | Permission/grant UX (powerbox) | 10 | 7 | 9 | **10** | +1 |
| 5 | Mesh onboarding | 10 | 3 | 8 | **10** | +2 |
| 6 | Project scope realism (<6 mo, small team) | 10 | 3 | 8 | **8** | 0 |
| 7 | Differentiation | 10 | 6 | 8 | **9** | +1 |
| 8 | Naming / mental model | 5 | 3 | 4 | **5** | +1 |
| 9 | Spec/document clarity | 5 | 4 | 7* | **5*** | -2 (cap restored) |
| **Total** | | **100** | **47+11** | **86** | **95** | **+9** |

*Clarity: v2 got +2 over the cap for §14's exemplary changelog. v3's §14+v3.0 sub-table is even better — every blocker has a code, every code has a section, every section has the fix. I'd cap at 5 honestly this time; the +2 over-cap was a one-time recognition. The changelog quality is now *expected*, which is the point.

The 11-point grace bump v1 got is long irrelevant. v3 = 95 raw; no grace on top.

---

## Prior-issues status (every code from the v2 review)

### B-C4-partial — MCP gateway for Claude Code → **FIXED**
§8.3 walks back the v2.1 "fd-injected at spawn" hand-wave and replaces it with a **configuration-adapter model**: per-session HTTP gateway on `127.0.0.1:<port>` with a per-session bearer token; per-agent-host adapter (Claude Code, Codex, Aider, OpenCode, Cline, Continue) reads the user's existing config, **snapshots** it, **rewrites** to a session-scoped path under `$XDG_RUNTIME_DIR/strata/sessions/<session>/`, launches the agent with `CLAUDE_CONFIG_DIR=…` (or `--settings`, or `--config`, per host), and **deletes** the session path on exit. The user's `~/.claude/settings.json` is never modified — verified by checksum on `strata uninstall`. The mermaid (§8.3) is concrete. **The honest disclosure is the best part:** *"Strata mediates Claude Code only when launched via `strata agent run claude-code`. Running `claude-code` directly bypasses Strata, by design."* That single sentence kills the v2 hand-wave.

§8.3.1 lists six adapter crates, each owning its host's snapshot/rewrite/cleanup logic. The pattern is replicable. Critic A's SPOF concern (#10) is preserved via per-session sharding.

### B-S-NEW-1 — manifest `implied_tier` → **FIXED**
§4.4 example now declares both `tier = 3` and `implied_tier = 3` with an inline comment showing the math (`max(2, 3, 1) = 3`). New §4.4.1 walks **three worked cases**: under-declared (auto-rejected at install with quoted error message), over-declared (allowed; tier as *ceiling*; powerbox shows `Declared tier: 3 / Actual tier: 2`), runtime-kind lie (rejected at parse and re-rejected at instantiation). All three are property-tested in `strata-manifest`. This is the "trivial fix, big DX win" I asked for and the architect did the over-declared case I didn't think of, which is the right one to think of (authors will reserve future tier headroom).

### B-S-NEW-2 — global `max_tier_allowed` → **FIXED**
§9.4 `config.toml` now contains `[security] max_tier_allowed = 5`. New §9.4.1 specifies install-time rejection, runtime suspension on upgrade-past-cap, hot-reload semantics that refuse to orphan running plugins, and a use-case table (default desktop = 5, household kiosk = 3, enterprise laptop = 2, pure-Wasm research box = 1). Quoted error message names the policy and the file path. Excellent.

### B-S-NEW-3 — Tailscale failure UX → **FIXED**
§9.1.1 ladder: 7 failure modes (binary missing, NeedsLogin, multi-profile, offline, Stopped, MagicDNS-disabled, shared-tailnet warning), each with **a literal message, a remedy, and a sysexits exit code** (64/65/75/0). Post-pairing `tailscale logout` handled in §6.1.1 + §9.1.1: liveness loop detects within 30s; biscuit caps survive the logout because they're signed by Strata's Ed25519 key, not Tailscale's WireGuard key — that detail is the right cryptographic answer. Mirrors §6.3's pairing UX rigor exactly as I asked.

§6.1.1 also resolves the "tailnet flap on tailscaled reload" false positive with hysteresis (state must persist two consecutive 5s polls).

### B-name-collision → **FIXED**
§0.1.1 audit table: `crates.io/crates/strata` named taken (alpenlabs Stratum-protocol crate, 2023), Strata Identity collision named explicitly (`strata.io` permanently avoided), GitHub `strata` user account named, Homebrew tap path standardized to `strata-dev/tap`. **The `strata-*` prefix policy is the right answer** (Tokio/Bevy/Embassy/Yew pattern); cargo plugin is `cargo-strata` (per `cargo-*` convention). Placeholder crate reservation at start-of-Phase-0 prevents typo-squatting. `docs/legal/name-audit.md` re-run yearly. `strata.dev` confirmed owned with DNSSEC. Marketing copy disambiguation from Strata Identity called out.

This is more thorough than I expected.

### B-hello-world → **FIXED (4-of-4 stuck points)**
§9.3 walked end-to-end:
1. **Tap consistency:** `strata-dev/tap/strata` (was `thekozugroup/strata/strata`); §9.1, §9.3, and §0.1.1 all use the same path. ✓
2. **`cargo-strata` install path:** "`cargo install cargo-strata`" canonical from crates.io (reserved at start-of-Phase-0); brew tap path also documented. ✓
3. **WIT file shown:** full `wit/world.wit` with `package alice:hello-world@0.1.0`, `world hello-world`, `interface echo/lifecycle/log` definitions. ✓
4. **Package step:** `cargo strata package` is now a first-class step between `build` and `sign` with quoted output (`'Packaged: target/strata/hello-world-0.1.0.tar.zst (4,209 bytes)'`). ✓

Plus: full `Cargo.toml`, `strata.toml`, `src/lib.rs` shown. **CI-tested end-to-end on every commit, multi-OS** (macOS, Linux x86_64, Linux aarch64, WSL2). A failing run blocks merge. That last commitment is what makes me believe the walkthrough won't bit-rot.

### B-Workload-A-streaming (`StreamingTask`) → **FIXED**
§7.1 `Task` is now an `enum { OneShot, Streaming }`. `StreamingTask` has `ChannelSpec` (inbound/outbound chunk schemas, `BackpressureMode::CreditBased { window: u32 } | Drop | Block`, `max_chunk_bytes`, `idle_timeout`), `PartialResultPolicy { accept_partial, minimum_useful_bytes }`, and `replication = 1, quorum = 1` validated at submit-time. The streaming RPC shape is shown in worked-example form (`StreamOpen` → `StreamAccepted` → `Chunk`/`Credit` interleaving → `StreamClosed`). §7.5 documents that streaming + `Integrity::Deterministic` is **rejected at submit-time** with a quoted error message. §7.5 also adds a full integrity-policy taxonomy (`Deterministic`, `SemanticEquivalent { metric, threshold }`, `TrustedExecutor { allowlist }`, `Attested { tee }` Phase-4-flag, `None`) — that's not strictly mine but it's the right answer for Critic A's #1 and it composes correctly with streaming. Workload A defaults to `TrustedExecutor`, which is the honest answer.

### B-S3 / B-S9 — bus factor → **FIXED in commitment, partial in proof**
§12.1 commits to:
- **Maintainer roster:** ≥2 named maintainers per L0/L1 crate. 3-letter placeholder roster table is in §12.1, to be filled at start-of-Phase-0.
- **Monthly rotation review:** 30-min meeting, output to `docs/governance/rotations.md`. Identifies any crate where one maintainer has done >80% of recent commits and rebalances.
- **Dual-control on signing keys:** Shamir 2-of-3 (two YubiKeys + offline officer share). No single person can sign a release.
- **Upstream OCI registry kill-switch:** `mirror.strata.dev` + IPFS pin + Hetzner mirror; **5-year prepaid hosting** if no foundation. `strata mirror set <url>` reconfigures without restart. Tarball-path users (§3.6 path B) immune by definition.
- **Incident-response chain:** `security@strata.dev`, PGP keys in `SECURITY.md`, 72h ack SLA, 90-day disclosure.

**This is the most concrete bus-factor commitment I've ever seen in a v3 spec.** It's not "the team is bigger than three" hand-waving — it's "the project survives any one of three people leaving without warning."

**Why I still hold 2 points** (kept at 9/10 differentiation, not 10/10): the mitigations are a process commitment, not a code commitment. Monthly rotation review and key ceremony rehearsal are exactly the kind of work that *seems* free at planning time and gets cut when Phase 1 is two weeks behind. I want to believe; bus-factor mitigations being "Phase-1 deliverables" rather than "Phase-2 to-do" is the right lever, and the spec pulls it. **8/10 → 9/10 is earned.** The last point is post-implementation evidence.

### B-M4 — i18n / a11y → **FIXED**
§9.4.2:
- **English-MVP for prose** (1.0 ships English; honest about the deferral to 2.0; gettext catalog reserved as `strata-i18n` crate).
- **i18n-stable structured error codes** (`STRATA-E0042`, etc.) — the codes are stable across versions and locales; `docs/error-codes.md` is the canonical translation surface. JSON log example shown.
- **Screen-reader pass per minor release** (VoiceOver on macOS, Orca on Linux). The `init` wizard avoids ANSI cursor games; QR code (§6.3) is presented with an accompanying SHA-256 hex line so it is fully usable without the visual code.
- **CI run with `--no-color --no-unicode`** to catch regressions.
- **Powerbox prompt deliberately minimal** — no tables, no animations.

This is the right stance. "Defer translation, commit to a11y" is honest.

---

## Verification of the v3-introduced sections

### §9.3 hello-world: walked it cold
I ran the commands in my head as a fresh user.

1. `brew install strata-dev/tap/strata` — works; tap path consistent throughout.
2. `strata keys gen --label "alice"` — writes `~/.config/strata/publishers/alice.key` + `.pub`. Output specified.
3. `cargo install cargo-strata` — published canonical path; placeholder reserved at start-of-Phase-0 (§0.1.1).
4. `cargo strata new hello-world` — generates 4 files, **all four shown in the spec body**: `Cargo.toml`, `strata.toml`, `src/lib.rs`, `wit/world.wit`. No more "what's in `world.wit`?" stuck point.
5. `cargo strata build` → wasm output specified. ✓
6. `cargo strata package` → `.tar.zst` output specified. ✓ **(was the v2 stuck point #4)**
7. `cargo strata sign --key alice` → `.sig` sibling specified. ✓
8. `strata trust add ed25519:abc... --label alice` → trust root populated. ✓
9. `strata install ./target/strata/hello-world-0.1.0.tar.zst` → installs.
10. `strata plugin start hello-world` + `strata logs hello-world` → expected output `"hello from hello-world"`.

**Zero stuck points.** I would type these 10 commands and reach the result. The commitment that this is **CI-tested on every commit, on macOS, Linux x86_64, Linux aarch64, WSL2, and a failing run blocks merge** is the part that prevents bit-rot.

One small nit (not grade-affecting): step 1 shows the brew path; the Linux `curl | sh` and Windows `winget` flows are also valid Phase-1 entry points, and the spec wisely focuses on one. Acceptable.

### §0.1.1 naming defense: did they avoid every collision they claim?
Yes, with one wart:
- ✓ `crates.io/strata` taken — addressed by `strata-*` prefix.
- ✓ Strata Identity (`strata.io`) — named, permanently avoided.
- ✓ GitHub `strata` user account — addressed by `thekozugroup/strata`.
- ✓ Homebrew tap consistency — `strata-dev/tap` everywhere.
- ✓ `strata.dev` ownership — claimed with DNSSEC.
- **Wart:** `strata-dev/tap` is *the org name* `strata-dev` plus tap-name `tap`. The audit says it "redirects to `github.com/thekozugroup/homebrew-tap`" — that's a Homebrew alias, not a re-registered org. If `strata-dev` GitHub org is *not* registered to thekozugroup, a malicious actor could register it and intercept the tap path. **Recommendation (not grade-affecting):** the audit should explicitly note `strata-dev` GitHub org is owned. Trivial fix; flagged below.

### §9.2 init wizard: edge cases
Walked four:
- **User has tailscale but logged out:** §9.1.1 row 2 (`NeedsLogin` → exit code 65 with literal `tailscale up` remedy). ✓
- **User opts for single-node mode:** §9.2 step 4 explicit branch; `strata init --single-node` flag bypasses pairing; daemon's startup re-validates the invariant. ✓ This was the §9.2/§11 #16 contradiction Critic A flagged and v3 resolves it cleanly.
- **User wants to add a peer 6 months later:** wizard says *"Run `strata pair --print-code` on this device"* — wizard is re-enterable. The spec says `strata config set mesh.tailscale.enabled true` re-runs the pairing prompt. Acceptable.
- **User has multiple Tailscale profiles:** §9.1.1 row 3 (multi-profile detection with `--tailscale-profile <name>` override). ✓

All four covered.

### §12.1 bus factor: realistic for OSS, or aspirational LARP?
**Half realistic, half aspirational** — and the spec is honest about which is which:

- **Maintainer roster** is a pure document discipline; trivial cost; high value. Realistic.
- **Monthly rotation review** is 30 min/month. Realistic if any of the three actually shows up. The discipline survives one bad month; it does not survive the team being underwater for Q3. Aspirational-leaning.
- **Shamir 2-of-3** is real cryptography; the rehearsal in Phase 1 is the proof step. Realistic.
- **Mirror + 5-year prepaid hosting** is the strongest commitment in the section. Realistic if the prepayment is actually made; aspirational if it's "we'll get to it." The spec says *"5-year prepaid hosting agreement initiated at 1.0"* — that's a Phase-1 ship-blocker. Realistic conditional on enforcement.
- **`security@strata.dev` + 72h ack SLA + 90-day disclosure** is text on a page until a real disclosure tests it. Aspirational until proven.

This is good for a 3-person OSS project. I've seen worse from organizations 100x bigger. Held 1 point on Differentiation (8→9, not 10) for the unprovable-on-paper portion.

### §9.5 maintenance plugin: concrete?
Yes. The split between kernel-internal `maintenance` (AOT cache GC, biscuit expiry sweeps, blob cache GC, log rotation, plugin pre-compilation on idle) and user-facing `device-maintenance` (auto-update, SMART, ZFS scrub, thermal events, key-rotation reminders, identity backup nag, Tailscale status, Borg/Restic verification, smartctl reports) is well-scoped. Phase-3+ deliverable. No new issue.

### §7.0 + §7.1 reference workloads + StreamingTask: do they fit the scheduler cleanly?
Walked Workload A end-to-end against §7.1+§7.4+§7.5:
- Submitter: laptop with `Integrity::TrustedExecutor { allowlist: ["abc12...desktop-nodeid"] }`. ✓
- Submit-time validation: streaming + TrustedExecutor is the only valid combo; spec says so explicitly. ✓
- Bidirectional QUIC over `strata/scheduler/1` ALPN; `Credit { add: 32 }` flow control. ✓
- Per-task biscuit on each `Chunk` envelope to prevent a misbehaving submitter injecting turns into someone else's stream. **Excellent detail.** ✓
- Latency budget <300ms first-token, ≥30 tok/s sustained. Pin remains in §7.0.

Workload B (deterministic image batch) and Workload C (test parallelization) fit the `OneShotTask` model unchanged from v2.1. The two workload types compose correctly with the `IntegrityPolicy` taxonomy.

**One subtle thing the architect got right:** `SemanticEquivalent` is rejected for streams at submit-time because per-chunk semantic equivalence is not the right granularity (the spec literally says *"you'd compare two whole streams against each other after both finish, which loses the streaming property"*). That sentence shows the architect actually thought about it instead of letting the type system pretend.

---

## New gaps I found in v3 (none critical, all minor)

- **M-NEW-V3-1: `strata-dev` GitHub org provenance.** §0.1.1 says the Homebrew tap is `strata-dev/tap` redirecting to `github.com/thekozugroup/homebrew-tap`. If the `strata-dev` GitHub org is not actually registered to thekozugroup, the redirect is a future supply-chain hole. Either register `strata-dev` and say so explicitly, or use `thekozugroup/tap` consistently. Trivial fix.

- **M-NEW-V3-2: Mirror trust path.** §12.1 mentions `mirror.strata.dev` as a kill-switch fallback. The mirror is "updated nightly from `ghcr.io`" and "runs read-only." That's fine for *availability* but the spec doesn't say whether the mirror's content is **publisher-signed** (so verification works the same way) or **mirror-signed** (so a mirror compromise breaks trust). The answer is presumably the former — every plugin is signed by its publisher's Ed25519 key, so the mirror can serve untrusted bytes without compromising verification — but the spec should say so out loud. Trivial fix in §12.1 paragraph 4.

- **M-NEW-V3-3: `cargo strata package` reproducible builds.** §9.3 promises a `.tar.zst` with a specific byte count. Packaging step doesn't say whether the `.tar.zst` is **bit-stable** across rebuilds (deterministic timestamps, sorted entries). For supply-chain audit and for hash-pinning, reproducible packaging matters. Either commit to `SOURCE_DATE_EPOCH` semantics or explicitly defer. Easy fix.

- **M-NEW-V3-4: `[security] max_tier_allowed` cannot be lowered while a higher-tier plugin is running** (§9.4.1). The spec says config-validate rejects orphaning configs. But if an operator wants to *eventually* lower the cap, they need a workflow: stop tier-5 plugins, edit config, reload. The spec doesn't show that workflow. Five lines of operator runbook would close this.

- **M-NEW-V3-5: Streaming partial-result attribution.** §7.1 `PartialResultPolicy` says `accept_partial: bool` and `minimum_useful_bytes: u32`. If a stream is interrupted at byte 8000 of a target 32000, who decides whether the partial is "useful"? The spec's wording is the *submitter* sets the policy and the *receiver* (submitter) gets a partial response. That's correct; what's missing is what happens to **billing/accounting** if a worker is paid by tokens or by wallclock — out of scope for MVP, but a footnote pointing forward to the future-work section on payments would be nice.

None of these are grade-affecting. All would land as "good first issues" once Phase 1 is open.

---

## What's improved (highlights that earned the grade jump)

1. **§14 v3.0 sub-changelog** mapping every code (B-C4-partial, B-S-NEW-1, B-S-NEW-2, B-S-NEW-3, B-name-collision, B-hello-world, B-Workload-A-streaming, B-S3/B-S9, B-M4 — plus all of A's new codes) to its fix section. **This is what a v3 should look like.** It is cheaper for the critic to verify the spec than to re-read it; that asymmetry is a gift to reviewers and is exactly the spec hygiene I want to see.
2. **§4.4.1 three-cases table** for `tier` vs `implied_tier` — the over-declared case is the one I didn't think of and the architect did. That's a sign of a real walk-through, not a fix-and-move-on.
3. **§7.5 IntegrityPolicy taxonomy** — composes with streaming correctly; submit-time validation is checked at the right place; the metric-plugin escape hatch (signed Wasm component implementing `compare(a, b) -> f64`) is the right architecture for "future workloads I haven't thought of yet."
4. **§8.3 configuration-adapter model** — the *honesty* about "running `claude-code` directly bypasses Strata, by design" is what makes me believe the gateway is real.
5. **§9.1.1 + §6.1.1 Tailscale ladder** — the cryptographic detail that biscuits survive `tailscale logout` because they're signed by Strata's key, not Tailscale's, is exactly the kind of correct thinking that distinguishes a thought-through spec from a list of features.
6. **§10.1 transitive-deps trust posture table** — wasmtime vendored, biscuit-auth pinned with internal audit, rustls everywhere (no openssl), each crate's posture (cargo-vet ✓ / partial / pinned / vendored) named explicitly. Goes well beyond "trust me bro."
7. **§12.1 Shamir 2-of-3 + 5-year prepaid mirror hosting** — concrete enough to test.
8. **§9.3 multi-OS CI-tested hello-world** — failing run blocks merge. This is the right enforcement.
9. **§9.4.2 i18n/a11y stance** — English-MVP + i18n-stable error codes + screen-reader-tested wizard. The "we won't fake it" framing earns trust.
10. **§9.2 single-node-vs-multi-node branch** — resolves the v2.1 §9.2/§11 #16 contradiction at every layer (init wizard, config validation, daemon start). This is the kind of invariant tracking I pay for.

---

## Verdict reasoning

v3 closes every blocker, every significant issue, and every minor I named in v2 except the unprovable-on-paper ones (Phase-1 timeline realism, bus-factor mitigations whose value depends on team execution). It introduces zero new criticals and only the five trivial minors named above. The §14 changelog is a model for spec revisions.

**Why not 100:**

- **Phase 1 timeline (4–6 months for a 3-person team)** still likely under-estimates by 2–4 months — same concern as v2. Spec acknowledges in §13 #2 (Component-Model async maturity) and the language "if we ship faster, great; we don't promise it" is honest. Held 2 points (Project scope realism stays at 8/10).
- **Bus-factor mitigations are commitments not proofs** — earned 9/10 on Differentiation (was 8/10 in v2) but not 10/10. The last point is post-Phase-1.
- **Five minor docs gaps named above** (`strata-dev` GitHub org provenance, mirror signing path, reproducible `cargo strata package`, `max_tier_allowed` lower-workflow, streaming partial-result attribution). Trivial individually. Total cost: 1 point off Operator DX (14/15) and 1 point off Plugin DX (15/15 only by the skin of its teeth — held the full 15 because the four B-hello-world stuck points are decisively closed).

**100 = "ship Monday morning with zero ambiguity blockers."** v3 ships Monday morning with zero blockers. The 5 points withheld are the realism tax on the timeline plus the can't-prove-it-on-paper portion of bus factor. Those are *exactly* the kind of points the architect cannot earn without writing code. v3 acknowledges this in the "Path to 100" footer — and they're right.

**To reach 100 in a future revision (or, more realistically, post-Phase-1):**

1. Phase 1 ships in claimed 4–6 months OR the spec is updated to 6–8 with explicit slack budgeted (close S-NEW-V3 timeline gap).
2. First Shamir 2-of-3 release ceremony rehearsal happens (closes one of the bus-factor proof items).
3. The five minor docs gaps above are closed.
4. The CI-tested hello-world has run on green for 4 weeks consecutively (closes the bit-rot risk).
5. First real `security@strata.dev` disclosure tested (or rehearsed).

**Critic B**
Field expert in DX, operations, product viability
Default verdict: this could ship to a 3-person team Monday and they would not be blocked by the spec.
