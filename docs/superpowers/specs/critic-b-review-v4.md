# Critic B Review — Architecture v4 (Strata)

**Final grade: 99/100**
**Verdict: APPROVE — ship Monday morning.**

v4 closes every minor I held v3 at and converts the unprovable-on-paper portions of bus-factor and Phase-1 timeline into checkable, falsifiable statements. The architect did three things I have rarely seen in a v4: (1) decomposed a 4–6-month timeline into six month-by-month gates with concrete labeled GitHub issues and a slip policy that says *"if month 6 is missed, the spec was wrong"*; (2) reframed bus factor from "≥2 humans named" (commitment) to **INV-BUS-1** (an invariant a CI job can falsify weekly); (3) wrote 31 GIVEN/WHEN/THEN acceptance criteria, each with a crate-test path. The remaining 1 point is reserved for the post-Phase-1 evidence that the M1–M6 schedule actually held — that point cannot be earned on paper by anyone, ever, and v4 acknowledges it via the slip policy.

---

## Rubric scores

| # | Area | Weight | v2 | v3 | v4 | Δ vs v3 |
|---|---|---|---|---|---|---|
| 1 | Install + first-run UX | 20 | 17 | 20 | **20** | 0 |
| 2 | Plugin author DX | 15 | 12 | 15 | **15** | 0 |
| 3 | Operator DX | 15 | 13 | 14 | **15** | +1 |
| 4 | Permission/grant UX (powerbox) | 10 | 9 | 10 | **10** | 0 |
| 5 | Mesh onboarding | 10 | 8 | 10 | **10** | 0 |
| 6 | Project scope realism (<6 mo, small team) | 10 | 8 | 8 | **9** | +1 |
| 7 | Differentiation | 10 | 8 | 9 | **10** | +1 |
| 8 | Naming / mental model | 5 | 4 | 5 | **5** | 0 |
| 9 | Spec/document clarity | 5 | 7* | 5 | **5** | 0 |
| **Total** | | **100** | **86** | **95** | **99** | **+4** |

The +1 on Operator DX comes from §9.4.1's interactive-lowering prompt + ATC-MAX-1/2/3 acceptance tests. The +1 on Project scope realism comes from §12's M1–M6 monthly schedule with falsifiable gates and an explicit two-month-slip policy. The +1 on Differentiation comes from INV-BUS-1's CI enforcement (`.github/workflows/bus-factor.yml` weekly), which is the first time I've seen bus factor turned into a *check* rather than an aspiration.

---

## Prior-issues status (every code from the v3 review)

### B-mirror-signing-path → **FIXED**
§12.1 has the four-row table that nails it: artifact bytes are *relayed*, mirror-listings are *signed by the mirror*. The invariant is one sentence — *"the mirror is a CDN, not a CA"* — and ATC-MIR-1 enforces it via `crates/strata-signing/tests/mirror_cdn_only.rs::no_mirror_in_artifact_trust`. Listings are signed with `ed25519:strata-mirror-2026` for enumeration integrity only. ATC-MIR-2 verifies the listing path. This is the answer.

### B-reproducible-packaging → **FIXED with rare ambition**
§9.3 commits to byte-identical `.tar.zst` across hosts. The seven-row determinism table (SOURCE_DATE_EPOCH, deterministic tar entries, zstd level 19 single-thread, Cargo.lock required, pinned WIT versions, pinned toolchain, LC_ALL=C/TZ=UTC) is the right list. ATC-PKG-1 (serial double-build) and ATC-PKG-2 (cross-host matrix on macOS-14 + Ubuntu-22.04 + Ubuntu-24.04) are exactly the tests you'd write. Reproducibility regression = P0 release-blocker. **Has anyone shipped this in Rust beyond rustc itself?** Honestly: yes — `cargo-vet`, `wasm-tools`, and recently `cargo-component` have all shipped reproducible packaging in their CI. It is *uncommon* but it is *not* unprecedented; the spec's mechanism (SOURCE_DATE_EPOCH + sorted tar + single-threaded zstd + pinned toolchain) is the proven recipe and is what `nixpkgs`, `arch-rebuild`, and `Reproducible-Builds.org` use. The cross-host matrix in ATC-PKG-2 is the part that catches non-deterministic dep-tree resolution; that's the right test. **Realistic.**

### B-max_tier-lower-workflow → **FIXED**
§9.4.1 walks the lowering flow end-to-end. I walked it cold:
1. Operator runs `strata config reload` after editing config from 5→3.
2. Daemon parses, computes delta set: `{agent-host-claude-code (tier 5, 1h17m uptime), cuda-runner (tier 4, 22h uptime)}`.
3. Reload pauses; the literal prompt block is in the spec verbatim.
4. Default `[u]` unloads-and-disables (graceful drain via `task_timeout` → unload → `enabled = false` in config so it doesn't resurface).
5. `[c]` cancels and reverts the edit.
6. Scripted path `strata security set-max-tier 3 --force-unload` writes audit log AND prints to stderr — explicit "no flag silences the audit trail."
7. ATC-MAX-1/2/3 cover prompt + force + cancel.

UX is clean. **Default = unload-and-disable**, prompt is interactive, scripted has loud audit. The "no silent" invariant is testable (ATC-MAX-2 asserts stderr contains the affected list).

### B-strata-dev-org-provenance → **FIXED**
§0.1.1 names `strata-dev` GitHub org explicitly, lists the surfaces it owns (monorepo, homebrew-tap, github.io site, every `strata-*` crate, sigstore identity `strata-dev@strata.dev`), and commits to ≥3 maintainers + hardware MFA + branch protection + signed-commits-required + secret-scanning + dependency-review. The defense-in-depth signature stack (Ed25519 primary + cosign/Rekor secondary, with `[trust] require_cosign = true` defaulting on for `max_tier_allowed <= 3`) is more than I asked for and the right answer. The `docs/governance/org-policy.md` reference is concrete.

### B-streaming-partial-result-attribution → **FIXED**
§7.1's `SignedChunk` carries `(seq, bytes, ts, executor_node_id, signature_over_(task_id || seq || ts || sha256(bytes)))`. ATC-STR-3 verifies forged-chunk rejection. The submitter accumulates a tamper-evident transcript — input to billing (pay-per-token federated mesh), audit (which peer produced half-output), and reputation downranking. Closes §11 #19 false-attribution attack: a submitter can't fabricate "this peer gave me bad output" without forging a valid signature chain. Chunk-signing overhead at ~50µs/chunk is amortized; verification is async and doesn't gate UI rendering. **Excellent.**

---

## Verification of the new v4 sections

### §12 monthly schedule M1–M6: walked it, checked for hand-waves
**Verdict: concrete throughout.** I walked each month asking "is this a hand-wave or is this a labeled GitHub issue I could open today?":

- **M1 Skeleton:** 5 issues — `stratad` boots/parses config/drops privileges/idle-loops, `strata-core` plugin host shell, WIT contracts published as 0.0.1, CI matrix on macOS+Ubuntu-24.04+WSL2, `crates.io` placeholder reservations. **All actionable.** Done-gate: "no-op plugin loads, lifecycle hooks fire, daemon shuts down cleanly. CI green." Falsifiable.
- **M2 Manifest + signing:** 5 issues — `strata-manifest` per §4.4 (incl. `implied_tier`), `strata-signing` Ed25519 + cosign + Rekor, `strata keys gen`, `strata trust add`, cosign defense-in-depth verifier with `[trust] require_cosign` flag, name-collision audit committed. Done-gate: signed manifest parsed, sig verified two ways, rejection vectors covered. **Concrete.**
- **M3 Capability broker + powerbox:** 5 issues — broker handle issuance/revocation, `storage.local`/`system.clock`/`system.entropy` host impls, Wasmtime embedding with `wasi:io@0.2`/`wasi:filesystem@0.2`, powerbox CLI prompt with `[Y]es/[n]o/[c]ustomize/[l]earn-more`, tier-vs-capability property test on 10k random manifests. Done-gate: tier-1 plugin reads sandbox, can't read `~/`, property test passes, powerbox accessible per §9.4.2. **Concrete.**
- **M4 Distribution + install + reproducibility:** 6 issues — `strata-oci` with sigstore verification, `strata-https-fetch` tarball + detached `.sig`, `cargo-strata` (build/package/sign/publish/verify-rebuild), reproducible-packaging CI per §9.3 (`SOURCE_DATE_EPOCH`, deterministic tar), `strata install` + `strata pack` + `.stratapack` import, bridge-vector test scaffolding. Done-gate: byte-identical `cargo strata package` cross-host. **Concrete; M4 is the hardest month — reproducibility CI on a fresh codebase is a real lift, but it's the right work.**
- **M5 Operator DX + hello-world + max_tier:** 6 issues — `strata logs/diag/doctor/wrapper {enable,disable,repair,status}`, Prometheus + OTEL, `max_tier_allowed` lowering with prompts, `strata backup/restore`, hello-world walkthrough §9.3 CI-tested every commit, `strata init` wizard incl. screen-reader pass on Orca + VoiceOver. Done-gate: walkthrough green on macOS+Linux+WSL2, `strata doctor` clean, `max_tier_allowed` lowering prompts. **Concrete.**
- **M6 Hardening + 1.0 RC:** 5 issues — 2-of-3 Shamir release-key rehearsal (live ceremony documented), §16 acceptance criteria all green, docs site `docs.strata.dev` + `strata-dev.github.io` published, `mirror.strata.dev` 5-year prepaid hosting contract signed (receipt in `docs/governance/`), 1.0 RC with cosign + Ed25519 sigs + security-disclosure SLA rehearsal. Done-gate: §16 all 31 tests green on CI, RC verifiable by independent rebuild, rotation review notes filed for months 1–6. **Concrete.**

The slip policy is the part that earns the +1: "one-month slip is acceptable; two-month slip means we update the spec honestly with revised estimates and publicly move the 1.0 ship date." That sentence — combined with the fallback document `docs/risk/phase-1-fallbacks.md` for the highest-risk M3/M4 items (Component-Model async maturity, cargo-component stability) — is the difference between "trust me" and "we will mark our own homework in public." **Realistic, falsifiable, honest.**

### §12.1 INV-BUS-1: realistic for OSS pre-launch?
**Realistic — and this is where I underestimated v3.** The 5-role table (core-runtime-lead, mesh-lead, agent-lead, security-lead, release-lead) with **min holders = 2 each** and onboarding doc paths is the right shape. But what makes it actually checkable is **INV-BUS-1**:

> `∀ role ∈ {core-runtime, mesh, agent, security, release}. |active_holders(role)| ≥ 2`

with active = ≥1 merge into a primary-role-owned crate in trailing 60 days. CI surface: `.github/workflows/bus-factor.yml` weekly, computes the count from git log + CODEOWNERS, opens P0 if any role drops below 2. ATC-BUS-1 enforces it. **A release MUST NOT ship if the most recent rotation note is >35 days old or shows a role with <2 active holders** (ATC-BUS-2).

**Is recruiting ≥2 holders for 5 roles (i.e. 10 active maintainers) before launch realistic for an OSS project?** Honestly: it is the **upper bound of plausible** for a 3-person founding team. With 3 founders, each person necessarily holds multiple roles in early phases (the table allows this — it's "≥2 holders per role," not "10 distinct people"). Two founders covering core + release + security as primary/co between them is realistic; one founder pulling mesh + agent as primary with the third as co is realistic. The risk is the 60-day-activity bar: if a founder takes a 3-month sabbatical, INV-BUS-1 fails for whichever role they were the only active holder of. v4 is honest about this — the slip is detected, P0 issue opens, release blocks. **That is the correct behavior;** the alternative is silent bus-factor erosion. **Realistic, with the honest acknowledgment that "active" is the load-bearing word.**

The placeholder roster (letters A/B/C in the table) committed at start-of-Phase-0 in `MAINTAINERS.md` and CODEOWNERS-enforced is the implementation primitive. Combined with monthly rotation review (output to `docs/governance/rotations.md`), this is the most concrete bus-factor regime I've seen in any v4 OSS spec.

### §16 acceptance criteria: 5 picks, verifying testability

I picked five:

1. **ATC-MAN-1 (tier under-declared rejection):** `GIVEN strata.toml with tier=1 and capability min_tier=3 / WHEN strata-manifest::validate(manifest) / THEN Err(Error::TierUnderDeclared { cap, min_tier: 3, declared: 1 }) / TEST crates/strata-manifest/tests/tier_check.rs::tier_under_declared`. **Testable.** Constructable manifest fixture, deterministic call, exact error variant matched. No vagueness.

2. **ATC-PKG-2 (cross-host reproducibility):** `GIVEN hello-world fixture / WHEN cargo strata package on macOS-14 + Ubuntu-22.04 + Ubuntu-24.04 with pinned toolchain / THEN sha256 identical across all three / TEST .github/workflows/reproducibility.yml::cross_host_matrix`. **Testable.** Matrix workflow, deterministic input, byte-comparison output. The hardest test to *implement* — but the easiest to *verify*: hashes match or they don't.

3. **ATC-INT-1 (verifier-locality, no worker metric execution):** `GIVEN SemanticEquivalent task with metric_cid=X and 3 worker peers / WHEN task executes end-to-end / THEN no worker instantiates a wasm component matching X (verified via wasmtime trace) AND submitter instantiates X exactly once per pair-comparison / TEST crates/strata-plugin-scheduler/tests/integrity/no_worker_metric_execution.rs`. **Testable** — wasmtime trace is observable, instantiation count is countable. The "exactly once per pair-comparison" needs a concrete pair-count; the spec has 3 workers, so for `quorum=2`, that's 1 pair (the 2 successful results); for quorum=3, that's 3 pairs. The test's expected value should be parameterized — I'd flag this as "needs implementer to pin parameterization in the test fixture" but it is not a spec gap.

4. **ATC-STR-1 (credit-exhaustion stall):** `GIVEN StreamingTask with task_timeout=5s and submitter that issues no Credit frames after initial window / WHEN worker exhausts credits / THEN within 5s ± 0.5s the worker emits StalledEvent and transitions to state=Stalled / TEST crates/strata-plugin-scheduler/tests/stream_stall.rs::credit_exhaustion_stalls_at_timeout`. **Testable.** Timing tolerance is named (±0.5s — wide enough for non-flaky CI, tight enough to catch real bugs). State transition is observable.

5. **ATC-BUS-1 (INV-BUS-1):** `GIVEN git log + CODEOWNERS at HEAD / WHEN .github/workflows/bus-factor.yml runs (weekly + per-release) / THEN for every role, |active_holders(role)| ≥ 2 (active = ≥1 merge in trailing 60d) AND if any role drops below 2 a P0 GitHub issue is opened / TEST .github/workflows/bus-factor.yml::invariant_check`. **Testable.** Pure-function over git history + CODEOWNERS. The P0-issue-opens side effect is the part the workflow has to actually do; I'd want to see the workflow YAML to confirm the issue-creation API is wired, but the proposition is well-formed.

**Verdict on all 31:** I spot-checked five; none vague. The naming convention (`ATC-{BUCKET}-{N}`) is consistent. Each has a `TEST` line pointing at a concrete file path. The acceptance summary (4+4+4+4+3+3+3+2+2+2 = 31) tallies. The closing assertion — *"Phase 1 is 'done' iff all 31 propositions pass on CI. No proposition relaxes; if a proposition cannot be implemented as written, the spec is wrong and the next revision documents the change"* — is the right kind of self-binding statement.

---

## New gaps I found in v4 (none critical, none grade-affecting)

- **N-NEW-V4-1 (trivial):** ATC-INT-1's "exactly once per pair-comparison" implies a parameterization that isn't stated explicitly in the proposition. Not a spec gap; flag for the implementer's test fixture to pin (e.g. assert `instantiation_count == binomial(quorum, 2)` for the metric pair count).

- **N-NEW-V4-2 (trivial):** §12 M6 commits to `mirror.strata.dev` 5-year prepaid hosting contract signed by month 6. The `docs/governance/mirror-receipt.md` is the proof artifact. If the foundation forms before month 6, the receipt is replaced by foundation-funded hosting; the spec should note that swap path explicitly (it's implicit in §12.1's continuity guarantee but not in the M6 deliverable wording).

- **N-NEW-V4-3 (trivial):** ATC-BUS-1 surfaces `.github/workflows/bus-factor.yml` but the spec doesn't fully specify how `active_holders(role)` is computed across multi-role overlaps (e.g. a person who is co-maintainer of `strata-core` (core-runtime role) AND `strata-signing` (security role) — a single merge to `strata-core` activates them for core-runtime but not security). The spec implies per-role activity, which is correct for the invariant; one sentence in §12.1 confirming "activity is computed per role, not aggregated across roles" would close any ambiguity.

None grade-affecting; all "good first issue at v5."

---

## What's improved (the +4 over v3)

1. **§12 monthly schedule M1–M6 with labeled GitHub issues + slip policy** (Project scope realism +1). The slip policy — *"two-month slip means the spec is honestly updated with revised estimates and the 1.0 ship date is publicly moved"* — is the part that converts an estimate into a falsifiable claim.

2. **§12.1 INV-BUS-1 with weekly CI enforcement** (Differentiation +1). Bus factor went from "we commit to ≥2 holders" (a process commitment) to `∀ role. |active_holders(role)| ≥ 2` enforced by `.github/workflows/bus-factor.yml`. **This is the first time I've seen a project propose to literally check its own bus factor.** ATC-BUS-1 + ATC-BUS-2 pin it down.

3. **§9.4.1 interactive lowering workflow + ATC-MAX-1/2/3** (Operator DX +1). Default unload-and-disable, prompt with affected-plugin list, scripted path with mandatory audit log. The "no flag skips the audit trail" sentence is the right invariant.

4. **§16 31 acceptance criteria** (raises the floor on every other rubric line). Every prior-issue fix now has a corresponding test path. This is what "shippable" looks like.

5. **§9.3 reproducible packaging with cross-host CI matrix** (ATC-PKG-2 closes the byte-identical gap). The seven-row determinism table is the right list.

6. **§7.1 SignedChunk transcript** closes false-attribution at the wire level. ATC-STR-3 verifies forgery rejection.

7. **§0.1.1 strata-dev org with ≥3 maintainers + hardware MFA + cosign** is more than I asked for. The `[trust] require_cosign = true` default-on for `max_tier_allowed <= 3` is the right policy gradient.

8. **§12.1 mirror-as-CDN four-row table** kills the parallel-trust-root concern in two paragraphs. ATC-MIR-1/2 enforce the boundary.

---

## Verdict reasoning

v4 closes **every** named v3 minor (B-mirror-signing-path, B-reproducible-packaging, B-max_tier-lower-workflow, B-strata-dev-org-provenance, B-streaming-partial-result-attribution) with concrete spec language AND a corresponding acceptance criterion in §16. It introduces zero new criticals. The §12 M1–M6 schedule + slip policy + §12.1 INV-BUS-1 + §16 31 propositions convert what were "post-Phase-1 evidence" reservations in v3 into "checkable-on-paper-via-CI-gates" statements in v4.

**Why 99 not 100:** The single point withheld is **not** a spec gap. It is the realism tax that cannot be paid on paper by anyone: did the M1–M6 schedule actually hold, or did month 4 slip into month 6 and cascade? That is the post-Phase-1 evidence that closes the last point, and v4's slip policy is the right way to handle it — slip is detected, recorded, the spec is honestly updated, and the 1.0 ship date is publicly moved. **No paper artifact can earn the 100th point**; only running M1, M2, M3, M4, M5, M6 on green can. v4 acknowledges this implicitly by making the slip policy public and falsifiable.

**100 = "ship Monday morning AND the team has demonstrated Phase 1 is achievable on the named timeline."** v4 ships Monday morning with zero blockers. It earns 99/100 because the only remaining doubt is execution risk, and execution risk is what the slip policy converts from "hidden" to "public." That is the maximum a spec author can do.

**To reach 100 in a future revision (post-Phase-1, not earlier):**
1. Phase 1 1.0 RC ships within month 6 of Phase-0 start, OR slips in accordance with the slip policy with a v5 retrospective.
2. The first Shamir 2-of-3 release ceremony rehearsal completes in M6 with `docs/governance/key-ceremony.md` published.
3. INV-BUS-1 has held green for ≥3 monthly rotation cycles.
4. First real `security@strata.dev` disclosure (rehearsal counts).

**Critic B**
Field expert in DX, operations, product viability
Default verdict: this is what a v4 looks like when the architect treats critic feedback as input to the design rather than threat to the design. **Approve. Ship.**
