# Phase-1 fallback register and slip policy

Spec: `docs/architecture.md` §12 ("Each has a documented fallback in
`docs/risk/phase-1-fallbacks.md`"). This file holds three things: the
**fallbacks** for the highest-risk Phase-1 items, the **slip policy** (§12.2),
and a **status table** of every §12 milestone deliverable against the code.

The status table describes the repository at commit `fab3eca` plus this
branch's observability work. It was written from `STATUS.md` and the code, not
from the issue tracker (none is reachable from the repository), so "done"
means "present in the code and tested here". Nothing is tagged or released;
CI-only checks (cross-host reproducibility, real cosign) are marked as such
because they have not been run from this repository.

Legend: **Implemented**, **Fell back** (shipped a documented alternative),
**Deferred** (not started or not complete, with the reason), **Unverified**
(cannot be checked from the repository).

## 1. Critical-path dependencies and their fallbacks

The spec names three: Wasmtime async maturity (M3), `cargo-component`
stability (M4), and `cargo entangle` plumbing (M4).

| Risk | Fallback the spec describes | What happened | State |
|---|---|---|---|
| **Wasmtime async / Component-Model async** (M3) | Sync-only host with a documented latency cost | Not needed. The host uses Wasmtime 43 (`component-model`), where async is always on: `instantiate_async` / `call_run(..).await`, per-invocation resource limits and epoch/timeout watchdogs (`crates/entangle-host`). Streaming plugins use host-side chunk channels (`stream-plugin` world), not guest async. | Primary path works; fallback unused |
| **`cargo-component` stability** (M4) | Build plugins without it | Taken. Plugins are plain `cargo build --target wasm32-wasip2` crates against `entangle-sdk` and the WIT in `entangle-wit`; `entangle plugins build` drives cargo directly (`crates/entangle-cli/src/cmd/package.rs`). The `wasm32-wasip2` target is installed in CI. | Fell back |
| **`cargo entangle` plumbing** (M4) | n/a in the spec; a separate `cargo-entangle` crate | Folded into the main CLI: `entangle plugins new/build/verify/publish`, with `cargo xtask plugin build` delegating to it so there is one implementation. No `cargo-entangle` crate exists and none is reserved on crates.io from this repository. | Fell back |

Other fallbacks taken that the spec does not list as critical path:

* **Tier-5 sandbox on macOS and via bubblewrap**: profiles are generated and
  unit-tested, but only Landlock/seccomp/namespaces run for real (Linux).
  `entangle-sandbox/tests/seatbelt_smoke.rs` exists for macOS CI; no result is
  recorded. Hosts without a usable sandbox refuse tier-5 plugins unless
  `[security] allow_unsandboxed_native` is set.
* **`mesh.iroh` without pkarr**: peers are dialled from `[scheduler] peers`.
* **`Attested` integrity**: returns `ENTANGLE-E0304`; needs TEE hardware.
* **Native Windows**: not started; WSL2 only (Phase 5 in the spec).

## 2. Slip policy (§12.2)

At the end of each month, every deliverable in that month's row is either
green or recorded here with a reason.

1. **One-month slip** is acceptable. Record it in the status table (state
   *Deferred*, with the reason and the month it moves to). The next month's
   slack absorbs it.
2. **Two-month slip** means Phase 1 will not finish by month 6. The spec is then
   **updated honestly**: revised estimates in §12, the 1.0 date moved publicly,
   and no retrospective copy may say "4–6 months" if the ship is at month 8.
3. A deliverable that cannot be done as written is **replaced, not dropped
   silently**: add a row to section 1 (what the fallback is, what it costs) and
   amend the spec text in the same change, as `architecture.md` §9.3 does with
   its "As implemented" paragraph.
4. A regression in a **reproducibility** check is a P0 release-blocker
   (`docs/release/reproducibility-checklist.md`); a role dropping below two
   holders opens a P0 issue (`.github/workflows/bus-factor.yml`). Neither is a
   slip: they stop the release.
5. Fallbacks are tracked as GitHub project items, not left implicit; each row in
   section 1 should link its item once the project exists.

Current slip: the schedule in §12 cannot be evaluated against dates (no
tracker, no tag). Items below marked *Deferred* are the ones that would have to
be scheduled or cut for a 1.0.

## 3. Milestone status

### M1 — Skeleton

| Deliverable | State | Notes |
|---|---|---|
| `entangled` boots, parses `config.toml`, idle-loops | Implemented | `crates/entangle-bin` (UDS RPC, maintenance loop, `/metrics`). |
| `entangled` drops privileges | Deferred | No setuid/setgid code. `packaging/entangled.service` runs it as `User=entangle`. |
| `entangle-core` skeleton + plugin host shell | Implemented | `entangle-core` (fault isolation: panic hook, core-task supervisor), `entangle-host`, `entangle-runtime`. |
| WIT contracts `entangle:plugin/lifecycle@0.1.0` published as crates 0.0.1 | Deferred | WIT lives in `entangle-wit` (`entangle:plugin@0.1.0`, `entangle:integrity@0.1.0`); nothing is published. The `init` / `activate` / `idle` / `shutdown` lifecycle exports are not implemented (runtime lifecycle is host-side; see STATUS). |
| CI matrix green on macOS, Ubuntu-24.04, WSL2 | Fell back | `ci.yml` runs ubuntu-24.04 and macos-14. No WSL2 job. |
| `crates.io` placeholder reservations | Unverified | Cannot be checked from the repository. |

### M2 — Manifest + signing

| Deliverable | State | Notes |
|---|---|---|
| `entangle-manifest` parses `entangle.toml` incl. `implied_tier` | Implemented | Includes `[lifecycle]`. The tier rule is covered by a 10 000-case property test (`crates/entangle-manifest/tests/tier_property.rs`). |
| `entangle-signing`: Ed25519 + cosign + Rekor | Fell back | Ed25519 publisher signatures on every plugin package. Cosign and Rekor are used for **release** artifacts (`entangle release verify`, `release.yml`), not for plugin packages. |
| `entangle keys gen`, `entangle trust add` | Fell back | `entangle init` generates the identity; `entangle keyring add/list/remove` is the trust root. Names differ from the spec. |
| §0.1.1 cosign defence-in-depth for plugins; `[trust] require_cosign` | Deferred | No `require_cosign` setting. Release verification pins the cosign identity to the tag. |
| Name-collision audit `docs/legal/name-audit.md` | Deferred | The file does not exist. |

### M3 — Capability broker + powerbox

| Deliverable | State | Notes |
|---|---|---|
| `entangle-broker`: issuance, revocation | Implemented | Deny by default, audit log, live revocation, `[security] deny_capabilities`, `entangle perms`. |
| `storage.local`; `system.clock`, `system.entropy` | Implemented | `storage.local` and shares via WASI preopens. Clock and entropy come from WASI 0.2 (`wasmtime-wasi`) and are not separate broker capabilities. |
| `entangle-host` Wasmtime embedding with WASI 0.2 | Implemented | |
| Powerbox CLI prompt (`[Y]es/[n]o/[c]ustomize/[l]earn-more`, §4.6) | Deferred | No powerbox. Capabilities are declared in the manifest and granted by the broker at load; `max_tier_allowed` lowering has its own prompt (`entangle security set-max-tier`). |
| `tier_required = max(cap.min_tier)` property test (10k manifests) | Implemented | `tier_property.rs`: implied tier equals the max, adding a capability never lowers it, under-declaration fails exactly when declared < implied. |

### M4 — Distribution + install + reproducibility

| Deliverable | State | Notes |
|---|---|---|
| `entangle-oci` fetch with signature verification | Implemented | Push/pull, digest and size checks, signed mirror listings (they expire; rollback protection is not implemented). No test performs a TLS handshake. |
| `entangle-https-fetch` tarball path + detached `.sig` | Deferred | No such crate at this commit (the budget file `docs/trust-footprint.toml` lists it as not yet present). |
| `cargo-entangle` build/package/sign/publish/verify-rebuild | Fell back | `entangle plugins build/publish/verify --rebuild` (see section 1). |
| Reproducible-packaging CI (`SOURCE_DATE_EPOCH`, deterministic tar) | Implemented | `reproducibility.yml`. The local tests check one host; the three-host comparison runs only in CI. See `docs/release/reproducibility-checklist.md`. |
| `entangle install`, `entangle pack`, `.entanglepack` import | Deferred | Neither command exists; `plugins install NAME` and `plugins install oci://…` do. |
| Bridge-vector test suite scaffolding | Implemented | Bridge biscuits (`entangle-biscuits`), `ENTANGLE-E0420`–`E0425`. |

### M5 — Operator DX + hello-world walkthrough + max_tier

| Deliverable | State | Notes |
|---|---|---|
| `entangle logs` | Implemented | Per-plugin and per-subsystem in-memory buffers over RPC (`docs/operations.md` §14d); memory only, not persisted. |
| `entangle diag`, `entangle doctor` | Implemented | `diag mesh [--probe]`; `doctor` runs 13 checks. |
| `entangle wrapper {enable,disable,repair,status}` | Implemented | The first-run wrapper prompt is not (no `entangle install`). |
| Prometheus `/metrics` + OpenTelemetry exporter | Implemented | Metrics endpoint off by default; OTLP/HTTP JSON, `http://` endpoints only. `entangle trace task` is also implemented (§9.6). |
| `[security] max_tier_allowed` incl. lowering workflow | Implemented | `security set-max-tier`, `config reload`, ATC-MAX-1..3. |
| `entangle backup` / `restore` | Implemented | Plugin data directories are not archived (deviation recorded in §9.6). |
| Hello-world walkthrough CI-tested on every commit | Fell back | `ci.yml` builds hello-world to wasm and `entangle-cli` tests run a daemon end to end; the full walkthrough as written (install, `plugin start`, `entangle logs`, log line equality) is not a CI job, and macOS/WSL2 are not all covered. |
| `entangle init` wizard incl. screen-reader pass | Unverified | The wizard exists (`dialoguer`, `--non-interactive`); no screen-reader pass is recorded. |

### M6 — Hardening + 1.0 rehearsal

| Deliverable | State | Notes |
|---|---|---|
| 2-of-3 Shamir release-key rehearsal | Deferred | `entangle release key split/combine` and `docs/governance/key-ceremony.md` exist; the ceremony has not been run (the document says so). |
| All §16 acceptance tests green | Implemented, with two CI-only gaps | All 35 IDs have live tests (`atc_matrix_full_coverage`); ATC-PKG-2's three-host build and ATC-REL-1's real cosign run only in CI. |
| Documentation site | Deferred | `docs/` only. |
| `mirror.entanglement.dev` hosting contract | Deferred | Nothing in `docs/governance/`. |
| 1.0 RC with cosign + Ed25519 signatures; disclosure SLA rehearsal | Deferred | No tag; `SECURITY.md` exists. |
| Maintainer rotation review notes for months 1–6 | Deferred | `docs/governance/rotations.md` is checked by `cargo xtask rotation-note-check`; `bus-factor` fails by design until each role has two holders (`docs/maintainers/roles.toml`). |

### Cross-cutting checks

| Check | State | Notes |
|---|---|---|
| L1+L2 trust footprint under 25k LOC (§2.3, §10) | Implemented | `cargo xtask loc-budget` (`docs/trust-footprint.toml`), CI job `trust-footprint`. Measured: 15 854 non-blank, non-comment, non-test lines across `entangle-core`, `-host`, `-broker`, `-manifest`, `-signing`, `-oci`, `-ipc`, plus `-runtime`, `-aot`, `-sandbox` and `-biscuits`, which carry kernel work the spec assigns to `entangle-core`/`entangle-host`. |
| Bus factor ≥ 2 per role (§12.1) | Deferred | Check exists and fails: one holder per role. |
