# Phase 1 Status

A snapshot of what's implemented vs. deferred for the Entanglement runtime as of the current `main` commit.

## Workspace

23 crates total (18 libraries, 2 binaries, 1 bench harness, 1 acceptance-test matrix runner, 1 build-tooling crate).

| Crate | Purpose |
|-------|---------|
| `entangle-types` | Tier enum, PluginId, PeerId, Task, IntegrityPolicy, error codes |
| `entangle-manifest` | `entangle.toml` schema + tier↔capability validation |
| `entangle-signing` | Ed25519 publisher signing, BLAKE3 artifact hashing, keyring |
| `entangle-wit` | WIT package `entangle:plugin@0.1.0` (5 interfaces) |
| `entangle-sdk` | Guest-side helpers + `entangle_plugin!` macro |
| `entangle-host` | Wasmtime + WASI 0.2 host wrapper, async plugin invocation |
| `entangle-broker` | Capability broker, deny-by-default, audit log, `CrossNodePolicy` |
| `entangle-ipc` | In-process pub/sub bus (broadcast channels, topic globs) |
| `entangle-runtime` | Kernel: manifest → signature → broker → host orchestration |
| `entangle-rpc` | Typed JSON-RPC 2.0 client for the daemon UDS socket |
| `entangle-mesh-local` | mDNS-SD discovery on `_entangle._udp.local`, hardware advert |
| `entangle-peers` | Persistent allowlist (`~/.entangle/peers.toml`) |
| `entangle-pairing` | 6-digit code + fingerprint mutual-TOFU state machine |
| `entangle-biscuits` | biscuit-auth wrapper + bridge-attenuation enforcement |
| `entangle-scheduler` | Worker pool + greedy multi-criteria placement |
| `entangle-agent-host` | MCP config adapter (Claude Code / Codex / OpenCode) |
| `entangle-observability` | TTY-aware tracing-subscriber bootstrap |
| `entangle-atc-matrix` | Spec ↔ test cross-checker |
| `entangle-cli` (binary `entangle`) | Operator CLI |
| `entangle-bin` (binary `entangled`) | Long-running daemon, UDS RPC, maintenance loop |
| `entangle-bench` | Criterion benchmarks |
| `tools/xtask` | `cargo xtask hello-world|hash-it build` |

## Tests

- 249 unit / integration tests passing.
- 28 ignored (Phase-2 enforcement, fixture-dependent, or single-threaded).
- `cargo fmt`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo doc --workspace --no-deps -- -D warnings` all clean.
- `cargo deny` runs in CI on every PR (advisories / bans / licenses / sources).
- `cargo audit` clean as of the latest `cargo update`.

## Acceptance criteria

35 ATC propositions in §16 of the spec.
- 14 covered directly with matching test names.
- 19 sub-group extensions add coverage on top (`ATC-CAP-*`, `ATC-SIG-*`, `ATC-AUDIT-*`, `ATC-MAX-TIER-*`, `ATC-OUT-*`, `ATC-REP-*`, `ATC-INT-*`, `ATC-BRG-*`).
- 18 remain uncovered (release / package / wrapper / mirror / bus-factor / man-3,4 / max — all Phase 2+).
- The matrix runner is `#[ignore]`'d at Phase 1.5; hard-fail on uncovered resumes in Phase 2.

## What works end-to-end

- **Initialize a host:** `entangle init [--non-interactive]` generates an Ed25519 identity, writes config, peers, keyring.
- **Build a plugin:** `cargo xtask hello-world build` → signed `.tar.zst` package; same for `hash-it`.
- **Trust a publisher:** `entangle keyring add <pubkey> --name <label>`.
- **Load and run a plugin:** `entangle plugins load <dir> [--allow-local]` then `entangle plugins invoke <id> --input <bytes>`.
- **Run the daemon:** `entangled run` exposes JSON-RPC 2.0 over `~/.entangle/sock`. CLI auto-uses RPC when available.
- **Discover peers on the LAN:** mDNS-SD via `_entangle._udp.local` with hardware-advert TXT records that feed the worker pool.
- **Pair a 2nd device:** `entangle pair` (initiator) ↔ `entangle pair --responder` (paste blobs); 6-digit code + fingerprint mutual TOFU; trusted peer persisted to `peers.toml`.
- **Verify cross-node capabilities:** mint biscuit-auth tokens with `entangle-biscuits::mint`; attenuate for bridge relay (5 mandatory facts enforced); `Broker::grant_with_biscuit` checks signature + expiry + peer + capability before issuing a handle.
- **Run integrity-checked compute:** `entangle compute dispatch <plugin> --integrity deterministic --replicas 2` runs the plugin twice and hash-quorums the output; `--integrity trusted-executor --allow <peer>` checks the local peer is allowed.
- **Wrap an AI agent:** `AgentSession::start("claude-code", gateway_url, name)` snapshots the agent's MCP config, splices in an Entanglement gateway server, restores on drop.
- **Self-diagnose:** `entangle doctor` runs 13 structured checks (identity, perms, keyring, peers, OS sandbox, daemon reachability, disk space, clock skew).
- **Maintain the host:** the daemon's built-in maintenance loop rotates logs, GCs the cache, warns about key rotation and missing identity backups.

## What's deferred to Phase 2+

- Cross-node dispatch over Iroh streams (the dispatcher's remote arm logs and falls back to local).
- The MCP gateway HTTP server itself (the agent-host wires the config; the server forwarding tool calls into the kernel is not yet implemented).
- `mesh.iroh` and `mesh.tailscale` transports (scaffolds only).
- `Integrity::SemanticEquivalent` and `Integrity::Attested` enforcement (return `NotImplemented`).
- Native NPU detection (advert hard-codes zeros).
- Real `landlock`/`seatbelt` subprocess sandboxing for tier-5 plugins.
- Prometheus / OpenTelemetry export.
- `cargo-vet` audit population.
- Worker advertisement over the wire (the wire format is in place; the publishing side advertises hardware in TXT records but the worker pool has no real peers yet on a single-host test).
- Native Windows support (WSL2 only).

## Release pipeline

- `.github/workflows/ci.yml` — fmt, clippy, test (Linux + macOS), wasm32-wasip2 build, docs, cargo-deny.
- `.github/workflows/release.yml` — three jobs: matrix build → SLSA Level 3 provenance + keyless `cosign sign-blob` → GitHub Release with tarballs + checksums + sigstore bundles.
- `.github/workflows/bus-factor.yml` — weekly check that every named role (`core-runtime-lead`, `mesh-lead`, `agent-lead`, `security-lead`, `release-lead`) has ≥2 holders. Currently fails by design (one holder per role) until additional maintainers are seated.
- `scripts/verify-release.sh` — end-user verification script (sha256 + blake3 + cosign).

## Governance

- `CONTRIBUTING.md` — full local dev workflow.
- `CODE_OF_CONDUCT.md` — Contributor Covenant 2.1.
- `SECURITY.md` — 90-day disclosure window, scope statement.
- `docs/maintainers/roles.toml` + 5 role-specific responsibility docs.
- `deny.toml` — supply-chain policy for advisories, licenses, sources, multi-version warnings.

## Read next

- [`README.md`](README.md) — portfolio narrative.
- [`docs/architecture.md`](docs/architecture.md) — full spec (~1900 lines, 16 sections + glossary + appendix).
- [`docs/tutorial.md`](docs/tutorial.md) — hands-on walkthrough.
- [`CHANGELOG.md`](CHANGELOG.md) — release notes.
