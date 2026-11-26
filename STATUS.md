# Entanglement release readiness

This checkout implements trusted one-shot WASI compute across paired workers. The Linux and release checks below describe the evidence available for this release candidate.

**Recently landed**

- **Real P2P transport.** `entangle-mesh-iroh` is no longer a scaffold: it
  binds a QUIC endpoint keyed by the daemon's own Ed25519 identity, so a
  peer's transport-authenticated identity *is* its `PeerId`
  (`PeerId::from_public_key_bytes(endpoint_id)`) — no second namespace of
  network identifiers to reconcile. Length-prefixed framing enforces its
  cap against the header *before* allocating, so a lying length prefix
  cannot make the daemon allocate.
- **One-command install.** `scripts/install.sh` verifies the SHA-256 before
  extracting and never invokes sudo; Homebrew formula and `docs/install.md`
  alongside it. Note: no releases are published yet, so the installer
  currently reports that and points at Docker/source.
- **Plugin authoring without a checkout.** `entangle plugins new` scaffolds
  a project and `entangle plugins build <DIR>` builds+signs *any* plugin
  directory — previously only the two bundled examples could be built.
  See `docs/plugin-authoring.md`.

## Workspace

26 crates total (21 libraries, 2 binaries, 1 bench harness, 1 acceptance-test matrix runner, 1 build-tooling crate) — see the `[workspace] members` list in `Cargo.toml`.

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
| `entangle-core` | Shared kernel utilities and foundational abstractions |
| `entangle-runtime` | Kernel: manifest → signature → broker → host orchestration |
| `entangle-rpc` | Typed JSON-RPC 2.0 client for the daemon UDS socket |
| `entangle-mesh-local` | mDNS-SD discovery on `_entangle._udp.local`, hardware advert |
| `entangle-mesh-iroh` | WAN Identity-bound QUIC mesh transport, ALPN and length-framed request/response |
| `entangle-mesh-tailscale` | Read-only Tailscale node discovery and authenticated QUIC routing to mapped workers |
| `entangle-oci` | OCI registry distribution — fetch/verify plugins (Phase 2 stub) |
| `entangle-peers` | Persistent allowlist (`~/.entangle/peers.toml`) |
| `entangle-pairing` | 6-digit code + fingerprint mutual-TOFU state machine |
| `entangle-biscuits` | biscuit-auth wrapper + bridge-attenuation enforcement |
| `entangle-scheduler` | Worker hardware and plugin discovery, resource-aware placement and trusted remote dispatch |
| `entangle-agent-host` | MCP config adapter (Claude Code / Codex / OpenCode) |
| `entangle-observability` | Structured logs and Prometheus registry shared by the daemon and CLI |
| `entangle-atc-matrix` | Spec ↔ test cross-checker |
| `entangle-cli` (binary `entangle`) | Operator CLI |
| `entangle-bin` (binary `entangled`) | Long-running daemon, UDS RPC, maintenance loop |
| `entangle-bench` | Criterion benchmarks |
| `tools/xtask` | `cargo xtask hello-world|hash-it build` |

## Release-candidate checks

| Check | Validation |
|---|---|
| Linux workspace | On x86-64 Linux and Rust 1.91, the locked workspace suite passed 675 tests and reported 28 ignored. Formatting, all-target Clippy and documentation with warnings treated as errors passed. The additional opt-in checks exercised multicast, pairing, signed hello-world, plugin scaffolding, catalog quickstart, and agent-host configuration restoration. |
| Cross-node execution | A signed component loaded only on the worker returns its output to a separate coordinator over authenticated QUIC. The test checks worker identity, resource rejection, revocation, and metrics on both processes. |
| Automatic paired LAN discovery | Two Linux daemon processes advertised ephemeral UDP ports over mDNS on the same host interface. With empty static route lists, a worker-only component executed over QUIC and the coordinator refused new work after revocation. |
| Relayed transport | Two authenticated endpoints exchanged a binary request and reply through the upstream Iroh 1.5 relay in a container with only a loopback interface. Both endpoints reported the relay as their selected path. The public relay check timed out, and the workspace proxy denied the connection. Public NAT traversal remains unverified. [Local relay procedure](docs/testing/local-relay.md) |
| Tailscale route adapter | Two Linux network namespaces with distinct addresses exercised the scheduler using synthetic Tailscale status. Real Tailscale enrollment, WireGuard and tailnet policy require a live two-device run. [Acceptance procedure](docs/testing/tailnet-compute.md) |
| Plugin catalog | All seven signed WASI components passed their workload checks both locally and from a separate coordinator with an empty plugin inventory. The test verifies worker identity, exact output bytes, CSV statistics, RFC 6901 and JSON queries, HTML, decoded image pixels, gzip round trips and the URL decoded from a generated QR code. [Catalog smoke test](plugins/smoke_test.py) |
| Unattended workers | The daemon restores configured signed components before advertising capacity. The CLI can trust a publisher while a worker is running, and subsequent package loads consult the current keyring. |
| Operator tier policy | Catalog installation under a tier-2 ceiling refused a tier-3 project before writing its package or trusting a signing key. Preparing the package for a different worker succeeded and the local execution path still refused to load it. |
| Dependencies and authorization | The locked workspace passed advisory, ban, license and source checks. The seven catalog and four standalone example/fixture lockfiles passed advisory checks. The candidate pins Biscuit 7.0.0-alpha.4 and Wasmtime 36.0.23 LTS. Tests exchange Ed25519 and P-256 tokens between Biscuit 6 and 7 and enforce signed Datalog checks for ordinary and bridge grants. [Biscuit compatibility and Rust API change](docs/testing/biscuit-compatibility.md) |
| Operations | `entangle metrics` reads from the live daemon. An optional loopback Prometheus endpoint exposes worker invocations and local/remote scheduler timing. [Operator guide](docs/operations.md#monitoring-work) |
| Release authorization | The roster lists one holder in each of five roles. The project's two-holder requirement and documented rotation and release-key procedures need independent maintainers and evidence. |
| Other platforms | The CLI and daemon passed a locked ARM64 Linux cross-target type check. The macOS hardware module was cross-type-checked separately. Native ARM64 Linux, Intel and Apple Silicon macOS, and WSL2 runtime checks require appropriate hosts. |

### Architecture acceptance inventory

The architecture defines 34 acceptance criteria. The scorecard compares each contract with its implementation, test evidence and outstanding work. The spec summary lists 35 and omits a definition for the sixth integrity criterion. [Architecture acceptance scorecard](docs/testing/architecture-acceptance.md)

## What works end-to-end

- **Initialize a host:** `entangle init [--non-interactive]` generates an Ed25519 identity, writes config, peers, keyring.
- Build and sign a plugin with `entangle plugins build <project>`. The resulting `dist/` directory contains the component, manifest and signature bundle.
- **Trust a publisher:** `entangle keyring add <pubkey> --name <label>`.
- **Load and run a plugin:** `entangle plugins load <dir> [--allow-local]` then `entangle plugins invoke <id> --input <bytes>`.
- **Run the daemon:** `entangled run` exposes JSON-RPC 2.0 over `~/.entangle/sock`. CLI auto-uses RPC when available.
- **Discover peers on the LAN:** mDNS-SD via `_entangle._udp.local` with hardware-advert TXT records that feed the worker pool.
- Pair a device with `entangle pair --responder` and `entangle pair <code>`. Confirm the displayed fingerprints. A manual copy-and-paste exchange is available with `--manual`. Both modes save the peer to `peers.toml`.
- **Verify cross-node capabilities:** mint biscuit-auth tokens with `entangle-biscuits::mint`; attenuate for bridge relay (5 mandatory facts enforced); `Broker::grant_with_biscuit` checks signature + expiry + peer + capability before issuing a handle.
- **Select an executor and verify results.** `entangle compute dispatch <plugin> --integrity trusted-executor --allow <peer>` restricts placement to an allowed identity. For local execution, `--integrity deterministic --replicas 2` repeats the invocation and compares output hashes. Distributed multi-executor replication is planned.
- **Wrap an AI agent:** `AgentSession::start("claude-code", gateway_url, name)` snapshots the agent's MCP config, splices in an Entanglement gateway server, restores on drop.
- **Self-diagnose:** `entangle doctor` runs 13 structured checks (identity, perms, keyring, peers, OS sandbox, daemon reachability, disk space, clock skew).
- **Maintain the host:** the daemon's built-in maintenance loop rotates logs, GCs the cache, warns about key rotation and missing identity backups.

## What's deferred to Phase 2+ (each item below has a Phase-1 scaffold)

| Deferred item | Scaffold location | Phase-1 contract |
|---|---|---|
| MCP gateway HTTP server | `entangle-agent-host::gateway` | `Gateway::start()` returns `GatewayError::NotImplemented` (`ENTANGLE-E0620`) |
| `Integrity::SemanticEquivalent` enforcement | `entangle-runtime::integrity` | `IntegrityError::NotImplemented("SemanticEquivalent")` with stable `ENTANGLE-E0304` |
| `Integrity::Attested` enforcement | same | `IntegrityError::NotImplemented("Attested")` with stable `ENTANGLE-E0304` |
| NPU vendor detection | `entangle-bin::npu` + `HardwareAdvert::npu_vendor` | TXT roundtrip wired; `detect()` returns `None` in Phase 1 |
| OS sandbox **engagement** | `entangle-runtime::os_sandbox::probe()` | probe-only; reports `Seatbelt`/`Landlock`/`Bubblewrap` availability; no engagement until Phase 2 |
| OpenTelemetry export | `entangle-observability::otel` | `OtelError::NotImplemented` (`ENTANGLE-E0650`) |
| `cargo-vet` audits | `supply-chain/{config,audits}.toml` | seeded; per-crate policy + `crypto-safe` criteria; populated as maintainers certify |
| Native Windows | `entangle print-platform` + spec §0.2 | reports `Unsupported { reason: "AppContainer is Phase 5+" }` |

## Release pipeline

- `.github/workflows/ci.yml` — fmt, clippy, test (Linux + macOS), wasm32-wasip2 build, docs, cargo-deny.
- The release workflow builds native and cross-target archives, checks governance and dependency advisories, and gates signing and publication of tagged releases. [Workflow](.github/workflows/release.yml)
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
- [`docs/architecture.md`](docs/architecture.md) — full spec (~2100 lines, 16 sections + glossary + appendix).
- [`docs/tutorial.md`](docs/tutorial.md) — hands-on walkthrough.
- [`docs/operations.md`](docs/operations.md) — operator runbook: install (systemd/Docker), config schema, file layout and permissions, health checks, error codes, backup/restore, logging, troubleshooting.
- [`CHANGELOG.md`](CHANGELOG.md) — release notes.
