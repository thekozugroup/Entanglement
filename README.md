A Rust runtime that turns the devices you already own into one cooperative compute fabric — plugins declare exactly what they need, the runtime grants nothing else, and devices pair with a 6-digit code over an encrypted mesh.

## How it works

Every device runs the same daemon (`entangled`). `entangle init` generates an Ed25519 identity, writes a config file and prints a fingerprint. A second device pairs with a 6-digit code and mutual trust-on-first-use. There is no central server, no account and no telemetry by default.

Plugins ship as signed `.wasm` components or `.tar.zst` packages. Each declares a permission tier (1 = pure sandbox, 5 = native subprocess) and a capability set. The capability broker denies by default. Wasm plugins can be granted brokered fetch, filesystem preopens (`/data`, `/shared`, `/shares/<n>`) and LAN/WAN sockets; grants can be listed and revoked while the plugin runs.

Tier-5 native plugins run as supervised subprocesses. On Linux they are confined with Landlock, a user and network namespace, a seccomp socket-family filter, `no_new_privs` and rlimits. Bubblewrap and macOS Seatbelt profiles are generated and unit-tested, but have not been run on a real bubblewrap or macOS host. The daemon refuses to install a plugin above `[security] max_tier_allowed`, and `entangle security set-max-tier` lowers it and unloads plugins above it.

Three transports can be mixed per device: `mesh.local` (mDNS on the LAN), `mesh.iroh` (QUIC with NAT traversal) and `mesh.tailscale` (a mutually authenticated channel over an existing tailnet). The scheduler picks a transport per peer in the order local, tailscale (only while the tailnet is active), iroh, and falls back only when a connect fails. Cross-device authorization uses biscuit-auth tokens that can only be narrowed.

Work can be run on a remote peer as a one-shot task or as a stream of signed chunks with credit-based flow control. Results can be checked with integrity policies: `Deterministic` (hash quorum across distinct workers), `SemanticEquivalent` (a signed metric plugin compares outputs) and `TrustedExecutor`. `Attested` (TEE) is not implemented.

## Examples

- [hello-world](./examples/hello-world/) — minimal tier-1 plugin returning a greeting.
- [hash-it](./examples/hash-it/) — tier-2 BLAKE3 hasher with zero declared capabilities.
- [native-echo](./examples/native-echo/) — tier-5 native plugin used to exercise the sandbox.
- [`plugins/`](./plugins/) — nine catalog plugins: `compress`, `csv-stats`, `image-resize`, `json-query`, `markdown-html`, `qr-encode` (tier 1), `stream-lines` (tier 1, streaming), `metric-bleu-4` and `metric-numerical-l2-relative` (tier 2, integrity metrics).

## Walkthrough

For a hands-on tour from `entangle init` through plugin invocation and peer pairing, see [`docs/tutorial.md`](./docs/tutorial.md).

## Deeper reading

- [`docs/architecture.md`](./docs/architecture.md) — canonical architecture spec (§0–§16).
- [`CONTRIBUTING.md`](./CONTRIBUTING.md) — local dev workflow.
- [`SECURITY.md`](./SECURITY.md) — vulnerability disclosure.

## Stack

- Rust workspace: 27 members (26 crates under `crates/` plus `tools/xtask`). See [`STATUS.md`](./STATUS.md) for each crate.
- Wasmtime + WASI 0.2 component model.
- Transports: mDNS-SD on the LAN, Iroh QUIC (identity-bound), Tailscale (X25519 + Ed25519 key exchange, ChaCha20-Poly1305 frames, tailnet-only sources).
- Ed25519 publisher signing + BLAKE3 artifact hashing.
- biscuit-auth Datalog capability tokens with bridge attenuation and a byte budget.
- OCI registry client for plugin push, pull and signed mirror listings.
- Prometheus-format `/metrics` and an OTLP/HTTP JSON trace exporter.
- Tokio async runtime.
- JSON-RPC 2.0 over Unix domain sockets.

## Install

Build from source — this is the path that works today:

```bash
git clone https://github.com/thekozugroup/Entanglement
cd Entanglement
./scripts/bootstrap.sh          # add --dry-run to see what it would do first
```

[`scripts/bootstrap.sh`](./scripts/bootstrap.sh) checks your toolchain (Rust
1.91+, plus the `wasm32-wasip2` target plugins need), installs `entangle` and
`entangled`, and runs `entangle init` only if you have no identity yet. It never
calls `sudo` and never overwrites an existing identity.

No Rust toolchain? Use Docker:
`docker compose -f docker/docker-compose.yml up --build`
(see [`docker/README.md`](./docker/README.md)).

Prefer no clone? `cargo install --git https://github.com/thekozugroup/Entanglement entangle-cli`
builds the CLI straight from the default branch (`entangle-bin` for the daemon).

> **No release is published yet**, so the `curl … | sh` one-liner
> ([`scripts/install.sh`](./scripts/install.sh)) and Homebrew cannot work — both
> install prebuilt release tarballs. They are documented and ready, and start
> working the moment a `v0.1.0` tag is cut.

Full guide — every install path with its current status, systemd, uninstall, and
troubleshooting: [`docs/install.md`](./docs/install.md).

## Status

Pre-release. No version is tagged or published. Measured on commit `080ab0b`: `cargo fmt`, `cargo clippy --workspace --all-targets -- -D warnings` and `RUSTDOCFLAGS=-D warnings cargo doc` are clean, and `cargo test --workspace` reports 1552 passed, 0 failed, 10 ignored. All 35 acceptance IDs in architecture.md §16 are covered by live tests.

Works now: local plugin hosting and invocation; pairing over the network; remote one-shot and streaming tasks over Iroh and Tailscale; integrity policies other than `Attested`; the MCP gateway (stdio downstream servers) and `entangle agent run`; tier-5 sandboxing on Linux; OCI publish and pull; metrics and traces.

Not available yet:

- `Attested` integrity (needs TEE hardware; returns `ENTANGLE-E0304`).
- Native Windows (Phase 5). Windows is supported through WSL2 only.
- `entangle install`, `entangle logs`, `entangle upgrade`, `entangle trace task`.
- On parallel branches, not on main: the Layer-2 1% replay spot-check, per-peer transport routing for `entangle compute stream` (it dials Iroh only), streaming invocation metrics, `entangle backup` / `restore`, `[plugins] disabled` with `plugins enable|disable`, `entangle release verify --tag`, HTTP downstream servers in the MCP gateway.

Full list with reasons: [`STATUS.md`](./STATUS.md). Changes: [`CHANGELOG.md`](./CHANGELOG.md).

## 5-minute demo

```
cargo install --path crates/entangle-cli   # installs the `entangle` binary
entangle init --non-interactive
rustup target add wasm32-wasip2
cargo xtask hello-world build              # prints your publisher fingerprint
entangle keyring add <fingerprint_from_above> --name self
entangle plugins load examples/hello-world/dist/ --allow-local
entangle plugins invoke <fingerprint_from_above>/hello-world@0.1.0 --input world
```

## More commands

Details and flags are in [`docs/operations.md`](./docs/operations.md).

| Command | Purpose |
|---|---|
| `entangle agent run <agent>` | Run claude-code, codex or opencode with its MCP servers routed through a per-session gateway (bearer auth, allow/deny policy, audit). `--trust-project-servers` skips the prompt for servers defined in the project's own config. |
| `entangle wrapper enable\|disable\|status\|repair` | Manage the shell shim that warns when an agent host runs outside Entanglement. |
| `entangle security set-max-tier <N>` | Lower `max_tier_allowed` and unload plugins above it. |
| `entangle config reload\|validate` | Apply or check `config.toml` changes. |
| `entangle perms list\|revoke` | List a loaded plugin's capability grants; revoke one until the plugin is reloaded. |
| `entangle plugins publish\|tags` | Push a signed package to an OCI registry; list tags and check the signed mirror listing. `plugins install oci://...` pulls one. |
| `entangle plugins verify --rebuild` | Rebuild a package from source and compare it with the built one. |
| `entangle release verify` | Check a release artifact against the Ed25519 release key and a cosign bundle. `release key split\|combine` does Shamir 2-of-3. |
| `entangle compute dispatch` | One-shot task with `--integrity none\|deterministic\|semantic-equivalent\|trusted-executor`. |
| `entangle compute stream` | Run a streaming task on a trusted peer and write chunks to stdout. |
| `entangle diag mesh [--probe]` | Show transports, endpoints and how each trusted peer is reachable. |
| `entangle metrics` | Print the daemon's Prometheus metrics over RPC. |

## Roadmap

The phase numbers below are the project's own labels, not the numbering in architecture.md §12.

| Phase | Theme | Status |
|-------|-------|--------|
| 1     | Core runtime, WASM host, signing, manifest, UDS RPC, mDNS LAN, pairing, biscuit tokens, local scheduler, agent-host config adapter | Shipped |
| 2     | Cross-node dispatch over Iroh; automatic pairing | Shipped |
| 2b    | `mesh.tailscale`, multi-transport scheduling, MCP gateway HTTP server, tier-5 OS sandboxing, capability grants, Prometheus and OTLP export | Shipped, with the gaps listed in STATUS.md (sandbox paths other than Linux Landlock/seccomp never run on a real host; gateway proxies stdio downstream servers only) |
| 3     | Integrity policies: `Deterministic`, `SemanticEquivalent` | Shipped. `Attested` is not implemented (needs TEE hardware). Layer-2 1% replay spot-check is on a branch, not main |
| 4     | Streaming tasks with chunk signing | Streaming shipped over Iroh and Tailscale. `compute stream` dials Iroh only; streaming metrics are on a branch. Speculative execution, straggler mitigation and reputation gossip are not implemented (reputation is a local per-peer score) |
| 1.5   | Distribution: OCI registry, reproducible packages, release verification, install script, Homebrew | Code and CI workflows exist. No release is published; `install.sh` and Homebrew need a `v0.1.0` tag. Cross-host reproducibility and real cosign run only in CI. Bus-factor check fails by design (one holder per role) |
| 5     | Native Windows AppContainer; Aider and Cursor adapters; plugin marketplace | Not started |

## Acknowledgements

Entanglement borrows ideas from:

- **WASI 0.2 Component Model & Wasmtime** — the plugin substrate.
- **biscuit-auth** — attenuatable, offline-verifiable capability tokens.
- **Iroh** — QUIC mesh with NAT hole-punching and DERP relay.
- **Tailscale & WireGuard** — the model for "your existing tailnet is the
  reliable WAN substrate".
- **Bytecode Alliance's `cargo-vet`** — supply-chain auditing.
- **The Capability Security community** — Mark S. Miller, the E language,
  and the Genode OS Framework for showing that deny-by-default at the API
  layer is achievable in practice, not just in theory.
