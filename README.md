A Rust runtime that turns the devices you already own into one cooperative compute fabric — plugins declare exactly what they need, the runtime grants nothing else, and devices pair with a 6-digit code over an encrypted mesh.

## How it works

Every device runs the same daemon (`entangled`). `entangle init` generates an Ed25519 identity, writes a config file and prints a fingerprint. A second device pairs with a 6-digit code and mutual trust-on-first-use. Identity and trust need no central server and no account. Trace export is off by default. `mesh.iroh` can fall back to iroh's public relay servers; `[scheduler] relay = false` turns that off.

Plugins ship as signed `.wasm` components or `.tar.zst` packages. Each declares a permission tier (1 = pure sandbox, 5 = native subprocess) and a capability set. The capability broker denies by default. Wasm plugins can be granted brokered fetch, filesystem preopens (`/data`, `/shared`, `/shares/<n>`) and LAN/WAN sockets; grants can be listed and revoked while the plugin runs.

Tier-5 native plugins run as supervised subprocesses. On Linux they are confined with Landlock, a user and network namespace (where unprivileged user namespaces work), a seccomp filter, `no_new_privs` and rlimits. Bubblewrap and macOS Seatbelt profiles are generated and unit-tested. A Seatbelt test that runs `sandbox-exec` compiles only on macOS (the CI macos-14 job). Neither path has been run on a real bubblewrap or macOS host in this work. The daemon refuses to install a plugin above `[security] max_tier_allowed`. `entangle security set-max-tier` changes the ceiling; lowering it unloads the plugins above the new ceiling.

Three transports can be mixed per device: `mesh.local` (mDNS on the LAN), `mesh.iroh` (QUIC with NAT traversal) and `mesh.tailscale` (a mutually authenticated channel over an existing tailnet). The scheduler picks a transport per peer in the order local, tailscale (only while the tailnet is active), iroh, and moves to the next only when connecting fails or times out. Remote tasks and streams are accepted only from peers in `~/.entangle/peers.toml`, identified by the transport's authenticated key, and only with a biscuit-auth `mesh.peer` capability token that the worker itself issued to that peer at pairing. Each request carries its own attenuation of that token (60-second expiry, fresh nonce, bound to the request); `entangle peers remove` revokes it.

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

- Rust workspace: 28 members (27 crates under `crates/` plus `tools/xtask`). See [`STATUS.md`](./STATUS.md) for each crate.
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

Works now: local plugin hosting and invocation; pairing over the network; remote one-shot tasks over Iroh and Tailscale; streaming tasks over Iroh and Tailscale (`entangle compute stream` picks the transport per peer like dispatch does); integrity policies other than `Attested`, with Layer-2 replay spot-checks; the MCP gateway (stdio and HTTP downstream servers) and `entangle agent run`; encrypted identity backup and restore; `plugins enable|disable`; plugins reloaded after a daemon restart, hot reload with drain-and-swap, lazy activation and an AOT compilation cache; tier-5 sandboxing on Linux; OCI publish and pull; metrics and traces.

Not available yet:

- `Attested` integrity (needs TEE hardware; returns `ENTANGLE-E0304`).
- Native Windows (Phase 5). On Windows only WSL2 is targeted; no CI job runs on Windows or WSL2.
- `entangle install`, `entangle logs`, `entangle upgrade`, `entangle trace task`.

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

Details and flags are in [`docs/operations.md`](./docs/operations.md); `agent run` is in [`docs/agents.md`](./docs/agents.md).

| Command | Purpose |
|---|---|
| `entangle agent run <agent>` | Run claude-code, codex or opencode with its MCP servers routed through a per-session gateway (bearer auth, allow/deny policy, audit). `--trust-project-servers` skips the prompt for servers defined in the project's own config. |
| `entangle wrapper enable\|disable\|status\|repair` | Manage the shell shim that warns when an agent host runs outside Entanglement. |
| `entangle security set-max-tier <N>` | Set `max_tier_allowed`. Lowering it unloads the plugins above the new ceiling, after a prompt or with `--force-unload`. |
| `entangle config reload\|validate` | `reload` applies an edited `max_tier_allowed` to the running daemon; other settings need a daemon restart. `validate` checks `config.toml`. |
| `entangle perms list\|revoke` | List a loaded plugin's capability grants; revoke one until the plugin is reloaded. |
| `entangle plugins publish\|tags` | Push a signed package to an OCI registry; list tags and check the signed mirror listing. `plugins install oci://...` pulls one. |
| `entangle plugins verify --rebuild` | Rebuild a package from source and compare it with the built one. |
| `entangle release verify` | Check a release artifact against the Ed25519 release key and a cosign bundle. `release key split\|combine` does Shamir secret sharing (2-of-3 by default). |
| `entangle compute dispatch` | One-shot task with `--integrity none\|deterministic\|semantic-equivalent\|trusted-executor`. |
| `entangle compute stream` | Run a streaming task on a trusted peer over `mesh.iroh` and write chunks to stdout. |
| `entangle diag mesh [--probe]` | Show transports, endpoints and how each trusted peer is reachable. |
| `entangle metrics` | Print the daemon's Prometheus metrics over RPC. |

## Roadmap

The phase numbers below are this README's own. They differ from the phases in architecture.md §12. "Implemented" means the code is in this tree; nothing is released.

| Phase | Theme | Status |
|-------|-------|--------|
| 1     | Core runtime, WASM host, signing, manifest, UDS RPC, mDNS LAN, pairing, biscuit tokens, local scheduler, agent-host config adapter | Implemented |
| 2     | Cross-node dispatch over Iroh; automatic pairing | Implemented |
| 2b    | `mesh.tailscale`, multi-transport scheduling, MCP gateway HTTP server, tier-5 OS sandboxing, capability grants, Prometheus and OTLP export | Implemented, with the gaps listed in STATUS.md (sandbox paths other than Linux Landlock/seccomp never run on a real host; gateway proxies stdio downstream servers only) |
| 3     | Integrity policies: `Deterministic`, `SemanticEquivalent` | Implemented, with Layer-2 replay spot-checks (1% by default). `Attested` is not implemented (needs TEE hardware) |
| 4     | Streaming tasks with chunk signing | Implemented. Streams run over Iroh and Tailscale, with per-peer transport selection in `compute stream`, and have invocation spans and metrics. Speculative execution, straggler mitigation and reputation gossip are not implemented (reputation is a local per-peer, per-policy score) |
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
