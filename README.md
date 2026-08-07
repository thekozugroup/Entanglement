A Rust runtime that turns the devices you already own into one cooperative compute fabric — plugins declare exactly what they need, the runtime grants nothing else, and devices pair with a 6-digit code over an encrypted mesh.

## How it works

Every device runs the same single-binary daemon (`entangled`). On first run, `entangle init` generates an Ed25519 identity, writes a config file, and shows you a fingerprint. Pairing a second device uses a 6-digit short-code with mutual TOFU — no central server, no account, no telemetry.

Plugins ship as signed `.wasm` components or `.tar.zst` bundles. Each one declares a permission tier (1 = pure sandbox, 5 = native subprocess) and a typed capability set. The capability broker is deny-by-default: a plugin only sees what it asked for and what the operator approved. Tier-5 native plugins exist as an honest escape hatch for workloads that can't run in WASM yet — they sit behind OS-level sandboxes (Landlock, Seatbelt) and can be disabled globally with one config line.

Three transport modes are mixable per device: a LAN-only mDNS path for offline-first households, an Iroh QUIC mesh with NAT hole-punching for cross-network setups, and a Tailscale path that piggybacks on your existing tailnet. Cross-device authorization uses biscuit-auth tokens, attenuable so a delegated capability can never widen.

## Examples

- [hello-world](./examples/hello-world/) — minimal tier-1 plugin returning a greeting.
- [hash-it](./examples/hash-it/) — tier-2 BLAKE3 hasher with zero declared capabilities.

## Walkthrough

For a hands-on tour from `entangle init` through plugin invocation and peer pairing, see [`docs/tutorial.md`](./docs/tutorial.md).

## Deeper reading

- [`docs/architecture.md`](./docs/architecture.md) — canonical architecture spec (§0–§16).
- [`CONTRIBUTING.md`](./CONTRIBUTING.md) — local dev workflow.
- [`SECURITY.md`](./SECURITY.md) — vulnerability disclosure.

## Stack

- Rust workspace: 21 lib crates, 2 binaries, 1 bench, 1 atc-matrix, 1 xtask (26 crates total).
- Wasmtime + WASI 0.2 component model.
- mDNS-SD discovery on the LAN; **working Iroh-QUIC transport** (identity-bound, used for pairing and cross-node dispatch); Tailscale transport still a scaffold.
- Ed25519 publisher signing + BLAKE3 artifact hashing.
- biscuit-auth Datalog capability tokens with bridge attenuation.
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

Phase 1 is implemented end-to-end, and the core Phase-2 capability now works:
devices **pair over the network** with a 6-digit code (no blob copy-paste), and
a task placed on a remote peer **actually executes there** over an
identity-bound QUIC transport, gated on the peer allowlist.

Still scaffolded and returning a structured `NotImplemented`: the MCP gateway
HTTP server, the `mesh.tailscale` transport, OS-sandbox engagement, and the
Prometheus/OpenTelemetry exporters. See [`STATUS.md`](./STATUS.md).

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

## Roadmap

| Phase | Theme | Status |
|-------|-------|--------|
| 1     | Core runtime + WASM host + signing + manifest + UDS RPC + mDNS LAN + pairing + biscuit tokens + local scheduler + agent-host config adapter | **Shipped** |
| 1.5   | Distribution: Homebrew tap, Linux install script, signed release artifacts (SLSA L3 + cosign) | In progress |
| 2     | Cross-node dispatch over Iroh QUIC + `mesh.iroh` transport + automatic pairing | **Shipped** |
| 2b    | MCP gateway HTTP server; `mesh.tailscale`; OS-sandbox engagement; Prometheus + OpenTelemetry exporters | Scaffolded (returns `NotImplemented`) |
| 3     | Integrity policies: `Deterministic` cross-node replication, `SemanticEquivalent` with operator-supplied metric components, `Attested` for TEEs | Designed |
| 4     | Streaming task model with chunk signing; speculative execution + straggler mitigation; reputation gossip | Designed |
| 5     | Native Windows AppContainer support; second-class agent-host adapters (Aider, Cursor); plugin marketplace | Deferred |

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
