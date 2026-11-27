# Entanglement

Entanglement runs signed WebAssembly components on paired devices. Each worker advertises the components it has loaded and the resources it can provide. A coordinator selects a worker and returns its output to the caller.

## How it works

Every device runs the same single-binary daemon (`entangled`). On first run, `entangle init` generates an Ed25519 identity, writes a config file, and shows you a fingerprint. Pairing a second device uses a 6-digit short-code with mutual TOFU — no central server, no account, no telemetry.

Entanglement runs signed WASI 0.2 components. The manifest declares the permission tier and requested capabilities, and the loader verifies the publisher before running the component. Operators can set a maximum tier. The native subprocess sandbox is still under development.

New installations enable LAN discovery and Iroh with public relays disabled. Paired nodes advertise their current addresses over mDNS. The scheduler authenticates a worker over QUIC and queries its hardware and loaded plugin versions before placing work. The optional Tailscale adapter discovers addresses on an existing tailnet and uses paired Entanglement keys to authenticate compute traffic. [Configure a tailnet worker](./docs/operations.md#running-a-worker-on-a-tailnet)

The installer verifies publisher signatures on OCI images and HTTPS tarballs.
Workers can also stream signed results under receiver-issued credit. A semantic
integrity policy compares replica outputs in a signed Wasm comparator on the
submitting device. [Package installation](./docs/plugin-authoring.md#install-a-prebuilt-component) · [Streaming](./docs/testing/streaming-compute.md)

## Examples

The bundled catalog includes compression, CSV statistics, image resizing, JSON Pointer, JSON queries, Markdown rendering and QR encoding. List installed source projects with `entangle plugins available --catalog ./plugins`. [Plugin catalog](./plugins/)

- [hello-world](./examples/hello-world/) — minimal tier-1 plugin returning a greeting.
- [hash-it](./examples/hash-it/) — tier-2 BLAKE3 hasher with zero declared capabilities.

- Produce lines progressively with a signed streaming guest. [stream-lines](./examples/stream-lines/)
- Run a preapproved Rust WASI test target across paired workers and retain per-test results. [Distributed Rust tests](./docs/testing/distributed-rust-tests.md)

## Walkthrough

For a hands-on tour from `entangle init` through plugin invocation and peer pairing, see [`docs/tutorial.md`](./docs/tutorial.md).

## Deeper reading

- [`docs/architecture.md`](./docs/architecture.md) — canonical architecture spec (§0–§16).
- [`CONTRIBUTING.md`](./CONTRIBUTING.md) — local dev workflow.
- [`SECURITY.md`](./SECURITY.md) — vulnerability disclosure.

## Stack

- Rust workspace: 21 lib crates, 2 binaries, 1 bench, 1 atc-matrix, 1 xtask (26 crates total).
- Wasmtime + WASI 0.2 component model.
- mDNS-SD discovery on the LAN; **working Iroh-QUIC transport** (identity-bound, used for pairing and cross-node dispatch); optional host Tailscale adapter for configured workers.
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
> install prebuilt release tarballs. Prebuilt installation requires a verified release and a populated Homebrew formula.

Full guide — every install path with its current status, systemd, uninstall, and
troubleshooting: [`docs/install.md`](./docs/install.md).

## Status

Linux workers execute signed components locally and on paired peers over QUIC. Operators can inspect the selected worker and scrape daemon metrics. The current acceptance record covers the tested platforms, workloads and outstanding release gates. [Release readiness](./STATUS.md)

## Try it locally

From the repository root with the CLI on your path, run the walkthrough. It builds and signs a component, then invokes it using the running daemon or a temporary in-process kernel.

```bash
entangle quickstart
```

## Roadmap

| Phase | Theme | Status |
|-------|-------|--------|
| 1     | Core runtime + WASM host + signing + manifest + UDS RPC + mDNS LAN + pairing + biscuit tokens + local scheduler + agent-host config adapter | Implemented in the source tree |
| 1.5   | Distribution: Homebrew tap, Linux install script, signed release artifacts (SLSA L3 + cosign) | In progress |
| 2     | Cross-node dispatch over Iroh QUIC + `mesh.iroh` transport + automatic pairing | Implemented in the source tree |
| 2b    | Prometheus metrics, MCP gateway HTTP server, OS sandbox, OpenTelemetry export | Prometheus implemented. Other integrations remain in development |
| 3 | Replicated result integrity | Signed semantic replica work and submitter-local comparator execution implemented. TEE attestation remains open. |
| 4 | Streaming and scheduling | Credit-based signed streams implemented. Speculative execution and reputation gossip remain open. |
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
