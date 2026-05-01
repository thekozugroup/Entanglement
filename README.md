A Rust runtime that turns the devices you already own into one cooperative compute fabric — plugins declare exactly what they need, the runtime grants nothing else, and devices pair with a 6-digit code over an encrypted mesh.

## Screenshots

![Entanglement architecture overview](./docs/screenshot.png)

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

- Rust workspace: 18 lib crates, 2 binaries, 1 bench, 1 atc-matrix, 1 xtask (~23 crates total)
- Wasmtime + WASI 0.2 component model
- Iroh QUIC mesh, mDNS, Tailscale
- Ed25519 + BLAKE3 publisher signing
- biscuit-auth Datalog capability tokens
- Tokio async runtime
- JSON-RPC 2.0 over Unix domain sockets

## Status

In progress
