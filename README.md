A tiny Rust runtime that turns the devices you already own into one cooperative compute fabric. Plugins declare exactly what they need — CPU, GPU, network, storage — and the runtime grants nothing else. Devices pair with a 6-digit code and share work over an encrypted mesh.

## Screenshots

![Entanglement architecture overview](./docs/screenshot.png)

## How it works

Every device runs the same single-binary daemon (`entangled`). On first run, `entangle init` generates an Ed25519 identity, writes a config file, and shows you a fingerprint. Pairing a second device is a 6-digit short-code with mutual TOFU — no central server, no account, no telemetry.

Plugins ship as signed `.wasm` components or `.tar.zst` bundles. Each one declares a permission tier (1 = pure sandbox, 5 = native subprocess) and a typed capability set. The capability broker is deny-by-default: a plugin only sees what it asked for and what the operator approved. Tier-5 native plugins exist as an honest escape hatch for workloads that can't run in WASM yet (Node-based AI agents, native GPU compute) — they sit behind OS-level sandboxes (Landlock, Seatbelt) and can be globally disabled with one config line.

Three transport modes are mixable per device: a LAN-only mDNS path for offline-first households, an Iroh QUIC mesh with NAT hole-punching for cross-network setups, and a Tailscale path that piggybacks on your existing tailnet. Cross-device authorization uses biscuit-auth tokens, attenuable so a delegated capability can never widen.

## Stack

- Rust (workspace of 14 crates)
- Wasmtime + WASI 0.2 component model
- Iroh QUIC mesh, mDNS, Tailscale
- Ed25519 + BLAKE3 publisher signing
- biscuit-auth Datalog capability tokens
- Tokio async runtime
- JSON-RPC 2.0 over Unix domain sockets

## Status

In progress
