# Changelog

All notable changes to Entanglement are documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added
- Phase 1 architecture spec at `docs/architecture.md`
- 18 Rust crates implementing the core kernel, RPC, mesh-local discovery,
  peer pairing, capability tokens, scheduler, agent-host scaffold,
  maintenance loop, and observability.
- Tutorial walkthrough at `docs/tutorial.md`.
- Two example plugins (`examples/hello-world`, `examples/hash-it`).
- Criterion benchmarks for hot paths (`crates/entangle-bench`).

### Status
- Phase 1 MVP target: kernel + plugin runtime + signing + manifest +
  CLI + daemon UDS RPC + mesh-local discovery + pairing primitives +
  biscuit-auth tokens + scheduler skeleton + agent-host config adapter.
- Phase 2 deferred: real cross-node dispatch, MCP gateway HTTP server,
  Iroh / Tailscale transports, NPU detection, OpenTelemetry export.

## How releases work
1. Update this file under `## [Unreleased]`.
2. When ready, rename `[Unreleased]` to `[X.Y.Z] - YYYY-MM-DD`.
3. Tag the commit `vX.Y.Z` and push. CI builds, signs, and publishes.
