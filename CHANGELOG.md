# Changelog

All notable changes to Entanglement are documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added
- Phase 1 architecture spec at `docs/architecture.md`.
- 18 Rust library crates plus the `entangle` / `entangled` binaries
  (~23 crates total) implementing the core runtime, RPC, mesh-local
  discovery, peer pairing, capability tokens, scheduler, agent-host
  scaffold, maintenance loop, and observability.
- Tutorial walkthrough at `docs/tutorial.md`.
- Two example plugins (`examples/hello-world`, `examples/hash-it`).
- Criterion benchmarks for hot paths (`crates/entangle-bench`).
- Phase-2 scaffolding for cross-node dispatch, MCP gateway,
  `mesh.iroh` / `mesh.tailscale` transports, NPU detection, Landlock /
  Seatbelt probes, Prometheus / OpenTelemetry exporters — each behind
  a feature flag or returning a structured `NotImplemented` error.
- `.iterations/` — sprint log for the 80-iteration completion push.

### Changed
- STATUS.md tracks Phase-2 scaffolding state alongside Phase-1 capability.
- CONTRIBUTING.md grew an "Iteration sprint" section documenting how
  to reproduce the sprint locally.

### Status
- Phase 1 MVP target: core runtime + plugin host + signing + manifest +
  CLI + daemon UDS RPC + mesh-local discovery + pairing primitives +
  biscuit-auth tokens + scheduler skeleton + agent-host config adapter.
- Phase 2 in progress: scaffolds returning `NotImplemented` for the
  cross-node dispatcher, MCP gateway, `mesh.iroh` / `mesh.tailscale`
  transports, OS sandbox probes, and Prometheus / OpenTelemetry export.

## How releases work
1. Update this file under `## [Unreleased]`.
2. When ready, rename `[Unreleased]` to `[X.Y.Z] - YYYY-MM-DD`.
3. Tag the commit `vX.Y.Z` and push. CI builds, signs, and publishes.
