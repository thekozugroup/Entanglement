# 80-Iteration Project-Completion Plan

Two virtual teams operate on every iteration:

- **Dev Team** — proposes & applies focused code/doc changes for the iteration's criterion.
- **Grade Team** — scores the result against the criterion on a 0–100 scale.

An *iteration* runs the dev↔grade loop until Grade Team scores 100. Then we advance.

## Criteria (80)

Phase-2 deferral closers, then breadth/depth polish covering docs, tests,
ergonomics, error paths, CLI UX, observability, security hardening,
distribution, governance, and demo readiness.

| # | Criterion |
|---|-----------|
| 1 | Workspace builds & baseline tests pass on stable toolchain |
| 2 | CHANGELOG reflects the 80-iter sprint (Unreleased section curated) |
| 3 | README sentence-level polish + accurate stack list |
| 4 | STATUS.md updated to match real state after iter cycle |
| 5 | docs/architecture.md spelling/typo pass (§0–§4) |
| 6 | docs/architecture.md typo pass (§5–§8) |
| 7 | docs/architecture.md typo pass (§9–§12) |
| 8 | docs/architecture.md typo pass (§13–§16 + appendix) |
| 9 | Top-level crate docs (// !) present & accurate for every lib crate |
| 10 | Public error types carry stable ENTANGLE-Exxxx codes everywhere |
| 11 | Cross-node dispatch: explicit NotImplemented path + helpful message |
| 12 | MCP gateway HTTP server: scaffold module with TODO map + tests pin behaviour |
| 13 | mesh.iroh transport stub: feature flag + clean compile-time stub |
| 14 | mesh.tailscale transport stub: feature flag + clean compile-time stub |
| 15 | Integrity::SemanticEquivalent — emits structured NotImplemented |
| 16 | Integrity::Attested — emits structured NotImplemented |
| 17 | NPU detection scaffolding (Linux only) + unit test |
| 18 | Landlock sandbox: real-LSM probe + safe no-op fallback |
| 19 | Seatbelt sandbox: macOS probe + safe no-op fallback |
| 20 | Prometheus metrics: exposition format helper + tests |
| 21 | OpenTelemetry export: feature-gated scaffold |
| 22 | cargo-vet bootstrap (supply-chain audits.toml & config.toml seed) |
| 23 | Worker advertisement wire-format: roundtrip test |
| 24 | Native Windows: explicit guard + `--print-platform` text |
| 25 | doctor: clock-skew daemon RPC check filled in |
| 26 | Manifest validation: better error contexts |
| 27 | Manifest: deny unknown fields with informative error |
| 28 | Signing: rotate-key story (doc + helper) |
| 29 | Keyring: trust-anchor revocation note |
| 30 | Broker audit log: structured entries (serde Serialize) |
| 31 | Broker: deny-by-default tests for every capability surface |
| 32 | IPC bus: topic-glob edge-case tests |
| 33 | RPC: typed error envelope test for each error code |
| 34 | RPC: client/server timeout test |
| 35 | Pairing: clock-skew tolerance test |
| 36 | Pairing: fingerprint truncation/equality test |
| 37 | Biscuits: bridge-attenuation widening rejection test |
| 38 | Biscuits: expired-token rejection test |
| 39 | Scheduler: greedy placement edge case (zero workers) |
| 40 | Scheduler: deterministic tiebreak unit test |
| 41 | Agent-host: snapshot/restore idempotency test |
| 42 | Observability: TTY vs non-TTY format selection test |
| 43 | CLI: `entangle --help` quality pass |
| 44 | CLI: `entangle doctor --json` schema documented |
| 45 | CLI: `entangle plugins list` cosmetic polish |
| 46 | CLI: `entangle peers list` cosmetic polish |
| 47 | xtask: example plugin build doc'd in CONTRIBUTING |
| 48 | Example: hello-world README sanity-check |
| 49 | Example: hash-it README sanity-check |
| 50 | Bench: criterion smoke test exists per hot path |
| 51 | CI: workflow file lint pass |
| 52 | Release pipeline: doc note about SLSA L3 outputs |
| 53 | Security: SECURITY.md polish + contact channel |
| 54 | Governance: roles.toml documented in maintainers/ |
| 55 | Code-of-conduct: project-specific contact |
| 56 | Contributing: local dev steps verified |
| 57 | License header presence in lib crates (top-level doc note) |
| 58 | Cargo deny config note + how to run locally |
| 59 | Cargo audit note + how to run locally |
| 60 | Cargo doc warning-as-error verified |
| 61 | Cross-platform: macOS install note in README |
| 62 | Cross-platform: Linux install note in README |
| 63 | Cross-platform: Windows/WSL2 install note in README |
| 64 | Tutorial: tested commands callout |
| 65 | Architecture: glossary completeness pass |
| 66 | Architecture: appendix link integrity |
| 67 | Errors: stable doc-comment per public error |
| 68 | Logs: structured fields documented |
| 69 | UDS socket: permissions documented |
| 70 | Config: schema documented in CONTRIBUTING or docs |
| 71 | Plugin tier↔capability table doc'd |
| 72 | Daemon shutdown: ordered teardown doc note |
| 73 | Maintenance loop: knobs documented |
| 74 | Rate limiting: explicit non-goal note |
| 75 | Threat model: short section in SECURITY.md |
| 76 | Demo script: README "5-minute demo" callout |
| 77 | Roadmap: Phase 2/3/4/5 short callouts |
| 78 | Bus-factor note in CONTRIBUTING |
| 79 | Acknowledgements / inspirations section |
| 80 | Final smoke build + test + clippy + doc; sign-off line in STATUS.md |
