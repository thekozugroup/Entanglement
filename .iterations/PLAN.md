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

## Criteria 81–160 (sprint 2)

Sprint 2 turns scaffolds into thicker contracts and adds real, testable
behaviour wherever a Phase-2 implementation can land without external
dependencies. Where the real implementation needs a network or kernel
feature we can't add here, the scaffold gets richer typed surface +
property tests instead.

| #   | Criterion |
|-----|-----------|
| 81  | Prometheus exposition: serve via in-process `format_text` helper used by future HTTP scrape; CLI `entangle metrics` prints to stdout |
| 82  | Prometheus Registry: histogram primitive + buckets test |
| 83  | OTEL config validation: endpoint URL parse + error |
| 84  | Kernel metrics: wire counter for `kernel.invocations_total` (Phase-1 friendly) |
| 85  | OS sandbox: doctor falls back to runtime probe; remove duplicated logic |
| 86  | Cross-node dispatch: typed `DispatchError::RemoteNotImplemented` carries the placement reason string |
| 87  | MCP gateway: bearer-token generator helper + test |
| 88  | MCP gateway: bind-addr validation rejects non-loopback by default |
| 89  | mesh.iroh: scaffold `parse_node_addr` helper + test |
| 90  | mesh.tailscale: `tailscale_cli_path` fallback to `$PATH` rule documented + tested |
| 91  | NPU detect: explicit Linux/macOS branches with structured rationale |
| 92  | Audit log: serde Serialize on `AuditEvent` for export |
| 93  | Audit log: filtered iter helper (`since`, `kind`) |
| 94  | Broker: capability surface enumeration helper for `entangle perms list` |
| 95  | Broker: revocation of a granted capability handle |
| 96  | IPC bus: backpressure semantics doc + test for lagged subscriber |
| 97  | RPC client: connect-timeout option |
| 98  | RPC server: per-method counters wired through metrics::Registry |
| 99  | Pairing: code expiry test |
| 100 | Pairing: rejection on fingerprint mismatch test |
| 101 | Biscuits: token-too-large rejection |
| 102 | Biscuits: bridge-cap byte-counter helper + test |
| 103 | Scheduler placement: GPU backend mismatch returns NoMatch |
| 104 | Scheduler placement: VRAM minimum enforcement |
| 105 | Scheduler placement: NPU vendor exact-match enforcement |
| 106 | Worker pool: bulk `remove_stale` after TTL |
| 107 | Dispatcher: `dispatch_one_shot` propagates kernel error context |
| 108 | Agent-host: snapshot file checksum carried in `Snapshot` |
| 109 | Agent-host: adapter not-found returns helpful list of known agents |
| 110 | Observability: documented env-var ladder (`RUST_LOG`, `ENTANGLE_LOG`) |
| 111 | CLI version: detailed --json output |
| 112 | CLI doctor: `--json` schema + tests |
| 113 | CLI doctor: tier-5 max test |
| 114 | CLI keyring: `--json` output |
| 115 | CLI plugins: `--json` output |
| 116 | CLI mesh peers: `--json` output |
| 117 | CLI compute: `--json` output |
| 118 | CLI metrics: new subcommand prints Prometheus exposition |
| 119 | xtask: `cargo xtask --help` enumerates commands |
| 120 | xtask: build outputs SHA256 alongside artifact |
| 121 | Example hello-world: assert tier-1 build produces wasm component |
| 122 | Example hash-it: assert tier-2 zero-cap build |
| 123 | Bench harness: counter for plugin instantiation time |
| 124 | Bench harness: capability grant micro-bench |
| 125 | CI: fmt+clippy+docs+test matrix verified by inspection |
| 126 | Release pipeline: sigstore bundle path documented |
| 127 | Release verify script: documented contract |
| 128 | Governance: at-rest holder count test |
| 129 | Roles: every role has a doc file referenced |
| 130 | CONTRIBUTING: link to `.iterations/` doc set |
| 131 | LICENSE: Apache-2.0 retained; NOTICE file presence |
| 132 | docs/architecture: glossary section anchor sanity |
| 133 | docs/architecture: spec version header date refreshed |
| 134 | docs/architecture: §0 acronyms table |
| 135 | docs/tutorial: dry-run command listing |
| 136 | docs/tutorial: troubleshooting section |
| 137 | docs/operator: new ops runbook stub |
| 138 | docker: minimal Dockerfile sanity check |
| 139 | scripts/verify-release.sh: dry-run lint |
| 140 | deny.toml: skip-list comment for known false-positives |
| 141 | rust-toolchain: pin reason commented |
| 142 | .gitignore: target/ + .iterations/runtime/ patterns |
| 143 | rustfmt config: workspace defaults sufficient |
| 144 | Manifest: helpful error on missing `[plugin]` table |
| 145 | Manifest: helpful error on invalid tier (0 or 6) |
| 146 | Signing: BLAKE3 short-fingerprint helper test |
| 147 | Keyring: trust-anchor expiry field design note |
| 148 | Runtime: panic on broker registration is caught + logged |
| 149 | Runtime: kernel.list_plugins() returns deterministic order |
| 150 | Runtime: kernel.unload_plugin() ok-when-absent semantics |
| 151 | Host: WASI 0.2 component negative-test for unknown export |
| 152 | Host: max-memory limit enforced + test |
| 153 | Peers: peer-allowlist canonical form is sorted dedup |
| 154 | Peers: peer record SerDe round-trip |
| 155 | OCI: digest reference validation |
| 156 | Wit: 5 interface enumeration test |
| 157 | SDK: macro expansion smoke test |
| 158 | atc-matrix: spec ↔ test cross-check helper |
| 159 | Workspace: every crate has README front-matter (lib doc points at spec)
| 160 | Final sprint-2 smoke build + test + clippy + doc; sign-off |

