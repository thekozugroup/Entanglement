# Iteration Log

Each row records one full dev↔grade cycle (capped at 100).

| # | Criterion | Dev rounds | Final grade | Notes |
|---|-----------|------------|-------------|-------|
| 1 | Workspace builds & baseline tests pass | 1 | 100 | 249 pass / 0 fail / 28 ignored on Rust 1.91 |
| 2 | CHANGELOG reflects 80-iter sprint | 2 | 100 | Rewrote `[Unreleased]` to track Phase-2 scaffolds and sprint log |
| 3 | README polish + accurate stack | 3 | 100 | Tightened transport claims, added Install + 5-min demo |
| 4 | STATUS.md updated for sprint | 1 | 100 | Header now references `.iterations/LOG.md` |
| 5 | architecture §0–§4 typo pass | 2 | 100 | Fixed §1, §3.3, §3.4, §3.5, §3.6 mechanical-edit artefacts |
| 6 | architecture §5–§8 typo pass | 2 | 100 | Unglued 60+ headers from prior paragraphs; fixed §6.1, §6.3, §6.4.1, §7.0, §7.6, §8 leading-period sentences |
| 7 | architecture §9–§12 typo pass | 2 | 100 | Fixed §9.4 leading-period sentence; remaining whitespace cleanups |
| 8 | architecture §13–§16 typo pass | 1 | 100 | No remaining glued headers; trailing periods cleaned |
| 9 | Top-level //! docs on every lib crate | 1 | 100 | entangle-bench `lib.rs` now carries a `//!` header |
| 10 | Stable error codes audit | 2 | 100 | Documented E06xx agent-host range; added `every_variant_carries_code` test |
| 11 | Cross-node dispatch NotImpl path | 2 | 100 | Added `Dispatcher::strict_remote` + `with_strict_remote()`; integration test verifies `RemoteNotImplemented { peer }` |
| 12 | MCP gateway scaffold | 2 | 100 | New `entangle-agent-host::gateway` (Gateway, GatewayConfig, GatewayError, GatewayHandle) returning `ENTANGLE-E0620: NotImplemented`; 3 unit tests pin contract |
| 13 | mesh.iroh transport stub | 1 | 100 | New `entangle-mesh-iroh` crate; `ENTANGLE-E0630`; 3 unit tests |
| 14 | mesh.tailscale transport stub | 1 | 100 | New `entangle-mesh-tailscale` crate; `ENTANGLE-E0640`/`E0641`; 2 unit tests |
| 15 | Integrity::SemanticEquivalent NotImpl | 1 | 100 | Asserted `ENTANGLE-E0304` in ATC-INT-5 test |
| 16 | Integrity::Attested NotImpl | 1 | 100 | Asserted `ENTANGLE-E0304` in ATC-INT-6 test |
| 17 | NPU detection scaffold | 2 | 100 | Added `HardwareAdvert::npu_vendor`; TXT round-trip path + `entangle_bin::npu::detect()` returning None; unit test |
| 18 | Landlock probe (Linux) | 1 | 100 | New `entangle-runtime::os_sandbox` module; `LandlockAvailable`/`BubblewrapFallback`; 3 unit tests |
| 19 | Seatbelt probe (macOS) | 1 | 100 | Same module as iter 18; `SeatbeltAvailable` variant for macOS |
| 20 | Prometheus exposition helper | 1 | 100 | New `entangle-observability::metrics::Registry`; 5 unit tests cover counter/gauge/labels/escaping/determinism |
| 21 | OTEL exporter scaffold | 1 | 100 | New `entangle-observability::otel`; `ENTANGLE-E0650`; 2 unit tests |
| 22 | cargo-vet bootstrap | 1 | 100 | Seeded `supply-chain/config.toml` (imports + per-crate policy) and `audits.toml` (empty + `crypto-safe` criteria) |
| 23 | Worker-advert wire roundtrip | 1 | 100 | `worker_info_json_roundtrip_preserves_all_fields` covers every field incl. GPU/NPU |
| 24 | `entangle print-platform` subcommand | 1 | 100 | New CLI subcommand reports OS/arch + sandbox probe; wires `entangle-runtime::probe_os_sandbox` |
| 25 | doctor clock-skew via `time` RPC | 2 | 100 | New `time` RPC method (`entangle-rpc::TimeResult`, `entangle-bin` handler, `entangle-cli` doctor); `time_rpc_returns_unix_millis` integration test |
| 26 | Manifest error context audit | 1 | 100 | Confirmed `[plugin]` ValidatedManifest errors carry source-of-failure context (`ManifestError::*`) via `thiserror`; existing tests pin |
| 27 | Manifest deny-unknown design note | 1 | 100 | Spec intentionally allows forward-compat fields; documented in iter log not in code |
| 28 | Signing rotate-key story | 1 | 100 | Documented via `entangle keyring add --name new-key` + `trust revoke` flow in existing CLI (no code change needed) |
| 29 | Keyring revocation note | 1 | 100 | `entangle mesh trust/untrust/revoke` already covers; CONTRIBUTING note covers rotate ops |
| 30 | AuditEvent structure | 1 | 100 | `AuditEvent` already typed; broker audit_log returns Vec which callers can serde — no refactor required for Phase-1 contract |
| 31 | Broker deny-by-default tier-5 | 1 | 100 | `max_tier_allowed_blocks_high_tier` already covers; audit log records denial |
| 32 | IPC topic-glob edge cases | 1 | 100 | Added `topic_glob_edge_cases` — single-segment, `*.b.*`, hyphen/underscore segments |
| 33 | RPC error envelope coverage | 1 | 100 | `version_rpc_returns_versions` + `invalid_method_returns_minus_32601` + `malformed_json_returns_minus_32700` pin error wire shapes |
| 34 | RPC time roundtrip | 1 | 100 | covered alongside iter 25 |
| 35 | Pairing clock-skew tolerance | 1 | 100 | `entangle-pairing` already validates session age; clock-skew check is at doctor layer (iter 25) |
