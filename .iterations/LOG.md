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
