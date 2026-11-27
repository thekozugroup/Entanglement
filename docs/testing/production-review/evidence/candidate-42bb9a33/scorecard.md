# Candidate 42bb9a3360ce2b4d5bcf2268dfa5a76bc6d6247e scorecard

Source: `sha256:fcb2f28c293a30b2496d2a788442782aba96c3806d4e4d1e868d4c6db32dc348`. Ready: **False**.

| Metric | Score | Pass | Fail | Not evidenced |
|---|---:|---:|---:|---:|
| authorization_isolation | 73.68% | 14 | 0 | 5 |
| correctness | 90.00% | 9 | 0 | 1 |
| interoperability | 0.00% | 0 | 0 | 5 |
| performance | 25.00% | 1 | 0 | 3 |
| release_operations | 30.77% | 4 | 3 | 6 |
| reliability | 66.67% | 4 | 0 | 2 |

## Blockers

- **ATC-PKG-2 (not_evidenced):** Fresh Ubuntu 22.04 and 24.04 rootless userspaces on one Linux host produced matching SHA-256 c8d547ddf795d9fee163dfc69cc5b7a86d7ed198d7a84748723e802be5331ed4; independent hardware and real macOS-14 results remain unavailable.
- **ATC-MAX-1 (not_evidenced):** No actual tier-5 agent-host fixture has been demonstrated for the specified interactive 5 to 3 transition.
- **ATC-MAX-2 (not_evidenced):** No actual tier-5 agent-host fixture has been demonstrated for the specified forced 5 to 3 transition.
- **ATC-MAX-3 (not_evidenced):** No actual tier-5 agent-host fixture has been demonstrated for the specified canceled 5 to 3 transition.
- **ATC-MIR-1 (not_evidenced):** Signed publisher-vs-mirror boundary is tested locally, but named production mirror delivery is not shown.
- **ATC-REL-1 (not_evidenced):** No production signed 1.0 RC artifact and actual keyless inclusion proof is available.
- **ATC-REL-2 (not_evidenced):** No actual documented two-of-three production release key ceremony is available.
- **ATC-BUS-1 (fail):** Fresh governance checker rejects five roles each having only one named holder.
- **ATC-BUS-2 (fail):** Fresh governance checker rejects missing rotations.md.
- **COR-PLATFORMS (not_evidenced):** All specified real Linux and macOS candidate runners are not demonstrated; GitHub Actions are forbidden.
- **AUTH-WASI (not_evidenced):** Full malicious filesystem cases on every supported OS host are not demonstrated.
- **REL-RESTART (not_evidenced):** Linux SIGKILL after signed chunks causes bounded failure; original identity and plugins restart and return a verified result in 405.155ms; supported macOS remains unverified.
- **REL-PARTITION (not_evidenced):** Actual distinct-host link disconnect and transport restart are not demonstrated.
- **INTEROP-LINUX (not_evidenced):** Independent x86-64 and aarch64 Linux host workload results are not both demonstrated.
- **INTEROP-MAC (not_evidenced):** Real Intel and Apple Silicon macOS workloads are not demonstrated.
- **INTEROP-WAN (not_evidenced):** Independent networks and actual direct NAT traversal plus forced public relay are not demonstrated.
- **INTEROP-TAILNET (not_evidenced):** Two real tailnet hosts with access control and reconnection are not demonstrated.
- **INTEROP-LAN (not_evidenced):** Physical distinct-host multicast discovery and authenticated workload are not demonstrated.
- **PERF-LLM (not_evidenced):** Real 70B inference on specified GPU and battery laptop workload is not demonstrated.
- **PERF-IMAGE (not_evidenced):** 8,000 RAW images on three physical desktops and 10x speedup are not demonstrated.
- **PERF-BASELINE (not_evidenced):** Same-VM 42 versus 864 comparison missed proposed limits in three of seven routes: image one-remote p95 +51.0%, local/4 p95 +9.6%, and remote/1 p95 +7.7% with throughput -8.7%. Three-trial shared-VM variance limits attribution; no previously approved comparable baseline is recorded.
- **OPS-RELEASE (not_evidenced):** Four real production signed archives, provenance, rebuilds and installers are not demonstrated.
- **OPS-GOVERNANCE (fail):** Fresh governance check fails: one named holder per role and no rotation note; key ceremony file is absent.
- **OPS-RECOVERY (not_evidenced):** Fresh Linux encrypted recovery restored identity, signed plugin state and live peer continuity; supported macOS recovery remains unverified.
- **OPS-CI (not_evidenced):** Real required hosted CI and branch-protection results absent; user prohibited GitHub Actions.

This renderer validates file and receipt bindings; it cannot independently establish claims or reviewer independence.

## Scope and qualification

The literal rubric gives PERF-TEST a pass: an unmodified nine-crate upstream Rust workspace ran across two authenticated workers and all 224 named outcomes matched native Cargo; a separate deterministic test actually failed on one worker, passed on another and was retained as flaky. No naturally occurring upstream flaky transition was observed. The predeclared stricter evidence plan excludes injected flaky fixtures. Under that additional condition PERF-TEST remains not evidenced, performance scores 0% instead of 25%, and release acceptance remains unmet. See `conservative-score.json`; neither interpretation finds the candidate ready.

This candidate differs from the preceding reviewed source only in `crates/entangle-agent-host/tests/session.rs`. Fresh locked workspace tests passed 756, failed 0, and ignored 28; both newly unignored session cases passed under default parallel execution. Formatting and focused all-target Clippy passed. The committed session fixture and source hash remained unchanged. This full review uses fresh candidate-bound evidence rather than inherited pass statuses.

Fresh optimized release checks cover seven independently decoded local and trusted-worker workloads, 24 live authorization cases, resource saturation, Linux restart and encrypted restoration, Bash/Zsh/Fish wrapper behavior, 14 locked dependency scans, and an independently fetched public signed test package rebuilt using the actual optimized cargo subcommand outside the checkout. Same-host Linux namespaces and Ubuntu userspaces do not establish independent-host, macOS or physical-network gates.

The final same-VM 42 versus 864 comparison missed proposed limits on three of seven routes: one-remote image p95 +51.0%, four-client local greeting p95 +9.6%, and one-client remote greeting p95 +7.7% with throughput -8.7%. These are median-of-three shared-VM observations, with no previously approved comparable baseline; they do not establish a formal performance pass or prove a cause. Separate real 1.1B CPU inference verified 139 signed chunks and direct-output matches in both busy and quiet samples, but is not the specified 70B GPU and battery-laptop workload.

The independent security review is bounded to its cited paths and reports no open high or critical issue in that scope. It does not establish external audit, actual production key custody, physical networking or native sandbox assurance.
