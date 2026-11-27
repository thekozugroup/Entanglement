# Candidate 864ae27bf3fd08e9d9c62abd4f43ff7bfd4c68c2 scorecard

Source: `sha256:2a5db79622c3130c68614ca443ad93b86efec77c11bb5b4e84f6ad7c02277c68`. Ready: **False**.

| Metric | Score | Pass | Fail | Not evidenced |
|---|---:|---:|---:|---:|
| authorization_isolation | 73.68% | 14 | 0 | 5 |
| correctness | 90.00% | 9 | 0 | 1 |
| interoperability | 0.00% | 0 | 0 | 5 |
| performance | 0.00% | 0 | 0 | 4 |
| release_operations | 30.77% | 4 | 3 | 6 |
| reliability | 66.67% | 4 | 0 | 2 |

## Blockers

- **ATC-PKG-2 (not_evidenced):** Ubuntu 22.04 and 24.04 rootless userspaces on one Linux host produced identical archive SHA-256 a4da1c97f3a4da18720c470cbb64f9ded945943851f3924664694733f19384d1; independent hardware and real macOS-14 results remain absent.
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
- **REL-RESTART (not_evidenced):** Linux release SIGKILL during active verified stream, bounded failure, identity restoration and verified result 119.57 ms after restart passed; supported macOS host remains absent.
- **REL-PARTITION (not_evidenced):** Actual distinct-host link disconnect and transport restart are not demonstrated.
- **INTEROP-LINUX (not_evidenced):** Independent x86-64 and aarch64 Linux host workload results are not both demonstrated.
- **INTEROP-MAC (not_evidenced):** Real Intel and Apple Silicon macOS workloads are not demonstrated.
- **INTEROP-WAN (not_evidenced):** Independent networks and actual direct NAT traversal plus forced public relay are not demonstrated.
- **INTEROP-TAILNET (not_evidenced):** Two real tailnet hosts with access control and reconnection are not demonstrated.
- **INTEROP-LAN (not_evidenced):** Physical distinct-host multicast discovery and authenticated workload are not demonstrated.
- **PERF-LLM (not_evidenced):** Real 70B inference on specified GPU and battery laptop workload is not demonstrated.
- **PERF-IMAGE (not_evidenced):** 8,000 RAW images on three physical desktops and 10x speedup are not demonstrated.
- **PERF-TEST (not_evidenced):** Entire Rust workspace distributed with flaky aggregation is not demonstrated.
- **PERF-BASELINE (not_evidenced):** Measured historical comparison has unapproved baseline and misses proposed per-route engineering limits: image local p95 +12.6% and throughput -12.1%, local greeting at one client throughput -9.0%, and remote greeting at one client p95 +5.8%. Formal approved-baseline gate remains unverified.
- **OPS-RELEASE (not_evidenced):** Four real production signed archives, provenance, rebuilds and installers are not demonstrated.
- **OPS-GOVERNANCE (fail):** Fresh governance check fails: one named holder per role and no rotation note; key ceremony file is absent.
- **OPS-RECOVERY (not_evidenced):** Fresh Linux encrypted recovery restored peer identity, trust and signed plugin state with live continuity; supported macOS host remains absent.
- **OPS-CI (not_evidenced):** Real required hosted CI and branch-protection results absent; user prohibited GitHub Actions.

This renderer validates file and receipt bindings; it cannot independently establish claims or reviewer independence.

The locked workspace suite passed 750 tests with 30 ignored. The separately selected agent-session and acceptance-inventory tests passed. The initial optional wrapper attempt lacked Fish and the initial agent-session command targeted the wrong package; both diagnostics are retained, and the complete shell and correct session runs passed. Seven decoded workloads passed locally and through the selected trusted worker using optimized candidate binaries. The independently fetched public test fixture rebuilt with a matching SHA-256 from the recorded successor commit; it is not a production release.

The dated security review is scoped to the cited package, stream, peer, shell and local RPC paths. It identifies no open high or critical finding in those paths; the previous direct-loader issue is closed for the tested Linux path. It does not claim external audit, real production key custody, physical networking, or platform-wide native sandbox assurance.

The shared-VM historical comparison showed local image p95 +12.6% and throughput -12.1%, local one-client greeting throughput -9.0%, and remote one-client greeting p95 +5.8%. Four other tested routes met the proposed engineering limits. The historical build has no recorded prior approval as the formal comparable baseline, so PERF-BASELINE is not evidenced. This does not establish the physical 70B or RAW-photo acceptance workloads.
