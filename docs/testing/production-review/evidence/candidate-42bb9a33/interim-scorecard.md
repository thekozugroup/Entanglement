# Candidate 42bb9a3360ce2b4d5bcf2268dfa5a76bc6d6247e scorecard

Source: `sha256:fcb2f28c293a30b2496d2a788442782aba96c3806d4e4d1e868d4c6db32dc348`. Ready: **False**.

| Metric | Score | Pass | Fail | Not evidenced |
|---|---:|---:|---:|---:|
| authorization_isolation | 63.16% | 12 | 0 | 7 |
| correctness | 70.00% | 7 | 0 | 3 |
| interoperability | 0.00% | 0 | 0 | 5 |
| performance | 0.00% | 0 | 0 | 4 |
| release_operations | 7.69% | 1 | 0 | 12 |
| reliability | 50.00% | 3 | 0 | 3 |

## Blockers

- **ATC-PKG-1 (not_evidenced):** Fresh successor serial clean package digest evidence is pending.
- **ATC-PKG-2 (not_evidenced):** Fresh candidate Ubuntu user-space evidence pending; real macOS-14 and independent host evidence remain absent.
- **ATC-PKG-4 (not_evidenced):** A public detached signed package for this successor and independent public fetch/rebuild have not yet been demonstrated.
- **ATC-WRP-1 (not_evidenced):** Actual successor release install and fresh-shell opt-in evidence is pending.
- **ATC-WRP-3 (not_evidenced):** Candidate has new shell wrapper doctor tests; exact release interactive bypass cases are pending.
- **ATC-MAX-1 (not_evidenced):** No actual tier-5 agent-host fixture has been demonstrated for the specified interactive 5 to 3 transition.
- **ATC-MAX-2 (not_evidenced):** No actual tier-5 agent-host fixture has been demonstrated for the specified forced 5 to 3 transition.
- **ATC-MAX-3 (not_evidenced):** No actual tier-5 agent-host fixture has been demonstrated for the specified canceled 5 to 3 transition.
- **ATC-MIR-1 (not_evidenced):** Signed publisher-vs-mirror boundary is tested locally, but named production mirror delivery is not shown.
- **ATC-REL-1 (not_evidenced):** No production signed 1.0 RC artifact and actual keyless inclusion proof is available.
- **ATC-REL-2 (not_evidenced):** No actual documented two-of-three production release key ceremony is available.
- **ATC-BUS-1 (not_evidenced):** Fresh actual bus-factor governance receipt pending.
- **ATC-BUS-2 (not_evidenced):** Fresh rotation governance receipt pending.
- **COR-PLATFORMS (not_evidenced):** All specified real Linux and macOS candidate runners are not demonstrated; GitHub Actions are forbidden.
- **AUTH-LIVE (not_evidenced):** Fresh candidate live trust-revocation and both-direction denial test is pending.
- **AUTH-WASI (not_evidenced):** Full malicious filesystem cases on every supported OS host are not demonstrated.
- **AUTH-CHAIN (not_evidenced):** Fresh source-bound scans of the root and all standalone lockfiles are pending.
- **REL-RESTART (not_evidenced):** Fresh candidate active-work restart evidence pending; supported macOS host remains absent.
- **REL-PARTITION (not_evidenced):** Actual distinct-host link disconnect and transport restart are not demonstrated.
- **REL-LIMITS (not_evidenced):** Fresh release saturation/recovery evidence pending.
- **INTEROP-LINUX (not_evidenced):** Independent x86-64 and aarch64 Linux host workload results are not both demonstrated.
- **INTEROP-MAC (not_evidenced):** Real Intel and Apple Silicon macOS workloads are not demonstrated.
- **INTEROP-WAN (not_evidenced):** Independent networks and actual direct NAT traversal plus forced public relay are not demonstrated.
- **INTEROP-TAILNET (not_evidenced):** Two real tailnet hosts with access control and reconnection are not demonstrated.
- **INTEROP-LAN (not_evidenced):** Physical distinct-host multicast discovery and authenticated workload are not demonstrated.
- **PERF-LLM (not_evidenced):** Real 70B inference on specified GPU and battery laptop workload is not demonstrated.
- **PERF-IMAGE (not_evidenced):** 8,000 RAW images on three physical desktops and 10x speedup are not demonstrated.
- **PERF-TEST (not_evidenced):** Entire Rust workspace distributed with flaky aggregation is not demonstrated.
- **PERF-BASELINE (not_evidenced):** Same-VM 761 versus 864 comparison missed proposed limits in six of seven routes (including image-local p95 +50.3% and remote/4 p95 +31.9%); three-trial shared-VM variance limits attribution. No previously approved comparable baseline is recorded, so the formal gate remains unverified.
- **OPS-RELEASE (not_evidenced):** Four real production signed archives, provenance, rebuilds and installers are not demonstrated.
- **OPS-GOVERNANCE (not_evidenced):** Fresh candidate actual governance receipt pending.
- **OPS-RECOVERY (not_evidenced):** Fresh Linux and supported macOS encrypted recovery remain pending.
- **OPS-SECURITY (not_evidenced):** Fresh candidate independent review and dated incident rehearsal are pending.
- **OPS-CI (not_evidenced):** Real required hosted CI and branch-protection results absent; user prohibited GitHub Actions.

This renderer validates file and receipt bindings; it cannot independently establish claims or reviewer independence.
