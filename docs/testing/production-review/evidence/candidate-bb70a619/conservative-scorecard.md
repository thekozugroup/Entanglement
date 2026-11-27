# Candidate bb70a6193f8879b1feb3e6d3ceb8f2980413ce58 scorecard

Source: `sha256:9cae32b67ebd4784779d1c37cd9cea5efc1a640fdfd71fca9a67dda8d9c777ab`. Ready: **False**.

| Metric | Score | Pass | Fail | Not evidenced |
|---|---:|---:|---:|---:|
| authorization_isolation | 73.68% | 14 | 0 | 5 |
| correctness | 90.00% | 9 | 0 | 1 |
| interoperability | 0.00% | 0 | 0 | 5 |
| performance | 0.00% | 0 | 0 | 4 |
| release_operations | 30.77% | 4 | 3 | 6 |
| reliability | 66.67% | 4 | 0 | 2 |

## Blockers

- **ATC-PKG-2 (not_evidenced):** Fresh Ubuntu 22.04 and 24.04 rootless userspaces on one Linux host produced identical archive SHA-256 6f97aa481728839f8ad155a6f65673ec1ab1038e4ddeae5bae219195f3cfea3f; real macOS and independent hosts remain unverified.
- **ATC-MAX-1 (not_evidenced):** Actual 5-to-3 with unaffected tier-3 survivor and affected 5-to-2 prompt/cancel/force tests pass; a loaded tier-5 agent host and affected 5-to-3 list remain unverified.
- **ATC-MAX-2 (not_evidenced):** Actual 5-to-3 with unaffected tier-3 survivor and affected 5-to-2 prompt/cancel/force tests pass; a loaded tier-5 agent host and affected 5-to-3 list remain unverified.
- **ATC-MAX-3 (not_evidenced):** Actual 5-to-3 with unaffected tier-3 survivor and affected 5-to-2 prompt/cancel/force tests pass; a loaded tier-5 agent host and affected 5-to-3 list remain unverified.
- **ATC-MIR-1 (not_evidenced):** Signed publisher-vs-mirror boundary is tested locally, but named production mirror delivery is not shown.
- **ATC-REL-1 (not_evidenced):** No production signed 1.0 RC artifact and actual keyless inclusion proof is available.
- **ATC-REL-2 (not_evidenced):** No actual documented two-of-three production release key ceremony is available.
- **ATC-BUS-1 (fail):** Actual governance check rejects five roles each with only one named holder.
- **ATC-BUS-2 (fail):** Actual governance check rejects missing rotation record.
- **COR-PLATFORMS (not_evidenced):** All specified real Linux and macOS candidate runners are not demonstrated; GitHub Actions are forbidden.
- **AUTH-WASI (not_evidenced):** Full malicious filesystem cases on every supported OS host are not demonstrated.
- **REL-RESTART (not_evidenced):** Linux SIGKILL after signed chunks causes bounded failure; identity/plugins recover and verified result returns in 538ms after restart; supported macOS remains unverified.
- **REL-PARTITION (not_evidenced):** A real private WireGuard/Headscale experiment exercised cold ACL deny/allow and service restarts in separate Linux namespaces, but distinct physical hosts and link partitions remain unverified.
- **INTEROP-LINUX (not_evidenced):** Release executables ran in Ubuntu 24.04 and Debian 13 userlands, but fail to launch on Ubuntu 22.04 and Debian 12 due to GLIBC_2.39; independent real x86-64 and aarch64 host workloads remain unverified.
- **INTEROP-MAC (not_evidenced):** Real Intel and Apple Silicon macOS workloads are not demonstrated.
- **INTEROP-WAN (not_evidenced):** Independent networks and actual direct NAT traversal plus forced public relay are not demonstrated.
- **INTEROP-TAILNET (not_evidenced):** Two real tailnet hosts with access control and reconnection are not demonstrated.
- **INTEROP-LAN (not_evidenced):** Physical distinct-host multicast discovery and authenticated workload are not demonstrated.
- **PERF-LLM (not_evidenced):** One-host CPU TinyLlama 1.1B produced six direct-matching responses and 139 independently verified chunk signatures; the specified 70B GPU plus battery laptop workload remains unverified.
- **PERF-IMAGE (not_evidenced):** Two genuine CC0 RAW images passed an independent full-frame quality oracle. A controlled three-pair same-host batch measured 1.125x for three workers against one; 8,000 RAW on three physical desktops and 10x speedup remain unverified.
- **PERF-TEST (not_evidenced):** The genuine 224-case upstream Rust workspace matches native on two workers and a separate deterministic live fixture preserves flaky outcomes, but the predeclared stricter evidence plan excludes injected flaky fixtures; no naturally occurring upstream flake was observed.
- **PERF-BASELINE (not_evidenced):** Same-VM comparison to 864ae27b met p95 and throughput engineering limits on four of seven routes; image-local rate missed by 5.2%, one-remote image p95 rose 6.3% and rate fell 7.0%, and one-remote greeting p95 rose 9.6%. No previously approved comparable baseline is recorded.
- **OPS-RELEASE (not_evidenced):** Four real production signed archives, provenance, rebuilds and installers are not demonstrated.
- **OPS-GOVERNANCE (fail):** Actual governance check fails: one named holder per role and no rotation note; key ceremony evidence is absent.
- **OPS-RECOVERY (not_evidenced):** Fresh Linux encrypted recovery restored identity, signed plugin state and live peer continuity; supported macOS remains unverified.
- **OPS-CI (not_evidenced):** Real required hosted CI and branch-protection results absent; user prohibited GitHub Actions.

This renderer validates file and receipt bindings; it cannot independently establish claims or reviewer independence.
