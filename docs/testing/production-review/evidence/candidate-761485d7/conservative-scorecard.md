# Candidate 761485d7490a56c7215ad958db81949204c74245 scorecard

Source: `sha256:d4bac68175f75abfc6b42773658c9022fd822051ffd1d6b38a58ab78df8c7281`. Ready: **False**.

| Metric | Score | Pass | Fail | Not evidenced |
|---|---:|---:|---:|---:|
| authorization_isolation | 73.68% | 14 | 0 | 5 |
| correctness | 90.00% | 9 | 0 | 1 |
| interoperability | 0.00% | 0 | 0 | 5 |
| performance | 0.00% | 0 | 0 | 4 |
| release_operations | 30.77% | 4 | 3 | 6 |
| reliability | 66.67% | 4 | 0 | 2 |

## Blockers

- **ATC-PKG-2 (not_evidenced):** Fresh Ubuntu 22.04 and 24.04 rootless userspaces on one host produced matching archive SHA-256 140bb868f466310310f75f10411772c8a2746b2c4b7d4f5dd1ab01f9478f50ba; separate real macOS-14 and independent hosts remain absent.
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
- **REL-RESTART (not_evidenced):** Linux SIGKILL after signed chunks causes bounded failure; original identity and plugins restart and return a verified result in 218.229ms; supported macOS remains unverified.
- **REL-PARTITION (not_evidenced):** Actual distinct-host link disconnect and transport restart are not demonstrated.
- **INTEROP-LINUX (not_evidenced):** Independent x86-64 and aarch64 Linux host workload results are not both demonstrated.
- **INTEROP-MAC (not_evidenced):** Real Intel and Apple Silicon macOS workloads are not demonstrated.
- **INTEROP-WAN (not_evidenced):** Independent networks and actual direct NAT traversal plus forced public relay are not demonstrated.
- **INTEROP-TAILNET (not_evidenced):** Two real tailnet hosts with access control and reconnection are not demonstrated.
- **INTEROP-LAN (not_evidenced):** Physical distinct-host multicast discovery and authenticated workload are not demonstrated.
- **PERF-LLM (not_evidenced):** Real 70B inference on specified GPU and battery laptop workload is not demonstrated.
- **PERF-IMAGE (not_evidenced):** 8,000 RAW images on three physical desktops and 10x speedup are not demonstrated.
- **PERF-TEST (not_evidenced):** The full unmodified nine-crate workspace matches all native outcomes across two workers and a separate deterministic retry fixture preserves failed-then-passed as flaky. The predeclared evidence plan expressly disallows an injected flaky fixture, and no naturally occurring upstream flake was observed.
- **PERF-BASELINE (not_evidenced):** Same-VM 761 versus 864 comparison missed proposed limits in six of seven routes (including image-local p95 +50.3% and remote/4 p95 +31.9%); three-trial shared-VM variance limits attribution. No previously approved comparable baseline is recorded, so the formal gate remains unverified.
- **OPS-RELEASE (not_evidenced):** Four real production signed archives, provenance, rebuilds and installers are not demonstrated.
- **OPS-GOVERNANCE (fail):** Fresh governance check fails: one named holder per role and no rotation note; key ceremony file is absent.
- **OPS-RECOVERY (not_evidenced):** Linux encrypted fresh-profile restore and peer continuity are demonstrated; supported macOS remains unverified.
- **OPS-CI (not_evidenced):** Real required hosted CI and branch-protection results absent; user prohibited GitHub Actions.

This renderer validates file and receipt bindings; it cannot independently establish claims or reviewer independence.

## Scope and qualification

The literal rubric gives PERF-TEST a pass: an unmodified nine-crate upstream workspace ran across two authenticated workers and all 224 named outcomes matched native Cargo; a separate deterministic test actually failed on one worker, passed on another and was retained as flaky. No naturally occurring upstream flaky transition was observed. The predeclared stricter evidence plan excludes injected flaky fixtures. Under that additional condition PERF-TEST is not evidenced, performance scores 0% rather than 25%, and release acceptance remains unmet. The separate conservative score is in `conservative-score.json`; neither interpretation finds the candidate ready.

The locked workspace suite passed 754 tests, with 30 ignored. My initial optional session command omitted its required serial setting; the resulting parallel run failed and temporarily deleted a tracked test fixture. The original blob was restored, its hash and frozen source were verified, and the correct serial tests and ATC inventory passed. The failed receipt is retained. The overlapping release build was rechecked with restored source and identical release binaries; the Ubuntu userspace builds used independent clean frozen Git-bundle checkouts.

Fresh optimized release checks cover seven decoded local and trusted-worker workloads, 24 live authorization cases, bounded saturation, a Linux restart, Bash/Zsh/Fish wrapper behavior, an independently fetched signed test package rebuilt by both the public-checkout alias and the actual optimized cargo subcommand, and 14 locked dependency scans. Same-host Linux results do not establish distinct-device, macOS or physical-network gates.

A measured shared-VM comparison against the previous candidate missed proposed limits in six of seven routes; the three-trial samples have host variability, and no previously approved formal baseline is recorded. Real 1.1B CPU inference on one host verified all 139 signed chunks and direct-output matches, but is not the 70B GPU/battery-laptop workload.

The independent security review is bounded to its cited paths and reports no open high or critical issue in that scope; it does not establish a production key ceremony, external audit, physical networking, or native sandbox coverage.
