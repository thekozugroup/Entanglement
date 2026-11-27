# Candidate a0926c6ef3471aad01cedd256028437b249ef747 scorecard

Source: `sha256:a2848766dd5b69cf72246e7cba06c95afe1807d2556f00efec115cdd40cdca45`. Ready: **False**.

| Metric | Score | Pass | Fail | Not evidenced |
|---|---:|---:|---:|---:|
| authorization_isolation | 73.68% | 14 | 0 | 5 |
| correctness | 90.00% | 9 | 0 | 1 |
| interoperability | 0.00% | 0 | 0 | 5 |
| performance | 25.00% | 1 | 0 | 3 |
| release_operations | 30.77% | 4 | 3 | 6 |
| reliability | 66.67% | 4 | 0 | 2 |

## Blockers

- **ATC-PKG-2 (not_evidenced):** Fresh disconnected Ubuntu 22.04 and 24.04 rootless userspaces produced identical archive SHA-256 9aba9778bf526db8727d60f27902c772b092c2c3577557b25dddd67b48f18545 on one Linux host; real macOS and independent hosts remain unverified.
- **ATC-MAX-1 (not_evidenced):** Actual 5-to-3 with unaffected tier-3 survivor and affected 5-to-2 prompt/cancel/force tests pass; a loaded tier-5 agent host and affected 5-to-3 list remain unverified.
- **ATC-MAX-2 (not_evidenced):** Actual 5-to-3 with unaffected tier-3 survivor and affected 5-to-2 prompt/cancel/force tests pass; a loaded tier-5 agent host and affected 5-to-3 list remain unverified.
- **ATC-MAX-3 (not_evidenced):** Actual 5-to-3 with unaffected tier-3 survivor and affected 5-to-2 prompt/cancel/force tests pass; a loaded tier-5 agent host and affected 5-to-3 list remain unverified.
- **ATC-MIR-1 (not_evidenced):** Local publisher-vs-mirror verification is tested, but the named production mirror could not be reached: proxy CONNECT 403 and DNS temporary failure; origin health remains unknown.
- **ATC-REL-1 (not_evidenced):** No production signed 1.0 RC artifact and actual keyless inclusion proof is available.
- **ATC-REL-2 (not_evidenced):** No actual documented two-of-three production release key ceremony is available.
- **ATC-BUS-1 (fail):** Actual governance check rejects five roles each with only one named holder.
- **ATC-BUS-2 (fail):** Actual governance check rejects missing rotation record.
- **COR-PLATFORMS (not_evidenced):** All specified real Linux and macOS candidate runners are not demonstrated; GitHub Actions are forbidden.
- **AUTH-WASI (not_evidenced):** Full malicious filesystem cases on every supported OS host are not demonstrated.
- **REL-RESTART (not_evidenced):** Linux SIGKILL after signed chunks causes bounded failure; identity/plugins recover and verified result returns in 634.129ms after restart; supported macOS remains unverified.
- **REL-PARTITION (not_evidenced):** Actual private WireGuard and Headscale cold-ACL and restarts passed between Linux namespaces; independent physical hosts and link partitions remain unverified.
- **INTEROP-LINUX (not_evidenced):** Canonical Linux release binaries ran on Ubuntu 24.04 and Debian 13, but failed on Ubuntu 22.04 and Debian 12 due to GLIBC_2.39; independent x86-64 and aarch64 host workloads remain unverified.
- **INTEROP-MAC (not_evidenced):** Real Intel and Apple Silicon macOS workloads are not demonstrated.
- **INTEROP-WAN (not_evidenced):** Independent networks and actual direct NAT traversal plus forced public relay are not demonstrated.
- **INTEROP-TAILNET (not_evidenced):** Two real tailnet hosts with access control and reconnection are not demonstrated.
- **INTEROP-LAN (not_evidenced):** Physical distinct-host multicast discovery and authenticated workload are not demonstrated.
- **PERF-LLM (not_evidenced):** A six-response TinyLlama 1.1B CPU replay with verified chunks passed after an earlier 0/6 timeout; the specified 70B GPU and battery laptop workload remains unverified.
- **PERF-IMAGE (not_evidenced):** Two genuine CC0 RAW images passed an independent full-frame quality oracle; a three-pair same-host comparison measured 1.246x for mesh vs one worker. 8,000 RAW on three physical desktops and 10x speedup remain unverified.
- **PERF-BASELINE (not_evidenced):** Same-VM 7-route engineering comparison met p95 and rate limits on four of seven routes; local image p95 rose 36.9% and rate fell 8.3%, 3-remote image p95 rose 5.1%, and local/4 greeting p95 rose 31.9% and rate fell 5.3%. A previously approved comparable baseline is absent.
- **OPS-RELEASE (not_evidenced):** Four real production signed archives, provenance, rebuilds and installers are not demonstrated.
- **OPS-GOVERNANCE (fail):** Actual governance check fails: one named holder per role and no rotation note; key ceremony evidence is absent.
- **OPS-RECOVERY (not_evidenced):** Fresh Linux encrypted recovery restored identity, signed plugin state and live peer continuity; supported macOS remains unverified.
- **OPS-CI (not_evidenced):** Real required hosted CI and branch-protection results absent; user prohibited GitHub Actions.

This renderer validates file and receipt bindings; it cannot independently establish claims or reviewer independence.

## Evidence and limitations

Three independent consecutive locked default-parallel workspace runs each passed 783 tests with 29 ignored ([first](workspace-test.json), [second](workspace-test-2.json), [third](workspace-test-3.json)); the fresh sharder tests passed 5/5. All 16 tracked locked graphs passed advisory, license, ban and source checks. The [photographic oracle](raw-photographic-quality-receipt.json) checked two genuine CC0 RAW files and synthetic scenes, with zero differing RGB16 samples; this one-host functional evidence does not establish the 8,000-photo physical speed goal. A three-pair same-host RAW comparison measured 1.246× mesh versus one worker.

The literal PERF-TEST score credits the real upstream nine-member workspace's 224 native-parity cases over two authenticated workers and a separate controlled real retry fixture ([workspace](distributed-rust-workspace/rngs-receipt.json), [retry](distributed-rust-release.json)). No naturally occurring upstream flake occurred. The [conservative scorecard](conservative-scorecard.md) applies the stricter predeclared evidence-plan rule excluding injected flaky fixtures; it leaves PERF-TEST unverified, with the other gates unchanged.

The seven-route [primary engineering comparison](performance.md) met the latency and throughput limits on four routes, missing on image-local, image-three-remote and greeting-local/4. In a separate preregistered six-pair [three-remote sensitivity test](three-remote-sensitivity/results.json), median p95 was 0.968×; this does not erase the primary 1.051× result or establish the cause. No approved comparable production baseline is recorded.

The canonical archive requires GLIBC_2.39 and failed to launch in Ubuntu 22.04 and Debian 12 userlands ([matrix](canonical-linux-userlands.json)). A separate unsigned [Ubuntu-compatible archive](jammy-posix-installer/jammy-posix-installer.json) installed on Ubuntu 22.04 and 24.04, but is not the canonical release. Both are one-host userland tests, not independent physical-host coverage or a production signing ceremony. The [public rebuild](public-package-release-binary.json) used the current verifier on a published predecessor fixture.

The [scoped security review](successor-security-review.md) and [publisher incident exercise](publisher-incident-exercise.md) do not establish external audit or production key custody. The [private WireGuard recovery](private-recovery-linux.json) used separate namespaces on one physical host. The shell and TinyLlama checks passed on quieter retries; the earlier Fish container timeout and six model timeouts are retained and their causes are not established. TinyLlama 1.1B on one CPU host does not meet the 70B workload.
