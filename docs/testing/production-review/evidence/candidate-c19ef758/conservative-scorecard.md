# Candidate c19ef7587a2215ef9434b642413bebd0473caf20 scorecard

Source: `sha256:81d8219e78f71c2e2987800cec205d72c22d015e1db4e0fc7577ba424e4ef644`. Ready: **False**.

| Metric | Score | Pass | Fail | Not evidenced |
|---|---:|---:|---:|---:|
| authorization_isolation | 73.68% | 14 | 0 | 5 |
| correctness | 90.00% | 9 | 0 | 1 |
| interoperability | 0.00% | 0 | 0 | 5 |
| performance | 0.00% | 0 | 0 | 4 |
| release_operations | 30.77% | 4 | 3 | 6 |
| reliability | 66.67% | 4 | 0 | 2 |

## Blockers

- **ATC-PKG-2 (not_evidenced):** Fresh offline Ubuntu 22.04 and 24.04 userlands yielded byte-identical plugin package 37403626… on one Linux host; physical macOS and independent hosts remain unverified.
- **ATC-MAX-1 (not_evidenced):** Candidate tier boundary tests pass for a 5-to-3 unaffected tier-3 survivor and 5-to-2 affected cases; loaded tier-5 agent host and affected 5-to-3 list remain unverified.
- **ATC-MAX-2 (not_evidenced):** Candidate tier boundary tests pass for a 5-to-3 unaffected tier-3 survivor and 5-to-2 affected cases; loaded tier-5 agent host and affected 5-to-3 list remain unverified.
- **ATC-MAX-3 (not_evidenced):** Candidate tier boundary tests pass for a 5-to-3 unaffected tier-3 survivor and 5-to-2 affected cases; loaded tier-5 agent host and affected 5-to-3 list remain unverified.
- **ATC-MIR-1 (not_evidenced):** Local publisher-vs-mirror verification is tested, but the named production mirror could not be reached: proxy CONNECT 403 and DNS temporary failure; origin health remains unknown.
- **ATC-REL-1 (not_evidenced):** No production signed 1.0 RC artifact and actual keyless inclusion proof is available.
- **ATC-REL-2 (not_evidenced):** No actual documented two-of-three production release key ceremony is available.
- **ATC-BUS-1 (fail):** Actual governance check rejects five roles each with only one named holder.
- **ATC-BUS-2 (fail):** Actual governance check rejects missing rotation record.
- **COR-PLATFORMS (not_evidenced):** All specified real Linux and macOS candidate runners are not demonstrated; GitHub Actions are forbidden.
- **AUTH-WASI (not_evidenced):** Full malicious filesystem cases on every supported OS host are not demonstrated.
- **REL-RESTART (not_evidenced):** Fresh Linux active-stream termination and restart recovery passed; supported macOS remains unverified.
- **REL-PARTITION (not_evidenced):** Real private WireGuard and Headscale ACL and service restart tests passed between Linux namespaces; independent physical hosts and link partitions remain unverified.
- **INTEROP-LINUX (not_evidenced):** Canonical release requires GLIBC_2.39; a separate unsigned GLIBC_2.34 compatible archive passed four local userlands. Independent actual x86-64 and aarch64 hosts remain unverified.
- **INTEROP-MAC (not_evidenced):** Real Intel and Apple Silicon macOS workloads are not demonstrated.
- **INTEROP-WAN (not_evidenced):** Independent networks and actual direct NAT traversal plus forced public relay are not demonstrated.
- **INTEROP-TAILNET (not_evidenced):** Two real tailnet hosts with access control and reconnection are not demonstrated.
- **INTEROP-LAN (not_evidenced):** Physical distinct-host multicast discovery and authenticated workload are not demonstrated.
- **PERF-LLM (not_evidenced):** Fresh six-response TinyLlama 1.1B CPU run passed with 139 verified signatures; specified 70B GPU plus battery laptop workload remains unverified.
- **PERF-IMAGE (not_evidenced):** Two genuine CC0 RAW images passed an independent full-frame quality oracle; same-host 3-worker timing was 1.063x versus one worker. The 8,000 RAW, three physical desktops and 10x speedup requirement remains unverified.
- **PERF-TEST (not_evidenced):** A genuine 224-case upstream Rust workspace matches native across two workers and a separate deterministic live fixture preserves flaky outcomes, but the predeclared stricter evidence plan excludes injected flaky fixtures; no naturally occurring upstream flake was observed.
- **PERF-BASELINE (not_evidenced):** Fresh same-VM seven-route engineering comparison met p95 and rate limits on three of seven routes; local/1 and local/4 greeting p95 rose 23.5% and 12.5%, remote/4 greeting p95 rose 12.4%, and local image throughput ratio was 0.949914 (below 0.95). A previously approved comparable baseline is absent.
- **OPS-RELEASE (not_evidenced):** Four real production signed archives, provenance, rebuilds and installers are not demonstrated.
- **OPS-GOVERNANCE (fail):** Actual governance check fails: one named holder per role and no rotation note; key ceremony evidence is absent.
- **OPS-RECOVERY (not_evidenced):** Fresh Linux encrypted recovery restored identity, signed plugin state and live peer continuity; supported macOS remains unverified.
- **OPS-CI (not_evidenced):** Real required hosted CI and branch-protection results absent; user prohibited GitHub Actions.

This renderer validates file and receipt bindings; it cannot independently establish claims or reviewer independence.
