# Candidate c19ef7587a2215ef9434b642413bebd0473caf20 scorecard

Source: `sha256:81d8219e78f71c2e2987800cec205d72c22d015e1db4e0fc7577ba424e4ef644`. Ready: **False**.

| Metric | Score | Pass | Fail | Not evidenced |
|---|---:|---:|---:|---:|
| authorization_isolation | 73.68% | 14 | 0 | 5 |
| correctness | 90.00% | 9 | 0 | 1 |
| interoperability | 0.00% | 0 | 0 | 5 |
| performance | 25.00% | 1 | 0 | 3 |
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
- **PERF-BASELINE (not_evidenced):** Fresh same-VM seven-route engineering comparison met p95 and rate limits on three of seven routes; local/1 and local/4 greeting p95 rose 23.5% and 12.5%, remote/4 greeting p95 rose 12.4%, and local image throughput ratio was 0.949914 (below 0.95). A previously approved comparable baseline is absent.
- **OPS-RELEASE (not_evidenced):** Four real production signed archives, provenance, rebuilds and installers are not demonstrated.
- **OPS-GOVERNANCE (fail):** Actual governance check fails: one named holder per role and no rotation note; key ceremony evidence is absent.
- **OPS-RECOVERY (not_evidenced):** Fresh Linux encrypted recovery restored identity, signed plugin state and live peer continuity; supported macOS remains unverified.
- **OPS-CI (not_evidenced):** Real required hosted CI and branch-protection results absent; user prohibited GitHub Actions.

This renderer validates file and receipt bindings; it cannot independently establish claims or reviewer independence.
## Evidence and limits

Three consecutive locked default-parallel workspace runs each passed 783 tests with 29 ignored ([first](workspace-test.json), [second](workspace-test-2.json), [third](workspace-test-3.json)); the Python sharder tests passed 5/5. All 16 tracked locked graphs passed advisory, license, ban and source checks. The [installer qualification](transactional-installer/normalized.json) exercised genuine compatible and incompatible optimized binaries in two Linux userlands, including a failed upgrade preserving both installed commands, partial repairs and second-rename rollback. Two distinct runnable builds reporting the same version can still be mistaken for a complete pair without `--force`. This does not establish power-loss atomicity.

The [packaging variance check](packaging-metadata-variations.json) verified identical native archive and sidecars under differing paths, file metadata, order, timezone, umask and ownership with identical input ELF bytes; it does not establish reproducible compiler output or independent macOS builds. The canonical archive still needs GLIBC_2.39. A separate unsigned GLIBC_2.34 archive passed Linux userland checks; neither is a signed production release. The [public rebuild](public-package-release-binary.json) used the current verifier on a published predecessor fixture.

The literal PERF-TEST score credits an upstream nine-crate workspace's 224 native-parity cases across two authenticated workers plus a separate controlled retry fixture ([workspace](distributed-rust-workspace/rngs-receipt.json), [retry](distributed-rust-release.json)). No naturally occurring upstream flake occurred. The [conservative scorecard](conservative-scorecard.md) applies the stricter preregistered plan that excludes the injected fixture and leaves this gate unverified.

The [primary seven-route comparison](performance.md) met the predeclared limits on three routes; four missed. Local image throughput ratio 0.949914 fell below 0.95 even though the displayed percent rounds to -5.0%. This comparison has no previously approved production baseline. The [photo oracle](raw-photographic-quality-receipt.json) verified two genuine RAW images, and a same-host two-photo batch measured 1.063× mesh versus one worker; neither meets the physical 8,000-photo performance criterion.

The initial [bandwidth placement test](bandwidth-live-scorer-receipt.json) failed its faster-peer assertion after both paths were exercised. A separate [preregistered diagnostic](bandwidth-diagnostic/receipt.json) later passed its route-selection checks; it does not replace the first failure. A source-bound [chooser analysis](bandwidth-placement-attribution/receipt.json) shows relative latency can change the expected winner; the first test did not capture the losing peer's full placement state, so the failure's cause is not established. The same-host test does not establish physical throughput.

The [scoped security review](successor-security-review.md) and [publisher incident exercise](publisher-incident-exercise.md) do not establish external audit or production key custody. The [private WireGuard recovery](private-recovery-linux.json) used namespaces on one physical host. The first Fish container invocation timed out; the separately retained interactive retry passed. The six-response TinyLlama CPU run does not meet the 70B workload. Physical hosts, production signing, current governance records and a previously approved comparable baseline remain open.
