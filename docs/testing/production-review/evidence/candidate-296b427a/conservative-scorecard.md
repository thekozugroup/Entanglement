# Conservative production assessment

Source `296b427a3bb2d60615ea3c56b9779f97039c6e24`. All 57 criteria are mandatory. Scores use the full denominator and the frozen rubric. Each missing verification earns zero credit. [Run ledger](../../runs/candidate-296b427a-conservative.json)

| Metric | Pass | Fail | Unverified | Score |
|---|---:|---:|---:|---:|
| Correctness | 9 | 0 | 1 | 90.00% |
| Authorization and isolation | 14 | 0 | 5 | 73.68% |
| Reliability | 4 | 0 | 2 | 66.67% |
| Interoperability | 0 | 0 | 5 | 0.00% |
| Performance | 0 | 0 | 4 | 0.00% |
| Release and operations | 4 | 3 | 6 | 30.77% |

## Open checks

- **ATC-PKG-2** (unverified). Fresh candidate Ubuntu user-space evidence pending; real macOS-14 and independent host evidence remain absent.
- **ATC-MAX-1** (unverified). The required loaded tier-5 agent host and affected 5-to-3 list remain unverified.
- **ATC-MAX-2** (unverified). The required loaded tier-5 agent host and affected 5-to-3 list remain unverified.
- **ATC-MAX-3** (unverified). The required loaded tier-5 agent host and affected 5-to-3 list remain unverified.
- **ATC-MIR-1** (unverified). Fresh direct and approved proxy probes failed before reaching the named mirror (CONNECT 403 and DNS temporary failure); origin health remains unknown.
- **ATC-REL-1** (unverified). No production signed 1.0 RC artifact and actual keyless inclusion proof is available.
- **ATC-REL-2** (unverified). No actual documented two-of-three production release key ceremony is available.
- **ATC-BUS-1** (fail). Actual governance check rejects five roles each with only one named holder.
- **ATC-BUS-2** (fail). Actual governance check rejects missing rotation record.
- **COR-PLATFORMS** (unverified). All specified real Linux and macOS candidate runners are not demonstrated; GitHub Actions are forbidden.
- **AUTH-WASI** (unverified). Full malicious filesystem cases on every supported OS host are not demonstrated.
- **REL-RESTART** (unverified). Fresh Linux active-stream termination and restart recovery passed; supported macOS remains unverified.
- **REL-PARTITION** (unverified). Linux same-host namespaces recovered after private overlay restarts, but worker overlay-to-job took 27.939s and coordinator 1.860s; independent physical host partition coverage remains absent.
- **INTEROP-LINUX** (unverified). Independent actual x86-64 and aarch64 host workloads remain unverified.
- **INTEROP-MAC** (unverified). Real Intel and Apple Silicon macOS workloads are not demonstrated.
- **INTEROP-WAN** (unverified). Independent networks and actual direct NAT traversal plus forced public relay are not demonstrated.
- **INTEROP-TAILNET** (unverified). Two real tailnet hosts with access control and reconnection are not demonstrated.
- **INTEROP-LAN** (unverified). Physical distinct-host multicast discovery and authenticated workload are not demonstrated.
- **PERF-LLM** (unverified). The specified 70B GPU plus battery laptop workload remains unverified.
- **PERF-IMAGE** (unverified). A same-host two-photo run measured 1.160x for three workers versus one; the 8,000 RAW, three physical desktops and 10x speedup requirement remains unverified.
- **PERF-TEST** (unverified). A genuine 128-block jaq witness records an assertion fail→pass across two authenticated workers on the same signed artifact, but that workspace has eight WASI sandbox golden failures and a native-only CLI. A different nine-crate workspace has 224 matching outcomes but no natural flake; the stricter workspace-wide same-suite evidence remains incomplete.
- **PERF-BASELINE** (unverified). Fresh same-VM seven-route comparison met engineering limits in three routes and missed four: local image p95 +11.0%, local greeting p95 +6.1%/+9.2%, remote/4 p95 +12.9%. A previously approved comparable production baseline is absent.
- **OPS-RELEASE** (unverified). Four real production signed archives, provenance, rebuilds and installers are not demonstrated.
- **OPS-GOVERNANCE** (fail). Actual governance check fails: one named holder per role and no rotation note; key ceremony evidence is absent.
- **OPS-RECOVERY** (unverified). Fresh Linux encrypted recovery restored identity, signed plugin state and live peer continuity; supported macOS remains unverified.
- **OPS-CI** (unverified). Real required hosted CI and branch-protection results absent; user prohibited GitHub Actions.
