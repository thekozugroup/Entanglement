# Candidate 2602ce17 production scorecard

Candidate source `sha256:c276c15010e510172c5fbf07e6d3dc3c979f8270e0eb0b200026e7b6c5f6770e`; rubric `sha256:d133c5f4f0df318c97080ea923ba65071d5599f05a7e1f1aa37b1fa2b1727322`. The reproducible [run](../../runs/candidate-2602ce17-final.json) binds each credited observation to hashed evidence. The scorer verifies the current source. All six metrics must exceed 95% and every hard gate must pass. **Decision: not production ready.**

| Metric | Score | Pass | Fail | Not evidenced |
|---|---:|---:|---:|---:|
| authorization isolation | 73.68% | 14 | 0 | 5 |
| correctness | 80.00% | 8 | 1 | 1 |
| interoperability | 0.00% | 0 | 0 | 5 |
| performance | 0.00% | 0 | 0 | 4 |
| release operations | 30.77% | 4 | 3 | 6 |
| reliability | 66.67% | 4 | 0 | 2 |

The exact-source locked workspace suite passed 746 tests, with 28 ignored. Seven production CLI workloads passed locally and on a separate loopback worker. The signed test package was independently fetched from public Git commit `cd94d73116633f35803212df4183a24fa6a64b06` and rebuilt from recorded source `2602ce17` with matching SHA-256. This is a disposable fixture, not a signed release.

The local independent security reviews found no unresolved high or critical issue in their stated scopes. One medium local direct-loader availability finding remains open. The security review and local incident rehearsal do not establish production ceremony, external auditing or coverage of every runtime and deployment.

The final shared-VM paired benchmark reported local image p95 +48.0%, local greeting p95 +34.8% at one client and +8.9% at four, and remote greeting p95 +8.0% at one client against the measured historical build. That build was not previously approved as the formal comparable baseline, so the performance gate remains not evidenced. Loopback results do not establish physical 70B GPU or three-desktop RAW workload targets.

## Unmet or unverified gates

### Authorization Isolation

- **ATC-MAX-1 (not_evidenced):** Real tier-3 fixture is tested at 5 to 2; required tier-5 agent-host and 5 to 3 scenario are unavailable.
- **ATC-MAX-2 (not_evidenced):** Force-unload fixture covers tier-3 plugins, not the required actual tier-5 agent-host.
- **ATC-MAX-3 (not_evidenced):** Cancel fixture covers tier-3 plugins, not the required actual tier-5 agent-host.
- **ATC-MIR-1 (not_evidenced):** Publisher versus mirror key separation and local HTTPS registry are tested; the specified named production mirror has not served an artifact.
- **AUTH-WASI (not_evidenced):** Linux guest isolation tests exist; full malicious filesystem cases on every supported OS host are not demonstrated.

### Correctness

- **ATC-WRP-3 (fail):** Actual parent-shell wrapper bypass with stale marker produces no doctor warning and exit 0; the literal stated PATH-before-function mechanism is not how normal shell resolution works, and alias/replacement failures are separately demonstrated.
- **COR-PLATFORMS (not_evidenced):** Final macOS hosted or independently operated host evidence is absent.

### Interoperability

- **INTEROP-LINUX (not_evidenced):** Only x86-64 Linux native workload is demonstrated; independent aarch64 host remains absent.
- **INTEROP-MAC (not_evidenced):** Neither real Intel nor Apple Silicon macOS release workload is demonstrated.
- **INTEROP-WAN (not_evidenced):** No two independent networks with actual direct NAT traversal and forced public relay are demonstrated.
- **INTEROP-TAILNET (not_evidenced):** No two actual tailnet hosts with access controls and disconnection/reconnection are demonstrated.
- **INTEROP-LAN (not_evidenced):** Physical hosts and real multicast discovery without a configured address are not demonstrated.

### Performance

- **PERF-LLM (not_evidenced):** Specified real 70B GPU plus battery laptop workload is not demonstrated.
- **PERF-IMAGE (not_evidenced):** Specified 8000 RAW photos across three physical desktops and 10x speedup is not demonstrated.
- **PERF-TEST (not_evidenced):** Two real existing Rust targets and flaky aggregation are demonstrated on loopback, but the entire Rust workspace distributed workflow is not.
- **PERF-BASELINE (not_evidenced):** Final shared-VM paired benchmark observed p95 regressions of 48.0% image local, 34.8% hello local/1, 8.9% hello local/4 and 8.0% hello remote/1. The chosen historical baseline has no recorded prior approval; formal comparable-baseline gate remains unproven.

### Release Operations

- **ATC-PKG-2 (not_evidenced):** Pinned Ubuntu 22.04 and 24.04 rootless userspaces on one Linux host produced matching archive SHA-256 `60ff5c285e314f15191c2b3963b459a9fb3bfa31ff699b7775ffc74c6ab70ec1`; independent physical hosts and macOS-14 results remain unverified.
- **ATC-REL-1 (not_evidenced):** Real dual-verification fixtures passed; an actual 1.0 RC artifact with production signatures is absent.
- **ATC-REL-2 (not_evidenced):** No documented actual two-of-three production key ceremony exists.
- **ATC-BUS-1 (fail):** Governance checker returns failure: each of five roles has only one named holder; required active-holder gate cannot pass.
- **ATC-BUS-2 (fail):** Required governance rotation record is absent; release checker fails.
- **OPS-RELEASE (not_evidenced):** Only an unsigned Linux local candidate archive exists; all four production artifacts with provenance, signatures and independent rebuilds are absent.
- **OPS-GOVERNANCE (fail):** Actual governance check fails on one holder per role and missing rotation record; key ceremony file is absent.
- **OPS-RECOVERY (not_evidenced):** Linux encrypted backup and restoration to a fresh profile demonstrated preserved peer identity, signed plugin state and live continuity; recovery on supported macOS hosts remains unverified.
- **OPS-CI (not_evidenced):** Hosted CI and branch protection evidence absent; user prohibited GitHub Actions.

### Reliability

- **REL-RESTART (not_evidenced):** Linux release worker kill, bounded stream failure, restart, preserved identity and 102 ms verified recovery passed; supported macOS host remains untested.
- **REL-PARTITION (not_evidenced):** Real distinct-host link disconnection, transport restart and reconnection have not been demonstrated.

The four observed failures are the wrapper doctor stale-marker bypass and three governance checks (one named holder per role and absent rotation record). `not_evidenced` means the complete fixed requirement has not been demonstrated; it is not an assertion that the feature fails.

Reproduce scoring with `python3 scripts/production_score.py --run docs/testing/production-review/runs/candidate-2602ce17-final.json`. This decision is specific to the source identifier above.
