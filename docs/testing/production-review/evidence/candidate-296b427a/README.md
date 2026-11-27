# Distributed Rust execution and release qualification

**Hold the production release.** The frozen candidate is `296b427a3bb2d60615ea3c56b9779f97039c6e24`, with source digest `sha256:b65a7bd226264bd85b84fca929676a8cb5be88dd6ee188e3b2e30d9f2cb9ab4b`. Six change-specific acceptance criteria passed independent review. The project has 57 mandatory checks, including physical deployment and release governance. Unverified criteria earn zero credit. [Change acceptance](qa-iteration-acceptance.json) · [Fixed project rubric](../../rubric-v1.json)

| Project metric | Verified checks | Conservative score |
|---|---:|---:|
| Correctness | 9/10 | 90.00% |
| Authorization and isolation | 14/19 | 73.68% |
| Reliability | 4/6 | 66.67% |
| Interoperability | 0/5 | 0.00% |
| Performance | 0/4 | 0.00% |
| Release and operations | 4/13 | 30.77% |

The conservative review records 31 passes, three governance failures and 23 unverified checks. It interprets the Rust performance requirement as needing full native parity and a naturally flaky retry within the same upstream workspace. The literal review accepts the two demonstrations across separate workspaces and awards one additional performance check, raising that metric to 25%. Both assessments hold the release. [Conservative scorecard](conservative-scorecard.md) · [Literal scorecard](scorecard.md)

To reproduce the scores, check out the evidence commit for this source and run `python3 docs/testing/production-review/evidence/candidate-296b427a/verify-review.py` from the repository root. The check hashes the source tree and all 54 cited evidence references in each assessment. [Verification script](verify-review.py)

## Distributed Rust work

Two peers can load different, validly signed builds with the same publisher, plugin name and version. The new runner pins the verified BLAKE3 digests of the executable and manifest. The selected worker checks both before instantiating a WASI libtest command. An ordinary diagnostic beginning with `test result:` can now precede a successful completion or a genuine failed assertion. Ambiguous completion records fail closed. Rust's native test selector supplied the oracle for repeated filters, exact matching, skips and ignore flags. [Runbook](../../../distributed-rust-tests.md) · [Signed build and reload checks](rust-sharder-integration/identity-results.md) · [Native selection and output checks](rust-libtest-native-oracle/README.md)

Each available worker can pick up a new named test as soon as it finishes its previous invocation. In an eight-run comparison on two local workers, all 64 tests passed. Median wall time on a signed mixed-duration workload fell from 1,383 ms to 698 ms. All four baseline runs showed the two concurrent invocations on one peer while the other had no case running. All four integrated runs kept one invocation per active peer. [Workload, per-peer timings and trial order](rust-sharder-integration/schedule-results.md)

On an unmodified nine-crate upstream workspace, native Cargo and two authenticated WASI peers matched on 224 named outcomes, including doctests and ignores. The new standalone JUnit converter also exported 198 ordinary tests from 17 signed upstream suites. Two independent XML readers checked 37 reports containing 323 case records, verifying each final outcome and the complete worker attempts. The largest fixture emitted 2,985,486 bytes of JSON containing markup, Unicode and control characters. [Upstream Cargo comparison](distributed-rust-workspace/README.md) · [JUnit XML from 17 upstream suites](junit/upstream-tests.xml) · [JUnit verification](junit/current-read.json) · [Reproduction](junit/README.md)

In a fixed 128-block campaign, the unmodified `jaq` project produced an actual time-rounding assertion failure and then a pass on a different authenticated worker. All 128 blocks completed with matching signed package identities. The full native run passed 113 cases. The full WASI run passed 105, encountered eight tests requiring filesystem inputs and could not load the CLI's native allocator. These results leave the single-workspace performance contract open. [Cohort, retained attempts and full native/WASI results](jaq-natural/README.md)

## Ordinary workload performance

Three of seven engineering comparisons met both preregistered limits against the earlier `c19ef758` Linux daemon. Two local greeting routes, four-client remote greetings and local image processing missed at least one limit. Separate camera work processed a genuine Nikon NEF and Canon CR2 with identical output hashes across configurations. Median wall times were 10.031 seconds with one worker and 8.644 seconds with three on the same host, a 1.16× speedup. [Seven-route measurements](performance.md) · [Raw photo timings and hashes](raw-batch/real-photo-wall-times.json)

A separate balanced follow-up ran 65,536 greetings and checked 3,456 image outputs. The median local-image and four-client remote-greeting p95 misses appeared in both build orders. Runs comparing two labels for the exact same candidate daemon also showed substantial variation. The cause of the misses remains unresolved. [Trial interpretation](performance-diagnostic/interpretation.md) · [Pairwise measurements and same-binary controls](performance-diagnostic/paired-summary.json)

## Platform, network and release checks

Three locked workspace runs each passed 787 tests, failed zero and reported 29 ignored. Both isolated AgentSession tests also passed in a separate serial run. All 53 Python tests passed, as did formatting, Clippy, documentation and the configured dependency checks on 16 Cargo graphs. [Rust tests](workspace-tests/index.json) · [Python tests](tooling-regressions.log) · [Dependency checks](dependencies.json)

The canonical unsigned x86-64 Linux archive has SHA-256 `871f154179c2387c76a09101e6316d5e242b6f6b144fa4bc98932bb164f31132`. Local and remote catalog workloads ran through the release CLI and daemon. The new x86-64 coordinator also dispatched a signed JSON Pointer job to the older `c19ef758` AArch64 worker under QEMU, verified the exact returned bytes, and recorded zero coordinator invocations. The physical machine was x86-64 Linux. [Archive and ELF hashes](linux-archive.json) · [Catalog workloads](native-linux-release.json) · [Mixed-version and mixed-ISA result](mixed-release-arm64/normalized.json)

The release passed 24 live authorization checks, a 32-stream capacity and recovery check, encrypted restore with retained worker identity, and wrapper checks in Bash, Zsh and Fish. A private Headscale control server and two real Tailscale clients exercised WireGuard, ACL enforcement and service recovery in isolated namespaces. Signed work resumed 27.939 seconds after the worker overlay returned and 1.860 seconds after the coordinator overlay returned. The original Entanglement processes stayed up throughout those transport restarts. [Live authorization](auth-live-linux.json) · [Encrypted restore](recovery-linux.json) · [Private tailnet recovery](private-recovery-linux.json) · [Defensive review](qa-security-review.md)

Two of six additional worker restarts reproduced the slow path. When the coordinator sampled the worker offline, its cached route stayed empty for about 28 seconds after UDP returned. Tailscale reported the worker online within 0.6 seconds and the worker socket was bound within 2.4 seconds. In the other four trials the route stayed cached and signed work recovered in 1.112–10.168 seconds. A separate final revocation check observed zero worker invocations, but failed to observe its expected authenticated refusal. [Timing and failed control](tailnet-route-phase/README.md)

The governance checker identified five critical roles with a single holder and no rotation record. The named public mirror remained unreachable from this environment with a proxy CONNECT 403 before reaching its origin. Physical Linux and macOS hosts, distinct-host LAN/WAN/tailnet evidence, the 70B GPU and battery workload, the 8,000-RAW three-desktop workload, an approved performance baseline, and production signing and custody remain external release gates. The owner directed all verification to run locally and prohibited GitHub Actions. [Governance output](governance-real.log) · [Mirror observation](public-mirror-approved-recheck.log) · [Full evidence plan](../../final-evidence-plan.md)
