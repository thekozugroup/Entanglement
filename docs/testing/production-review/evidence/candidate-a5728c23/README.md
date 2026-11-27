# Trusted Tailscale route recovery and Linux release qualification

**Hold the production release.** The evaluated source is `a5728c230e5049556b806cae8597fe823dd67987` with SHA-256 source identifier `a43296d252b79d7a0762861de1251b0e2e77fde20af2ea5dd43254617376fce5`. The published project rubric has 57 mandatory criteria. Three governance checks failed and several platform and custody checks need external evidence. [Frozen rubric](../../rubric-v1.json) · [Plan registered before integration](qualification-plans/integrated.md)

| Metric | Literal project rubric | Conservative assessment |
|---|---:|---:|
| Correctness | 9/10 · 90.00% | 9/10 · 90.00% |
| Authorization and isolation | 14/19 · 73.68% | 14/19 · 73.68% |
| Reliability | 4/6 · 66.67% | 4/6 · 66.67% |
| Interoperability | 0/5 · 0.00% | 0/5 · 0.00% |
| Performance | 1/4 · 25.00% | 0/4 · 0.00% |
| Release and operations | 4/13 · 30.77% | 4/13 · 30.77% |

The literal assessment records 32 passes, three failures and 22 unverified checks. The conservative assessment requires both workspace-wide test parity and a naturally occurring cross-worker retry in the same upstream workspace. That interpretation leaves 31 passes, three failures and 23 unverified. [Literal ledger](../../runs/candidate-a5728c23-final.json) · [Conservative ledger](../../runs/candidate-a5728c23-conservative.json) · [Independent adjudication](qa-rubric-adjudication.md) · [Independent review of subsequent platform and performance evidence](qa-supplement.md)

To reproduce both scores and check their execution receipts, run `python3 docs/testing/production-review/evidence/candidate-a5728c23/verify-review.py` at the qualification commit. Add `--archive PATH` for each local release tarball to check its SHA-256. From a later documentation revision, the verifier prints the qualification commit to use in a separate clone.

## Tailscale recovery

On the reference release, an authenticated worker's address could stay absent for nearly 30 seconds after its Tailscale service recovered. A one-shot submission can now wake the daemon's existing local status reader when it selects an explicitly mapped and paired worker with a missing route. Concurrent misses share one status query. The coordinator rechecks current pairing and the worker identity before dialing. Background polling continues and each submission performs at most one wire invocation. [Operator guide](../../../../operations.md#running-a-worker-on-a-tailnet) · [Reference diagnosis](../candidate-296b427a/tailnet-route-phase/README.md)

| Fixed worker restart | Reference time from restored UDP to verified work | Integrated time | Verified worker executions |
|---|---:|---:|---:|
| C1 | 28.244 s | 3.410 s | 1 |
| C2 | 28.004 s | 2.598 s | 1 |

These tests used a private Headscale control plane, two real Tailscale clients and one physical Linux host. In C2, three attempts were refused locally while the worker or the coordinator's map was still recovering. A separate run established fresh inventory through a newly signed plugin, revoked coordinator trust while disconnected, received the worker's authenticated `not-authorized` response and measured no increase in its invocation counter. Repair restored signed work. [Measured phases, port observations and trust controls](tailnet-route-phase/README.md)

The standard private recovery test rejected, allowed and rejected UDP traffic on the scheduler port as its ACL changed. After a service restart, time from restored overlay reachability to verified work was 3.170 seconds on the worker and 1.786 seconds on the coordinator. [Standard recovery measurements](private-recovery-linux.json)

Tailscale is an opt-in adapter compiled into the CLI and daemon. Connect both hosts using their installed Tailscale clients, pair their Entanglement identities, select `transports = ["tailscale"]` on both daemons and map the worker's stable Tailscale node ID to its paired Entanglement key and UDP port. The coordinator then retrieves CPU, memory and loaded plugin information over authenticated QUIC. When the pairing listener is unreachable, use `entangle pair --manual` on the initiator and `entangle pair --responder --manual` on the responder. Both the manual exchange and direct-address QUIC pairing saved the correct reciprocal identities in separate release CLI profiles. [Transport configuration](../../../../operations.md#running-a-worker-on-a-tailnet) · [Verified commands and prompts](operator-pairing/README.md)

## Signed distributed Rust workloads

A nine-crate upstream Cargo workspace matched all 224 named native/WASI outcomes. Two authenticated workers executed 131 and 91 passing cases, with two documented cases ignored. A single 17-suite JUnit report retained 198 ordinary tests and their attempt histories. In a separate unmodified jaq suite, three genuine assertion failures recovered on another worker in a preregistered 128-block campaign. Native jaq passed all 113 tests. WASI passed 105, encountered eight filesystem-dependent failures and could not load the CLI's native allocator. [Nine-crate results and JUnit](distributed-rust-workspace/README.md) · [Genuine jaq retries](jaq-natural/README.md)

The compiled plugin handle now occupies 136 bytes on optimized x86-64 Linux, down from 208 bytes. The archive's daemon ELF is bound to the exact Rust metadata used for that measurement. An immutable shared command retains each signed test suite's executable and manifest digests across clones. Fourteen fresh signed cases cover mismatched packages, replacement, drain, revocation, older peers and retry. [Handle proof and isolated 24-arm performance experiment](handle-layout/README.md) · [Signed peer results](qa-identity.json) · [Independent review](qa-security-review.md)

Six real TinyLlama 1.1B CPU requests exercised a llama.cpp server through the OpenAI-compatible `/v1/completions` and `/v1/chat/completions` interfaces. An independent verifier checked the returned model output and all 139 Ed25519-signed stream chunks against the elected worker. The specified 70B GPU and battery-laptop workload still needs its target hardware. [Independent protocol and signature verification](real-inference/independent-verification.json)

## Ordinary workload performance

Five of seven routes met the registered p95 and throughput limits against the `c19ef758` engineering baseline. All seven met the throughput limit. Single-client and four-client local greeting p95 exceeded the reference by 5.51% and 6.82%, respectively. The four-client miss appeared in all three pairs. The same-binary controls showed enough variation to leave the cause unresolved. In the separate storage-only experiment, the 95% intervals for all four primary latency and throughput ratios included equality. [Integrated per-trial values and interpretation](engineering/performance-interpretation.md) · [Full primary data](performance.json)

A separate single-daemon test used 32 fresh processes, pinned client and daemon CPUs, and a different RPC client event loop. Across eight build pairs, single-client p95 rose 14.6% (95% interval +1.0% to +24.0%) and throughput fell 18.1%. With four clients, the p95 ratio was 0.948 (0.844–1.030) and the throughput ratio was 1.028. Eight same-binary control pairs accompanied those measurements. Neither concurrency level met the preregistered criterion for a persistent p95 regression. The slower single-client result remains an open performance finding. [Diagnostic protocol](local-greeting-diagnostic/plan.md) · [Paired observations and confidence intervals](local-greeting-diagnostic/summary.json)

A signed camera-processing job produced identical outputs from a genuine Nikon NEF and Canon CR2 across all trials. Median wall time was 9.964 seconds for one worker and 9.099 seconds for three workers sharing this host, a 1.095× speedup. [Measured outputs and times](raw-batch/real-photo-wall-times.json) · [Source, command and artifact receipt](raw-batch/wall-times-receipt.json)

## Linux compatibility

The unsigned canonical x86-64 Linux archive has SHA-256 `21f9efbc6a235f25d28235f5da7171c87b52dabd482c0ec63dd01fdc3557f611`. Both executables import glibc 2.39. In pinned Ubuntu 24.04 and Debian 13 userlands they ran signed JSON Pointer requests, including escaped Unicode, JSON null and missing-member controls. Ubuntu 22.04 and Debian 12 rejected this build at startup. [Archive and ELF hashes](linux-archive.json) · [Four userlands](linux-compatibility/linux-userspaces/normalized.json)

Two clean Ubuntu 22.04 builds from the same source produced the same unsigned x86-64 archive digest, `9a4c23b648ad26f23fa925c5171218094fb6b68247bcfbdc62dc19dca83d592d`. The highest glibc symbol version imported by either executable is 2.34. This build passed the signed JSON Pointer workload and its refusal controls in Ubuntu 22.04, Ubuntu 24.04, Debian 12 and Debian 13 on one x86-64 machine. The first build's export failed after the archive was hashed inside the build container. A second offline build yielded the same digest after export. [Build and packaging commands](linux-compatibility/jammy-replay/build-jammy.sh) · [Portable archive receipt](linux-compatibility/jammy-replay/jammy-linux-archive.json) · [Cold-build comparison](linux-compatibility/jammy-native-replay-comparison.json) · [Four-userland workload results](linux-compatibility/jammy-userspaces/normalized.json)

On Debian 13, the portable executables also processed all eight catalog workloads locally and through a paired worker. The coordinator had an empty plugin inventory. This check staged prebuilt WASI components, and the regular catalog commands signed, installed and invoked them. [Eight-plugin portable release run](linux-compatibility/portable-catalog/normalized.json)

Using the project's POSIX installer as an unprivileged user, both Ubuntu versions installed the portable build. On Ubuntu 22.04 an attempted upgrade to the canonical build failed its glibc check and preserved both installed executables byte for byte. Ubuntu 24.04 completed the same upgrade. Both hosts retained their identity and signed plugin and successfully processed a fresh input afterward. [Installer and update controls](linux-compatibility/posix-installer/installer-matrix.json)

Separate Ubuntu 22.04 and 24.04 builds of the signed hello-world WASI package yielded identical 20,909-byte archives from two different native packaging executables. The required macOS comparison is pending. [Ubuntu package comparison](linux-compatibility/ubuntu-guest-package-comparison.json)

The current AArch64 Linux release archive has SHA-256 `2621efd1f76555a4902ca234b5630bd36737b9f421b8bd8b0ab69fee91f2111c`. It ran under QEMU on the same x86-64 machine. The ARM worker rejected the package before publisher approval, then completed a signed job. Native x86-64 and emulated ARM64 coordinators also dispatched to each other. In each direction the selected worker alone added one execution and returned the exact fresh nonce. [ARM build and checksums](linux-compatibility/current-arm64/arm-archive.json) · [Signed execution in both directions](linux-compatibility/current-arm64/summary.json)

The same bidirectional signed-job checks passed between the current x86-64 binary and an earlier `c19ef758` ARM64 release under QEMU. Both coordinators had empty plugin inventories in their respective cross-version runs. [Current coordinator to older worker](linux-compatibility/repeat/mixed-release-arm64/normalized.json) · [Older coordinator to current worker](linux-compatibility/reverse-mixed-isa/README.md)

## Build and release controls

Three locked, default-parallel Rust runs each passed 792 tests with 29 ignored. Two isolated agent session tests passed serially. All 55 Python tests passed. Formatting, Clippy, rustdoc, Linux mDNS discovery, HTTPS OCI distribution, the signed publisher rehearsal and the configured dependency checks across 16 graphs passed. The archived local release also passed 24 live authorization checks, a 32-stream saturation/recovery check, eight signed plugin workloads, and interactive controls in Bash, Zsh and Fish. [Rust tests](workspace-tests/index.json) · [Python tests](tooling-regressions.log) · [Supply chain](dependencies.json) · [Signed catalog](native-linux-release.json) · [Live trust and limits](auth-live-linux.json) · [Shells](wrapper-live-linux.json)

For each cited execution receipt, the readiness scorer checks its path, both source stamps, the log path and digest, exit code, procedure and ordered UTC timestamps. The new scorer preserved the historical outputs and exit statuses of all 22 existing ledgers across 817 references to 181 distinct receipts. The independent review compared output bytes and the integrated run reproduced the percentages and blocker counts. [Historical comparison](score-tool/historical-replay.json) · [Integrated replay](integrated-historical-replay.log)

A real interactive tier-lowering exercise used two signed tier-3 WebAssembly packages. Cancel restored the ceiling to five, forced lowering unloaded both packages and the disabled state survived restart. The three written maximum-tier contracts require a loaded native tier-5 agent host for the five-to-three transition. That supervised host and its platform sandbox remain an implementation gap. [Tier-policy run](signed-wasm-tier-lowering.log) · [Operator guide](../../../../operations.md#adjusting-the-tier-ceiling)

The cloud setup script built the current development binaries and WASI example and passed its package checks. An activated development shell reported 13 healthy checks and all seven representative RPC tests passed. [Environment setup and health](cloud-onboarding.json)

The governance check found five single-holder roles and a missing rotation record. Two HTTPS attempts to reach the named public mirror were rejected by the environment proxy before reaching the origin. Read-only GitHub branch metadata was also inaccessible. Verification ran outside GitHub Actions at the owner's request. Production custody, signed release archives and provenance, physical Linux and macOS hardware, independent LAN/WAN/tailnet devices, approved performance baselines, the 70B GPU/battery case, and the 8,000-photo three-desktop case remain open. [Governance](governance-real.log) · [Mirror](public-mirror-approved-recheck.log) · [Branch metadata](main-branch-metadata-approved.log) · [Release contracts](../../final-evidence-plan.md)
