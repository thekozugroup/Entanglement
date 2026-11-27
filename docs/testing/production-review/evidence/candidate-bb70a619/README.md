# Entanglement release candidate review

The independently graded candidate falls short of the project's production thresholds. The review covers source commit `bb70a6193f8879b1feb3e6d3ceb8f2980413ce58` and source identifier `sha256:9cae32b67ebd4784779d1c37cd9cea5efc1a640fdfd71fca9a67dda8d9c777ab`. The evidence ledger applies the 57 checks frozen before implementation. Missing evidence earns zero. Each of the six metrics must exceed 95% and every hard gate must pass. [Frozen rubric](../../rubric-v1.json) · [Conservative scorecard and individual blockers](conservative-scorecard.md) · [Literal rubric interpretation](scorecard.md)

## Workloads and compatibility

| Workload | Result on the frozen Linux candidate |
|---|---|
| Signed plugin catalog | The coordinator advertised zero loaded plugins and successfully dispatched each of the eight catalog plugins to its authenticated peer. Local invocation, HTTPS OCI distribution and publisher admission checks also passed. [Catalog](native-linux-x86-64.log) · [OCI](oci-distribution-https.log) · [Publisher](live-publisher.log) |
| RAW photographs | The Canon EOS 350D CR2 and Nikon D40 NEF produced 14,159,382 output pixels. All 42,478,146 channel values matched an independent SciPy whole-frame implementation. Two authenticated workers processed nine tiles each. Three synthetic hazy scenes recovered about 71% of their original error, and the clean control's mean change was 0.0029 on a normalized 0–1 scale. [Photographic measurements](raw-photographic-quality.json) · [Fixtures and quality thresholds](../../../../testing/raw-image-fixtures.md) |
| Worker selection | With the same two peer identities and daemons, the scheduler favored the faster peer both before and after the uploader bandwidth limits were swapped. Measured upload rates were 78.05 and 3.30 Mbit/s in the first configuration, then 35.96 and 76.41 Mbit/s. The paths ran within one host. [Measured goodput and assignment records](bandwidth-live-linux.json) |
| Tailnet | An authenticated workload succeeded after private Headscale/Tailscale cold boot and after independent coordinator and worker transport restarts. Revoking the submitter refused its next invocation. [Private WireGuard recovery](private-recovery-linux.json) |
| Rust workspace | Nine unmodified upstream crates produced 224 matching native and distributed test outcomes. A separate control recovered on its second worker and preserved flaky, failed and ignored outcomes. The predeclared conservative score requires an actual upstream flake. [Workspace and retry evidence](distributed-rust-workspace/README.md) |
| OpenAI-compatible inference | Six completion and chat streams from a 1.1B-parameter CPU model matched direct API results. Independent verification recovered the signed workers' fingerprints, checked all 139 signatures and accounted for 140 completion tokens. [Independent verification](real-inference/independent-verification.json) |
| Rolling upgrade | The previous and current CLI each dispatched through the other version's daemon and received a byte-identical PNG. The current CLI also dehazed a generated DNG across two previous-version daemons, preserving full-frame pixels. [Mixed-version receipt](mixed-version-linux/rerun-with-libraw/receipt.json) |
| Linux packaging | Ubuntu 22.04 and 24.04 userspaces built identical signed fixture packages. The candidate release executables launched on Ubuntu 24.04 and Debian 13, and reported a missing GLIBC_2.39 on Ubuntu 22.04 and Debian 12. [Rebuilds](pkg-linux-matrix/linux-matrix.json) · [Release executable checks](archive-launch.json) |

## Qualification history

Two frozen builds were disqualified by independent full-suite runs. The first exposed an asynchronous UDP port release in a restart test. The next exposed a parallel test racing an executable that had just been written. The successor waits for socket availability and uses an immutable executable for the Tailscale command test. [First verdict](../candidate-83629d47/iteration-verdict.md) · [Second verdict](../candidate-1a772db2/iteration-verdict.md)

Three consecutive locked full-workspace runs on the successor each reported **774 passed, zero failed, and 29 ignored**. Focused testing separately passed 13 image conformance cases and 11 real shell-wrapper cases. Strict Clippy, rustdoc, formatting and all 15 configured dependency graphs passed. The defensive review and the signed publisher-incident rehearsal covered the new paths. [Full run 1](workspace-test.json) · [Run 2](workspace-test-2.json) · [Run 3](workspace-test-3.json) · [Image cases](image-unit-conformance.json) · [Shells](wrapper-full-shells.json) · [Dependency graphs](dependencies.json) · [Security review](dehaze-security-review.md) · [Incident rehearsal](publisher-incident-exercise.md)

The downloadable x86-64 GNU/Linux archive has SHA-256 `e2538c818ff960801f882001023ba0f3601a821944660cf382dfe6ea0d7c5aa2` and carries no production release signature. [Archive receipt and individual binary hashes](linux-archive.json)

## Supplemental Linux archive

A clean Ubuntu 22.04 build of the same source and release profile produces an additional x86-64 Linux archive with SHA-256 `fdfb5caa3551620f19d2f991ae9ae36287b86cc5a553582f8423c56e1c6c2885`. Before the network-disconnected build, all 616 cached registry archives matched the dependency lock. Both executables require glibc symbols through version 2.34. This archive ran the daemon and a signed Wasm workload in Ubuntu 22.04 and 24.04 and Debian 12 and 13. Each environment rejected the untrusted publisher before admission and returned the expected greeting after explicit trust. A second reviewer independently verified all six archive members, compared installed binaries byte-for-byte, and exercised publisher trust on Ubuntu 22.04 and Debian 12 using the real POSIX installer. These four userspaces ran on one x86-64 host. The archive is unsigned. [Independent advisory, installer results and setup retries](glibc-compat/independent-advisory.md) · [Build provenance](glibc-compat/build.json) · [Archive and binary digests](glibc-compat/linux-archive.json) · [Ubuntu 22.04 and Debian 12 tests](glibc-compat/workload.json) · [Ubuntu 24.04 and Debian 13 tests](glibc-compat/workload-newer-userspaces.json)

The same compatibility archive also dispatched signed work in both directions between Ubuntu 22.04 and Debian 12 over direct authenticated Iroh QUIC. Each submitting daemon had an empty plugin inventory. Each selected the intended remote worker and verified the distinct nonce result. The private Docker network had no default route or published ports. [Peer identities, route settings, outputs and cleanup](glibc-compat/cross-userspace.json)

## Performance on one Linux host

The two genuine photographs took a median **10.064 s** on the single-worker route and **8.946 s** on the three-worker route, or **1.125×** throughput. The submitter ran three concurrent tiles, and each mesh trial used all three authenticated worker identities. The medians cover three alternating measured pairs after a complete warmup pair. All 16 rendered files across warmup and timing runs matched their per-photograph content hashes. The one-second resource sampler observed no compiler or build processes across 87 samples. Both topologies shared one four-core CPU quota. The 8,000-RAW, three-physical-desktop, 10× architecture gate remains open. [Per-photo timings, executor assignments and hashes](raw-batch/real-photo-wall-times.json) · [Host samples](raw-batch/resource-samples.json) · [Reproduction guide](../../../../performance.md#measure-a-raw-dehaze-batch)

Six alternating matched pairs compared the previous reviewed release (`42bb9a33`) with this candidate on a 6,294,518-byte signed image dispatch. Median wall time moved from 1.483 s to 1.030 s. The median paired changes were −30.6% in wall time, −83.4% in CLI peak RSS and −58.0% in daemon peak RSS. All 12 timed results were byte-identical. The first series completed validation and encountered an error saving the report. Its raw observations and the complete repeated series are both available. [Integrated comparison and isolated allocation check](uds-image-comparison/README.md)

The seven-route comparison validated 24,576 signed greeting calls and 432 image results. Against the historical engineering comparator `864ae27b`, four routes met both prescribed limits. Local image throughput fell 5.2%. With one remote worker, image p95 rose 6.3% and throughput fell 7.0%. Single-client remote greeting p95 rose 9.6%. Approval of a production baseline is still outstanding. [All seven rows, method and individual trials](performance.md)

In six additional CPU-affinity-controlled pairs, one-remote image p95 rose a median paired 6.8%, with individual ratios ranging from 0.769 to 1.306. The paired throughput drop was 3.65%. The central local-image throughput and single-client remote-greeting p95 met their diagnostic limits. Each image input was smaller than the upload-sampling threshold, and the test fixed its eligible worker. One initial pair overlapped Ubuntu package provisioning. Earlier reviewed builds also exceeded the one-remote image p95 limit against this comparator. The current investigation found no specific source defect responsible for the variation. The original seven-route result still determines the comparison outcome. [Diagnostic samples and scope](one-remote-diagnostic/README.md) · [Prior measurements and execution path](one-remote-history.md)

## Release decision

| Metric | Passing / total | Conservative score |
|---|---:|---:|
| Correctness | 9 / 10 | 90.00% |
| Authorization and isolation | 14 / 19 | 73.68% |
| Reliability | 4 / 6 | 66.67% |
| Interoperability | 0 / 5 | 0.00% |
| Performance | 0 / 4 | 0.00% |
| Release and operations | 4 / 13 | 30.77% |

The conservative review records 31 passing checks, three failures and 23 unverified checks. All three failures concern actual governance: five roles have a single named holder and the rotation record is missing. The literal interpretation credits the separate flaky-retry control, giving performance 25% and 32 total passes. Each interpretation yields the same release decision. [Scorecard](conservative-scorecard.md) · [Governance output](governance-real.log)

Further production qualification requires independent Linux and macOS hardware, real LAN/WAN/tailnet peers, the specified GPU and photo workloads, production signing and custody, and release controls. The loaded tier-5 agent-host prerequisite also remains outstanding. Native admission rejected the signed control on Linux. All runs in this review used the local cloud environment under the owner's instruction to skip GitHub Actions. [Tier boundary](tier-policy-boundary/receipt.json) · [Agent-host prerequisite](tier-policy-boundary/gate-rationale.md) · [Complete gate list](conservative-scorecard.md)
