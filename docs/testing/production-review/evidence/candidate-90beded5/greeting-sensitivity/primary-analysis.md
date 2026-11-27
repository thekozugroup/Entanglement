# Primary chronology, execution path and binary layout

The 90beded5 series ran from 2026-11-27 11:01:36 UTC until 2026-11-27 11:02:18 UTC. It retained 24,576 checked greeting responses and 432 checked image outputs. Only three-remote images met both limits. The table preserves launch order. Each greeting cell gives p95 milliseconds and requests per second, separated by a slash. Each fresh cluster executed local/1, local/4, remote/1 and remote/4 in that sequence. The original driver reports durations and order per row but omits per-row absolute UTC. [Full observations](../performance.json) · [Raw logs](../engineering/raw/)

| Arm launch UTC | Pair / daemon | Local 1 | Local 4 | Remote 1 | Remote 4 | Driver seconds |
|---|---|---:|---:|---:|---:|---:|
| 11:01:36 | 1 / baseline | 0.458 / 3332 | 1.021 / 6638 | 2.809 / 496 | 3.956 / 1419 | 3.55 |
| 11:01:40 | 1 / candidate | 0.461 / 3211 | 0.943 / 6847 | 2.491 / 500 | 5.766 / 1167 | 3.59 |
| 11:01:44 | 2 / candidate | 0.433 / 3672 | 0.868 / 7482 | 2.701 / 508 | 4.790 / 1241 | 3.44 |
| 11:01:47 | 2 / baseline | 0.305 / 5185 | 0.725 / 7902 | 2.376 / 523 | 3.998 / 1372 | 3.22 |
| 11:01:50 | 3 / baseline | 0.320 / 4432 | 0.736 / 8315 | 2.496 / 522 | 4.431 / 1351 | 3.27 |
| 11:01:54 | 3 / candidate | 0.355 / 4284 | 0.759 / 7906 | 3.879 / 484 | 11.480 / 734 | 4.11 |

For local/1, p95 was higher in all three candidate arms, by 0.003, 0.128 and 0.035 ms. The second pair had the largest p95 and rate differences. At local/4, the first candidate arm was faster on both measures and the other two had higher tails. At remote/1, the first candidate arm had a lower p95; subsequent ratios were 1.137 and 1.554. Remote/4 degraded in every pair, with p95 ratios 1.458, 1.198 and 2.591. The third candidate p95 reached 11.480 ms, with 734.0 requests/s versus its paired comparator. See the exact rates above. Four closed-loop clients can accumulate delay from worker contention and host scheduling. The static loopback test does not instrument the server queue, network wait or handshake cost; the per-request timings cannot assign the delay among them.

Image suite launches were 11:01:58 UTC for the candidate and 11:02:08 UTC for the comparator. Each suite used one cluster for all nine trials. The fourth through sixth candidate trials were slow across three different topologies. Each cell gives batch wall seconds, p95 milliseconds and total observed worker CPU cores. Each run processed the same 24 inputs with four concurrent clients. Each trial has an exact wall duration but the image driver does not emit a separate absolute timestamp for each trial. [Raw image records](../engineering/raw/)

| Trial | Topology | Candidate seconds / p95 / workers’ CPU | Comparator seconds / p95 / workers’ CPU |
|---:|---|---:|---:|
| 1 | local | 0.496 / 112.7 / 3.59 | 0.547 / 152.0 / 3.25 |
| 2 | one_remote | 0.565 / 124.2 / 3.08 | 0.563 / 120.4 / 3.14 |
| 3 | three_remote | 0.650 / 133.7 / 2.96 | 0.643 / 139.4 / 3.05 |
| 4 | one_remote | 0.830 / 199.9 / 2.88 | 0.564 / 121.9 / 3.01 |
| 5 | three_remote | 0.840 / 196.3 / 3.12 | 0.614 / 126.3 / 2.98 |
| 6 | local | 0.627 / 154.7 / 3.45 | 0.485 / 107.2 / 3.65 |
| 7 | three_remote | 0.661 / 134.8 / 3.01 | 0.644 / 136.7 / 3.03 |
| 8 | local | 0.566 / 135.8 / 3.44 | 0.558 / 128.1 / 3.46 |
| 9 | one_remote | 0.663 / 141.4 / 2.92 | 0.640 / 114.7 / 3.42 |

All three topologies had their largest candidate/comparator p95 ratio on the second repetition, ranging from 1.443 to 1.639; this affected the ultimately passing three-remote route as well. Local image p95 ranged from improvement to regression across ordinals. One-remote image p95 was higher on all three repetitions, most on the second. Both suites processed the same input and produced the same decoded per-image output and ordered PNG digest. The suite ordering confounds build with time for images. The worker CPU metric covers worker processes; it cannot separate guest execution, scheduler wait, transport, kernel steal or other contention.

The live monitor found only the driver, benchmark daemons and Python processes above its CPU reporting threshold. One python3 process was observed throughout the series, consistent with the monitoring comparison runner; the original observations captured its name and PID but not its argv. Two separate Python image drivers occurred in their respective image suite intervals. No known build process appeared across 38 monitor samples. Cgroup throttling increased by 0.272318 s in 18 of 420 observed quota periods. The host load-average snapshot rose during the series, 1.63 to 2.57 over one minute. Sampling and aggregate counters cannot identify one specific route’s queue delay.

## What changed in the hot path

Both releases built the same locked workspace packages with the release profile. Cargo.toml, Cargo.lock, the dispatcher, scoring, worker/server and runtime client, server and guest sources match. Rustc 1.91.1, GCC 14.2 and LLD 21.1.2 are recorded in both ELF comment sections. The committed release manifest selects optimization 3, thin LTO, one codegen unit and symbol stripping. The build receipts record the top-level Cargo invocation, not a complete per-crate rustc argv. The two daemons have distinct ELF digests. [Original build](../../candidate-a5728c23/release-build.json) · [Current build](../release-build.json)

Only the daemon’s Tailscale address classifier moved into the already-linked adapter crate. The warm greeting fixture configures the iroh transport with a static 127.0.0.1 worker address and no tailnet mappings. The image fixture also explicitly configures only static loopback Iroh addresses. The operator CLI command is never invoked by these benchmark jobs, and the classifier is used only to read actual Tailscale status. The changed source adds no polling, lock acquisition, status subprocess or trust-file access to the measured path. [Verified unchanged dispatch and route functions](../tailnet-link-latency/callpath.json)

The ELF .text section starts at the same address in both artifacts and grows by 64 bytes. Both unwind tables index 43,081 code starts. Comparing ranges by ordinal, 43,078 retain the same length; 35,290 starts shift by +32 bytes, 198 by +64, two by +80 and 7,591 stay fixed. Different relative displacements affect byte equality; both release executables omit a static symbol table, so these ordinal spans cannot identify named hot functions. The size and layout changes leave instruction-cache effects plausible but unmeasured. The primary series shows six misses, with the clearest pair consistency at remote/4. It establishes neither the cause nor a product correction. The separately registered replication retains this series in full. [ELF measurements](elf-layout.json) · [Supplemental plan](plan.md)

Disassembly narrows the three length changes. The +80-byte interval at baseline PC 0xe035e0 directly references the exact diagnostic for selecting a local Tailscale bind address in both releases. The second interval shrinks by 48 bytes and has no independently resolved symbol. The third interval grows by 32 bytes, entirely accounted for by additional trailing int3 alignment padding (29 versus 61 bytes); its instruction-mnemonic sequence before the padding matches. The remaining 43,078 identical lengths do not imply identical machine semantics, and the data cannot attribute a measured latency difference to code placement. [Changed address ranges](changed-unwind-spans.json)
