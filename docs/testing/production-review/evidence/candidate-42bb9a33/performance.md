# Frozen-candidate compute performance

Tested `42bb9a3360ce2b4d5bcf2268dfa5a76bc6d6247e` against `864ae27bf3fd08e9d9c62abd4f43ff7bfd4c68c2` on the same VM between 2026-11-27 04:07:10 UTC and 2026-11-27 04:07:51 UTC. The candidate daemon SHA-256 was `ed345717b93bde2b64e1284e9dd8f308a2f09da4997993ce71f9b8dc8df911cd`. Both image setups used the same release CLI, source image and signed catalog component. [Raw samples, binary digests and CPU activity](performance.json)

The prespecified engineering limits require candidate p95 no more than 5% above baseline and throughput at least 95% of baseline on each route. Each greeting row covers 3,072 validated calls per build. Each image row covers 72 independently decoded, byte-verified results per build. The table reports the median of three trial values. Greeting throughput is tasks/s and image throughput is images/s.

| Workload and clients | Baseline p50 / p95 (ms) | Candidate p50 / p95 (ms) | Baseline / candidate rate | p95 change | Rate change | Limits |
| --- | ---: | ---: | ---: | ---: | ---: | --- |
| image local | 71.086 / 126.477 | 73.460 / 125.341 | 42.36 / 44.86 | -0.9% | +5.9% | Pass |
| image one_remote | 98.044 / 127.746 | 98.603 / 192.938 | 35.34 / 35.60 | +51.0% | +0.7% | Miss |
| image three_remote | 99.117 / 133.669 | 104.587 / 129.644 | 38.16 / 36.49 | -3.0% | -4.4% | Pass |
| local / 1 | 0.237 / 0.488 | 0.240 / 0.399 | 3234.90 / 3686.80 | -18.2% | +14.0% | Pass |
| local / 4 | 0.509 / 0.834 | 0.498 / 0.914 | 7341.40 / 7294.20 | +9.6% | -0.6% | Miss |
| remote / 1 | 1.801 / 2.839 | 1.847 / 3.058 | 492.80 / 450.00 | +7.7% | -8.7% | Miss |
| remote / 4 | 2.874 / 4.363 | 2.689 / 3.934 | 1314.40 / 1431.60 | -9.8% | +8.9% | Pass |

Across both builds, the run verified 24,576 signed greeting calls and 432 image results. The candidate's three-worker image throughput was 1.025× its single-remote rate on the shared CPU quota. Every automatically placed image batch used all three distinct executor identities.

The VM ran Debian 13, Linux 6.18.57 x86-64, with an Intel Xeon Platinum 8573C, five virtual CPUs, a four-core CPU quota and 32 GiB memory limit. The release profile used Rust 1.91.1, Wasmtime 36.0.23 and iroh 1.5.0. For greetings, one or four closed-loop clients sent unique 11-byte inputs through local Unix RPC or a second daemon over authenticated loopback QUIC. Each route warmed 16 calls before measuring 1,024. The two daemons each had two Tokio and two Rayon threads. Image batches used four clients, four Tokio and four Rayon threads per daemon, and the same 24 encoded JPEGs in each of three rotated route trials. Source bytes, independent oracle results and per-image latencies are in the raw evidence.

On the prior 26 November baseline, the three greeting p95 values spanned 0.352–0.500 ms locally with one client, 0.763–1.083 ms locally with four, 3.012–3.590 ms remotely with one, and 5.318–7.218 ms remotely with four. The same-window comparison above controls for changing host conditions more closely. The three individual values for both tested builds are in the raw evidence.

The prior isolated serializer experiment on this host measured a 4.78× improvement in 256 KiB wire operations. Across six paired same-source one-remote image runs its p95 increased 1.98%, with individual pair ratios spanning 0.899–1.344. The unrestricted whole-application image route varied between 1.036× and 1.185× three-over-one in earlier trials. On distinct one-core allocations, three workers achieved 2.007× the throughput of one. These comparisons describe scheduling and host variance. The 70B workload, 8,000 RAW image workload and formal approval of the baseline remain separate production gates. [Earlier measurements](../../../../performance.md)

### Reproduce

Build both source revisions using the standard locked release profile and put their daemons in separate directories with the same final CLI. For each of three rounds, set `ENTANGLE_BENCH_DAEMON` to the absolute path of one daemon and run the existing `benchmark::measure_dispatch` test using the same driver file. Run baseline first on rounds one and three, candidate first on round two. For each image run use `scripts/benchmark_image_batch.py` with the parameters in the performance guide. The image candidate ran first. Keep compiler, packaging and other intensive jobs out of the timing window. [Commands and image source](../../../../performance.md#reproduce-the-signed-image-workload)

The independent `/proc` sampler counted live processes and CPU deltas at approximately one-second intervals. It cannot exclude shorter unobserved interference.

Monitor coverage was 04:07:11–04:07:51 UTC across 39 samples; 0 included a recognized build process. Other observed processes over 0.25 CPU cores appeared in 0 intervals.

### Interpretation for the current source revision

Four of seven routes stayed inside both limits. Compared with the previous identical daemon pair, the local image result changed from a miss to a pass. The single-remote image p95 was 51.0% higher in the current run, while throughput rose 0.7%. Four-client local greeting p95 was 9.6% higher, and single-client remote greetings had 7.7% higher p95 and 8.7% lower throughput. All dispatches verified their outputs. The binary comparison found identical hashes for both builds used in the two rounds.

The fixed-CPU, 16-pair check of these same release daemons measured a median local four-client p95 ratio of 0.989, with a 95% paired-bootstrap interval of 0.940–1.079. The interval crosses the 5% limit. The measured misses and variation keep the formal performance gate open. [Identical-binary and trial-order controls](../candidate-761485d7/performance-controls/results.md) · [Fixed-CPU diagnostic](../candidate-761485d7/performance-controls/local-four/README.md)
