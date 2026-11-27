# Frozen-candidate compute performance

Tested `864ae27bf3fd08e9d9c62abd4f43ff7bfd4c68c2` against `233177f933c5b4e89aea6063cb06d449528ad065` on the same VM between 2026-11-27 02:54:21 UTC and 2026-11-27 02:55:04 UTC. The candidate daemon SHA-256 was `5e11e7af5eae74c8cbec3f140e7322b98b9f5910cdb8cd269b53f9ae6d2b73f9`. Both image setups used the same release CLI, source image and signed catalog component. [Raw samples, binary digests and CPU activity](performance.json)

The prespecified engineering limits require candidate p95 no more than 5% above baseline and throughput at least 95% of baseline on each route. Each greeting row covers 3,072 validated calls per build. Each image row covers 72 independently decoded, byte-verified results per build. The table reports the median of three trial values. Greeting throughput is tasks/s and image throughput is images/s.

| Workload and clients | Baseline p50 / p95 (ms) | Candidate p50 / p95 (ms) | Baseline / candidate rate | p95 change | Rate change | Limits |
| --- | ---: | ---: | ---: | ---: | ---: | --- |
| image local | 71.704 / 136.585 | 80.565 / 153.779 | 43.58 / 38.29 | +12.6% | -12.1% | Miss |
| image one_remote | 110.241 / 144.108 | 108.719 / 145.892 | 33.99 / 32.98 | +1.2% | -3.0% | Pass |
| image three_remote | 108.860 / 151.480 | 105.236 / 142.396 | 35.06 / 36.25 | -6.0% | +3.4% | Pass |
| local / 1 | 0.208 / 0.436 | 0.224 / 0.417 | 3992.50 / 3632.40 | -4.4% | -9.0% | Miss |
| local / 4 | 0.539 / 0.895 | 0.521 / 0.833 | 6776.40 / 7212.20 | -6.9% | +6.4% | Pass |
| remote / 1 | 1.912 / 2.694 | 1.941 / 2.850 | 491.00 / 473.60 | +5.8% | -3.5% | Miss |
| remote / 4 | 3.596 / 5.941 | 3.001 / 4.291 | 1023.50 / 1249.20 | -27.8% | +22.1% | Pass |

Across both builds, the run verified 24,576 signed greeting calls and 432 image results. The candidate's three-worker image throughput was 1.099× its single-remote rate on the shared CPU quota. Every automatically placed image batch used all three distinct executor identities.

The VM ran Debian 13, Linux 6.18.57 x86-64, with an Intel Xeon Platinum 8573C, five virtual CPUs, a four-core CPU quota and 32 GiB memory limit. The release profile used Rust 1.91.1, Wasmtime 36.0.23 and iroh 1.5.0. For greetings, one or four closed-loop clients sent unique 11-byte inputs through local Unix RPC or a second daemon over authenticated loopback QUIC. Each route warmed 16 calls before measuring 1,024. The two daemons each had two Tokio and two Rayon threads. Image batches used four clients, four Tokio and four Rayon threads per daemon, and the same 24 encoded JPEGs in each of three rotated route trials. Source bytes, independent oracle results and per-image latencies are in the raw evidence.

On the prior 26 November baseline, the three greeting p95 values spanned 0.352–0.500 ms locally with one client, 0.763–1.083 ms locally with four, 3.012–3.590 ms remotely with one, and 5.318–7.218 ms remotely with four. The same-window comparison above controls for changing host conditions more closely. The three individual values for both tested builds are in the raw evidence.

The prior isolated serializer experiment on this host measured a 4.78× improvement in 256 KiB wire operations. Across six paired same-source one-remote image runs its p95 increased 1.98%, with individual pair ratios spanning 0.899–1.344. The unrestricted whole-application image route varied between 1.036× and 1.185× three-over-one in earlier trials. On distinct one-core allocations, three workers achieved 2.007× the throughput of one. These comparisons describe scheduling and host variance. The 70B workload, 8,000 RAW image workload and formal approval of the baseline remain separate production gates. [Earlier measurements](../../../../performance.md)

### Reproduce

Build both source revisions using the standard locked release profile and put their daemons in separate directories with the same final CLI. For each of three rounds, set `ENTANGLE_BENCH_DAEMON` to the absolute path of one daemon and run the existing `benchmark::measure_dispatch` test using the same driver file. Run baseline first on rounds one and three, candidate first on round two. For each image run use `scripts/benchmark_image_batch.py` with the parameters in the performance guide. The image candidate ran first. Keep compiler, packaging and other intensive jobs out of the timing window. [Commands and image source](../../../../performance.md#reproduce-the-signed-image-workload)

The independent `/proc` sampler counted live processes and CPU deltas at approximately one-second intervals. It cannot exclude shorter unobserved interference.

Monitor coverage was 02:54:21–02:55:04 UTC across 43 samples; 0 included a recognized build process. In three intervals the test driver itself appeared as `entangle-succes`, the 15-character process name assigned to the archived successor-linked driver. No unrelated process exceeded 0.25 cores in those samples.

## Production Rust client confirmation

The release-candidate daemon and its checked-out Rust client rendered 288 verified PNGs across the stock and successor client runs. The six batches used the same signed component, input set and four-client concurrency. Median client CPU fell from 10.83 to 5.21 ms per image (-51.9%), meeting the predeclared 20% reduction. Median image throughput changed by +18.3% and p95 by -15.2%. [Exact client and daemon hashes, per-pair results and CPU samples](production-client-confirmation.json)

The preceding frozen candidate missed local greeting and image performance limits. A separate six-pair isolation found mixed local image tails, and the measured client change addresses avoidable client-side serialization and cloning. This run retains the original per-route qualification limits. [Previous frozen evidence](../candidate-2602ce17/performance.md) · [Diagnostic](../candidate-2602ce17/local-regression-diagnostic.md) · [Isolated client measurements](../candidate-2602ce17/rpc-client-isolation.md)
