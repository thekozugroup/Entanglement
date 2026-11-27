# Frozen-candidate compute performance

Tested `c19ef7587a2215ef9434b642413bebd0473caf20` against `bb70a6193f8879b1feb3e6d3ceb8f2980413ce58` on the same VM between 2026-11-27 07:03:24 UTC and 2026-11-27 07:04:07 UTC. The candidate daemon SHA-256 was `ae746362f564f20a6ae00d81883a4873078ad9f847684145341d57315b6fc823`. Both image setups used the same release CLI, source image and signed catalog component. [Raw samples, binary digests and CPU activity](performance.json)

The prespecified engineering limits require candidate p95 no more than 5% above baseline and throughput at least 95% of baseline on each route. Each greeting row covers 3,072 validated calls per build. Each image row covers 72 independently decoded, byte-verified results per build. The table reports the median of three trial values. Greeting throughput is tasks/s and image throughput is images/s.

| Workload and clients | Baseline p50 / p95 (ms) | Candidate p50 / p95 (ms) | Baseline / candidate rate | p95 change | Rate change | Limits |
| --- | ---: | ---: | ---: | ---: | ---: | --- |
| image local | 70.184 / 158.569 | 88.140 / 158.065 | 42.39 / 40.27 | -0.3% | -5.0% | Miss |
| image one_remote | 107.711 / 164.017 | 98.167 / 117.646 | 34.75 / 39.50 | -28.3% | +13.7% | Pass |
| image three_remote | 109.745 / 165.488 | 107.162 / 146.494 | 33.20 / 34.65 | -11.5% | +4.4% | Pass |
| local / 1 | 0.216 / 0.395 | 0.206 / 0.488 | 3944.10 / 3722.10 | +23.5% | -5.6% | Miss |
| local / 4 | 0.467 / 0.829 | 0.520 / 0.933 | 7768.90 / 6920.90 | +12.5% | -10.9% | Miss |
| remote / 1 | 1.851 / 3.661 | 1.844 / 3.501 | 454.50 / 467.40 | -4.4% | +2.8% | Pass |
| remote / 4 | 2.772 / 4.837 | 2.959 / 5.437 | 1263.10 / 1216.80 | +12.4% | -3.7% | Miss |

Across both builds, the run verified 24,576 signed greeting calls and 432 image results. The candidate's three-worker image throughput was 0.877× its single-remote rate on the shared CPU quota. Every automatically placed image batch used all three distinct executor identities.

The VM ran Debian 13, Linux 6.18.57 x86-64, with an Intel Xeon Platinum 8573C, five virtual CPUs, a four-core CPU quota and 32 GiB memory limit. The release profile used Rust 1.91.1, Wasmtime 36.0.23 and iroh 1.5.0. For greetings, one or four closed-loop clients sent unique 11-byte inputs through local Unix RPC or a second daemon over authenticated loopback QUIC. Each route warmed 16 calls before measuring 1,024. The two daemons each had two Tokio and two Rayon threads. Image batches used four clients, four Tokio and four Rayon threads per daemon, and the same 24 encoded JPEGs in each of three rotated route trials. Source bytes, independent oracle results and per-image latencies are in the raw evidence.

On the prior 26 November baseline, the three greeting p95 values spanned 0.352–0.500 ms locally with one client, 0.763–1.083 ms locally with four, 3.012–3.590 ms remotely with one, and 5.318–7.218 ms remotely with four. The same-window comparison above controls for changing host conditions more closely. The three individual values for both tested builds are in the raw evidence.

The prior isolated serializer experiment on this host measured a 4.78× improvement in 256 KiB wire operations. Across six paired same-source one-remote image runs its p95 increased 1.98%, with individual pair ratios spanning 0.899–1.344. The unrestricted whole-application image route varied between 1.036× and 1.185× three-over-one in earlier trials. On distinct one-core allocations, three workers achieved 2.007× the throughput of one. These comparisons describe scheduling and host variance. The 70B workload, 8,000 RAW image workload and formal approval of the baseline remain separate production gates. [Earlier measurements](../../../../performance.md)

### Reproduce

Build both source revisions using the standard locked release profile and put their daemons in separate directories with the same final CLI. For each of three rounds, set `ENTANGLE_BENCH_DAEMON` to the absolute path of one daemon and run the existing `benchmark::measure_dispatch` test using the same driver file. Run baseline first on rounds one and three, candidate first on round two. For each image run use `scripts/benchmark_image_batch.py` with the parameters in the performance guide. The image candidate ran first. Keep compiler, packaging and other intensive jobs out of the timing window. [Commands and image source](../../../../performance.md#reproduce-the-signed-image-workload)

The independent `/proc` sampler counted live processes and CPU deltas at approximately one-second intervals. It cannot exclude shorter unobserved interference.

Monitor coverage was 07:03:24–07:04:07 UTC across 41 samples; 0 included a recognized build process. Other observed processes over 0.25 CPU cores appeared in 0 intervals.
