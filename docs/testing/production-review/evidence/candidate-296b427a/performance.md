# Frozen-candidate compute performance

Tested `296b427a3bb2d60615ea3c56b9779f97039c6e24` against `c19ef7587a2215ef9434b642413bebd0473caf20` on the same VM between 2026-11-27 08:39:05 UTC and 2026-11-27 08:39:46 UTC. The candidate daemon SHA-256 was `a581695b1ac2b939391501d3daef987ad188bddcd85a473ab661a7a1a31e936e`. Both image setups used the same release CLI, source image and signed catalog component. [Raw samples, binary digests and CPU activity](performance.json)

The prespecified engineering limits require candidate p95 no more than 5% above baseline and throughput at least 95% of baseline on each route. Each greeting row covers 3,072 validated calls per build. Each image row covers 72 independently decoded, byte-verified results per build. The table reports the median of three trial values. Greeting throughput is tasks/s and image throughput is images/s.

| Workload and clients | Baseline p50 / p95 (ms) | Candidate p50 / p95 (ms) | Baseline / candidate rate | p95 change | Rate change | Limits |
| --- | ---: | ---: | ---: | ---: | ---: | --- |
| image local | 78.287 / 121.195 | 86.752 / 134.553 | 42.60 / 41.53 | +11.0% | -2.5% | Miss |
| image one_remote | 108.824 / 186.288 | 96.590 / 162.547 | 32.12 / 38.54 | -12.7% | +20.0% | Pass |
| image three_remote | 97.912 / 135.966 | 101.443 / 127.493 | 37.04 / 37.21 | -6.2% | +0.5% | Pass |
| local / 1 | 0.204 / 0.344 | 0.211 / 0.365 | 4310.70 / 3947.10 | +6.1% | -8.4% | Miss |
| local / 4 | 0.522 / 0.928 | 0.519 / 1.013 | 7072.50 / 6551.40 | +9.2% | -7.4% | Miss |
| remote / 1 | 1.870 / 2.810 | 1.784 / 2.358 | 475.20 / 516.30 | -16.1% | +8.6% | Pass |
| remote / 4 | 2.719 / 4.041 | 2.866 / 4.562 | 1351.10 / 1272.00 | +12.9% | -5.9% | Miss |

Across both builds, the run verified 24,576 signed greeting calls and 432 image results. The candidate's three-worker image throughput was 0.966× its single-remote rate on the shared CPU quota. Every automatically placed image batch used all three distinct executor identities.

The VM ran Debian 13, Linux 6.18.57 x86-64, with an Intel Xeon Platinum 8573C, five virtual CPUs, a four-core CPU quota and 32 GiB memory limit. The release profile used Rust 1.91.1, Wasmtime 36.0.23 and iroh 1.5.0. For greetings, one or four closed-loop clients sent unique 11-byte inputs through local Unix RPC or a second daemon over authenticated loopback QUIC. Each route warmed 16 calls before measuring 1,024. The two daemons each had two Tokio and two Rayon threads. Image batches used four clients, four Tokio and four Rayon threads per daemon, and the same 24 encoded JPEGs in each of three rotated route trials. Source bytes, independent oracle results and per-image latencies are in the raw evidence.

On the prior 26 November baseline, the three greeting p95 values spanned 0.352–0.500 ms locally with one client, 0.763–1.083 ms locally with four, 3.012–3.590 ms remotely with one, and 5.318–7.218 ms remotely with four. The same-window comparison above controls for changing host conditions more closely. The three individual values for both tested builds are in the raw evidence.

The prior isolated serializer experiment on this host measured a 4.78× improvement in 256 KiB wire operations. Across six paired same-source one-remote image runs its p95 increased 1.98%, with individual pair ratios spanning 0.899–1.344. The unrestricted whole-application image route varied between 1.036× and 1.185× three-over-one in earlier trials. On distinct one-core allocations, three workers achieved 2.007× the throughput of one. These comparisons describe scheduling and host variance. The 70B workload, 8,000 RAW image workload and formal approval of the baseline remain separate production gates. [Earlier measurements](../../../../performance.md)

### Reproduce

Build both source revisions using the standard locked release profile and put their daemons in separate directories with the same final CLI. For each of three rounds, set `ENTANGLE_BENCH_DAEMON` to the absolute path of one daemon and run the existing `benchmark::measure_dispatch` test using the same driver file. Run baseline first on rounds one and three, candidate first on round two. For each image run use `scripts/benchmark_image_batch.py` with the parameters in the performance guide. The image candidate ran first. Keep compiler, packaging and other intensive jobs out of the timing window. [Commands and image source](../../../../performance.md#reproduce-the-signed-image-workload)

The independent `/proc` sampler counted live processes and CPU deltas at approximately one-second intervals. It cannot exclude shorter unobserved interference.

Monitor coverage was 08:39:05–08:39:45 UTC across 38 samples; 0 included a recognized build process. Other observed processes over 0.25 CPU cores appeared in 0 intervals.
