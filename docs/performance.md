# One-shot compute performance

The dispatch benchmark times a task from the client’s Unix-socket RPC call through decoding its response. It verifies the executor ID and output for every call. The local route submits directly to the daemon that has the plugin. The remote route submits to a separate daemon with an empty plugin registry, which schedules the task on the same executor over authenticated loopback QUIC. Both processes run on the same host with relays disabled.

## Linux loopback results, 26 November 2026

Three fresh daemon pairs completed **12,288 timed dispatches** on an x86-64 Linux 6.18.57 VM reporting an Intel Xeon Platinum 8573C. The VM exposed five virtual CPUs with a four-core cgroup quota and a 32 GiB memory limit. The release used Rust 1.91.1, Wasmtime 36.0.23, and iroh 1.5.0. The measured daemon’s SHA-256 was `882373f6fcc85e50b5812b5225156ab907001b8b61a73787b3a402a997e14cdb`.

Each row includes 1,024 warmed calls in each of three trials to one executor. The p50, p95, and throughput columns report the median of the three per-trial values. The ranges show the lowest and highest trial results.

| Route | Concurrent clients | p50 (ms) | p95 (ms) | p95 range (ms) | Tasks/s | Tasks/s range |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Local | 1 | 0.264 | 0.488 | 0.352–0.500 | 3,287 | 2,993–3,929 |
| Local | 4 | 0.504 | 0.898 | 0.763–1.083 | 7,349 | 5,928–7,548 |
| Remote over QUIC | 1 | 1.942 | 3.290 | 3.012–3.590 | 456 | 451–475 |
| Remote over QUIC | 4 | 3.832 | 6.900 | 5.318–7.218 | 912 | 872–1,012 |

The first signed package load took **47.095–106.698 ms** across the three fresh executors. The first local dispatch took 0.812–1.154 ms and the first successful remote dispatch took 2.198–7.020 ms.

In the separate in-process Criterion run, compiling and pre-instantiating the fixture took **44.413 ms** (95% confidence interval 41.752–46.892 ms). Invoking the preloaded signed component through `Kernel::invoke` with a five-byte input took **39.175 µs** (95% confidence interval 34.876–44.918 µs). These intervals describe Criterion’s estimates over 30 samples per benchmark.

## Reproduce

From the repository root on Linux or macOS, run the following commands on an otherwise idle host.

```sh
cargo build --locked --release -p entangle-bin -p entangle-cli
ENTANGLE_BENCH_DAEMON="$PWD/target/release/entangled" \
  cargo test --locked -p entangle-bin --test daemon_compute \
  benchmark::measure_dispatch -- --exact --ignored --nocapture
```

Each run starts fresh daemons and generates a publisher key, peer identities, and a signed package containing the 50,943-byte WASI Preview 2 hello-pong fixture. The first package-load timing covers the load RPC, signature verification, and component compilation. File-system caches are uncontrolled. First local and first remote dispatch timings begin after the component is loaded. The first remote call follows the first local invocation on the same executor. Its timing covers the first successful submission and excludes retries while the submitter learns worker capabilities.

Each route runs first with one client, then with four concurrent clients. Each configuration warms up with 16 requests and measures 1,024 more. A client submits its next request immediately after its previous response. Each measured task sends a unique 11-byte ASCII input, requests 0.01 CPU cores, and uses the `None` task integrity policy. The daemons enforce peer trust and signed-package verification. The driver checks the 19-byte greeting against that input and verifies the executor ID. The runtime instantiates a fresh guest for every invocation from the already compiled component. Each call opens a Unix socket connection. The remote path also establishes a QUIC connection for the task.

Per-call p50 and p95 use nearest rank. Throughput divides verified completions by total wall time for the measured group. The test driver is unoptimized and the daemons use the release profile. Each daemon uses two Tokio and two Rayon threads with `RUST_LOG=warn`. The driver uses two Tokio threads.

For a separate measurement inside a single process, the existing Criterion kernel suite measures compilation from component bytes and repeated signed-plugin calls directly through `Kernel::invoke`.

```sh
TOKIO_WORKER_THREADS=2 RAYON_NUM_THREADS=2 \
  cargo bench --locked -p entangle-bench --bench kernel -- \
  'kernel/(plugin_instantiate|kernel_invoke)/hello-pong' --warm-up-time 1 --measurement-time 3 \
  --sample-size 30 --noplot
```

The architecture’s workload A budgets <300 ms to the first token and ≥30 tokens/s for streaming 70B inference. Workload B targets a 10× wall-clock speedup on an 8,000-photo job across three desktops. Those acceptance tests require the corresponding model, hardware, or dataset. This benchmark measures a short one-shot component on loopback. [Architecture §7.0](architecture.md#70-reference-workloads)

## Image workload and wire-codec acceptance criteria

These criteria were recorded before the 27 November measurements.

- The application workload resizes 24 distinct JPEG variants of a real photograph to PNG using the signed catalog component and Lanczos3. All routes receive the identical byte corpus, four concurrent clients and the same per-daemon thread settings. Every PNG must have the requested dimensions and its mean absolute error in each eight-bit RGB channel must be at most three levels against an independent Pillow resize. All routes must also produce byte-identical results for each input. Each automatically scheduled three-worker trial must use all three authenticated workers.
- For this shared-VM workload, the scaling target is at least 1.10× the median throughput of the same coordinator pinned to one remote executor. The local four-client reference is measured on the same corpus. All routes share the same host CPU quota.
- For the scheduler wire optimization, the engineering target is at least 2× baseline throughput at 256 KiB and at most a 10% median time regression at 64 bytes. The microbenchmark measures both directions of a validated v1 echo round trip, holding plugin execution and transport outside the timer. Wire bytes and existing error checks must remain compatible.

### Reproduce the signed image workload

The reference corpus is the U.S. Navy photograph of Grace Hopper distributed with Matplotlib. The measured source JPEG is 512 × 600 and has SHA-256 `a8ca6d734765703b09728ab47fe59f473d93ae3967fc24c7c0288c3c7adb7130`. The harness deterministically crops and mirrors this one photograph into 24 distinct JPEGs at 768 × 896. It requests Lanczos resizing to 192 × 224 PNG from the signed catalog component. [Source photograph](https://github.com/matplotlib/matplotlib/blob/v3.10.0/lib/matplotlib/mpl-data/sample_data/grace_hopper.jpg)

On a Linux host with Python 3.11 or later, Pillow, OpenSSL and the Rust `wasm32-wasip2` target installed, run the following from the repository root. The benchmark writes detailed per-trial measurements to JSON. Exit status 2 signals that measured scaling missed the declared threshold. Oracle or executor-selection failures stop the run with an error.

```sh
cargo build --locked --release -p entangle-bin -p entangle-cli
cargo build --locked --release --target wasm32-wasip2 \
  --target-dir target/catalog-smoke --manifest-path plugins/image-resize/Cargo.toml
curl -fL https://raw.githubusercontent.com/matplotlib/matplotlib/v3.10.0/lib/matplotlib/mpl-data/sample_data/grace_hopper.jpg \
  -o target/grace_hopper.jpg
python3 -m unittest discover -s scripts/tests -p test_benchmark_image_batch.py
python3 scripts/benchmark_image_batch.py --bin-dir target/release \
  --wasm target/catalog-smoke/wasm32-wasip2/release/entangle_image_resize.wasm \
  --image target/grace_hopper.jpg --results image-results.json
cargo bench --locked -p entangle-scheduler --bench wire_payload
```

Four isolated daemon identities share a VM. Three workers load the same signed package and first execute a directed warmup through the coordinator. The coordinator has an empty package registry. Every timed batch uses four concurrent clients. The driver rotates the order of the three routes over three trials and keeps each batch's 3,482,013 input bytes identical. Timing starts at Unix socket connect and ends at receipt of the final response byte. JSON parsing and reference-image checks follow the timer. Each route returns 2,035,585 bytes of lossless PNG per batch. Actual worker IDs and task counts accompany every batch. The driver checks every PNG against the independent Pillow reference and verifies equal SHA-256 output for each input across routes.

The wire microbenchmark uses optimized Rust, two warmup intervals and nine measured intervals per payload size. Each operation encodes and decodes a v1 request, echoes it in a successful response, encodes and decodes that response, then checks every returned byte. Each interval contains 50,000 operations at 64 bytes or 64 operations at 256 KiB. Earlier code encoded each byte as a sequence element. The optimized wire codec passes the byte slice directly to postcard while preserving its exact serialized representation.

### Paired results, 27 November 2026

The baseline daemon was built from `233177f933c5b4e89aea6063cb06d449528ad065`. The comparison daemon had SHA-256 `51baa1f88ef3906c8b04ce18e5b5c673f34a510e4d85e6622860ea4942d49504` and included other integration changes. Both ran on the four-core-quota VM described above, using Pillow 12.2.0 and the same WASI component. Owners paused builds for the recorded interval, 01:35:00–01:35:22 UTC. The launch check excluded zombie processes. A separate process monitor sampled no live compiler at two-second intervals during 01:35:10–01:35:22. There was no continuous monitor for the first ten seconds or exclusive host allocation. Daemon binaries ran in baseline-then-candidate order, with each route rotated inside its three trials. [Raw trial data and protocol versions](testing/production-review/evidence/image-wire-2026-11-27.json)

Across both binaries, **432 of 432** timed image outputs matched byte-for-byte for their respective inputs. Worst independent reference error was **0.2353** on the 0–255 channel scale. Every automatic batch used all three executor identities. Table entries are medians across the three 24-image trials. The ranges cover all three throughput values.

| Version | Route | Images/s (range) | Batch wall (s) | RPC p50 (ms) | RPC p95 (ms) |
| --- | --- | ---: | ---: | ---: | ---: |
| Baseline | Local | 41.92 (41.33–42.22) | 0.573 | 74.58 | 133.13 |
| Baseline | One remote | 35.18 (30.87–38.74) | 0.682 | 104.96 | 159.97 |
| Baseline | Three remote | 38.12 (35.47–40.50) | 0.630 | 103.03 | 130.46 |
| Candidate | Local | 34.19 (33.91–49.73) | 0.702 | 103.03 | 133.50 |
| Candidate | One remote | 37.22 (30.46–38.42) | 0.645 | 94.09 | 192.04 |
| Candidate | Three remote | 38.56 (35.13–41.27) | 0.622 | 98.66 | 122.22 |

The three-worker speedups were **1.084× baseline** and **1.036× candidate**. Both missed the 1.10× scaling threshold. The co-located workers share the same CPU quota as the single worker; additional processes added no hardware capacity. Single-remote throughput rose 5.8%, three-remote throughput rose 1.1%, single-remote p95 increased 20.0%, and median local throughput fell 18.4%. The broad trial ranges, binary order and other candidate changes limit attribution. These application measurements leave the production ≤5% regression gate open. The physical 8,000-RAW, three-desktop workload and 70B streaming targets still require their specified hosts, inputs and measurements.

The isolated wire benchmark ran in baseline, candidate, candidate, baseline order. Averaging the two per-run medians, 256 KiB took **1,013.06 µs before** and **211.85 µs after**, a **4.78× speedup**. At 64 bytes the medians were **0.4665 µs** and **0.3725 µs**, a **20.2% reduction**. Both wire thresholds passed. The scheduler tests also verified cross-decoding and byte-identical v1 serialization at six payload sizes. This narrower measurement isolates the per-byte serialization cost from Wasm execution, RPC JSON and QUIC setup.

### Fixed worker capacity experiment

A separate experiment controls per-worker CPU capacity. Before running it, we set the application throughput target at **1.50×** for three remote workers versus one and the candidate latency target at **no more than 5% p95 regression** versus the baseline on each route. The same three trials, route rotation, four clients, image corpus, signed component, output checks and per-daemon thread settings apply. The Linux driver option `--worker-cpu-affinity` pins each worker to one distinct virtual CPU with `taskset` and restricts the coordinator and benchmark driver to the remaining virtual CPUs. The driver records actual affinity as well as changes in process CPU time during each timed batch. Average CPU cores per process equals CPU seconds divided by batch wall seconds. The unrestricted configuration is also rerun with that instrumentation. The original unrestricted and physical workload gates retain their separate outcomes.

The instrumented run produced **864 verified image results** in four fresh clusters. It ran unrestricted baseline, fixed-capacity candidate, fixed-capacity baseline and unrestricted candidate, in that order. Each fixed worker had 12 OS threads at warmup sharing its assigned CPU. The coordinator had seven threads on CPUs 3 and 4. The unrestricted workers had 11 threads apiece and the coordinator had nine, all eligible for CPUs 0–4 under the four-core cgroup quota. The driver checked each live thread’s affinity. During 55 one-second process CPU samples, there were no live compiler or build-tool matches. No other observed process exceeded 0.25 average cores in a sampled interval. [Per-batch CPU, affinity, timing and process-monitor samples](testing/production-review/evidence/image-capacity-2026-11-27.json)

| CPU capacity | Binary | Local images/s | One remote images/s | Three remote images/s | Three/one | Worker CPU cores, one → three |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| Shared | Baseline | 38.85 | 35.14 | 36.22 | 1.031× | 2.98 → 2.89 |
| Shared | Candidate | 46.41 | 31.33 | 37.12 | 1.185× | 2.67 → 2.97 |
| One core per worker | Baseline | 14.77 | 15.68 | 28.08 | 1.791× | 0.96 → 2.52 |
| One core per worker | Candidate | 14.62 | 14.70 | 29.51 | **2.007×** | **0.96 → 2.48** |

One unrestricted daemon already executed several image tasks concurrently and consumed roughly three CPU cores. Three unrestricted workers used about the same aggregate compute. When each worker had one CPU, activating two more workers added measured compute capacity and the candidate passed the 1.50× gate. Its three workers each completed between 6 and 11 tasks per batch. This experiment measures scaling across distinct CPU allocations on one VM.

| CPU capacity | Route | Baseline p95 (ms) | Candidate p95 (ms) | Change |
| --- | --- | ---: | ---: | ---: |
| Shared | Local | 132.73 | 120.24 | −9.4% |
| Shared | One remote | 157.45 | 186.95 | +18.7% |
| Shared | Three remote | 174.51 | 127.80 | −26.8% |
| One core per worker | Local | 436.47 | 450.14 | +3.1% |
| One core per worker | One remote | 326.90 | 323.86 | −0.9% |
| One core per worker | Three remote | 272.93 | 174.94 | −35.9% |

All fixed-capacity routes passed the preregistered 5% p95 bound. Fixed single-remote throughput fell 6.3% versus baseline. The unrestricted one-remote p95 increase repeated the first measurement's direction and magnitude, and its throughput fell 10.8% in this repeat. The unrestricted candidate's three/one ratio varied from 1.036× to 1.185× across runs. The initial shared-capacity miss and the physical workload requirements remain open.

### Isolating the one-remote tail

Before measuring the next comparison, we specified two production-profile binaries built from the same candidate checkout and lock file. The only source change between those builds is how the two v1 payload fields are serialized. Six fresh matched runs per binary will alternate scalar-first and bulk-first ordering using the original corpus, four clients and three warmed 24-image single-remote batches per run. The gate for retaining bulk serialization on this workload is a median per-run p95 no more than 5% above scalar serialization, alongside the existing wire microbenchmark target. This controls the other integration changes present in the earlier two binaries.

The six matched pairs completed **864 renders**, with identical input and PNG hashes across both builds. Scalar serialization produced a median one-remote p95 of **163.56 ms**; bulk serialization produced **166.80 ms**, **1.98% higher**. Four of the six pairs favored bulk. The per-pair ratios ranged from 0.899× to 1.344×. Median throughput was **35.55 images/s scalar** and **34.51 images/s bulk**, 2.94% lower. The codec-only comparison passed its prespecified p95 limit and the 256 KiB throughput test. The default uses bulk serialization. The larger historical one-remote p95 increase remains unexplained across those integrated binaries. [Pair-level results, individual call latencies, binary digests and live CPU samples](testing/production-review/evidence/codec-isolation-2026-11-27.json)

The comparison used the same source path and Rust release settings. The scalar build omitted only the two `#[serde(with = "serde_bytes")]` field attributes on the v1 request input and successful response output. Both binaries used the same `Cargo.lock` (SHA-256 `22cca61e5bc1535c9d2d5b3f7f9eeb1d56ee77635e1e80c6693ab129def6cd6b`). The daemon had a separate build target name in both builds to preserve the workspace release artifact. The driver used `--route one_remote` alongside the image benchmark arguments shown above. Odd-numbered pairs ran scalar first and even pairs ran bulk first. Each per-run number is the median of three 24-call nearest-rank p95s. The reported p95 compares the median of the six independently initialized runs for each codec. No compiler or build process appeared in the 58 one-second samples between 01:57:00 and 01:57:58 UTC.
