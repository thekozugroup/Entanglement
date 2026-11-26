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
