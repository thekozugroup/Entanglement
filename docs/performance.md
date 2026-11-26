# One-shot compute performance

The dispatch benchmark times a task from the client’s Unix-socket RPC call through decoding its response. It verifies the executor ID and output for every call. The local route submits directly to the daemon that has the plugin. The remote route submits to a separate daemon with an empty plugin registry, which schedules the task on the same executor over authenticated loopback QUIC. Both processes run on the same host with relays disabled.

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
