# Distributed Rust tests

An operator can run stable Rust libtest executables compiled for `wasm32-wasip2` across paired Entanglement workers. Use suites that run without host files, inherited environment variables, subprocesses, or network access. The workers run each selected test in a fresh WASI sandbox with the usual compute memory and wall-clock limits and 64 KiB each for captured stdout and stderr.

Compile your chosen test target and take the `.wasm` executable from the compiler artifact record whose `profile.test` is true.

```sh
rustup target add wasm32-wasip2
cargo test --locked --target wasm32-wasip2 --no-run -p entangle-types \
  --test atc_spec --message-format=json
```

Save this manifest as `entangle.toml` in a suite packaging directory. Change the name, version, and description for your suite. Use a new version when changing the test executable so workers can load the same signed artifact.

```toml
[plugin]
id = "PUBLISHER_PLACEHOLDER/rust-atc@0.1.0"
version = "0.1.0"
tier = 1
runtime = "wasm"
description = "Rust acceptance tests"

[build]
wit_world = "wasi:cli/command@0.2.0"
target = "wasm32-wasip2"
```

Sign the executable with `entangle plugins build /path/to/suite --wasm "$WASM" --out /path/to/signed-suite`. Each worker must trust that publisher key, load the same signed directory with `entangle plugins load /path/to/signed-suite`, and pair with the coordinator. Use `entangle mesh peers` to find the paired peer IDs. Read the full plugin ID from the signed manifest. With the daemons running, invoke the runner from the coordinator over its local socket.

```sh
python3 scripts/run-rust-tests.py "$PLUGIN_ID" --peer "$WORKER_A" --peer "$WORKER_B" \
  --filter atc_int --retries 1 > rust-test-report.json
```

Pass additional signed plugin IDs before the flags to aggregate several suites. The runner compares each suite's test and ignore lists reported by every selected worker, schedules exact test names across the trusted peers, and retries on the next peer. The JSON records the totals, per-suite results, and each attempt with its number and executor ID. The sandbox exposes the 1-based attempt number in `ENTANGLE_LIBTEST_ATTEMPT`, up to 11. A failed test that subsequently passes is `flaky`. A standard Rust panic report from the panic-abort WASI target is a test failure. Other crashes and transport failures are `error`. The runner exits with status 1 if any test stays failed or has no valid result after retries.

List filtering supports one substring or `--exact` and repeatable `--skip`. By default, a test listed as ignored has status `ignored` and an empty `attempts` array. Use `--include-ignored` to request execution alongside regular tests or `--ignored` to select only tests listed as ignored.

The target can also report an ignore after a test is selected, including when `--include-ignored` requests execution. For example, Rust's panic-abort WASI harness can skip a `#[should_panic]` test that passes natively. The report records that ignore with the worker ID, attempt number, and captured libtest output. An ignore on the first attempt completes the selection without retrying. An ignored retry consumes one attempt and leaves any earlier failure or error unresolved until a later pass. A report with only passes and ignores exits successfully. Compare named native and WASI dispositions when checking parity, since a native pass and a WASI ignore are distinct outcomes.

## Loopback integration test

From the repository root, build the two Entanglement executables and compile both `atc_spec` targets. Set `TYPES_WASM` and `MANIFEST_WASM` to the respective test executable paths in the Cargo compiler artifact output. Run the fixture with Python 3.11 or newer and OpenSSL on Linux.

```sh
cargo build --locked -p entangle-bin -p entangle-cli
cargo test --locked --target wasm32-wasip2 --no-run -p entangle-types \
  --test atc_spec --message-format=json
cargo test --locked --target wasm32-wasip2 --no-run -p entangle-manifest \
  --test atc_spec --message-format=json
rustc --target wasm32-wasip2 --test scripts/tests/fixtures/libtest_retry.rs \
  -o target/libtest_retry.wasm
python3 scripts/tests/distributed-rust-tests.py --types-wasm "$TYPES_WASM" \
  --manifest-wasm "$MANIFEST_WASM" --retry-wasm target/libtest_retry.wasm
```

The pilot generates three temporary identities and starts one coordinator plus two independent worker daemons. It checks aggregation of the existing `entangle-types` and `entangle-manifest` acceptance suites, per-worker attribution, default ignores, and filtering. A separate regression fixture supplies one deliberately ignored test that always fails when selected and another that fails on attempt 1 and passes on attempt 2. The report must retain both authenticated worker attempts and distinguish an unresolved failure from a flaky test.

## Observed Linux loopback run

On 27 November 2026 with Rust 1.91.1, the two existing suites reported 14 passed and 8 ignored in 152 ms after the packages were loaded. The two workers ran seven tests each. The filter and skip run reported five passed and 11 filtered. The separate regression fixture retained its first-attempt panic and second-attempt pass from different workers. Its ignored test made no attempt until explicitly selected, then failed on both workers and returned exit status 1. This run covered two existing WASI-compatible test targets on one host. [Raw reports and artifact digests](production-review/evidence/distributed-rust-tests-2026-11-27.json)
