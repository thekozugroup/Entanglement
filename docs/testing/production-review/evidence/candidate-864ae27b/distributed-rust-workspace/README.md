# Distributed Cargo workspace evidence

The frozen Linux daemon ran the complete default Rust test suite from the production rust-random/rngs repository on two authenticated QUIC workers. The local native oracle and the distributed run each reported 198 passing unit/integration tests, 24 passing documentation tests and two ignored documentation tests. An independent comparison found zero differences across all 224 package, target, case name and disposition records. Cargo exited successfully in both runs. The source tree and compiler drivers used no injected test or failure. No genuine fail-then-pass transition occurred. [Receipt](rngs-receipt.json) · [Case-level comparison](rngs-native-parity.json)

The nine-member workspace was pinned to `aeaa3f312f915fdf72f0d43af6a84197b079bf81` with its MIT or Apache-2.0 license. It has no committed Cargo.lock, so the first resolution was archived and both targets used that same dependency lock. The daemon and CLI are the official 864ae27b optimized binaries. This evidence measures test outcomes and worker attribution on one Linux VM. [Upstream revision](https://github.com/rust-random/rngs/tree/aeaa3f312f915fdf72f0d43af6a84197b079bf81) · [Frozen dependency lock](rngs-Cargo.lock.gz)

The evidence driver implements Cargo's target-runner interface. Cargo gave it the 17 WASI libtest executables and six Rust 2024 merged documentation-test executables produced by rustdoc. Each worker trusted the coordinator’s publisher key, loaded the signed artifacts into its runtime and executed them through the shipped scheduler with an explicit worker allowlist. Regular tests used the shipped exact-name sharder. Rustdoc's merged executable runs its complete crate group on invocation and reports individual case names and dispositions. The driver checked its exit status and summary against the observed cases and retained complete worker output. Cargo itself handled the remaining three library documentation groups with no test cases. The audit driver lives in this evidence directory. [Distributed case records](rngs-distributed.json.gz) · [Cargo output](rngs-distributed-cargo.log.gz) · [Native Cargo output](rngs-native-cargo.log.gz)

## Reproduction

Use Python 3.11+, OpenSSL, Git, Rust 1.91.1 with the wasm32-wasip2 target, and the frozen release daemon and CLI. Point `ent_root` at the Entanglement checkout. The audit keeps the upstream source outside this repository.

```sh
ent_root=/workspace/Entanglement
ev="$ent_root/docs/testing/production-review/evidence/candidate-864ae27b/distributed-rust-workspace"
work=$(mktemp -d)
git clone https://github.com/rust-random/rngs.git "$work/rngs"
git -C "$work/rngs" checkout --detach aeaa3f312f915fdf72f0d43af6a84197b079bf81
cd "$work/rngs"
gzip -dc "$ev/rngs-Cargo.lock.gz" > Cargo.lock
export CARGO_TARGET_DIR="$work/target" CARGO_PROFILE_DEV_DEBUG=0 CARGO_INCREMENTAL=0
cargo +1.91.1 fetch --locked
cargo +1.91.1 metadata --offline --locked --format-version=1 --no-deps > "$work/metadata.json"
cargo +1.91.1 test --offline --locked --workspace --no-run --message-format=json > "$work/native.jsonl"
cargo +1.91.1 test --offline --locked --workspace --no-fail-fast > "$work/native.log" 2>&1
cargo +1.91.1 test --offline --locked --workspace --target wasm32-wasip2 --no-run \
  --message-format=json > "$work/wasi.jsonl"
python3 "$ev/dispatch-cargo-workspace.py" --root "$ent_root" --workspace "$PWD" \
  --binaries "$ent_root/target/release" --metadata "$work/metadata.json" \
  --wasm-artifacts "$work/wasi.jsonl" --out "$work/distributed.json" --cargo-log "$work/distributed.log"
python3 "$ev/verify-native-parity.py" --metadata "$work/metadata.json" \
  --native-artifacts "$work/native.jsonl" --native-log "$work/native.log" \
  --distributed "$work/distributed.json" --out "$work/comparison.json"
```

## Qualification limits

Architecture §7.0 selects a Rust monorepo and permits WASI and signed tier-5 subprocess test units. It names no particular monorepo, physical processor or numerical speedup for this workload. The fixed evidence plan additionally requires actual flaky semantics and disallows an injected flaky fixture. This run supplies complete workspace coverage and aggregation. Genuinely flaky worker execution remains unproven. [Architecture](../../../../../architecture.md#70-reference-workloads) · [Frozen evidence plan](../../../final-evidence-plan.md)

A separate unmodified rand 0.9.2 workspace exposed a concrete mismatch. Its native oracle passed 132 regular cases and 65 doctests, with four doctests ignored. The eight signed WASI artifacts supplied 126 ordinary passes and four errors. Its four `#[should_panic]` selectors returned `0 passed; 1 ignored` under the target's panic-abort harness even though the ignored-list operation omitted them. Four native cases were also absent on WASI, and two 32-bit-specific cases appeared. The full comparison preserves these failures. [Rand diagnosis](rand092-diagnostic.json) · [Signed worker results](rand092-remote.json.gz)

The Entanglement workspace's full locked WASI build failed on Tokio's native I/O requirements. The released runtime rejects generic native executable packages. An original pre-fix proptest workspace at `cb347889a0b8709ec241133d5492095069987383` has a documented genuine probabilistic failure, but its default build requires native process wait support. A separate reduced-feature WASI probe also failed on Unix-only tests. A future signed, sandboxed native libtest execution path or a WASI-compatible upstream workload with an observed natural retry could cover this remaining requirement. [Compiler output](cross-target-errors.json) · [Entanglement full-workspace build](entanglement-full-wasi-no-run.log.gz) · [Upstream proptest fix](https://github.com/proptest-rs/proptest/commit/2325e7ac887ab3c87ad19d1498c4349cfd7ec808)
