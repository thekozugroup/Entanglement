#!/usr/bin/env bash
set -eu
D=/tmp/entangle-demand-qa/jaq-natural
R=/workspace/Entanglement
B=/tmp/entangle-demand-qa/released-296b427a
M="$R/docs/testing/production-review/evidence/candidate-296b427a/linux-archive.json"
source "$D/env.sh"
export CARGO_TARGET_DIR="$D/target178"
export JAQ_COMPONENT_ENCODER="$D/component-adapter"
export JAQ_WASI_ADAPTER="$CARGO_HOME/registry/src/index.crates.io-1949cf8c6b5b557f/wasi-preview1-component-adapter-provider-36.0.23/artefacts/wasi_snapshot_preview1.command.wasm"
for i in {1..900}; do test ! -x "$B/entangled" || break; sleep 2; done
test -x "$B/entangled"
python3 "$D/campaign-296.py" --root "$R" --binaries "$B" --archive "$M" --sharder "$R/scripts/run-rust-tests.py" --fixture "$R/scripts/tests/distributed-rust-tests.py" --encoder "$JAQ_COMPONENT_ENCODER" --adapter "$JAQ_WASI_ADAPTER" --out "$D/campaign-296" > "$D/campaign-296-launch.log" 2>&1
export JAQ_ARTIFACT_EVIDENCE="$D/full-296-artifact-bindings"
mkdir "$JAQ_ARTIFACT_EVIDENCE"
python3 "$D/workspace-296.py" --root "$R" --workspace "$D/upstream" --metadata "$D/workspace-metadata178.json" --wasm-artifacts "$D/original178-wasi-artifacts.jsonl" --binaries "$B" --out "$D/full-296.json" --cargo-log "$D/full-296-cargo.log" --sharder "$R/scripts/run-rust-tests.py" --binary-manifest "$M" > "$D/full-296-launch.log" 2>&1
