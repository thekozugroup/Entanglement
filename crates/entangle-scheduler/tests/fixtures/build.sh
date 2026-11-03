#!/usr/bin/env bash
# Rebuild the stdlib metric fixtures from plugins/metric-* and copy them here.
#
# The integrity tests (tests/integrity_atc.rs) run the *real* stdlib metric
# components, pre-built so the test suite does not need the wasm32-wasip2
# target. Re-run this after changing plugins/metric-bleu-4 or
# plugins/metric-numerical-l2-relative.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$HERE/../../../.."
rustup target add wasm32-wasip2 >/dev/null 2>&1 || true
for name in metric-bleu-4 metric-numerical-l2-relative; do
  (cd "$ROOT/plugins/$name" && cargo build --release --target wasm32-wasip2)
  crate="entangle_${name//-/_}"
  cp "$ROOT/plugins/$name/target/wasm32-wasip2/release/$crate.wasm" "$HERE/$name.wasm"
  ls -la "$HERE/$name.wasm"
done
