#!/usr/bin/env bash
# Build hello-pong.wasm and place it under crates/entangle-host/tests/fixtures/.
#
# Uses `rustup run 1.91` to ensure the rustup-managed toolchain is used
# (avoids Homebrew rustc which lacks the wasm32-wasip2 stdlib).
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$HERE"
rustup target add wasm32-wasip2 --toolchain 1.91 >/dev/null 2>&1 || true
rustup run 1.91 cargo build --release --target wasm32-wasip2
DEST="$HERE/../../tests/fixtures"
mkdir -p "$DEST"
cp target/wasm32-wasip2/release/hello_pong.wasm "$DEST/hello-pong.wasm"
ls -la "$DEST/hello-pong.wasm"
echo "built $DEST/hello-pong.wasm"
