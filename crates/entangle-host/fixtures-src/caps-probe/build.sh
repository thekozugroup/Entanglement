#!/usr/bin/env bash
# Build caps-probe.wasm and place it under crates/entangle-host/tests/fixtures/.
#
# Uses `rustup run 1.91` to ensure the rustup-managed toolchain is used
# (avoids Homebrew rustc which lacks the wasm32-wasip2 stdlib).
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$HERE"
rustup target add wasm32-wasip2 --toolchain 1.91 >/dev/null 2>&1 || true
rustup run 1.91 cargo build --release --target wasm32-wasip2
TARGET="${CARGO_TARGET_DIR:-target}"
DEST="$HERE/../../tests/fixtures"
mkdir -p "$DEST"
cp "$TARGET/wasm32-wasip2/release/caps_probe.wasm" "$DEST/caps-probe.wasm"
ls -la "$DEST/caps-probe.wasm"
echo "built $DEST/caps-probe.wasm"
