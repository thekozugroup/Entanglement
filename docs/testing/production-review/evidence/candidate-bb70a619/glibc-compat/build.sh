#!/bin/bash
set -euxo pipefail
export PATH="/fixture/toolchain/bin:/usr/bin:/bin"
export CARGO_HOME=/tmp/build-cargo-home CARGO_TARGET_DIR=/tmp/build-target
export CARGO_BUILD_JOBS=3 CARGO_INCREMENTAL=0 CARGO_NET_OFFLINE=true
test "$(wc -l </proc/net/route)" -eq 1
test ! -e "$CARGO_TARGET_DIR"
mkdir -p "$CARGO_HOME/registry"
cp -R /fixture/registry/cache /fixture/registry/index "$CARGO_HOME/registry/"
git clone --branch frozen-compatible /fixture/source.bundle /tmp/build-source
cd /tmp/build-source
test "$(git rev-parse HEAD)" = bb70a6193f8879b1feb3e6d3ceb8f2980413ce58
test -z "$(git status --porcelain)"
sha256sum Cargo.lock Cargo.toml
cargo build --release --locked --offline -p entangle-cli -p entangle-bin -p cargo-entangle -p xtask
test -z "$(git status --porcelain)"
sha256sum "$CARGO_TARGET_DIR"/release/{entangle,entangled,cargo-entangle,xtask}
