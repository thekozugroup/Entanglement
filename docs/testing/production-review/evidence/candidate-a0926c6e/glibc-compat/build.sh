#!/bin/bash
set -euxo pipefail
export PATH="/fixture/toolchain/bin:/usr/bin:/bin"
export CARGO_HOME=/tmp/build-cargo-home CARGO_TARGET_DIR=/tmp/build-target
export CARGO_BUILD_JOBS=3 CARGO_INCREMENTAL=0 CARGO_NET_OFFLINE=true
test "$(wc -l </proc/net/route)" -eq 1
test -d "$CARGO_TARGET_DIR"
cd /tmp/build-source
git fetch --no-tags /tmp/successor.bundle refs/heads/frozen-compatible
git checkout --detach FETCH_HEAD
test "$(git rev-parse HEAD)" = a0926c6ef3471aad01cedd256028437b249ef747
test -z "$(git status --porcelain)"
sha256sum Cargo.lock Cargo.toml
cargo clean --release --offline --locked --package cargo-entangle --package entangle-agent-host --package entangle-atc-matrix --package entangle-bench --package entangle-bin --package entangle-biscuits --package entangle-broker --package entangle-cli --package entangle-core --package entangle-host --package entangle-ipc --package entangle-manifest --package entangle-mesh-iroh --package entangle-mesh-local --package entangle-mesh-tailscale --package entangle-observability --package entangle-oci --package entangle-pairing --package entangle-peers --package entangle-rpc --package entangle-runtime --package entangle-scheduler --package entangle-sdk --package entangle-signing --package entangle-types --package entangle-wit --package xtask
cargo build --release --locked --offline -p entangle-cli -p entangle-bin -p cargo-entangle -p xtask
test -z "$(git status --porcelain)"
sha256sum "$CARGO_TARGET_DIR"/release/{entangle,entangled,cargo-entangle,xtask}
