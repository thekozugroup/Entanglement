#!/bin/sh
set -eu
# Select the already provisioned compiler directly; respect the isolated offline namespace.
export RUSTUP_TOOLCHAIN=1.91.1-x86_64-unknown-linux-gnu
export PATH=/usr/local/rustup/toolchains/1.91.1-x86_64-unknown-linux-gnu/bin:$PATH
export LC_ALL=C CARGO_NET_OFFLINE=true CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS=3
export CARGO_HOME=/private/cargo CARGO_TARGET_DIR=/private/target
export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc
export CC_aarch64_unknown_linux_gnu=aarch64-linux-gnu-gcc
export CXX_aarch64_unknown_linux_gnu=aarch64-linux-gnu-g++
export AR_aarch64_unknown_linux_gnu=aarch64-linux-gnu-ar
export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_RUNNER='/private/qemu/qemu-aarch64 -L /usr/aarch64-linux-gnu'
# One rootless namespace using loopback only after private tooling provision.
test "$(wc -l </proc/net/route)" -eq 1
mkdir -p "$CARGO_HOME/registry"
# Seed only Cargo's authenticated archive/index; newly expanded crate sources are local.
ln -sf /seed-registry/cache "$CARGO_HOME/registry/cache"
ln -sf /seed-registry/index "$CARGO_HOME/registry/index"
cd /src
sha256sum Cargo.lock Cargo.toml
rustc --print target-libdir --target aarch64-unknown-linux-gnu
printf 'Start UTC: ';date -u +%FT%TZ
cargo build --release --workspace --bins --locked --target aarch64-unknown-linux-gnu --offline
for exe in entangle entangled; do
  path="$CARGO_TARGET_DIR/aarch64-unknown-linux-gnu/release/$exe"
  sha256sum "$path"
  aarch64-linux-gnu-readelf -h "$path"
  aarch64-linux-gnu-readelf --program-headers --wide "$path" | grep 'interpreter'
  aarch64-linux-gnu-readelf -d "$path" | grep NEEDED
  aarch64-linux-gnu-readelf --version-info "$path" | grep 'Name: GLIBC_' | sort -V
  /private/qemu/qemu-aarch64 -L /usr/aarch64-linux-gnu "$path" --version
done
printf 'End UTC: ';date -u +%FT%TZ
