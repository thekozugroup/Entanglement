#!/bin/sh
set -eu
test "$#" -eq 2
expected_commit=$1
expected_lock=$2
export PATH=/seed/toolchain/bin:/opt/entangle-build/bin:/usr/bin:/bin
export HOME=/build-target/home
export CARGO_HOME=/build-target/cargo-home
export CARGO_TARGET_DIR=/build-target/target
export CARGO_BUILD_JOBS=2 CARGO_NET_OFFLINE=true CARGO_INCREMENTAL=0
export LC_ALL=C.UTF-8
test "$(id -u)" -eq 65534
test "$(wc -l </proc/net/route)" -eq 1
test "$(df -B1 /build-target | awk 'NR==2{print $2}')" = 7516192768
test -z "$(ls -A /build-target)"
getconf GNU_LIBC_VERSION
rustc -Vv
cargo -Vv
python3 --version
b3sum --version
mkdir -p "$HOME" "$CARGO_HOME/registry"
/usr/bin/cp -R /seed/registry/cache /seed/registry/index "$CARGO_HOME/registry/"
git clone --branch frozen-compat /source.bundle /build-target/source
cd /build-target/source
test "$(git rev-parse HEAD)" = "$expected_commit"
test "$(sha256sum Cargo.lock | cut -d ' ' -f 1)" = "$expected_lock"
test -z "$(git status --porcelain)"
target=x86_64-unknown-linux-gnu
cargo build --release --offline --locked --target "$target" -p entangle-cli -p entangle-bin -p cargo-entangle
test -z "$(git status --porcelain)"
bindir="$CARGO_TARGET_DIR/$target/release"
sha256sum "$bindir/entangle" "$bindir/entangled" "$bindir/cargo-entangle"
epoch=$(git show -s --format=%ct HEAD)
python3 scripts/package-native-release.py --version v0.1.0 --target "$target" --bin-dir "$bindir" \
    --source-date-epoch "$epoch" --output-dir /build-target/archive
sha256sum /build-target/archive/entanglement-v0.1.0-x86_64-unknown-linux-gnu.tar.gz
df -B1 /build-target
