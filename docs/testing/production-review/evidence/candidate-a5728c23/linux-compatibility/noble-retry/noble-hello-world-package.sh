#!/bin/sh
set -eu
test "$#" -eq 1
expected_commit=$1
test "$(id -u)" -eq 65534
test "$(wc -l </proc/net/route)" -eq 1
. /etc/os-release
test "$VERSION_ID" = 24.04
test "$(getconf GNU_LIBC_VERSION)" = 'glibc 2.39'
printf '%s\n' "$PRETTY_NAME"
getconf GNU_LIBC_VERSION
df -B1 /build-target
export PATH=/packager:/seed/toolchain/bin:/usr/bin:/bin
export HOME=/build-target/home
export CARGO_HOME=/build-target/cargo-home
export CARGO_NET_OFFLINE=true CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS=2
export LC_ALL=C.UTF-8
mkdir -p "$HOME" "$CARGO_HOME/registry"
cp -R /seed/registry/cache /seed/registry/index "$CARGO_HOME/registry/"
sha256sum /source.bundle /packager/cargo-entangle /seed/toolchain/bin/cargo /seed/toolchain/bin/rustc
git clone --branch frozen-compat /source.bundle '/build-target/noble source'
test "$(git -C '/build-target/noble source' rev-parse HEAD)" = "$expected_commit"
test -z "$(git -C '/build-target/noble source' status --porcelain)"
cd /build-target
cargo entangle --version
archive=/build-target/hello-world-repro.tar.zst
cargo entangle package '/build-target/noble source/examples/hello-world' \
    --source-url https://github.com/thekozugroup/Entanglement.git \
    --key /public-repro-fixture.pem --out "$archive"
sha256sum "$archive"
stat -c '%s' "$archive"
