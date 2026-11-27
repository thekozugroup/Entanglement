#!/bin/sh
set -eu
commit=$1
os_version=$2
libc=$3
. /etc/os-release
test "$VERSION_ID" = "$os_version"
test "$(getconf GNU_LIBC_VERSION)" = "glibc $libc"
test "$(id -u)" -eq 65534
test "$(wc -l </proc/net/route)" -eq 1
export PATH=/packager:/seed/toolchain/bin:/usr/bin:/bin
export HOME=/build/home CARGO_HOME=/build/cargo-home TMPDIR=/build/tmp
export CARGO_NET_OFFLINE=true CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS=2 LC_ALL=C.UTF-8
mkdir -p "$HOME" "$CARGO_HOME/registry" "$TMPDIR"
cp -R /seed/registry/cache /seed/registry/index "$CARGO_HOME/registry/"
git clone --branch frozen-compat /source.bundle "/build/Ubuntu $os_version source"
checkout="/build/Ubuntu $os_version source"
test "$(git -C "$checkout" rev-parse HEAD)" = "$commit"
test -z "$(git -C "$checkout" status --porcelain)"
fixture="$checkout/examples/hello-world"
cd /build
printf 'OS %s, ' "$PRETTY_NAME"
getconf GNU_LIBC_VERSION
rustc --version --verbose
cargo --version
cargo entangle --version
test "$(rustc --version | cut -d' ' -f2)" = 1.91.1
(cd "$fixture" && sha256sum Cargo.lock rust-toolchain.toml entangle.toml src/lib.rs)
cargo entangle package "$fixture" --source-url https://github.com/thekozugroup/Entanglement.git --key /public-repro-fixture.pem --out /build/hello-world.tar.zst
sha256sum /build/hello-world.tar.zst
stat -c '%s' /build/hello-world.tar.zst
