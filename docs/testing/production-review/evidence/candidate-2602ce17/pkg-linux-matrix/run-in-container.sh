#!/bin/bash
# Build the final package independently in one pinned Ubuntu userspace.
set -euo pipefail
set -x

expected_version=$1
expected_commit=$2
source /etc/os-release
test "$VERSION_ID" = "$expected_version"
cat /etc/os-release
uname -m
id
ldd --version
gcc --version
git --version
cat /proc/net/route
test "$(wc -l </proc/net/route)" -eq 1

work=$(mktemp -d "/tmp/entangle ubuntu-$VERSION_ID.XXXXXX")
export CARGO_HOME="$work/cargo-home"
export CARGO_TARGET_DIR="$work/operator-build"
export CARGO_BUILD_JOBS=2 CARGO_NET_OFFLINE=true CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0
export PATH="/fixture/toolchain/bin:$PATH"
mkdir -p "$CARGO_HOME/registry"
cp -R /fixture/registry/cache /fixture/registry/index "$CARGO_HOME/registry/"
rustc -Vv
cargo -Vv
sha256sum /fixture/toolchain/bin/{cargo,rustc} /fixture/source.bundle
git clone --no-hardlinks --no-checkout /fixture/source.bundle "$work/frozen source"
git -C "$work/frozen source" checkout --detach "$expected_commit"
test "$(git -C "$work/frozen source" rev-parse HEAD)" = "$expected_commit"
test -z "$(git -C "$work/frozen source" status --porcelain)"
(cd "$work/frozen source" && cargo build --offline --locked -p cargo-entangle)
sha256sum "$CARGO_TARGET_DIR/debug/cargo-entangle"
export PATH="$CARGO_TARGET_DIR/debug:$PATH"
cd "$work"
cargo entangle --version
cargo entangle package "$work/frozen source/examples/hello-world" \
    --source-url https://github.com/thekozugroup/Entanglement.git \
    --key /fixture/public-repro-fixture-seed.pem --out /tmp/hello-world.tar.zst
sha256sum /tmp/hello-world.tar.zst
