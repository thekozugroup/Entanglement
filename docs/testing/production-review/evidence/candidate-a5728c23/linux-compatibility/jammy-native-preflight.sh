#!/bin/sh
set -eu
test "$(id -u)" -eq 65534
test "$(wc -l </proc/net/route)" -eq 1
test -z "$(ls -A /build-target)"
fixture=/build-target/native-preflight
mkdir "$fixture"
trap 'rm -rf "$fixture"' EXIT
export HOME="$fixture/home"
export CARGO_HOME="$fixture/cargo-home"
export CARGO_TARGET_DIR="$fixture/target"
export PATH=/seed/toolchain/bin:/usr/bin:/bin
export CARGO_NET_OFFLINE=true CARGO_INCREMENTAL=0
mkdir "$HOME" "$fixture/src"
cd "$fixture"
printf '%s\n' '[package]' 'name = "entangle-native-tmpfs-check"' 'version = "0.0.0"' 'edition = "2021"' > Cargo.toml
printf '%s\n' 'fn main() { println!("Jammy locked native build"); }' > src/main.rs
cargo generate-lockfile --offline
cargo build --release --locked --offline --jobs 1 --target x86_64-unknown-linux-gnu
native="$CARGO_TARGET_DIR/x86_64-unknown-linux-gnu/release/entangle-native-tmpfs-check"
test "$("$native")" = 'Jammy locked native build'
"$native"
ldd "$native"
sha256sum Cargo.lock "$native"
pages=0
for file in /proc/[0-9]*/statm; do
    if read -r size rss rest 2>/dev/null < "$file"; then
        pages=$((pages + rss))
    fi
done
printf 'Namespaced process RSS bytes: %s\n' "$((pages * $(getconf PAGESIZE)))"
