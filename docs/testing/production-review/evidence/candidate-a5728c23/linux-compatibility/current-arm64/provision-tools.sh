set -eu
export LC_ALL=C DEBIAN_FRONTEND=noninteractive
apt-get -o Acquire::Retries=2 update
apt-get -s install --no-install-recommends gcc-aarch64-linux-gnu g++-aarch64-linux-gnu libc6-dev-arm64-cross git make perl pkg-config
apt-get install -y --no-install-recommends gcc-aarch64-linux-gnu g++-aarch64-linux-gnu libc6-dev-arm64-cross git make perl pkg-config
apt-cache policy gcc-aarch64-linux-gnu g++-aarch64-linux-gnu libc6-dev-arm64-cross
dpkg-query -W -f='installed ${Package} ${Version}\n'
aarch64-linux-gnu-gcc -v
sha256sum /usr/bin/aarch64-linux-gnu-gcc /usr/bin/aarch64-linux-gnu-g++ /usr/bin/aarch64-linux-gnu-ld /usr/aarch64-linux-gnu/lib/ld-linux-aarch64.so.1 /usr/aarch64-linux-gnu/lib/libc.so.6 /emu/qemu-aarch64
/emu/qemu-aarch64 --version
/emu/qemu-aarch64 -L /usr/aarch64-linux-gnu /usr/aarch64-linux-gnu/lib/ld-linux-aarch64.so.1 --version
RUSTUP_TOOLCHAIN=1.91.1-x86_64-unknown-linux-gnu rustc -Vv
RUSTUP_TOOLCHAIN=1.91.1-x86_64-unknown-linux-gnu cargo -Vv
apt-get clean
