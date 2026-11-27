set -eu
export LC_ALL=C DEBIAN_FRONTEND=noninteractive
apt-get -o Acquire::Retries=2 -o Acquire::http::Timeout=25 update
apt-get -o Acquire::http::Timeout=25 -s install --no-install-recommends gcc-aarch64-linux-gnu g++-aarch64-linux-gnu libc6-dev-arm64-cross gcc libc6-dev git make perl pkg-config
apt-get -o Acquire::Retries=2 -o Acquire::http::Timeout=25 install -y --no-install-recommends gcc-aarch64-linux-gnu g++-aarch64-linux-gnu libc6-dev-arm64-cross gcc libc6-dev git make perl pkg-config
apt-cache policy gcc-aarch64-linux-gnu g++-aarch64-linux-gnu libc6-dev-arm64-cross
dpkg-query -W -f='installed ${Package} ${Version}\n'
aarch64-linux-gnu-gcc -v
sha256sum /usr/bin/aarch64-linux-gnu-gcc /usr/bin/aarch64-linux-gnu-g++ /usr/bin/aarch64-linux-gnu-ld /usr/aarch64-linux-gnu/lib/ld-linux-aarch64.so.1 /usr/aarch64-linux-gnu/lib/libc.so.6 /emu/qemu-aarch64
/emu/qemu-aarch64 --version
/emu/qemu-aarch64 -L /usr/aarch64-linux-gnu /usr/aarch64-linux-gnu/lib/ld-linux-aarch64.so.1 --version
apt-get clean
