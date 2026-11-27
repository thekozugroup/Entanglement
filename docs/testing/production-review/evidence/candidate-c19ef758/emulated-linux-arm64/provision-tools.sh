#!/bin/sh
set -eu
export LC_ALL=C DEBIAN_FRONTEND=noninteractive
apt-get -o Acquire::Retries=2 update
apt-get -s install --no-install-recommends gcc-aarch64-linux-gnu g++-aarch64-linux-gnu libc6-dev-arm64-cross git make perl pkg-config cmake > /tmp/plan.txt
cat /tmp/plan.txt
# apt verifies package hashes against signed repository Release metadata.
apt-get install -y --no-install-recommends gcc-aarch64-linux-gnu g++-aarch64-linux-gnu libc6-dev-arm64-cross git make perl pkg-config
mkdir -p /private/qemu
cd /private/qemu
apt-get download qemu-user
apt-cache show qemu-user | sed -n '/^Package:/p;/^Version:/p;/^Filename:/p;/^SHA256:/p;/^Size:/p' > /tmp/qemu-debian-index.txt
cat /tmp/qemu-debian-index.txt
sha256sum qemu-user_*.deb
release_sha=$(sha256sum qemu-user_*.deb | cut -d' ' -f1)
grep -Fqx "SHA256: $release_sha" /tmp/qemu-debian-index.txt
# Extract one emulator from the authenticated package without maintainer scripts or binfmt registration.
dpkg-deb --fsys-tarfile qemu-user_*.deb | tar -xOf - ./usr/bin/qemu-aarch64 > qemu-aarch64
chmod 0755 qemu-aarch64
./qemu-aarch64 --version
sha256sum qemu-aarch64
rm qemu-user_*.deb
apt-get clean
rm -rf /var/lib/apt/lists/*
aarch64-linux-gnu-gcc -v
rustc -Vv
cargo -Vv
sha256sum "$(rustc --print sysroot)/bin/rustc" "$(rustc --print sysroot)/bin/cargo"
sha256sum /usr/share/keyrings/debian-archive-keyring.gpg
command -v pkg-config make git perl gcc g++ aarch64-linux-gnu-g++ aarch64-linux-gnu-ar
command -v cmake || true
cat /etc/os-release
