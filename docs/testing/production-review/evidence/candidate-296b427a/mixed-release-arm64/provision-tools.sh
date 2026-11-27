#!/bin/sh
# Use authenticated Debian packages in an isolated build container.
set -eu
export LC_ALL=C DEBIAN_FRONTEND=noninteractive
test -d /export
apt-get -o Acquire::Retries=2 update
mkdir -p /export/fs /tmp/entangle-debs
chmod 0755 /export/fs /tmp/entangle-debs
cd /tmp/entangle-debs
for package in qemu-user libc6-arm64-cross libgcc-s1-arm64-cross libstdc++6-arm64-cross; do
    apt-get download "$package"
    set -- "${package}_"*.deb
    test "$#" -eq 1 && test -f "$1"
    version="$(dpkg-deb -f "$1" Version)"
    digest="$(sha256sum "$1" | cut -d ' ' -f1)"
    printf '%s %s %s\n' "$package" "$version" "$digest" | tee -a /export/packages.txt
    apt-cache show "$package=$version" | grep -Fqx "SHA256: $digest"
    if [ "$package" = qemu-user ]; then
        dpkg-deb --fsys-tarfile "$1" | tar -xOf - ./usr/bin/qemu-aarch64 > /export/qemu-aarch64
        chmod 0755 /export/qemu-aarch64
    else
        dpkg-deb -x "$1" /export/fs
    fi
done
test -e /export/fs/usr/aarch64-linux-gnu/lib/ld-linux-aarch64.so.1
sha256sum /usr/share/keyrings/debian-archive-keyring.gpg /export/qemu-aarch64
/export/qemu-aarch64 --version
/export/qemu-aarch64 -L /export/fs/usr/aarch64-linux-gnu \
    /export/fs/usr/aarch64-linux-gnu/lib/ld-linux-aarch64.so.1 --version
