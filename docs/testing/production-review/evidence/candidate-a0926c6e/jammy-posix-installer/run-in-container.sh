#!/bin/sh
set -eu
expected_version=$1
FIXTURE_TAG=$2
FIXTURE_ARCHIVE=$3
entangle_sha256=$4
entangled_sha256=$5
export FIXTURE_TAG FIXTURE_ARCHIVE
unset PREFIX ENTANGLE_INSTALL_OS ENTANGLE_INSTALL_ARCH
. /etc/os-release
[ "$VERSION_ID" = "$expected_version" ]
[ "$(id -u)" -ne 0 ]
[ "$(uname -m)" = x86_64 ]
cat /etc/os-release
id
readlink /bin/sh
ldd --version
test "$(wc -l </proc/net/route)" -eq 1
work=$(mktemp -d '/tmp/entangle install.XXXXXX')
trap 'rm -rf "$work"' EXIT
export HOME="$work/home" PATH="$work/bin:/usr/bin:/bin"
mkdir -p "$HOME" "$work/bin"
cp /fixture/curl-fixture.sh "$work/bin/curl"
chmod 0755 "$work/bin/curl"

for FIXTURE_MODE in positive corrupt; do
    FIXTURE_REQUESTS="$work/$FIXTURE_MODE.urls"
    export FIXTURE_MODE FIXTURE_REQUESTS
    prefix="$HOME/$FIXTURE_MODE installation"
    printf '\nInstaller case %s\n' "$FIXTURE_MODE"
    status=0
    /bin/sh /fixture/install.sh --version "$FIXTURE_TAG" --prefix "$prefix" > "$work/install.log" 2>&1 || status=$?
    cat "$work/install.log"
    printf 'exit = %s\n' "$status"
    cat "$FIXTURE_REQUESTS"
    url="https://github.com/thekozugroup/Entanglement/releases/download/$FIXTURE_TAG/$FIXTURE_ARCHIVE"
    [ "$(wc -l <"$FIXTURE_REQUESTS")" -eq 2 ]
    [ "$(grep -Fc -x "$url" "$FIXTURE_REQUESTS")" -eq 1 ]
    [ "$(grep -Fc -x "$url.sha256" "$FIXTURE_REQUESTS")" -eq 1 ]
    if [ "$FIXTURE_MODE" = positive ]; then
        [ "$status" -eq 0 ]
        [ "$(sha256sum "$prefix/bin/entangle" | awk '{ print $1 }')" = "$entangle_sha256" ]
        [ "$(sha256sum "$prefix/bin/entangled" | awk '{ print $1 }')" = "$entangled_sha256" ]
        sha256sum "$prefix/bin/entangle" "$prefix/bin/entangled"
        "$prefix/bin/entangle" --version
        "$prefix/bin/entangled" --version
    else
        [ "$status" -eq 1 ]
        grep -Fq 'SHA-256 MISMATCH' "$work/install.log"
        [ ! -e "$prefix/bin/entangle" ]
        [ ! -e "$prefix/bin/entangled" ]
    fi
done
printf '\nBoth archive-integrity checks passed.\n'
