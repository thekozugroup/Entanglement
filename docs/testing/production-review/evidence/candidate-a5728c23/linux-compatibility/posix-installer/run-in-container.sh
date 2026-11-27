#!/bin/sh
set -eu
distro=$1
mode=$2
export FIXTURE_ARCHIVE=$3
canonical_cli=$4
canonical_daemon=$5
portable_cli=$6
portable_daemon=$7
umask 077
. /etc/os-release
[ "$VERSION_ID" = "$distro" ] && [ "$(id -u)" = 65534 ]
test "$(wc -l </proc/net/route)" -eq 1
work=$(mktemp -d '/work/posix checkout.XXXXXX')
export HOME="$work/isolated home" PATH="$work/tools:/usr/bin:/bin"
export RUST_LOG=error TOKIO_WORKER_THREADS=2 RAYON_NUM_THREADS=2
mkdir -p "$HOME" "$work/tools"
cp /fixture/curl-fixture.sh "$work/tools/curl"
chmod 0755 "$work/tools/curl"
prefix="$HOME/tool prefix"
cli="$prefix/bin/entangle"
daemon="$prefix/bin/entangled"
pid=
trap 'if [ -n "$pid" ]; then kill -TERM "$pid" 2>/dev/null || :; wait "$pid" || :; fi' EXIT
emit(){ printf 'OBS\t%s\t%s\n' "$1" "$2"; }
emit distro "$VERSION_ID"
emit libc "$(getconf GNU_LIBC_VERSION)"
emit uid "$(id -u)"
emit posix_shell "$(readlink -f /bin/sh)"
install_fixture(){
    FIXTURE_VARIANT=$1
    expected=$2
    label=$3
    shift 3
    FIXTURE_REQUESTS="$work/urls-$label"
    export FIXTURE_VARIANT FIXTURE_REQUESTS
    status=0
    /bin/sh /fixture/install.sh --version v0.1.0 --prefix "$prefix" "$@" >"$work/installer-$label.log" 2>&1 || status=$?
    [ "$expected" -eq "$status" ] || { cat "$work/installer-$label.log" >&2; exit 1; }
    url="https://github.com/thekozugroup/Entanglement/releases/download/v0.1.0/$FIXTURE_ARCHIVE"
    expected_urls=$(printf '%s\n%s\n' "$url" "$url.sha256")
    [ "$(cat "$FIXTURE_REQUESTS")" = "$expected_urls" ] && [ "$(wc -l <"$FIXTURE_REQUESTS")" -eq 2 ]
    [ ! -e "$prefix/bin/.entangle-install.lock" ]
    emit "$label.install_exit" "$status"
    emit "$label.request_count" "$(wc -l <"$FIXTURE_REQUESTS")"
    if [ "$status" -ne 0 ]; then
        grep -Fq 'staged entangle did not pass its version check' "$work/installer-$label.log"
        grep -Fq "GLIBC_2.39" "$work/installer-$label.log"
        emit "$label.rejection" "staged entangle version check: GLIBC_2.39 unavailable"
    fi
}
pair(){
    label=$1;expected_cli=$2;expected_daemon=$3
    cli_hash=$(sha256sum "$cli" | cut -d' ' -f1); daemon_hash=$(sha256sum "$daemon" | cut -d' ' -f1)
    [ "$cli_hash" = "$expected_cli" ] && [ "$daemon_hash" = "$expected_daemon" ] || exit 1
    emit "$label.entangle_sha256" "$cli_hash"; emit "$label.entangled_sha256" "$daemon_hash"
    cli_version=$("$cli" --version); daemon_version=$("$daemon" --version)
    [ "$cli_version" = 'entangle 0.1.0' ] && [ "$daemon_version" = 'entangled 0.1.0' ] || exit 1
    emit "$label.entangle_version" "$cli_version"; emit "$label.entangled_version" "$daemon_version"
}
working(){
    label=$1
    if [ ! -d "$HOME/signed-suite" ]; then
        "$cli" init --non-interactive >"$work/init.log"
        printf '[mesh]\ntransports=[]\n' > "$HOME/.entangle/config.toml"
        "$cli" plugins build /fixture/sample --wasm /fixture/sample/component.wasm --out "$HOME/signed-suite" >"$work/build.log"
        pub=$(sed -n 's/.*entangle keyring add \([a-f0-9]*\) --name.*/\1/p' "$work/build.log")
        [ "${#pub}" -eq 64 ]
    fi
    plugin=$(sed -n 's/^id = "\([^"]*\)".*/\1/p' "$HOME/signed-suite/entangle.toml")
    case "$plugin" in */json-pointer@0.1.0) ;; *) exit 1;; esac
    "$daemon" run >"$work/daemon-$label.log" 2>&1 & pid=$!
    n=0; while [ ! -S "$HOME/.entangle/sock" ]; do
        n=$((n+1)); [ "$n" -le 100 ] && kill -0 "$pid" || { cat "$work/daemon-$label.log" >&2; exit 1; }; sleep .05
    done
    status=$("$cli" mesh status --json)
    peer=$(printf '%s' "$status" | sed -n 's/.*"local_peer_id":[[:space:]]*"\([a-f0-9]*\)".*/\1/p')
    [ "${#peer}" -eq 32 ]
    if [ ! -f "$work/trusted" ]; then
        untrusted=0; "$cli" plugins load "$HOME/signed-suite" >"$work/denied.log" 2>&1 || untrusted=$?
        [ "$untrusted" -ne 0 ] && grep -Eiq 'trust|publisher|verification key|keyring' "$work/denied.log" || exit 1
        "$cli" keyring add "$pub" --name 'isolated installer publisher' >/dev/null
        touch "$work/trusted"
    fi
    "$cli" plugins load "$HOME/signed-suite" >"$work/loaded.log"
    nonce="ubuntu-$distro-$label"
    output=$("$cli" plugins invoke "$plugin" --input "{\"pointer\":\"/selected\",\"data\":{\"selected\":\"$nonce\",\"other\":0}}" --raw)
    [ "$output" = "\"$nonce\"" ]
    emit "$label.peer" "$peer"
    emit "$label.plugin_id" "$plugin"
    emit "$label.signature_sha256" "$(sha256sum "$HOME/signed-suite/plugin.wasm.sig" | cut -d' ' -f1)"
    emit "$label.expected_output" "\"$nonce\""
    emit "$label.actual_output" "$output"
    kill -TERM "$pid"; wait "$pid"; pid=
    emit "$label.daemon_exit" 0
}
case "$mode-$distro" in
fresh-canonical-22.04)
    install_fixture canonical 1 canonical
    [ ! -e "$cli" ] && [ ! -e "$daemon" ]
    emit canonical.empty_prefix_after_rejection yes;;
fresh-canonical-24.04)
    install_fixture canonical 0 canonical
    pair canonical "$canonical_cli" "$canonical_daemon"; working canonical;;
update-22.04|update-24.04)
    install_fixture jammy 0 portable
    pair portable "$portable_cli" "$portable_daemon"; working portable
    if [ "$distro" = 22.04 ]; then
        install_fixture canonical 1 canonical_update --force
        pair after_rejection "$portable_cli" "$portable_daemon"; working after_rejection
    else
        install_fixture canonical 0 canonical_update --force
        pair after_upgrade "$canonical_cli" "$canonical_daemon"; working after_upgrade
    fi;;
*) exit 2;;
esac
