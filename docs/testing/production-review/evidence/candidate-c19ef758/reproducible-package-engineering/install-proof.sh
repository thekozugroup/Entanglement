#!/bin/sh
set -eu

asset_dir=$1
installer=$2
stage=$(mktemp -d /tmp/ent-native-install.XXXXXX)
daemon_pid=
cleanup() {
    if [ -n "$daemon_pid" ]; then
        kill "$daemon_pid" 2>/dev/null || :
        wait "$daemon_pid" || :
    fi
    rm -rf "$stage"
}
trap cleanup 0

export HOME="$stage/home"
export XDG_CONFIG_HOME="$HOME/.config"
export XDG_RUNTIME_DIR="$stage/runtime"
export PATH="$stage/tools:/usr/bin:/bin"
export ENTANGLE_FIXTURE_ASSETS="$asset_dir"
export ENTANGLE_FIXTURE_LOG="$stage/requests"
export TOKIO_WORKER_THREADS=2 RAYON_NUM_THREADS=2
unset ENTANGLE_INSTALL_OS ENTANGLE_INSTALL_ARCH
mkdir -p "$HOME" "$stage/tools" "$XDG_RUNTIME_DIR"
cat >"$stage/tools/curl" <<'EOF'
#!/bin/sh
set -eu
[ "$#" -eq 7 ] && [ "$1" = -fsSL ] && [ "$2" = --proto ] && [ "$3" = '=https' ] &&
    [ "$4" = --tlsv1.2 ] && [ "$5" = -o ]
case "$7" in
  https://github.com/thekozugroup/Entanglement/releases/download/v0.1.0/entanglement-v0.1.0-x86_64-unknown-linux-gnu.tar.gz|https://github.com/thekozugroup/Entanglement/releases/download/v0.1.0/entanglement-v0.1.0-x86_64-unknown-linux-gnu.tar.gz.sha256)
    printf '%s\n' "$7" >>"$ENTANGLE_FIXTURE_LOG"
    cp "$ENTANGLE_FIXTURE_ASSETS/${7##*/}" "$6"
    ;;
  *) exit 3 ;;
esac
EOF
chmod 0755 "$stage/tools/curl"

cat /etc/os-release
getconf GNU_LIBC_VERSION
uname -m
sh "$installer" --version 0.1.0 --prefix "$HOME/bin"
[ "$(wc -l < "$ENTANGLE_FIXTURE_LOG")" = 2 ]
cat "$ENTANGLE_FIXTURE_LOG"

printf '%s  %s\n' \
  dfd160a6158221624db5327ae3d1c86b94f36dc018ca82821bb0912604f45e33 "$HOME/bin/entangle" \
  ae746362f564f20a6ae00d81883a4873078ad9f847684145341d57315b6fc823 "$HOME/bin/entangled" \
  | sha256sum -c -
for binary in entangle entangled; do
    actual=$("$HOME/bin/$binary" --version)
    [ "$actual" = "$binary 0.1.0" ]
    printf '%s\n' "$actual"
done

"$HOME/bin/entangle" init --non-interactive
"$HOME/bin/entangled" run >"$stage/daemon.log" 2>&1 &
daemon_pid=$!
i=0
while ! "$HOME/bin/entangle" mesh status --json >"$stage/status.json" 2>"$stage/status-error"; do
    i=$((i + 1))
    if [ "$i" -ge 80 ] || ! kill -0 "$daemon_pid" 2>/dev/null; then
        cat "$stage/status-error" "$stage/daemon.log" >&2
        exit 1
    fi
    sleep 0.1
done
test -S "$HOME/.entangle/sock"
grep -q '"local_peer_id"' "$stage/status.json"
cat "$stage/status.json"
