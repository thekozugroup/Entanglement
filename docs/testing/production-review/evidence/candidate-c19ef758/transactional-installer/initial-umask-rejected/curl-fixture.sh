#!/bin/sh
set -eu
[ "$#" -eq 7 ]
[ "$1" = -fsSL ] && [ "$2" = --proto ] && [ "$3" = =https ]
[ "$4" = --tlsv1.2 ] && [ "$5" = -o ]
url="https://github.com/thekozugroup/Entanglement/releases/download/v0.1.0/$FIXTURE_ARCHIVE"
case "$FIXTURE_VARIANT" in
    jammy|canonical|missing-checksum|malformed-checksum|bad-checksum|missing-daemon) ;;
    *) exit 2 ;;
esac
case "$7" in
    "$url"|"$url.sha256") ;;
    *) exit 2 ;;
esac
printf '%s\n' "$7" >> "$FIXTURE_REQUESTS"
exec cp "/fixture/$FIXTURE_VARIANT/${7##*/}" "$6"
