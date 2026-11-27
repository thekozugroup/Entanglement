#!/bin/sh
# Serve only the two recorded release asset URLs from the mounted local archive.
set -eu
[ "$#" -eq 7 ]
[ "$1" = '-fsSL' ]
[ "$2" = '--proto' ]
[ "$3" = '=https' ]
[ "$4" = '--tlsv1.2' ]
[ "$5" = '-o' ]
url="https://github.com/thekozugroup/Entanglement/releases/download/$FIXTURE_TAG/$FIXTURE_ARCHIVE"
case "$7" in
    "$url")
        cp "/fixture/$FIXTURE_ARCHIVE" "$6"
        if [ "$FIXTURE_MODE" = corrupt ]; then
            printf 'x' >> "$6"
        fi
        ;;
    "$url.sha256")
        cp "/fixture/$FIXTURE_ARCHIVE.sha256" "$6"
        ;;
    *)
        printf 'unrecognized release fixture URL: %s\n' "$7" >&2
        exit 2
        ;;
esac
printf '%s\n' "$7" >> "$FIXTURE_REQUESTS"
