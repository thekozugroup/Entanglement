#!/bin/sh
set -eu
if [ "${FIXTURE_RENAME_FAILURE:-0}" = 1 ] && [ "$#" -eq 3 ] && [ "$1" = -f ]; then
    case "$2" in
        */.entangle-install.lock/new/entangled)
            printf 'fixture: controlled second publication failure\n' >&2
            exit 1
            ;;
    esac
fi
exec /usr/bin/mv "$@"
