#!/bin/sh
# Each test names its private symlink to select the requested status behavior.
[ "$#" -eq 2 ] && [ "$1" = status ] && [ "$2" = --json ] || exit 1
case "${0##*/}" in
    tailscale) exec cat "$0.json" ;;
    'inactive fixture') printf '%s' '{"BackendState":"NeedsLogin"}' ;;
    'failing fixture') printf '%s' '{"BackendState":"Running"}'; exit 42 ;;
    'oversized fixture') exec dd if=/dev/zero bs=1048576 count=17 ;;
    'hung fixture') exec sleep 60 ;;
    *) exit 1 ;;
esac
