#!/bin/sh
# Optional static Linux collector. Build on the jump box; no target compiler.
unset ENV BASH_ENV CDPATH
if [ -n "${HUNTER_ROOTKIT_COLLECTOR:-}" ]; then
    exec "$HUNTER_ROOTKIT_COLLECTOR" "$@"
fi
case $(uname -m) in
    x86_64|amd64) arch=amd64 ;; aarch64|arm64) arch=arm64 ;;
    i?86) arch=386 ;; armv7*|armv6*) arch=arm ;; *) arch=unknown ;;
esac
directory=$(CDPATH= cd -P "$(dirname "$0")" && pwd) || exit 1
collector=$directory/rootkit/bin/hunter-rootkit-linux-$arch
if [ ! -x "$collector" ]; then
    printf 'hunter-rootkit: Build the collector on the jump box: ./rootkit/build.sh %s\n' "$arch" >&2
    printf 'Copy that binary to the target, or use ./coordinate/ctl rootkit --arch %s ...\n' "$arch" >&2
    exit 1
fi
exec "$collector" "$@"
