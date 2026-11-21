#!/bin/sh
# Standard library only. No network or target compiler required.
set -eu
umask 077
DIR=$(CDPATH= cd -P "$(dirname "$0")" && pwd)
if [ "${1:-}" = --help ]; then
    printf 'Usage: ./watchdog/build.sh [amd64|arm64|386|arm] (default: jump-box architecture)\n'
    exit 0
fi
[ "$#" -le 1 ] || { printf 'Specify one architecture\n' >&2; exit 2; }
command -v go >/dev/null 2>&1 || { printf 'Install Go on the jump box to build the static collector.\n' >&2; exit 1; }
arch=${1:-$(go env GOARCH)}
case $arch in amd64|arm64|386|arm) ;; *) printf 'Unsupported architecture: %s\n' "$arch" >&2; exit 2 ;; esac
for subdir in bin .cache; do
    [ ! -L "$DIR/$subdir" ] || { printf 'Refusing symlinked build directory\n' >&2; exit 1; }
    mkdir -p "$DIR/$subdir"
done
WORK=$(mktemp -d "$DIR/.cache/build.XXXXXXXXXX")
trap 'rm -rf "$WORK"' 0
trap 'exit 1' 1 2 15
export CGO_ENABLED=0 GO111MODULE=off GOTOOLCHAIN=local
export GOCACHE=$DIR/.cache/go-build
GOOS=linux GOARCH=$arch GOARM=6 go build -trimpath -ldflags '-s -w' -o "$WORK/collector" "$DIR/watch.go"
# Check the ELF itself on the jump box, including cross-compiled executables.
go run "$DIR/../rootkit/verify-static.go" "$WORK/collector"
chmod 700 "$WORK/collector"
destination=$DIR/bin/hunter-watch-linux-$arch
[ ! -L "$destination" ] || { printf 'Refusing symlinked output\n' >&2; exit 1; }
mv -f "$WORK/collector" "$destination"
cksum < "$DIR/watch.go" > "$destination.source"
printf 'Built static collector: %s\n' "$destination"
