#!/bin/sh
# Install only the jump-box executable; never connects to or changes targets.
set -eu
umask 077
unset ENV BASH_ENV CDPATH
DIR=$(CDPATH= cd -P "$(dirname "$0")" && pwd)
SOURCE= BINARY=
usage() {
    cat <<'HELP'
Usage: ./coordinate/ctl install [--source DIR | --binary FILE]

Build Coordinate from its upstream GitHub repository into coordinate/bin/coordinate.
Requires git, Go 1.26.3+ and network access on this jump box only.
  --source DIR   Build an existing checkout instead of downloading the source
  --binary FILE  Install a downloaded executable instead of building (no Go needed)
  -h, --help     Show help

No sudo, OS package installations or remote connections are performed.
An existing executable is replaced only after the candidate passes its help check.
HELP
}
die() { printf 'hunter-coordinate install: %s\n' "$*" >&2; exit 1; }
while [ "$#" -gt 0 ]; do
    case $1 in
        -h|--help) usage; exit 0 ;;
        --source|--binary)
            [ "$#" -ge 2 ] && [ -n "$2" ] || die "Missing value for $1"
            if [ "$1" = --source ]; then SOURCE=$2; else BINARY=$2; fi
            shift 2 ;;
        *) die "Unknown option: $1" ;;
    esac
done
[ -z "$SOURCE" ] || [ -z "$BINARY" ] || die 'Choose --source or --binary'
if [ -n "$BINARY" ]; then
    [ -f "$BINARY" ] && [ -r "$BINARY" ] || die 'Binary is not a readable file'
    BINARY=$(CDPATH= cd -P "$(dirname "$BINARY")" && printf '%s/%s\n' "$(pwd)" "$(basename "$BINARY")")
else
    command -v go >/dev/null 2>&1 || die 'Go is missing. Install Go 1.26.3+ on the jump box, or use install --binary /path/to/downloaded/coordinate'
    if [ -n "$SOURCE" ]; then
        [ -d "$SOURCE" ] || die 'Source directory does not exist'
        SOURCE=$(CDPATH= cd -P "$SOURCE" && pwd)
        [ -f "$SOURCE/go.mod" ] && [ -d "$SOURCE/cmd" ] || die 'Source needs go.mod and cmd/'
    else
        command -v git >/dev/null 2>&1 || die 'git is required to download the source; use --source DIR or --binary FILE'
    fi
fi
for subdir in bin vendor; do
    [ ! -L "$DIR/$subdir" ] || die "Refusing symlinked install directory: $DIR/$subdir"
    mkdir -p "$DIR/$subdir"
done
LOCK=$DIR/vendor/.install-lock
mkdir "$LOCK" 2>/dev/null || die "Another install is running, or a stale lock exists: $LOCK"
WORK=
cleanup() {
    [ -z "$WORK" ] || rm -rf "$WORK"
    rmdir "$LOCK" 2>/dev/null || :
}
trap cleanup 0
trap 'exit 130' 1 2 15
WORK=$(mktemp -d "$DIR/vendor/install.XXXXXXXXXX")
if [ -n "$BINARY" ]; then
    cp "$BINARY" "$WORK/coordinate"
else
    if [ -z "$SOURCE" ]; then
        printf 'Downloading Coordinate source from GitHub...\n'
        if ! GIT_TERMINAL_PROMPT=0 git -c credential.helper= clone --depth 1 -- \
            https://github.com/Foister150/coordinate-foister.git "$WORK/source"; then
            die 'GitHub download failed. Check network/DNS, then retry ./coordinate/ctl install; offline alternatives: install --source DIR or install --binary FILE'
        fi
        SOURCE=$WORK/source
    fi
    printf 'Building Coordinate with %s...\n' "$(go version)"
    # Keep build/module caches inside the repository; avoid system-wide writes.
    if ! (
        cd "$SOURCE"
        GOTOOLCHAIN=local CGO_ENABLED=0 GOCACHE="$DIR/vendor/go-build" \
            GOMODCACHE="$DIR/vendor/go-mod" go build -mod=readonly -trimpath -o "$WORK/coordinate" ./cmd
    ); then
        die 'Build failed; the previous binary was kept. Check Go version and dependency download access, or use install --binary FILE'
    fi
fi
chmod 700 "$WORK/coordinate"
"$WORK/coordinate" --help > "$WORK/help.txt" 2>&1 || die 'Candidate executable failed --help; the previous binary was kept'
for flag in --no-rsync --transfer-timeout --sudo --download --outfile-fmt --tmpdir; do
    grep -F -e "$flag" "$WORK/help.txt" >/dev/null || die "Candidate lacks $flag; install the current upstream version"
done
[ ! -L "$DIR/bin/coordinate" ] || die 'Refusing symlinked destination executable'
mv -f "$WORK/coordinate" "$DIR/bin/coordinate"
printf 'Installed: %s/bin/coordinate\n' "$DIR"
