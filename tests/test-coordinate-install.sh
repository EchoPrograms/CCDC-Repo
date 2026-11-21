#!/bin/sh
# Mock the downloader/compiler; no network, SSH, target scripts or package changes.
set -eu
REPO=$(CDPATH= cd "$(dirname "$0")/.." && pwd)
TMP=$(mktemp -d /tmp/hunter-coordinate-install.XXXXXXXX)
trap 'rm -rf "$TMP"' 0
trap 'exit 1' 1 2 15
mkdir -p "$TMP/repo/coordinate" "$TMP/bin" "$TMP/no-go" "$TMP/source/cmd"
cp "$REPO/coordinate/ctl" "$REPO/coordinate/install.sh" "$REPO/coordinate/remote.sh" "$TMP/repo/coordinate/"
cp "$REPO/hunter-setup.sh" "$TMP/repo/"
printf 'module fixture\ngo 1.26.3\n' > "$TMP/source/go.mod"
export INSTALL_TEST_ROOT=$TMP
for util in basename cat chmod cp date dirname grep mkdir mktemp mv pwd rm rmdir sed sh tr; do
    path=$(command -v "$util")
    ln -s "$path" "$TMP/bin/$util"
    ln -s "$path" "$TMP/no-go/$util"
done
cat > "$TMP/candidate" <<'BINARY'
#!/bin/sh
if [ "${1:-}" = --help ]; then
    printf '%s\n' '--no-rsync --transfer-timeout --sudo --download --outfile-fmt --tmpdir'
else
    printf 'EXECUTED\n' >> "$INSTALL_TEST_ROOT/native-calls"
fi
BINARY
chmod +x "$TMP/candidate"
cat > "$TMP/bin/git" <<'GIT'
#!/bin/sh
printf 'git\n' >> "$INSTALL_TEST_ROOT/build-calls"
[ "${INSTALL_TEST_CLONE_FAIL:-no}" = no ] || exit 42
for arg do destination=$arg; done
mkdir -p "$destination/cmd"
printf 'module fixture\ngo 1.26.3\n' > "$destination/go.mod"
GIT
cat > "$TMP/bin/go" <<'GO'
#!/bin/sh
if [ "${1:-}" = version ]; then printf 'go version go1.27.4 linux/amd64\n'; exit 0; fi
printf 'go\n' >> "$INSTALL_TEST_ROOT/build-calls"
[ "$GOTOOLCHAIN" = local ] && [ "$CGO_ENABLED" = 0 ] || exit 51
case $GOCACHE in "$INSTALL_TEST_ROOT"/repo/coordinate/vendor/*) ;; *) exit 52 ;; esac
case $GOMODCACHE in "$INSTALL_TEST_ROOT"/repo/coordinate/vendor/*) ;; *) exit 53 ;; esac
[ "${INSTALL_TEST_BUILD_FAIL:-no}" = no ] || exit 54
output=
while [ "$#" -gt 0 ]; do
    case $1 in -o) output=$2; shift 2 ;; *) shift ;; esac
done
[ -n "$output" ] || exit 55
cp "$INSTALL_TEST_ROOT/candidate" "$output"
GO
chmod +x "$TMP/bin/git" "$TMP/bin/go"
INSTALL=$TMP/repo/coordinate/install.sh
CTL=$TMP/repo/coordinate/ctl
PATH="$TMP/bin" /bin/sh "$INSTALL" > "$TMP/install.out"
[ -x "$TMP/repo/coordinate/bin/coordinate" ]
[ "$(cat "$TMP/build-calls")" = "$(printf 'git\ngo')" ]
[ ! -e "$TMP/repo/coordinate/vendor/.install-lock" ]
cmp "$TMP/candidate" "$TMP/repo/coordinate/bin/coordinate"
printf 'PASS: source download/build installs validated binary locally and releases lock\n'

if INSTALL_TEST_CLONE_FAIL=yes PATH="$TMP/bin" /bin/sh "$INSTALL" > "$TMP/clone-fail.out" 2>&1; then exit 1; fi
cmp "$TMP/candidate" "$TMP/repo/coordinate/bin/coordinate"
[ ! -e "$TMP/repo/coordinate/vendor/.install-lock" ]
grep -F 'Check network/DNS' "$TMP/clone-fail.out" >/dev/null
if INSTALL_TEST_BUILD_FAIL=yes PATH="$TMP/bin" /bin/sh "$INSTALL" --source "$TMP/source" > "$TMP/build-fail.out" 2>&1; then exit 1; fi
cmp "$TMP/candidate" "$TMP/repo/coordinate/bin/coordinate"
[ ! -e "$TMP/repo/coordinate/vendor/.install-lock" ]
printf 'PASS: failed download/build keeps existing binary and cleans partial install\n'

printf '#!/bin/sh\nprintf "old version\\n"\n' > "$TMP/old-binary"
if PATH="$TMP/bin" /bin/sh "$INSTALL" --binary "$TMP/old-binary" > "$TMP/old.out" 2>&1; then exit 1; fi
cmp "$TMP/candidate" "$TMP/repo/coordinate/bin/coordinate"
PATH="$TMP/no-go" /bin/sh "$INSTALL" --binary "$TMP/candidate" > "$TMP/prebuilt.out"
cmp "$TMP/candidate" "$TMP/repo/coordinate/bin/coordinate"
if PATH="$TMP/no-go" /bin/sh "$INSTALL" > "$TMP/no-go.out" 2>&1; then exit 1; fi
grep -F 'Go is missing' "$TMP/no-go.out" >/dev/null
printf 'PASS: unsupported binary rejected, prebuilt install needs no Go, missing Go is actionable\n'

# Explicit ctl install delegates without requiring target/user arguments.
PATH="$TMP/no-go" /bin/sh "$CTL" install --binary "$TMP/candidate" > "$TMP/ctl-install.out"
cmp "$TMP/candidate" "$TMP/repo/coordinate/bin/coordinate"
rm "$TMP/repo/coordinate/bin/coordinate"
before=$(wc -l < "$TMP/build-calls")
PATH="$TMP/bin" /bin/sh "$CTL" setup --targets 127.0.0.1 --port 2222 --user defender \
    --prepare-only > "$TMP/prepare.out"
[ "$before" = "$(wc -l < "$TMP/build-calls")" ]
[ ! -e "$TMP/native-calls" ]
PATH="$TMP/bin" /bin/sh "$CTL" setup --targets 127.0.0.1 --port 2222 --user defender > "$TMP/bootstrap.out"
[ -x "$TMP/repo/coordinate/bin/coordinate" ]
grep -F 'installing the jump-box executable' "$TMP/bootstrap.out" >/dev/null
[ "$(wc -l < "$TMP/native-calls")" -eq 2 ]
printf 'PASS: ctl install works; prepare-only never installs; normal missing-binary run bootstraps then executes/collects\n'

before=$(wc -l < "$TMP/build-calls")
PATH="$TMP/bin" /bin/sh "$CTL" setup --targets 127.0.0.1 --port 2222 --user defender > "$TMP/reuse.out"
[ "$before" = "$(wc -l < "$TMP/build-calls")" ]
rm "$TMP/repo/coordinate/bin/coordinate"
native_before=$(wc -l < "$TMP/native-calls")
if INSTALL_TEST_CLONE_FAIL=yes PATH="$TMP/bin" /bin/sh "$CTL" setup --targets 127.0.0.1 --port 2222 --user defender > "$TMP/bootstrap-fail.out" 2>&1; then exit 1; fi
[ "$native_before" = "$(wc -l < "$TMP/native-calls")" ]
[ ! -e "$TMP/repo/coordinate/bin/coordinate" ]
[ ! -e "$TMP/repo/coordinate/vendor/.install-lock" ]
printf 'PASS: installed binary reused; failed bootstrap stops before any SSH operation\n'
