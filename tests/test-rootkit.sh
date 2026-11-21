#!/bin/sh
# All changes stay in fixtures; never change a real loader or kernel control.
set -eu
REPO=$(CDPATH= cd "$(dirname "$0")/.." && pwd)
TMP=$(mktemp -d /tmp/hunter-rootkit-test.XXXXXXXX)
trap 'rm -rf "$TMP"' 0
trap 'exit 1' 1 2 15
export GO111MODULE=off CGO_ENABLED=0 GOTOOLCHAIN=local GOCACHE=$REPO/rootkit/.cache/go-build
go test "$REPO/rootkit/collector.go" "$REPO/rootkit/collector_test.go"
printf 'PASS: multiple implants, module comparisons, env redaction, offline boundaries, exact removal, dry-run, private records and phase guards\n'
"$REPO/rootkit/build.sh" amd64 > "$TMP/build.out"
BIN=$REPO/rootkit/bin/hunter-rootkit-linux-amd64
ROOT=$TMP/root
mkdir -p "$ROOT/etc/modprobe.d" "$ROOT/opt" "$ROOT/proc/sys/kernel" "$ROOT/sys/module/hidden/initstate-placeholder" "$ROOT/proc/42"
printf '/opt/a.so /opt/b.so\n' > "$ROOT/etc/ld.so.preload"
printf 'one\n' > "$ROOT/opt/a.so"
printf 'two\n' > "$ROOT/opt/b.so"
printf 'install shortcut /sbin/insmod /opt/a.ko\n' > "$ROOT/etc/modprobe.d/hidden.conf"
printf 'normal 1 0 - Live 0\n' > "$ROOT/proc/modules"
printf 'live\n' > "$ROOT/sys/module/hidden/initstate"
printf '0\n' > "$ROOT/proc/sys/kernel/modules_disabled"
printf '1000-2000 r-xp 0 00:00 0 /opt/a.so\n' > "$ROOT/proc/42/maps"
printf 'LD_AUDIT=/opt/b.so\000SECRET=NEVER_PRINT\000' > "$ROOT/proc/42/environ"
"$BIN" --root "$ROOT" --output "$TMP/report.txt" --color always > "$TMP/stdout"
grep -F '[CRITICAL] Loadable module absent' "$TMP/report.txt" >/dev/null
grep -F 'Process still maps a system preload library' "$TMP/report.txt" >/dev/null
grep -F 'modprobe override' "$TMP/report.txt" >/dev/null
[ "$(stat -c %a "$TMP/report.txt")" = 600 ]
esc=$(printf '\033')
grep -F "$esc[1;91m" "$TMP/stdout" >/dev/null
if grep -E 'NEVER_PRINT' "$TMP/report.txt" || grep -F "$esc" "$TMP/report.txt";then exit 1;fi
awk '/^CHECK COVERAGE/{exit} /^\[/{r=($0~/^\[CRITICAL\]/?1:$0~/^\[HIGH\]/?2:3);if(r<prev)exit 1;prev=r;n++} END{if(!n)exit 1}' "$TMP/report.txt"
if "$BIN" --root "$ROOT" --output "$TMP/report.txt" >/dev/null 2>&1;then exit 1;fi
ln -s "$TMP/victim" "$TMP/link.txt"
if "$BIN" --root "$ROOT" --output "$TMP/link.txt" >/dev/null 2>&1;then exit 1;fi
[ ! -e "$TMP/victim" ]
printf 'PASS: real static binary, severity/color, private report, no overwrite or output symlink following\n'

"$BIN" --root "$ROOT" --userspace-only --output "$TMP/userspace.txt" > "$TMP/userspace.stdout"
grep -F 'kernel module checks skipped' "$TMP/userspace.txt" >/dev/null
grep -F '/opt/a.so' "$TMP/userspace.txt" >/dev/null
if grep -F 'Loadable module absent' "$TMP/userspace.txt";then exit 1;fi
printf 'PASS: userspace-only scan retains preload detections and skips kernel module inventory\n'

# Harmless constructor shows that libc loads the library, but this collector does not.
if command -v cc >/dev/null 2>&1;then
    cat > "$TMP/marker.c" <<'C'
#include <stdio.h>
#include <stdlib.h>
__attribute__((constructor)) static void mark(void) {
    const char *p = getenv("HUNTER_TEST_MARKER");
    if (p != NULL) { FILE *f = fopen(p, "w"); if (f != NULL) { fputs("loaded", f); fclose(f); } }
}
C
    cc -Wall -Wextra -Werror -fPIC -shared "$TMP/marker.c" -o "$TMP/marker.so"
    LD_PRELOAD="$TMP/marker.so" HUNTER_TEST_MARKER="$TMP/marker" /bin/sh -c ':'
    [ -s "$TMP/marker" ]
    rm "$TMP/marker"
    LD_PRELOAD="$TMP/marker.so" HUNTER_TEST_MARKER="$TMP/marker" "$BIN" --root "$ROOT" --output "$TMP/static-report.txt" > "$TMP/static-stdout"
    [ ! -e "$TMP/marker" ]
    grep -F '/opt/b.so' "$TMP/static-report.txt" >/dev/null
    printf 'PASS: LD_PRELOAD constructor runs in dynamic shell but never loads into the static collector\n'
fi

"$REPO/coordinate/ctl" rootkit --targets 192.0.2.10 --user defender --prepare-only --output-dir "$TMP/runs" -- --userspace-only > "$TMP/prepared"
PAYLOAD=$(sed -n 's/^Local run: //p' "$TMP/prepared")/payload.sh
sh -n "$PAYLOAD"
# Extract only the binary heredoc as inert data; no generated payload execution.
awk '/^write_collector\(\)/{start=1;next} start && /^base64 -d <<\047/{copy=1;next} copy && /^HUNTER_SCRIPT_.*_BINARY$/{exit} copy{print}' "$PAYLOAD" | base64 -d > "$TMP/extracted"
cmp "$BIN" "$TMP/extracted"
if "$REPO/coordinate/ctl" setup --targets 192.0.2.10 --user defender --prepare-only -- --apply > "$TMP/rejected" 2>&1;then exit 1;fi
printf 'PASS: Coordinate embeds exact collector bytes; setup rejects rootkit containment flags\n'
