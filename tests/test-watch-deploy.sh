#!/bin/sh
set -eu
ROOT=$(CDPATH= cd -P "$(dirname "$0")/.." && pwd)
T=$(mktemp -d /tmp/hunter-watch-test.XXXXXXXX)
trap 'rm -rf "$T"' 0
mkdir -p "$T/repo/coordinate" "$T/repo/watchdog/bin" "$T/out"
cp "$ROOT/coordinate/ctl" "$ROOT/coordinate/remote.sh" "$T/repo/coordinate/"
cp "$ROOT/hunter-watch.sh" "$T/repo/"
printf '#!/bin/sh\nexit 0\n' > "$T/repo/watchdog/bin/hunter-watch-linux-amd64"
chmod 700 "$T/repo/watchdog/bin/hunter-watch-linux-amd64"
printf 'example|tcp|127.0.0.1:80|-|-|-|alert|5|3|60|3|3600\n' > "$T/config"
chmod 600 "$T/config"
sh "$T/repo/coordinate/ctl" watch --targets example --user test --watch-config "$T/config" --output-dir "$T/out" --prepare-only -- install > "$T/result"
payload=$(sed -n 's/^Prepared only; no SSH connections. Review: //p' "$T/result")
[ -f "$payload" ]
sh -n "$payload"
grep -q 'write_watch_config()' "$payload"
grep -q 'write_watch_collector()' "$payload"
if sh "$T/repo/coordinate/ctl" watch --targets example --user test --output-dir "$T/out" --prepare-only -- install >/dev/null 2>&1; then exit 1; fi
if sh "$T/repo/coordinate/ctl" watch --targets example --user test --output-dir "$T/out" --prepare-only -- enable-recovery --owner invalid >/dev/null 2>&1; then exit 1; fi
printf 'PASS: watch payload embeds helper and manifest; invalid requests rejected\n'
if [ "$(id -u)" != 0 ]; then
    printf 'SKIP: root-only fixture installation tests (run as root)\n'
    exit 0
fi
mkdir -p "$T/fixture/run/systemd/system" "$T/fixture/etc/systemd/system"
HUNTER_WATCH_COLLECTOR="$T/repo/watchdog/bin/hunter-watch-linux-amd64" sh "$ROOT/hunter-watch.sh" install --root "$T/fixture" --config "$T/config"
[ -x "$T/fixture/usr/local/libexec/hunter-watch" ]
[ -f "$T/fixture/etc/hunter-watch/services.conf" ]
[ -f "$T/fixture/etc/systemd/system/hunter-watch.timer" ]
grep -qx 'TimeoutStartSec=0' "$T/fixture/etc/systemd/system/hunter-watch.service"
grep -qx 'OnUnitInactiveSec=30s' "$T/fixture/etc/systemd/system/hunter-watch.timer"
[ ! -e "$T/fixture/.x86/watchdog/recovery-owner" ]
printf 'PASS: fixture installs monitor without recovery switch\n'

mkdir -p "$T/openrc/run/openrc"
: > "$T/openrc/run/openrc/softlevel"
HUNTER_WATCH_COLLECTOR="$T/repo/watchdog/bin/hunter-watch-linux-amd64" sh "$ROOT/hunter-watch.sh" install --root "$T/openrc" --config "$T/config"
grep -q 'supervisor=supervise-daemon' "$T/openrc/etc/init.d/hunter-watch"
grep -q 'watch --interval 30' "$T/openrc/etc/init.d/hunter-watch"
mkdir -p "$T/cron"
HUNTER_WATCH_COLLECTOR="$T/repo/watchdog/bin/hunter-watch-linux-amd64" sh "$ROOT/hunter-watch.sh" install --root "$T/cron" --config "$T/config"
grep -q '^\* \* \* \* \* /usr/local/libexec/hunter-watch check' "$T/cron/etc/hunter-watch/cron.example"
printf 'PASS: OpenRC and cron fixture scheduler selection and contents\n'
