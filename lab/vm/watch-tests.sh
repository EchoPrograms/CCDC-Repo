#!/bin/sh
# Run only in an isolated, disposable systemd VM with the test CD mounted.
set -eu
[ "${CCDC_DISPOSABLE_VM:-}" = 1 ] || { echo 'Set CCDC_DISPOSABLE_VM=1 only inside a disposable isolated VM.' >&2; exit 1; }
[ "$(id -u)" -eq 0 ] || { echo 'Root is required.' >&2; exit 1; }
[ -d /run/systemd/system ] && command -v systemctl >/dev/null || { echo 'A running systemd guest is required.' >&2; exit 1; }
[ -f /mnt/ccdc-cd/hunter-watch.sh ] && [ -f /mnt/ccdc-cd/watchdog/ccdc-watch-tests ] && [ -f /mnt/ccdc-cd/watchdog/bin/hunter-watch-linux-amd64 ] && [ -f /mnt/ccdc-cd/watchdog/examples/services.conf ] || { echo 'Required files are missing from the mounted test CD.' >&2; exit 1; }
if [ -e /etc/systemd/system/ccdc-fixture.service ] || systemctl cat ccdc-fixture.service >/dev/null 2>&1; then
  echo 'Refusing to replace existing ccdc-fixture.service.' >&2; exit 1
fi
created=0
cleanup() {
  if [ "$created" -eq 1 ]; then
    systemctl stop ccdc-fixture.service >/dev/null 2>&1 || :
    rm -f /etc/systemd/system/ccdc-fixture.service
    systemctl daemon-reload >/dev/null 2>&1 || :
  fi
}
trap cleanup 0
trap 'exit 1' HUP INT TERM
mkdir -p /var/tmp/watch-results-final /var/tmp/watch-work-final /var/tmp/watch-fixture-final/run/systemd/system
cp -a /mnt/ccdc-cd/. /var/tmp/watch-work-final/
cd /var/tmp/watch-work-final
out=/var/tmp/watch-results-final
run() {
  name=$1; shift
  if timeout 600 "$@" > "$out/$name.log" 2>&1; then rc=0; else rc=$?; fi
  echo "$rc" > "$out/$name.exit"
  echo "WATCH TEST $name EXIT $rc" > /dev/console
}
run engine-tests env HUNTER_WATCH_TEST_VM=1 ./watchdog/ccdc-watch-tests -test.v -test.timeout=480s
chown root:root watchdog/examples/services.conf
chmod 600 watchdog/examples/services.conf
run install-fixture sh ./hunter-watch.sh install --root /var/tmp/watch-fixture-final --no-start --config watchdog/examples/services.conf
created=1
printf '[Unit]\nDescription=Disposable watchdog recovery fixture\n[Service]\nType=simple\nExecStart=/bin/sleep infinity\n' > /etc/systemd/system/ccdc-fixture.service
systemctl daemon-reload
systemctl start ccdc-fixture.service
systemctl stop ccdc-fixture.service
printf 'fixture|unit|ccdc-fixture.service|-|ccdc-fixture.service|-|auto|5|1|1|2|60\n' > /var/tmp/watch-manifest
chmod 600 /var/tmp/watch-manifest
bin=./watchdog/bin/hunter-watch-linux-amd64
run enable "$bin" enable-recovery --config /var/tmp/watch-manifest --state-dir /var/tmp/watch-state-final --log "$out/events.jsonl" --owner local
run check "$bin" check --config /var/tmp/watch-manifest --state-dir /var/tmp/watch-state-final --log "$out/events.jsonl"
run verify systemctl is-active ccdc-fixture.service
printf 'WATCH TESTS DONE\n' > /dev/console
