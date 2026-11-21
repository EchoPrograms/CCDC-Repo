#!/bin/sh
# This script runs inside a disposable VM, from a read-only CD.
set -eu
umask 077
[ "${CCDC_DISPOSABLE_VM:-}" = 1 ] || { echo 'Set CCDC_DISPOSABLE_VM=1 only inside a disposable isolated VM.' >&2; exit 1; }
[ "$(id -u)" -eq 0 ] || { echo 'Root is required.' >&2; exit 1; }
[ -d /run/systemd/system ] || { echo 'A normal systemd guest is required.' >&2; exit 1; }
for file in hunter-setup.sh hunter-hunt.sh hunter-rootkit.sh hunter-harden.sh hunter-watch.sh watchdog/examples/services.conf; do
  [ -f "/mnt/ccdc-cd/$file" ] || { echo "Missing test CD file: $file" >&2; exit 1; }
done
# A slow backup is not necessarily broken. Zero allows it to finish without
# an imposed timeout; callers can choose an explicit per-command limit.
limit=${CCDC_TEST_TIMEOUT:-0}
case $limit in ''|*[!0-9]*) echo 'CCDC_TEST_TIMEOUT must be seconds (0 means unlimited).' >&2; exit 1 ;; esac
[ "$limit" = 0 ] || command -v timeout >/dev/null 2>&1 || { echo 'timeout is required for a nonzero test limit.' >&2; exit 1; }
for path in /var/tmp/ccdc-results /var/tmp/ccdc-work /var/tmp/ccdc-state /var/tmp/ccdc-watch-fixture; do
  [ ! -e "$path" ] && [ ! -L "$path" ] || { echo "Refusing to replace prior test state: $path" >&2; exit 1; }
done
mkdir /var/tmp/ccdc-results /var/tmp/ccdc-work
cp -a /mnt/ccdc-cd/. /var/tmp/ccdc-work/
cd /var/tmp/ccdc-work
out=/var/tmp/ccdc-results
failed=0
run() {
  name=$1; shift
  date -u '+%Y-%m-%dT%H:%M:%SZ' > "$out/$name.started"
  printf '%s\n' "Starting $name" > /dev/console
  if [ "$limit" = 0 ]; then
    if "$@" > "$out/$name.log" 2>&1; then code=0; else code=$?; fi
  else
    if timeout "$limit" "$@" > "$out/$name.log" 2>&1; then code=0; else code=$?; fi
  fi
  printf '%s\n' "$code" > "$out/$name.exit"
  date -u '+%Y-%m-%dT%H:%M:%SZ' > "$out/$name.finished"
  [ "$code" -eq 0 ] || failed=1
  printf '%s\n' "Finished $name: $code" > /dev/console
}
run setup sh ./hunter-setup.sh --no-install --state-dir /var/tmp/ccdc-state
run hunt sh ./hunter-hunt.sh --color never --state-dir /var/tmp/ccdc-state -o "$out/hunt-report.txt"
run rootkit sh ./hunter-rootkit.sh -color never -output "$out/rootkit-report.txt"
run harden-dry sh ./hunter-harden.sh --dry-run --state-dir /var/tmp/ccdc-state
mkdir -p "$out/setup-runs" /var/tmp/ccdc-watch-fixture/run/systemd/system
for file in /var/tmp/ccdc-state/runs/*/errors.log; do
  [ -f "$file" ] || continue
  run_dir=${file%/errors.log}
  cp "$file" "$out/setup-runs/${run_dir##*/}-errors.log"
done
chmod 600 watchdog/examples/services.conf
run watch-fixture sh ./hunter-watch.sh install --root /var/tmp/ccdc-watch-fixture --no-start --config watchdog/examples/services.conf
printf 'DONE | any_test_failed=%s\n' "$failed" > /dev/console
exit "$failed"
