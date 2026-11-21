#!/bin/sh
# Local checks require no Docker daemon, root, network, or Python.
set -eu
REPO=$(CDPATH= cd "$(dirname "$0")/.." && pwd)
LAB="$REPO/lab/alpine"
TMP=$(mktemp -d "${TMPDIR:-/tmp}/ccdc-alpine-test.XXXXXXXX")
trap 'rm -rf "$TMP"' 0
trap 'exit 1' 1 2 15
for script in "$LAB"/*.sh "$LAB/ctl" "$REPO/ccdc-hunt.sh"; do sh -n "$script"; done
"$LAB/ctl" config --quiet
printf 'PASS: Compose model and shell syntax\n'
if command -v php >/dev/null 2>&1; then
    "$LAB/ctl" config --format json > "$TMP/compose.json"
    php -r '
        $c = json_decode(file_get_contents($argv[1]), true, 512, JSON_THROW_ON_ERROR);
        $t = $c["services"]["target"]; $g = $c["services"]["gateway"];
        $checks = [
            array_keys($t["networks"]) === ["practice"],
            empty($t["ports"]),
            $c["networks"]["practice"]["internal"] === true,
            empty($c["networks"]["access"]["internal"]),
            array_key_exists("practice", $g["networks"]) && array_key_exists("access", $g["networks"]),
            count($g["ports"]) === 2,
            empty($t["volumes"]) && empty($g["volumes"]),
            $g["read_only"] === true && $g["user"] === "65534:65534",
            in_array("ALL", $g["cap_drop"], true),
            (string)$g["sysctls"]["net.ipv4.ip_forward"] === "0",
        ];
        foreach ($g["ports"] as $port) $checks[] = $port["host_ip"] === "127.0.0.1";
        if (in_array(false, $checks, true)) {fwrite(STDERR, "Unsafe or unpublishable lab network topology\n"); exit(1);}
    ' "$TMP/compose.json"
    printf 'PASS: isolated target and restricted gateway own valid localhost publications\n'
fi
if command -v cc >/dev/null 2>&1; then
    cc -Wall -Wextra -Werror -fsyntax-only "$LAB/preload.c" "$LAB/diagnostic.c" "$LAB/sleeper.c"
    printf 'PASS: all C sources pass strict compiler checks\n'
fi
# Never run the seeder against the host. Check its refusal before any mutation.
if CCDC_LAB_SEED=disabled sh "$LAB/seed.sh" > "$TMP/guard" 2>&1; then
    printf 'FAIL: seeder accepted a non-lab invocation\n' >&2; exit 1
fi
grep 'Refusing to seed' "$TMP/guard" > /dev/null
# Extract the exact planted files from the recipe as inert data into a fake root.
ROOT="$TMP/fixture"
mkdir -p "$ROOT/etc/sudoers.d" "$ROOT/root" "$ROOT/home/defender" "$ROOT/var/log" "$ROOT/tmp/.cache"
awk '/^cat > \// && /<<.*PAYLOAD/ {print $3}' "$LAB/seed.sh" > "$TMP/targets"
while IFS= read -r target; do mkdir -p "$ROOT$(dirname "$target")"; done < "$TMP/targets"
awk -v prefix="$ROOT" '
    /^cat > \// && /<<.*PAYLOAD/ {out=prefix $3; capture=1; next}
    capture && $0=="PAYLOAD" {close(out); capture=0; next}
    capture {print > out}' "$LAB/seed.sh"
cat > "$ROOT/etc/passwd" <<'DATA'
root:x:0:0:root:/root:/bin/sh
backupsvc:x:0:0:Backup service:/root:/bin/bash
defender:x:1000:1000:Defender:/home/defender:/bin/bash
DATA
printf 'sudo:x:1000:defender\n' > "$ROOT/etc/group"
printf '/tmp/.cache/libaudit.so\n' > "$ROOT/etc/ld.so.preload"
printf 'support ALL=(ALL) NOPASSWD: ALL\n' > "$ROOT/etc/sudoers.d/90-support"
printf 'LAB FIXTURE: diamorphine marker\n' > "$ROOT/var/log/kern.log"
if command -v php >/dev/null 2>&1; then
    for webfile in "$ROOT/var/www/html/assets/cache.php" "$ROOT/var/www/html/uploads/preview.php" "$ROOT/opt/customer/public/debug.php"; do php -l "$webfile" > /dev/null; done
    printf 'PASS: actual planted PHP files pass syntax checks without execution\n'
fi
sh "$REPO/ccdc-hunt.sh" --root "$ROOT" --web-root /opt/customer/public \
    -o "$TMP/scan.txt" > "$TMP/scan.stdout" 2> "$TMP/scan.stderr"
for title in 'Additional UID 0' 'Alias overrides' 'PAM sufficient unconditional' \
    'PAM executes an external' 'APT command hook' 'System-wide dynamic loader preload' \
    'Reverse shell or network-to-command' 'Kernel log contains' 'Web request input'; do
    grep -F "$title" "$TMP/scan.stdout" > /dev/null || { printf 'FAIL: missing %s\n' "$title" >&2; exit 1; }
done
for location in '/etc/rc.local' '/etc/update-motd.d/97-session' '/etc/systemd/system/cache-sync.service' '/opt/customer/public/debug.php'; do
    grep -F "$location" "$TMP/scan.stdout" > /dev/null || { printf 'FAIL: no alert for %s\n' "$location" >&2; exit 1; }
done
printf 'PASS: hunter detects actual planted config files in an offline fixture\n'
# Grade a representative report covering all manifest cases. Inventory-only
# results must never be counted as alerts; expected misses remain visible.
{
    printf 'CCDC persistence triage — COMPLETED\n'
    awk -F '\t' '$1 !~ /^#/ && $4 ~ /^(alert|baseline)$/ {
        print "[HIGH] " $7; print "  Location: " $6 ":1"; print "  Evidence: synthetic grader test"; print ""
    }' "$LAB/scenarios.tsv"
    printf 'DETAILED EVIDENCE\n--- CRON /var/spool/cron/crontabs/support ---\n'
} > "$TMP/grader-report"
printf 'ACL=unsupported\n' > "$TMP/status"
sh "$LAB/grade.sh" "$TMP/grader-report" default "$TMP/status" > "$TMP/grade-default"
grep -E '^CRON02[[:space:]]+active[[:space:]]+INVENTORY_ONLY' "$TMP/grade-default" > /dev/null
grep -E '^APK01[[:space:]]+active[[:space:]]+NO_HIT' "$TMP/grade-default" > /dev/null
grep -E '^WEB03[[:space:]]+active[[:space:]]+NO_HIT' "$TMP/grade-default" > /dev/null
grep -E '^ACL01[[:space:]]+active[[:space:]]+SKIPPED' "$TMP/grade-default" > /dev/null
# The custom profile must fail until the custom-root alert is present.
if sh "$LAB/grade.sh" "$TMP/grader-report" custom "$TMP/status" > "$TMP/grade-custom-missing"; then
    printf 'FAIL: grader accepted a missing custom-root alert\n' >&2; exit 1
fi
awk '/^DETAILED EVIDENCE/ {print "[HIGH] Web request input"; print "  Location: /opt/customer/public/debug.php:1"; print ""} {print}' \
    "$TMP/grader-report" > "$TMP/grader-custom-report"
sh "$LAB/grade.sh" "$TMP/grader-custom-report" custom "$TMP/status" > "$TMP/grade-custom"
# Delete an expected alert but leave its location in detailed inventory.
awk '/^\[HIGH\] Additional UID 0/ {skip=1} skip && /^$/ {skip=0; next} !skip {print}' "$TMP/grader-report" > "$TMP/grader-missing"
printf '\n--- /etc/passwd ---\n' >> "$TMP/grader-missing"
if sh "$LAB/grade.sh" "$TMP/grader-missing" default "$TMP/status" > "$TMP/grade-missing"; then
    printf 'FAIL: grader counted inventory as a finding\n' >&2; exit 1
fi
printf 'PASS: grader distinguishes alerts, inventory, baseline, skips and known misses\n'
BUSYBOX=
if command -v busybox >/dev/null 2>&1; then BUSYBOX=$(command -v busybox);
elif [ -x /usr/lib/initcpio/busybox ]; then BUSYBOX=/usr/lib/initcpio/busybox; fi
if [ -n "$BUSYBOX" ]; then
    "$BUSYBOX" sh "$REPO/ccdc-hunt.sh" --root "$ROOT" --web-root /opt/customer/public \
        -o "$TMP/busybox-scan.txt" > "$TMP/busybox.stdout" 2> "$TMP/busybox.stderr"
    grep 'PAM sufficient unconditional' "$TMP/busybox.stdout" > /dev/null
    printf 'PASS: BusyBox ash runs the collector on planted config fixtures\n'
    # Execute the real process-collection block with this BusyBox ps. Minimal
    # builds reject -e/-o; the collector should still obtain a basic process list.
    mkdir "$TMP/bin" "$TMP/ps-work"
    ln -s "$BUSYBOX" "$TMP/bin/ps"
    ln -s "$(command -v sh)" "$TMP/bin/sh"
    ln -s "$(command -v cat)" "$TMP/bin/cat"
    awk '/^    if ps -e -o / {capture=1} capture {print}
        capture && /^    clean_text < "\$WORK\/processes"/ {exit}' "$REPO/hunter-hunt.sh" > "$TMP/ps-block"
    WORK="$TMP/ps-work" PS_BLOCK="$TMP/ps-block" PATH="$TMP/bin" sh -c '
        note() { printf "%s: %s\n" "$1" "$2" >> "$WORK/coverage"; }
        clean_text() { cat; }
        : > "$WORK/evidence"
        . "$PS_BLOCK"
        [ -s "$WORK/processes" ]
        [ ! -s "$WORK/errors" ]
    '
    printf 'PASS: real BusyBox process collection including minimal-flag fallback\n'
fi
printf 'Local lab checks passed. Build, SSH and live implant tests still require Docker: ./lab/alpine/ctl up && ./lab/alpine/ctl test\n'
