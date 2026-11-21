#!/bin/sh
# Exercise the controller and generated remote payload with fake hunter scripts.
# No SSH, package manager, live hunter, setup, or hardener runs in these fixtures.
set -eu
REPO=$(CDPATH= cd "$(dirname "$0")/.." && pwd)
TMP=$(mktemp -d /tmp/hunter-coordinate-test.XXXXXXXX)
cleanup() {
    if [ -f "$TMP/remotes" ]; then
        while IFS= read -r remote; do
            case $remote in /tmp/hunter-coordinate-setup-*|/tmp/hunter-coordinate-hunt-*|/tmp/hunter-coordinate-harden-*|/tmp/hunter-coordinate-rootkit-*) rm -rf "$remote" ;; esac
        done < "$TMP/remotes"
    fi
    rm -rf "$TMP"
}
trap cleanup 0
trap 'exit 1' 1 2 15
mkdir -p "$TMP/repo/coordinate" "$TMP/bin" "$TMP/runs"
cp "$REPO/coordinate/ctl" "$REPO/coordinate/remote.sh" "$TMP/repo/coordinate/"
CTL=$TMP/repo/coordinate/ctl
export MOCK_ROOT=$TMP
export MOCK_UID=$(id -u) MOCK_GID=$(id -g)
for util in awk base64 cat chmod chown date dd kill mkdir rm sed tail uname; do
    path=$(command -v "$util"); ln -s "$path" "$TMP/bin/$util"
done
# Only the generated fixture payload sees this root identity.
printf '#!/bin/sh\nprintf "0\\n"\n' > "$TMP/bin/id"
chmod +x "$TMP/bin/id"
for phase in setup hunt rootkit harden; do
    {
        printf '#!/bin/sh\n# IMPL_%s\nselected=%s\nprintf "selected=%s\\n" >> "$MOCK_ROOT/phases"\n' "$phase" "$phase" "$phase"
        cat <<'FAKE'
output= state=
printf 'received arguments:\n'
while [ "$#" -gt 0 ]; do
    printf '<%s>\n' "$1"
    if [ "$1" = --output ]; then output=$2; fi
    if [ "$1" = --state-dir ]; then state=$2; fi
    shift
done
if [ "${MOCK_RECORDS:-no}" = yes ]; then
    case $state in "$MOCK_ROOT"/state*) ;; *) exit 94 ;; esac
    record_id=20261119T000000Z-4242
    if [ "$selected" = setup ]; then
        record=$state/runs/$record_id
        printf 'Run %s | distro fixture | package manager fixture\n' "$record_id"
    else
        record=$state/hardening/$record_id
        printf 'Record: %s/harden.log\n' "$record"
    fi
    mkdir -p "$record"
    printf 'PACKAGE_DETAIL_ONLY_IN_LOG\n' > "$record/$selected.log"
    printf 'DETAIL_ERROR_ONLY_IN_LOG\n' > "$record/errors.log"
    printf 'HASH_MANIFEST\n' > "$record/manifest.sha256"
    printf 'CAPACITY_DETAIL\n' > "$record/backup-capacity.txt"
    chmod 640 "$record/$selected.log"
    if [ "${MOCK_SCRIPT_RC:-0}" = 0 ]; then : > "$record/COMPLETE"; else : > "$record/PARTIAL"; fi
fi
if [ -n "$output" ]; then
    {
        printf 'CCDC fixture report\nCRITICAL=1 HIGH=1 MEDIUM=0 LOW=0 INFO=0\n'
        printf '[CRITICAL] Fixture implant\n  Action: remove fixture persistence\n'
        printf '[HIGH] Fixture key\n  Action: review fixture keys\nCHECK COVERAGE\n'
        # Exceeds Coordinate's capture limit: it must travel as a file.
        dd if=/dev/zero bs=1048576 count=2 2>/dev/null | tr '\000' X
        printf '\nEND_OF_COMPLETE_REPORT\n'
    } > "$output"
fi
printf 'phase finished\n'
if [ "$selected" = rootkit ]; then
    printf 'POST-CLEANUP RECHECK: selected preload tokens still present=0\nCRITICAL=0 HIGH=1 MEDIUM=0 LOW=0 INFO=0\n[HIGH] CURRENT_ROOTKIT_VIEW\n  Action: inspect remaining mappings\nCHECK COVERAGE\n'
fi
printf 'fixture diagnostics\n' >&2
exit "${MOCK_SCRIPT_RC:-0}"
FAKE
    } > "$TMP/repo/hunter-$phase.sh"
done
mkdir -p "$TMP/repo/rootkit/bin"
cp "$TMP/repo/hunter-rootkit.sh" "$TMP/repo/rootkit/bin/hunter-rootkit-linux-amd64"
chmod +x "$TMP/repo/rootkit/bin/hunter-rootkit-linux-amd64"
cat > "$TMP/repo/hunter-rootkit.sh" <<'ROOTKIT'
#!/bin/sh
# IMPL_rootkit
exec "$HUNTER_ROOTKIT_COLLECTOR" "$@"
ROOTKIT
# Utilities needed by the fake hunter, not by real target programs.
ln -s "$(command -v tr)" "$TMP/bin/tr"
cat > "$TMP/coordinate" <<'MOCK'
#!/bin/sh
set -eu
if [ "${1:-}" = --help ]; then
    if [ "${MOCK_OLD:-no}" = yes ]; then printf '%s\n' '--sudo'; exit 0; fi
    printf '%s\n' '--no-rsync --transfer-timeout --sudo --download --outfile-fmt --tmpdir'
    exit 0
fi
printf 'CALL\n' >> "$MOCK_ROOT/calls"
payload= download= sudo=no no_rsync=no use_config=no limit=
while [ "$#" -gt 0 ]; do
    printf '<%s>\n' "$1" >> "$MOCK_ROOT/calls"
    case $1 in
        --targets|--usernames|--port|--max-hosts|--timeout|--transfer-timeout|--tmpdir|--outfile-fmt)
            printf '<%s>\n' "$2" >> "$MOCK_ROOT/calls"; shift 2 ;;
        --limit) limit=$2; shift 2 ;;
        --download) download=$2; shift 2 ;;
        --sudo) sudo=yes; shift ;;
        --no-rsync) no_rsync=yes; shift ;;
        --use-config) use_config=yes; shift ;;
        --key|--key=*) shift ;;
        -p|--passwords|-x|--command|-F|--upload|--schedule) exit 90 ;;
        /*/payload.sh) payload=$1; shift ;;
        *) printf 'Unexpected native argument: %s\n' "$1" >&2; exit 91 ;;
    esac
done
[ "$no_rsync" = yes ] && [ "$limit" = 1 ]
[ ! -e env.json ] # arbitrary controller env.json must never be inherited
if [ "$use_config" = yes ]; then
    [ -f config.json ] && [ "$(stat -c %a config.json)" = 600 ]
    grep -F 'CONFIG_SECRET' config.json >/dev/null
fi
if [ "${MOCK_READ_STDIN:-no}" = yes ]; then
    IFS= read -r password
    [ "$password" = PROMPT_SECRET ]
fi
if [ -n "$download" ]; then
    # Upstream transfers precede payload execution; the runner must split calls.
    [ -z "$payload" ] && [ "$sudo" = no ]
    printf 'fetch\n' >> "$MOCK_ROOT/order"
    [ "${MOCK_FETCH_FAIL:-no}" = no ] || exit 6
    remote=${download%%;*}
    [ -d "$remote" ] || exit 4
    mkdir -p output/downloads/fixture/artifacts
    cp -R "$remote" output/downloads/fixture/artifacts/
else
    [ -n "$payload" ] && [ "$sudo" = yes ]
    printf 'execute\n' >> "$MOCK_ROOT/order"
    [ "${MOCK_CONNECT_FAIL:-no}" = no ] || exit 8
    remote=$(sed -n "s/^ARTIFACTS='\([^']*\)'/\1/p" "$payload")
    printf '%s\n' "$remote" >> "$MOCK_ROOT/remotes"
    # Test-only PATH substitution keeps fake root and fake scripts isolated.
    sed 's|^PATH=/usr/sbin:.*|PATH=$MOCK_ROOT/bin|' "$payload" > "$MOCK_ROOT/remote-payload.sh"
    rc=0
    SUDO_UID=$MOCK_UID SUDO_GID=$MOCK_GID sh "$MOCK_ROOT/remote-payload.sh" > "$MOCK_ROOT/preview" 2> "$MOCK_ROOT/preview.err" || rc=$?
    [ "$(wc -c < "$MOCK_ROOT/preview")" -lt 1048576 ] || exit 92
    cat "$MOCK_ROOT/preview"
    cat "$MOCK_ROOT/preview.err" >&2
    exit "$rc"
fi
MOCK
chmod +x "$TMP/coordinate"
run() { sh "$CTL" "$@" --binary "$TMP/coordinate" --output-dir "$TMP/runs"; }
find_run() { sed -n 's/^Local run: //p' "$1"; }

# An omitted phase dispatches setup alone; neither native invocation gets a password.
printf 'PROMPT_SECRET\nPROMPT_SECRET\n' | MOCK_READ_STDIN=yes run --targets 192.0.2.5 --user defender > "$TMP/setup.out"
SETUP_RUN=$(find_run "$TMP/setup.out")
grep -Fx 'selected=setup' "$TMP/phases" >/dev/null
[ "$(wc -l < "$TMP/phases")" -eq 1 ]
[ "$(cat "$TMP/order")" = "$(printf 'execute\nfetch')" ]
[ "$(grep -c '^CALL$' "$TMP/calls")" -eq 2 ]
if grep -E 'PROMPT_SECRET|--passwords|--schedule|--upload' "$TMP/calls"; then exit 1; fi
[ "$(stat -c %a "$SETUP_RUN")" = 700 ]
grep -Fx execution_status=0 "$SETUP_RUN/run.txt" >/dev/null
printf 'PASS: default preparation only, separate execution/collection, prompted stdin, private output\n'

INJECTION="/srv/\$(touch '$TMP/INJECTED')/team's site"
sh "$CTL" hunt --targets 192.0.2.5 --user defender --port 2222 --binary "$TMP/coordinate" \
    --output-dir "$TMP/runs" --color always -- --web-root "$INJECTION" > "$TMP/hunt.out"
HUNT_RUN=$(find_run "$TMP/hunt.out")
REPORT=$(find "$HUNT_RUN/output/downloads" -name report.txt)
[ "$(wc -c < "$REPORT")" -gt 2097152 ]
tail -n 1 "$REPORT" | grep -Fx END_OF_COMPLETE_REPORT >/dev/null
[ "$(stat -c %a "$REPORT")" = 600 ]
[ ! -e "$TMP/INJECTED" ]
grep -F "<$INJECTION>" "${REPORT%/*}/stdout.txt" >/dev/null
grep -F 'remove fixture persistence' "$TMP/hunt.out" >/dev/null
esc=$(printf '\033')
grep -F "$esc[1;91m" "$TMP/hunt.out" >/dev/null
if grep -F "$esc" "$REPORT"; then exit 1; fi
[ ! -e "${REPORT%/*}/private" ]
printf 'PASS: large complete report transfer, severity/color preview, literal argument quoting, executable cleanup\n'

sh "$CTL" rootkit --targets 192.0.2.5 --user defender --binary "$TMP/coordinate" \
    --output-dir "$TMP/runs" -- --userspace-only > "$TMP/rootkit.out"
ROOTKIT_RUN=$(find_run "$TMP/rootkit.out")
ROOTKIT_REPORT=$(find "$ROOTKIT_RUN/output/downloads" -name report.txt)
tail -n 1 "$ROOTKIT_REPORT" | grep -Fx END_OF_COMPLETE_REPORT >/dev/null
grep -Fx selected=rootkit "$TMP/phases" >/dev/null
[ ! -e "${ROOTKIT_REPORT%/*}/private" ]
grep -Fx execution_status=0 "$ROOTKIT_RUN/run.txt" >/dev/null
grep -F CURRENT_ROOTKIT_VIEW "$TMP/rootkit.out" >/dev/null
grep -F 'POST-CLEANUP RECHECK' "$TMP/rootkit.out" >/dev/null
if grep -F 'Fixture implant' "$TMP/rootkit.out";then exit 1;fi
printf 'PASS: rootkit payload decodes and executes the embedded collector, retrieves full report and deletes executable staging\n'

# Failure is visible and still collects the complete/partial artifacts.
if MOCK_RECORDS=yes MOCK_SCRIPT_RC=7 sh "$CTL" harden --targets 192.0.2.5 --user defender \
    --state-dir "$TMP/state with spaces" --binary "$TMP/coordinate" --output-dir "$TMP/runs" > "$TMP/fail.out" 2> "$TMP/fail.err"; then exit 1; fi
FAILED_RUN=$(find_run "$TMP/fail.out")
grep -Fx execution_status=7 "$FAILED_RUN/run.txt" >/dev/null
grep -Fx collection_status=0 "$FAILED_RUN/run.txt" >/dev/null
find "$FAILED_RUN/output/downloads" -name status.txt -exec grep -Fx exit_status=7 {} \; | grep exit_status >/dev/null
find "$FAILED_RUN/output/downloads" -name record-harden.log.txt -exec grep -Fx PACKAGE_DETAIL_ONLY_IN_LOG {} \; | grep PACKAGE_DETAIL >/dev/null
[ "$(stat -c %a "$TMP/state with spaces/hardening/20261119T000000Z-4242/harden.log")" = 640 ]
if MOCK_FETCH_FAIL=yes run hunt --targets 192.0.2.5 --user defender > "$TMP/fetch-fail.out" 2> "$TMP/fetch-fail.err"; then exit 1; fi
FETCH_FAILED_RUN=$(find_run "$TMP/fetch-fail.out")
grep -Fx execution_status=0 "$FETCH_FAILED_RUN/run.txt" >/dev/null
grep -Fx collection_status=6 "$FETCH_FAILED_RUN/run.txt" >/dev/null
printf 'PASS: failed payload and full operation log fetched; original permissions kept; collection failure is nonzero\n'

MOCK_RECORDS=yes run setup --targets 192.0.2.5 --user defender --state-dir "$TMP/state with spaces" > "$TMP/record.out"
RECORD_RUN=$(find_run "$TMP/record.out")
MANIFEST=$(find "$RECORD_RUN/output/downloads" -name record-manifest.sha256.txt)
grep -Fx HASH_MANIFEST "$MANIFEST" >/dev/null
[ "$(stat -c %a "$MANIFEST")" = 600 ]
grep -Fx DETAIL_ERROR_ONLY_IN_LOG "${MANIFEST%/*}/record-errors.log.txt" >/dev/null
grep -Fx CAPACITY_DETAIL "${MANIFEST%/*}/record-backup-capacity.txt.txt" >/dev/null
[ "$(stat -c %a "$TMP/state with spaces/runs/20261119T000000Z-4242/setup.log")" = 640 ]
printf 'PASS: setup operation logs and manifest copied privately without modifying originals\n'

printf '[{"IP":"192.0.2.5","Username":"defender","Password":"CONFIG_SECRET"}]\n' > "$TMP/config.json"
printf '{"UNEXPECTED":"bad"}\n' > "$TMP/repo/env.json"
run setup --config "$TMP/config.json" > "$TMP/config.out"
CONFIG_RUN=$(find_run "$TMP/config.out")
[ ! -e "$CONFIG_RUN/config.json" ]
if grep -RF 'CONFIG_SECRET' "$CONFIG_RUN"; then exit 1; fi
if MOCK_SCRIPT_RC=3 run hunt --config "$TMP/config.json" > "$TMP/config-fail.out" 2> "$TMP/config-fail.err"; then exit 1; fi
[ ! -e "$(find_run "$TMP/config-fail.out")/config.json" ]
printf 'PASS: explicit private credential copy removed on success/failure; incidental env/config files isolated\n'

before=$(wc -l < "$TMP/calls")
for invalid in '--port 0' '--port 65536' '--timeout 0' '--max-hosts 99999' '--color bogus'; do
    # Intentional field splitting for these fixed test option/value pairs only.
    if run setup --targets 192.0.2.5 --user defender $invalid >/dev/null 2>&1; then exit 1; fi
done
if run hunt --targets 192.0.2.5 --user defender -- --output /etc/danger >/dev/null 2>&1; then exit 1; fi
if run setup --targets 192.0.2.5 --user defender -- --reinstall-core >/dev/null 2>&1; then exit 1; fi
if run setup --targets 192.0.2.5 --user defender -- --dry-run >/dev/null 2>&1; then exit 1; fi
if run harden --targets 192.0.2.5 --config "$TMP/config.json" --user defender >/dev/null 2>&1; then exit 1; fi
if MOCK_OLD=yes run setup --targets 192.0.2.5 --user defender >/dev/null 2>&1; then exit 1; fi
[ "$before" = "$(wc -l < "$TMP/calls")" ]
run hunt --targets 192.0.2.5 --user defender --prepare-only > "$TMP/prepared.out"
PREPARED=$(find_run "$TMP/prepared.out")
sh -n "$PREPARED/payload.sh"
grep -F '# IMPL_hunt' "$PREPARED/payload.sh" >/dev/null
if grep -E '# IMPL_(setup|harden)' "$PREPARED/payload.sh"; then exit 1; fi
[ "$before" = "$(wc -l < "$TMP/calls")" ]
[ "$SETUP_RUN" != "$CONFIG_RUN" ]
printf 'PASS: phase/argument validation and old-binary checks before SSH; prepare-only is offline and phase-specific\n'

# Normalize decimal input before passing it to Go flag parsers that accept octal.
run setup --targets 192.0.2.5 --user defender --port 000022 > "$TMP/decimal.out"
grep -Fx port=22 "$(find_run "$TMP/decimal.out")/run.txt" >/dev/null
printf 'PASS: leading-zero port values are normalized to decimal\n'
