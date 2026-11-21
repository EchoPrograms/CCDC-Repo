# Appended to a generated script by ctl. Not an independently runnable command.
PATH=/usr/sbin:/usr/bin:/sbin:/bin:/usr/local/sbin:/usr/local/bin
export PATH
LC_ALL=C
export LC_ALL
unset ENV BASH_ENV CDPATH
umask 077
[ "$(id -u)" = 0 ] || { printf 'Root required; Coordinate must use --sudo.\n' >&2; exit 1; }
case $PHASE in setup|hunt|rootkit|harden|watch) ;; *) exit 2 ;; esac
case $ARTIFACTS in /tmp/hunter-coordinate-*) ;; *) exit 2 ;; esac
case ${ARTIFACTS#/tmp/} in *[!A-Za-z0-9._-]*) exit 2 ;; esac

# sudo normally supplies the actual SSH login's IDs. Downloads do not use sudo.
# Hand only completed data to that user, after deleting all executable staging.
LOGIN_UID=${SUDO_UID:-0}
LOGIN_GID=${SUDO_GID:-0}
case $LOGIN_UID:$LOGIN_GID in *[!0-9:]*|:*|*:) printf 'Invalid sudo login identity\n' >&2; exit 1 ;; esac
mkdir "$ARTIFACTS" || { printf 'Refusing existing artifact path: %s\n' "$ARTIFACTS" >&2; exit 1; }
chmod 700 "$ARTIFACTS" || exit 1
RC=125
CHILD=
collect_record() {
    # Copy this phase's operation logs, not the large protected backup archives.
    # IDs come from the selected script's own stdout and must match its format.
    record_id=
    case $PHASE in
        setup)
            record_id=$(awk '$1=="Run" && $3=="|" {print $2; exit}' "$ARTIFACTS/stdout.txt")
            record_base=$STATE/runs ;;
        harden)
            record_path=$(sed -n 's/^Record: //p' "$ARTIFACTS/stdout.txt" | tail -n 1)
            case $record_path in "$STATE"/hardening/*/harden.log)
                record_id=${record_path%/harden.log}; record_id=${record_id##*/} ;;
            esac
            record_base=$STATE/hardening ;;
        *) return 0 ;;
    esac
    case $record_id in ''|*[!0-9TZ-]*) return 0 ;; esac
    record_path=$record_base/$record_id
    [ -d "$record_path" ] && [ ! -L "$record_path" ] || return 0
    for record_name in setup.log harden.log errors.log manifest.sha256 backups.sha256 backup-status.txt backup-capacity.txt backup-size-estimates.txt backup-filesystem.txt COMPLETE PARTIAL INCOMPLETE; do
        if [ -f "$record_path/$record_name" ] && [ ! -L "$record_path/$record_name" ]; then
            cat "$record_path/$record_name" > "$ARTIFACTS/record-$record_name.txt" || return 1
        fi
    done
}
finish() {
    trap - 0 1 2 15
    collect_record || RC=1
    # Never execute or write into staging after making it owned by the SSH user.
    rm -rf "$ARTIFACTS/private" || RC=1
    {
        printf 'phase=%s\nexit_status=%s\n' "$PHASE" "$RC"
        printf 'host=%s\nstate_dir=%s\n' "$(uname -n)" "$STATE"
    } > "$ARTIFACTS/status.txt" || RC=1
    printf '\n=== %s | %s | exit %s ===\n' "$PHASE" "$(uname -n)" "$RC"
    if { [ "$PHASE" = hunt ] || [ "$PHASE" = rootkit ]; } && [ -f "$ARTIFACTS/report.txt" ]; then
        # Bounded console preview; the full sorted report is transferred as data.
        preview=$ARTIFACTS/report.txt
        # Rootkit stdout contains the final recheck, whereas its report also
        # retains the pre-change snapshot. Show the current result on screen.
        if [ "$PHASE" = rootkit ] && [ -s "$ARTIFACTS/stdout.txt" ]; then preview=$ARTIFACTS/stdout.txt; fi
        dd if="$preview" bs=32768 count=1 2>/dev/null | awk -v color="$DISPLAY_COLOR" '
            BEGIN {esc=sprintf("%c",27)}
            /^CHECK COVERAGE/ || /^DETAILED EVIDENCE/ || NR>100 {exit}
            {line=$0; c=""}
            /^\[CRITICAL\]/ {c="1;91"}
            /^\[HIGH\]/ {c="1;31"}
            /^\[MEDIUM\]/ {c="1;33"}
            /^\[LOW\]/ {c="36"}
            /^\[INFO\]/ {c="34"}
            {if(color=="yes" && c!="") print esc "[" c "m" line esc "[0m"; else print line}'
    elif [ -f "$ARTIFACTS/stdout.txt" ]; then
        tail -n 30 "$ARTIFACTS/stdout.txt" | dd bs=16384 count=1 2>/dev/null
    fi
    if [ -s "$ARTIFACTS/stderr.txt" ]; then
        printf '\nRecent diagnostics (full stderr.txt is collected):\n'
        tail -n 12 "$ARTIFACTS/stderr.txt" | dd bs=4096 count=1 2>/dev/null
    fi
    printf '\nFull result files: %s\n' "$ARTIFACTS"
    chmod 600 "$ARTIFACTS"/*.txt || RC=1
    chown "$LOGIN_UID:$LOGIN_GID" "$ARTIFACTS"/*.txt || RC=1
    chown "$LOGIN_UID:$LOGIN_GID" "$ARTIFACTS" || RC=1
    exit "$RC"
}
interrupted() {
    trap '' 1 2 15
    if [ -n "$CHILD" ]; then kill -TERM "$CHILD" 2>/dev/null || :; wait "$CHILD" 2>/dev/null || :; fi
    RC=130
    exit "$RC"
}
trap finish 0
trap interrupted 1 2 15
mkdir "$ARTIFACTS/private" || exit 1
write_script > "$ARTIFACTS/private/hunter.sh" || exit 1
if [ "$PHASE" = rootkit ]; then
    write_collector > "$ARTIFACTS/private/collector" || exit 1
    chmod 500 "$ARTIFACTS/private/collector" || exit 1
    HUNTER_ROOTKIT_COLLECTOR=$ARTIFACTS/private/collector
    export HUNTER_ROOTKIT_COLLECTOR
fi
if [ "$PHASE" = watch ]; then
    write_watch_collector > "$ARTIFACTS/private/watch-collector" || exit 1
    chmod 500 "$ARTIFACTS/private/watch-collector" || exit 1
    HUNTER_WATCH_COLLECTOR=$ARTIFACTS/private/watch-collector
    export HUNTER_WATCH_COLLECTOR
    if [ "${1:-status}" = install ]; then
        write_watch_config > "$ARTIFACTS/private/watch-config" || exit 1
        chmod 600 "$ARTIFACTS/private/watch-config" || exit 1
        set -- "$@" --config "$ARTIFACTS/private/watch-config"
    fi
fi
if [ "$PHASE" = hunt ] || [ "$PHASE" = rootkit ]; then
    set -- --output "$ARTIFACTS/report.txt" --color never --state-dir "$STATE" "$@"
else
    set -- --state-dir "$STATE" "$@"
fi
/bin/sh "$ARTIFACTS/private/hunter.sh" "$@" > "$ARTIFACTS/stdout.txt" 2> "$ARTIFACTS/stderr.txt" &
CHILD=$!
wait "$CHILD"
RC=$?
CHILD=
exit "$RC"
