#!/bin/sh
# Grade actual alert locations separately from inventory and deliberate blind spots.
set -eu
if [ "$#" -lt 1 ] || [ "$#" -gt 3 ]; then
    printf 'Usage: sh grade.sh REPORT [default|custom] [SEED_STATUS]\n' >&2
    exit 2
fi
REPORT=$1
PROFILE=${2:-default}
STATUS=${3:-/var/lib/ccdc-lab/seed-status}
case $PROFILE in default|custom) ;; *) printf 'Profile must be default or custom.\n' >&2; exit 2 ;; esac
[ -r "$REPORT" ] || { printf 'Cannot read report: %s\n' "$REPORT" >&2; exit 2; }
MANIFEST=$(CDPATH= cd "$(dirname "$0")" && pwd)/scenarios.tsv
has_alert() {
    awk -v location="$1" -v title="$2" '
        /^DETAILED EVIDENCE/ {exit}
        /^\[(CRITICAL|HIGH|MEDIUM|LOW|INFO)\]/ {heading=$0}
        /^  Location: / && index($0,location) && (title=="-" || index(heading,title)) {found=1}
        END {exit !found}' "$REPORT"
}
has_inventory() {
    awk -v location="$1" '
        /^DETAILED EVIDENCE/ {details=1; next}
        details && index($0,location) {found=1; exit}
        END {exit !found}' "$REPORT"
}
# Require a finished hunter report; don't grade a partial/empty file as all-clear.
grep 'CCDC persistence triage.*COMPLETED' "$REPORT" > /dev/null || {
    printf 'Not a completed hunter report.\n' >&2; exit 2
}
TAB=$(printf '\t')
active_total=0 active_alerts=0 unexpected=0 fixture_alerts=0 dormant_alerts=0 skipped=0
printf '\nGROUND TRUTH COMPARISON (%s web-root profile)\n' "$PROFILE"
printf '%-10s %-11s %-17s %-11s %s\n' ID MODE ACTUAL EXPECTED LOCATION
while IFS="$TAB" read -r sid area mode normal custom location title; do
    case $sid in ''|\#*) continue ;; esac
    if [ "$PROFILE" = custom ]; then expected=$custom; else expected=$normal; fi
    case $sid in ACL*)
        if [ -r "$STATUS" ] && grep '^ACL=unsupported$' "$STATUS" >/dev/null; then expected=skip; fi ;;
    esac
    if [ "$expected" = skip ]; then
        actual=SKIPPED; skipped=$((skipped + 1))
    else
        if has_alert "$location" "$title"; then actual=ALERT;
        elif has_inventory "$location"; then actual=INVENTORY_ONLY;
        else actual=NO_HIT; fi
        case $expected in
            alert|baseline) [ "$actual" = ALERT ] || unexpected=$((unexpected + 1)) ;;
            inventory) [ "$actual" != NO_HIT ] || unexpected=$((unexpected + 1)) ;;
            miss) ;; # A new alert here is an improvement, not a failed test.
        esac
        case $mode in
            active)
                active_total=$((active_total + 1))
                [ "$actual" != ALERT ] || active_alerts=$((active_alerts + 1)) ;;
            fixture) [ "$actual" != ALERT ] || fixture_alerts=$((fixture_alerts + 1)) ;;
            dormant) [ "$actual" != ALERT ] || dormant_alerts=$((dormant_alerts + 1)) ;;
        esac
    fi
    printf '%-10s %-11s %-17s %-11s %s\n' "$sid" "$mode" "$actual" "$expected" "$location"
done < "$MANIFEST"
printf '\nActive scenario alerts: %s/%s. Dormant policy alerts: %s. Fixture alerts: %s. Skipped: %s.\n' \
    "$active_alerts" "$active_total" "$dormant_alerts" "$fixture_alerts" "$skipped"
printf 'Expected alerts/inventory missing: %s\n' "$unexpected"
printf 'CRON02 is a baseline-review case; APK01 is a known coverage gap. WEB03 needs --web-root.\n'
printf 'B00 is approved administrator access: its alert illustrates baseline-related false positives.\n'
printf 'Fixture/dormant counts do not measure real rootkit or live authentication-backdoor detection.\n'
[ "$unexpected" -eq 0 ]
