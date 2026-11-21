#!/bin/sh
# Full hardening flow with native commands mocked and configuration redirected
# in a test-only copy. Never install packages or edit the workstation's /etc.
set -eu
REPO=$(CDPATH= cd "$(dirname "$0")/.." && pwd)
TMP=$(mktemp -d /tmp/hunter-harden-test.XXXXXXXX)
trap 'rm -rf "$TMP"' 0
trap 'exit 1' 1 2 15
ROOT=$TMP/root
BIN=$TMP/bin
mkdir -p "$BIN" "$ROOT/etc/apache2/mods-available" "$ROOT/etc/apache2/mods-enabled" \
    "$ROOT/etc/apache2/conf-enabled" "$ROOT/etc/modsecurity" "$ROOT/etc/ssh" \
    "$ROOT/usr/share/modsecurity-crs/rules" "$ROOT/.x86/runs/initial"
printf 'ID=debian\n' > "$ROOT/etc/os-release"
printf 'LogLevel VERBOSE\n' > "$ROOT/etc/ssh/sshd_config"
printf 'root ALL=(ALL) ALL\n' > "$ROOT/etc/sudoers"
printf 'SecRuleEngine DetectionOnly\nSecAuditEngine Off\n' > "$ROOT/etc/modsecurity/modsecurity.conf"
chmod 640 "$ROOT/etc/modsecurity/modsecurity.conf"
printf '# native CRS loader fixture\n' > "$ROOT/usr/share/modsecurity-crs/owasp-crs.load"
printf '# native rule fixture\n' > "$ROOT/usr/share/modsecurity-crs/rules/REQUEST-901-INITIALIZATION.conf"
printf 'initial\n' > "$ROOT/.x86/latest"
printf 'KEEP_ORIGINAL_BASELINE\n' > "$ROOT/.x86/runs/initial/manifest.sha256"
for module in security2 headers unique_id; do printf '# module fixture\n' > "$ROOT/etc/apache2/mods-available/$module.load"; done
for utility in awk cat chmod cp date find grep ls mkdir mv rm rmdir sed sort tar tee tr uname env sha256sum readlink ln; do
    target=$(command -v "$utility")
    ln -s "$target" "$BIN/$utility"
done
REAL_LS=$(command -v ls)
export REAL_LS
rm "$BIN/ls"
cat > "$BIN/ls" <<'MOCK'
#!/bin/sh
if [ "$1" = -ldn ]; then "$REAL_LS" "$@" | awk '{$3=0; print}'
else exec "$REAL_LS" "$@"; fi
MOCK
cat > "$BIN/mock-command" <<'MOCK'
#!/bin/sh
name=${0##*/}
printf '%s %s\n' "$name" "$*" >> "$MOCK_CALLS"
case $name in
    id) printf '0\n' ;;
    dpkg-query)
        last=; for argument do last=$argument; done
        case $last in openssh-server|libpam-modules|coreutils|bash|apache2) printf 'install ok installed\n' ;; *) exit 1 ;; esac ;;
    apt-get)
        if [ -n "${MOCK_FAIL_PACKAGE:-}" ]; then
            for argument do [ "$argument" != "$MOCK_FAIL_PACKAGE" ] || exit 1; done
        fi ;;
    apache2ctl)
        case "$*" in
            '-M') printf 'security2_module (shared)\nheaders_module (shared)\nunique_id_module (shared)\n' ;;
            '-t -D DUMP_INCLUDES')
                printf 'Included configuration files:\n  %s/etc/apache2/apache2.conf\n' "$MOCK_ROOT"
                fragment=$MOCK_ROOT/etc/apache2/conf-enabled/zz-hunter-security.conf
                if [ -f "$fragment" ]; then
                    printf '  %s\n' "$fragment"
                    if grep -F 'owasp-crs.load' "$fragment" >/dev/null; then
                        printf '  %s/usr/share/modsecurity-crs/rules/REQUEST-901-INITIALIZATION.conf\n' "$MOCK_ROOT"
                    fi
                fi ;;
            '-t') [ "${MOCK_APACHE_FAIL:-no}" != yes ] || exit 1 ;;
            *) exit 90 ;;
        esac ;;
    a2enmod)
        module=$1
        link=$MOCK_ROOT/etc/apache2/mods-enabled/$module.load
        [ -L "$link" ] || ln -s "$MOCK_ROOT/etc/apache2/mods-available/$module.load" "$link" ;;
    rc-service)
        if [ "$2" = status ] && [ "${MOCK_SERVICE_STOPPED:-no}" = yes ]; then exit 1; fi
        if [ "$1:$2" = apache2:reload ] && [ "${MOCK_RELOAD_FAIL:-no}" = yes ]; then exit 1; fi ;;
    chattr) exit 1 ;;
    sshd|visudo) : ;;
    *) exit 91 ;;
esac
MOCK
chmod +x "$BIN/mock-command" "$BIN/ls"
for name in id dpkg-query apt-get apache2ctl a2enmod rc-service chattr sshd visudo; do ln -s mock-command "$BIN/$name"; done
sed -e 's|^PATH=/usr/sbin:.*|PATH=$HUNTER_TEST_PATH|' \
    -e 's|^CONFIG_ROOT=$|CONFIG_ROOT=$HUNTER_TEST_ROOT|' "$REPO/hunter-harden.sh" > "$TMP/harden.sh"
export HUNTER_TEST_PATH="$BIN" HUNTER_TEST_ROOT="$ROOT" MOCK_ROOT="$ROOT" MOCK_CALLS="$TMP/calls"
: > "$MOCK_CALLS"
sh "$TMP/harden.sh" --dry-run > "$TMP/plan.txt"
[ ! -d "$ROOT/.x86/hardening" ]
grep -F 'install --reinstall -y libpam-modules' "$TMP/plan.txt" >/dev/null
grep -F 'libapache2-mod-security2' "$TMP/plan.txt" >/dev/null
if grep -E '^(apt-get|a2enmod|chattr|sshd|visudo) ' "$MOCK_CALLS"; then exit 1; fi
printf 'PASS: dry-run plans installed core packages and WAF without writes/install/config commands\n'
: > "$MOCK_CALLS"
sh "$TMP/harden.sh" --no-refresh > "$TMP/apply.txt"
grep -F 'SecRuleEngine On' "$ROOT/etc/modsecurity/modsecurity.conf" >/dev/null
grep -F 'SecAuditEngine RelevantOnly' "$ROOT/etc/modsecurity/modsecurity.conf" >/dev/null
FRAGMENT=$ROOT/etc/apache2/conf-enabled/zz-hunter-security.conf
grep -F 'ServerTokens Prod' "$FRAGMENT" >/dev/null
grep -F 'owasp-crs.load' "$FRAGMENT" >/dev/null
grep -F 'rc-service apache2 reload' "$MOCK_CALLS" >/dev/null
grep -F 'rc-service sshd reload' "$MOCK_CALLS" >/dev/null
grep -F 'apt-get -o Dpkg::Options::=--force-confmiss install --reinstall -y libpam-modules' "$MOCK_CALLS" >/dev/null
# Tool installation belongs to setup, not post-hunt hardening.
if grep -E '^apt-get install -y (auditd|debsums|ripgrep|acl)' "$MOCK_CALLS"; then exit 1; fi
[ "$(cat "$ROOT/.x86/latest")" = initial ]
grep -x KEEP_ORIGINAL_BASELINE "$ROOT/.x86/runs/initial/manifest.sha256" >/dev/null
set -- "$ROOT/.x86/hardening"/*/COMPLETE
[ "$#" -eq 1 ] && [ -f "$1" ]
RUN=${1%/*}
[ -s "$RUN/etc-before.tar" ] && [ -s "$RUN/etc-before.sha256" ]
tar -xOf "$RUN/etc-before.tar" ./etc/modsecurity/modsecurity.conf | grep -F 'SecRuleEngine DetectionOnly' >/dev/null
printf 'PASS: installed core recovery, WAF rules, validated reload, logs/backups, preserved baseline\n'
sh "$TMP/harden.sh" --skip-core --no-refresh > "$TMP/rerun.txt"
[ "$(grep -c 'Include.*owasp-crs.load' "$FRAGMENT")" -eq 1 ]
printf 'PASS: repeated hardening retains exactly one managed CRS Include\n'
# Exercise actual rollback after edits: existing files/modes restored, new
# fragment and newly enabled module symlinks removed, no reload on test failure.
rm -f "$FRAGMENT" "$ROOT/etc/apache2/mods-enabled"/*.load
printf 'SecRuleEngine DetectionOnly\nSecAuditEngine Off\n' > "$ROOT/etc/modsecurity/modsecurity.conf"
chmod 640 "$ROOT/etc/modsecurity/modsecurity.conf"
BEFORE=$(sha256sum < "$ROOT/etc/modsecurity/modsecurity.conf")
: > "$MOCK_CALLS"
if MOCK_APACHE_FAIL=yes sh "$TMP/harden.sh" --skip-core --no-refresh > "$TMP/rollback.txt"; then exit 1; fi
[ "$BEFORE" = "$(sha256sum < "$ROOT/etc/modsecurity/modsecurity.conf")" ]
[ "$(ls -ld "$ROOT/etc/modsecurity/modsecurity.conf" | awk '{print $1}')" = -rw-r----- ]
[ ! -e "$FRAGMENT" ] && [ ! -L "$ROOT/etc/apache2/mods-enabled/security2.load" ]
if grep -F 'rc-service apache2 reload' "$MOCK_CALLS"; then exit 1; fi
set -- "$ROOT/.x86/hardening"/*/PARTIAL
[ "$#" -eq 1 ] && [ -f "$1" ]
printf 'PASS: rejected Apache config rolls back content, permissions, new files and module links\n'
: > "$MOCK_CALLS"
if MOCK_RELOAD_FAIL=yes sh "$TMP/harden.sh" --skip-core --no-refresh > "$TMP/reload-failed.txt"; then exit 1; fi
[ "$BEFORE" = "$(sha256sum < "$ROOT/etc/modsecurity/modsecurity.conf")" ]
[ ! -e "$FRAGMENT" ] && [ ! -L "$ROOT/etc/apache2/mods-enabled/security2.load" ]
grep -F 'rc-service apache2 reload' "$MOCK_CALLS" >/dev/null
printf 'PASS: failed Apache reload restores the previous configuration\n'
# One failed core package must be reported and return failure, not a clean run.
if MOCK_FAIL_PACKAGE=coreutils sh "$TMP/harden.sh" --skip-apache --no-refresh > "$TMP/failed-package.txt"; then exit 1; fi
grep -F 'FAILED: Core package reinstall: coreutils' "$TMP/failed-package.txt" >/dev/null
[ ! -e "$ROOT/.x86/.setup-lock" ]
printf 'PASS: partial package failure returns failure and releases the shared mutation lock\n'
awk '/^reinstall_one\(\)/ {copy=1} copy {print} copy && /^}/ {exit}' "$REPO/hunter-harden.sh" > "$TMP/reinstall-function"
for manager in apt-get dnf yum zypper pacman apk; do
    PM=$manager FUNCTIONS=$TMP/reinstall-function sh -c '
        run() { printf "%s\n" "$*"; }
        . "$FUNCTIONS"
        reinstall_one core-test
    ' > "$TMP/$manager.txt"
done
grep -F 'install --reinstall -y' "$TMP/apt-get.txt" >/dev/null
grep -F 'dnf reinstall -y' "$TMP/dnf.txt" >/dev/null
grep -F 'yum reinstall -y' "$TMP/yum.txt" >/dev/null
grep -F 'zypper --non-interactive install --force' "$TMP/zypper.txt" >/dev/null
grep -F 'pacman -S --noconfirm core-test' "$TMP/pacman.txt" >/dev/null
if grep -F -- --needed "$TMP/pacman.txt"; then exit 1; fi
grep -F 'apk fix --reinstall core-test' "$TMP/apk.txt" >/dev/null
printf 'PASS: apt/dnf/yum/zypper/pacman/apk reinstall commands force replacement\n'
: > "$MOCK_CALLS"
MOCK_SERVICE_STOPPED=yes sh "$TMP/harden.sh" --skip-core --no-refresh > "$TMP/stopped.txt"
if grep -E '^rc-service .* (reload|start)$' "$MOCK_CALLS"; then exit 1; fi
grep -F 'stopped service was not started' "$TMP/stopped.txt" >/dev/null
printf 'PASS: hardening validates stopped Apache without starting it\n'
