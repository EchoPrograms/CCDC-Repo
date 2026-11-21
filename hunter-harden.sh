#!/bin/sh
# Post-hunt package recovery and web hardening. Standalone POSIX shell.
PATH=/usr/sbin:/usr/bin:/sbin:/bin:/usr/local/sbin:/usr/local/bin
export PATH
LC_ALL=C
export LC_ALL
unset ENV BASH_ENV CDPATH
umask 077

usage() {
    cat <<'EOF'
Usage: sudo sh hunter-harden.sh [options]
  --dry-run           Show installed core packages and planned commands; no writes.
  --state-dir /PATH   Store private hardening records (default /.x86).
  --skip-core         Skip core package reinstalls and SSH reload.
  --skip-apache       Skip Apache packages and configuration.
  --no-refresh        Use existing package repository metadata.
  --help             Show help.

Run after hunter-hunt.sh. Default: reinstall installed core packages and enable
Apache ModSecurity/CRS and safe HTTP settings if Apache is installed. Scanning
and logging utilities are installed by hunter-setup.sh. Uses apt, yum/dnf, zypper, pacman or apk. No target Python.
Logs/rollback copies: STATE/hardening/UTC-PID/. The setup baseline is preserved.
Exit: 0 complete, 1 failed/partial, 2 invalid arguments.
EOF
}
die() { printf 'hunter-harden: %s\n' "$*" >&2; exit 1; }
badarg() { printf 'hunter-harden: %s\n' "$*" >&2; exit 2; }
DRY_RUN=no STATE=/.x86 CORE=yes APACHE=yes REFRESH=yes
while [ "$#" -gt 0 ]; do
    case $1 in
        -h|--help) usage; exit 0 ;;
        --dry-run) DRY_RUN=yes; shift ;;
        --skip-core) CORE=no; shift ;;
        --skip-apache) APACHE=no; shift ;;
        --no-refresh) REFRESH=no; shift ;;
        --state-dir)
            [ "$#" -ge 2 ] && [ -n "$2" ] || badarg 'Missing state directory'
            STATE=${2%/}
            case $STATE in /*) ;; *) badarg 'State directory must be absolute' ;; esac
            case $STATE in ''|/|*//*|*'|'*|*'\'*|*'
'*|*'	'*) badarg 'Use a canonical state directory without path delimiters' ;; esac
            case /$STATE/ in */../*|*/./*) badarg 'Use a canonical state directory' ;; esac
            shift 2 ;;
        *) badarg "Unknown option: $1" ;;
    esac
done
case $STATE/ in /etc/*) badarg 'State directory must be outside /etc' ;; esac
for utility in awk cat chmod cp date find grep id ls mkdir mv rm rmdir sed sort tar tee tr uname; do
    command -v "$utility" >/dev/null 2>&1 || die "Required utility missing: $utility"
done
if [ "$DRY_RUN" = no ]; then [ "$(id -u)" = 0 ] || die 'Run as root, or use --dry-run'; fi
# All live configuration accesses use this prefix. It is intentionally fixed;
# hardening a mounted image is not supported by this script.
CONFIG_ROOT=
path() { printf '%s%s\n' "$CONFIG_ROOT" "$1"; }
PM=none
OS=$(awk -F= '$1=="ID" {gsub(/["\047]/,"",$2); print $2}' "$(path /etc/os-release)" 2>/dev/null)
case $OS in
    debian|ubuntu|linuxmint|kali|pop) command -v apt-get >/dev/null 2>&1 && PM=apt-get ;;
    opensuse*|sles|sled|suse*) command -v zypper >/dev/null 2>&1 && PM=zypper ;;
    arch|manjaro|endeavouros|artix) command -v pacman >/dev/null 2>&1 && PM=pacman ;;
    alpine) command -v apk >/dev/null 2>&1 && PM=apk ;;
esac
if [ "$PM" = none ]; then
    for manager in apt-get dnf yum zypper pacman apk; do
        if command -v "$manager" >/dev/null 2>&1; then PM=$manager; break; fi
    done
fi
[ "$PM" != none ] || die 'No supported native package manager found'

safe_dir() {
    sd_path=$1; sd_mode=${2:-700}
    oldifs=$IFS; IFS=/; set -f; set -- $sd_path; set +f; IFS=$oldifs
    sd_current=
    for sd_segment do
        [ -n "$sd_segment" ] || continue
        sd_current=$sd_current/$sd_segment
        [ ! -L "$sd_current" ] || die "Refusing symlinked directory: $sd_current"
        if [ -e "$sd_current" ]; then [ -d "$sd_current" ] || die "Not a directory: $sd_current"
        else mkdir -m "$sd_mode" "$sd_current" || die "Cannot create $sd_current"; fi
    done
}
RUN= LOCK= FAILURES=0 SUCCESSES=0 SKIPPED=0
cleanup() { [ -z "$LOCK" ] || rmdir "$LOCK" 2>/dev/null || :; }
trap cleanup 0
trap 'printf "hunter-harden: interrupted; incomplete records retained at %s\n" "$RUN" >&2; exit 1' 1 2 15
if [ "$DRY_RUN" = no ]; then
    STORE=$(path "$STATE")
    safe_dir "$STORE"
    [ "$(ls -ldn "$STORE" | awk '{print $3}')" = "$(id -u)" ] || die 'State directory must be owned by root'
    chmod 700 "$STORE" || die 'Cannot protect state directory'
    # Share the setup lock so baseline collection and hardening cannot overlap.
    mkdir "$STORE/.setup-lock" 2>/dev/null || die "Setup or hardening already running, or stale lock: $STORE/.setup-lock"
    LOCK=$STORE/.setup-lock
    safe_dir "$STORE/hardening"
    RUN=$STORE/hardening/$(date -u '+%Y%m%dT%H%M%SZ')-$$
    mkdir "$RUN" || die 'Cannot create private hardening record'
    : > "$RUN/INCOMPLETE"
    : > "$RUN/harden.log"
    : > "$RUN/errors.log"
    : > "$RUN/config-journal"
fi
log() {
    if [ "$DRY_RUN" = yes ]; then printf '%s\n' "$*" | tr '\000-\010\013-\037\177' '?'
    else printf '%s\n' "$*" | tr '\000-\010\013-\037\177' '?' | tee -a "$RUN/harden.log"; fi
}
failed() { FAILURES=$((FAILURES + 1)); log "FAILED: $*"; }
skip() { SKIPPED=$((SKIPPED + 1)); log "SKIPPED: $*"; }
run() {
    if [ "$DRY_RUN" = yes ]; then log "PLAN: $*"; return 0; fi
    log "RUN: $*"
    "$@" >> "$RUN/harden.log" 2>> "$RUN/errors.log"
}
installed() {
    case $PM in
        apt-get) dpkg-query -W '-f=${Status}\n' "$1" 2>/dev/null | grep -E '^[^ ]+ ok installed$' >/dev/null ;;
        dnf|yum|zypper) rpm -q --quiet "$1" >/dev/null 2>&1 ;;
        pacman) pacman -Q "$1" >/dev/null 2>&1 ;;
        apk) apk info -e "$1" >/dev/null 2>&1 ;;
    esac
}
reinstall_one() {
    case $PM in
        apt-get) run env DEBIAN_FRONTEND=noninteractive apt-get -o Dpkg::Options::=--force-confmiss install --reinstall -y "$1" ;;
        dnf|yum) run "$PM" reinstall -y "$1" ;;
        zypper) run zypper --non-interactive install --force "$1" ;;
        pacman) run pacman -S --noconfirm "$1" ;;
        apk) run apk fix --reinstall "$1" ;;
    esac
}
install_one() {
    case $PM in
        apt-get) run env DEBIAN_FRONTEND=noninteractive apt-get install -y "$1" ;;
        dnf|yum) run "$PM" install -y "$1" ;;
        zypper) run zypper --non-interactive install --no-recommends "$1" ;;
        pacman) run pacman -S --noconfirm --needed "$1" ;;
        apk) run apk add --no-cache "$1" ;;
    esac
}
log "HUNTER HARDEN | distro=${OS:-unknown} | manager=$PM | dry-run=$DRY_RUN"
if [ "$DRY_RUN" = no ]; then
    log "Record: $RUN/harden.log"
    # Preserve all original configs before executing any package-manager hooks.
    log 'Backing up /etc before package and configuration changes'
    tar_extra=
    tar_help=$(tar --help 2>/dev/null || :)
    case $tar_help in *--acls*) tar_extra=--acls ;; esac
    case $tar_help in *--xattrs*) tar_extra="$tar_extra --xattrs" ;; esac
    (cd "${CONFIG_ROOT:-/}" && tar $tar_extra -cpf "$RUN/etc-before.tar" ./etc) 2>> "$RUN/errors.log" || die 'Configuration backup failed; hardening was not started'
    if command -v sha256sum >/dev/null 2>&1; then sha256sum < "$RUN/etc-before.tar" > "$RUN/etc-before.sha256"
    elif command -v shasum >/dev/null 2>&1; then shasum -a 256 < "$RUN/etc-before.tar" > "$RUN/etc-before.sha256"
    elif command -v openssl >/dev/null 2>&1; then openssl dgst -sha256 < "$RUN/etc-before.tar" > "$RUN/etc-before.sha256"; fi
    if command -v chattr >/dev/null 2>&1; then chattr +i "$RUN/etc-before.tar" 2>> "$RUN/errors.log" || :; fi
fi
if [ "$REFRESH" = yes ]; then
    case $PM in
        apt-get) run apt-get update || failed 'APT index refresh' ;;
        dnf|yum) run "$PM" makecache || failed 'RPM repository refresh' ;;
        zypper) run zypper --non-interactive refresh || failed 'Zypper repository refresh' ;;
        pacman) log 'Using existing pacman sync database; no partial -Sy refresh or OS upgrade' ;;
        apk) : ;;
    esac
fi
if [ "$CORE" = yes ]; then
    case $PM in
        apt-get) core_packages='openssh-server openssh-client libpam-modules libpam-modules-bin libpam-runtime sudo coreutils findutils grep sed gawk bash dash util-linux procps iproute2 libc6 openssl dpkg apt auditd apache2 apache2-bin nginx nginx-core' ;;
        dnf|yum) core_packages='openssh openssh-server openssh-clients pam sudo coreutils findutils grep sed gawk bash util-linux procps-ng iproute glibc openssl rpm audit httpd nginx' ;;
        zypper) core_packages='openssh openssh-server openssh-clients pam sudo coreutils findutils grep sed gawk bash util-linux procps iproute2 glibc openssl rpm audit apache2 nginx' ;;
        pacman) core_packages='openssh pam sudo coreutils findutils grep sed gawk bash util-linux procps-ng iproute2 glibc openssl pacman audit apache nginx' ;;
        apk) core_packages='openssh openssh-server openssh-client openssh-server-common linux-pam sudo busybox coreutils findutils grep sed gawk bash util-linux procps iproute2 musl openssl apk-tools audit apache2 nginx' ;;
    esac
    log 'Reinstalling installed authentication, shell, administration, runtime and web-server packages'
    for package in $core_packages; do
        if installed "$package"; then
            if reinstall_one "$package"; then SUCCESSES=$((SUCCESSES + 1))
            else failed "Core package reinstall: $package"; fi
        else skip "Core package not installed: $package"; fi
    done
fi
# Journal only our config edits so a failed Apache test can restore files/modes.
SAVED=0
save_config() {
    saved_path=$1
    case $saved_path in *'|'*|*'\'*|*'
'*) die "Unsupported configuration filename: $saved_path" ;; esac
    awk -F'|' -v p="$saved_path" '$3==p {found=1} END {exit !found}' "$RUN/config-journal" && return 0
    [ ! -L "$saved_path" ] || die "Refusing configuration symlink: $saved_path"
    SAVED=$((SAVED + 1))
    if [ -e "$saved_path" ]; then
        [ -f "$saved_path" ] || die "Not a regular configuration: $saved_path"
        cp -p "$saved_path" "$RUN/original-$SAVED" || die "Cannot preserve $saved_path"
        printf 'EXISTING|%s|%s\n' "$SAVED" "$saved_path" >> "$RUN/config-journal"
    else printf 'NEW|%s|%s\n' "$SAVED" "$saved_path" >> "$RUN/config-journal"; fi
}
put() {
    put_dest=$1
    safe_dir "${put_dest%/*}" 755
    save_config "$put_dest"
    put_tmp=${put_dest%/*}/.hunter-harden-$$.tmp
    (set -C; : > "$put_tmp") || die "Cannot stage $put_dest"
    if [ -f "$put_dest" ]; then cp -p "$put_dest" "$put_tmp" || die 'Cannot preserve file mode'
    else chmod 644 "$put_tmp"; fi
    cat > "$put_tmp" && mv -f "$put_tmp" "$put_dest" || die "Cannot install $put_dest"
}
rollback_apache() {
    log 'Restoring Apache files edited by this hardening run'
    while IFS='|' read -r saved_kind saved_n saved_file; do
        [ ! -L "$saved_file" ] || { failed "Rollback refused changed symlink: $saved_file"; continue; }
        if [ "$saved_kind" = EXISTING ]; then
            restore_tmp=${saved_file%/*}/.hunter-restore-$$.tmp
            (set -C; : > "$restore_tmp") || { failed "Cannot stage rollback: $saved_file"; continue; }
            cp -p "$RUN/original-$saved_n" "$restore_tmp" && mv -f "$restore_tmp" "$saved_file" || failed "Rollback failed: $saved_file"
        else rm -f "$saved_file" || failed "Cannot remove new config: $saved_file"; fi
    done < "$RUN/config-journal"
    # Only links absent before our a2enmod calls are listed here.
    if [ -f "$RUN/module-links-new" ]; then
        while IFS= read -r module_link; do
            [ ! -L "$module_link" ] || rm -f "$module_link" || failed "Cannot remove module link: $module_link"
        done < "$RUN/module-links-new"
    fi
}
service_active() {
    if command -v systemctl >/dev/null 2>&1 && [ -d "$(path /run/systemd/system)" ]; then systemctl is-active --quiet "$1"
    elif command -v rc-service >/dev/null 2>&1; then rc-service "$1" status >/dev/null 2>&1
    elif command -v pgrep >/dev/null 2>&1; then
        case $1 in ssh) process_name=sshd ;; *) process_name=$1 ;; esac
        pgrep -x "$process_name" >/dev/null 2>&1
    else return 1; fi
}
reload_service() {
    if command -v systemctl >/dev/null 2>&1 && [ -d "$(path /run/systemd/system)" ]; then run systemctl reload "$1"
    elif command -v rc-service >/dev/null 2>&1; then run rc-service "$1" reload
    elif command -v service >/dev/null 2>&1; then run service "$1" reload
    else return 1; fi
}

apache_harden() {
    APACHE_BIN=
    for binary in apache2ctl apachectl httpd; do
        if command -v "$binary" >/dev/null 2>&1; then APACHE_BIN=$binary; break; fi
    done
    [ -n "$APACHE_BIN" ] || { skip 'Apache is not installed'; return 0; }
    case $PM in
        apt-get) apache_packages='libapache2-mod-security2 modsecurity-crs'; apache_service=apache2; apache_fragment=$(path /etc/apache2/conf-enabled/zz-hunter-security.conf) ;;
        dnf|yum) apache_packages='mod_security mod_security_crs'; apache_service=httpd; apache_fragment=$(path /etc/httpd/conf.d/zz-hunter-security.conf) ;;
        zypper) apache_packages='apache2-mod_security2'; apache_service=apache2; apache_fragment=$(path /etc/apache2/conf.d/zz-hunter-security.conf) ;;
        pacman) apache_packages=; apache_service=httpd; apache_fragment=$(path /etc/httpd/conf/extra/hunter-security.conf) ;;
        apk) apache_packages=; apache_service=apache2; apache_fragment=$(path /etc/apache2/conf.d/zz-hunter-security.conf) ;;
    esac
    apache_was_active=no
    if service_active "$apache_service"; then apache_was_active=yes; fi
    for package in $apache_packages; do
        if install_one "$package"; then SUCCESSES=$((SUCCESSES + 1))
        else failed "Apache security package unavailable: $package"; fi
    done
    if [ "$DRY_RUN" = yes ]; then
        log "PLAN: preserve and configure $apache_fragment (ServerTokens Prod, ServerSignature Off, TraceEnable Off, nosniff header)"
        log 'PLAN: enable headers/unique_id/security2 when available; set SecRuleEngine On and SecAuditEngine RelevantOnly; verify CRS includes'
        log "PLAN: $APACHE_BIN -t; verify effective includes/modules; reload $apache_service only if already running; rollback config edits on failure"
        return 0
    fi
    : > "$RUN/module-links-new"
    if command -v a2enmod >/dev/null 2>&1; then
        # SUSE keeps its module list in this regular file instead of symlinks.
        [ ! -f "$(path /etc/sysconfig/apache2)" ] || save_config "$(path /etc/sysconfig/apache2)"
        for module in headers unique_id security2; do
            for suffix in load conf; do
                module_link=$(path "/etc/apache2/mods-enabled/$module.$suffix")
                if [ ! -e "$module_link" ] && [ ! -L "$module_link" ]; then printf '%s\n' "$module_link" >> "$RUN/module-links-new"; fi
            done
            run a2enmod "$module" || failed "Could not enable Apache module: $module"
        done
    fi
    recommended=$(path /etc/modsecurity/modsecurity.conf-recommended)
    if [ ! -e "$(path /etc/modsecurity/modsecurity.conf)" ] && [ -f "$recommended" ]; then
        put "$(path /etc/modsecurity/modsecurity.conf)" < "$recommended"
    fi
    # Retain this script's CRS loader on reruns. Otherwise seeing our already
    # loaded rules and replacing the fragment would drop the only CRS Include.
    : > "$RUN/apache-managed-crs"
    if [ -f "$apache_fragment" ] && [ ! -L "$apache_fragment" ]; then
        awk '/^[[:space:]]*Include[[:space:]]+"/ {print}' "$apache_fragment" > "$RUN/apache-managed-crs"
    fi
    : > "$RUN/apache-configs"
    for directory in /etc/modsecurity /etc/modsecurity.d /etc/httpd /etc/apache2; do
        [ ! -d "$(path "$directory")" ] || find "$(path "$directory")" -type f -name '*.conf' -print >> "$RUN/apache-configs"
    done
    while IFS= read -r config; do
        grep -E '^[[:space:]]*Sec(Rule|Audit)Engine[[:space:]]' "$config" >/dev/null || continue
        sed -e 's/^[[:space:]]*SecRuleEngine[[:space:]].*/SecRuleEngine On/' \
            -e 's/^[[:space:]]*SecAuditEngine[[:space:]].*/SecAuditEngine RelevantOnly/' "$config" > "$RUN/apache-edited"
        put "$config" < "$RUN/apache-edited"
    done < "$RUN/apache-configs"
    "$APACHE_BIN" -t -D DUMP_INCLUDES > "$RUN/apache-includes.before" 2>> "$RUN/errors.log" || :
    "$APACHE_BIN" -M > "$RUN/apache-modules" 2>> "$RUN/errors.log" || :
    waf_loaded=no
    if grep -E 'security2_module' "$RUN/apache-modules" >/dev/null; then waf_loaded=yes
    elif [ -n "$apache_packages" ]; then failed 'Apache ModSecurity v2 module was not loaded after package installation'
    else skip 'Apache ModSecurity v2 module is unavailable; applying HTTP settings only'; fi
    crs_load= crs_setup= crs_rules=
    if [ "$waf_loaded" = yes ] && ! grep -E 'REQUEST-[0-9]|modsecurity_crs_[0-9]|/rules/[^ /]+\.conf' "$RUN/apache-includes.before" >/dev/null; then
        for candidate in /usr/share/modsecurity-crs/owasp-crs.load /usr/share/modsecurity-crs/*.load /usr/share/owasp-modsecurity-crs/*.load; do
            if [ -f "$(path "$candidate")" ]; then crs_load=$candidate; break; fi
        done
        if [ -z "$crs_load" ]; then
            for directory in /usr/share/modsecurity-crs /usr/share/owasp-modsecurity-crs /etc/apache2/mod_security2; do
                if [ -d "$(path "$directory/rules")" ]; then
                    for candidate in "$directory/crs-setup.conf" "$directory/crs-setup.conf.example" /etc/modsecurity/crs/crs-setup.conf; do
                        if [ -f "$(path "$candidate")" ]; then crs_setup=$candidate; crs_rules=$directory/rules; break; fi
                    done
                    [ -z "$crs_setup" ] || break
                fi
            done
        fi
    fi
    {
        printf '# Managed by hunter-harden\nServerTokens Prod\nServerSignature Off\nTraceEnable Off\n'
        printf '<IfModule headers_module>\n    Header always set X-Content-Type-Options "nosniff"\n    Header always unset X-Powered-By\n</IfModule>\n'
        if [ "$waf_loaded" = yes ]; then
            printf '<IfModule security2_module>\n    SecRuleEngine On\n    SecAuditEngine RelevantOnly\n'
            if [ -n "$crs_load" ]; then printf '    Include "%s"\n' "$(path "$crs_load")"
            elif [ -n "$crs_setup" ]; then
                printf '    Include "%s"\n    Include "%s/*.conf"\n' "$(path "$crs_setup")" "$(path "$crs_rules")"
            else cat "$RUN/apache-managed-crs"; fi
            printf '</IfModule>\n'
        fi
    } > "$RUN/apache-fragment"
    put "$apache_fragment" < "$RUN/apache-fragment"
    # Arch includes conf/extra selectively. Add exactly one managed Include.
    if [ "$PM" = pacman ]; then
        apache_main=$(path /etc/httpd/conf/httpd.conf)
        if ! grep -F "$apache_fragment" "$apache_main" >/dev/null; then
            { cat "$apache_main"; printf '\nInclude "%s"\n' "$apache_fragment"; } > "$RUN/apache-main"
            put "$apache_main" < "$RUN/apache-main"
        fi
    fi
    if ! run "$APACHE_BIN" -t; then
        failed 'Apache configuration test; no reload attempted'
        rollback_apache; return 1
    fi
    "$APACHE_BIN" -t -D DUMP_INCLUDES > "$RUN/apache-includes.after" 2>> "$RUN/errors.log" || :
    if ! grep -F "$apache_fragment" "$RUN/apache-includes.after" >/dev/null; then
        failed 'Apache is not including the managed security configuration'
        rollback_apache; return 1
    fi
    if [ "$waf_loaded" = yes ] && ! grep -E 'REQUEST-[0-9]|modsecurity_crs_[0-9]|/rules/[^ /]+\.conf' "$RUN/apache-includes.after" >/dev/null; then
        failed 'ModSecurity is loaded but effective CRS rules were not found'
    fi
    if [ "$apache_was_active" = yes ]; then
        if ! reload_service "$apache_service"; then
            failed 'Apache reload failed; restoring edited configuration'
            rollback_apache; return 1
        fi
    else log 'Apache configured and validated; stopped service was not started'; fi
    SUCCESSES=$((SUCCESSES + 1))
    log "Apache hardened; ModSecurity loaded=$waf_loaded; effective configuration saved"
}
if [ "$APACHE" = yes ]; then apache_harden || :; fi
if [ "$CORE" = yes ]; then
    if command -v visudo >/dev/null 2>&1 && [ -f "$(path /etc/sudoers)" ]; then
        run visudo -cf "$(path /etc/sudoers)" || failed 'Sudo configuration validation'
    fi
    if command -v sshd >/dev/null 2>&1 && [ -f "$(path /etc/ssh/sshd_config)" ]; then
        if run sshd -t -f "$(path /etc/ssh/sshd_config)"; then
            if [ "$DRY_RUN" = yes ]; then log 'PLAN: reload SSH if running after successful validation'
            elif service_active sshd; then reload_service sshd || failed 'SSH reload'
            elif service_active ssh; then reload_service ssh || failed 'SSH reload'
            else log 'SSH configuration validated; no running SSH service found to reload'; fi
        else failed 'SSH configuration validation; SSH was not reloaded'; fi
    fi
fi
if [ "$DRY_RUN" = yes ]; then
    log "DRY RUN COMPLETE | planned successful operations=$SUCCESSES | failures=$FAILURES | skipped=$SKIPPED"
    exit 0
fi
log "HARDENING RESULT | successful operations=$SUCCESSES | failures=$FAILURES | skipped=$SKIPPED"
log "Report: $RUN/harden.log"
log 'Run hunter-hunt.sh again to review the result; run hunter-setup.sh --snapshot-only when ready to refresh the baseline.'
rm -f "$RUN/INCOMPLETE"
if [ "$FAILURES" -eq 0 ]; then : > "$RUN/COMPLETE"; else : > "$RUN/PARTIAL"; fi
if command -v chattr >/dev/null 2>&1; then chattr +i "$RUN/etc-before.tar" 2> "$STORE/hardening-immutable-${RUN##*/}.log" || :; fi
[ "$FAILURES" -eq 0 ]
