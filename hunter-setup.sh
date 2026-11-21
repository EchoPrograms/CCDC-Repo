#!/bin/sh
# CCDC evidence preservation and logging setup. No Python or Bash required.
PATH=/usr/sbin:/usr/bin:/sbin:/bin:/usr/local/sbin:/usr/local/bin
export PATH
LC_ALL=C
export LC_ALL
unset ENV BASH_ENV CDPATH
umask 077

usage() {
    cat <<'EOF'
Usage: sh hunter-setup.sh [options]
  --state-dir /PATH    Versioned backups and snapshots (default /.x86).
  --backup-root /PATH  Add an application/data tree; repeat as needed.
  --no-install        Use existing tools; do not contact package repositories.
  --snapshot-only     Back up and refresh snapshot without changing logging.
  --require-immutable Fail if this filesystem cannot enforce chattr +i.
  --root DIR          Offline snapshot only; never install or start services.
  --help              Show help.

Default: synchronous backups, tool installation, auditd, sudo I/O replay,
persistent system/authentication logs, SHA-256 snapshot, immutable backups only.
Each invocation creates a new version; prior versions are never unsealed.
EOF
}
die() { printf 'hunter-setup: %s\n' "$*" >&2; exit 1; }
ROOT= STATE=/.x86 EXTRA= INSTALL=yes CONFIGURE=yes REQUIRE_I=no
while [ "$#" -gt 0 ]; do
    case $1 in
        --help|-h) usage; exit 0 ;;
        --no-install) INSTALL=no; shift ;;
        --snapshot-only) CONFIGURE=no; INSTALL=no; shift ;;
        --reinstall-core|--apache-harden) die "Hardening moved to hunter-harden.sh; setup only prepares logging, tools and backups" ;;
        --require-immutable) REQUIRE_I=yes; shift ;;
        --root|--state-dir|--backup-root)
            opt=$1; [ "$#" -ge 2 ] || die "Missing value for $1"
            case $2 in /*) ;; *) die "$opt requires an absolute path" ;; esac
            case $2 in *'|'*|*'\'*|*'
'*|*'	'*) die 'Unsupported delimiter in path' ;; esac
            case $2 in *//*) die 'Use canonical paths without repeated slashes' ;; esac
            case /$2/ in */../*|*/./*) die 'Use canonical absolute paths' ;; esac
            case $opt in --root) ROOT=$2; CONFIGURE=no; INSTALL=no ;;
                --state-dir) STATE=${2%/} ;; --backup-root)
                    extra_path=${2%/}; [ -n "$extra_path" ] || die 'Backing up / is not supported'
                    EXTRA="$EXTRA
$extra_path" ;; esac
            shift 2 ;;
        *) die "Unknown option: $1" ;;
    esac
done
[ -n "$STATE" ] && [ "$STATE" != / ] || die 'State directory cannot be /'
for tool in awk cat chmod cp date df du find grep id ls mkdir mv rm rmdir sed sort tar tee tr uname wc; do
    command -v "$tool" >/dev/null 2>&1 || die "Required tool missing: $tool"
done
if [ -n "$ROOT" ]; then
    ROOT=$(CDPATH= cd -P "$ROOT" && pwd) || die 'Cannot resolve offline root'
    [ "$ROOT" != / ] || die 'Omit --root for the live system'
else
    [ "$(id -u)" = 0 ] || die 'Run setup as root (sudo sh hunter-setup.sh)'
fi
path() { printf '%s%s\n' "$ROOT" "$1"; }
inside_root() {
    [ -n "$ROOT" ] || return 0
    if command -v realpath >/dev/null 2>&1; then ir=$(realpath "$1" 2>/dev/null)
    elif command -v readlink >/dev/null 2>&1; then ir=$(readlink -f "$1" 2>/dev/null)
    else return 1; fi
    case $ir in "$ROOT"|"$ROOT"/*) return 0 ;; *) return 1 ;; esac
}
# Reject symlinked parents before writing configuration or private state.
safe_dir() {
    sd=$1
    case $sd in /*) ;; *) die "Not absolute: $sd" ;; esac
    oldifs=$IFS; IFS=/; set -f; set -- $sd; set +f; IFS=$oldifs
    sd_part=
    for sd_segment do
        [ -n "$sd_segment" ] || continue
        sd_part=$sd_part/$sd_segment
        [ ! -L "$sd_part" ] || die "Refusing symlinked directory: $sd_part"
        if [ -e "$sd_part" ]; then [ -d "$sd_part" ] || die "Not a directory: $sd_part"
        else mkdir "$sd_part" || die "Cannot create $sd_part"; fi
    done
}
STORE=$(path "$STATE")
safe_dir "$STORE"
owner=$(ls -ldn "$STORE" | awk '{print $3}')
[ "$owner" = "$(id -u)" ] || die 'State directory must belong to the invoking root/user'
chmod 700 "$STORE" || die 'Cannot protect state directory'
safe_dir "$STORE/runs"
[ ! -L "$STORE/latest" ] || die 'latest must be a regular pointer file'
mkdir "$STORE/.setup-lock" 2>/dev/null || die "Setup already running, or stale lock: $STORE/.setup-lock"
cleanup() { rmdir "$STORE/.setup-lock" 2>/dev/null || :; }
trap cleanup 0
trap 'exit 1' 1 2 15
RUN_ID=$(date -u '+%Y%m%dT%H%M%SZ')-$$
RUN=$STORE/runs/$RUN_ID
mkdir "$RUN" || die 'Cannot create run directory'
: > "$RUN/INCOMPLETE"
: > "$RUN/setup.log"
: > "$RUN/errors.log"
log() { printf '%s\n' "$*" | tr '\000-\010\013-\037\177' '?' | tee -a "$RUN/setup.log"; }
gap() { log "UNAVAILABLE: $*"; }
run() {
    log "Running: $*"
    "$@" >> "$RUN/setup.log" 2>> "$RUN/errors.log"
}
HASH=
if command -v sha256sum >/dev/null 2>&1; then HASH=sha256sum
elif command -v shasum >/dev/null 2>&1; then HASH=shasum
elif command -v openssl >/dev/null 2>&1; then HASH=openssl
else die 'SHA-256 requires sha256sum, shasum, or openssl before setup'; fi
hash() {
    case $HASH in sha256sum) sha256sum < "$1" ;; shasum) shasum -a 256 < "$1" ;;
        openssl) openssl dgst -sha256 < "$1" ;; esac | awk '{print $NF=="-" ? $1 : $NF}'
}
PM=none
# Read /etc/os-release as data, never source it. Prefer native manager by distro.
OS=
if inside_root "$(path /etc/os-release)"; then
    OS=$(awk -F= '$1=="ID" {gsub(/["\047]/,"",$2); print $2}' "$(path /etc/os-release)" 2>/dev/null)
fi
case $OS in
    opensuse*|sles|sled|suse*) command -v zypper >/dev/null 2>&1 && PM=zypper ;;
    arch|manjaro|endeavouros|artix) command -v pacman >/dev/null 2>&1 && PM=pacman ;;
    alpine) command -v apk >/dev/null 2>&1 && PM=apk ;;
esac
[ -z "$ROOT" ] || PM=offline
if [ "$PM" = none ]; then
    for manager in apt-get dnf yum zypper pacman apk; do
        if command -v "$manager" >/dev/null 2>&1; then PM=$manager; break; fi
    done
fi
printf 'format=1\nid=%s\nhost=%s\nos=%s\nmanager=%s\nroot=%s\n' \
    "$RUN_ID" "$(uname -n)" "$OS" "$PM" "${ROOT:-/}" > "$RUN/run.meta"
log "Run $RUN_ID | distro ${OS:-unknown} | package manager $PM"

# Like Snoopy's lin.sh, preserve these complete trees before package/config work.
# A tar per tree preserves permissions, hardlinks and symlinks without dereference.
printf '%s\n' /var/www /etc /home /opt /root /srv/www /srv/http /usr/local/www /usr/share/nginx/html /var/spool/cron /var/spool/at /var/spool/anacron /var/cron /var/at /var/lib/systemd/linger > "$RUN/backup-roots"
printf '%s\n' "$EXTRA" | sed '/^$/d' >> "$RUN/backup-roots"
# Discover simple absolute Apache/nginx document roots, including custom apps.
for cfgdir in /etc/apache2 /etc/httpd /etc/nginx /usr/local/etc/apache24 /usr/local/etc/nginx; do
    [ -d "$(path "$cfgdir")" ] || continue
    inside_root "$(path "$cfgdir")" || die "Outside-root config directory: $cfgdir"
    find "$(path "$cfgdir")" -type f -exec awk '
        tolower($1)=="documentroot" || tolower($1)=="root" || tolower($1)=="alias" {
            p=$2; gsub(/[";\047]/,"",p); if(p ~ /^\// && p !~ /[|\\]/) print p
        }' {} + 2>> "$RUN/errors.log" >> "$RUN/backup-roots"
done
awk '{if($0!="/") sub(/\/+$/,"",$0); print}' "$RUN/backup-roots" | sort -u > "$RUN/backup-roots.sorted"
mkdir "$RUN/backups"
: > "$RUN/backups.sha256"
tar_help=$(tar --help 2>/dev/null || :)
tar_acl= tar_xattr=
case $tar_help in *--acls*) tar_acl=--acls ;; esac
case $tar_help in *--xattrs*) tar_xattr=--xattrs ;; esac
if [ -z "$tar_acl$tar_xattr" ]; then log 'Backup format: portable tar metadata; ACL/xattr preservation unavailable in this tar'; fi
: > "$RUN/backup-selected"
while IFS= read -r logical; do
    logical=${logical%/}
    case $logical in /*) ;; *) die 'Invalid discovered backup root' ;; esac
    [ -d "$(path "$logical")" ] || continue
    case $logical in /|*//*|*/../*|*'|'*|*'\'*) die "Unsafe backup root: $logical" ;; esac
    # Never follow a source symlink or include our own version store recursively.
    [ ! -L "$(path "$logical")" ] || { gap "Symlinked backup root $logical"; continue; }
    inside_root "$(path "$logical")" || die "Outside-root backup source: $logical"
    case $STATE/ in "$logical"/*) die "State $STATE is inside backup root $logical; choose --state-dir outside that tree" ;; esac
    case $logical/ in "$STATE"/*) continue ;; esac
    printf '%s\n' "$logical" >> "$RUN/backup-selected"
done < "$RUN/backup-roots.sorted"

# Refuse an obviously undersized destination before writing large archives or
# changing logging/packages. Count each selected tree, including overlapping
# roots, because each gets its own archive. This is an estimate, not a quota:
# source growth, sparse files on portable du, and other writers can change it.
du_apparent=
case $(du --help 2>&1 || :) in *--apparent-size*) du_apparent=--apparent-size ;; esac
: > "$RUN/backup-size-estimates.txt"
while IFS= read -r logical; do
    if ! du $du_apparent -sk "$(path "$logical")" > "$RUN/du-current.txt" 2>> "$RUN/errors.log"; then
        die "Cannot estimate backup size for $logical; no archives or logging changes started. See $RUN/errors.log"
    fi
    size_kib=$(awk 'NR==1 && $1 ~ /^[0-9]+$/ {print $1}' "$RUN/du-current.txt")
    case $size_kib in ''|*[!0-9]*) die "Invalid backup size estimate for $logical" ;; esac
    printf '%s|%s\n' "$size_kib" "$logical" >> "$RUN/backup-size-estimates.txt"
done < "$RUN/backup-selected"
rm -f "$RUN/du-current.txt"
df -Pk "$RUN" > "$RUN/backup-filesystem.txt" 2>> "$RUN/errors.log" || die 'Cannot determine backup destination capacity'
available_kib=$(awk 'NR>1 && $4 ~ /^[0-9]+$/ {n++; free=$4} END {if(n==1) print free; else exit 1}' "$RUN/backup-filesystem.txt") || die 'Cannot parse backup destination capacity'
required_kib=$(awk -F'|' '{total+=$1} END {printf "%.0f\n", total*1.25+262144}' "$RUN/backup-size-estimates.txt")
printf 'estimated_required_kib=%s\navailable_kib=%s\nsize_mode=%s\n' "$required_kib" "$available_kib" "${du_apparent:-allocated-blocks}" > "$RUN/backup-capacity.txt"
log "Backup capacity estimate: required $required_kib KiB (25% margin + 256 MiB reserve), available $available_kib KiB"
if ! awk -v free="$available_kib" -v need="$required_kib" 'BEGIN {exit !(free>=need)}'; then
    die "Insufficient backup space; choose --state-dir on a larger filesystem outside the source trees. No archives or logging changes started. See $RUN/backup-capacity.txt"
fi

backup_n=0
while IFS= read -r logical; do
    backup_n=$((backup_n + 1))
    archive=$RUN/backups/$backup_n.tar
    log "Backing up $logical"
    if (cd "${ROOT:-/}" && tar $tar_acl $tar_xattr -cpf "$archive" ".${logical}") 2>> "$RUN/errors.log"; then
        printf '%s|%s|%s\n' "$logical" 0 "$backup_n.tar" >> "$RUN/backup-status.txt"
    else
        tar_status=$?
        printf '%s|%s|%s\n' "$logical" "$tar_status" "$backup_n.tar" >> "$RUN/backup-status.txt"
        die "Backup failed for $logical (tar exit $tar_status); no baseline was published. See $RUN/errors.log"
    fi
    printf '%s|%s|%s\n' "$(hash "$archive")" "$backup_n.tar" "$logical" >> "$RUN/backups.sha256"
done < "$RUN/backup-selected"

# Protect the pre-change copies before any package hooks or configuration work.
# Only the backup directory/archives receive immutable flags.
backup_sealed=no
if command -v chattr >/dev/null 2>&1 && command -v lsattr >/dev/null 2>&1; then
    if chattr -R +i "$RUN/backups" 2>> "$RUN/errors.log"; then
        find "$RUN/backups" -exec lsattr -d {} + > "$RUN/backup-attributes.txt" 2>> "$RUN/errors.log"
        if awk 'NF {n++; if($1 !~ /i/) bad=1} END {exit (!n || bad)}' "$RUN/backup-attributes.txt"; then backup_sealed=yes; fi
    fi
fi
log "Pre-change backup immutable=$backup_sealed"
if [ "$backup_sealed:$REQUIRE_I" = no:yes ]; then
    die 'Cannot seal pre-change backups; package and logging changes were not started'
fi

# Collect runtime inventory both before setup and for the published comparison.
inventory() {
    inv=$RUN/$1; mkdir "$inv"
    for file in /etc/passwd /etc/group /etc/os-release /etc/crontab /etc/anacrontab; do
        inside_root "$(path "$file")" || continue
        [ -f "$(path "$file")" ] && [ ! -L "$(path "$file")" ] && cp -p "$(path "$file")" "$inv/$(printf '%s' "$file" | tr / _)"
    done
    find "$(path /etc)" -type f -mtime -30 -print > "$inv/recent-etc.txt" 2>> "$RUN/errors.log" || :
    : > "$inv/cron-paths.txt"
    for d in /etc/crontabs /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly /var/spool/cron /var/spool/at /etc/periodic; do
        [ ! -d "$(path "$d")" ] || find "$(path "$d")" -type f -print >> "$inv/cron-paths.txt" 2>> "$RUN/errors.log"
    done
    [ -z "$ROOT" ] || return 0
    (ps -e -o pid,ppid,uid,args || ps -ef || ps) > "$inv/processes.txt" 2>> "$RUN/errors.log"
    (if command -v ss >/dev/null 2>&1; then ss -anp; elif command -v netstat >/dev/null 2>&1; then netstat -an; fi) > "$inv/sockets.txt" 2>> "$RUN/errors.log"
    if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
        systemctl --no-pager --plain list-units --type=service --all > "$inv/services.txt" 2>> "$RUN/errors.log"
        systemctl --no-pager --plain list-unit-files > "$inv/unit-files.txt" 2>> "$RUN/errors.log"
        systemctl --no-pager --plain list-timers --all > "$inv/timers.txt" 2>> "$RUN/errors.log"
    elif command -v rc-status >/dev/null 2>&1; then
        rc-status -a > "$inv/services.txt" 2>> "$RUN/errors.log"
    else ls -ld /etc/init.d/* /etc/rc.d/* /usr/local/etc/rc.d/* > "$inv/services.txt" 2>/dev/null || :; fi
    if command -v getent >/dev/null 2>&1; then
        getent passwd > "$inv/nss-passwd.txt"
        for g in root sudo wheel admin docker lxd disk; do getent group "$g" || :; done > "$inv/nss-privileged-groups.txt"
    fi
    case $PM in
        apt-get) dpkg-query -W > "$inv/packages.txt" ;;
        dnf|yum|zypper) rpm -qa > "$inv/packages.txt" ;;
        pacman) pacman -Q > "$inv/packages.txt" ;;
        apk) apk info -v > "$inv/packages.txt" ;;
    esac
    mount > "$inv/mounts.txt" 2>> "$RUN/errors.log" || :
    if command -v auditctl >/dev/null 2>&1; then auditctl -s > "$inv/audit-status.txt" 2>> "$RUN/errors.log" || :; fi
}
inventory before

package_installed() {
    case $PM in
        apt-get) dpkg-query -W '-f=${Status}\n' "$1" 2>/dev/null | grep -E '^[^ ]+ ok installed$' >/dev/null ;;
        dnf|yum|zypper) rpm -q --quiet "$1" >/dev/null 2>&1 ;;
        pacman) pacman -Q "$1" >/dev/null 2>&1 ;;
        apk) apk info -e "$1" >/dev/null 2>&1 ;;
        *) return 1 ;;
    esac
}
install_one() {
    # Preparation installs missing tools; upgrading or repairing installed
    # packages belongs to the later hardening phase.
    if package_installed "$1"; then log "Tool package already installed; keeping it unchanged: $1"; return 0; fi
    case $PM in
        apt-get) run env DEBIAN_FRONTEND=noninteractive apt-get install -y "$1" ;;
        dnf|yum) run "$PM" install -y "$1" ;;
        zypper) run zypper --non-interactive install --no-recommends "$1" ;;
        pacman) run pacman -S --noconfirm --needed "$1" ;;
        apk) run apk add --no-cache "$1" ;;
        *) return 1 ;;
    esac
}
if [ "$INSTALL" = yes ]; then
    case $PM in apt-get) run apt-get update || gap 'APT index refresh failed' ;;
        dnf|yum) run "$PM" makecache || gap 'RPM repository refresh failed' ;;
        zypper) run zypper --non-interactive refresh || gap 'Zypper refresh failed' ;;
        pacman) log 'Using existing pacman sync database; no partial -Sy refresh or full OS upgrade' ;;
        apk) : ;; *) gap 'No supported package manager' ;; esac
    case $PM in
        apt-get) packages='sudo auditd audispd-plugins acl attr e2fsprogs debsums binutils lsof libcap2-bin ripgrep rsyslog logrotate' ;;
        dnf|yum) packages='sudo audit acl attr e2fsprogs binutils lsof libcap ripgrep rsyslog logrotate' ;;
        zypper) packages='sudo audit acl attr e2fsprogs binutils lsof libcap-progs ripgrep rsyslog logrotate' ;;
        pacman) packages='sudo audit acl attr e2fsprogs binutils lsof libcap ripgrep pacutils logrotate' ;;
        apk) packages='sudo audit audit-openrc acl attr e2fsprogs-extra binutils lsof libcap-utils ripgrep rsyslog rsyslog-openrc logrotate' ;;
        *) packages= ;;
    esac
    for package in $packages; do install_one "$package" || gap "Package $package could not be installed from configured repositories"; done
fi
# Write a complete owned file through a private temporary file, then atomic rename.
put() {
    dest=$(path "$1"); parent=${dest%/*}
    safe_dir "$parent"
    [ ! -L "$dest" ] || die "Refusing configuration symlink: $dest"
    [ ! -e "$dest" ] || [ -f "$dest" ] || die "Not a regular config: $dest"
    put_tmp=$parent/.hunter-$$.tmp
    (set -C; : > "$put_tmp") || die "Cannot stage $dest"
    # Updating logging must not tighten permissions on existing live configs.
    if [ -f "$dest" ]; then cp -p "$dest" "$put_tmp" || die "Cannot preserve metadata for $dest"
    else chmod "$2" "$put_tmp" || die "Cannot protect new logging config $dest"; fi
    cat > "$put_tmp" && mv -f "$put_tmp" "$dest" || die "Cannot install $dest"
}
start_service() {
    if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
        run systemctl enable "$1" || :
        run systemctl start "$1"
    elif command -v rc-service >/dev/null 2>&1; then
        run rc-update add "$1" default || :
        run rc-service "$1" start
    elif command -v service >/dev/null 2>&1; then run service "$1" start
    else return 1; fi
}
if [ "$CONFIGURE" = yes ]; then
    if command -v visudo >/dev/null 2>&1; then
        safe_dir /var/log/sudo-io; chmod 700 /var/log/sudo-io
        cat > "$RUN/sudoers.candidate" <<'EOF'
Defaults log_input,log_output
Defaults iolog_dir="/var/log/sudo-io"
Defaults logfile="/var/log/sudo.log"
EOF
        if run visudo -cf "$RUN/sudoers.candidate"; then
            # Ensure include exists; a validated staged main config precedes replacement.
            if ! awk '$1 ~ /^(@|#)includedir$/ && $2=="/etc/sudoers.d" {ok=1} END {exit !ok}' /etc/sudoers; then
                cat /etc/sudoers > "$RUN/sudoers.main"
                printf '\n#includedir /etc/sudoers.d\n' >> "$RUN/sudoers.main"
                run visudo -cf "$RUN/sudoers.main" || die 'Existing sudoers/include validation failed'
                put /etc/sudoers 440 < "$RUN/sudoers.main"
            fi
            put /etc/sudoers.d/99-hunter-logging 440 < "$RUN/sudoers.candidate"
            if ! run visudo -cf /etc/sudoers; then
                rm -f /etc/sudoers.d/99-hunter-logging
                die 'Combined sudo configuration failed validation; hunter drop-in removed'
            fi
            log 'Sudo terminal input/output logging enabled; replay with: sudoreplay -l'
        else gap 'Installed sudo does not support requested I/O logging'; fi
    else gap 'sudo/visudo/sudoreplay not installed'; fi

    if command -v auditctl >/dev/null 2>&1 && [ -d /etc/audit ]; then
        : > "$RUN/audit.rules"
        arch=$(uname -m)
        case $arch in x86_64) arches='b64 b32' ;; aarch64|ppc64*|s390x|riscv64) arches=b64 ;; *) arches=b32 ;; esac
        for audit_arch in $arches; do
            printf '%s\n' "-a always,exit -F arch=$audit_arch -S execve -F euid=0 -k hunter_root_exec" >> "$RUN/audit.rules"
            printf '%s\n' "-a always,exit -F arch=$audit_arch -S execve -F auid>=1000 -F auid!=4294967295 -k hunter_user_exec" >> "$RUN/audit.rules"
            printf '%s\n' "-a always,exit -F arch=$audit_arch -S execve -F auid=4294967295 -k hunter_service_exec" >> "$RUN/audit.rules"
            for watch in /etc/passwd /etc/shadow /etc/group /etc/gshadow /etc/sudoers /etc/sudoers.d /etc/ssh /etc/pam.d /etc/crontab /etc/crontabs /etc/cron.d /var/spool/cron /etc/systemd /etc/init.d /etc/profile /etc/profile.d /etc/ld.so.preload /etc/ld.so.conf.d /etc/audit /lib/modules /root/.ssh /home /var/www /srv/www /srv/http /opt "$STATE"; do
                [ -e "$watch" ] || continue
                if [ -d "$watch" ]; then field=dir; else field=path; fi
                printf '%s\n' "-a always,exit -F arch=$audit_arch -F $field=$watch -F perm=wa -k hunter_persistence" >> "$RUN/audit.rules"
            done
            printf '%s\n' "-a always,exit -F arch=$audit_arch -S init_module,finit_module,delete_module -k hunter_modules" >> "$RUN/audit.rules"
        done
        put /etc/audit/rules.d/70-hunter.rules 600 < "$RUN/audit.rules"
        if command -v augenrules >/dev/null 2>&1; then run augenrules || gap 'Persistent audit rules could not compile'
        else
            if [ -f /etc/audit/audit.rules ]; then
                awk '/^# BEGIN HUNTER$/ {skip=1; next} /^# END HUNTER$/ {skip=0; next} !skip {print}' /etc/audit/audit.rules > "$RUN/audit.combined"
            else : > "$RUN/audit.combined"; fi
            { printf '# BEGIN HUNTER\n'; cat "$RUN/audit.rules"; printf '# END HUNTER\n'; } >> "$RUN/audit.combined"
            put /etc/audit/audit.rules 600 < "$RUN/audit.combined"
        fi
        # Keep existing auditd options; set bounded rotation and syslog alerts.
        if [ -f /etc/audit/auditd.conf ]; then
            awk '
                /^[[:space:]]*(max_log_file|max_log_file_action|num_logs|space_left_action|disk_full_action|disk_error_action)[[:space:]]*=/ {next}
                {print}
                END {print "max_log_file = 64\nnum_logs = 8\nmax_log_file_action = ROTATE\nspace_left_action = SYSLOG\ndisk_full_action = SYSLOG\ndisk_error_action = SYSLOG"}
            ' /etc/audit/auditd.conf > "$RUN/auditd.conf"
            put /etc/audit/auditd.conf 600 < "$RUN/auditd.conf"
        fi
        start_service auditd || gap 'auditd service could not start (check kernel/container audit support)'
        run auditctl --signal reload || run service auditd reload || gap 'auditd rotation configuration will apply at next start'
        # Load only our rules; never delete other teams' rules or set audit immutable.
        # Remove an exact prior owned rule set before loading to make reruns work.
        if run auditctl -s; then
            auditctl -l > "$RUN/audit.active" 2>> "$RUN/errors.log"
            awk '/-k hunter_(root_exec|user_exec|service_exec|persistence|modules)( |$)|key=hunter_(root_exec|user_exec|service_exec|persistence|modules)( |$)/ {sub(/^-a /,"-d "); print}' "$RUN/audit.active" > "$RUN/audit.remove"
            if [ -s "$RUN/audit.remove" ]; then run auditctl -R "$RUN/audit.remove" || gap 'Could not replace prior hunter audit rules'; fi
            run auditctl -R /etc/audit/rules.d/70-hunter.rules || gap 'Kernel audit rules could not load; persistent rules saved for boot'
        else gap 'Kernel audit access unavailable; persistent audit rules saved'; fi
    else gap 'Linux audit tooling/configuration unavailable on this OS'; fi

    if command -v journalctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
        put /etc/systemd/journald.conf.d/70-hunter.conf 644 <<'EOF'
[Journal]
Storage=persistent
Compress=yes
SystemMaxUse=512M
SystemKeepFree=256M
MaxRetentionSec=30day
EOF
        safe_dir /var/log/journal
        run systemctl restart systemd-journald || gap 'journald restart failed'
        run journalctl --flush || gap 'Journal flush failed'
    fi
    if command -v rsyslogd >/dev/null 2>&1; then
        cat > "$RUN/rsyslog.candidate" <<'EOF'
auth,authpriv.* /var/log/hunter-auth.log
cron.* /var/log/hunter-cron.log
daemon.warning /var/log/hunter-daemon.log
EOF
        # Append an include only if the distro does not already load drop-ins.
        if [ -f /etc/rsyslog.conf ] && grep -q 'rsyslog.d' /etc/rsyslog.conf; then
            put /etc/rsyslog.d/70-hunter.conf 600 < "$RUN/rsyslog.candidate"
            if run rsyslogd -N1; then
                if [ -d /run/systemd/system ]; then run systemctl restart rsyslog || gap 'rsyslog restart failed'
                elif command -v rc-service >/dev/null 2>&1; then run rc-service rsyslog restart || gap 'rsyslog restart failed'
                else start_service rsyslog || gap 'rsyslog start failed'; fi
            else rm -f /etc/rsyslog.d/70-hunter.conf; gap 'rsyslog config rejected; hunter drop-in removed'; fi
        else gap 'rsyslog has no drop-in include; existing syslog configuration preserved'; fi
    elif command -v rc-service >/dev/null 2>&1; then
        start_service syslog || gap 'OpenRC syslog could not start'
    fi
    if command -v sshd >/dev/null 2>&1 && [ -f /etc/ssh/sshd_config ]; then
        # Prepend so OpenSSH first-value semantics beat later LogLevel/Match blocks.
        { printf '# hunter authentication logging\nLogLevel VERBOSE\n'
          awk '/^# hunter authentication logging$/ {skip=1; next} skip && /^LogLevel VERBOSE$/ {skip=0; next} {skip=0; print}' /etc/ssh/sshd_config
        } > "$RUN/sshd.candidate"
        if run sshd -t -f "$RUN/sshd.candidate"; then
            put /etc/ssh/sshd_config 600 < "$RUN/sshd.candidate"
            if [ -d /run/systemd/system ]; then
                run systemctl reload sshd || run systemctl reload ssh || gap 'SSH config saved; reload unavailable'
            elif command -v rc-service >/dev/null 2>&1; then run rc-service sshd reload || gap 'SSH reload unavailable'
            else run service sshd reload || run service ssh reload || gap 'SSH reload unavailable'; fi
        else gap 'SSH logging candidate rejected; existing config preserved'; fi
    fi
    put /etc/logrotate.d/hunter 600 <<'EOF'
/var/log/sudo.log /var/log/hunter-auth.log /var/log/hunter-cron.log /var/log/hunter-daemon.log {
    daily
    rotate 14
    size 32M
    missingok
    notifempty
    compress
    delaycompress
    copytruncate
    create 0600 root root
}
EOF
fi

log 'Recording SHA-256, ownership, permissions, symlinks and privileged file metadata'
inventory after
# Files covered: all configs, executables/libraries, user/application/web trees,
# service/cron state. Logs, caches, proc/sys/dev and old backups are excluded.
printf '%s\n' /etc /bin /sbin /lib /lib64 /usr/bin /usr/sbin /usr/lib /usr/lib64 /usr/local /root /home /opt /var/www /srv /var/spool/cron /var/spool/at /var/lib/systemd > "$RUN/hash-roots"
cat "$RUN/backup-roots.sorted" >> "$RUN/hash-roots"
printf '%s\n' "$EXTRA" | sed '/^$/d' >> "$RUN/hash-roots"
: > "$RUN/paths"
while IFS= read -r logical; do
    tree=$(path "$logical"); [ -d "$tree" ] || continue
    # Following just a top-level /usr-merge alias is safe; nested symlinks stay links.
    if [ -n "$ROOT" ] && [ -L "$tree" ]; then continue; fi
    inside_root "$tree" || { gap "Outside-root hash tree: $logical"; continue; }
    find "$tree/." -xdev \( -path "$STORE" -o -path '*/.ansible/tmp' \) -prune -o \( -type f -o -type l \) -print 2>> "$RUN/errors.log" | sed 's|/\./|/|g' >> "$RUN/paths"
done < "$RUN/hash-roots"
sort -u "$RUN/paths" > "$RUN/paths.sorted"
: > "$RUN/manifest.sha256"
: > "$RUN/metadata.txt"
while IFS= read -r file; do
    case $file in *'|'*|*'\'*) gap "Unsupported filename omitted from manifest: $file"; continue ;; esac
    logical=${file#"$ROOT"}
    is_link=no
    if [ -L "$file" ]; then is_link=yes; else [ -f "$file" ] || continue; fi
    # Resolve parent directories in offline mode before reading any file bytes.
    if [ -n "$ROOT" ] && [ "$is_link" = no ]; then
        if command -v realpath >/dev/null 2>&1; then resolved=$(realpath "$file" 2>/dev/null)
        else resolved=$(readlink -f "$file" 2>/dev/null); fi
        case $resolved in "$ROOT"/*) ;; *) gap "Outside-root path skipped: $file"; continue ;; esac
    fi
    fields=$(ls -ldn "$file" 2>> "$RUN/errors.log" | awk '{print $1 "|" $3 "|" $4}')
    if [ "$is_link" = yes ]; then
        ls -ldn "$file" >> "$RUN/metadata.txt"
        readlink "$file" > "$RUN/link-target" || { gap "Cannot read link $file"; continue; }
        digest=$(hash "$RUN/link-target" 2>> "$RUN/errors.log")
    else digest=$(hash "$file" 2>> "$RUN/errors.log"); fi
    case $digest in ''|*[!0-9a-fA-F]*) gap "Hash failed: $file"; continue ;; esac
    [ "${#digest}" -eq 64 ] || { gap "Invalid hash: $file"; continue; }
    printf '%s|%s|%s\n' "$digest" "$fields" "$logical" >> "$RUN/manifest.sha256"
done < "$RUN/paths.sorted"
rm -f "$RUN/link-target"
if command -v getcap >/dev/null 2>&1; then
    : > "$RUN/capabilities.txt"
    while IFS= read -r logical; do
        inside_root "$(path "$logical")" || continue
        [ ! -d "$(path "$logical")" ] || getcap -r "$(path "$logical")" >> "$RUN/capabilities.txt" 2>> "$RUN/errors.log"
    done < "$RUN/hash-roots"
fi
if command -v getfacl >/dev/null 2>&1; then
    for logical in /etc /root /var/www /home; do
        inside_root "$(path "$logical")" || continue
        [ ! -d "$(path "$logical")" ] || getfacl -R -n "$(path "$logical")" 2>> "$RUN/errors.log"
    done > "$RUN/acls.txt"
fi
rm -f "$RUN/INCOMPLETE"
printf 'completed=%s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" > "$RUN/COMPLETE"
log "Snapshot files: $(wc -l < "$RUN/manifest.sha256") | backups: $backup_n"
log "Saved run: $RUN"
# Retry backup protection now that attribute utilities may have been installed.
# Manifests, logs, live configs and the rest of the run remain mutable.
sealed=yes
if command -v chattr >/dev/null 2>&1 && command -v lsattr >/dev/null 2>&1; then
    if ! chattr -R +i "$RUN/backups" 2> "$STORE/immutable-$RUN_ID.log"; then sealed=no; fi
    find "$RUN/backups" -exec lsattr -d {} + > "$STORE/immutable-$RUN_ID.txt" 2>> "$STORE/immutable-$RUN_ID.log" || sealed=no
    awk 'NF {n++; if($1 !~ /i/) bad=1} END {exit (!n || bad)}' "$STORE/immutable-$RUN_ID.txt" || sealed=no
else sealed=no; fi
if [ "$sealed" = no ]; then
    printf 'hunter-setup: Immutable flag unavailable for some/all backup files; details: %s/immutable-%s.log\n' "$STORE" "$RUN_ID" >&2
    [ "$REQUIRE_I" = no ] || die 'Immutable protection required; latest baseline not updated'
fi
printf '%s\n' "$RUN_ID" > "$STORE/.latest-$$"
mv -f "$STORE/.latest-$$" "$STORE/latest" || die 'Cannot publish latest snapshot'
printf 'hunter-setup: COMPLETE | baseline %s | backup_immutable=%s\n' "$RUN_ID" "$sealed"
printf 'hunter-setup: Preparation complete. Run hunter-hunt.sh only when the hunt phase begins (state-dir %s).\n' "$STATE"
