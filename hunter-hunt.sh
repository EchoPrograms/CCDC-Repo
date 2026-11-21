#!/bin/sh
# CCDC persistence triage. POSIX shell; no target scripts are executed.
# Source: https://matheuzsecurity.github.io/hacking/linux-threat-hunting-persistence/
# Read README.md for scope, limitations, and report interpretation.

PATH=/usr/sbin:/usr/bin:/sbin:/bin:/usr/local/sbin:/usr/local/bin
export PATH
LC_ALL=C
export LC_ALL
unset ENV BASH_ENV CDPATH
umask 077

usage() {
    cat <<'USAGE'
Usage: sh hunter-hunt.sh [-o REPORT] [--root DIR] [--scan-root /PATH]
                         [--web-root /PATH] [--state-dir /PATH] [--baseline FILE]

Read-only persistence triage, with a private report and severity-ordered output.
  -o, --output FILE  Create FILE exclusively (never overwrite). Default: ./ccdc-hunt-*.txt
  --root DIR        Inspect a mounted filesystem; disable live-host commands.
                    Paths in the following options are relative to this root.
  --scan-root PATH  Also search this filesystem for SUID, libraries, modules and ACLs.
                    Repeat for extra mounts. Each search stays on one filesystem.
  --web-root PATH   Also search this web tree recursively. May be repeated.
  --state-dir PATH  Setup snapshot/backup store to exclude (default /.x86).
  --baseline FILE   Compare to this setup manifest (otherwise use latest).
  --color MODE      auto (default), always, or never. Reports stay plain text.
  --install-tools   Install missing scanning tools using native repositories.
  -h, --help        Show help.

Use root for visibility. No repairs, service changes, or payload execution.
Exit: 0 = completed (findings may exist), 1 = failure/interrupted, 2 = usage error.
USAGE
}
fail() { printf 'ccdc-hunt: %s\n' "$*" >&2; exit 1; }
badarg() { printf 'ccdc-hunt: %s\n' "$*" >&2; exit 2; }
ROOT= OUTPUT= EXTRA_SCAN= EXTRA_WEB= OFFLINE=no STATE=/.x86 BASELINE= COLOR=auto INSTALL_TOOLS=no
while [ "$#" -gt 0 ]; do
    case $1 in
        -h|--help) usage; exit 0 ;;
        --install-tools) INSTALL_TOOLS=yes; shift ;;
        --color)
            [ "$#" -ge 2 ] || badarg 'Missing color mode'
            case $2 in auto|always|never) COLOR=$2 ;; *) badarg 'Color must be auto, always, or never' ;; esac
            shift 2 ;;
        -o|--output|--root|--scan-root|--web-root|--state-dir|--baseline)
            opt=$1
            [ "$#" -ge 2 ] && [ -n "$2" ] || badarg "Missing value for $1"
            case $2 in *'
'*|*'\'*|*'|'*) badarg 'Paths must not contain newlines, backslashes or |' ;; esac
            case $opt in
                -o|--output) OUTPUT=$2 ;;
                --root) ROOT=$2; OFFLINE=yes ;;
                --state-dir) case $2 in /*) STATE=${2%/} ;; *) badarg 'State directory must be absolute' ;; esac ;;
                --baseline) BASELINE=$2 ;;
                --scan-root|--web-root)
                    case $2 in /*) ;; *) badarg "$opt needs an absolute target path" ;; esac
                    case /$2/ in */../*) badarg 'Parent path components are not supported' ;; esac
                    if [ "$opt" = --scan-root ]; then EXTRA_SCAN="$EXTRA_SCAN
$2"; else EXTRA_WEB="$EXTRA_WEB
$2"; fi ;;
            esac
            shift 2 ;;
        *) badarg "Unknown option: $1 (try --help)" ;;
    esac
done
[ -n "$STATE" ] && [ "$STATE" != / ] || badarg 'State directory cannot be /'
case /$STATE/ in */../*) badarg 'Parent path components are not supported' ;; esac
[ "$INSTALL_TOOLS:$OFFLINE" != yes:yes ] || badarg 'Tool installation requires the live system'
for tool in awk cat cksum date find grep id ls mkdir rm sed sort tr uname wc; do
    command -v "$tool" >/dev/null 2>&1 || fail "Required standard utility is missing: $tool"
done
if [ "$OFFLINE" = yes ]; then
    [ -d "$ROOT" ] || badarg 'The inspection root must be a directory'
    ROOT=$(CDPATH= cd -P "$ROOT" && pwd) || fail 'Cannot resolve inspection root'
    [ "$ROOT" != / ] || badarg 'Omit --root to inspect the live system'
fi
HOST=$(uname -n 2>/dev/null | tr -c 'A-Za-z0-9._\n-' '_')
STAMP=$(date -u '+%Y%m%dT%H%M%SZ')
[ -n "$OUTPUT" ] || OUTPUT="./ccdc-hunt-$HOST-$STAMP-$$.txt"
case $OUTPUT in /*) ;; *) OUTPUT="$(pwd)/$OUTPUT" ;; esac
[ ! -e "$OUTPUT" ] && [ ! -L "$OUTPUT" ] || fail "Refusing to overwrite: $OUTPUT"
# Keep the exclusively created report open; never reopen it by pathname.
set -C
exec 3> "$OUTPUT"
set +C
TMPBASE=${TMPDIR:-/tmp}
case $TMPBASE in /*) ;; *) TMPBASE=/tmp ;; esac
WORK=
i=0
while [ "$i" -lt 30 ]; do
    candidate="$TMPBASE/ccdc-hunt-$STAMP-$$-$i"
    if mkdir "$candidate" 2>/dev/null; then WORK=$candidate; break; fi
    i=$((i + 1))
done
[ -n "$WORK" ] || fail 'Cannot create a private working directory'
for part in 1 2 3 4 5 evidence coverage errors seen; do : > "$WORK/$part"; done
FINISHED=no
clean_text() { tr '\000-\010\013-\037\177' '?'; }
# Rank buckets avoid reliance on nonportable sort options or shell arrays.
emit() {
    case $1 in CRITICAL) rank=1 ;; HIGH) rank=2 ;; MEDIUM) rank=3 ;; LOW) rank=4 ;; *) rank=5 ;; esac
    {
        printf '[%s] %s\n' "$1" "$2"
        printf '  Location: %s\n  Evidence: %s\n  Action: %s\n\n' "$3" "$4" "$5"
    } | clean_text >> "$WORK/$rank"
}
note() { printf '%s: %s\n' "$1" "$2" | clean_text >> "$WORK/coverage"; }
progress() { printf 'ccdc-hunt: %s\n' "$*" >&2; }
evidence() { printf '\n--- %s ---\n' "$*" | clean_text >> "$WORK/evidence"; }
finish() {
    [ "$FINISHED" = no ] || return
    FINISHED=yes
    if [ -s "$WORK/errors" ]; then
        emit MEDIUM 'Incomplete visibility' 'Collection errors' \
            'Some reads or commands failed; see COLLECTION ERRORS in the saved report.' \
            'Rerun with appropriate privileges and review each failure. Missing evidence is not a clean result.'
    fi
    {
        printf '\nCCDC persistence triage — %s\n' "$1"
        printf 'Host: %s | UTC: %s | UID: %s | Root: %s\n' "$HOST" "$STAMP" "$(id -u)" "${ROOT:-/}"
        printf 'Report: %s\n' "$OUTPUT"
        printf 'Priority: CRITICAL > HIGH > MEDIUM > LOW > INFO. Findings are triage leads, not proof.\n'
        for sev in 1 2 3 4 5; do
            n=$(awk '/^\[(CRITICAL|HIGH|MEDIUM|LOW|INFO)\]/ {n++} END {print n+0}' "$WORK/$sev")
            case $sev in 1) label=CRITICAL ;; 2) label=HIGH ;; 3) label=MEDIUM ;; 4) label=LOW ;; 5) label=INFO ;; esac
            printf '%s=%s ' "$label" "$n"
        done
        printf '\n\n'
        for sev in 1 2 3 4 5; do cat "$WORK/$sev"; done
        printf 'CHECK COVERAGE\n'
        cat "$WORK/coverage"
    } | clean_text > "$WORK/summary"
    cat "$WORK/summary" >&3 || fail 'Cannot write report (check disk space)'
    printf '\nDETAILED EVIDENCE (config excerpts capped at 100 active lines per file)\n' >&3 || fail 'Cannot write report'
    cat "$WORK/evidence" >&3 || fail 'Cannot write evidence to report'
    if [ -s "$WORK/errors" ]; then
        printf '\nCOLLECTION ERRORS\n' >&3
        clean_text < "$WORK/errors" >&3
    fi
    if [ "$COLOR" = always ] || { [ "$COLOR" = auto ] && [ -t 1 ] && [ -z "${NO_COLOR:-}" ] && [ "${TERM:-dumb}" != dumb ]; }; then
        awk 'BEGIN {esc=sprintf("%c",27)}
             /^\[CRITICAL\]/ {print esc "[1;91m" $0 esc "[0m"; next}
             /^\[HIGH\]/ {print esc "[1;31m" $0 esc "[0m"; next}
             /^\[MEDIUM\]/ {print esc "[1;33m" $0 esc "[0m"; next}
             /^\[LOW\]/ {print esc "[36m" $0 esc "[0m"; next}
             /^\[INFO\]/ {print esc "[34m" $0 esc "[0m"; next}
             {print}' "$WORK/summary"
    else cat "$WORK/summary"; fi
    exec 3>&-
}
trap 'rm -rf "$WORK"' 0
trap 'finish INTERRUPTED; exit 1' 1 2 15
printf 'CCDC report started %s. If no completion summary follows, collection did not finish.\n' "$STAMP" >&3
printf 'Source: https://matheuzsecurity.github.io/hacking/linux-threat-hunting-persistence/\n' >&3

# Prefix a path without evaluating it. No chroot, eval, sourcing, or ldd.
path() { printf '%s%s\n' "$ROOT" "$1"; }
# Offline inspection deliberately rejects symlinks resolving outside the mounted root.
# readlink -f is optional: without it offline symlinks are skipped explicitly.
readable() {
    [ -f "$1" ] || return 1
    if [ "$OFFLINE" = yes ]; then
        resolved=
        if command -v realpath >/dev/null 2>&1; then
            resolved=$(realpath "$1" 2>/dev/null)
        elif command -v readlink >/dev/null 2>&1; then
            resolved=$(readlink -f "$1" 2>/dev/null)
        fi
        if [ -n "$resolved" ]; then
            case $resolved in "$ROOT"/*) ;; *) printf 'Outside-root symlink skipped: %s\n' "$1" >> "$WORK/errors"; return 1 ;; esac
        else
            # Parent symlinks cannot be validated with test -L alone.
            printf 'Offline path could not be resolved safely: %s\n' "$1" >> "$WORK/errors"
            return 1
        fi
    fi
    if [ ! -r "$1" ]; then printf 'Unreadable file: %s\n' "$1" >> "$WORK/errors"; return 1; fi
    return 0
}
# Literal path deduplication; filenames are data, never commands or regexes.
unseen() {
    awk -v key="$1" '$0 == key {found=1} END {exit !found}' "$WORK/seen" && return 1
    printf '%s\n' "$1" >> "$WORK/seen"
}
# POSIX find, including symlinked configuration files. No GNU -printf/-regex/-perm /4000.
list_tree() {
    [ -d "$1" ] || return 0
    if [ "$OFFLINE" = yes ]; then
        if command -v realpath >/dev/null 2>&1; then
            tree_resolved=$(realpath "$1" 2>/dev/null)
        elif command -v readlink >/dev/null 2>&1; then
            tree_resolved=$(readlink -f "$1" 2>/dev/null)
        else tree_resolved=; fi
        case $tree_resolved in "$ROOT"|"$ROOT"/*) ;; *)
            printf 'Unresolvable/outside-root directory skipped: %s\n' "$1" >> "$WORK/errors"; return 1 ;;
        esac
    fi
    find "$1/." -xdev \( -path "$(path "$STATE")" -o -path '*/.ansible/tmp' -o -path "$WORK" -o -path "$OUTPUT" \) -prune -o \
        \( -type f -o -type l \) -print 2>> "$WORK/errors" | sed 's|/\./|/|g'
}
metadata() {
    ls -ldn "$1" 2>> "$WORK/errors" | clean_text >> "$WORK/evidence"
    if command -v sha256sum >/dev/null 2>&1; then
        printf 'SHA256 '; sha256sum < "$1" 2>> "$WORK/errors"
    elif command -v shasum >/dev/null 2>&1; then
        printf 'SHA256 '; shasum -a 256 < "$1" 2>> "$WORK/errors"
    elif command -v openssl >/dev/null 2>&1; then openssl dgst -sha256 < "$1" 2>> "$WORK/errors"
    else printf 'CRC inventory only: '; cksum "$1" 2>> "$WORK/errors"; fi | clean_text >> "$WORK/evidence"
}
fix_for() {
    case $1 in
        SSH*) printf '%s' 'Confirm key ownership from a trusted channel; remove only unapproved key entries or hooks. Keep the current root session and test a separate SSH login before ending it.' ;;
        CRON) printf '%s' 'Preserve this job and payload; remove the unapproved cron entry from its owning user/system schedule, then contain the payload.' ;;
        SHELL) printf '%s' 'Preserve the file; remove the unapproved startup command/alias and inspect every referenced script.' ;;
        APT) printf '%s' 'Remove only the unapproved APT hook after preserving it; inspect its referenced commands before the next package operation.' ;;
        SUDO) printf '%s' 'Confirm required administrators; edit the offending rule with visudo and validate before closing the current root session.' ;;
        SYSTEMD) printf '%s' 'Identify the unit/drop-in and payload; preserve evidence, then stop and disable the confirmed malicious unit in the correct system/user scope and reload that manager.' ;;
        PAM) printf '%s' 'Keep the current root session; test a second SSH login before and after any targeted PAM repair from trusted matching packages. Without console access, avoid broad authentication edits or restarts.' ;;
        MOTD|INIT|RC_LOCAL) printf '%s' 'Preserve the startup/login hook and payload; remove only the unapproved command and verify the service still works.' ;;
        LOADER) printf '%s' 'Validate the library and loader setting against trusted packages; remove only unapproved preload/audit configuration using trusted recovery tools.' ;;
        WEB) printf '%s' 'Preserve the file and access logs; quarantine confirmed webshells, patch the entry point, and rotate exposed application credentials.' ;;
        *) printf '%s' 'Preserve evidence and compare with a trusted baseline before changing the system.' ;;
    esac
}
scan_file() {
    # $1 category, $2 path. All paths come from quoted reads or fixed literals.
    readable "$2" || return
    unseen "$1|$2" || return
    bytes=$(wc -c < "$2" 2>> "$WORK/errors")
    if [ "${bytes:-0}" -gt 10485760 ]; then
        printf 'Content scan skipped (>10 MiB): %s\n' "$2" >> "$WORK/errors"
        return
    fi
    evidence "$1 $2"
    metadata "$2"
    case ${2#"$ROOT"} in /etc/*|/root/.ssh/*)
        # Symlink mode bits do not grant write access to the destination.
        # readable() has already checked containment for offline inspection.
        target_metadata=$(ls -Lldn "$2" 2>> "$WORK/errors")
        if printf '%s\n' "$target_metadata" | awk 'substr($1,6,1)=="w" || substr($1,9,1)=="w" {bad=1} END {exit !bad}'; then
            emit HIGH 'Sensitive configuration writable by group or other users' "$2" \
                "$target_metadata" 'Inspect ownership and intended administrators; remove unauthorized write permissions after preserving metadata.'
        fi ;;
    esac
    if [ "$1" != SSH_KEYS ]; then
        awk 'NF && $0 !~ /^[[:space:]]*[#;]/ {n++; if(n<=100) print NR ": " substr($0,1,700)} END {if(n>100) print "[excerpt truncated; detection scanned the entire file]"}' "$2" 2>> "$WORK/errors" | clean_text >> "$WORK/evidence"
    fi
    fix=$(fix_for "$1")
    awk -v mode="$1" '
        function hit(sev, reason) {
            if (!seen[reason]++) print sev "|" NR "|" reason "|" substr($0,1,500)
        }
        /^[[:space:]]*$/ {next}
        /^[[:space:]]*#/ && mode != "SUDO" {next}
        /^[[:space:]]*;/ && mode == "WEB_CONFIG" {next}
        {
            line=tolower($0)
            if (mode == "SSH_KEYS") {
                if ($0 !~ /^[[:space:]]*#/) keys++
                if (line ~ /command[[:space:]]*=/ && !seen["forced"]++)
                    print "MEDIUM|" NR "|SSH forced command requires approval|A command= key option is set (public key material omitted)"
                next
            }
            if (line ~ /\/dev\/(tcp|udp)\// || line ~ /socat.*(exec:|system:)/ ||
                line ~ /(^|[[:space:];|])(nc|ncat|netcat)[[:space:]].*[[:space:]]-[a-z]*[ec][[:space:]]/)
                hit("HIGH", "Reverse shell or network-to-command pattern")
            if (line ~ /(curl|wget).*[|][[:space:]]*(\/[^[:space:]]*\/)?(sh|bash|dash|ash|ksh)/ ||
                line ~ /eval.*(base64|decode|rot13)/)
                hit("HIGH", "Download-and-execute or encoded command execution")
            if (line ~ /ld_preload|ld_audit/) hit("HIGH", "Dynamic loader injection setting")
            if (mode == "LKM_STARTUP" && (line ~ /^[[:space:]]*(install|remove)[[:space:]]/ || line ~ /(^|[[:space:];|])(insmod|modprobe)[[:space:]]/))
                hit("HIGH", "Module load command or modprobe override")
            if (mode != "WEB" && line ~ /\/(tmp|var\/tmp|dev\/shm)\//)
                hit("MEDIUM", "Hook references a temporary or shared-memory path")
            if (mode == "SHELL" && line ~ /^[[:space:]]*alias[[:space:]]+(sudo|su|ssh|ls|ps|ss|netstat|find|cat)=/)
                hit("MEDIUM", "Alias overrides an administration command")
            if (mode == "APT" && line ~ /(pre|post)-invoke|pre-install-pkgs/)
                hit("MEDIUM", "APT command hook requires a baseline")
            if (mode == "PACKAGE_HOOK" && line ~ /(^|[[:space:]])(exec|command|pre_transaction|post_transaction|enabled)[[:space:]=]|^[[:space:]]*[^#[:space:]]/)
                hit("MEDIUM", "Package manager execution hook")
            if (mode == "SUDO" && line !~ /^[[:space:]]*#/ && line ~ /nopasswd[[:space:]]*:/)
                hit("HIGH", "Passwordless sudo grant requires approval")
            if (mode == "SUDO" && line !~ /^[[:space:]]*#/ && line ~ /all[[:space:]]*=[[:space:]]*\(all/)
                hit("MEDIUM", "Broad sudo administrator grant")
            if (mode == "SUDO" && line !~ /^[[:space:]]*#/ && line ~ /!authenticate|!log_input|!log_output|env_keep.*ld_(preload|audit|library_path)/)
                hit("HIGH", "Sudo authentication, replay logging or loader protection disabled")
            if (mode == "PAM" && line ~ /^[[:space:]]*auth[[:space:]]+sufficient[[:space:]]+.*pam_permit/)
                hit("CRITICAL", "PAM sufficient unconditional authentication rule")
            if (mode == "PAM" && line ~ /pam_exec\.so|pam_python\.so/)
                hit("HIGH", "PAM executes an external program or script")
            if (mode == "PAM" && line ~ /pam_exec\.so/ && line ~ /expose_authtok/)
                hit("CRITICAL", "PAM external helper receives authentication token")
            if (mode == "PAM" && line ~ /^[[:space:]]*-?auth/ && line ~ /success=done/ && line ~ /pam_permit\.so/)
                hit("CRITICAL", "PAM unconditional authentication with immediate success")
            if (mode == "PAM" && line ~ /nullok|pam_rootok\.so|pam_succeed_if\.so.*(user|uid).*(=|in)/)
                hit("MEDIUM", "PAM authentication exception or empty-password argument")
            if (mode == "PAM" && line ~ /pam_[^[:space:]]*\.so/ && line ~ /\/(tmp|home|var\/tmp|dev\/shm)\//)
                hit("CRITICAL", "PAM module referenced from a user-writable location")
            if (mode == "PAM" && line ~ /\.so([[:space:]]|$)/ && line ~ /\/(tmp|home|root|opt|var\/tmp|dev\/shm)\//)
                hit("CRITICAL", "PAM authentication library outside system module paths")
            if (mode == "SSH_CONFIG" && line ~ /^[[:space:]]*(authorizedkeyscommand|authorizedprincipalscommand|trustedusercakeys|authorizedkeysfile|authorizedprincipalsfile)[[:space:]]/)
                hit("MEDIUM", "Additional SSH authorization source; inspect referenced paths")
            if (mode == "SSH_CONFIG" && line ~ /^[[:space:]]*(permitrootlogin[[:space:]]+yes|permitemptypasswords[[:space:]]+yes|strictmodes[[:space:]]+no|permituserenvironment[[:space:]]+yes)/)
                hit("HIGH", "SSH authentication or environment protection weakened")
            if (mode == "SSH_CONFIG" && line ~ /^[[:space:]]*(authorizedkeyscommand|authorizedprincipalscommand|forcecommand)[[:space:]]/ && line ~ /\/(tmp|var\/tmp|dev\/shm|home)\//)
                hit("HIGH", "SSH authorization helper or forced command in a writable tree")
            if (mode == "SYSTEMD" && line ~ /^[[:space:]]*(execstart|execstartpre|execstartpost|execreload|execstop|environment|environmentfile)=/ && line ~ /\/(home|tmp|var\/tmp|dev\/shm)\//)
                hit("HIGH", "Systemd execution or environment from a writable tree")
            if (mode == "UDEV" && line ~ /run[+]?=|program=/)
                hit("MEDIUM", "Device event executes an external command")
            if (mode == "AUTOSTART" && line ~ /^[[:space:]]*exec=/)
                hit("MEDIUM", "Desktop autostart execution hook")
            if (mode == "WEB_CONFIG" && line ~ /^[[:space:]]*(php_(admin_)?value[[:space:]]+)?auto_(prepend|append)_file[[:space:]=]/) {
                injected=line; sub(/^.*auto_(prepend|append)_file[[:space:]=]*/,"",injected)
                sub(/[[:space:]]*;.*/,"",injected); gsub(/[[:space:]"\047]/,"",injected)
                if (injected!="" && injected!="none" && injected!="off") hit("HIGH", "Web configuration automatically injects a code file")
            }
            if (mode == "WEB_CONFIG" && line ~ /addhandler.*(php|cgi)|sethandler.*(php|cgi)/)
                hit("MEDIUM", "Web executable handler configuration")
            if (mode == "WEB") {
                if (line ~ /\$_(get|post|request|cookie)|request[.(]|req\.(query|body|params)/) input=1
                if (line ~ /(^|[^a-z_])(eval|assert|system|exec|shell_exec|passthru|popen|proc_open)[[:space:]]*\(|runtime.*exec|processbuilder|child_process/) {
                    execute=1; hit("MEDIUM", "Web code can execute commands or evaluated code")
                }
                if (line ~ /base64_decode|str_rot13|gzinflate|gzuncompress|fsockopen|pfsockopen/)
                    hit("MEDIUM", "Web obfuscation or outbound socket primitive")
            }
        }
        END {
            if (mode == "SSH_KEYS" && keys) print "MEDIUM|0|SSH authorization entries require owner approval|" keys " entries (public key material omitted)"
            if (mode == "WEB" && input && execute) print "HIGH|0|Web request input and code/command execution in the same file|Heuristic; verify data flow before quarantine"
        }
    ' "$2" 2>> "$WORK/errors" > "$WORK/matches"
    while IFS='|' read -r level line reason excerpt; do
        [ -n "$level" ] || continue
        emit "$level" "$reason" "$2:$line" "$excerpt" "$fix"
    done < "$WORK/matches"
}
scan_tree() {
    list_tree "$2" > "$WORK/tree"
    while IFS= read -r file; do scan_file "$1" "$file"; done < "$WORK/tree"
}
if [ "$(id -u)" != 0 ]; then
    emit MEDIUM 'Running without root privileges' 'Scan scope' 'Protected files and process details may be unreadable.' 'Run from a trusted root shell for complete visibility; inspect collection errors.'
fi
if [ "$OFFLINE" = yes ]; then
    note MODE 'Mounted filesystem inspection; no live processes, kernel, sockets, package commands or runtime environment are inspected.'
fi
manager=offline
if [ "$OFFLINE" = no ]; then
    manager=none
    native_os=
    if readable /etc/os-release; then native_os=$(awk -F= '$1=="ID" {gsub(/["\047]/,"",$2); print $2}' /etc/os-release); fi
    case $native_os in
        opensuse*|sles|sled|suse*) command -v zypper >/dev/null 2>&1 && manager=zypper ;;
        arch|manjaro|endeavouros|artix) command -v pacman >/dev/null 2>&1 && manager=pacman ;;
        alpine) command -v apk >/dev/null 2>&1 && manager=apk ;;
    esac
fi
if [ "$manager" = none ]; then
    for candidate in apt-get dnf yum zypper pacman apk; do
        if command -v "$candidate" >/dev/null 2>&1; then manager=$candidate; break; fi
    done
fi
case $manager in apt-get) NATIVE_BACKEND=dpkg ;; dnf|yum|zypper) NATIVE_BACKEND=rpm ;; *) NATIVE_BACKEND=$manager ;; esac
note PLATFORM "Native package manager=$manager; verification backend=$NATIVE_BACKEND"
if [ "$INSTALL_TOOLS" = yes ]; then
    [ "$(id -u)" = 0 ] || fail '--install-tools requires root'
    progress 'Installing scanning tools from configured native repositories'
    evidence "Requested scanning-tool installation: $manager"
    case $manager in
        apt-get) tools='acl attr binutils lsof libcap2-bin debsums ripgrep'; apt-get update >> "$WORK/evidence" 2>> "$WORK/errors" ;;
        dnf|yum) tools='acl attr binutils lsof libcap ripgrep' ;;
        zypper) tools='acl attr binutils lsof libcap-progs ripgrep' ;;
        pacman) tools='acl attr binutils lsof libcap pacutils ripgrep' ;;
        apk) tools='acl attr binutils lsof libcap-utils ripgrep' ;;
        *) tools=; note INSTALL 'No supported package manager found' ;;
    esac
    for package in $tools; do
        case $manager in
            apt-get) env DEBIAN_FRONTEND=noninteractive apt-get install -y "$package" ;;
            dnf|yum) "$manager" install -y "$package" ;;
            zypper) zypper --non-interactive install --no-recommends "$package" ;;
            pacman) pacman -S --noconfirm --needed "$package" ;;
            apk) apk add --no-cache "$package" ;;
        esac >> "$WORK/evidence" 2>> "$WORK/errors" || note INSTALL "Could not install $package"
    done
fi
progress 'Checking accounts, SSH authorization, shell startup and schedules'
PASSWD=$(path /etc/passwd)
if readable "$PASSWD"; then
    awk -F: '$3==0 && $1!="root" {print $1}' "$PASSWD" > "$WORK/uid0"
    while IFS= read -r account; do
        emit CRITICAL 'Additional UID 0 account' "$PASSWD" "$account has UID 0" 'Confirm the competition baseline; lock an unapproved account, revoke its access, and investigate its activity before deleting evidence.'
    done < "$WORK/uid0"
    awk -F: '$6 ~ /^\// {print $1 "|" $6}' "$PASSWD" > "$WORK/homes"
else
    printf 'Cannot inspect account database: %s\n' "$PASSWD" >> "$WORK/errors"
    : > "$WORK/homes"
fi
# Also inspect orphaned conventional home directories, absent from passwd.
for home in "$(path /root)" "$(path /home)"/* "$(path /Users)"/* "$(path /var/root)"; do
    [ -d "$home" ] || continue
    logical=${home#"$ROOT"}
    printf '?|%s\n' "$logical" >> "$WORK/homes"
done
sort -u "$WORK/homes" > "$WORK/homes.sorted"
while IFS='|' read -r account homedir; do
    case $homedir in /*) ;; *) continue ;; esac
    case /$homedir/ in */../*) printf 'Invalid home path skipped: %s\n' "$homedir" >> "$WORK/errors"; continue ;; esac
    home=$(path "$homedir")
    for file in "$home/.ssh/authorized_keys" "$home/.ssh/authorized_keys2" "$home/.ssh/rc" "$home/.ssh/environment"; do
        case $file in */authorized_keys*) scan_file SSH_KEYS "$file" ;; *) scan_file SSH_CONFIG "$file" ;; esac
    done
    for suffix in .profile .bashrc .bash_profile .bash_login .bash_logout .zshrc .zprofile .zshenv .zlogin .kshrc .login .cshrc .xinitrc .xsession .xprofile; do scan_file SHELL "$home/$suffix"; done
    scan_tree SYSTEMD "$home/.config/systemd/user"
    scan_tree SYSTEMD "$home/.local/share/systemd/user"
    scan_tree AUTOSTART "$home/.config/autostart"
    scan_tree SHELL "$home/.config/environment.d"
done < "$WORK/homes.sorted"
scan_file SSH_CONFIG "$(path /etc/ssh/sshd_config)"
scan_file SSH_CONFIG "$(path /etc/ssh/sshrc)"
scan_tree SSH_CONFIG "$(path /etc/ssh/sshd_config.d)"
note SSH 'Checked passwd and conventional homes, authorized_keys/authorized_keys2, SSH rc/environment, and server configuration. Custom key paths, Include targets, CA keys and command-backed keys need review when configured; private keys are never printed.'
for file in /etc/profile /etc/bashrc /etc/bash.bashrc /etc/zshrc /etc/zprofile /etc/zshenv /etc/csh.cshrc /etc/csh.login /etc/environment; do scan_file SHELL "$(path "$file")"; done
scan_tree SHELL "$(path /etc/profile.d)"
scan_tree SHELL "$(path /etc/zsh)"
note SHELL 'Checked system/user shell startup files, aliases and loader variables.'
for file in /etc/crontab /etc/anacrontab; do scan_file CRON "$(path "$file")"; done
for dir in /etc/crontabs /etc/periodic /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly /var/spool/cron /var/spool/anacron /var/cron /var/spool/at /var/at; do scan_tree CRON "$(path "$dir")"; done
note CRON 'Checked system schedules, periodic directories, cron spools and at-job spools. Existing jobs are preserved in evidence, including jobs with no heuristic hit.'
scan_file APT "$(path /etc/apt/apt.conf)"
scan_tree APT "$(path /etc/apt/apt.conf.d)"
if [ -d "$(path /etc/apt)" ]; then note APT 'Checked apt.conf and apt.conf.d hooks.'; else note APT 'NOT PRESENT: no /etc/apt on this target.'; fi
for dir in /etc/pacman.d/hooks /usr/share/libalpm/hooks /etc/apk/commit_hooks.d /etc/zypp/plugins /usr/lib/zypp/plugins /etc/yum/pluginconf.d /etc/dnf/plugins /etc/dnf/plugins/post-transaction-actions.d; do scan_tree PACKAGE_HOOK "$(path "$dir")"; done
note PACKAGE_HOOKS 'Checked APT, pacman/ALPM, APK, DNF/YUM and zypp execution/plugin hooks.'
for dir in /etc/udev/rules.d /usr/lib/udev/rules.d; do scan_tree UDEV "$(path "$dir")"; done
scan_tree AUTOSTART "$(path /etc/xdg/autostart)"
for dir in /etc/environment.d /usr/lib/environment.d /etc/modules-load.d /etc/modprobe.d; do scan_tree INIT "$(path "$dir")"; done
scan_file INIT "$(path /etc/inittab)"
scan_tree INIT "$(path /etc/local.d)"
scan_tree INIT "$(path /etc/conf.d)"
scan_tree INIT "$(path /etc/runlevels)"
scan_file SUDO "$(path /etc/sudoers)"
scan_tree SUDO "$(path /etc/sudoers.d)"
GROUP=$(path /etc/group)
if readable "$GROUP"; then
    evidence 'Privileged group membership'
    awk -F: '$1 ~ /^(root|wheel|sudo|admin|adm|docker|lxd|disk)$/ {print}' "$GROUP" | clean_text >> "$WORK/evidence"
    members=$(awk -F: '$1 ~ /^(wheel|sudo|admin|docker|lxd|disk)$/ && $4!="" {print $1 ": " $4}' "$GROUP")
    [ -z "$members" ] || emit MEDIUM 'Privileged group members require approval' "$GROUP" "$members" 'Remove only unapproved memberships; docker/lxd/disk can grant effective root access. Verify required team access first.'
fi
SHADOW=$(path /etc/shadow)
if readable "$SHADOW"; then
    awk -F: '$2=="" {print $1}' "$SHADOW" > "$WORK/empty-passwords"
    while IFS= read -r account; do emit HIGH 'Empty password field' "$SHADOW" "$account has an empty password field (no hash logged)" 'Confirm PAM policy and account requirements; lock the unapproved account or set a strong password.'; done < "$WORK/empty-passwords"
fi
note PRIVILEGE 'Checked UID 0 accounts, sudo rules, privileged group members, empty shadow password fields; filesystem SUID scan follows.'

progress 'Checking service managers, PAM, loader configuration and boot/login hooks'
for dir in /etc/systemd/system /lib/systemd/system /usr/lib/systemd/system /usr/local/lib/systemd/system /run/systemd/system /run/systemd/transient /run/systemd/generator /run/systemd/generator.early /run/systemd/generator.late /etc/systemd/user /usr/lib/systemd/user /var/lib/systemd/linger; do scan_tree SYSTEMD "$(path "$dir")"; done
for dir in "$(path /run/user)"/*/systemd; do scan_tree SYSTEMD "$dir"; done
if [ -d "$(path /etc/systemd)" ] || [ -d "$(path /usr/lib/systemd)" ]; then note SYSTEMD 'Checked system/user units, overrides, timers, runtime units, generators and linger files; unit contents are read, never executed.'; else note SYSTEMD 'NOT PRESENT: no standard systemd directories.'; fi
scan_tree PAM "$(path /etc/pam.d)"
scan_file PAM "$(path /etc/pam.conf)"
if readable "$(path /usr/include/type.h)"; then
    scan_file PAM "$(path /usr/include/type.h)"
    emit MEDIUM 'PAM-backdoor article artifact' "$(path /usr/include/type.h)" 'The article identifies this path as a possible backdoor artifact; its presence alone is not proof.' 'Inspect this header and compare PAM modules to trusted packages. Do not infer a backdoor from a string position.'
fi
note PAM 'Checked PAM configuration and the article header artifact. Module strings and available package integrity checks follow during filesystem scanning.'
for dir in /etc/init.d /etc/rc.d /etc/init /usr/local/etc/rc.d; do scan_tree INIT "$(path "$dir")"; done
for dir in "$(path /etc)"/rc[0-9S].d; do scan_tree INIT "$dir"; done
for file in /etc/rc.local /etc/rc.d/rc.local /etc/rc /etc/rc.conf /etc/rc.conf.local; do scan_file RC_LOCAL "$(path "$file")"; done
scan_tree RC_LOCAL "$(path /lib/systemd/system/rc-local.service.d)"
scan_tree RC_LOCAL "$(path /usr/lib/systemd/system/rc-local.service.d)"
note INIT 'Checked init.d, rc*.d, Upstart and BSD-style startup locations.'
note RC_LOCAL 'Checked rc.local and related systemd generator/drop-in locations.'
scan_file MOTD "$(path /etc/motd)"
scan_tree MOTD "$(path /etc/update-motd.d)"
scan_file MOTD "$(path /usr/lib/update-notifier/update-motd-updates-available)"
note MOTD 'Checked MOTD text, executable update hooks, notifier helper; filesystem discovery also finds other *motd* files.'
scan_file LOADER "$(path /etc/ld.so.preload)"
PRELOAD=$(path /etc/ld.so.preload)
if readable "$PRELOAD"; then
    preload=$(awk '{sub(/#.*/, ""); if (NF) print}' "$PRELOAD")
    [ -z "$preload" ] || emit HIGH 'System-wide dynamic loader preload' "$PRELOAD" "$preload" 'Validate every listed library against an approved baseline; preserve suspicious objects and restore loader settings with trusted tools. Legitimate preload libraries exist.'
fi
for file in "$(path /etc)"/ld*.conf; do scan_file LOADER "$file"; done
scan_tree LOADER "$(path /etc/ld.so.conf.d)"
scan_file LOADER "$(path /etc/ld-elf.so.preload)"
note LOADER 'Checked system preload and loader search configuration; shared-object paths and live process mappings/environment are inspected below. No ldd or target binary execution.'
scan_file LKM_STARTUP "$(path /etc/modules)"
for directory in /etc/modules-load.d /run/modules-load.d /usr/lib/modules-load.d /lib/modules-load.d /etc/modprobe.d /run/modprobe.d /usr/lib/modprobe.d /lib/modprobe.d; do
    scan_tree LKM_STARTUP "$(path "$directory")"
done
note LKM_STARTUP 'Inspected module load lists and modprobe overrides. A modprobe blacklist alone does not prevent direct init_module/finit_module syscalls.'
note ROOTKIT_TRUST 'Dynamic utilities can be intercepted by LD_PRELOAD; use the independently built static hunter-rootkit collector for another view. A compromised kernel can hide evidence from both. No userspace scan proves the box clean.'

# Logs on disk are useful in both live and mounted-filesystem modes.
for file in "$(path /var/log/kern.log)" "$(path /var/log)"/dmesg*; do
    readable "$file" || continue
    evidence "Kernel log indicators $file"
    case $file in *.gz|*.xz|*.bz2|*.zst)
        note KERNEL_LOG "SKIPPED compressed log: $file; inspect with trusted decompression tools."; continue ;;
    esac
    grep -i -E 'taint|out-of-tree|module verification|signature|rootkit|diamorphine|reptile' "$file" 2>> "$WORK/errors" | clean_text >> "$WORK/evidence"
    if grep -i -E 'rootkit|diamorphine|reptile|syslogk|suterusu' "$file" > /dev/null 2>> "$WORK/errors"; then
        emit HIGH 'Kernel log contains a rootkit-name indicator' "$file" 'A known rootkit name or the word rootkit appears in a kernel log; verify context.' 'Preserve logs and validate modules/kernel from a trusted baseline; a log string is an investigative lead.'
    fi
done

# Only local filesystems are discovered automatically. Explicit --scan-root adds others.
printf '%s\n' "${ROOT:-/}" > "$WORK/roots"
[ ! -d "$(path /dev/shm)" ] || path /dev/shm >> "$WORK/roots"
if [ "$OFFLINE" = no ] && [ -r /proc/self/mounts ]; then
    awk '$3 ~ /^(ext[234]|xfs|btrfs|zfs|ufs|ffs|jfs|reiserfs|overlay|squashfs|vfat|exfat|f2fs|jffs2|ubifs|tmpfs|ramfs)$/ && $2 !~ /^\/(proc|sys|dev|run)(\/|$)/ {gsub(/\\040/, " ", $2); if ($2 !~ /\\/) print $2}' /proc/self/mounts |
        while IFS= read -r mountpoint; do
            # Docker also bind-mounts individual files such as /etc/hosts.
            [ ! -d "$mountpoint" ] || printf '%s\n' "$mountpoint"
        done >> "$WORK/roots"
elif [ "$OFFLINE" = no ]; then
    note FILESYSTEMS 'Automatic extra mount discovery unavailable; / is scanned with -xdev. Add --scan-root for additional local filesystems.'
fi
printf '%s\n' "$EXTRA_SCAN" | while IFS= read -r extra; do [ -z "$extra" ] || path "$extra"; done >> "$WORK/roots"
sort -u "$WORK/roots" > "$WORK/roots.unchecked"
: > "$WORK/roots.sorted"
while IFS= read -r tree; do
    if [ "$OFFLINE" = yes ]; then
        if command -v realpath >/dev/null 2>&1; then
            resolved_tree=$(realpath "$tree" 2>/dev/null)
        elif command -v readlink >/dev/null 2>&1; then
            resolved_tree=$(readlink -f "$tree" 2>/dev/null)
        else resolved_tree=; fi
        case $resolved_tree in "$ROOT"|"$ROOT"/*) ;; *)
            printf 'Unresolvable/outside-root search root skipped: %s\n' "$tree" >> "$WORK/errors"; continue ;;
        esac
    fi
    printf '%s\n' "$tree" >> "$WORK/roots.sorted"
done < "$WORK/roots.unchecked"
# Every broad walk prunes pseudo-filesystems, our own files, and runtime trees.
walk_candidates() {
    find "$1" -xdev \( -path "$WORK" -o -path "$OUTPUT" \
        -o -path "$(path "$STATE")" -o -path "$(path /var/lib/hunter)" \
        -o -path "$(path /proc)" -o -path "$(path /sys)" -o -path "$(path /dev)" -o -path "$(path /run)" \) -prune -o \
        \( -type f -o -type l \) \( -perm -4000 -o -perm -2000 -o -name 'authorized_keys' -o -name 'authorized_keys2' \
        -o -name 'id_rsa' -o -name 'id_dsa' -o -name 'id_ecdsa' -o -name 'id_ed25519' \
        -o -name 'pam_*.so' -o -name '*.ko' -o -name '*.ko.*' -o -name '*.so' -o -name '*.so.*' -o -name '*motd*' \) -print 2>> "$WORK/errors"
}
verify_pam() {
    [ "$OFFLINE" = no ] || return
    pkg=
    if [ "${NATIVE_BACKEND:-dpkg}" = dpkg ] && command -v dpkg-query >/dev/null 2>&1 && command -v dpkg >/dev/null 2>&1; then
        pkg=$(dpkg-query -S "$1" 2>/dev/null | sed -n '1s/: \/.*//p')
        # Handle merged-/usr aliases without needing readlink -f.
        if [ -z "$pkg" ]; then
            case $1 in /lib/*|/lib64/*) pkg=$(dpkg-query -S "/usr$1" 2>/dev/null | sed -n '1s/: \/.*//p') ;; esac
        fi
        if [ -n "$pkg" ] && unseen "PKG|$pkg"; then
            evidence "PAM package verification: $pkg"
            dpkg --verify "$pkg" > "$WORK/verify" 2>> "$WORK/errors"
            clean_text < "$WORK/verify" >> "$WORK/evidence"
            if awk '($1 ~ /5/ || $1=="missing") && $NF ~ /pam_[^/]*\.so$/ {bad=1} END {exit !bad}' "$WORK/verify"; then
                emit CRITICAL 'PAM module package checksum mismatch' "$pkg" 'A PAM module differs from local package checksums; see detailed evidence.' 'Recover through a trusted console/image, preserve the altered module, and reinstall the matching trusted authentication package. Investigate broader compromise.'
            fi
        fi
    elif [ "${NATIVE_BACKEND:-rpm}" = rpm ] && command -v rpm >/dev/null 2>&1; then
        pkg=$(rpm -qf --qf '%{NAME}\n' "$1" 2>/dev/null) || pkg=
        if [ -n "$pkg" ] && unseen "PKG|$pkg"; then
            evidence "PAM RPM verification: $pkg (verification scripts disabled)"
            rpm -V --noscripts "$pkg" > "$WORK/verify" 2>> "$WORK/errors"
            clean_text < "$WORK/verify" >> "$WORK/evidence"
            if awk '($1 ~ /[5MLUG]/ || $1=="missing") && $NF ~ /pam_[^/]*\.so$/ {bad=1} END {exit !bad}' "$WORK/verify"; then
                emit CRITICAL 'PAM module package checksum mismatch' "$pkg" 'A PAM module differs from local RPM checksums; see detailed evidence.' 'Preserve evidence and restore the authentication package using trusted matching media and console access.'
            fi
        fi
    elif [ "${NATIVE_BACKEND:-pacman}" = pacman ] && command -v pacman >/dev/null 2>&1; then
        pkg=$(pacman -Qqo "$1" 2>/dev/null) || pkg=
        if [ -n "$pkg" ] && unseen "PKG|$pkg"; then
            evidence "PAM pacman package verification: $pkg"
            pacman -Qkk "$pkg" > "$WORK/verify" 2>&1
            clean_text < "$WORK/verify" >> "$WORK/evidence"
            if command -v paccheck >/dev/null 2>&1; then
                paccheck --sha256sum --quiet "$pkg" < /dev/null > "$WORK/verify-hash" 2>&1
                verify_rc=$?
                clean_text < "$WORK/verify-hash" >> "$WORK/evidence"
                if [ "$verify_rc" -ne 0 ] && grep -E 'pam_[^/ ]*\.so.*(mismatch|differ)|[Ss][Hh][Aa]256' "$WORK/verify-hash" >/dev/null; then
                    emit CRITICAL 'PAM module package checksum mismatch' "$pkg" 'paccheck reports a module/hash discrepancy; see evidence.' 'Preserve the module and restore the matching PAM package from trusted media.'
                fi
            else note PAM_INTEGRITY 'pacman -Qkk checks metadata; install pacutils for SHA-256 verification with paccheck.'; fi
        fi
    elif [ "${NATIVE_BACKEND:-apk}" = apk ] && command -v apk >/dev/null 2>&1; then
        pkg=$(apk info --who-owns "$1" 2>/dev/null) || pkg=
        if [ -n "$pkg" ] && unseen APK_AUDIT; then
            evidence 'APK installed system file audit (content and permissions)'
            apk audit --system --check-permissions > "$WORK/apk-audit" 2>> "$WORK/errors"
            clean_text < "$WORK/apk-audit" >> "$WORK/evidence"
            if grep -E '^[UMX] .*pam_[^/]*\.so' "$WORK/apk-audit" >/dev/null; then
                emit CRITICAL 'PAM module package checksum or metadata mismatch' apk 'APK audit reports changed/missing PAM modules; see evidence.' 'Preserve affected modules and recover using matching trusted packages.'
            fi
        fi
    fi
    if [ -z "$pkg" ]; then
        if command -v dpkg-query >/dev/null 2>&1 || command -v rpm >/dev/null 2>&1 || command -v pacman >/dev/null 2>&1 || command -v apk >/dev/null 2>&1; then
            emit HIGH 'PAM module has no package owner' "$1" 'The native package database returned no owner for this authentication module.' 'Preserve it and establish its source; compare with the exact distro PAM package and inspect all referencing PAM rules.'
        fi
        note PAM_INTEGRITY "UNVERIFIED: no supported package owner/verification tool for $1; compare with a trusted matching package."
        if unseen PAM_UNVERIFIED; then
            emit MEDIUM 'PAM binary integrity could not be verified' "$1" 'No supported package owner or verification backend; string scans cannot establish module integrity.' 'Compare PAM module bytes with trusted packages for the exact target OS/version. See PAM_INTEGRITY coverage for every unverified module.'
        fi
    fi
}
progress 'Searching local filesystems for SUID files, PAM modules, kernel modules and shared objects'
: > "$WORK/candidates"
while IFS= read -r tree; do
    if [ -d "$tree" ]; then
        note SEARCH_ROOT "$tree (-xdev; pseudo/runtime trees pruned)"
        walk_candidates "$tree" >> "$WORK/candidates"
    else printf 'Scan root missing: %s\n' "$tree" >> "$WORK/errors"; fi
done < "$WORK/roots.sorted"
sort -u "$WORK/candidates" > "$WORK/candidates.sorted"
evidence 'Filesystem candidates: all SUID, shared objects, kernel modules, PAM modules and MOTD paths'
clean_text < "$WORK/candidates.sorted" >> "$WORK/evidence"
while IFS= read -r file; do
    readable "$file" || continue
    case $file in
        */authorized_keys|*/authorized_keys2) scan_file SSH_KEYS "$file" ;;
        */id_rsa|*/id_dsa|*/id_ecdsa|*/id_ed25519)
            evidence "Private SSH key path (contents omitted): $file"
            ls -ldn "$file" | clean_text >> "$WORK/evidence"
            if ls -ldn "$file" | awk 'substr($1,5,3) ~ /r/ || substr($1,8,3) ~ /r/ {bad=1} END {exit !bad}'; then
                emit HIGH 'Private SSH key readable outside its owner' "$file" "$(ls -ldn "$file")" 'Restrict unauthorized reads, investigate exposure, and replace compromised keys. Key contents were not collected.'
            else note SSH_PRIVATE_KEY "$file (path and permissions only)"; fi ;;
    esac
    if [ -g "$file" ]; then
        case ${file##*/} in sh|bash|dash|ash|busybox|python*|perl*|ruby*|node|php*|vim|find|awk|tar)
            emit HIGH 'SGID shell or command-capable utility' "$file" "$(ls -ldn "$file")" 'Confirm package permissions and remove an unauthorized group privilege bit.' ;;
            *) evidence "SGID $file"; ls -ldn "$file" | clean_text >> "$WORK/evidence" ;;
        esac
    fi
    if [ -u "$file" ]; then
        evidence "SUID $file"
        ls -ldn "$file" 2>> "$WORK/errors" | clean_text >> "$WORK/evidence"
        owner=$(ls -ldn "$file" 2>> "$WORK/errors" | awk '{print $3}')
        name=${file##*/}
        case $name in
            sh|bash|dash|ash|ksh|zsh|csh|tcsh|busybox)
                if [ "$owner" = 0 ]; then level=CRITICAL; else level=HIGH; fi
                emit "$level" 'SUID shell or multipurpose shell binary' "$file" "SUID enabled; owner UID $owner" 'Preserve metadata, confirm required behavior, then remove the unauthorized SUID bit with chmod u-s on this exact path and investigate who created it.' ;;
            python*|perl*|ruby*|node|php*|lua*|vim|vi|find|awk|gawk|nawk|nmap|cp|tar)
                emit HIGH 'SUID interpreter or command-capable utility' "$file" "SUID enabled; owner UID $owner" 'Check against the approved package baseline; remove an unauthorized SUID bit with chmod u-s on this exact file.' ;;
            *) case ${file#"$ROOT"} in
                /tmp/*|/var/tmp/*|/dev/shm/*|/home/*|/root/*)
                    emit HIGH 'SUID file in a home or temporary directory' "$file" "Owner UID $owner" 'Preserve the binary and metadata; compare with trusted packages and remove unauthorized SUID permissions.' ;;
                *) emit LOW 'SUID executable needs baseline approval' "$file" "SUID enabled; owner UID $owner. Many standard system tools legitimately use SUID." 'Compare this file and its permissions with the approved package baseline. Preserve required SUID functionality; remove only unauthorized grants.' ;;
            esac ;;
        esac
        if ls -ldn "$file" | awk 'substr($1,9,1)=="w" {bad=1} END {exit !bad}'; then
            emit CRITICAL 'World-writable SUID file' "$file" "Owner UID $owner" 'Preserve evidence and immediately remove unauthorized write/SUID permissions after confirming service requirements.'
        fi
    fi
    case $file in
        */pam_*.so)
            evidence "PAM module $file"
            metadata "$file"
            if ls -ldn "$file" | awk 'substr($1,6,1)=="w" || substr($1,9,1)=="w" {bad=1} END {exit !bad}'; then
                emit CRITICAL 'PAM module writable by group or other users' "$file" "$(ls -ldn "$file")" 'Preserve ownership and contents, remove unauthorized writes, and restore authentication modules from matching trusted packages.'
            fi
            if command -v strings >/dev/null 2>&1; then
                strings "$file" 2>> "$WORK/errors" | awk 'tolower($0) ~ /hunt3r|backdoor|pam_unix.*\.log|\/tmp\/|\/dev\/tcp/ {print substr($0,1,500)}' > "$WORK/pam-strings"
                if [ -s "$WORK/pam-strings" ]; then
                    clean_text < "$WORK/pam-strings" >> "$WORK/evidence"
                    emit MEDIUM 'PAM module contains reviewable strings' "$file" 'Backdoor/logging/temporary-path marker; strings alone are not proof.' 'Compare the entire module with a trusted matching package. A hardcoded password can appear anywhere or be hidden; fixed string line numbers do not detect it reliably.'
                fi
            else note PAM_STRINGS 'SKIPPED: strings unavailable; package/baseline verification is still required.'; fi
            verify_pam "$file" ;;
        *.ko|*.ko.*)
            case ${file#"$ROOT"} in
                /lib/modules/*|/usr/lib/modules/*) ;; *) emit MEDIUM 'Kernel module outside standard module trees' "$file" 'Module filename found outside /lib/modules or /usr/lib/modules.' 'Validate the module source/signature and startup load instructions against the baseline; do not load it for testing.' ;;
            esac ;;
    esac
    case $file in *motd*) scan_file MOTD "$file" ;; esac
    case ${file#"$ROOT"} in /tmp/*.so|/tmp/*.so.*|/var/tmp/*.so|/var/tmp/*.so.*|/dev/shm/*.so|/dev/shm/*.so.*)
        emit MEDIUM 'Shared object in temporary storage' "$file" 'May be build output or a loader-injection payload.' 'Correlate with preload settings and process maps, then preserve and quarantine only confirmed malicious libraries.' ;;
    esac
done < "$WORK/candidates.sorted"
note SUID 'All SUID candidates in the search roots are inventoried; shells/interpreters, temporary/home paths and world-write permissions are prioritized. Renamed or modified ordinary binaries require a trusted package baseline.'
note LKM_FILES 'Inventoried on-disk kernel modules; locations outside standard module trees require review.'

progress 'Checking extended ACLs (may take time on large filesystems)'
if command -v getfacl >/dev/null 2>&1; then
    acl_p=
    getfacl -p -n "${ROOT:-/}" >/dev/null 2>&1 && acl_p=-p
    : > "$WORK/acls"
    while IFS= read -r tree; do
        [ -d "$tree" ] || continue
        find "$tree" -xdev \( -path "$WORK" -o -path "$OUTPUT" \
            -o -path "$(path "$STATE")" -o -path "$(path /var/lib/hunter)" \
            -o -path "$(path /proc)" -o -path "$(path /sys)" -o -path "$(path /dev)" -o -path "$(path /run)" \) -prune -o \
            \( -type f -o -type d \) -exec getfacl $acl_p -n {} + 2>> "$WORK/errors" |
        awk '/^# file: / {file=substr($0,9)}
             /^(default:)?(user|group):[^:]+:/ {print file "|" $0}
             /^(default:)?other::.*w/ {print file "|" $0}' >> "$WORK/acls"
    done < "$WORK/roots.sorted"
    sort -u "$WORK/acls" > "$WORK/acls.sorted"
    evidence 'Extended named/default ACL entries and world-write ACL entries (mask/effective permissions retained)'
    clean_text < "$WORK/acls.sorted" >> "$WORK/evidence"
    awk -F'|' -v root="$ROOT" '
        {
            p=$1; if (substr(p,1,1)!="/") p="/" p
            if (root!="" && index(p,root "/")==1) p=substr(p,length(root)+1)
            if (p ~ /^\/(etc|root|bin|sbin|lib|lib64)(\/|$)/ || p ~ /^\/usr\/(bin|sbin|lib|lib64|local\/bin|local\/sbin)(\/|$)/) {
                entry=$2
                if (entry ~ /^(default:)?user:0:/) next
                perm=entry; sub(/^.*:/,"",perm); sub(/[[:space:]].*/,"",perm)
                if (entry ~ /#effective:/) {perm=entry; sub(/^.*#effective:/,"",perm); sub(/[[:space:]].*/,"",perm)}
                if (perm ~ /w/) print "HIGH|" $1 "|" entry
                else if (p ~ /\/(shadow|gshadow|master.passwd)$/ || p ~ /^\/root(\/|$)/) print "MEDIUM|" $1 "|" entry
            }
        }' "$WORK/acls.sorted" > "$WORK/acl-findings"
    while IFS='|' read -r level file entry; do
        emit "$level" 'ACL grants access to a sensitive path' "$file" "$entry" 'Confirm the grantee and effective mask. Remove only the unauthorized named/default ACL entry with the platform setfacl tool; preserve required ACLs and verify access.'
    done < "$WORK/acl-findings"
    note ACL 'Scanned files/directories across all search roots; named/default and world-write entries are saved. ACL masks are honored when prioritizing sensitive paths; NFSv4 ACL syntax may require platform tools.'
else
    note ACL 'SKIPPED: getfacl unavailable. Mode bits do not substitute for extended ACL inspection.'
    emit MEDIUM 'Extended ACL check unavailable' 'getfacl' 'No ACL reader installed; extended permission persistence has not been ruled out.' 'Use a trusted getfacl or platform ACL tool to inspect named/default grants, especially /root, shadow and persistence hooks.'
fi

progress 'Searching web roots recursively'
: > "$WORK/webroots"
for dir in /var/www /srv/www /srv/http /usr/local/www /usr/share/nginx/html /opt/lampp/htdocs; do path "$dir"; done > "$WORK/webroots"
printf '%s\n' "$EXTRA_WEB" | while IFS= read -r extra; do [ -z "$extra" ] || path "$extra"; done >> "$WORK/webroots"
for dir in /etc/nginx /etc/apache2 /etc/httpd /usr/local/etc/nginx /usr/local/etc/apache24; do
    list_tree "$(path "$dir")" > "$WORK/web-configs"
    while IFS= read -r file; do
        readable "$file" || continue
        awk 'tolower($1)=="documentroot" || tolower($1)=="root" || tolower($1)=="alias" {
            p=$2; gsub(/[";\047]/,"",p); if(p ~ /^\// && p !~ /[|\\]/) print p
        }' "$file" | while IFS= read -r docroot; do
            case /$docroot/ in */../*) continue ;; esac
            path "$docroot"
        done >> "$WORK/webroots"
    done < "$WORK/web-configs"
done
sort -u "$WORK/webroots" > "$WORK/webroots.sorted"
web_count=0
while IFS= read -r tree; do
    [ -d "$tree" ] || continue
    web_count=$((web_count + 1))
    note WEB_ROOT "$tree"
    list_tree "$tree" > "$WORK/webfiles"
    while IFS= read -r file; do
        case $file in *.php|*.php[0-9]|*.phtml|*.phar|*.inc|*.jsp|*.jspx|*.asp|*.aspx|*.cgi|*.pl|*.py|*.rb|*.sh|*.js)
            scan_file WEB "$file" ;;
            */.htaccess|*/.user.ini) scan_file WEB_CONFIG "$file" ;;
        esac
    done < "$WORK/webfiles"
done < "$WORK/webroots.sorted"
note WEBSHELL "Searched $web_count existing web roots for command execution, request input, sockets and obfuscation. Heuristics need code review; add custom docroots using --web-root. Extensionless/disguised code and custom extensions require manual review."
# Configuration is evidence for finding custom docroots, not something to execute.
for dir in /etc/nginx /etc/apache2 /etc/httpd /usr/local/etc/nginx /usr/local/etc/apache24; do scan_tree WEB_CONFIG "$(path "$dir")"; done
for dir in /etc/php /etc/php.d /etc/php-fpm.d /etc/php7 /etc/php8 /etc/php81 /etc/php82 /etc/php83 /etc/php84 /etc/php85 /etc/modsecurity /etc/modsecurity.d; do scan_tree WEB_CONFIG "$(path "$dir")"; done

if [ "$OFFLINE" = no ]; then
    progress 'Collecting live kernel, process, loader and socket evidence'
    evidence 'Processes'
    if ps -e -o pid,ppid,uid,args > "$WORK/processes" 2> "$WORK/ps-errors"; then
        :
    elif ps -ef > "$WORK/processes" 2> "$WORK/ps-errors"; then
        note PS 'Used portable full-format process output; custom numeric columns unavailable.'
    elif ps > "$WORK/processes" 2> "$WORK/ps-errors"; then
        note PS 'Used basic process listing; full-format flags unavailable on this implementation.'
    else
        cat "$WORK/ps-errors" >> "$WORK/errors"
    fi
    clean_text < "$WORK/processes" >> "$WORK/evidence"
    evidence 'Network sockets'
    if command -v ss >/dev/null 2>&1; then
        ss -anp 2>> "$WORK/errors" | clean_text >> "$WORK/evidence"
    elif command -v netstat >/dev/null 2>&1; then
        netstat -an 2>> "$WORK/errors" | clean_text >> "$WORK/evidence"
    else note SOCKETS 'SKIPPED: neither ss nor netstat is available.'; fi
    if command -v lsof >/dev/null 2>&1; then
        evidence 'Network open files'
        lsof -n -P -i 2>> "$WORK/errors" | clean_text >> "$WORK/evidence"
    else note LSOF 'SKIPPED: lsof is unavailable; process/proc and socket checks are independent.'; fi
    if [ -r /proc/modules ]; then
        evidence '/proc/modules'
        clean_text < /proc/modules >> "$WORK/evidence"
        if command -v lsmod >/dev/null 2>&1; then evidence lsmod; lsmod 2>> "$WORK/errors" | clean_text >> "$WORK/evidence"; fi
        for module in /sys/module/*; do
            [ -f "$module/initstate" ] || continue
            name=${module##*/}
            if ! awk -v name="$name" '$1==name {yes=1} END {exit !yes}' /proc/modules; then
                emit HIGH 'Module visibility mismatch' "$module" 'A loadable module has sysfs initstate but is absent from /proc/modules. A load/unload race is possible.' 'Recheck with trusted tools; preserve kernel logs and memory, and investigate from trusted recovery media if the mismatch persists.'
            fi
        done
        for file in /proc/modules /proc/kallsyms /sys/kernel/tracing/available_filter_functions /sys/kernel/tracing/available_filter_functions_addrs /sys/kernel/debug/tracing/available_filter_functions; do
            if [ -r "$file" ]; then
                evidence "Known rootkit-name heuristic $file"
                grep -i -E 'diamorphine|reptile|adore_ng|suterusu|syslogk|kovi[dD]|ftrace.*hook|hook.*(getdents|kill|sys_call)' "$file" 2>> "$WORK/errors" > "$WORK/kernel-hits"
                if [ -s "$WORK/kernel-hits" ]; then
                    clean_text < "$WORK/kernel-hits" >> "$WORK/evidence"
                    emit HIGH 'Kernel symbol/module marker requires investigation' "$file" 'Rootkit-name or hook-name heuristic matched; see evidence. Symbols alone are not proof.' 'Validate against a known-good matching kernel/module set; preserve logs/memory and use trusted recovery media for confirmed kernel compromise.'
                fi
            else note KERNEL_SOURCE "UNAVAILABLE: $file"; fi
        done
        evidence 'Kernel log indicators'
        if command -v dmesg >/dev/null 2>&1; then
            dmesg > "$WORK/dmesg" 2>> "$WORK/errors"
            grep -i -E 'taint|out-of-tree|module verification|signature|rootkit|diamorphine|reptile' "$WORK/dmesg" | clean_text >> "$WORK/evidence"
            if grep -i -E 'rootkit|diamorphine|reptile|syslogk|suterusu' "$WORK/dmesg" > /dev/null; then
                emit HIGH 'Kernel ring buffer contains a rootkit-name indicator' dmesg 'A rootkit-name heuristic matched; inspect the log context.' 'Preserve kernel logs and investigate modules from a trusted matching kernel baseline; a name match alone is not proof.'
            fi
        else note DMESG 'SKIPPED: dmesg unavailable.'; fi
        proc_count=0; denied_maps=0; denied_env=0
        for proc in /proc/[0-9]*; do
            [ -d "$proc" ] || continue
            pid=${proc##*/}
            [ "$pid" != "$$" ] || continue
            proc_count=$((proc_count + 1))
            if [ -r "$proc/maps" ]; then
                if ! awk '$0 ~ /\/(tmp|var\/tmp|dev\/shm)\/.*\.so/ || $0 ~ /\.so.*\(deleted\)/ {print substr($0,1,700)}' "$proc/maps" 2>/dev/null > "$WORK/map-hits"; then
                    [ ! -d "$proc" ] || denied_maps=$((denied_maps + 1))
                fi
                if [ -s "$WORK/map-hits" ]; then
                    evidence "PID $pid suspicious shared-object mappings"
                    clean_text < "$WORK/map-hits" >> "$WORK/evidence"
                    emit HIGH 'Process maps temporary or deleted shared object' "$proc/maps" 'See saved mapping paths; deleted mappings can also follow legitimate upgrades.' 'Identify the process owner/service and library provenance. Preserve evidence; contain a confirmed malicious process and remove its persistence hook.'
                fi
            else [ ! -d "$proc" ] || denied_maps=$((denied_maps + 1)); fi
            if [ -r "$proc/environ" ]; then
                : > "$WORK/env-denied"
                { tr '\000' '\n' 2>/dev/null < "$proc/environ" || printf 'failed\n' > "$WORK/env-denied"; } |
                    awk '/^LD_(PRELOAD|AUDIT|LIBRARY_PATH)=./ {print substr($0,1,700)}' > "$WORK/env-hits"
                if [ -s "$WORK/env-denied" ]; then [ ! -d "$proc" ] || denied_env=$((denied_env + 1)); fi
                if [ -s "$WORK/env-hits" ]; then
                    evidence "PID $pid loader environment (other environment variables omitted)"
                    clean_text < "$WORK/env-hits" >> "$WORK/evidence"
                    emit HIGH 'Process loader injection environment' "$proc/environ" 'LD_PRELOAD, LD_AUDIT or LD_LIBRARY_PATH is set; legitimate instrumentation also uses these.' 'Verify every referenced library and parent service; preserve evidence and remove only unapproved settings at their startup source. Keep current root and tested second SSH sessions.'
                fi
            else [ ! -d "$proc" ] || denied_env=$((denied_env + 1)); fi
            if command -v readlink >/dev/null 2>&1; then
                exe=$(readlink "$proc/exe" 2>/dev/null)
                cwd=$(readlink "$proc/cwd" 2>/dev/null)
                case $exe in /tmp/*|/var/tmp/*|/dev/shm/*|*' (deleted)')
                    emit MEDIUM 'Process executable needs provenance review' "$proc/exe" "exe=$exe; cwd=$cwd" 'Identify the owning service and compare the executable to trusted files; temporary or deleted executables can also be legitimate.' ;;
                esac
            fi
        done
        note PROC "Inspected $proc_count proc entries; unreadable maps=$denied_maps, environment=$denied_env (process exits can race). Only loader environment variables are saved."
        if [ "$denied_maps" -gt 0 ] || [ "$denied_env" -gt 0 ]; then
            emit MEDIUM 'Process inspection partially unavailable' /proc 'Some process mappings or environments could not be read.' 'Check privileges, hidepid, container namespaces and collection coverage; rerun from trusted host/root access when appropriate.'
        fi
        note LKM 'Collected module lists, sysfs visibility comparison, known symbol indicators and available kernel log evidence. A hidden/modified kernel can evade every userspace check.'
    else
        note LKM 'UNAVAILABLE: Linux /proc/modules not readable/present; kernel symbols, sysfs and process maps are platform-specific.'
        if command -v kldstat >/dev/null 2>&1; then evidence 'BSD kernel modules'; kldstat 2>> "$WORK/errors" | clean_text >> "$WORK/evidence"; fi
        if command -v kextstat >/dev/null 2>&1; then evidence 'Darwin kernel extensions'; kextstat 2>> "$WORK/errors" | clean_text >> "$WORK/evidence"; fi
    fi
    evidence 'Mount table'
    if [ -r /proc/self/mountinfo ]; then
        clean_text < /proc/self/mountinfo >> "$WORK/evidence"
        awk '$5 ~ /^\/proc\/[0-9]+(\/|$)/ {print $5 "|" $0}' /proc/self/mountinfo > "$WORK/hidden-mounts"
        while IFS='|' read -r target details; do
            emit HIGH 'Mount overlays a process directory' "$target" "$details" 'Confirm container/runtime intent; preserve mount/process evidence, then unmount only a confirmed concealment mount. Investigate the revealed process and its persistence before stopping it.'
        done < "$WORK/hidden-mounts"
        note PROC_MOUNTS 'Checked mountinfo for overlays at /proc/PID or descendants; container mounts need context.'
    elif command -v mount >/dev/null 2>&1; then
        mount > "$WORK/mounts" 2>> "$WORK/errors"
        clean_text < "$WORK/mounts" >> "$WORK/evidence"
        if grep -E ' on /proc/[0-9]+([ /]|$)' "$WORK/mounts" > /dev/null; then emit HIGH 'Possible mount over a process directory' 'mount output' 'Mount target under /proc/PID; review the mount table in evidence.' 'Validate runtime/container intent and investigate any process concealed by an unauthorized mount.'; fi
        note PROC_MOUNTS 'Used portable mount output; Linux mountinfo is unavailable.'
    else note PROC_MOUNTS 'SKIPPED: no readable mountinfo or mount command.'; fi
    # Parse dynamic dependencies without executing inspected programs (unlike ldd).
    if command -v readelf >/dev/null 2>&1; then
        for file in /bin/ls /bin/sh /bin/bash /usr/bin/ssh /bin/netstat /usr/bin/netstat; do
            [ -f "$file" ] || continue
            evidence "ELF dynamic metadata $file"
            readelf -d "$file" 2>> "$WORK/errors" | awk '/NEEDED|RPATH|RUNPATH|AUDIT/' | clean_text >> "$WORK/evidence"
        done
    else note ELF 'SKIPPED: readelf unavailable; loader configuration and process checks still ran where supported.'; fi
else
    note LKM 'LIVE CHECKS SKIPPED in --root mode: no inference about the running kernel or hidden processes on the mounted target.'
    note PROC_MOUNTS 'LIVE CHECKS SKIPPED in --root mode; a mounted disk has no authoritative process/mount state.'
    note PAM_INTEGRITY 'Local host package verification SKIPPED in --root mode; compare modules with trusted target-version packages.'
fi
for optional in unhide rkhunter chkrootkit tracee pspy pspy64 lynis tiger vol; do
    if command -v "$optional" >/dev/null 2>&1; then
        note OPTIONAL_TOOL "$optional installed; not auto-run (independent follow-up tool)."
    else note OPTIONAL_TOOL "$optional unavailable; not required."; fi
done
progress 'Checking file capabilities, recent PAM changes, logging and package integrity'
if command -v getcap >/dev/null 2>&1; then
    : > "$WORK/caps"
    while IFS= read -r tree; do
        [ -d "$tree" ] || continue
        find "$tree" -xdev \( -path "$WORK" -o -path "$OUTPUT" -o -path "$(path "$STATE")" \
            -o -path "$(path /proc)" -o -path "$(path /sys)" -o -path "$(path /dev)" -o -path "$(path /run)" \) -prune -o \
            -type f -exec getcap {} + >> "$WORK/caps" 2>> "$WORK/errors"
    done < "$WORK/roots.sorted"
    sort -u "$WORK/caps" > "$WORK/caps.sorted"
    evidence 'Linux file capabilities'
    clean_text < "$WORK/caps.sorted" >> "$WORK/evidence"
    while IFS= read -r capline; do
        case $capline in *cap_setuid*|*cap_setgid*|*cap_setfcap*|*cap_setpcap*|*cap_dac_override*|*cap_dac_read_search*|*cap_sys_admin*|*cap_sys_ptrace*|*cap_sys_module*|*cap_chown*|*cap_fowner*|*cap_net_admin*|*cap_bpf*)
            emit HIGH 'File capability grants powerful privileges' "${capline% cap_*}" "$capline" 'Confirm package capabilities and intended use; remove unauthorized grants using setcap after preserving evidence.' ;;
        esac
    done < "$WORK/caps.sorted"
    note CAPABILITIES 'Inventoried file capabilities across local scan roots; powerful grants prioritized.'
else note CAPABILITIES 'UNAVAILABLE: getcap (install libcap utilities for this OS).'; fi
if [ -d "$(path /etc/pam.d)" ]; then
    find "$(path /etc/pam.d)" -type f -mtime -30 -print 2>> "$WORK/errors" > "$WORK/recent-pam"
    evidence 'PAM configuration modified in the last 30 days'
    clean_text < "$WORK/recent-pam" >> "$WORK/evidence"
    if [ -s "$WORK/recent-pam" ]; then
        emit LOW 'Recently modified PAM configuration' "$(path /etc/pam.d)" \
            "$(wc -l < "$WORK/recent-pam") files changed within 30 days; paths saved in evidence." 'Check the listed authentication stack changes and package ownership.'
    fi
fi

# Verify core executables without invoking them. RPM verification scriptlets are
# explicitly disabled. Package databases, configs and target scripts are not sourced.
if [ "$OFFLINE" = no ]; then
    for core in /usr/sbin/sshd /usr/bin/ssh /usr/bin/sudo /bin/su /usr/bin/su /bin/ls /bin/ps /usr/bin/ps /usr/bin/find /bin/netstat /usr/bin/ss; do
        [ -f "$core" ] || continue
        package= backend=
        if [ "$NATIVE_BACKEND" = dpkg ] && command -v dpkg-query >/dev/null 2>&1; then
            backend=dpkg; package=$(dpkg-query -S "$core" 2>/dev/null | sed -n '1s/: \/.*//p')
            if [ -z "$package" ]; then case $core in /bin/*|/sbin/*) package=$(dpkg-query -S "/usr$core" 2>/dev/null | sed -n '1s/: \/.*//p') ;; esac; fi
        elif [ "$NATIVE_BACKEND" = rpm ] && command -v rpm >/dev/null 2>&1; then backend=rpm; package=$(rpm -qf --qf '%{NAME}\n' "$core" 2>/dev/null) || package=
        elif [ "$NATIVE_BACKEND" = pacman ] && command -v pacman >/dev/null 2>&1; then backend=pacman; package=$(pacman -Qqo "$core" 2>/dev/null) || package=
        elif [ "$NATIVE_BACKEND" = apk ] && command -v apk >/dev/null 2>&1; then backend=apk; package=$(apk info --who-owns "$core" 2>/dev/null) || package=; fi
        if [ -z "$package" ]; then
            emit HIGH 'Core administration binary has no package owner' "$core" 'No native package record owns this installed core executable.' 'Identify its source and compare bytes to a matching trusted package.'
            continue
        fi
        unseen "CORE_PKG|$package" || continue
        evidence "Core package integrity: $backend $package ($core)"
        case $backend in
            dpkg) dpkg --verify "$package" > "$WORK/core-verify" 2>> "$WORK/errors"
                awk '($1 ~ /5/ || $1=="missing") && $NF !~ /^\/etc\// {print}' "$WORK/core-verify" > "$WORK/core-bad" ;;
            rpm) rpm -V --noscripts "$package" > "$WORK/core-verify" 2>> "$WORK/errors"
                awk '($1 ~ /[5MLUG]/ || $1=="missing") && $NF !~ /^\/etc\// {print}' "$WORK/core-verify" > "$WORK/core-bad" ;;
            pacman) pacman -Qkk "$package" > "$WORK/core-verify" 2>&1
                grep -i -E 'warning:.*(permissions|uid|gid|symlink|size).*mismatch' "$WORK/core-verify" > "$WORK/core-bad"
                if command -v paccheck >/dev/null 2>&1; then
                    paccheck --sha256sum --quiet "$package" < /dev/null >> "$WORK/core-bad" 2>&1
                else note PACKAGE_INTEGRITY 'pacman metadata checked; paccheck SHA-256 tool unavailable'; fi ;;
            apk)
                if [ ! -f "$WORK/apk-audit" ]; then apk audit --system --check-permissions > "$WORK/apk-audit" 2>> "$WORK/errors"; fi
                cat "$WORK/apk-audit" > "$WORK/core-verify"
                awk '$1 ~ /^[UX]$/ && $2 ~ /^\/?(usr\/)?(s?bin|lib|lib64)\// {print}' "$WORK/apk-audit" > "$WORK/core-bad" ;;
        esac
        clean_text < "$WORK/core-verify" >> "$WORK/evidence"
        if [ -s "$WORK/core-bad" ]; then
            emit HIGH 'Core package file integrity discrepancy' "$package" "$(head -n 8 "$WORK/core-bad")" 'Preserve the affected files and compare/reinstall using matching trusted packages; inspect the full verification output.'
        fi
        [ "$backend" != apk ] || break
    done
    note PACKAGE_INTEGRITY 'Native dpkg, RPM (yum/dnf/zypper), pacman/paccheck or APK verification used where present.'
    evidence 'Active services and schedules'
    if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
        systemctl --no-pager --plain --type=service --state=active >> "$WORK/evidence" 2>> "$WORK/errors"
        systemctl --no-pager --plain list-unit-files >> "$WORK/evidence" 2>> "$WORK/errors"
        systemctl --no-pager --plain list-timers --all >> "$WORK/evidence" 2>> "$WORK/errors"
    elif command -v rc-status >/dev/null 2>&1; then rc-status -a >> "$WORK/evidence" 2>> "$WORK/errors"
    else ls -ld /etc/init.d/* /etc/rc.d/* /usr/local/etc/rc.d/* >> "$WORK/evidence" 2>/dev/null || :; fi
    if command -v getent >/dev/null 2>&1; then
        evidence 'NSS privileged users and groups'
        getent passwd | awk -F: '$3==0 {print $1 ":uid=" $3 ":home=" $6 ":shell=" $7}' >> "$WORK/evidence"
        getent passwd | awk -F: '$3==0 && $1!="root" {print $1}' > "$WORK/nss-root"
        while IFS= read -r account; do
            if ! awk -F: -v a="$account" '$1==a && $3==0 {ok=1} END {exit !ok}' "$PASSWD"; then
                emit CRITICAL 'Additional NSS UID 0 account' getent "$account has UID 0 through NSS" 'Inspect the directory/NSS identity provider and revoke unapproved root identities.'
            fi
        done < "$WORK/nss-root"
        for group in root sudo wheel admin adm docker lxd disk; do getent group "$group" || :; done | clean_text >> "$WORK/evidence"
    fi
    if command -v auditctl >/dev/null 2>&1; then
        evidence 'Audit status and active rules'
        auditctl -s > "$WORK/audit-status" 2>> "$WORK/errors"
        clean_text < "$WORK/audit-status" >> "$WORK/evidence"
        auditctl -l >> "$WORK/evidence" 2>> "$WORK/errors"
        if awk '$1=="enabled" && $2==0 || $1=="lost" && $2>0 {bad=1} END {exit !bad}' "$WORK/audit-status"; then
            emit HIGH 'Audit disabled or audit records lost' auditctl "$(cat "$WORK/audit-status")" 'Restore audit collection and investigate why records were disabled or dropped; inspect backlog and storage limits.'
        fi
    fi
    if command -v sshd >/dev/null 2>&1; then
        evidence 'Effective OpenSSH server settings'
        sshd -T > "$WORK/sshd-effective" 2>> "$WORK/errors"
        awk '$1 ~ /^(loglevel|permitrootlogin|permitemptypasswords|pubkeyauthentication|passwordauthentication|authorizedkeysfile|authorizedkeyscommand|authorizedprincipalscommand|trustedusercakeys|permituserenvironment|forcecommand|usepam)$/ {print}' "$WORK/sshd-effective" | clean_text >> "$WORK/evidence"
    fi
fi

# Static Apache checks work on mounted roots too, without loading server modules.
apache_seen=no
: > "$WORK/apache-config"
for dir in /etc/apache2 /etc/httpd /usr/local/etc/apache24 /etc/modsecurity /etc/modsecurity.d; do
    [ ! -d "$(path "$dir")" ] || apache_seen=yes
    list_tree "$(path "$dir")" > "$WORK/apache-paths"
    while IFS= read -r file; do
        readable "$file" || continue
        awk 'NF && $0 !~ /^[[:space:]]*#/ {print}' "$file" >> "$WORK/apache-config"
    done < "$WORK/apache-paths"
done
if [ "$apache_seen" = yes ]; then
    if ! grep -i -E 'security2_module|mod_security2\.so|security2\.conf' "$WORK/apache-config" >/dev/null; then
        emit MEDIUM 'Apache ModSecurity module not found in configuration' Apache 'No active security2 module directive/include found.' 'Install the distro ModSecurity Apache module, enable it, validate server configuration, and reload.'
    fi
    if ! grep -i -E '^[[:space:]]*SecRuleEngine[[:space:]]+On([[:space:]]|$)' "$WORK/apache-config" >/dev/null; then
        emit MEDIUM 'ModSecurity blocking engine is not configured On' Apache 'No active SecRuleEngine On directive found in inspected configuration.' 'Review application compatibility, configure SecRuleEngine On, run the Apache config test, and reload.'
    fi
    if ! grep -i -E '^[[:space:]]*Include(Optional)?[[:space:]].*(crs|owasp|REQUEST-9|rules/\*)' "$WORK/apache-config" >/dev/null; then
        emit MEDIUM 'Apache CRS rules include not found' Apache 'No active Core Rule Set include found in inspected configuration.' 'Install the distro CRS package and include its setup/rules through the distribution security module configuration.'
    fi
    note APACHE 'Inspected ModSecurity load directives, blocking engine and CRS includes. Effective virtual-host config is saved where available.'
fi

# Compare every retained snapshot entry, and discover new files in the same trees.
# A file present in a snapshot still receives all heuristic checks above.
if [ -z "$BASELINE" ]; then
    pointer=$(path "$STATE/latest")
    if readable "$pointer"; then
        baseline_id=$(cat "$pointer")
        case $baseline_id in ''|*[!A-Za-z0-9._-]*) note SNAPSHOT 'Invalid latest pointer' ;;
            *) BASELINE=$(path "$STATE/runs/$baseline_id/manifest.sha256") ;;
        esac
    fi
fi
if [ -n "$BASELINE" ]; then
    readable "$BASELINE" || fail "Cannot read snapshot: $BASELINE"
    progress 'Comparing hashes and permissions with the selected setup snapshot'
    : > "$WORK/baseline-known"
    changed=0
    while IFS='|' read -r old_hash old_mode old_uid old_gid logical; do
        case $logical in /*) ;; *) continue ;; esac
        case /$logical/ in */../*|*'\'*) continue ;; esac
        printf '%s\n' "$logical" >> "$WORK/baseline-known"
        target=$(path "$logical")
        change= new_hash=
        if [ -L "$target" ] && [ "${old_mode#l}" = "$old_mode" ]; then change='Regular file replaced with symlink'
        elif [ "${old_mode#l}" != "$old_mode" ]; then
            if [ -L "$target" ]; then
                readlink "$target" > "$WORK/link-target"
                if command -v sha256sum >/dev/null 2>&1; then new_hash=$(sha256sum < "$WORK/link-target" | awk '{print $1}')
                elif command -v shasum >/dev/null 2>&1; then new_hash=$(shasum -a 256 < "$WORK/link-target" | awk '{print $1}')
                elif command -v openssl >/dev/null 2>&1; then new_hash=$(openssl dgst -sha256 < "$WORK/link-target" | awk '{print $NF}'); fi
                [ "$new_hash" = "$old_hash" ] || change='Symlink target changed'
            else change='Symlink removed or replaced with regular file'; fi
        elif [ ! -e "$target" ]; then change='File removed'
        elif readable "$target"; then
            if command -v sha256sum >/dev/null 2>&1; then new_hash=$(sha256sum < "$target" | awk '{print $1}')
            elif command -v shasum >/dev/null 2>&1; then new_hash=$(shasum -a 256 < "$target" | awk '{print $1}')
            elif command -v openssl >/dev/null 2>&1; then new_hash=$(openssl dgst -sha256 < "$target" | awk '{print $NF}')
            else note SNAPSHOT 'SHA-256 tool unavailable; content comparison skipped'; fi
            [ -z "$new_hash" ] || [ "$new_hash" = "$old_hash" ] || change='SHA-256 content changed'
            fields=$(ls -ldn "$target" | awk '{print $1 "|" $3 "|" $4}')
            [ "$fields" = "$old_mode|$old_uid|$old_gid" ] || change="${change:+$change; }permissions/ownership changed"
        else continue; fi
        [ -n "$change" ] || continue
        changed=$((changed + 1))
        case $logical in
            */pam_*.so|/etc/pam.d/*|/etc/ld.so.preload|/etc/sudoers*|/etc/ssh/*|*/authorized_keys*) level=HIGH ;;
            /bin/*|/sbin/*|/usr/bin/*|/usr/sbin/*|/lib/*|/lib64/*|/usr/lib/*|/usr/lib64/*) level=HIGH ;;
            *) level=MEDIUM ;;
        esac
        emit "$level" 'File changed since setup snapshot' "$target" "$change; previous SHA256=$old_hash${new_hash:+; current SHA256=$new_hash}" 'Review the change against team work and package updates; investigate unapproved changes and preserve affected files.'
    done < "$BASELINE"
    : > "$WORK/current-paths"
    baseline_dir=${BASELINE%/*}
    roots_file=$baseline_dir/hash-roots
    if readable "$roots_file"; then
        while IFS= read -r logical; do
            case $logical in /*) ;; *) continue ;; esac
            case /$logical/ in */../*) continue ;; esac
            list_tree "$(path "$logical")" | while IFS= read -r file; do
                case $file in "$(path "$STATE")"/*|"$OUTPUT"|"$WORK"/*) continue ;; esac
                printf '%s\n' "${file#"$ROOT"}"
            done >> "$WORK/current-paths"
        done < "$roots_file"
        awk 'FILENAME==ARGV[1] {old[$0]=1;next} !old[$0] && !seen[$0]++ {print}' "$WORK/baseline-known" "$WORK/current-paths" > "$WORK/new-paths"
        while IFS= read -r logical; do
            emit MEDIUM 'New file since setup snapshot' "$(path "$logical")" 'This path was not a regular file in the selected manifest.' 'Check whether team work or a package update created it; inspect new authentication, startup and executable files first.'
        done < "$WORK/new-paths"
    fi
    note SNAPSHOT "Compared $BASELINE; changed/removed regular files=$changed. New file paths are checked in the recorded hash roots."
    if [ "$OFFLINE" = no ]; then
        service_names() {
            awk '$1 ~ /\.service$/ && $3=="active" {print $1}
                 /\[[[:space:]]*started[[:space:]]*\]/ {print $1}' "$1" | sort -u
        }
        previous_services=$baseline_dir/after/services.txt
        if [ -r "$previous_services" ]; then
            if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
                systemctl --no-pager --plain list-units --type=service --all > "$WORK/services-now" 2>> "$WORK/errors"
            elif command -v rc-status >/dev/null 2>&1; then rc-status -a > "$WORK/services-now" 2>> "$WORK/errors"
            else : > "$WORK/services-now"; fi
            service_names "$previous_services" > "$WORK/services-old"
            service_names "$WORK/services-now" > "$WORK/services-new"
            awk 'FILENAME==ARGV[1] {old[$0]=1;next} !old[$0] {print}' "$WORK/services-old" "$WORK/services-new" > "$WORK/services-added"
            while IFS= read -r unit; do
                emit MEDIUM 'Service became active since setup snapshot' "$unit" 'This service was not recorded active in the selected snapshot.' 'Confirm team changes and inspect the service definition, executable and associated network listeners.'
            done < "$WORK/services-added"
        fi
        previous_sockets=$baseline_dir/after/sockets.txt
        if [ -r "$previous_sockets" ] && command -v ss >/dev/null 2>&1; then
            ss -anp > "$WORK/sockets-now" 2>> "$WORK/errors"
            listening_endpoints() {
                awk '$1 ~ /^(tcp|udp)/ {
                    if ($2=="LISTEN" || $2=="UNCONN") print $1 "|" $5
                    else if ($6=="LISTEN" || $1 ~ /^udp/ && $2 ~ /^[0-9]+$/) print $1 "|" $4
                }' "$1" | sort -u
            }
            listening_endpoints "$previous_sockets" > "$WORK/sockets-old"
            listening_endpoints "$WORK/sockets-now" > "$WORK/sockets-new"
            awk 'FILENAME==ARGV[1] {old[$0]=1;next} !old[$0] {print}' "$WORK/sockets-old" "$WORK/sockets-new" > "$WORK/sockets-added"
            while IFS= read -r endpoint; do
                emit MEDIUM 'New listening endpoint since setup snapshot' "$endpoint" 'This local TCP listener or unconnected UDP socket was not recorded in the snapshot.' 'Identify the owning process in the socket evidence and confirm that its service and bind address are intended.'
            done < "$WORK/sockets-added"
        fi
    fi
else note SNAPSHOT 'No setup snapshot selected; run hunter-setup to enable change comparison.'; fi
note REPORT 'Config/process evidence can contain secrets; report permissions are 600. Private SSH key contents and full process environments are omitted.'
note PATHS 'Line-oriented path processing: spaces are supported; filenames containing newline, backslash or | are not supported. Symlinked directories and nested mounts in targeted trees may require explicit --scan-root/--web-root or manual review.'
finish COMPLETED
exit 0
