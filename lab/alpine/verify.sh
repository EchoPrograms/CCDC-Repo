#!/bin/sh
# Live tests inside the disposable target. Invokes only local lab endpoints.
set -eu
[ -f /.dockerenv ] && [ -f /var/lib/ccdc-lab/seeded ] || {
    printf 'Run this through ./lab/alpine/ctl test after starting the lab.\n' >&2
    exit 1
}
/usr/local/bin/lab-healthcheck
printf 'PASS: SSH/HTTP health\n'
SSHPASS=${LAB_PASSWORD:-CCDC-Practice-2026!}
export SSHPASS
sshpass -e ssh -F /dev/null -T -p 22 -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -o PreferredAuthentications=password \
    -o PubkeyAuthentication=no defender@127.0.0.1 \
    'test "$(id -un)" = defender && test "$(sudo -n id -u)" = 0'
unset SSHPASS
printf 'PASS: password SSH login and passwordless sudo\n'
key_result=$(printf 'id -un\nexit\n' | ssh -F /dev/null -T -p 22 \
    -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR \
    -o BatchMode=yes -o IdentitiesOnly=yes -i /root/.lab-keys/operator defender@127.0.0.1)
printf '%s\n' "$key_result" | grep '^defender$' > /dev/null
printf 'PASS: planted authorization key and forced command\n'
root_result=$(su -s /bin/sh -c '/usr/local/libexec/.rescue/bash -p -c "id -u"' support)
[ "$root_result" = 0 ]
printf 'PASS: SUID Bash grants effective root inside the container\n'
wget -q -O - 'http://127.0.0.1:8080/assets/cache.php?cmd=id' | grep 'webapp' > /dev/null
wget -q -O - --post-data 'payload=ZWNobyAiQ0NEQ19XRUJfT0siOw==' \
    http://127.0.0.1:8080/uploads/preview.php | grep 'CCDC_WEB_OK' > /dev/null
wget -q -O - 'http://127.0.0.1:8081/debug.php?cmd=id' | grep 'webapp' > /dev/null
printf 'PASS: both default webshells and custom-root webshell run as webapp\n'
bind_result=$(printf 'id -u\nexit\n' | socat -T3 -t1 - TCP:127.0.0.1:4444)
printf '%s\n' "$bind_result" | grep '^0$' > /dev/null
printf 'PASS: loopback-only bind shell operates inside the container\n'
grep 'CCDC_LAB_PRELOAD_MARKER' /var/log/ccdc-lab/preload-events.log > /dev/null
mapped=no
for proc in /proc/[0-9]*; do
    if grep '/tmp/.cache/libaudit.so' "$proc/maps" > /dev/null 2>&1; then mapped=yes; break; fi
done
[ "$mapped" = yes ]
printf 'PASS: marker library was loaded and remains mapped in a live process\n'
pgrep -x crond > /dev/null
printf 'PASS: cron daemon running (scheduled callbacks fire on the next minute)\n'
if grep '^ACL=available$' /var/lib/ccdc-lab/seed-status > /dev/null; then
    support_uid=$(id -u support)
    getfacl -p -n /etc/profile.d/40-service.sh | grep "^user:$support_uid:rw-" > /dev/null
    printf 'PASS: planted ACL grants are present\n'
else
    printf 'SKIP: backing filesystem cannot store extended ACLs\n'
fi
if ip -4 route | grep '^default ' > /dev/null; then
    printf 'FAIL: expected an internal Docker network without an external default route.\n' >&2
    exit 1
fi
printf 'PASS: container has no external default route\n'
printf 'All live lab checks passed.\n'
