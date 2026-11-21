#!/bin/sh
set -eu
[ -f /.dockerenv ] || { printf 'Docker container required.\n' >&2; exit 1; }
if [ ! -f /var/lib/ccdc-lab/seeded ]; then
    case ${LAB_PASSWORD:-CCDC-Practice-2026!} in
        *:*) printf 'LAB_PASSWORD must not contain a colon.\n' >&2; exit 1 ;;
        *'
'*) printf 'LAB_PASSWORD must not contain a newline.\n' >&2; exit 1 ;;
    esac
    printf 'defender:%s\n' "${LAB_PASSWORD:-CCDC-Practice-2026!}" | chpasswd
    CCDC_LAB_SEED=container-only /opt/lab/seed.sh
    mkdir -p /etc/ssh
    cat > /etc/ssh/sshd_config <<'SSHD'
Port 22
ListenAddress 0.0.0.0
HostKey /etc/ssh/ssh_host_ed25519_key
HostKey /etc/ssh/ssh_host_rsa_key
PidFile /run/sshd.pid
PermitRootLogin no
PasswordAuthentication yes
PermitEmptyPasswords no
KbdInteractiveAuthentication no
PubkeyAuthentication yes
AuthorizedKeysFile .ssh/authorized_keys
AllowUsers defender
PrintMotd yes
UseDNS no
LogLevel VERBOSE
Subsystem sftp internal-sftp
SSHD
    printf '\nCCDC disposable practice target. Run: sudo /opt/ccdc/ccdc-hunt.sh\n' > /etc/motd
fi
unset LAB_PASSWORD
ssh-keygen -A
mkdir -p /run/sshd
/usr/sbin/sshd -t
# Explicit startup provides repeatable container behavior without running a
# system-wide init that expects writable host cgroups/sysfs.
if [ -x /etc/rc.local ]; then /etc/rc.local; fi
if [ -x /etc/init.d/network-check ]; then /etc/init.d/network-check start; fi
crond -b -l 8 -L /var/log/ccdc-lab/cron.log
su -s /bin/sh -c 'exec /usr/bin/php84 -S 0.0.0.0:8080 -t /var/www/html' webapp >> /var/log/ccdc-lab/http.log 2>&1 &
su -s /bin/sh -c 'exec /usr/bin/php84 -S 127.0.0.1:8081 -t /opt/customer/public' webapp >> /var/log/ccdc-lab/customer-http.log 2>&1 &
if [ -f /tmp/.cache/libaudit.so ] && [ -x /usr/local/libexec/lab-sleeper ]; then
    LD_PRELOAD=/tmp/.cache/libaudit.so /usr/local/libexec/lab-sleeper &
fi
printf 'CCDC Alpine lab ready: defender via SSH, sudo -n enabled.\n'
exec /usr/sbin/sshd -D -e
