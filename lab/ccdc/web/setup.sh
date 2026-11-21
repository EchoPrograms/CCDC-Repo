#!/bin/sh
set -eu
mkdir -p /run/sshd /var/lib/site-cache /opt/site-tools /etc/cron.d
useradd -m -s /bin/bash defender
printf 'defender:practice-lab' | chpasswd
printf 'defender ALL=(ALL) NOPASSWD:ALL\n' > /etc/sudoers.d/defender
chmod 440 /etc/sudoers.d/defender
useradd -m -s /bin/bash deploysvc
printf 'deploysvc:service-lab' | chpasswd
ssh-keygen -q -t ed25519 -N '' -f /tmp/site-key
mkdir -p /home/deploysvc/.ssh
cp /tmp/site-key.pub /home/deploysvc/.ssh/authorized_keys
chown -R deploysvc:deploysvc /home/deploysvc/.ssh
chmod 700 /home/deploysvc/.ssh
chmod 600 /home/deploysvc/.ssh/authorized_keys
rm /tmp/site-key /tmp/site-key.pub
printf '#!/bin/sh\ndate -u >> /var/lib/site-cache/refresh.log\n' > /opt/site-tools/refresh
chmod 755 /opt/site-tools/refresh
printf '* * * * * root /opt/site-tools/refresh\n' > /etc/cron.d/site-refresh
chmod 644 /etc/cron.d/site-refresh
printf 'session optional pam_env.so envfile=/etc/security/site-env.conf\n' >> /etc/pam.d/sshd
printf 'SITE_PROFILE DEFAULT=staging\n' > /etc/security/site-env.conf
printf 'DPkg::Post-Invoke { "touch /var/lib/site-cache/package-event"; };\n' > /etc/apt/apt.conf.d/90site-cache
gcc -shared -fPIC -o /usr/local/lib/libsitecache.so /tmp/marker.c
printf '/usr/local/lib/libsitecache.so\n' > /etc/ld.so.preload
cp /usr/bin/find /opt/site-tools/file-search
chmod 4755 /opt/site-tools/file-search
printf '#!/bin/sh\ndate -u >> /var/lib/site-cache/boot.log\n' > /opt/site-tools/on-start
chmod 755 /opt/site-tools/on-start
printf '\nPasswordAuthentication yes\nPermitRootLogin no\n' >> /etc/ssh/sshd_config
rm -f /tmp/marker.c /tmp/setup.sh
