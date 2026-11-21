#!/bin/sh
# Deliberately insecure training fixtures; disposable isolated Ubuntu clone only.
set -eu
[ "${CCDC_DISPOSABLE_VM:-}" = 1 ] || { echo 'Set CCDC_DISPOSABLE_VM=1 inside the disposable VM.' >&2; exit 1; }
[ "$(id -u)" = 0 ] && [ -d /run/systemd/system ] || { echo 'Root and running systemd required.' >&2; exit 1; }
for cmd in apache2ctl php gcc sudo sshd crontab; do command -v "$cmd" >/dev/null || { echo "Missing $cmd" >&2; exit 1; }; done
[ ! -e /var/lib/ccdc-practice/.seeded ] || { echo 'Already seeded'; exit 1; }
mkdir -p /var/lib/ccdc-practice /var/www/ccdc-practice /opt/ccdc-tools /run/sshd
chown www-data:www-data /var/lib/ccdc-practice
chmod 770 /var/lib/ccdc-practice
id defender >/dev/null 2>&1 || useradd -m -s /bin/bash defender
printf 'defender:practice-lab\n' | chpasswd
printf 'defender ALL=(ALL) NOPASSWD:ALL\n' > /etc/sudoers.d/ccdc-defender
chmod 440 /etc/sudoers.d/ccdc-defender
id deploysvc >/dev/null 2>&1 || useradd -m -s /bin/bash deploysvc
printf 'deploysvc:service-lab\n' | chpasswd
mkdir -p /home/deploysvc/.ssh
ssh-keygen -q -t ed25519 -N '' -f /tmp/ccdc-lab-key
cp /tmp/ccdc-lab-key.pub /home/deploysvc/.ssh/authorized_keys
chown -R deploysvc:deploysvc /home/deploysvc/.ssh
chmod 700 /home/deploysvc/.ssh; chmod 600 /home/deploysvc/.ssh/authorized_keys
rm -f /tmp/ccdc-lab-key /tmp/ccdc-lab-key.pub
cp /mnt/ccdc-seed/vm-app.php /var/www/ccdc-practice/index.php
cp /mnt/ccdc-seed/vm-maintenance.php /var/www/ccdc-practice/.maintenance.php
cat > /etc/apache2/sites-available/ccdc-practice.conf <<'CONF'
<VirtualHost 127.0.0.1:18080>
 DocumentRoot /var/www/ccdc-practice
 <Directory /var/www/ccdc-practice>
  Require all granted
 </Directory>
</VirtualHost>
CONF
printf '\nListen 127.0.0.1:18080\n' >> /etc/apache2/ports.conf
a2ensite ccdc-practice >/dev/null
printf '#!/bin/sh\ndate -u >> /var/lib/ccdc-practice/refresh.log\n' > /opt/ccdc-tools/refresh
chmod 755 /opt/ccdc-tools/refresh
printf '* * * * * root /opt/ccdc-tools/refresh\n' > /etc/cron.d/ccdc-refresh
chmod 644 /etc/cron.d/ccdc-refresh
printf 'DPkg::Post-Invoke { "touch /var/lib/ccdc-practice/package-event"; };\n' > /etc/apt/apt.conf.d/90ccdc-cache
cp /usr/bin/find /opt/ccdc-tools/file-search
chmod 4755 /opt/ccdc-tools/file-search
cat > /tmp/ccdc-marker.c <<'SRC'
#include <fcntl.h>
#include <unistd.h>
__attribute__((constructor)) static void mark(void) { int fd=open("/var/lib/ccdc-practice/preload.log",O_WRONLY|O_CREAT|O_APPEND,0666); if(fd>=0){(void)write(fd,"loaded\n",7);close(fd);} }
SRC
gcc -shared -fPIC -o /usr/local/lib/libccdc-cache.so /tmp/ccdc-marker.c
printf '\n/usr/local/lib/libccdc-cache.so\n' >> /etc/ld.so.preload
rm -f /tmp/ccdc-marker.c
apache2ctl configtest
systemctl enable --now ssh cron
systemctl restart apache2
install -o root -g root -m 644 /dev/null /var/lib/ccdc-practice/.seeded
printf 'CCDC_SEED_COMPLETE\n'
