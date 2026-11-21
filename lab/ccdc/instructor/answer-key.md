# Instructor scenario inventory

The web image intentionally contains the following independent investigative leads. They are installed on build and reinstated by reset. They are training fixtures and should not be used outside the isolated lab.

- `deploysvc`: extra local account with password `service-lab` and an authorized SSH public key under its home. The generated private key is discarded during the image build; the account remains usable with its password.
- `/etc/cron.d/site-refresh` executes `/opt/site-tools/refresh` every minute as root; it writes `/var/lib/site-cache/refresh.log`.
- `/opt/site-tools/on-start` is invoked by the container entrypoint and appends to `/var/lib/site-cache/boot.log` at startup.
- `/etc/pam.d/sshd` loads `pam_env.so` with `/etc/security/site-env.conf`, adding a harmless session variable. This is a configuration change, not a credential-stealing PAM module.
- `/etc/ld.so.preload` loads `/usr/local/lib/libsitecache.so`, whose constructor appends `loaded` to `/var/lib/site-cache/preload.log` whenever permissions permit. This is a functional glibc preload fixture, not a stealth mechanism.
- `/var/www/html/.maintenance.php?action=identity` is an exposed maintenance command endpoint. Other supported actions are `processes` and `uptime`; its commands run with the web server's container privileges. It intentionally accepts only these fixed commands.
- `/etc/apt/apt.conf.d/90site-cache` runs a post-invoke command that creates `/var/lib/site-cache/package-event` after dpkg operations.
- `/opt/site-tools/file-search` is a setuid-root copy of `find`.

The Alpine DNS server is a clean second target with SSH and a local DNS record, useful for comparing distributions. Database credentials and SSH passwords are deliberately weak lab credentials. The database is a separate container, and scoring checks availability and successful transactions rather than detecting any fixture. `outage` and `restore` exercise availability separately. No host kernel modules are loaded.
