---
updated: 2026-11-20
tags: [ccdc, checklist, hardening]
---
# Linux hardening checklist

**Phase 2 covers hunting, cleanup and preventative hardening together.** Use the initial findings to guide changes; follow [[Starting Checklist|phase 1 startup]] for backups, logging and Wazuh first. Keep one established root shell and a second tested SSH connection; test scored services after each logical change.

## 1. Review the hunt and stop active persistence

- [ ] Keep full hunt/static reports off-host and retain the first setup snapshot.
- [ ] Prioritize [[LD Preload - Userspace Cleanup|confirmed loader persistence]] before relying on package reinstall commands.
- [ ] Preserve and remove exact malicious cron jobs, services, hooks, accounts or webshells. Find their reinstallation source.
- [ ] Keep required service jobs and your administrative access. Do not bulk-delete authorized keys, shell profiles or cron directories.

## 2. Access and authentication

Read-only cross-checks, on the target:

```sh
getent passwd
getent group sudo
getent group wheel
sudo visudo -c
sudo ls -la /etc/sudoers.d /etc/pam.d
sudo find /etc/pam.d -type f -mtime -30 -print
```

If `getent` is unavailable, inspect `/etc/passwd` and `/etc/group`; that misses external NSS identities. Group membership is only one part of privilege: inspect the main sudoers file, includes, direct user grants and other authentication sources too.

- [ ] Identify every UID 0 account, privileged group, sudo rule and unexpected shell-enabled service account.
- [ ] Review authorized key fingerprints/options, `AuthorizedKeysCommand`, `ForceCommand`, `PermitUserEnvironment`, `Match` blocks and SSH rc hooks. Keep required scoring and administrative access.
- [ ] Rotate OS **and application/database** passwords in a planned order. Update dependent clients and your credential store, then test a fresh login.
- [ ] Inspect PAM includes for unknown modules, `pam_exec`, `pam_permit` and control flags that bypass expected authentication. These names can have legitimate uses; check the actual chain.

Locate key files by name without dumping private key contents:

```sh
sudo find /root /home /etc/ssh -type f \
  \( -name authorized_keys -o -name authorized_keys2 -o -name id_rsa \
     -o -name id_ed25519 -o -name id_ecdsa \) -print
```

Add custom home paths from passwd/NSS. Use the hunter's broader inventory for keys outside these common roots.

For a suspicious PAM module, determine the actual path first, then check package ownership and bytes. Examples, **only on the matching distro/layout**:

```sh
dpkg -S /lib/x86_64-linux-gnu/security/pam_unix.so
rpm -qf /usr/lib64/security/pam_unix.so
```

Ownership is provenance evidence, not byte verification. Use [[Hunter Hunt - Persistence Triage|integrity results]] and trusted packages; don't paste a path from another distro blindly.

## 3. Scheduled and startup execution

```sh
sudo crontab -l
sudo ls -la /etc/cron.d /var/spool/cron
```

Review `/etc/crontab`, `/etc/crontabs`, periodic directories, user spools and `at` jobs where present. A root `crontab -l` does not list every user's jobs. Cron is not the only scheduler.

For systemd hosts:

```sh
systemctl --no-pager list-units --type=service --all
systemctl --no-pager list-unit-files
systemctl --no-pager list-timers --all
```

Inspect exact `ExecStart`, environment files, drop-ins and user units. On OpenRC, use `rc-status --all` and `rc-update show`; also inspect `/etc/init.d` and `/etc/local.d`. Remove the malicious launch mechanism, not the scheduler itself. Review package hooks, MOTD, udev, rc.local and shell/login files in the hunter report.

## 4. Restore core packages and web protection

- [ ] Preview [[Hunter Harden - Package and Apache Recovery|hunter-harden]] on one host.
- [ ] Confirm package repositories and required application behavior before applying.
- [ ] Run the hardener and review its complete/partial result.
- [ ] Follow [[Webshell Hardening Checklist]] for app fixes, uploads, PHP and CRS false positives.
- [ ] Check fresh SSH authentication, sudo, app login, static/dynamic pages and database-backed transactions.

## 5. Network and final verification

- [ ] Follow [[Firewall - Default Deny with iptables]]: deny inbound/outbound/forwarded traffic and allow only required services and replies. Build the source/destination/protocol/port flow table first; include both IP families.
- [ ] Preserve jump-box SSH, scoreboard probes, DNS, database/app dependencies and repository access as required. Apply rules one host at a time with a tested recovery method.
- [ ] Recheck listeners and externally test required paths; a locally listening socket does not prove reachability.
- [ ] Use [[Packet Capture - Wireshark and Injects]] to preserve an inject window or diagnose missing requests/replies without opening broad firewall exceptions.
- [ ] Rerun hunt and static userspace collection with the same extra roots. Investigate recreated artifacts.
- [ ] Refresh setup with `--snapshot-only` after reviewing the state. Preserve the original snapshot; scripts retain the detailed operation logs.

No generic firewall lockdown, reboot or module lock belongs in the automatic first response for an SSH-only scored host. See [[References|manuals]] for deliberate changes beyond the scripts.
