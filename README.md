# CCDC hunter pipeline

Three standalone POSIX `/bin/sh` scripts, with **no Python on targets**, plus optional static collectors and a service watchdog. The tryout has two phases: preparation, then hunting/cleanup/preventative hardening together. The hunters cover the persistence locations in [Linux Threat Hunting Persistence](https://matheuzsecurity.github.io/hacking/linux-threat-hunting-persistence/) and add package integrity, snapshot comparison, file capabilities, extra startup hooks, and logging checks.

```sh
# First part: preparation only
sudo sh hunter-setup.sh

# When the hunt phase is allowed
sudo sh hunter-hunt.sh

# In the same second phase, review and apply preventative actions
sudo sh hunter-harden.sh
```

`hunter-setup.sh` installs scanning/logging tools, preserves backups and snapshots, and configures logging. It does not hunt for threats, reinstall core packages, enable web protection, or change authentication grants. Only its backup directory/archives get immutable flags; live files, manifests and logs do not. `hunter-hunt.sh` collects evidence and prints findings from **CRITICAL → HIGH → MEDIUM → LOW → INFO**, with a location, evidence, and suggested fix for each finding. Every hunt automatically saves a private plain text report; terminal headings are colored when supported. Hunting does not remove implants, change authentication, restart services, or repair files. `--install-tools` explicitly permits installing scanning tools.

The existing `ccdc-hunt.sh` command remains a launcher; keep `hunter-hunt.sh` beside it. Each of the three scripts can be copied and run independently. `hunter-harden.sh` performs the later package-repair and preventative changes. An optional [static rootkit collector and SSH-only response workflow](rootkit/README.md) adds an independent view against LD_PRELOAD interposition and explicit, selected containment.

## Package managers and systems

| Native manager | Distros/families | Verification |
| --- | --- | --- |
| apt / apt-get | Debian, Ubuntu, Mint, Kali and derivatives | dpkg ownership and checksum verification |
| yum / dnf | RHEL, Rocky, AlmaLinux, CentOS, Fedora, Oracle Linux, Amazon Linux | RPM ownership and verification, with verification scripts disabled |
| zypper | openSUSE Leap/Tumbleweed, SLES/SLED | RPM ownership and verification |
| pacman | Arch, Manjaro, EndeavourOS, Artix | pacman file/metadata checks; paccheck SHA-256 when installed |
| apk | Alpine | APK ownership and installed system file audit |

Setup uses each distro's package names and configured repositories, installing missing tool packages while keeping already installed packages unchanged. It does not add COPR, AUR, EPEL, or other repositories, perform an OS upgrade, or do `pacman -Sy` without an upgrade. A missing optional package is recorded without blocking the other packages. On other Unix systems, available filesystem checks still run; Linux kernel, package, and service features are conditional. Systemd, OpenRC and traditional service commands are supported by setup; the hunter reads init scripts without executing them.

## Setup, backups, and refreshes

```sh
# Back up, install tools, configure logs, and publish a snapshot:
sudo sh hunter-setup.sh

# Include application/data trees and require actual filesystem immutability:
sudo sh hunter-setup.sh --backup-root /data/app --require-immutable

# Refresh after fixing findings, using tools already installed:
sudo sh hunter-setup.sh --no-install

# Refresh backups and snapshot only, without changing logging/packages:
sudo sh hunter-setup.sh --snapshot-only
```

By default each run creates `/.x86/runs/UTC-PID/`. This follows the backup selection in `SnoopyOnSecurity/Linux_Misc/lin.sh`, using synchronous versioned archives instead of a background copy. Backups include `/var/www`, `/etc`, `/home`, `/opt`, `/root`, common additional web directories, simple absolute document roots found in Apache/nginx configuration, and every `--backup-root`. Symlinks are archived as links. GNU tar ACL/xattr preservation is enabled when supported; portable tar retains ordinary metadata. Backup checksums and original source paths are recorded.

Before archive writes, setup estimates selected tree sizes and checks destination free space with a 25% margin plus 256 MiB reserve. An undersized destination or failed size read stops preparation before package/logging changes and preserves the previous baseline. Choose `--state-dir` on a larger filesystem outside the source trees. The estimate uses apparent size where supported; portable allocated-block estimates can undercount sparse files, and other writers/source growth can consume space afterward.

The run also contains:

- `before/` and `after/`: accounts, packages, processes, sockets, services, unit files/timers, recent config changes, cron paths, mounts, and audit status where available.
- `manifest.sha256`: SHA-256, mode, UID, GID and logical path for configs, programs/libraries, user/application/web trees and cron/service state. Symlink hashes describe the link target, without reading through it.
- `metadata.txt`, `capabilities.txt`, `acls.txt`: available filesystem metadata.
- `setup.log`, `errors.log`: package and configuration results.
- `backup-capacity.txt`, `backup-size-estimates.txt`, `backup-filesystem.txt`, `backup-status.txt`: capacity estimates and each attempted archive's status; Coordinate collects these with operation logs.
- `COMPLETE`: completed collection marker. Failed backups never publish a new snapshot.

Setup attempts `chattr +i` only on `RUN/backups/` and its archives before tool installation/logging work, then retries and verifies that backup protection at completion. It does not make the run directory, hash manifests, backup-checksum ledger, logs, live configuration, services or other files immutable. Results are recorded with the run. `--require-immutable` stops before tool/logging changes if the initial backups cannot be sealed, and prevents publishing `latest` if backup protection is incomplete. Earlier backup versions are retained and never unsealed. Repeating setup creates a new version and updates the regular `/.x86/latest` pointer. Use `--state-dir /different/location` in all three scripts to relocate storage; it must be outside the trees being backed up.

All content heuristics run on every hunt, including files already present in a snapshot. The snapshot is used to find changes, not to whitelist files. Backup stores are excluded from broad hunting scans.

Setup needs root, tar and a SHA-256 provider (`sha256sum`, `shasum`, or `openssl`) before its first backup. It installs sudo, audit tooling, ACL/attribute utilities, package verification tools, binutils, lsof, capability utilities, ripgrep and log rotation as available. It never changes user passwords, deletes SSH keys, or removes scheduled jobs.

## Logging during preparation

Setup configures:

- **sudo replay:** validated `/etc/sudoers.d/99-hunter-logging`, input/output logging to `/var/log/sudo-io`, and `/var/log/sudo.log`. Run `sudo sudoreplay -l`, then `sudo sudoreplay SESSION_ID`. Sudo I/O logs include terminal input/output; the directory is root-only. See [sudo I/O logging](https://www.man7.org/linux/man-pages/man5/sudoers.5.html).
- **auditd:** persistent `70-hunter.rules`, root/user/service process execution, changes to authentication, sudo, SSH, cron, startup, audit, web/user/application paths, and kernel module operations. Rotation is set to eight 64 MB files, with storage errors sent to syslog. Setup replaces only its own active rules and preserves other rules. Unsupported kernel/container audit capabilities are recorded. Rules use syscall filters described in [auditctl](https://www.man7.org/linux/man-pages/man8/auditctl.8.html).
- **system logging:** persistent journald storage capped at 512 MB and 30 days, plus auth/cron/daemon rsyslog files when drop-ins are supported. See [journald persistence and retention](https://www.freedesktop.org/software/systemd/man/latest/journald.conf.html).
- **SSH:** `LogLevel VERBOSE`, installed only after `sshd -t` accepts the candidate, followed by a reload.
- **rotation:** `/etc/logrotate.d/hunter` for sudo and dedicated syslog text files.

The previous setup flags `--reinstall-core` and `--apache-harden` are rejected with instructions to use `hunter-harden.sh` during the later phase. Setup never invokes the hunter or hardener. Logging updates preserve existing configuration permissions; setup does not impose `use_pty`, SSH authentication restrictions, firewall rules, PAM repairs or Apache blocking rules.

## Hardening after the hunt

```sh
# Preview package recovery and Apache changes without writing files:
sudo sh hunter-harden.sh --dry-run

# Apply core recovery and available Apache security controls:
sudo sh hunter-harden.sh

# Core recovery only, or web hardening only:
sudo sh hunter-harden.sh --skip-apache
sudo sh hunter-harden.sh --skip-core
```

The hardener supports apt, yum/dnf, zypper, pacman and apk. It reinstalls **already installed** SSH/PAM, sudo, shell, core utilities, process/network tools, libc/OpenSSL, package-manager, audit and web-server packages using the native distro package names. Missing core packages are skipped rather than adding new services. Scanning and logging utilities stay in setup.

For installed Apache, hardening installs available ModSecurity/CRS packages, enables headers/unique_id/security2 where supported, sets `SecRuleEngine On` and `SecAuditEngine RelevantOnly`, and verifies effective CRS includes. It adds `ServerTokens Prod`, `ServerSignature Off`, `TraceEnable Off`, the nosniff header, and removal of X-Powered-By headers. Configuration is tested before reloading an already running Apache service. Failed validation or reload restores this run's config edits and newly enabled module links. Repeating hardening retains its CRS Include. Distro module availability is handled explicitly; see [upstream package layouts](https://modsecurity.org/docs/2-installation/2-5-modsecurity-v2-apache/index.html) and [Apache core directives](https://httpd.apache.org/docs/2.4/mod/core.html).

Each actual run saves a private `STATE/hardening/UTC-PID/` record with `etc-before.tar`, available SHA-256 checksum, configuration rollback copies, `harden.log`, `errors.log`, and a `COMPLETE` or `PARTIAL` marker. Failed operations produce exit status 1. Hardening does not refresh `STATE/latest` or the hunt baseline. Rerun the hunter to check the result, then run setup with `--snapshot-only` when ready to establish the next comparison snapshot.

## Hunting

```sh
sudo sh hunter-hunt.sh
sudo sh hunter-hunt.sh -o /root/tryout-first.txt
sudo sh hunter-hunt.sh --web-root /data/app/public --scan-root /data
sudo sh hunter-hunt.sh --install-tools --color always
sudo sh hunter-hunt.sh --baseline /.x86/runs/OLDER-RUN/manifest.sha256

# Mounted target: no live-host package/process/service commands or installations:
sudo sh hunter-hunt.sh --root /mnt/target --web-root /data/app/public
sudo sh hunter-setup.sh --root /mnt/target
```

Coverage includes:

- Extra UID 0 accounts, local/NSS administrators, empty shadow fields, sudo grants and protection bypasses.
- Global `authorized_keys`/`authorized_keys2` and common private SSH key names, SSH server options, rc/environment hooks and private key permissions. Private key bodies and public key material are omitted.
- System/user shell startup, aliases, desktop autostart and environment files.
- Cron/anacron/at spools, Alpine `/etc/crontabs` and periodic jobs.
- APT, pacman/ALPM, APK, yum/dnf and zypp hooks/plugins.
- Systemd units, drop-ins, timers, generators, runtime units, lingering, active services, OpenRC/local init, rc.local, udev and MOTD.
- PAM configuration and recent changes, unconditional authentication, external helpers/token exposure, unusual module paths, binary strings, ownership and native package checks.
- SUID/SGID interpreters, unusual privileged binaries, world writable privileged files, extended ACLs and powerful file capabilities.
- Loader preload/audit settings, shared libraries, temporary/deleted mappings, process environment injection, kernel module/log/symbol indicators and suspicious process mounts.
- Recursive webshell heuristics, Apache/nginx document-root discovery, `.htaccess`/`.user.ini`, PHP injection settings, and static ModSecurity/module/CRS checks.
- Core SSH/sudo/su and administration binary integrity; audit status and dropped records; changed/new/removed files, ownership/modes, symlink targets, newly active services and new listening endpoints since setup.

Reports default to `./ccdc-hunt-HOST-UTC-PID.txt`, mode **600**, and refuse existing paths/symlinks. The terminal shows the severity-sorted findings and coverage; the saved report adds detailed evidence and collection errors. `--color never` or `NO_COLOR=1` disables terminal color. Exit status: 0 completed, 1 failed/interrupted, 2 invalid arguments; findings do not change the exit status.

Scans stay on one filesystem per root and discover common local mounts. Use repeated `--scan-root`/`--web-root` for additional locations. Config excerpts are limited to 100 active lines, while detection reads the whole file up to 10 MiB. Paths with spaces work; newline, backslash and `|` filenames are unsupported. Offline reads reject paths resolving outside the mounted root. Runtime evidence and package queries are disabled in offline mode. Transient `.ansible/tmp` contents are excluded from snapshot comparisons.

## Rootkits without console access

Build a static collector on the jump box, then run its read-only Coordinate phase when hunting is allowed:

```sh
./rootkit/build.sh amd64
./coordinate/ctl rootkit --targets 192.0.2.10 --user defender
# Alpine practice lab:
./coordinate/ctl rootkit --targets 127.0.0.1 --port 2222 --user defender
# Prioritize LD_PRELOAD and other userspace loader persistence:
./coordinate/ctl rootkit --targets 192.0.2.10 --user defender -- --userspace-only
```

No Go, compiler, Python or shared libraries are needed on targets. It inspects multiple preload libraries, process mappings/environment, module visibility, startup load hooks and BPF handles, retaining a private severity-sorted report. `--userspace-only` focuses on loader persistence, service environment files and login hooks, skipping module/BPF checks. Explicit containment previews selected preload removal or a module-load lock; changes require `--apply`. Applied cleanup automatically rechecks the selected entries and affected processes. It never automatically unloads modules, kills processes, reboots or restarts SSH. Setup remains preparation only. See the [rootkit guide](rootkit/README.md) for commands, access precautions, containment records and the irreversible-until-reboot module switch.

A static executable bypasses userspace loader interposition; it cannot establish trust in a kernel already controlled by an LKM. Confirmed kernel compromise needs trusted rebuild/recovery. Keep a root session and test a second SSH connection before targeted repairs; do not treat a successful scan or disappearance of symptoms as proof of eradication.

## Jump-box Coordinate over SSH passwords

[Coordinate](https://github.com/Foister150/coordinate-foister) is the primary remote runner. If missing, `ctl` builds its executable locally using git and Go on the jump box. You can install ahead of time with `./coordinate/ctl install`; see the [Coordinate setup guide](coordinate/README.md). Run from this repository:

```sh
# First part: preparation only. Omitting "setup" also defaults to this phase.
./coordinate/ctl setup --targets '192.0.2.10-20' --user defender

# When hunting is allowed: severity preview plus complete private reports.
./coordinate/ctl hunt --targets '192.0.2.10-20' --user defender

# Later, explicitly preview or apply hardening:
./coordinate/ctl harden --targets 192.0.2.10 --user defender -- --dry-run
./coordinate/ctl harden --targets 192.0.2.10 --user defender

# Extra web/filesystem roots:
./coordinate/ctl hunt --targets 192.0.2.10 --user defender \
  -- --web-root /data/app/public --scan-root /data

# Alpine lab, after ./lab/alpine/ctl up:
./coordinate/ctl setup --targets 127.0.0.1 --port 2222 --user defender
```

No Ansible, sshpass or target Python is needed. Coordinate prompts for the SSH password for execution and again for collection; sudo uses that password or the account's passwordless sudo grant. Use `--config coordinate/credentials.json` for private per-host credentials, or `--key FILE`/`--agent` for SSH keys. The [runner guide](coordinate/README.md) includes installation, credential examples, output paths, transfer recovery, and the upstream host-key verification limitation.

Each invocation runs exactly one phase. Setup is the only default; hunting, rootkit inspection and hardening require explicit phase names. Full reports and operation logs are fetched into unique private `reports/coordinate/` directories even after a target script fails. The runner forces built-in transfers to avoid automatic rsync installation. `--prepare-only` generates a reviewable payload without connecting. The earlier `ansible/` playbooks remain as a legacy option.

## Service availability and recovery

The [watchdog guide](watchdog/README.md) covers HTTP status/body, DNS answers, TCP, service units, disk/inodes and database query checks. Build the static helper on the jump box, review a manifest, then deploy it through Coordinate:

```sh
./watchdog/build.sh amd64
cp watchdog/examples/services.conf services.conf
# Edit endpoints and units, then install monitoring only:
./coordinate/ctl watch --targets 192.0.2.10 --user defender --watch-config services.conf -- install
./coordinate/ctl watch --targets 192.0.2.10 --user defender -- status
# Phase 2, after testing selected auto policies:
./coordinate/ctl watch --targets 192.0.2.10 --user defender -- enable-recovery --owner local
```

Installation leaves recovery disabled on a new host. Local recovery checks dependencies, consecutive failures, cooldown and a persistent rolling restart budget, then verifies application health after a restart. Sensitive SSH/network/authentication/database units remain alert-only. Wazuh can collect structured events, route notifications and optionally own recovery through the supplied allowlisted Active Response handler. Use one recovery owner per host and independent jump-box probes for network reachability. Wazuh configuration is supplied as reviewable snippets; notifications and a running manager must be configured and tested separately.

## Practice lab and checks

The independent [CCDC service lab](lab/ccdc/README.md) provides PHP/Apache, MariaDB and Alpine DNS, with SSH targets, intentionally insecure changes and functional outage exercises. Its scoring checks availability and database transactions independently of hunter detections. The Compose topology remains runtime-unverified because Docker access was denied. Its [isolated VM alternative](lab/ccdc/vm-README.md) has passed real web transactions, guest-loopback password SSH/sudo and outage/restore checks; it uses file-backed state and no NIC. The [Ubuntu VM guide](lab/vm/README.md) explains disposable overlays for the provided CyberPatriot image. Keep the original archive and base disk unchanged.

The [Alpine SSH lab](lab/alpine/README.md) includes the updated scripts and planted persistence scenarios. Rebuild it to pick up changes:

```sh
./lab/alpine/ctl up
./lab/alpine/ctl ssh
# Inside the target:
sudo sh /opt/ccdc/hunter-setup.sh
# Phase 2: hunting and hardening together:
sudo sh /opt/ccdc/hunter-hunt.sh --web-root /opt/customer/public
sudo sh /opt/ccdc/hunter-harden.sh
```

Local checks do not alter host packages/configuration:

```sh
sh tests/test-hunt.sh
sh tests/test-pipeline.sh
sh tests/test-harden.sh
sh tests/test-coordinate.sh
sh tests/test-coordinate-install.sh
sh tests/test-rootkit.sh
sh tests/test-alpine-lab.sh
sh tests/test-alpine-ctl.sh
sh tests/test-watch-deploy.sh
GO111MODULE=off go test ./watchdog
```

The tests cover config implants, severity ordering, key redaction, offline boundaries, output protection, snapshot refresh/change types, backup hashes, native install/reinstall dispatch, backup-only immutability, preparation phase boundaries, hardening dry-runs, Apache rollback/reruns, BusyBox ash, lab/controller fixtures, and Coordinate execution/collection with reports larger than its command capture limit. Actual package installs, daemon configuration and live Coordinate SSH runs require testing on the target distro; they are not validated by the offline fixture suite.
