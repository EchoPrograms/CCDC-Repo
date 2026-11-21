---
updated: 2026-11-20
tags: [ccdc, references]
---
# References

Open a focused guide first; use these primary manuals for the exact behavior or a deeper investigation. Local script behavior was checked against the repository on **2026-11-20**. Upstream manuals may describe newer features than an older competition host supports; its installed `man`/`--help` is the release-specific reference.

## Local source map

All source paths below are relative to the root of your repository clone. Read these notes locally in Obsidian; inspect the corresponding source in your local clone or on the jump box.

| Subject | Obsidian guide | Source to inspect |
| --- | --- | --- |
| Full pipeline | [[00 CCDC Runbook\|Runbook]] · [[Reference Hardening script\|Script map]] | `README.md`; each script's `--help` |
| Host/version lookups | [[Host Info Commands\|Copy-paste inventory commands]] | Target OS/kernel, network, units and native package queries |
| Preparation | [[Hunter Setup - Backups and Logging\|Setup]] | `hunter-setup.sh` |
| Persistence detection | [[Hunter Hunt - Persistence Triage\|Hunt]] | `hunter-hunt.sh` |
| Static userspace cleanup | [[LD Preload - Userspace Cleanup\|LD preload]] | `rootkit/README.md`, `collector.go`, `build.sh` |
| Package/Apache recovery | [[Hunter Harden - Package and Apache Recovery\|Harden]] | `hunter-harden.sh` |
| Fleet transport | [[Coordinate - Jump Box\|Coordinate]] | `coordinate/README.md`, `ctl`, `remote.sh`, `install.sh` |
| Lab scenarios | [[Alpine Practice Lab\|Alpine lab]] | `lab/alpine/README.md`, `scenarios.tsv`, `ctl` |
| Extra tools | [[Tools - SnoopyOnSecurity\|Snoopy inventory]] | Exact project files under `SnoopyOnSecurity/` |

## Persistence and userspace loaders

- [0xMatheuZ: Linux Threat Hunting Persistence](https://matheuzsecurity.github.io/hacking/linux-threat-hunting-persistence/) — the original coverage source: keys, cron, profiles, package hooks, privilege, systemd, preload/PAM, ACLs, init/MOTD, mounts and webshells. Use it for mechanism background; follow the current local scripts for this pipeline.
- [Linux dynamic loader, ld.so(8)](https://man7.org/linux/man-pages/man8/ld.so.8.html) — `LD_PRELOAD`, `LD_AUDIT`, library lookup, secure execution and `/etc/ld.so.preload`. Explains why clearing one environment variable is insufficient.
- [OpenSSH sshd_config(5)](https://man7.org/linux/man-pages/man5/sshd_config.5.html) — key commands, forced commands, environment and `Match` semantics; validate before reloading.
- [systemctl](https://www.freedesktop.org/software/systemd/man/latest/systemctl.html) — active units versus installed unit files, timers, inspection and service lifecycle.

## Logging and evidence

- [auditctl(8)](https://man7.org/linux/man-pages/man8/auditctl.8.html) — active rules, audit status, filtering and kernel limitations.
- [ausearch(8)](https://man7.org/linux/man-pages/man8/ausearch.8.html) — event keys, time ranges and decoded records.
- [sudoers manual](https://www.sudo.ws/docs/man/sudoers.man/) — input/output logging options, includes and policy semantics.
- [sudoreplay(8)](https://man7.org/linux/man-pages/man8/sudoreplay.8.html) — list, filter and replay recorded sudo sessions.
- [journald.conf](https://www.freedesktop.org/software/systemd/man/latest/journald.conf.html) — persistence, retention, disk caps and forwarding settings.
- [Wazuh quickstart](https://documentation.wazuh.com/current/quickstart.html) — the official all-in-one Bash installer used during [[Starting Checklist#Phase 1 — Wazuh startup|phase 1 startup]]. The `4.14` command was current when checked on 2026-11-20.
- [Wazuh Linux agent deployment](https://documentation.wazuh.com/current/installation-guide/wazuh-agent/wazuh-agent-package-linux.html) — enroll target agents after the manager is available; verify connected agents and incoming events during startup.

Operational examples: [[Logging - Auditd and Sudo Replay]].

## Network monitoring and firewall

- [[Service Watchdogs and Alerts]] and [[Watchdog Wazuh Configuration]] — health probes, DOWN/RECOVERED rules and notification delivery.
- [[Packet Capture - Wireshark and Injects]] — bounded packet recording, export and analysis; [tcpdump](https://man7.org/linux/man-pages/man8/tcpdump.8.html), [dumpcap](https://www.wireshark.org/docs/man-pages/dumpcap.html), [Wazuh/Suricata integration](https://documentation.wazuh.com/current/proof-of-concept-guide/integrate-network-ids-suricata.html).
- [[Firewall - Default Deny with iptables]] — explicit inbound/outbound service pairs and rollback; [iptables](https://man7.org/linux/man-pages/man8/iptables.8.html), [iptables-restore](https://man7.org/linux/man-pages/man8/iptables-restore.8.html), [iptables-apply](https://man7.org/linux/man-pages/man8/iptables-apply.8.html).

## Web stack and PII searches

- [Apache apachectl reference](https://httpd.apache.org/docs/2.4/programs/apachectl.html) — config tests, virtual-host/module output and graceful control.
- [OWASP Core Rule Set documentation](https://coreruleset.org/docs/) — installation, rule-engine behavior and operational setup.
- [CRS false positives and tuning](https://coreruleset.org/docs/2-how-crs-works/2-3-false-positives-and-tuning/) — identify the triggering rule and make narrow exclusions for legitimate requests.
- [PHP core configuration directives](https://www.php.net/manual/en/ini.core.php) — `disable_functions`, per-directory configuration and related limits; not a complete webshell defense.
- [PHP file-upload security](https://www.php.net/manual/en/features.file-upload.php) — upload handling and validation background.
- [ripgrep guide](https://github.com/BurntSushi/ripgrep/blob/master/GUIDE.md) — regexes, hidden/ignored files, binary handling and filenames-only output.

Operational examples: [[Webshell Hardening Checklist]] · [[PII Searcher]].

## Coordinate and the lab

- [Coordinate upstream](https://github.com/Foister150/coordinate-foister) — native command flags/build instructions; the local wrapper adds phase selection and two-stage evidence collection.
- [Coordinate runner source](https://github.com/Foister150/coordinate-foister/blob/main/internal/runner/runner.go) and [bug audit](https://github.com/Foister150/coordinate-foister/blob/main/BUG_AUDIT.md) — transport behavior and host-key verification limitation.
- [Docker bridge networking](https://docs.docker.com/engine/network/drivers/bridge/) — container network isolation and published ports; a container listener is separate from a reachable host port.

## Kernel mechanisms — advanced reference

These explain evidence and recovery limits; they are not instructions to reboot or lock modules during preparation.

- [Module-loading syscalls](https://man7.org/linux/man-pages/man2/init_module.2.html) — how privileged processes load kernel modules.
- [modules_disabled sysctl](https://docs.kernel.org/admin-guide/sysctl/kernel.html#modules-disabled) — one-way prevention of module loads **and unloads** until reboot, without removing existing modules.
- [Kernel module signing](https://docs.kernel.org/admin-guide/module-signing.html) — signature policy, trust and enforcement.
- [Tainted kernels](https://www.kernel.org/doc/html/latest/admin-guide/tainted-kernels.html) — decode taint flags without treating taint itself as proof of a rootkit.
- [systemd-modules-load.service](https://www.freedesktop.org/software/systemd/man/latest/systemd-modules-load.service.html) — early boot module loading, including initramfs context.
- [Initramfs background](https://docs.kernel.org/filesystems/ramfs-rootfs-initramfs.html) — why reboot can execute persistence before the normal root filesystem and SSH service.

Keep the competition response focused on [[LD Preload - Userspace Cleanup|confirmed userspace persistence]]. A trusted rebuild/reimage is the recovery path for confirmed kernel compromise; neither package reinstalls nor a clean live scan establishes kernel trust.
