---
updated: 2026-11-20
tags: [ccdc, logging, auditd, sudo]
---
# Logging — auditd and sudo replay

Setup configures these facilities where the OS supports them. Verify events arrive; configuration files alone do not establish working collection. Commands here run on the target unless specified otherwise.

## Quick verification after setup

```sh
sudo visudo -c
sudo id
sudo sudoreplay -l
sudo auditctl -s
sudo auditctl -l
```

The harmless `sudo id` should generate a recorded sudo session. Check audit status for enabled collection, backlog pressure and lost events. Containers may not control the host audit subsystem; setup records missing capabilities rather than making the container privileged.

## Sudo I/O replay

Setup installs a validated `/etc/sudoers.d/99-hunter-logging` with `log_input`, `log_output`, `/var/log/sudo-io` and `/var/log/sudo.log`. It enables the include if necessary, validates the combined policy and grants no extra sudo privileges.

```sh
# List sessions; copy a session ID from the result.
sudo sudoreplay -l
sudo sudoreplay -l user defender

# Replace with the real ID, for example the TSID from sudo.log.
sudo sudoreplay REPLACE-SESSION-ID
sudo tail -n 60 /var/log/sudo.log
```

Replay records input/output for sudo-launched sessions, including commands inside a recorded interactive root shell. It is not a complete record of all SSH traffic or every directly root-launched process. I/O logs can contain sensitive typed input and application output; keep the raw files private and outside shared Obsidian notes. See the [sudoreplay manual](https://man7.org/linux/man-pages/man8/sudoreplay.8.html) and [sudoers logging options](https://www.sudo.ws/docs/man/sudoers.man/).

## Audit searches

Setup's persistent rules are `/etc/audit/rules.d/70-hunter.rules`. Useful keys:

| Key | Meaning |
| --- | --- |
| `hunter_root_exec` | Execution with effective UID 0 |
| `hunter_user_exec` | Execution attributed to user login IDs |
| `hunter_service_exec` | Execution without a normal login audit ID |
| `hunter_persistence` | Writes/attribute changes on watched sensitive paths |
| `hunter_modules` | Module load/unload syscalls |

```sh
sudo ausearch -k hunter_persistence -ts today -i
sudo ausearch -k hunter_root_exec -ts recent -i
sudo ausearch -k hunter_user_exec -ts recent -i
sudo ausearch -k hunter_service_exec -ts recent -i
sudo ausearch -k hunter_modules -ts today -i
```

Correlate `auid` (login identity), `uid`/`euid`, executable, arguments, PID/parent and path records. One event can contain multiple record types. These rules generate substantial execution traffic; watch disk use, lost-event counters and rotation. Setup does not set audit's irreversible `-e 2` lock.

Audit file watches depend on the installed rules and supported kernel facilities. A watched file that did not exist when rules were loaded may have been skipped; inspect `auditctl -l` and setup gaps. Host root can tamper with local logs, so preserve important records off-host. References: [auditctl](https://man7.org/linux/man-pages/man8/auditctl.8.html), [ausearch time/key filtering](https://man7.org/linux/man-pages/man8/ausearch.8.html).

## SSH, cron and system logs

On systemd hosts:

```sh
sudo journalctl --disk-usage
sudo journalctl -u sshd -u ssh --since '30 minutes ago' --no-pager
sudo journalctl -u cron -u crond --since today --no-pager
sudo journalctl -k --since today --no-pager
```

Use only units present on the host. OpenRC/syslog systems commonly use `/var/log/messages`, `/var/log/auth.log` or `/var/log/secure`. When rsyslog accepts the hunter drop-in, also inspect:

```sh
sudo tail -n 80 /var/log/hunter-auth.log
sudo tail -n 80 /var/log/hunter-cron.log
sudo tail -n 80 /var/log/hunter-daemon.log
```

Setup sets SSH `LogLevel VERBOSE` after validation and attempts a reload for logging. Journald is made persistent with a 512 MiB cap, 256 MiB keep-free target and 30-day retention where supported. Audit rotation uses configured limits; sudo/app log volume also needs monitoring. Missing files can mean no matching events or an unavailable logging path—check setup records and service state.

Application logs matter too: inspect the actual Apache/PHP/database service configuration for destinations, request IDs and timestamps. Setup does not automatically centralize every application log. Complete [[Starting Checklist#Phase 1 — Wazuh startup|Wazuh startup]] during phase 1 and verify each agent sends events; configure collection of the actual application and hunter log paths as needed.

## Competition loop

Use saved logs/reports to investigate a relevant time window and verify that the same activity stops after remediation. Add only a useful path or unresolved issue to the host note. Keep raw logs and replay files in private evidence storage outside the committed notes.

See [[Hunter Setup - Backups and Logging|setup details]] and [journald configuration](https://www.freedesktop.org/software/systemd/man/latest/journald.conf.html).
