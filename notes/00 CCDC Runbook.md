---
updated: 2026-11-20
tags: [ccdc, runbook]
aliases: [CCDC, CCDC Quick Reference]
---
# CCDC runbook — solo Linux tryout

**Start here during competition.** Keep these notes open locally in Obsidian. Run jump-box commands in a terminal or SSH session from the root of your CCDC repository clone, wherever you cloned it. Source paths are relative to that root. Replace `192.0.2.10` with an assigned target; it is an example address.

## Two tryout phases

| Phase | Run | Result |
| --- | --- | --- |
| 1 · Preparation | `./coordinate/ctl setup --targets 192.0.2.10 --user defender` | Backups, baseline, logging, missing scanning tools |
| 1 · Wazuh startup | [[Starting Checklist#Phase 1 — Wazuh startup\|Install the manager and enroll agents]] | Central logging and monitoring |
| 2 · Hunt + harden | `./coordinate/ctl hunt --targets 192.0.2.10 --user defender` | Read-only persistence findings, severity ordered |
| 2 · Userspace inspection | `./coordinate/ctl rootkit --targets 192.0.2.10 --user defender -- --userspace-only` | Static userspace view; use its selected cleanup workflow for confirmed implants |
| 2 · Harden preview | `./coordinate/ctl harden --targets 192.0.2.10 --user defender -- --dry-run` | Preview package recovery and Apache changes |
| 2 · Harden apply | `./coordinate/ctl harden --targets 192.0.2.10 --user defender` | Core package reinstalls and Apache protections |
| 2 · After cleanup | `./coordinate/ctl setup --targets 192.0.2.10 --user defender -- --snapshot-only` | New backup and comparison baseline |

> [!important] Phase boundaries
> **Phase 1:** setup, backups, inventory, logging and Wazuh monitoring. **Phase 2:** hunting, cleanup and preventative hardening together. Only backup archives/directories receive immutable flags. Leave automatic blocking/response off during preparation.

Coordinate runs one script command per invocation. Its `hunt`, `rootkit` and `harden` commands all belong to tryout phase 2; there is no separate permission stage between them. Password authentication is interactive; Coordinate normally prompts again when downloading results. Targets need no Python for the hunter scripts. See [[Coordinate - Jump Box|Coordinate installation, credentials and recovery]].

## Immediate working order

1. Fill a [[Host Notes Template|host note]] with distro/version, IPs, services, dependencies and useful paths. Keep quick notes on current problems and keep the scoreboard visible. The scripts retain detailed logs and reports.
2. Follow [[Starting Checklist|phase 1 startup]]: run setup on the targets, install Wazuh on the manager host, enroll agents and verify incoming events.
3. In phase 2, run the shell hunter **and** the static userspace collector. Add custom application roots to the hunt, then clean up and harden within this same phase.
4. Triage confirmed active privileged execution first: loader/PAM tampering, root backdoors, SSH hooks, malicious services/cron, then webshells and lower-confidence changes. The report's severity is a starting point; service impact and evidence determine the next action.
5. Prioritize [[LD Preload - Userspace Cleanup|LD preload cleanup]]. Remove confirmed launch paths, then replace affected running application processes deliberately.
6. Apply [[Linux Hardening Checklist|targeted hardening]], test scored transactions and new SSH access, rerun the hunt, then refresh the baseline when ready.

## Commands you will reuse

```sh
# Run from the repository root on the jump box.
./coordinate/ctl install

# Extra trees: use the real application and mounted-data paths.
./coordinate/ctl hunt --targets 192.0.2.10 --user defender -- \
  --web-root /srv/shop/public --scan-root /data

# Nonstandard SSH port, including the practice target.
./coordinate/ctl setup --targets 127.0.0.1 --port 2222 --user defender
```

## Find the right guide

`Competition/` contains checklists and the host template. `Hunter/` contains the pipeline and logging guides. `Reference/` contains tool guides, the practice lab and deeper reading.

| Need | Open |
| --- | --- |
| Host details, kernel/package versions, ports and dependencies | [[Host Info Commands\|Copy-paste inventory commands]] |
| Service health, alerts and controlled recovery | [[Service Watchdogs and Alerts\|Watchdogs and Wazuh]] |
| Packet evidence and inject analysis | [[Packet Capture - Wireshark and Injects\|PCAP and Wireshark]] |
| Default-deny inbound/outbound service rules and SSH rollback | [[Firewall - Default Deny with iptables\|iptables firewall]] |
| Backup contents, baseline versions, immutability | [[Hunter Setup - Backups and Logging\|Setup]] |
| Findings, coverage, package integrity, offline scans | [[Hunter Hunt - Persistence Triage\|Hunt]] |
| Exact preload preview/apply/recheck | [[LD Preload - Userspace Cleanup\|Userspace cleanup]] |
| Package managers, script arguments, legacy scripts | [[Reference Hardening script\|Script reference]] |
| Audit searches and recorded sudo sessions | [[Logging - Auditd and Sudo Replay\|Logging]] |
| Apache, PHP and application recovery | [[Webshell Hardening Checklist\|Webshells]] |
| Optional local tools | [[Tools - SnoopyOnSecurity\|SnoopyOnSecurity]] · [[PII Searcher\|PII searches]] |
| Disposable practice | [[Alpine Practice Lab\|Alpine SSH lab]] · [[CCDC Service Practice Lab\|Service lab]] |
| Manuals and deeper background | [[References\|References]] |

## Evidence and access

Full remote results are under `reports/coordinate/PHASE-TIME.RANDOM/output/downloads/HOST/artifacts/`. Target backups stay under `/.x86`; they are **not** downloaded automatically. Keep reports and evidence off the target in private storage, and passwords in your credential store. Use the host note for current service details and quick notes.

Keep an established root session plus a second tested SSH session during authentication or service changes. No console means recovery options are limited. A successful collector exit means the collection completed; findings can still exist, and a compromised kernel can conceal evidence.
