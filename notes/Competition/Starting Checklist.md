---
updated: 2026-11-20
tags: [ccdc, checklist]
---
# Starting checklist

[[00 CCDC Runbook|Runbook]] · [[Coordinate - Jump Box|Remote runner]]

## Before connecting

- [ ] Confirm assigned IPs, permitted actions for this phase, scored services and inject deadlines.
- [ ] Make one [[Host Notes Template|host note]] per Linux box: distro/version, IPs, SSH details and service names/ports. Use [[Host Info Commands|the copy-paste commands]] for lookups.
- [ ] Fill in service dependencies and a useful check for each scored service, including login or database-backed requests.
- [ ] Prepare Coordinate on the jump box: `./coordinate/ctl install`.
- [ ] Generate and inspect a local payload before connecting:

```sh
./coordinate/ctl setup --targets 192.0.2.10 --user defender --prepare-only -- --backup-root /srv/shop
```

  This writes a reviewable payload and makes no SSH connection; it does not test authentication, target execution or collection.
- [ ] Keep a working SSH session open. Test sudo; record how to reach a second independent session.

## Phase 1 — backups, tooling and logging

From the root of your repository clone on the jump box:

```sh
# Start with one target. Add actual application trees to the backup.
./coordinate/ctl setup --targets 192.0.2.10 --user defender -- \
  --backup-root /srv/shop
```

- [ ] Confirm the run reports `COMPLETE`; read `stderr.txt` and setup records for coverage gaps.
- [ ] Confirm the recorded backup roots include web content, configuration and application data under `/opt` or custom locations.
- [ ] Confirm the target's `/.x86/latest` points to the new completed run; the saved setup records contain its ID.
- [ ] Check whether backup immutability succeeded. Container/unsupported filesystems can lack it; the run records the outcome.
- [ ] Confirm audit, sudo I/O and authentication logging using [[Logging - Auditd and Sudo Replay]].
- [ ] Test scored services and a fresh SSH connection after logging configuration.
- [ ] Expand preparation to the remaining hosts with the same SSH port/credential policy.

Setup captures accounts, services, listeners, cron and hashes as inventory. It does not decide which entries are malicious. Preserve this first snapshot even if the host is already compromised. Setup does not rotate credentials, remove keys/jobs, reinstall core packages, enable a WAF or lock kernel modules.

For a direct target session with scripts already copied there:

```sh
sudo sh hunter-setup.sh --backup-root /srv/shop
```

## Phase 1 — Wazuh startup

- [ ] Choose the Wazuh manager host. For 1–25 agents, the [official quickstart](https://documentation.wazuh.com/current/quickstart.html) recommends a supported 64-bit Linux host with 4 vCPU, 8 GiB RAM and 50 GB storage.
- [ ] On that manager host, run the official quickstart's all-in-one Bash installer. It installs the manager, indexer and dashboard:

```sh
curl -fsSLO https://packages.wazuh.com/4.14/wazuh-install.sh && sudo bash ./wazuh-install.sh -a
```

The `4.14` path matches the official quickstart checked on 2026-11-20. Use Bash for this installer. Open `https://MANAGER_IP/` and save the printed `admin` credentials in your credential store. The generated `wazuh-install-files.tar` contains credentials; keep it private. See the [quickstart](https://documentation.wazuh.com/current/quickstart.html).

- [ ] In the dashboard, use **Deploy new agent** for each supported Linux target. Select its distro/architecture, enter the manager's reachable IP and use a unique agent name. Run the generated install/enrollment commands on that target, then start its agent. See [Linux agent deployment](https://documentation.wazuh.com/current/installation-guide/wazuh-agent/wazuh-agent-package-linux.html).
- [ ] Use logging/inventory during phase 1; leave automatic blocking/active response off. Begin threat investigation and preventative changes in phase 2.
- [ ] Confirm each target connects and a fresh authentication/sudo event reaches the dashboard. Check the manager's agent list with:

```sh
# On the Wazuh manager.
sudo /var/ossec/bin/agent_control -l
```

- [ ] Install monitor-only service checks and configure alerts using [[Service Watchdogs and Alerts]]. Verify notification delivery; explicitly enable recovery for tested services during phase 2.
- [ ] Put the manager address and each target's agent name in the host note. Use the [package support list](https://documentation.wazuh.com/current/installation-guide/packages-list.html) for unusual distros; the hunter's package-manager coverage is separate from Wazuh agent availability.

- [ ] If packet evidence is needed for injects, start [[Packet Capture - Wireshark and Injects|a bounded passive capture]] on the relevant hosts/sensor. Confirm packets and timestamps are useful; Wazuh alerts do not preserve the PCAP for you.
- [ ] Prepare required network flows using [[Firewall - Default Deny with iptables]], then apply the policy in phase 2.

## Phase 2 — hunt, cleanup and preventative hardening

- [ ] Run [[Hunter Hunt - Persistence Triage|hunter-hunt]], including custom document roots and mounts.
- [ ] Run [[LD Preload - Userspace Cleanup|the static userspace collector]].
- [ ] Read the highest-severity findings and coverage/errors section. Handle one confirmed high-impact issue at a time and retest the affected service.
- [ ] Keep only current problems, useful paths and service quirks in the host note; use saved reports for detailed findings.
- [ ] Keep answering injects and checking the scoreboard throughout.
- [ ] Use [[Linux Hardening Checklist]] for credential rotation, targeted persistence cleanup, reviewed package recovery, web protection and narrow firewall changes. These actions are part of this same phase; test after each logical change.
- [ ] Rerun the relevant checks, then refresh the baseline after reviewing the resulting state.
