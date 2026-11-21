---
updated: 2026-11-20
tags: [ccdc, monitoring, availability, wazuh]
---
# Service watchdogs and alerts

Hunter's watchdog checks HTTP, TCP, DNS, native units, disk space/inodes, MySQL and PostgreSQL, records JSON events, and can optionally restart selected services. Start with monitoring; enable recovery only after testing. For implementation details in the repository, read `watchdog/README.md` and `watchdog/CONTRACT.md`.

**Yes: Wazuh can tell you when a service goes down.** Feed it the watchdog's DOWN/RECOVERED events and configure notification delivery using [[Watchdog Wazuh Configuration]]. A running process or connected agent alone does not prove the application works. Keep an external service probe on the jump box to distinguish unreachable services from missing host telemetry. Wazuh also supports [scheduled command monitoring](https://documentation.wazuh.com/current/user-manual/capabilities/command-monitoring/index.html).

For Wireshark evidence, use [[Packet Capture - Wireshark and Injects]]. Wazuh can ingest Suricata's network alerts; PCAP recording and retention are separate.

Build the static Linux helper on the jump box with `./watchdog/build.sh amd64` (also arm64, 386 and arm). Go is needed on the build machine only; targets need neither Go nor Python. MySQL and PostgreSQL checks use their native clients and private client configuration files. Never put database passwords in the manifest.

## Phase 1: monitor

1. Inventory actual endpoints, units and dependencies using [[Host Info Commands]] and [[Host Notes Template]]. Create a manifest and verify it with the helper's `validate --config /absolute/path` command.
2. Install on the target directly with `sudo ./hunter-watch.sh install --config /absolute/path/services.conf`, or use `./coordinate/ctl watch --targets HOST --user USER --watch-config services.conf -- install`. Coordinate's `--arch` selects the target binary. Install preserves existing state and does not create a recovery switch.
3. Run `sudo ./hunter-watch.sh check` and `sudo ./hunter-watch.sh status`. Check `/var/log/hunter-watch.jsonl`, configure Wazuh JSON collection and the included rules, and test notification delivery. The systemd timer waits 30 seconds after each completed check; the OpenRC watch loop uses a 30-second interval, and the crontab fallback checks each minute.
4. Independently check scored network endpoints from the jump box using the same static helper and a separate monitor-only manifest, state directory and log. For example, `./watchdog/bin/hunter-watch-linux-amd64 check --config /absolute/path/external.conf --state-dir /absolute/path/external-state --log /absolute/path/external.jsonl`. Keep its recovery switch absent; external probes do not establish that a host agent or kernel is trustworthy.

The manifest is data, not shell. For example, change these addresses and units to match the environment:

```text
# id|kind|target|expect|unit|dependencies|policy|timeout|failures|cooldown|max_restarts|window
dns|dns|127.0.0.1:53/example.org|-|-|-|alert|5|3|300|2|900
db|tcp|127.0.0.1:5432|-|-|-|alert|5|3|300|2|900
web|http|http://127.0.0.1:8080/|200|web.service|dns,db|alert|5|3|300|2|900
```

The web check depends on both DNS and DB checks; dependency failure suppresses recovery. Three consecutive failures trigger DOWN. Cooldown and attempt limits apply if recovery is subsequently enabled for a suitable `auto` service.

## Phase 2: controlled recovery

After testing a specific safe service, change its manifest policy to `auto`, reinstall the validated config, then choose one owner: `sudo ./hunter-watch.sh enable-recovery --owner local` or `--owner wazuh`. Local ownership retries on later checks subject to cooldown and the rolling attempt cap. Wazuh ownership responds to the transition-only DOWN event once per outage; it does not schedule retries after a failed response. Repeated manual responses still share the restart budget. Prefer local ownership when bounded automatic retries are needed. Disable either with `sudo ./hunter-watch.sh disable-recovery`.

The manifest must name a safe unit, and SSH, network, authentication and database units are refused by default. Wazuh Active Response is separately opt-in; its handler accepts only matching DOWN requests for eligible manifest services, confirms persisted DOWN state and probes the service and dependencies again.

For Wazuh 4.14, the provided rules route DOWN, recovery failure/exhaustion and RECOVERED. The manager's commonly installed email threshold of 12 excludes these level 10 and level 5 events; use [[Watchdog Wazuh Configuration]] and test delivery. Phase 1 should verify alerts before any recovery is enabled. Treat an unavailable agent separately from a service DOWN.

See [[Starting Checklist]] for startup and the [Wazuh email alert reference](https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/email-alerts.html).
