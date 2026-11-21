---
updated: 2026-11-20
tags: [ccdc, template]
---
# Host notes template

Duplicate this note per Linux host and name it after the hostname or IP. Fill in what is useful and update it in place. The scripts save operation logs and reports automatically; this note holds the current host details, services, dependencies and quick notes. Keep credentials in your private credential store.

**Copy-paste lookup commands:** [[Host Info Commands]] — run them inside the target's SSH session.

## Host

| Field | Value |
| --- | --- |
| Hostname / role | |
| IP address(es) / CIDR / interface | |
| Default gateway / DNS servers | |
| Distro / version | |
| Kernel / architecture | |
| Package manager / init system | |
| SSH user / port / sudo access | |
| Wazuh manager / agent name | |
| Firewall owner/backend / saved rule paths | |
| Allowed admin / scoring-client networks | |
| Credential-store entry | |
| Access / recovery constraints | SSH only; no console |

**Current phase:** 1 — preparation / 2 — hunt, cleanup and hardening

## Services

Include the service/version, its reachable address or URL, and one useful health check. Mark scored services in the first column.

For monitoring and recovery policy, see [[Service Watchdogs and Alerts]].

| Service / version / scored? | Listen address, port or URL | Unit / process | Test / current status |
| --- | --- | --- | --- |
| | | | |

## Dependencies

Include local services and remote dependencies. Write the actual destination and port; note startup order only when it matters. Example: web app → database host on TCP 3306; PHP site → local PHP-FPM socket.

| Service | Needs: service, host/IP:port or socket | Purpose / startup order |
| --- | --- | --- |
| | | |

## Useful paths

| Service | Config | Web root / data | Logs |
| --- | --- | --- | --- |
| | | | |

## Notes

- Quirks / known issues:
- Suspicious item or next thing to check:
- Useful commands:

**Latest report folder, if useful:**

**Backup / state location:** `/.x86`

**PCAP capture point / interface / retention directory, if used:**

Return to [[00 CCDC Runbook]].
