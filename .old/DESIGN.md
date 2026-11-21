# CCDC monitoring toolkit design

Status: requirements and proposed defaults; no implementation or host changes yet.

## Deployment topology

- Run the master on a selected competition box reachable from the jumpbox and monitored hosts.
- Run the browser and initial bootstrap command on the jumpbox. No inbound listener is required on the jumpbox.
- Run an agent on every enrolled host, including the master host.
- Keep the master's agent a separate service with its own identity and configuration.
- Agents initiate connections to the master; the master does not need an inbound listener on agents.
- Bootstrap over SSH from the jumpbox where reachable. If bootstrap must run from the master, verify that management route separately.

## Proposed network defaults

| Source | Destination | Purpose | Restriction |
| --- | --- | --- | --- |
| Jumpbox | Master TCP 8443 | HTTPS web UI and administrator API | Explicit jumpbox source address allowlist plus login |
| Enrolled agents | Master TCP 9443 | TLS enrollment and telemetry | Explicit agent source address allowlist; short-lived enrollment tokens followed by per-agent mutual TLS |
| Master's local agent | Master loopback TCP 9443 | Local host telemetry | Same per-agent authentication; listener must explicitly cover loopback |
| Bootstrap machine | Enrolled hosts' configured SSH ports | Discovery and installation | Existing authorized management access |

Ports and bind addresses are configurable and checked for conflicts before installation.
The agent listener must not expose the administrator API or UI.
The UI source restriction applies at both the host firewall and application.
Use the source address actually observed by the master, accounting for NAT. Do not trust forwarded IP headers unless an explicitly configured trusted proxy supplies them.
IPv4 and IPv6 must receive equivalent access controls; disable an unused address family on these listeners rather than leave it unrestricted.
No changes to external routers, upstream ACLs, or NAT are implied by host firewall automation.

## Automatic firewall management

1. Detect the OS and active firewall management owner, not merely installed commands. Prefer its supported configuration interface.
2. Inspect existing policy and save a recovery snapshot. Calculate the minimal owned changes for the selected interfaces, addresses, and ports.
3. Add master-side UI and telemetry restrictions and required agent egress allowances where existing egress policy needs them. Preserve SSH and competition services.
4. Never flush the existing ruleset, replace its default policy, disable a firewall manager, or open inbound agent ports.
5. Use dedicated named rules, chains, or anchors where supported, integrated with the active policy. A standalone allow rule is not proof that the whole ruleset allows a connection.
6. Validate configuration, arm a local timed rollback before applying, and apply transactionally where supported. Roll back only this tool's changes, without overwriting concurrent administrator changes.
7. Verify a new management connection and UI access from the jumpbox, agent enrollment and heartbeat, the master's local agent, and rejection of UI access from a non-allowlisted test source when available. Report any untested restriction.
8. Cancel rollback only after required positive checks pass. Retain a readable change report and an explicit cleanup operation.
9. Persist successful rules using the active firewall owner's native mechanism, then verify persistence in lab reboot tests.

If several tools appear to own filtering or a backend is unsupported, report the conflict and provide a proposed rule plan instead of guessing or claiming protection.
Application source filtering remains mandatory, and the UI must not start in an unrestricted fallback mode.

Initial firewall support: Linux nftables and firewalld through separate adapters. Add iptables/UFW, BSD PF/IPFW, and Solaris IP Filter only with corresponding integration tests. Service-manager support and firewall support are separate capabilities.

## Master and agent protections

- Authenticate UI users even when their source address is allowed. Use TLS, secure sessions, CSRF protection for cookie-authenticated changes, and login rate limits.
- Keep deployment credentials in memory by default; redact them from logs and do not pass passwords in command-line arguments.
- Verify SSH host identity and pin the master CA during enrollment; never disable TLS verification as a deployment fallback.
- Give each agent a separate revocable certificate; keep private keys local and permission restricted.
- Bound event size, queue size, disk usage, connection concurrency, and retries. Buffer telemetry during master outages with explicit loss counters.
- Run collection with only necessary privileges, native service supervision, root-owned installation files, and platform-specific sandboxing.
- Alert on missing heartbeats and configuration/service changes. Optional immutable flags require a documented update and recovery procedure.
- A root/kernel compromise can disable or falsify local monitoring. The master host is also a monitored competition host and a potential single point of failure; support encrypted off-host exports initiated by the jumpbox.

## Initial deliverable

Linux/systemd master and agents, SSH bootstrap, HTTPS UI, separate mutually authenticated telemetry endpoint, automatic supported firewall integration with rollback, inventory, authentication events, baseline differences, heartbeats, and external service checks.

Later adapters cover OpenRC, BSD rc.d, and Solaris/illumos SMF, with support claimed only for tested OS/version/architecture combinations.

## Implementation inputs

The bootstrap setup must collect the chosen master address, jumpbox source address as seen by the master, explicit host inventory and SSH ports, credential profiles, and configured listener ports. These are deployment-time inputs, not values to guess during development.

## Firewall reference notes

- nftables accept verdicts can still encounter a later dropping base chain: https://wiki.iptables.org/wiki-nftables/index.php/Configuring_chains
- OpenBSD PF rule order and quick rules affect policy integration: https://www.openbsd.org/faq/pf/filter.html
