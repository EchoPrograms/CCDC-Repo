# CCDC monitoring toolkit

Requirements for a portable master, monitoring agent, and SSH deployment controller for a solo CCDC Linux operator.

The master runs on a competition host. The jumpbox initiates browser and management connections; it requires no inbound listener. All monitored machines, including the master host, run an agent that initiates authenticated telemetry connections to the master.

## Requirements documents

| Document | Contents |
| --- | --- |
| [Scope and conventions](docs/requirements/README.md) | Required platforms, terminology, priorities, and completion criteria |
| [Agent](docs/requirements/agent.md) | Collectors, privilege boundaries, buffering, lifecycle, and tamper evidence |
| [Master host](docs/requirements/master.md) | Server placement, web access, ingestion, storage, alerts, and local agent |
| [Deployment](docs/requirements/deployment.md) | Credential handling, discovery, installation, upgrades, recovery, and removal |
| [Compatibility contract](docs/requirements/compatibility.md) | Adapter functions, artifact selection, common results, and portability rules |
| [Linux](docs/requirements/platforms/linux.md) | Distribution, libc, init, firewall, logging, and sandbox adapters |
| [FreeBSD](docs/requirements/platforms/freebsd.md) | rc.d, daemon supervision, PF/IPFW/IP Filter, and jail boundaries |
| [OpenBSD](docs/requirements/platforms/openbsd.md) | rcctl, supervision, PF, syslog, pledge, and unveil |
| [Solaris and illumos](docs/requirements/platforms/solaris.md) | SMF, Solaris version differences, PF/IP Filter, zones, and runtime gaps |
| [Firewall](docs/requirements/firewall.md) | Network policy, backend integration, transactions, and rollback |
| [Verification](docs/requirements/verification.md) | Acceptance scenarios and the platform release gate |
| [References](docs/requirements/references.md) | Primary sources and local toolchain observations |

[DESIGN.md](DESIGN.md) is the short architectural overview. The requirements documents govern implementation where they provide more detail.

Status: documentation only. No agent, master, installer, service definitions, or firewall rules have been implemented. No OS has passed runtime validation.
