# Scope and conventions

## Product outcome

One operator must be able to discover an explicit inventory, deploy monitoring, view central evidence, and detect loss of visibility without interrupting competition services. Deployment must work without internet access or inbound access to the jumpbox.

"Host" means any monitored machine. "Master host" means the selected machine running the central server and web UI. "Agent" means the local collector and outbound transport, including the instance on the master host. "Controller" means the bootstrap/deployment command run from the jumpbox or another explicitly selected management machine.

## Required scope

- **REQ-001:** Linux, FreeBSD, OpenBSD, and Oracle Solaris are required product targets for both agent and master roles on the primary architecture profiles below. None may be removed from scope because Linux is implemented first.
- **REQ-002:** illumos is an additional required agent target because it shares relevant Solaris interfaces but requires separate detection and testing. A master build is an additional qualification target. NetBSD and DragonFly BSD are extension targets, not prerequisites for the four requested OS families.
- **REQ-003:** Each required family must implement the common adapter contract, native service integration, collectors, firewall integration, offline deployment, upgrade, rollback, and uninstall. Capabilities limited by an OS must report the limitation explicitly.
- **REQ-004:** Core means required for every supported profile; conditional means required when the stated host facility is present and authorized; extension means a separate feature that does not block core qualification. An unsupported required capability blocks qualification for that profile.
- **REQ-005:** A platform profile is the exact OS release/patch level, architecture, runtime dependencies, service manager, firewall owner/backend, role, and virtualization boundary. A platform name alone is not a support claim.

## Primary qualification profiles

These are implementation targets, not statements that binaries already exist. Exact point releases, SRUs, kernel floors, toolchain versions, and package versions must be pinned in the release compatibility manifest before implementation is declared supported.

| Profile | Agent target | Master target | Required integration coverage |
| --- | --- | --- | --- |
| Linux glibc | amd64 and arm64 | amd64 and arm64 | Debian/Ubuntu systemd and RHEL-family systemd; nftables and firewalld |
| Linux musl | amd64 and arm64 | amd64 | Alpine/OpenRC; nftables |
| Linux alternate init | amd64 | amd64 | SysV init, runit, and s6 in separate test profiles; applicable firewall adapters |
| FreeBSD | amd64 and arm64 | amd64 | rc.d with tested restart supervision; PF and IPFW; IP Filter when active |
| OpenBSD | amd64 and arm64 | amd64 | rc.d/rcctl plus explicit supervisor; OpenBSD PF |
| Oracle Solaris 11.4 | amd64 | amd64 | SMF, Solaris PF, global and restricted non-global zone detection |
| illumos | amd64 | Additional qualification target | SMF, detected IP Filter or distribution-specific firewall |

- **REQ-006:** Older Solaris 10 and 11.0–11.3, Solaris SPARC, Linux 386/ARMv7, and older BSD releases have explicit compatibility investigation requirements in their platform documents. They must not be mislabeled as covered by a modern amd64 binary. They remain named expansion targets; primary-family completion does not mean every historical version or architecture is supported.
- **REQ-007:** For each primary family, pin at least one exact native test image before its adapter is accepted. For Linux, include all distribution/init/libc combinations above. Add the oldest intended release and one newer release where available. For Solaris, identify the exact SRU and availability of licensed installation media.
- **REQ-008:** A complete four-family release requires passing primary master and agent scenarios in every required family. Early Linux previews must identify themselves as partial releases.

## Architecture and implementation boundaries

- **REQ-009:** Prefer Go for modern master/controller/agent builds, conditional on native runtime and dependency qualification. Bootstrap scripts must use the target's verified shell, not assume Bash. Bundled binaries must avoid requiring a compiler or package download on monitored boxes.
- **REQ-010:** Storage and crypto dependencies must support every primary master platform. SQLite is a candidate, not a portability assumption; choose and validate its driver before committing. No dependency may silently eliminate BSD or Solaris targets.
- **REQ-011:** Credential guessing, broad subnet scanning, general remote shells, automatic account/password rotation, and unsolicited changes to scored applications are outside the initial implementation. Discovery concerns explicitly supplied hosts and management ports.
- **REQ-012:** Hardening must provide supervision, restricted permissions, platform sandboxing where compatible, optional file flags, and off-host evidence. It cannot promise survival or truthful collection under root/kernel compromise.
- **REQ-013:** Credentials and network addresses are deployment inputs. Development must proceed with fixtures; production values are not prerequisites for writing or testing software.

## Document conventions

MUST, MUST NOT, and SHOULD denote required behavior, prohibited behavior, and a default that needs a documented reason to change. Requirement identifiers are stable. Acceptance scenarios in [verification.md](verification.md) map to these identifiers and platform sections.

All requirements are currently **specified**, not implemented. Future implementation tracking must use `specified`, `implemented`, `build-tested`, `runtime-tested`, and `qualified` separately, with evidence references. `unsupported` and `blocked` apply to specific profile/capability combinations, not an entire OS without explanation.

## Delivery order

1. Common event/transport/configuration contracts and per-OS discovery fixtures.
2. Portable core plus Linux reference adapters and integration lab.
3. FreeBSD, OpenBSD, and Solaris adapters, beginning their native build/runtime probes early.
4. Full firewall transactions, service failure tests, updates, and four-family qualification.
5. Additional architectures and legacy runtime implementations.

This order does not defer designing required BSD/Solaris adapters until after Linux architecture decisions are irreversible. Multi-OS implementation exceeds the earlier few-day Linux prototype estimate.
