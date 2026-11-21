---
updated: 2026-11-20
tags: [ccdc, scripts, reference]
aliases: [Hunter Script Reference]
---
# Hunter script reference

Run jump-box commands from the root of your CCDC repository clone; its location and directory name are your choice. Use the current scripts there rather than copying an old embedded hardening script out of a note. [[00 CCDC Runbook|The runbook]] provides the short operational sequence. The notes are for local Obsidian reference; Obsidian is not needed on the jump box.

## Script map

| Script/path | Run where | Purpose | Guide |
| --- | --- | --- | --- |
| `coordinate/ctl` | Jump box | Password-auth SSH execution and result collection for one phase | [[Coordinate - Jump Box\|Coordinate]] |
| `hunter-setup.sh` | Target, root | Versioned backups, baseline, logging and missing scanning tools | [[Hunter Setup - Backups and Logging\|Setup]] |
| `hunter-hunt.sh` | Target, preferably root | Read-only persistence triage and private severity-sorted report | [[Hunter Hunt - Persistence Triage\|Hunt]] |
| `rootkit/build.sh` | Jump box | Build a static Linux collector for the target architecture | [[LD Preload - Userspace Cleanup\|Userspace cleanup]] |
| `rootkit/bin/hunter-rootkit-linux-ARCH` | Target, root | Static inspection; selected containment only with explicit flags | [[LD Preload - Userspace Cleanup\|Userspace cleanup]] |
| `hunter-rootkit.sh` | Target with collector | Convenience launcher, requires a matching existing binary | [[LD Preload - Userspace Cleanup\|Userspace cleanup]] |
| `hunter-harden.sh` | Target, root for apply | Reinstall installed core packages; protect an existing Apache deployment | [[Hunter Harden - Package and Apache Recovery\|Harden]] |
| `ccdc-hunt.sh` | Target | Legacy launcher for `hunter-hunt.sh` | Prefer the current name |
| `lab/alpine/ctl` | Docker-capable host | Start, connect, scan, grade and reset the practice lab | [[Alpine Practice Lab\|Lab]] |

Hunter shell scripts use `/bin/sh`, standard Unix utilities and feature detection. They target **Linux across several distro families**, not every Unix kernel. FreeBSD/macOS package handling is not implemented. The static collector is Linux ELF, built separately per CPU architecture.

## Supported native package managers

| Manager | Common distro families | Setup | Harden |
| --- | --- | --- | --- |
| `apt-get` | Debian, Ubuntu and derivatives | Install missing available tools | Reinstall selected installed core packages; restore missing conffiles where supported |
| `dnf` / `yum` | Fedora, RHEL, Rocky, AlmaLinux, CentOS-family systems | Native RPM repositories | Native reinstall of installed packages |
| `zypper` | openSUSE and SUSE-family systems | Native repositories | Forced install of installed core packages |
| `pacman` | Arch and derivatives | Install missing tools with `--needed` | Reinstall selected installed packages without `--needed` |
| `apk` | Alpine | Native tools/OpenRC packages where available | `apk fix --reinstall` for selected installed packages |

Package names and availability vary by release and enabled repositories; failed/missing items are recorded. The scripts do not add an obsolete COPR/EPEL repository or convert distro families. They do not perform a distribution upgrade. Avoid an ad hoc `pacman -Sy` partial-upgrade workflow.

## Direct target pipeline

The tryout has two phases; phase 2 includes hunting, cleanup and preventative hardening together:

```sh
# Phase 1: preparation; also complete Wazuh startup in the starting checklist.
sudo sh hunter-setup.sh
# Phase 2: hunt, address confirmed persistence, then harden.
sudo sh hunter-hunt.sh --web-root /actual/app/public
sudo sh hunter-harden.sh --dry-run
sudo sh hunter-harden.sh
# After remediation and verification.
sudo sh hunter-hunt.sh --web-root /actual/app/public
sudo sh hunter-setup.sh --snapshot-only
```

Static userspace collection/selected preload removal is a separate step; use its [[LD Preload - Userspace Cleanup|exact preview/apply workflow]]. Setting a nondefault `--state-dir` requires the same value throughout the pipeline. Use `--help` on the actual checked-out script when confirming flags.

## Why the old embedded script was replaced

`SnoopyOnSecurity/Linux_Misc/lin.sh` remains available in the source tree for review. It backgrounds backups, deletes SSH/profile material, rotates passwords, removes schedulers and applies immutable flags to live paths. Those actions conflict with the initial tryout phase and can interrupt an SSH-only scored service. Its old package/repository assumptions are also not the cross-distro hunter pipeline.

The current setup keeps the useful backup idea: preserve configuration, web trees, homes, `/opt` and root's files before changes. It makes backups synchronous/versioned and restricts immutability to backup data. Use [[Tools - SnoopyOnSecurity|the tool inventory]] before borrowing individual legacy ideas.

Source documentation: `README.md`, `coordinate/README.md`, `rootkit/README.md`, `lab/alpine/README.md`. External technical references are linked from [[References]]. These notes reflect the local implementation reviewed on 2026-11-20; if the scripts change later, reconcile behavior with their help and source.
