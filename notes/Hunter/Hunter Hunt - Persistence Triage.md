---
updated: 2026-11-20
tags: [ccdc, hunter, triage]
---
# Hunter hunt — persistence triage

**Run in phase 2, which includes hunting, cleanup and preventative hardening.** `hunter-hunt.sh` collects evidence and writes a severity-ordered report. It does not remove persistence, change services or repair files; use its findings to guide cleanup and the separate harden command within this same phase. Missing-tool installation requires the explicit `--install-tools` option; setup is the normal place for tools.

## Commands

From the jump-box repository:

```sh
./coordinate/ctl hunt --targets 192.0.2.10 --user defender

# Custom document roots and separate mounted filesystems need explicit coverage.
./coordinate/ctl hunt --targets 192.0.2.10 --user defender -- \
  --web-root /srv/shop/public --web-root /opt/customer/public --scan-root /data
```

On a target with the script present:

```sh
sudo sh hunter-hunt.sh --web-root /srv/shop/public --color auto
```

Direct reports default to `ccdc-hunt-HOST-TIME-PID.txt` in the current directory. `-o /root/hunt-first.txt` chooses a new path; existing files are refused. Saved reports are private, plain text; terminal output supports `--color auto|always|never`.

## Read results efficiently

1. Start with **CRITICAL**, then **HIGH**. Check the evidence and proposed action before touching the host.
2. Correlate accounts, launch configuration, executable/library paths, running processes, listeners and log times. One suspicious string alone is a lead.
3. Read coverage gaps and collection errors. A missing tool, unreadable directory or failed package query changes how much confidence to place in the result.
4. Keep current problems, service checks and useful paths in [[Host Notes Template]]. The saved report holds the detailed findings.
5. After remediation, rerun the same scan roots and compare full reports; update the baseline only after review.

| Priority | Typical leads | Next check |
| --- | --- | --- |
| Critical/High | Loader/PAM backdoors, privileged persistence, hostile SSH commands, active webshells | Static userspace view, package provenance, launch source and affected process |
| Medium | Unexpected privilege grants, writable privileged paths, unusual hooks or listeners | Intended owner, business purpose, file metadata and related logs |
| Low/Info | Inventory, contextual differences, weaker indicators | Compare with the host role, service notes and saved setup inventory |

Severity is contextual. A lab's approved passwordless sudo group can alert, and a new legitimate service can resemble persistence. Preserve evidence before cleanup.

## Coverage map

| Area | What the hunter inspects |
| --- | --- |
| Access | Local/NSS accounts, UID 0, sudoers, SSH configuration and key locations/options |
| Authentication | PAM configuration, module ownership/integrity evidence and suspicious binary strings |
| Scheduled execution | System/user cron, cron spools, at jobs, systemd services/timers, user units, OpenRC/init/rc.local |
| Startup | Shell profiles, MOTD hooks, udev, environment settings, service launch files |
| Package hooks | APT, YUM/DNF, Zypper, ALPM and APK hook locations |
| Privilege | SUID/SGID, capabilities, ACLs and writable execution/configuration paths |
| Runtime | Processes, sockets, loader settings, mapped libraries, module configuration and kernel/log indicators |
| Web | Apache/PHP configuration, common webshell patterns and supplied application roots |
| Drift | New/removed/changed files, modes, owners, symlink targets, services and listeners versus setup |

The [original persistence article](https://matheuzsecurity.github.io/hacking/linux-threat-hunting-persistence/) explains the core mechanisms. The current hunter also covers other distro/init/package-hook layouts.

## Integrity checks: what they establish

- `dpkg -S` or `rpm -qf` tells you which package claims a file; it does not prove the bytes are original.
- Debian-family checks can use package verification and `debsums` when installed. RPM checks use verification without package verification scripts.
- Pacman `-Qkk` primarily checks packaged file metadata; use available checksum tooling such as `paccheck` for stronger content evidence. APK has its own audit comparison.
- All installed package databases and the first baseline may already be compromised. Compare against trusted package artifacts on the jump box when confidence matters.

## Extra options

```sh
# Select a particular saved baseline instead of the latest one.
sudo sh hunter-hunt.sh --baseline /.x86/runs/REPLACE-RUN-ID/manifest.sha256

# Mounted image: no target processes, package installs or live service commands.
sudo sh hunter-hunt.sh --root /mnt/image --web-root /srv/shop/public
```

With `--root`, `/srv/shop/public` means the path inside the mounted image. Offline collection cannot establish what was running. Use `--state-dir` consistently when setup used a nondefault store.

Broad searches stay on one filesystem and exclude the configured backup store; add other mounted trees explicitly. Reports bound displayed excerpts, and some file checks have size/read limits. Pathnames with newlines, backslashes or `|` are unsupported. The hunter does not source configuration, execute discovered scripts or use `ldd` on untrusted binaries.

**Exit codes:** `0` collection completed, findings may exist; `1` failed/interrupted collection; `2` invalid arguments. A dynamically linked toolchain can be deceived by userspace hooks. Pair this report with [[LD Preload - Userspace Cleanup|the static userspace collector]].
