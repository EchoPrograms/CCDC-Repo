---
updated: 2026-11-20
tags: [ccdc, rootkits, ld-preload]
aliases: [LD_PRELOAD cleanup]
---
# LD preload — userspace cleanup

**Phase 2 priority: inspect with the static collector, remove confirmed preload entries, then address affected processes and reinfection.** Hunting and preventative actions are allowed in this same phase. This gives a practical first response without spending the tryout chasing speculative LKM indicators.

## 1. Collect without changing the target

Run from the jump-box CCDC repository:

```sh
./coordinate/ctl rootkit --targets 192.0.2.10 --user defender -- --userspace-only
```

Coordinate builds/embeds a static Linux collector if needed. Go is needed only on the jump box; the target needs no Go, Python or shared-library runtime for this binary. Use `--arch arm64`, `--arch 386` or `--arch arm` **before** `--` for those targets; the default is `amd64`.

Read `/etc/ld.so.preload` entries, SHA-256 evidence, loader environment sources, mapped-library processes, deleted/memfd executable mappings and tracer leads. Temporary mappings, profilers and JITs can be legitimate. Verify a library against its owner/package and the intended application before selecting it.

The static binary bypasses glibc loader interposition. Ordinary `cat`, `ps`, `ls`, package tools and shells may use hooked shared libraries. `unset LD_PRELOAD` does not bypass the separate system-wide `/etc/ld.so.preload` mechanism. See the [loader manual](https://man7.org/linux/man-pages/man8/ld.so.8.html).

## 2. Preview selected containment

Use **exact absolute library paths from the evidence**. The path below is a placeholder. Repeat the option for multiple confirmed implants.

```sh
./coordinate/ctl rootkit --targets 192.0.2.10 --user defender -- \
  --userspace-only \
  --quarantine-preload /path/to/confirmed-implant.so
```

Without `--apply`, this is a read-only preview. It does not empty the preload file or automatically label every library malicious. Sonames and loader expansions such as `$LIB` need separate resolution; the cleanup option accepts literal absolute paths.

## 3. Apply selected cleanup in phase 2

Keep a root shell open and test a second SSH session first. Apply to one host before expanding:

```sh
./coordinate/ctl rootkit --targets 192.0.2.10 --user defender -- \
  --userspace-only \
  --quarantine-preload /path/to/confirmed-implant.so --apply
```

The collector preserves the original preload file and selected library bytes, hashes and metadata under `/.x86/rootkit/TIME-RANDOM/`. It atomically removes the selected tokens while retaining unselected entries/comments and supported original metadata. It refuses unsafe paths or metadata-preservation failures. It never deletes the library bytes, kills processes, restarts SSH or refreshes the baseline.

**The name “quarantine” means preserved evidence plus selected preload-token removal.** The library remains at its original path. Other launch mechanisms can still load it.

## 4. Read the automatic recheck

After a successful apply, the collector takes fresh read-only observations. Find:

```text
POST-CLEANUP RECHECK: selected preload tokens still present=0
```

`0` verifies the selected tokens were absent at that immediate check. A remaining count or `UNKNOWN` is a failed verification; inspect the full report and possible file recreation. Coordinate previews the final observations, while `report.txt` retains pre-change evidence too.

Existing processes can retain the removed library. The collector records selected paths and keeps looking for their mappings on later runs. A clean library subsequently installed at the same path still needs provenance review.

## 5. Close the remaining paths

- Review `LD_PRELOAD`, `LD_AUDIT` and `LD_LIBRARY_PATH` in profiles, `/etc/environment`, systemd units and `EnvironmentFile=` files, `/etc/default`, `/etc/sysconfig`, user units and SSH/login environment hooks. The collector reports these; it does not rewrite them.
- Remove the confirmed job, service, shell hook or root access that recreates the preload entry. An immediate clean result does not continuously enforce it.
- Replace/re-exec affected application services one at a time and test scored transactions. A new SSH connection does not guarantee that its daemon parent is clean.
- Use [[Hunter Hunt - Persistence Triage|the full hunter]] for PAM, accounts, package bytes, webshells and other persistence. Apply [[Hunter Harden - Package and Apache Recovery|reviewed package recovery]] after addressing active loader persistence.
- Keep reports/evidence off-host. Rerun both views, then deliberately take a new setup snapshot after review.

Patched loader/libc/PAM files, ptrace injection and another active root process need additional remediation. Clearing one injection source does not eradicate every userspace implant.

## Direct/static operation

Build on the jump box with `./rootkit/build.sh amd64`; it checks the ELF has no dynamic interpreter/imported libraries and prints SHA-256. Copy the matching `rootkit/bin/hunter-rootkit-linux-amd64` through your established SSH transport. For example, after placing it at `/root/hunter-rootkit`:

```sh
sudo /root/hunter-rootkit --userspace-only --output /root/userspace-first.txt
```

Direct execution avoids another dynamic shell wrapper. Reports are private and refuse existing destinations. `hunter-rootkit.sh` is a convenience launcher for an available collector, not the static executable itself.

## Kernel context — keep this bounded

`--userspace-only` skips module checks, module startup configuration and BPF-handle inventory. It rejects module locking. Omit it for broader **read-only** context if evidence justifies it. Kernel taint or differences between `/proc/modules` and sysfs are leads, not proof.

An LKM can be loaded through privileged module-loading syscalls, including at boot through module lists, services or initramfs. Reboot can reload it before SSH is available. Static userspace tools still rely on that kernel; confirmed kernel compromise needs trusted infrastructure-assisted recovery/reimage.

The collector's separate `--disable-modules-until-reboot --apply` control is advanced preventative hardening. It prevents both future module loads and unloads until reboot, removes no existing rootkit, and has no timed undo. Leave it out of this priority workflow. Read [kernel modules_disabled documentation](https://docs.kernel.org/admin-guide/sysctl/kernel.html#modules-disabled) before considering it.

Source implementation and longer technical notes: `rootkit/collector.go`, `rootkit/README.md`. See [[References|deeper references]].
