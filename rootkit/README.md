# Rootkit response with SSH access

Use the jump box as the place to build tools and retain evidence. Keep the current root shell open and establish a second independent SSH connection before changing an affected machine. Work on one machine first, then expand. The first tryout phase remains `hunter-setup.sh` only: building tools on the jump box is preparation, but rootkit scanning and containment wait until their authorized phases.

An LD_PRELOAD rootkit can lie through dynamically linked tools such as `ls`, `ps`, `cat`, package managers and the shell. Clearing `LD_PRELOAD` from an environment does **not** bypass `/etc/ld.so.preload`. This repository provides a static collector with no target shared-library dependencies. It improves visibility against library interposition while still relying on the running kernel. The [Linux loader manual](https://man7.org/linux/man-pages/man8/ld.so.8.html) describes both injection sources and static executables.

An LKM rootkit can hide its files, processes, sockets and modules from this collector too. A lack of findings cannot establish that a machine is clean. Confirmed kernel compromise calls for a trusted rebuild/reimage arranged through the competition infrastructure or machine owner. With SSH only, the practical objective is to preserve access, collect evidence off-host, reduce reinfection paths and keep required services working until that recovery is possible. Package reinstalls, static tools and immutable backups do not repair trust in a compromised kernel.

## First priority: userspace preload cleanup

For tryout time management, use `--userspace-only` to focus on loader persistence and affected processes. It skips module checks, module startup configuration and BPF-handle enumeration, and rejects the module-lock flag. Setup still performs preparation only.

```sh
# Read-only: find preload entries, process mappings and loader startup sources.
./coordinate/ctl rootkit --targets 192.0.2.10 --user defender -- --userspace-only

# Preview removing one confirmed entry; repeat --quarantine-preload as needed.
./coordinate/ctl rootkit --targets 192.0.2.10 --user defender -- \
  --userspace-only --quarantine-preload /path/to/confirmed-implant.so

# During the authorized hardening phase: apply and automatically recheck.
./coordinate/ctl rootkit --targets 192.0.2.10 --user defender -- \
  --userspace-only --quarantine-preload /path/to/confirmed-implant.so --apply
```

This automates preservation, selected `/etc/ld.so.preload` token removal, and an immediate read-only recheck. It does not automatically classify every preload entry as malicious. Successfully removing that entry stops that particular injection source for future applicable executions; already running processes retain loaded code. The collector continues to report their mappings using its quarantine history. A fresh SSH connection tests access, but an infected SSH daemon parent can still exist.

The recheck uses fresh observations instead of repeating pre-change findings. It reports `selected preload tokens still present=0`, a remaining count, or `UNKNOWN` when it cannot verify the file. A recreated selected entry or unreadable verification produces a failed run. Coordinate displays the final observations; the private report retains both the pre-change collection and final result. This is an immediate check, not continuous prevention.

Startup checks include common system environment/default/sysconfig directories, literal systemd `EnvironmentFile=` references, and passwd/common home login environments and user units. Unresolved specifiers/globs remain explicit coverage items. Removing a system preload entry does not edit those separate injection sources. The tool reports them for targeted review instead of rewriting service/login configurations while you depend on SSH.

Handle confirmed loader persistence before relying on package reinstalls. After that, replace/re-exec affected application services individually and retest their required behavior. Keep SSH/PAM changes deliberate with a second tested root session. Patched libc/loader/PAM binaries, ptrace injection, backdoor accounts and an attacker who retains root require additional remediation; clearing one preload file does not eradicate all userspace compromise or stop a root process recreating it.

## Build once on the jump box

```sh
# Go is required only here. No third-party modules or network downloads are used.
./rootkit/build.sh amd64

# Build separately for other target CPU architectures:
./rootkit/build.sh arm64
./rootkit/build.sh 386
./rootkit/build.sh arm
```

The build checks that the resulting Linux ELF has no dynamic interpreter or imported libraries and prints its SHA-256. Binaries are saved in the ignored `rootkit/bin/` directory. Keep these originals on the jump box. `arm` uses GOARM=6. Build for the target architecture; libc family does not matter, so the Linux amd64 binary works on both Alpine/musl and glibc distributions with a compatible kernel. A target compiler, Go runtime installation, Python and BusyBox installation are unnecessary.

## Read-only scan

Coordinate embeds the binary in a root-owned temporary payload, runs it, then downloads the full report through the existing private transfer pipeline:

```sh
./coordinate/ctl rootkit --targets 192.0.2.10 --user defender
./coordinate/ctl rootkit --targets 192.0.2.11 --user defender --arch arm64

# Practice target, already started with ./lab/alpine/ctl up:
./coordinate/ctl rootkit --targets 127.0.0.1 --port 2222 --user defender
```

The collector defaults to read-only collection. Use `-- --userspace-only` for the focused loader workflow above, or omit it for the broader rootkit view. It does not run installed utilities, load/unload modules, install packages, change authentication/firewalls, or restart services. Root allows better visibility into process maps and environment. Coordinate's SSH/sudo/bootstrap still run through the target's existing processes; a static payload does not make that earlier transport trustworthy. The runner's upstream host-key limitation remains documented in [the Coordinate guide](../coordinate/README.md).

When running directly, copy the matching binary over your existing SSH transport and execute it as root. For example, after placing it at `/root/hunter-rootkit`:

```sh
sudo /root/hunter-rootkit --output /root/rootkit-first.txt
sudo /root/hunter-rootkit --output /root/rootkit-second.txt
```

Local runs save a new private report automatically when `--output` is omitted. Existing reports and symlink destinations are refused. The wrapper `hunter-rootkit.sh` finds a locally built binary, or uses `HUNTER_ROOTKIT_COLLECTOR=/absolute/path`. Directly executing the static binary avoids starting an extra dynamic shell for that wrapper.

Collection covers:

- Every distinct `/etc/ld.so.preload` entry, including multiple implants at once; absolute library paths are hashed without loading them. Unresolved sonames/expansions remain explicit leads.
- Loader environment settings in startup/service files and every readable process environment; other environment variables are omitted.
- Processes mapping the listed preload libraries, temporary/deleted executable mappings and memfd executable mappings. These are leads: upgrades, profilers and JIT runtimes can create similar mappings.
- Process mappings for paths selected in this tool's earlier containment records, so removing a preload token does not erase the reference used to inspect already running processes. Reuse of a path for a clean library still needs provenance review.
- Nonzero `TracerPid` values for ptrace/debugger review, without killing or detaching anything.
- Two `/proc/modules` snapshots versus live sysfs modules, excluding built-in modules without `initstate`. Module races remain possible. Both views come from the same kernel.
- Module load lists and modprobe install/remove overrides, including `/run` and distro library directories.
- Kernel/module taint, signature-enforcement state, lockdown and module/BPF controls as contextual evidence. Taint alone is not a rootkit verdict; see [kernel taint documentation](https://www.kernel.org/doc/html/latest/admin-guide/tainted-kernels.html).
- BPF program/map/link/BTF IDs exposed in process fdinfo. This is a partial inventory: programs without a visible open handle, pinned programs and concealed objects can be missed. Investigate attachments separately with a trusted `bpftool` where available.

The full shell hunter remains useful for package integrity, SSH/PAM persistence, webshells, processes, kernel symbol/log markers and other launch mechanisms. Run both views and compare from the jump box. Neither automatically suppresses suspicious files because they existed at setup time. The static collector bounds individual file reads to avoid hanging on special or enormous files and records coverage gaps.

Coordinate reports live under `reports/coordinate/rootkit-TIME.RANDOM/output/downloads/HOST/artifacts/`. Direct reports default to `ccdc-rootkit-TIME-PID.txt`. Findings are severity-sorted, terminal headings are colored, and saved reports are plain mode 600. Zero exit status means collection completed, not that a kernel is clean.

## Remove confirmed preload persistence

First inspect **all** entries, process mappings, loader environment hooks and their provenance. Keep the current root session, test a second SSH login and fetch the initial report before applying a change. The collector never guesses that all libraries in the file are malicious.

```sh
# Preview removal of two exact confirmed paths. No changes are made.
./coordinate/ctl rootkit --targets 192.0.2.10 --user defender -- \
  --quarantine-preload /opt/.implant/first.so \
  --quarantine-preload /usr/local/lib/second.so

# During the authorized hardening phase, apply those selected edits:
./coordinate/ctl rootkit --targets 192.0.2.10 --user defender -- \
  --quarantine-preload /opt/.implant/first.so \
  --quarantine-preload /usr/local/lib/second.so --apply
```

This removes only the exact selected tokens from `/etc/ld.so.preload`; comments and unselected entries remain. The source file, selected readable libraries, hashes, original UID/GID/mode and pre-change evidence are saved privately under `STATE/rootkit/TIME-RANDOM/`. The collector preserves the preload file's UID/GID, ordinary mode and available ACL/xattr metadata, refuses symlinked preload files and conflicting setup/hardening runs, and leaves an `INCOMPLETE` record on a partial mutation failure. It refuses edits with content-bound IMA/EVM metadata or a failure to preserve attributes. It never deletes a library, kills a process, changes a running SSH daemon or refreshes the baseline. After a successful applied operation it performs a fresh scan; a complete mutation record does not guarantee that later verification or process cleanup succeeded.

“Quarantine” here isolates the selected startup entries; the library files stay available for evidence. Existing processes keep already loaded code, and service-specific `LD_PRELOAD`/`LD_AUDIT` hooks remain separate persistence. After a tested fresh SSH login, address confirmed affected services one at a time. Do not bulk-restart sshd, PAM consumers or all services on an SSH-only system. An infected SSH parent can remain infected despite a new child/session, so a successful login confirms access, not recovery.

Use `--state-dir /path` consistently if you relocated `/.x86`. Original backup archives and containment records stay root-only on the target; Coordinate copies the report/stdout/stderr, not these library backups. The report includes the record path. Retain evidence on the jump box before relying on it for recovery. An attacker with kernel control can change or falsify either local records or readback.

## Optional module load lock

Linux supports `kernel.modules_disabled=1`, which blocks **both loading and unloading** until reboot. It does not evict existing modules, remove a rootkit, block all kernel exploitation, stop privileged eBPF, or protect against a kernel that ignores the control. Blacklisting a module in modprobe configuration only affects that loader's policy and does not block direct insertion syscalls. The actual one-way control is documented by the [kernel sysctl documentation](https://docs.kernel.org/admin-guide/sysctl/kernel.html#modules-disabled).

With no console access, leave this off until you have checked that required storage, network, crypto, firewall and filesystem dependencies are already loaded and you accept losing module operations until reboot. New connections, service changes and maintenance can require previously unused modules. There is no timed rollback for this switch. In particular, it also prevents a later legitimate attempt to unload a suspicious module.

```sh
# Preview only:
./coordinate/ctl rootkit --targets 192.0.2.10 --user defender -- \
  --disable-modules-until-reboot

# Explicitly apply only after evaluating the above constraints:
./coordinate/ctl rootkit --targets 192.0.2.10 --user defender -- \
  --disable-modules-until-reboot --apply
```

The collector records the before-state, sets and reads back the control, and writes no boot/sysctl configuration. It never attempts to reverse the switch, load/unload anything or reboot. Module signature enforcement/Secure Boot can help prevent unsigned module loading on an appropriately configured trusted boot chain, but changing boot or enrollment settings is outside this SSH-only workflow; see [kernel module signing](https://docs.kernel.org/admin-guide/module-signing.html).

## Additional rootkit paths and operational order

An attacker can also use eBPF hooks, ptrace injection, replaced binaries/PAM, service environment overrides, initramfs or boot persistence. Read-only BPF handle inventory, package checks and startup checks expose some of these paths, but do not prove their absence. Clearing LD_PRELOAD does not address them.

During authorized hunting, preserve module/loader/process evidence first and keep at least two SSH sessions. Test on a single host, preview exact loader edits, then apply confirmed changes and retest access. Clean each persistence source and entry point before a selected service is replaced; reinstalling packages alone can execute existing malicious hooks and leaves a compromised kernel running. Keep module unloading and reboot out of automated response.

Where you control infrastructure outside these hosts, restrict management access at the jump box/network layer and retain logs on a separate receiver. Those controls survive local tampering better than host-only rules, although a compromised host can still suppress or forge the logs it sends. Do not automatically isolate a competition service's required scoring or administration traffic.

After verified cleanup, run the ordinary hunter and static collector again. Refresh the setup snapshot only when you intentionally want a new comparison point. A confirmed LKM remains a rebuild/recovery issue even if symptoms disappear.

## Checks

`sh tests/test-rootkit.sh` exercises multiple preload/modules, environment redaction, safe offline boundaries, exact selected removal, dry-run and module-control writes against fixture files only. It also proves a harmless LD_PRELOAD constructor loads into a dynamic shell but not into the actual static collector, checks report permissions/color, and verifies the Coordinate bundle contains the exact binary. It does not load a kernel rootkit, alter live kernel controls or claim recovery of a compromised machine.
