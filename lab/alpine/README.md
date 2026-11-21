# Alpine CCDC persistence practice

A disposable SSH target built from the [official Alpine image](https://hub.docker.com/_/alpine), using Alpine 3.24, BusyBox, musl and OpenRC utilities. The lab has working container-local persistence examples, dormant policies and clearly labeled fixtures for mechanisms Alpine does not implement. The hunter is copied into the image; no Python is installed or required.

## Start and connect

From the CCDC repository directory, using an account with Docker and Docker Compose access:

```sh
./lab/alpine/ctl up
./lab/alpine/ctl ssh
```

Default credentials:

- SSH: `ssh -p 2222 defender@127.0.0.1`
- User: `defender`
- Password: `CCDC-Practice-2026!`
- Passwordless sudo group: `sudo`, with `%sudo ALL=(ALL) NOPASSWD: ALL`.
- Web service: `http://127.0.0.1:8088/`.

To change the password or ports, copy `.env.example` to `.env` in this directory and edit it before starting. Do not source `.env` as shell code. Existing containers retain their password until reset; changing `.env` alone does not change an already initialized account. `ctl ssh` discovers the configured published port automatically.

The normal admin group is intentional baseline access. The hunter will flag its passwordless rule; the answer key labels that alert as approved access instead of an implant.

## Hunt manually or compare results

Inside the SSH session:

```sh
sudo -n id
cd /home/defender
sudo sh /opt/ccdc/ccdc-hunt.sh
```

The report filename is printed. Reports written by sudo have mode 600 and need sudo to read.

For the tryout phases, the image also includes these standalone commands:

```sh
# Preparation: install scanning/logging tools, enable logs, save backups/snapshots.
# Only backup archives/directories receive immutable flags when supported.
sudo sh /opt/ccdc/hunter-setup.sh

# Later, once hunting is allowed:
sudo sh /opt/ccdc/hunter-hunt.sh --web-root /opt/customer/public

# After the hunt, once preventative actions are allowed:
sudo sh /opt/ccdc/hunter-harden.sh --dry-run
sudo sh /opt/ccdc/hunter-harden.sh
```

The hardener reinstalls installed native core packages and configures Apache only
when present. The lab uses PHP's web server, so Apache hardening is skipped here.
Hardening can change the planted scenarios; use the original lab tests on a fresh
target, and reset afterward when you want to repeat the original exercise.

For an automatic scan, local report copy and ground-truth comparison, use the host:

```sh
# Default paths: shows the inventory-only cron case and two known misses.
./lab/alpine/ctl hunt

# Adds the custom application document root: closes the web-root miss.
./lab/alpine/ctl hunt --custom-web

# Checks real SSH/passwordless sudo, SUID, webshells, local bind shell,
# preload mappings, ACL availability and network setup, then grades both scans.
./lab/alpine/ctl test
```

Copied reports and grading summaries go into `lab/alpine/reports/`. No host directory is mounted into the vulnerable target. `ctl hunt` and `ctl test` use Docker exec as root for consistent collection; the manual SSH route exercises the requested defender/sudo workflow. The live test separately authenticates over SSH with both the password and planted key.

`ctl test` expects a fresh lab. After remediation, use `hunt` to compare remaining findings. Rebuild with `up` to include subsequent hunter source changes; existing containers do not bind-mount the host copy.

## Planted scenarios and honest scoring

The complete answer key is [scenarios.tsv](scenarios.tsv). Each row records an ID, mechanism, whether it is active/dormant/a fixture, expected default/custom-root behavior, exact location and finding title. The grader inspects the alert summary separately from detailed inventory; a path merely appearing in evidence does not count as detection.

Working examples include:

- A generated SSH maintenance key plus forced-command hook on `defender`.
- An unapproved `support` sudo rule, a real root-owned SUID Bash copy, and a harmless world-writable SUID diagnostic executable.
- Root and user cron jobs, a shell alias, user/system profile hooks, a boot hook and wired MOTD hooks.
- A root bind shell listening on **container loopback only**, port 4444; the host does not publish that port.
- Two PHP webshells under the default web tree and another under `/opt/customer/public`, all running as unprivileged `webapp`.
- A real per-process `LD_PRELOAD` library in `/tmp/.cache` and a persistent process mapping it. The library only writes a local constructor marker; it does not hide processes, intercept APIs or capture data.
- Named ACL grants on a system profile, shadow and the root directory, when supported by the Docker backing filesystem.
- An Alpine APK commit hook that writes a local marker.

The `backupsvc` UID 0 identity is locked and labeled dormant. Two custom PAM service policies are syntactically real but are not wired into SSH/sudo authentication. Stock PAM modules are left intact. The SSH service uses ordinary password/key authentication and only allows `defender`.

APT and systemd files are **inactive cross-distribution fixtures**. Alpine uses APK/OpenRC. The `/etc/ld.so.preload` file is also a **fixture** because musl does not use glibc's system preload file; the separate per-process preload example is real. The `.ko` file is plain text and its kernel log entry explicitly says it is a fixture. No kernel module is built or loaded. A hidden `/proc/PID` mount is marked unsupported and skipped.

The grader deliberately exposes limitations:

| Scenario | Default result | What it demonstrates |
| --- | --- | --- |
| `CRON02` | Inventory only | A scheduled job can look ordinary; baseline review is necessary. |
| `APK01` | No hit | The original Linux-article hunter does not inspect APK commit hooks. |
| `WEB03` | No hit, then alert with custom root | A document root outside defaults must be selected. |
| `B00` | Alert on approved sudo rule | A heuristic cannot determine which administrator access is authorized. |

Active alerts are counted separately from dormant policies and fixtures. Passing the grader means expected lab outcomes matched; it does **not** mean every implant was detected or that real rootkits have been tested. ACL failures are recorded in `/var/lib/ccdc-lab/seed-status` and shown as skips, not detections. A partial hunter report is rejected by the grader.

## Runtime and reset behavior

The entrypoint explicitly starts cron, web services, the local bind shell and preload worker, and invokes the local boot hook. This avoids requiring a full init boot with writable cgroups/sysfs. The MOTD scripts are explicitly wired into `/etc/profile.d/30-motd.sh`, since the ordinary Alpine SSH path does not automatically execute Debian-style update-motd scripts. Changes survive `docker restart`; seeding occurs only once per container filesystem. Some payloads run at startup by design, so a restart can restart a surviving payload.

```sh
./lab/alpine/ctl status
./lab/alpine/ctl logs
./lab/alpine/ctl reset   # Discards this target's changes and generates fresh SSH keys.
./lab/alpine/ctl down    # Removes this project's containers/networks; keeps copied reports.
```

The wrapper keeps a dedicated host-key file and clears it on reset. For direct SSH, remove the old `[127.0.0.1]:2222` public host-key record after a reset with `ssh-keygen -R '[127.0.0.1]:2222'`.

All published ports bind to `127.0.0.1` on a separate **gateway** container. It forwards only SSH and HTTP to the target. The target stays solely on an [internal Docker network](https://docs.docker.com/engine/network/drivers/bridge/), with no external default route. The gateway joins the internal and ordinary access networks, runs as an unprivileged UID with all capabilities dropped, has a read-only root filesystem, and disables IP forwarding. Neither container mounts host directories or the Docker socket. The target lacks module/mount/network-admin capabilities; SUID and sudo are intentionally enabled there. Do not add `--privileged`, host networking or host filesystem mounts to this exercise. Containers share the host kernel; use a disposable VM for real kernel rootkit/process-mount work.

Docker publishes ports through a container's default-gateway network. An internal-only target cannot publish a host port itself; Docker may report port `0` or omit the mapping. This is [documented by a Docker maintainer](https://github.com/moby/moby/discussions/53256). The separate gateway supplies the host mappings without giving the target an external route. `ctl up` and `ctl ssh` reject missing/zero mappings, and `ctl test` checks SSH reachability from the host before running the internal tests.

If an older lab shows `Bad port '0'` or connection refused despite SSH listening inside the target, rebuild with `./lab/alpine/ctl up`, then use `./lab/alpine/ctl ssh`. The updated topology recreates the old target, resetting its filesystem and host keys. Normal SSH access uses the gateway's published port; `target:22` is intentionally not published directly. The SSH config also omits `UsePAM`, which the non-PAM Alpine OpenSSH build does not support.

## Existing projects checked

[PANIX](https://github.com/Aegrah/PANIX) supplies many persistence setup/revert modules and is useful for broader detection engineering. Its published support table lists mainstream glibc distributions rather than Alpine. It is a persistence framework, not a ready-made Alpine SSH target.

The [4rji CCDC practice lab writeup](https://docs.4rji.com/digitalocean) describes deliberately compromised Linux training machines, including scheduled tasks, web backdoors and hidden processes. It is a lab setup/writeup rather than the narrowly scoped Alpine container needed here.

This target uses explicit, reviewable seeds with a scenario manifest and expected detection outcomes.

## Validation status

Local checks:

```sh
sh tests/test-alpine-lab.sh
sh tests/test-alpine-ctl.sh
sh tests/test-hunt.sh
```

The first command validates Compose and shell syntax, compiles C source checks, lints the actual PHP payloads where PHP is available, checks the seeder guard, scans the recipe's real planted config files in an offline fixture, and tests the grader's alert/inventory/miss distinction. Where installed, BusyBox ash runs the collector and its real `ps` implementation exercises process-list fallback. The controller tests mock Docker's real missing/zero port responses to confirm SSH is never invoked with an invalid port and that custom published ports are used correctly.

Docker daemon access is unavailable in the development session. The image build, SSH login, scheduled execution, live preload behavior and container integration tests have **not** been run here. They are provided by `ctl up` and `ctl test`; runtime results should be checked on the Docker host before treating the lab as validated.
