---
updated: 2026-11-20
tags: [ccdc, lab, alpine]
---
# Alpine practice lab

A disposable Alpine/BusyBox/musl target for the hunter workflow, with SSH, passwordless sudo, web content and planted persistence. Host-side control is `lab/alpine/ctl` relative to the repository root. It requires Docker and Docker Compose on the lab host; targets need no Python.

Before practice, run `docker compose version` and `docker ps` as the intended lab user. A socket permission error means that user cannot access the Docker daemon; arrange authorized access with the lab administrator before proceeding. This check does not start containers.

For the independent multi-service web/database/DNS exercise, see [[CCDC Service Practice Lab]].

## Start and connect

```sh
# Run from the repository root on the Docker-capable lab host.
./lab/alpine/ctl up
./lab/alpine/ctl status
./lab/alpine/ctl ssh
```

| Item | Default lab value |
| --- | --- |
| SSH | `127.0.0.1:2222` |
| Username | `defender` |
| Password, practice only | `CCDC-Practice-2026!` |
| Privilege | `sudo -n` via the lab's passwordless sudo group |
| Web | `http://127.0.0.1:8088/` |

Direct SSH: `ssh -p 2222 defender@127.0.0.1`. The approved lab sudo grant will appear in privilege findings; distinguish it from planted access. The target uses an isolated internal network and an SSH gateway; package repositories can be unreachable. Do not solve lab setup gaps by granting the vulnerable container host privileges or mounting the Docker socket.

## Practice the real pipeline through Coordinate

```sh
./coordinate/ctl setup --targets 127.0.0.1 --port 2222 --user defender

# Phase 2: hunting, cleanup and hardening together; investigate first.
./coordinate/ctl hunt --targets 127.0.0.1 --port 2222 --user defender -- \
  --web-root /opt/customer/public
./coordinate/ctl rootkit --targets 127.0.0.1 --port 2222 --user defender -- \
  --userspace-only

# Preview then apply only when you intend to change the exercise.
./coordinate/ctl harden --targets 127.0.0.1 --port 2222 --user defender -- --dry-run
```

Inside the target, the shell scripts are under `/opt/ccdc/`:

```sh
sudo -n id
sudo sh /opt/ccdc/hunter-hunt.sh --web-root /opt/customer/public
```

The lab serves PHP without Apache, so the hardener skips Apache configuration. Reinstall/hardening can change the planted exercise; grade a fresh target before cleanup.

## Compare against the answer key

```sh
./lab/alpine/ctl hunt
./lab/alpine/ctl hunt --custom-web
./lab/alpine/ctl test
```

Host copies and grading records go to `lab/alpine/reports/`. The scenario inventory is `lab/alpine/scenarios.tsv`; it labels active, dormant and fixture cases. The grader distinguishes an alert from a path merely appearing in collected inventory. Expect coverage gaps; use the scenario IDs and actual reports rather than assuming every planted row must alert.

The host `hunt`/`test` helpers use Docker exec for consistent root collection; use Coordinate or manual SSH to exercise your competition transport. Tests include SSH/sudo and scenario checks. Rebuild with `up` to include changed hunter source; the target does not bind-mount the host checkout.

## Understand what this lab can demonstrate

- Active container-local examples include keys/hooks, cron/startup persistence, sudo/SUID, shell profiles, webshells and an APK hook. ACL cases depend on the backing filesystem.
- A real per-process preload library creates a local marker and a mapped-library detection opportunity. It does not hide processes, intercept administrative APIs or steal data.
- Alpine's musl does not implement glibc's system-wide `/etc/ld.so.preload` behavior; that file is a detection fixture here. Use a disposable glibc VM to validate actual global-preload neutralization.
- The planted `.ko` is a text fixture, not a loaded LKM. Containers share the host kernel; this exercise does not establish LKM detection/removal. Use an isolated disposable VM for actual kernel work.
- Some systemd/APT/PAM examples are dormant cross-distro fixtures rather than active Alpine mechanisms. Consult the scenario file before interpreting the result.

## Troubleshooting and reset

```sh
./lab/alpine/ctl config
./lab/alpine/ctl logs
./lab/alpine/ctl status
```

For `Bad port '0'` or `Connection refused`, check the effective Compose configuration, published gateway port and startup logs. Use the current `ctl ssh`, which discovers the published SSH port and rejects zero. A log saying sshd listens on container port 22 does not establish that host port 2222 is published. `UsePAM` can be unsupported by Alpine's OpenSSH build; verify actual readiness rather than assuming that warning is a failed listener.

Copy `lab/alpine/.env.example` to `.env` and edit before starting to change ports/password. Do not source it as shell. Existing initialized containers retain the old password until reset.

`./lab/alpine/ctl reset` **destroys and recreates** target state/keys for a fresh exercise. `./lab/alpine/ctl down` removes containers/networks; retained host reports remain. Preserve reports before resetting.

Source detail: `lab/alpine/README.md`, `scenarios.tsv` and `ctl`. See [[Coordinate - Jump Box|Coordinate troubleshooting]] and [Docker bridge isolation](https://docs.docker.com/engine/network/drivers/bridge/).
