---
updated: 2026-11-20
tags: [ccdc, coordinate, ssh]
---
# Coordinate — jump box

The supported fleet runner is `coordinate/ctl`, wrapping [Coordinate](https://github.com/Foister150/coordinate-foister). It sends one chosen script over SSH with sudo, then separately downloads private result files. No target Python, Ansible or sshpass is needed. The old Ansible material is reference only.

## Install and verify before the tryout

```sh
# Run from the repository root on the jump box.
go version
./coordinate/ctl install
./coordinate/ctl --help
```

Building Coordinate requires Git and Go 1.26.3 or newer on the jump box; check `go version` before the tryout. The installer normally needs network access for the source and dependencies. It uses no sudo or OS package manager, keeps build data under `coordinate/vendor/` and preserves an existing binary if replacement fails. You can supply an existing checkout or prebuilt executable:

```sh
./coordinate/ctl install --source /path/to/coordinate-foister
./coordinate/ctl install --binary /path/to/coordinate-linux-amd64
./coordinate/ctl setup --targets 192.0.2.10 --user defender --binary /path/to/coordinate
```

For an offline jump box, stage a compatible prebuilt Coordinate executable in advance and use `install --binary /path/to/coordinate-linux-amd64`; it avoids the source download and Go build. Alternatively stage a source checkout and its dependencies before going offline. Test the installed binary and needed architecture-specific collector builds before the event. `--prepare-only` generates a payload without SSH but does not test transport or the target.

For “Coordinate is not installed,” run `install` from this repository and confirm `coordinate/bin/coordinate` exists, or pass `--binary`. Check jump-box DNS/network if download/build fails. Targets do not need the compiler or Coordinate installed.

## Run one script command at a time

```sh
# Phase 1: preparation.
./coordinate/ctl setup --targets '192.0.2.10-20' --user defender
# Phase 2: hunting, cleanup and hardening together.
./coordinate/ctl hunt --targets 192.0.2.10 --user defender -- --web-root /srv/shop/public
./coordinate/ctl rootkit --targets 192.0.2.10 --user defender -- --userspace-only
./coordinate/ctl harden --targets 192.0.2.10 --user defender -- --dry-run
```

The tryout has two phases: preparation, then hunting/cleanup/preventative hardening together. Coordinate still executes one selected script command per invocation; `hunt`, `rootkit` and `harden` all belong to tryout phase 2. An omitted command defaults to **setup only**; there is no `all`. Options after `--` go literally to the selected script. Remote output locations and color are managed by the wrapper; use its own `--output-dir`/`--color` options.

| Runner option | Purpose |
| --- | --- |
| `--targets HOSTS` | Assigned DNS names/IPs, supported lists/ranges/CIDR |
| `--user USER` | SSH login; omit when using an explicit credential config |
| `--port PORT` | Common SSH port for this invocation; lab uses `2222` |
| `--state-dir /PATH` | Shared target state location for every phase |
| `--output-dir DIR` | Jump-box results; default `reports/coordinate` |
| `--max-hosts N` | Concurrency, default 10; begin with one host |
| `--timeout N` / `--transfer-timeout N` | Payload/transfer seconds; defaults 3600/900 |
| `--arch ARCH` | Rootkit collector architecture, default `amd64` |
| `--prepare-only` | Generate payload without SSH or Coordinate installation; may build the collector locally |
| `--color auto\|always\|never` | Terminal previews; saved reports remain plain |

Run groups with different SSH ports separately. Hosts sharing the same hostname can collide in upstream download naming; use separate invocations for them.

## Passwords and sudo

Interactive password auth normally prompts twice: execution, then collection. Prompted passwords are not passed as command arguments or written into the wrapper's files. Passwordless sudo works. If sudo needs a password, Coordinate uses the SSH password; it has no separate become-password setting. Direct root SSH is another supported mode if allowed by the environment.

For different per-host credentials, prepare a private ignored file and edit it locally:

```sh
(umask 077; cp coordinate/credentials.json.example coordinate/credentials.json)
chmod 600 coordinate/credentials.json
./coordinate/ctl setup --config coordinate/credentials.json
```

The JSON is plaintext: keep it out of Obsidian and commits. The wrapper makes a private temporary copy and removes that copy after the run; your original remains. Keys use `--user defender --key /path/to/key`, or `--user defender --agent`. Key auth is simplest with passwordless sudo.

Upstream currently disables SSH host-key verification and exposes no strict-checking switch. Track this transport limitation in the [upstream runner source](https://github.com/Foister150/coordinate-foister/blob/main/internal/runner/runner.go) and [CF031 audit item](https://github.com/Foister150/coordinate-foister/blob/main/BUG_AUDIT.md); connecting with the wrapper is not independent host-identity validation.

## Results and failed transfers

```text
reports/coordinate/PHASE-TIME.RANDOM/
  payload.sh  run.txt
  output/downloads/HOST/artifacts/hunter-coordinate-PHASE-TIME.RANDOM/
    status.txt  stdout.txt  stderr.txt
    report.txt                 hunt/rootkit full report
    record-*.txt               available setup/harden records
```

The console contains a bounded preview; **read `report.txt` for full evidence**. Directories are private and records mode 600. Backup archives and rootkit-preserved libraries remain in the target state store. The remote artifact directory is retained for recovery.

Execution and collection are separate calls because native Coordinate downloads run before its payloads. Both calls force `--no-rsync`, avoiding automatic transfer-related package installation. Collection is attempted after an execution failure so partial evidence can still return. Either failed stage gives wrapper exit 1; inspect `run.txt`, per-host `status.txt` and `stderr.txt` to distinguish them. Hunt exit 0 can still contain threats.

Do not rerun setup merely to download results: it would create another baseline. Retry **collection only**, using the exact retained remote artifact path from `run.txt`/output and a fresh private local directory:

```sh
# Start at the repository root; keep the executable path when changing directories.
coordinate_bin="$(pwd -P)/coordinate/bin/coordinate"
recovery=$(mktemp -d /tmp/hunter-recovery.XXXXXXXX)
cd "$recovery"
"$coordinate_bin" \
  --targets 192.0.2.10 --usernames defender --port 22 --no-rsync \
  --download '/tmp/hunter-coordinate-hunt-REPLACE-ID;artifacts'
```

Use the same authentication method and port as the failed run. Native options differ from wrapper options (`--usernames` above is intentional). Longer source documentation: `coordinate/README.md`. Return to [[00 CCDC Runbook]].
