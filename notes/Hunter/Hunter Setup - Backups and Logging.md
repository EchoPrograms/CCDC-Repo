---
updated: 2026-11-21
tags: [ccdc, hunter, backups]
---
# Hunter setup — backups and logging

**Use immediately during the preparation phase.** Canonical script: `hunter-setup.sh` at the repository root. It is POSIX shell, requires root for a live target and needs no Python.

## Run it

Jump box, from the CCDC repository:

```sh
./coordinate/ctl setup --targets 192.0.2.10 --user defender -- \
  --backup-root /srv/shop --backup-root /data
```

Directly on a target with the script available:

```sh
sudo sh hunter-setup.sh --backup-root /srv/shop --backup-root /data
```

Choose backup roots that exist. The state directory must be outside every backed-up tree. For example, do not select `/opt` as the state directory when `/opt` is being archived.

Use a destination with enough free space for full archives. Setup checks estimated sizes plus a 25% margin and 256 MiB reserve before archive writes. If it refuses capacity or cannot read a source size, inspect the saved records and select a larger destination with `--state-dir`; use that same path for later scripts. Other writers and growing source files can still consume space after this estimate. A failure before backup completion also means logging configuration has not started.

## What setup changes

| Action | Behavior |
| --- | --- |
| Backups | Synchronous, versioned archives before logging/package work; preserves full selected trees |
| Installed tools | Missing scanning/logging tools from the detected native repositories; no blanket core reinstalls or distribution upgrade |
| Auditd | Persistent hunter rules for execution and sensitive persistence changes, plus module load/unload syscall logging |
| Sudo replay | Validated `log_input`/`log_output` configuration and private I/O directory; no new sudo privileges |
| System logs | Persistent journal where available, authentication/cron syslog, log rotation |
| SSH logs | Validates configuration, sets `LogLevel VERBOSE`, attempts a reload for logging |
| Snapshot | Before/after runtime inventory, hashes, ownership/modes, ACLs and capabilities when tools permit |
| Immutable flags | Backup directories and archives only; never live files, manifests or logging configuration |

The default backup roots include `/etc`, `/var/www`, `/home`, `/opt`, `/root`, applicable discovered web trees and cron data. Add application paths explicitly when needed. Ordinary filesystem archives of a running database are not transaction-consistent database backups; arrange an application-native dump/snapshot if required by the service or inject.

## Options worth remembering

| Option | Use |
| --- | --- |
| `--backup-root /PATH` | Repeat for additional application or data trees |
| `--state-dir /PATH` | Relocate all hunter state; use the same value throughout the pipeline |
| `--no-install` | Preserve existing tools; configure logging and take the snapshot without repository access |
| `--snapshot-only` | Back up and refresh inventory/hashes without installations or logging changes |
| `--require-immutable` | Fail if backup immutability cannot be enforced; do not publish the new latest baseline |
| `--root /mnt/image` | Offline snapshot; no live installations or service configuration |

Backups need `tar` and an existing SHA-256 provider (`sha256sum`, `shasum` or `openssl`) before setup can proceed. Tools installed afterward cannot repair a failed initial backup step. Native package failures and unavailable facilities appear in the run records.

## Where the records live

```text
/.x86/
  latest                         regular file containing the selected run ID
  runs/UTC-PID/
    backups/                     numbered archives, not directory names
    backups.sha256               hash | archive filename | original tree
    backup-status.txt            tree | tar exit status | archive filename
    backup-capacity.txt          required/available KiB and estimate mode
    backup-size-estimates.txt    source KiB | original tree
    backup-filesystem.txt        destination df output
    before/  after/              services, listeners, cron and other inventory
    manifest.sha256              content hash | metadata fields | path
    metadata.txt  acls.txt  capabilities.txt
    setup.log  errors.log  COMPLETE
```

The manifests use hunter-specific fields; they are not plain `sha256sum -c` input. Map an archive to its original tree with `backups.sha256`, inspect it with `tar -tf`, and extract into a private staging directory before deciding what to restore. Restoring an entire `/etc` over a running SSH-only host can replace authentication and service configuration; prefer the exact required files.

Coordinate retrieves available setup logs/manifests as `record-*.txt`; archive bytes remain on the target. Copy needed archives off-host deliberately and keep their recorded hashes. Immutable flags protect against ordinary edits on supporting filesystems; root can clear them, and a compromised kernel can bypass them.

## Completion and refresh

Read the completion line, `errors.log`, `setup.log` and the immutable result. `COMPLETE` records the snapshot step; it does not certify that every optional logging facility was available. Confirm the actual log events using [[Logging - Auditd and Sudo Replay]].

If tar reports missing or changing filenames and setup fails, preserve `errors.log` and `backup-status.txt`; `latest` stays on the previous completed run. Live changes and an untrusted userspace view can both cause this. Do not accept a partial archive as a completed baseline. During phase 2, use [[LD Preload - Userspace Cleanup]] to inspect confirmed loader interference, then retry setup after selected cleanup. This occurred with a real preload implant in the Ubuntu practice image.

Rerunning setup creates a new version and updates `latest`; older versions remain. After reviewed cleanup:

```sh
./coordinate/ctl setup --targets 192.0.2.10 --user defender -- --snapshot-only
```

The initial state may contain implants. Hunter still evaluates suspicious content present in the baseline; a matching hash is not an allowlist. Prior and refreshed runs remain in the state store; use their saved records when comparing snapshots.

See [[Hunter Hunt - Persistence Triage|Hunt]] · [[Reference Hardening script|Package-manager support]] · [[References|Manuals]].
