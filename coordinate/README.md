# Hunter over Coordinate

[Coordinate](https://github.com/Foister150/coordinate-foister) replaces Ansible as the jump-box runner. `ctl` selects one hunter phase, embeds the current standalone script with your arguments, runs it over SSH with required sudo, and collects private result files. Targets need `/bin/sh`, SSH, sudo for non-root logins, and the standard utilities used by the selected hunter. No target Python, Ansible, or sshpass is required.

## Install on the jump box

The runner automatically builds Coordinate locally if the executable is missing. It downloads the source and uses the jump box's git and Go; targets need neither. To install ahead of the tryout, run:

```sh
# Run from the CCDC repository root.
./coordinate/ctl install
./coordinate/bin/coordinate --help

# Existing source checkout, or a downloaded release binary:
./coordinate/ctl install --source /path/to/coordinate-foister
./coordinate/ctl install --binary /path/to/coordinate-linux-amd64
```

The [upstream build instructions](https://github.com/Foister150/coordinate-foister#install) require Go 1.26.3 or later for source builds and network access for dependencies. The installer uses no sudo or OS package manager, keeps caches under the ignored `coordinate/vendor/` directory, validates the new executable, and retains any previous binary if downloading/building/validation fails. `--binary FILE` needs no Go. If a download fails, check jump-box network/DNS or supply an existing checkout/binary.

`ctl` automatically finds `coordinate/bin/coordinate`, otherwise it uses PATH. You can also point it directly at an executable with `--binary /path/to/coordinate`. It checks for the current transfer/sudo/output flags before connecting. `--prepare-only` never installs Coordinate or connects to a target. Run `./coordinate/ctl --help` for all runner options.

## Tryout phases

```sh
# First part: backups, tooling, logging and baseline only. This is also the default.
./coordinate/ctl setup --targets '192.0.2.10-20' --user defender

# When hunting is allowed: full reports plus highest-priority findings on screen.
./coordinate/ctl hunt --targets '192.0.2.10-20' --user defender

# Separate static rootkit view (builds the collector locally if missing):
./coordinate/ctl rootkit --targets '192.0.2.10-20' --user defender

# Focus on LD_PRELOAD/userspace cleanup instead of module investigation:
./coordinate/ctl rootkit --targets '192.0.2.10-20' --user defender -- --userspace-only

# Extra paths go to the selected script after --.
./coordinate/ctl hunt --targets 192.0.2.10 --user defender \
  -- --web-root /srv/shop/public --scan-root /data

# After the hunt: first preview, then explicitly apply hardening.
./coordinate/ctl harden --targets 192.0.2.10 --user defender -- --dry-run
./coordinate/ctl harden --targets 192.0.2.10 --user defender

# Refresh after cleanup; earlier baseline/backup versions are retained.
./coordinate/ctl setup --targets 192.0.2.10 --user defender -- --snapshot-only
```

There is no `all` phase or automatic transition into hunting/hardening. An omitted phase means setup only. The runner never adds rootkit inspection, hardening flags or a hunt to setup. Tool installation stays in setup; hunt installs tools only with your explicit `-- --install-tools`. Backup immutability stays inside the hunter scripts and is not applied to transferred reports, manifests, logs or live configuration.

The optional `rootkit` phase builds a static Linux collector on the jump box using Go and no third-party modules; targets need no compiler or Go installation. `--arch amd64|arm64|386|arm` selects its target CPU (default amd64). It uses the same private report pipeline, with read-only collection by default. See the [SSH-only rootkit guide](../rootkit/README.md) for selected containment and kernel trust limits. `--prepare-only` can build/embed this local collector but never connects or applies anything.

Use `--port 2222` for the Alpine practice lab:

```sh
./lab/alpine/ctl up
./coordinate/ctl setup --targets 127.0.0.1 --port 2222 --user defender
# Later:
./coordinate/ctl hunt --targets 127.0.0.1 --port 2222 --user defender \
  -- --web-root /opt/customer/public
```

The lab password is in `lab/alpine/README.md`. Its isolated network may prevent package downloads, and container filesystems may not support immutable backups; those results remain in the setup records.

## Authentication and different host credentials

By default Coordinate prompts for the SSH password twice: once for execution and once for collection. The runner never passes passwords in arguments or writes prompted passwords to its files. Passwordless sudo works. Password-requiring sudo uses the SSH password; Coordinate has no separate sudo-password option. Use direct root SSH or an account with matching SSH/sudo credentials when required.

To reuse different credentials per host, create the ignored file privately:

```sh
(umask 077; cp coordinate/credentials.json.example coordinate/credentials.json)
# Edit the IP, Username, and Password values locally.
chmod 600 coordinate/credentials.json
./coordinate/ctl setup --config coordinate/credentials.json
./coordinate/ctl hunt --config coordinate/credentials.json
# Select a subset or a different common SSH port:
./coordinate/ctl hunt --config coordinate/credentials.json --targets 192.0.2.10 --port 22
```

The JSON is plaintext. `ctl` makes a mode 600 temporary copy in its private run directory, then removes that copy on success, failure or handled interruption. The original remains for your later runs. Each invocation uses its own working directory, so unrelated `config.json` or `env.json` files are not loaded. With key authentication, use `--user defender --key /path/to/key` or `--user defender --agent`; passwordless sudo is the practical choice for those logins. Run separate commands for groups using different SSH ports.

Upstream currently disables SSH host-key verification (`InsecureIgnoreHostKey`); it provides no strict-checking switch. This is a limitation of the selected transport, confirmed in its [runner source](https://github.com/Foister150/coordinate-foister/blob/main/internal/runner/runner.go) and [open audit item CF031](https://github.com/Foister150/coordinate-foister/blob/main/BUG_AUDIT.md).

## Output and recovery

Every invocation creates a unique mode 700 directory under `reports/coordinate/`, or your `--output-dir`. It contains the exact `payload.sh`, invocation metadata and execution/collection statuses in `run.txt`, and Coordinate's output under `output/`. Downloaded files are beneath:

```text
reports/coordinate/PHASE-TIME.RANDOM/output/downloads/HOST/artifacts/
  hunter-coordinate-PHASE-TIME.RANDOM/
    status.txt                 selected phase and target script exit status
    stdout.txt                 full script stdout
    stderr.txt                 full script stderr
    report.txt                 hunt/rootkit: full, plain, severity-ordered report
    record-*.txt               setup/harden operation logs and available manifests
```

Reports and logs are mode 600. Setup's versioned backup archives and original records remain in the remote state directory (`/.x86` by default); they are not downloaded. Use the same `--state-dir /path` for every phase if relocating storage.

Only a bounded preview goes through Coordinate's command-output capture. Full hunt reports are transferred as files, so large detailed evidence is retained. The preview shows severity counts and the first findings in severity order, with actions; rootkit cleanup previews its final recheck while retaining pre-change evidence in the full report. `--color always` forces color and `--color never` disables it. Saved `report.txt` is always plain text. Use `less /path/to/report.txt` to read the full findings and evidence.

Execution and collection are separate calls because [upstream transfers precede payload execution](https://github.com/Foister150/coordinate-foister/blob/main/internal/ssh/ssh.go). Both force `--no-rsync`, avoiding transfer-triggered package installation. The root payload removes its executable staging before handing the private result directory to the SSH login user for collection; it does not change permissions on source logs or backup stores.

Collection is attempted even after a host failure, and either failed stage makes the runner exit 1. A successful hunt returns 0 even when it finds threats. All local partial results and remote artifacts are retained for recovery. Coordinate names download folders by hostname; run hosts with duplicate names in separate invocations to avoid its no-overwrite collision error. After a failed transfer, retry collection alone from a **new private directory** using the recorded remote artifact path and the same authentication/port:

```sh
recovery=$(mktemp -d /tmp/hunter-recovery.XXXXXXXX)
cd "$recovery"
/absolute/path/to/coordinate --targets 192.0.2.10 --usernames defender --port 22 \
  --no-rsync --download '/tmp/hunter-coordinate-hunt-TIME.RANDOM;artifacts'
```

Run `./coordinate/ctl hunt --targets 192.0.2.10 --user defender --prepare-only` to generate a reviewable payload without SSH or a Coordinate installation. This does not execute the phase. The defaults allow 10 hosts at once, one payload per host, 3600 seconds per payload, and 900 seconds per transfer; runner options can adjust those limits. Do not retry setup just to retrieve files: running setup again deliberately creates a new baseline.

## Local verification

`sh tests/test-coordinate.sh` uses a mock Coordinate executable and fake hunter scripts. It checks phase separation, both SSH calls, password stdin, private credential cleanup, literal quoting, a report exceeding 2 MiB, color, partial-result retrieval, failed transfers, and old-binary rejection. Existing hunter tests verify the real phase implementations separately. These fixtures do not claim a live Coordinate/SSH run.

`sh tests/test-coordinate-install.sh` checks automatic installation, source and prebuilt-binary paths, failed download/build preservation, cleanup, and missing-Go handling with a mocked downloader/compiler and no network access.
