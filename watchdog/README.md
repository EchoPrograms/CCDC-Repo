# Hunter watchdog

Build on the jump box with `./watchdog/build.sh [amd64|arm64|386|arm]`. Go and the standard library are needed only for the build; the Linux helper is static and targets need no Go or Python. Supported checks are HTTP, TCP, DNS, native units, disk space/inodes, MySQL and PostgreSQL; database checks require their native clients and private credential files. Copy the installer, helper and a reviewed manifest to the target, or use Coordinate. The manifest is pipe-delimited data; see [examples/services.conf](examples/services.conf) and [CONTRACT.md](CONTRACT.md). Use a private file owned by the invoking user and not writable by group or others. Do not put passwords in the manifest; database checks refer to private client configuration files.

Run `sudo ./hunter-watch.sh install --config /path/to/services.conf`. The installer stages and validates the manifest before installation, then installs a systemd timer or an OpenRC service supervised by supervise-daemon. The systemd timer waits 30 seconds after a completed check before starting the next one; OpenRC runs the watch loop at its configured interval. On other systems it adds a marked entry to root’s existing crontab (60-second cadence). The helper serializes checks and bounds its JSON log. `--no-start` skips immediate activation; on cron hosts it writes an inactive entry to `/etc/hunter-watch/cron.example` for an administrator to add to root’s crontab. An offline fixture selects systemd with `run/systemd/system`, OpenRC with `run/openrc/softlevel`, or otherwise writes that cron example. `--root DIR` creates an offline fixture without live service actions. A reinstall preserves state, logs and recovery ownership.

Installation is monitor-only: no recovery switch is created. After reviewing policy, explicitly run `sudo ./hunter-watch.sh enable-recovery --owner local` for local recovery or `--owner wazuh` for Wazuh responses. Disable it with `sudo ./hunter-watch.sh disable-recovery`. Use `check` for one tick and `status` for persisted state. Default state is `/.x86/watchdog`; `--state-dir /path` selects its parent. Recovery of sensitive SSH, networking, authentication and database units is refused by default.

Coordinate: `./coordinate/ctl watch --targets HOST --user USER --watch-config services.conf -- install`. Use `--arch arm64` (or amd64, 386, arm) to select the target helper. Other actions need no manifest, for example `./coordinate/ctl watch --targets HOST --user USER -- status` or `-- enable-recovery --owner local`. Output is collected with the usual Coordinate artifacts; JSON logs remain on the host. Use `--prepare-only` to inspect the payload.

## Wazuh 4.14

On the manager, place the contents of [rules.xml](wazuh/rules.xml) in a local rules file under `/var/ossec/etc/rules/`, avoiding ID conflicts. Validate with `/var/ossec/bin/wazuh-logtest` using a representative JSON event, then restart the manager using its normal service manager. On each agent add [agent-localfile.xml](wazuh/agent-localfile.xml) inside `ossec_config`, restart the agent and verify events arrive in the manager. Health samples use level 0; DOWN triggers rule 100710.

Optional [notification fragments](wazuh/notifications.xml) route DOWN (100710), RECOVERED (100711), RECOVERY_EXHAUSTED (100714), and RECOVERY_FAILED (100715) to email or Slack. Configure the manager's global email/SMTP settings and replace placeholders before enabling either. Wazuh's installed `email_alert_level` is commonly 12, which filters the level 10 failure events and level 5 RECOVERED; the example lowers the global and granular thresholds to 5 and filters by rule ID. This global change can affect other email routing. Merge the settings into existing configuration, and review Wazuh's [alert thresholds](https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/alerts.html), [granular email settings](https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/email-alerts.html), and [integrations](https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/integration.html). A custom webhook requires a separately implemented manager integration executable; none is included here. Validate configuration and test delivery under your normal procedures.

Active response is opt-in: install [hunter-watch-ar](wazuh/hunter-watch-ar) as a root-owned executable in the agent's Wazuh active-response bin directory, add [active-response.xml](wazuh/active-response.xml) on the manager, review the root-controlled manifest and explicitly enable owner `wazuh` on the host. The service ID must appear in the manifest with policy `auto` and a safe, nonempty unit; the sensitive-unit denylist also applies. The stateless helper accepts only matching DOWN/add requests, requires a confirmed DOWN in persisted state, and checks the service and its dependencies again before recovery. Owner `local` never recovers through active response. Installation never enables active response.

## Independent lab probes

With [lab/ccdc](../lab/ccdc/README.md) running, monitor its published endpoints from the Docker host. No root is needed for these external checks:

```sh
./watchdog/build.sh amd64
./watchdog/bin/hunter-watch-linux-amd64 watch \
  --config "$(pwd -P)/watchdog/examples/ccdc-lab-external.conf" \
  --state-dir "$(pwd -P)/reports/lab-service-watch" \
  --log "$(pwd -P)/reports/lab-service-watch/events.jsonl" --interval 30
```

Use the lab controller's `outage` and `restore` commands in another terminal. Three failed samples produce one DOWN transition; a passing sample produces RECOVERED. The HTTP check verifies the database-backed response, DNS checks the specified server and answer, and SSH TCP checks only establish a listening endpoint. Keep these external checks monitor-only. Their results continue to describe reachability when a target's local agent fails. A `check` exit status of zero means collection completed; read its events to determine health.

With local ownership, failed recovery can be retried on later checks within the cooldown and rolling attempt cap. With Wazuh ownership, the transition-only DOWN alert triggers at most one automatic response per outage; failed responses do not schedule periodic retries. Manual repeated responses remain subject to the shared budget. Use local ownership when bounded automatic retries are needed.
