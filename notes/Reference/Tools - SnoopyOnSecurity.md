---
updated: 2026-11-20
tags: [ccdc, tools, snoopy]
---
# Tools — SnoopyOnSecurity

These are the tools under `SnoopyOnSecurity/` in the repository. They are **optional source material**, not dependencies of the POSIX hunter scripts. Review a tool's implementation and configuration before running it on a scored host. Some are invasive or require Python, Bash, Rust-built binaries, eBPF support or Ansible.

## What is there, and when to use it

| Location | Observed role/dependencies | Competition use |
| --- | --- | --- |
| `Linux_Misc/lin.sh` | Bash bulk backup/hardening script; changes users/access/services and live attributes | Historical reference; use the phase-separated hunter scripts instead |
| `Linux_Misc/pii.sh` | Bash/GNU grep PII-pattern search, prints values | Optional inject-specific review; prefer [[PII Searcher\|scoped filename-only discovery]] |
| `Pigpen/pigpen.sh` | Bash plus bundled/local `rg`, broad PII regex scan with exclusions and match-count filtering | Same scoped PII role; review skipped trees, thresholds and printed data |
| `PeppermintPatty/peppermint_patty_debian.sh` and `_rhel.sh` | Distro-specific Apache/ModSecurity scripts | Reference only unless individually adapted/tested; current hunter hardener manages this job |
| `Woodstock/` | Ansible playbooks/roles; first-pass includes access, password, core package, service and cron changes | Legacy orchestration; use Coordinate for the current pipeline |
| `RedBaron2/` | Rust workspace, userspace agent plus Flying-Ace rules; process/eBPF/TTY, integrity, YARA and other components | Optional separately tested sensor project; configuration can enable active controls |
| `RedBaron2/flying-ace-engine/README.md` | YAML rules with Rhai expressions for process-event detection | Deeper study for custom detections after the basic competition workflow works |
| `Marbles/` | Python sandbox/analyzer project with Docker, packet/protobuf/crypto dependencies | Isolated analyst/jump-box work if needed; not target bootstrap |
| `Marbles/keyhook/` | C shared library using `LD_PRELOAD` to hook encryption and log secrets | Specialized analysis experiment; not a preload-rootkit remover or general defense |
| `DaisyHill/` | Includes PowerShell utilities and an older RedBaron tree | Separate Windows/legacy material outside the solo Linux workflow |

This inventory describes the checked-in source, not a claim that each project builds or is safe under every default configuration. The folder README is mostly artwork; inspect the actual scripts, Cargo configuration, rules and playbooks for behavior.

## Preferred tryout use

1. Use [[Hunter Setup - Backups and Logging|hunter setup]] for backups, snapshots and logging.
2. Use [[Hunter Hunt - Persistence Triage|hunter hunt]] and [[LD Preload - Userspace Cleanup|the static collector]] for the main investigation.
3. Use [[Hunter Harden - Package and Apache Recovery|hunter harden]] for reviewed core/Apache recovery.
4. Bring in a Snoopy tool only for a concrete remaining need: an inject's PII discovery, an isolated sample analysis, or a tested additional detection source.

## Important implementation differences

`lin.sh` can delete SSH keys/profile files, rotate passwords, remove cron-related software and make live paths immutable. These are not allowed preparation actions and can break ongoing access. The hunter setup archives the useful source trees synchronously and only protects backup data.

The Debian PeppermintPatty script changes ModSecurity includes/rules, downloads a pinned CRS archive, contains broad rule exclusions/deletion and restarts Apache. Do not stack it on top of the hunter's managed configuration without reconciling the include chain and exclusions. Follow [[Webshell Hardening Checklist]] and the current CRS docs.

Woodstock's `first_pass.yml` includes SSH key/password changes, reinstalls, service cleanup and cron cleanup. Running it as a substitute for preparation would cross phase boundaries. The current Coordinate wrapper runs one selected script command per invocation; hunting and hardening commands both belong to tryout phase 2.

RedBaron2 source includes firewall and fanotify configuration, process-response code, and TTY/event handling. Treat a default agent launch as a possible active-control deployment, not a passive hunt command. Validate kernel/BTF requirements, architecture, privacy of recordings, forwarding endpoints and response behavior in a lab before use.

Marbles/keyhook introduces its own preload library and key logging. It can create exactly the loader artifacts you are investigating; keep such experiments isolated and documented. Do not preload it into your administrative SSH workflow.

## Deeper local reading

From the repository root, these reads do not execute a tool:

```sh
sed -n '1,180p' SnoopyOnSecurity/Linux_Misc/lin.sh
sed -n '1,160p' SnoopyOnSecurity/Pigpen/pigpen.sh
sed -n '1,120p' SnoopyOnSecurity/Woodstock/first_pass.yml
sed -n '1,180p' SnoopyOnSecurity/RedBaron2/flying-ace-engine/README.md
sed -n '1,120p' SnoopyOnSecurity/Marbles/keyhook/README.md
```

Use [[References|primary technical references]] for the underlying mechanisms. Secrets/config files already present in this directory are not copied into the notes export.
