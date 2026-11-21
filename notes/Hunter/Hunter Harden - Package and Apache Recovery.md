---
updated: 2026-11-20
tags: [ccdc, hunter, hardening]
---
# Hunter harden — package and Apache recovery

**Use in phase 2, alongside hunting and cleanup.** Run the initial hunt, address confirmed persistence, then preview/apply this command without waiting for another tryout phase. It reinstalls installed core packages and adds protections to an existing Apache deployment. Scanning/logging-tool installation belongs in phase 1 setup.

## Preview, apply, verify

From the jump-box repository, start with one host:

```sh
./coordinate/ctl harden --targets 192.0.2.10 --user defender -- --dry-run
./coordinate/ctl harden --targets 192.0.2.10 --user defender
```

Directly on a target:

```sh
sudo sh hunter-harden.sh --dry-run
sudo sh hunter-harden.sh
```

The dry run does not write configuration or install packages. Review selected packages and web-server changes before applying. Keep existing root access and a second tested SSH connection. Address [[LD Preload - Userspace Cleanup|active loader persistence]] first, since hooked package tools can misreport what they do.

## What it does

| Area | Result |
| --- | --- |
| Core packages | Reinstall selected **already installed** SSH, PAM, sudo, libc/SSL, common system/process/network tools, package-manager and related packages |
| Package selection | Uses the detected apt-get, dnf/yum, zypper, pacman or apk workflow; missing core packages are skipped rather than inventing a service stack |
| APT conffiles | Uses `--force-confmiss` to restore missing conffiles; existing modified conffiles are not universally replaced |
| SSH | Validates configuration and attempts a reload of an already active SSH service after core recovery |
| Apache, if installed | Installs/enables available ModSecurity/CRS components, required modules and managed security settings |
| HTTP settings | Includes reduced server disclosure, disabled TRACE, `nosniff` and removal of the powered-by header where supported |
| WAF | Enables blocking with `SecRuleEngine On`, relevant-only auditing and checks actual CRS inclusion |
| Validation | Tests Apache configuration before reloading an already active service; leaves a stopped service stopped |
| Records | Backs up `/etc`, hashes the archive and saves operations/rollback records under the state store |

Package installation can run native package scripts. The hardener's reload logic does not prevent every package manager/service hook from affecting running services. Run scored-service tests immediately afterward.

## Useful options

| Flag | Effect |
| --- | --- |
| `--dry-run` | Preview without writes |
| `--skip-core` | Skip core reinstalls and the hardener's SSH reload |
| `--skip-apache` | Skip Apache package/configuration changes |
| `--no-refresh` | Use existing repository metadata |
| `--state-dir /PATH` | Use the same store selected at setup; default `/.x86` |

The script does not harden an offline mounted image. It does not remove arbitrary malicious cron jobs, backdoor users, injected process memory or webshells. Package recovery does not restore trust in a compromised kernel or overwrite every custom configuration file.

## Records and rollback

```text
/.x86/hardening/UTC-PID/
  etc-before.tar
  harden.log
  ... hashes and rollback records ...
  COMPLETE or PARTIAL
```

Only backup archives receive immutable treatment; live configuration remains editable. On Apache validation/reload failure, the script attempts to restore its managed content, modes and newly created module links. This is a targeted configuration rollback, not reversal of every package installation or native package side effect. Read the partial-failure records before doing another change.

`0` means the hardening run completed; `1` means failed/partial; `2` means invalid arguments. Coordinate also returns failure if result collection fails. The setup baseline is retained unchanged.

## Post-change tests

- [ ] Open a fresh SSH session and verify sudo/PAM behavior.
- [ ] Test scored HTTP endpoints, login, forms/uploads, API requests and database-backed transactions.
- [ ] Inspect ModSecurity audit entries for blocked legitimate traffic. Use narrow rule/endpoint exclusions following [[Webshell Hardening Checklist|the web checklist]].
- [ ] Rerun the same hunt and userspace collection. Investigate remaining/recreated launch paths.
- [ ] Refresh setup with `--snapshot-only` after review, preserving the original baseline ID.

See [[Reference Hardening script|package-manager support]], [[Linux Hardening Checklist|the wider hardening checklist]] and [[References|Apache/CRS manuals]]. Source: `hunter-harden.sh`, repository `README.md`.
