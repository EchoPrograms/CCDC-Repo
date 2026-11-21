---
updated: 2026-11-20
tags: [ccdc, web, checklist]
---
# Webshell hardening checklist

During phase 1, back up web/config/application trees and enable logging through [[Hunter Setup - Backups and Logging|setup]]. In phase 2, investigate, remove confirmed webshells, fix their entry points and harden the application within the same phase.

## Find the application that is actually served

- [ ] Record frontend, backend/PHP-FPM, virtual hosts, document roots, upload/cache directories and database dependencies.
- [ ] Check the service unit/launch command and site configuration. A web app may live under `/srv`, `/opt`, a home directory or a mounted volume.
- [ ] Save the current scored-service tests: homepage, login, API/form/upload path and a database-backed transaction.
- [ ] Add all relevant roots to the hunt rather than assuming `/var/www` is sufficient.

```sh
# Jump box, from the CCDC repository.
./coordinate/ctl hunt --targets 192.0.2.10 --user defender -- \
  --web-root /srv/shop/public --web-root /opt/customer/public
```

## Triage a suspected webshell

- [ ] Preserve bytes, hash, owner/mode, timestamps and nearby access/error-log events before modifying the file.
- [ ] Review request parameters, file uploads, obfuscation and code execution together. `eval`, `base64_decode` or a process function alone is not a verdict.
- [ ] Compare with an application release/package or a trusted deployment copy. Check `.user.ini`, `.htaccess`, `auto_prepend_file`, PHP extensions and backend/service configuration too.
- [ ] Look for the write path: vulnerable plugin/app, exposed admin, upload handling, stolen credentials or excessive web-user write permissions.
- [ ] After authorization, remove the exact malicious content and fix its entry point. Retest the application and look for recreation.

Renaming one PHP file or blocking one URL does not remove all execution paths. Keep evidence outside the served tree. Do not copy the webshell source into a public/shared note.

## Apache and ModSecurity

Use the managed hardener rather than repeating distro-specific install snippets:

```sh
./coordinate/ctl harden --targets 192.0.2.10 --user defender -- --dry-run
# Phase 2: review the plan, then apply.
./coordinate/ctl harden --targets 192.0.2.10 --user defender
```

For an installed Apache deployment it installs/enables available ModSecurity and CRS components, enables blocking and validates actual rule inclusion. It validates configuration before reloading an already active service. It does not configure Nginx, Caddy, PHP's development server or every application reverse proxy as Apache.

On Apache, inspect the effective modules and virtual hosts using the available distro command:

```sh
sudo apachectl -t
sudo apachectl -M
sudo apachectl -S
```

Some distros use `apache2ctl` or a configured `httpd -t` invocation instead. A loaded `security2_module` does not alone prove CRS rules are included. Check the actual include chain, rule-engine setting and audit log, then test representative legitimate transactions. Use [Apache's control reference](https://httpd.apache.org/docs/2.4/programs/apachectl.html) and [CRS tuning guidance](https://coreruleset.org/docs/2-how-crs-works/2-3-false-positives-and-tuning/).

If a valid scored request is blocked, identify its audit entry/rule ID and apply the narrowest route/parameter-specific exclusion. Keep a rollback copy and test again. Avoid blindly copying broad `SecRuleRemoveById` lists or deleting whole CRS rule files.

## PHP protections: apply with app tests

First identify the web SAPI and its loaded configuration. `php --ini` describes CLI PHP; PHP-FPM and Apache PHP can load different files. Avoid leaving a public `phpinfo()` page to discover configuration.

The old note's example remains a possible app-specific restriction:

```ini
disable_functions = exec,passthru,shell_exec,system,proc_open,popen,pcntl_exec
```

Use it only after checking required app behavior and the active PHP version/SAPI. It is not enabled by hunter automatically. PHP documents [disable_functions](https://www.php.net/manual/en/ini.core.php#ini.disable-functions) as an incomplete security measure; it cannot replace application fixes, and a shell can abuse filesystem/database/network APIs without these functions.

- Restrict script execution in upload/cache directories through the actual web-server/PHP handler configuration. A filesystem `noexec` mount does not prevent PHP from reading/interpreting a script.
- Give the web account write access only where the application needs it. Deploy code read-only to that account when practical; don't blindly make the whole web tree immutable.
- Review dangerous auto-prepend/append settings, unexpected extensions and per-directory overrides. Preserve legitimate framework behavior.
- Reload only the relevant service after a successful configuration test. Retest the scored paths and monitor errors/WAF audit records.

## Close the loop

- [ ] Verify the planted file and its launch/write source are gone or corrected.
- [ ] Check userspace/root persistence if the web process escaped its intended privileges.
- [ ] Re-run the same web-root scan and compare reports.
- [ ] Update the current service status if needed; refresh the setup snapshot after review.

See [[Hunter Harden - Package and Apache Recovery|hardener behavior/rollback]], [[Logging - Auditd and Sudo Replay|logging]] and [[References|deeper web references]].
