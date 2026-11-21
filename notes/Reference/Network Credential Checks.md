---
updated: 2026-11-21
tags: [ccdc, credentials, ssh]
---
# Network credential checks

Use the jump-box tool only against explicitly authorized hosts in an exact target inventory. Start with its plan and review the target, account scope and exclusions before any authentication. The first backend is SSH; an application or domain credential is not an SSH credential unless explicitly mapped and authorized. Do not guess addresses or infer mappings from service names.

Prepare private local files using the tool's documented examples. Target rows are `alias|host|port|scope`; choose `shared` when an account may be shared across hosts and `local` only after confirming the host accounts are independent. Credential rows are `protocol|alias-or-*|username|password`. Keep passwords in mode-600 local files; do not put them in command arguments, notes or reports. Jump-box SSH checks need `sshpass` and `timeout`; targets need no Python or additional software.

```sh
./network/ctl check --targets network/targets.local.tsv --credentials network/credentials.local.tsv
./network/ctl spray --targets network/targets.local.tsv --users network/users.local.txt --password-file network/password.local.txt
```

Both commands produce a plan unless `--execute` is explicitly supplied. The persistent ledger limits attempts to one per account per 24 hours: shared accounts count across hosts; confirmed local accounts count per host. Review account lockout rules and operational authorization before any execution. Credential checks do not change passwords or accounts.

**Do not touch:** `whiteteam`, `user`, `ceroc`, `cloudbase-init`, and `fleet-automation@prime.time`. Scored accounts are also protected: `dan.plum`, `xavier.vonerck`, `cortland.gunn`, `maryjoan.hansen`, `bill.conradt`, `del.harvey`, `jeff.zucker`, `jim.christian`, `stone.phillips`, `patty.patterson`, `michael.charles`, `svc_sql`, `fleet`, `sa`, and `postgres`. Never change their passwords, disable them, or delete them. Hunter's read-only inventory may still show these accounts. Coordinate rejects protected automation logins.

See [[Linux Hardening Checklist]] for access review, [OpenSSH client configuration](https://man.openbsd.org/ssh_config.5) and the [sshpass manual](https://manpages.debian.org/bookworm/sshpass/sshpass.1.en.html).
