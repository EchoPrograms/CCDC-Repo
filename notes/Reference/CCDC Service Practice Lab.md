---
updated: 2026-11-21
tags: [ccdc, lab, availability]
---
# CCDC service practice lab

This independent disposable exercise provides a PHP/Apache web service backed by MariaDB and an Alpine DNS server. Use a trusted lab host and keep published ports on loopback. Docker Engine, Compose and curl are required; initial image and package downloads need network access. As the intended user, check `docker compose version` and `docker ps` before starting. Resolve Docker socket permissions through the lab administrator.

From the repository root:

```sh
./lab/ccdc/ctl up
./lab/ccdc/ctl status
./lab/ccdc/ctl verify
./lab/ccdc/ctl score
```

The score checks the web/database transaction, DNS answer and SSH daemons; test password authentication and sudo separately. Each score or verify adds a database row. Practice an availability failure with `./lab/ccdc/ctl outage web`, `outage db` or `outage dns`; use the matching `restore` action and score again. Web SSH is on localhost port 12222 and DNS SSH on port 12223; the lab-only login is `defender` / `practice-lab`. Full setup and lifecycle details are in repository file `lab/ccdc/README.md`.

`./lab/ccdc/ctl down` retains the database volume; `./lab/ccdc/ctl reset` deletes it and recreates the lab. Keep evidence before resetting. For the separate SSH and hunter exercise see [[Alpine Practice Lab]].

## Isolated VM alternative

Repository file `lab/ccdc/vm-README.md` describes a disposable overlay of the Aperture Ubuntu image. It retains that image's exercise and adds independent training fixtures, a PHP/Apache service and persistent file-backed application state. It has no database service and no network interface. Access uses a clone-only root serial console; guest-loopback SSH can test real password login and sudo. This console is a lab management aid, not an available production recovery method.

With the read-only CD mounted at `/mnt/ccdc-seed`, run these **inside the guest**:

```sh
sh /mnt/ccdc-seed/vm-score.sh score
sh /mnt/ccdc-seed/vm-score.sh outage
sh /mnt/ccdc-seed/vm-score.sh score
sh /mnt/ccdc-seed/vm-score.sh restore
sh /mnt/ccdc-seed/vm-score.sh score
```

The outage score should fail with HTTP 503; the restored score should pass and retain application state. The lab-only login is `defender` / `practice-lab`. Follow the normal [[Starting Checklist|preparation and phase 2 workflow]], using direct target commands from the copied scripts when jump-box SSH is unavailable. Record that limitation instead of treating guest-console execution as Coordinate validation.

On 2026-11-21 the VM seeder, real web transaction, actual guest-loopback password SSH/sudo and outage/restore passed. The Compose lab could not be started in the development session because Docker socket access was denied; these VM results do not validate its MariaDB/DNS topology.
