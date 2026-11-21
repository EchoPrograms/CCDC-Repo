# CCDC service defense practice lab

A disposable lab with a PHP/Apache web service backed by MariaDB and a separate Alpine DNS server. The web service stores a visit on each POST. The DNS server answers `portal.ccdc.test` with documentation address `192.0.2.10`; that address is a DNS fixture, not the web container's address. The targets contain intentionally insecure changes for defenders to investigate. Keep this lab on a trusted machine and do not expose its ports beyond loopback.

An [isolated Ubuntu VM alternative](vm-README.md) is also available and has passed live web, guest-loopback password SSH/sudo and outage/restore checks. It uses file-backed application state and has no NIC; it does not implement this Compose lab's MariaDB/DNS topology. The Compose build/runtime remains unverified in the development session because Docker socket access was denied.

Requirements: Docker Engine with Compose, internet access to pull images and packages on first build, and curl on the host. Published ports bind to `127.0.0.1`. Both Docker networks are internal; there are no host bind mounts, Docker socket mounts, privileged containers, or kernel modules. Image builds need network access; running containers do not need external network access. The MariaDB database uses a Docker named volume.

Run from this directory:

```sh
./ctl up
./ctl status
./ctl verify
./ctl score
./ctl logs web
```

The first startup can take time while MariaDB initializes. `score` performs a real database insert through the web application, checks the DNS answer and checks each SSH daemon; it returns nonzero if any check fails. Each score/verify run adds a database row. It reports service availability, independently of security findings. Check the web app directly with `curl http://127.0.0.1:18080/` or `curl -X POST http://127.0.0.1:18080/`.

Defender login on both targets is `defender` with password `practice-lab` and passwordless sudo. Connect with `ssh -p 12222 defender@127.0.0.1` for the web host or port `12223` for DNS. These credentials are deliberately public and are only for this local lab. Host SSH clients may retain changed host keys after a reset; remove the corresponding `[127.0.0.1]:port` entry from your known-hosts file if needed. To run a local inspection script, copy it into the selected running target with `docker compose cp /path/to/script web:/tmp/script`, then execute it as defender through SSH. The Alpine service name is `dns`.

For availability and watchdog exercises, run `./ctl outage web`, `./ctl outage db`, or `./ctl outage dns`, then `./ctl score`. Restore with `./ctl restore web`, `./ctl restore db`, or `./ctl restore dns`. The web outage produces a 503; database and DNS outages stop their containers. A restored database may need a few seconds before transactions succeed. `./ctl down` stops and removes containers and networks but retains the database volume. `./ctl reset` **deletes the database volume and all container changes**, rebuilds, and recreates the lab. Reset also recreates the deliberately insecure fixtures. `./ctl logs [web|db|dns]` and `docker compose ps` help diagnose startup problems.

Instructors: the separate [scenario inventory](instructor/answer-key.md) gives the expected changes and reveals the exercise. Avoid opening it before a blind investigation. This is a training environment with embedded credentials and intentionally unsafe configurations, not a production deployment.
