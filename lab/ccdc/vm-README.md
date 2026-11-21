# Isolated Ubuntu VM practice target

This is an alternative when Docker is unavailable. It uses a fresh qcow2 overlay of the extracted Aperture Ubuntu disk, the guest's kernel and initrd, QEMU software emulation, and **no guest NIC**. The original archive and base disk are not modified. The web app stores a persistent visit counter in a private guest directory; it has no database dependency. The original Aperture scenario remains present, along with additional deliberately insecure training fixtures. Use only a disposable clone.

The current lab runs under a root serial console. Its management channel is local FIFO access, not network SSH. From the repository root, one operator at a time can send a command and read output:

```sh
timeout 5 sh -c 'printf "%s\n" "sh /mnt/ccdc-seed/vm-score.sh score" > lab/ccdc/vm-state/serial.in'
tail -n 60 lab/ccdc/vm-state/serial.log
```

Inside the guest, `sh /mnt/ccdc-seed/vm-score.sh score` inserts a visit and checks the SSH daemon; `outage` makes the web service return 503, and `restore` re-enables it. The web listener is guest loopback `127.0.0.1:18080`. Defender credentials are `defender` / `practice-lab`, with passwordless sudo. Test actual password authentication separately from inside the guest:

```sh
ssh -F /dev/null -o PreferredAuthentications=password -o PubkeyAuthentication=no \
  -o UserKnownHostsFile=/root/ccdc-lab-known-hosts -o StrictHostKeyChecking=accept-new \
  defender@127.0.0.1 'id; sudo -n id'
```

With no NIC, the host and external machines cannot connect. The CD mounted at `/mnt/ccdc-seed` also contains the copied hunter tools; it is read-only. To use them, copy desired files and the `rootkit` directory from the CD to a guest working directory first.

Build and stage a current static helper before creating the CD. From the repository root on the jump box:

```sh
./rootkit/build.sh amd64
stage=lab/ccdc/vm-state/stage
mkdir -p "$stage/rootkit/bin"
cp lab/ccdc/vm-seed.sh lab/ccdc/vm-score.sh lab/ccdc/vm-app.php lab/ccdc/vm-maintenance.php "$stage/"
cp hunter-setup.sh hunter-hunt.sh hunter-harden.sh hunter-rootkit.sh "$stage/"
cp rootkit/bin/hunter-rootkit-linux-amd64 "$stage/rootkit/bin/"
xorriso -as mkisofs -J -R -o lab/ccdc/vm-state/seed.iso "$stage"
```

Use a fresh staging directory for a new exercise. These commands build an ISO; they do not start or seed a VM.

The active clone is disposable; changes survive guest restart but not deletion of its overlay. The writable `vm-state/` directory contains the overlay, staged ISO, FIFOs and serial log and must stay out of version control. See [VM preparation](../vm/README.md) for extracting the unchanged VMDK and its kernel/initrd. To recreate this target, use a new overlay and attach a read-only ISO containing `vm-seed.sh`, `vm-score.sh`, `vm-app.php`, `vm-maintenance.php`, the four hunter shell scripts, and `rootkit/bin/hunter-rootkit-linux-amd64`. Use `qemu-img create -f qcow2 -F vmdk -b BASE NEW_OVERLAY`, then follow the VM preparation guide's recovery bootstrap and normal-systemd boot, using `-nic none`. Mount that ISO read-only at `/mnt/ccdc-seed` and run `CCDC_DISPOSABLE_VM=1 sh /mnt/ccdc-seed/vm-seed.sh` as root. The seeder requires the guest's Apache, PHP, SSH, sudo, cron and compiler packages and refuses to seed a marked clone twice. It intentionally grants this clone root serial autologin. For a reviewer-accessible serial channel use QEMU `-chardev pipe,id=console,path=PATH -serial chardev:console`, with private `PATH.in` and `PATH.out` FIFOs and one persistent reader that appends `.out` to a private log.

The separate Compose lab retains its own MariaDB-backed service and DNS target; this VM fallback does not implement those services. VM test results are in [ccdc-lab.md](../../reports/validation/ccdc-lab.md).
