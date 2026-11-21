# Aperture VM recovery-boot lab (experimental)

The original CyberPatriot archive is read only; all guest writes go to a qcow2 overlay. Direct kernel boot has reached a normal systemd login. The initial EFI firmware boot stopped in OVMF with a page fault. A serial autologin bootstrap and a guest-side watchdog validation procedure are documented below; the controller does not automate these steps.

`./lab/vm/ctl prep /path/to/archive.zip` extracts only the VMDK descriptor, its extents and VMX to `lab/vm/.state/aperture/`; it never writes to the archive. The archive path is required; prep uses unzip and streams only the expected members. Extraction requires enough disk space (the current extracted disk is about 26 GiB). Existing base images are retained. Do not modify the base or delete it while overlays depend on it.

To prepare the direct-boot kernel and initrd without mounting the guest or modifying the image, a read-only conversion and ext4 inspection worked in this workspace. It requires additional free disk space for both temporary raw files. The offsets and names below are specific to this archive; check its partition table before reuse:

```sh
base='lab/vm/.state/aperture'
qemu-img convert -f vmdk -O raw "$base/Aperture Science Ubuntu/Aperture Science Ubuntu.vmdk" "$base/inspection.raw"
fdisk -l "$base/inspection.raw"
dd if="$base/inspection.raw" of="$base/root.ext4" bs=4M iflag=skip_bytes skip=540016640 conv=sparse status=progress
debugfs -R "dump /boot/vmlinuz-5.19.0-46-generic $base/vmlinuz" "$base/root.ext4"
debugfs -R "dump /boot/initrd.img-5.19.0-46-generic $base/initrd" "$base/root.ext4"
```

`./lab/vm/ctl start` boots systemd in the foreground using software emulation, with no network and an overlay named `practice.qcow2`. `./lab/vm/ctl recovery` instead enters a root recovery shell directly, without authentication, so use it only in this isolated lab. `./lab/vm/ctl status` checks the managed QEMU PID and command; `./lab/vm/ctl stop` sends the verified QEMU process SIGTERM. Shutting down abruptly can leave filesystem changes unflushed; run `sync` at the guest shell first. A stale PID file must be removed manually after confirming no managed VM is using the overlay. Recreating the overlay discards its changes. The controller currently does not automate script tests (`test` returns an error).

For a read-only script transfer, create an ISO from a staging directory containing only the intended files with `xorriso -as mkisofs -J -R -o scripts.iso staging/`; attach it with `-cdrom scripts.iso` when launching QEMU, then mount `/dev/sr0` read-only in the guest. Never attach a writable host directory or Docker socket. Since the recovery boot does not start systemd, test outcomes involving services and startup must not be treated as normal-boot results.

`reports/validation/aperture/` records the current diagnostic limits. No KVM, host kernel module, bridge, port forwarding, or outside network is needed for this recovery session. Retained overlays and logs are not proof of a running VM; check the actual QEMU process or live tool handle before sending commands or starting another instance.

For the general script runner, stage `run-tests.sh` with the scripts and helpers on the CD, boot a **fresh disposable clone normally**, and mount the CD at `/mnt/ccdc-cd`. Run `CCDC_DISPOSABLE_VM=1 sh /mnt/ccdc-cd/run-tests.sh`. It refuses existing test state, saves per-command logs, timestamps and exit codes under `/var/tmp/ccdc-results`, and returns nonzero if any test failed. Its default has no imposed time limit: full backups/hashing under software emulation can take substantially longer than five minutes. To choose a limit, set `CCDC_TEST_TIMEOUT` to seconds; exit 124 is an incomplete timed-out run. Observe the same process and its log rather than launching another setup against the same state directory. A `.started` file without `.finished` means that command has no terminal result yet. This runner performs setup, a read-only hunt, static collection, a hardening preview and a staged watchdog install; it does not perform actual core package or Apache recovery.

## Reproducing watchdog validation

The final watchdog test used normal systemd, a disposable overlay, no guest NIC, and a read-only ISO. The guest-side runner is [watch-tests.sh](watch-tests.sh); it runs the static Go tests (including guarded systemd recovery), a staged installer fixture, and a separate controlled systemd service recovery. It alters the guest clone and must never be run on a production system. The host must already have a freshly built `watchdog/bin/hunter-watch-linux-amd64` and the matching static test binary at `/tmp/ccdc-watch-tests`. Build them on the host with `./watchdog/build.sh amd64` and `GO111MODULE=off go test -c -o /tmp/ccdc-watch-tests ./watchdog`; the guest needs neither Go nor network access.

Stage only the needed files:

```sh
stage=lab/vm/.state/aperture/watch-stage
mkdir -p "$stage/watchdog/bin" "$stage/watchdog/examples"
cp hunter-watch.sh lab/vm/watch-tests.sh "$stage/"
cp watchdog/bin/hunter-watch-linux-amd64 "$stage/watchdog/bin/"
cp watchdog/examples/services.conf "$stage/watchdog/examples/"
cp /tmp/ccdc-watch-tests "$stage/watchdog/ccdc-watch-tests"
xorriso -as mkisofs -J -R -o lab/vm/.state/aperture/watch-tests.iso "$stage"
```

Create a fresh overlay and bootstrap clone-only serial access. These commands assume the kernel and initrd were extracted as above and run from the repository root:

```sh
base="$PWD/lab/vm/.state/aperture"
qemu-img create -f qcow2 -F vmdk -b "$base/Aperture Science Ubuntu/Aperture Science Ubuntu.vmdk" "$base/watch-repro.qcow2"
qemu-system-x86_64 -machine q35,accel=tcg -m 2048 -smp 2 \
  -kernel "$base/vmlinuz" -initrd "$base/initrd" \
  -append 'root=/dev/vda2 rw console=ttyS0 init=/bin/bash quiet' \
  -drive "file=$base/watch-repro.qcow2,format=qcow2,if=virtio" \
  -nic none -display none -serial stdio -monitor none
```

At the recovery shell, install the clone-only serial override and power off:

```sh
mkdir -p /etc/systemd/system/serial-getty@ttyS0.service.d
printf '%s\n' '[Service]' 'ExecStart=' 'ExecStart=-/sbin/agetty --autologin root --keep-baud 115200,38400,9600 %I $TERM' > /etc/systemd/system/serial-getty@ttyS0.service.d/lab.conf
sync
/sbin/poweroff -f
```

Boot the same overlay normally and attach the ISO read-only:

```sh
qemu-system-x86_64 -machine q35,accel=tcg -m 2048 -smp 2 \
  -kernel "$base/vmlinuz" -initrd "$base/initrd" \
  -append 'root=/dev/vda2 rw console=ttyS0 quiet' \
  -drive "file=$base/watch-repro.qcow2,format=qcow2,if=virtio" \
  -cdrom "$base/watch-tests.iso" -nic none -display none -serial stdio -monitor none
```

This intentionally grants root to anyone with the VM serial console; the VM must remain isolated. In the guest after normal boot:

```sh
mkdir -p /mnt/ccdc-cd
mount -o ro /dev/sr0 /mnt/ccdc-cd
CCDC_DISPOSABLE_VM=1 sh /mnt/ccdc-cd/watch-tests.sh
```

The script writes `/var/tmp/watch-results-final/` with per-test `.exit` and `.log` files and JSON events. Each invocation must use a fresh clone because the script uses fixed paths and a temporary systemd service. On the tested clone, all five exit files were 0 and the events showed DOWN, RECOVERY_ATTEMPT, and RECOVERED. See [validation evidence](../../reports/validation/aperture/README.md) for the distinction between tests that passed and tests that timed out. The helper hash for this run was `808c72a1bea2974d9417ea966a9fdf893b249638fc7c0452cf157d326e3ef136`.
