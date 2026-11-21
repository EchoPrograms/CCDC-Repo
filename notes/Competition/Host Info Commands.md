---
updated: 2026-11-20
tags: [ccdc, reference, inventory]
---
# Host info commands

Run these **inside the target's SSH session**. Use the sections you need to fill [[Host Notes Template]]; the commands query information without installing packages or changing service configuration.

## Host, distro and running kernel

```sh
hostname
cat /etc/os-release
uname -r
uname -m
cat /proc/1/comm
```

Copy the distro name/version, running kernel release and architecture. PID 1's name helps identify the init system. `uname -r` reports the **running** kernel; installed kernel packages can be newer. Architecture also selects the static collector: `x86_64` → `amd64`, `aarch64` → `arm64`. See [uname](https://man7.org/linux/man-pages/man1/uname.1.html).

## IPs, gateway and DNS

```sh
if command -v ip >/dev/null 2>&1; then
    ip address show
    ip route show
else
    ifconfig -a
    netstat -rn
fi
cat /etc/resolv.conf
```

Copy the service-facing IP/CIDR, interface, default gateway and DNS servers. If DNS points to a local systemd-resolved stub, query its upstream servers with:

```sh
resolvectl dns
```

Use that last command only where systemd-resolved is present. References: [IP addresses](https://man7.org/linux/man-pages/man8/ip-address.8.html), [resolved DNS information](https://www.freedesktop.org/software/systemd/man/latest/resolvectl.html).

## Listening ports and running services

```sh
if command -v ss >/dev/null 2>&1; then
    sudo ss -lntup
else
    sudo netstat -lntup
fi

if [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; then
    systemctl --no-pager list-units --type=service --state=running
elif command -v rc-status >/dev/null 2>&1; then
    rc-status -a
else
    ps
fi
```

Copy service names, processes and listen addresses/ports. `127.0.0.1` binds locally; `0.0.0.0` binds all IPv4 interfaces. For local dependencies such as a PHP-FPM or database socket, also use `sudo ss -lxnp` (`sudo netstat -lxnp` if needed). A listener still needs a functional service check from the appropriate client. See [ss](https://man7.org/linux/man-pages/man8/ss.8.html).

## One service: unit, launch command and dependencies

**Systemd only:** replace the example with a unit from the list above.

```sh
unit=apache2.service
systemctl show "$unit" \
    -p FragmentPath -p DropInPaths -p ExecStart \
    -p Requires -p Wants -p After
systemctl cat "$unit"
```

This locates the unit/drop-ins and shows launch and unit dependencies. `After=` is startup ordering; remote databases, DNS/auth endpoints and PHP-FPM sockets often come from the application's configuration instead. On OpenRC, read the relevant `/etc/init.d/NAME` and `/etc/conf.d/NAME` files. Copy useful paths and dependency endpoints into the host note; keep credentials in your credential store. See [systemctl inspection commands](https://www.freedesktop.org/software/systemd/man/latest/systemctl.html).

## Exact installed versions: SSH, sudo, PAM, libc and OpenSSL

Run **the one command matching the target's distro family**. Missing package names mean that component/name is not installed; no installation is needed for these queries.

| Distro family | Copy-paste command |
| --- | --- |
| Debian / Ubuntu | `dpkg-query -W -f='${Package}\t${Version}\t${db:Status-Abbrev}\n' openssh-server sudo libpam-modules libc6 openssl` |
| RHEL / Fedora / SUSE | `rpm -q openssh-server openssh sudo pam glibc openssl` |
| Arch | `pacman -Q openssh sudo pam glibc openssl` |
| Alpine | `apk info -v` lists installed package versions; use the filtered block below |

```sh
# Alpine: keep just the relevant installed package names/versions.
apk info -v | awk '/^(openssh|sudo|pam|linux-pam|musl|openssl)-/'
```

On Debian/Ubuntu, `ii` in the final column means installed; `rc` means removed with configuration left behind. For a service version, use the same native query with its actual package name, such as `nginx`, `apache2`, `httpd` or a database server package. Keep the full distro package release when relevant; distributions can backport fixes without adopting a new upstream version. `ssh -V` reports the SSH **client**, and `mysql --version` reports a client too. Installed package versions do not prove an already running daemon has been replaced after an upgrade.

Query references: [dpkg-query](https://manpages.debian.org/trixie/dpkg/dpkg-query.1.en.html), [RPM](https://rpm.org/docs/6.0.x/man/rpm.8), [pacman](https://man.archlinux.org/man/pacman.8.en), [Alpine APK](https://docs.alpinelinux.org/user-handbook/0.1a/Working/apk.html). Background: [Debian security version/backport FAQ](https://www.debian.org/security/faq#version).

If loader tampering makes the host's utilities unreliable, use [[LD Preload - Userspace Cleanup|the static userspace collector]] for that investigation. Return to [[00 CCDC Runbook]].
