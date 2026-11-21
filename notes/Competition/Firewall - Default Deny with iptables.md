---
updated: 2026-11-20
tags: [ccdc, firewall, iptables]
---
# Firewall — default deny with iptables

**Phase 2: deny inbound, outbound and forwarded traffic; allow only documented service flows and necessary network control.** Prepare the flow table during phase 1. Apply one host at a time, with automatic rollback and a second fresh SSH test before accepting. These are manual instructions; hunter-setup does not apply a firewall.

## Quick working order

1. Record the real SSH source, interfaces, scored clients, services and outbound dependencies in [[Host Notes Template]].
2. Save the current rules. Identify the existing firewall owner/backend.
3. Build the IPv4 policy below; either close unused IPv6 or build matching IPv6 allowances.
4. Test syntax, apply with rollback, then test **new SSH connections**, scored transactions, DNS and Wazuh from the correct machines.
5. Accept and persist only the working policy. See [[Packet Capture - Wireshark and Injects]] when a required flow fails.

## Inventory before editing

Run on the target. Inspect `SSH_CONNECTION` before entering a root login shell; its fields are client IP, client port, server IP, server port. Use the client address **as seen by the target**, including any NAT/VPN/jump host.

```sh
printf '%s\n' "$SSH_CONNECTION"
ip -br address
ip route
ip -6 route
ss -lntup
ss -ntup
cat /etc/resolv.conf
resolvectl status
iptables --version
sudo iptables-save
sudo ip6tables-save
```

`resolvectl` is optional: if resolv.conf names a loopback stub, find its real upstream DNS servers using the resolver's configuration/status. `iptables --version` identifies the nftables or legacy backend. Keep save/restore commands on the same backend. Check `nft list ruleset`, `firewall-cmd --state` or `ufw status` where installed. Pick one firewall owner; a reload by firewalld/UFW, container software or Wazuh firewall Active Response can change your policy. Do not switch backend or flush rules as a troubleshooting shortcut.

The replacement below is for a **standalone service endpoint**, not a Docker host, router, VPN gateway or Kubernetes node. It replaces that family's entire `filter` table, including custom chains. Those other roles need explicit forwarding/container rules and coordination with their firewall manager. Docker-published traffic can traverse `FORWARD` rather than host `INPUT`; see [Docker firewall behavior](https://docs.docker.com/engine/network/packet-filtering-firewalls/).

| Required flow | Allow the connection in | Allow its replies in |
| --- | --- | --- |
| Jump box → SSH port | INPUT | OUTPUT |
| Scoring/client networks → web, DNS, mail, etc. | INPUT | OUTPUT |
| Application → remote DB/API/directory | OUTPUT | INPUT |
| Host → approved DNS resolvers, time servers | OUTPUT | INPUT |
| Agent → Wazuh manager | OUTPUT | INPUT |

Replies go to client ephemeral ports. Match the **service source port** on replies; do not open the entire ephemeral-port range. Local Unix sockets need no IP rule. Loopback is permitted below for local dependencies.

## Build the IPv4 service policy

Use a root shell on the target for these file operations (`sudo -i`). Keep the original SSH session open. All addresses below are documentation examples: **replace every value**, retain only needed services, and add every real dependency before applying.

```sh
umask 077
fwdir=$(mktemp -d /root/hunter-firewall.XXXXXXXX)
printf 'Firewall working directory: %s\n' "$fwdir"
(
  set -e
  iptables-save > "$fwdir/before.v4"
  ip6tables-save > "$fwdir/before.v6"
  if grep -q '^\*filter$' "$fwdir/before.v4" &&
     grep -q '^\*filter$' "$fwdir/before.v6"; then
    touch "$fwdir/APPLY_OK"
  fi
  # An absent filter table allows traffic. Empty restore input would not undo
  # a newly added DROP policy, so record that original behavior explicitly.
  for family in v4 v6; do
    if ! grep -q '^\*filter$' "$fwdir/before.$family"; then
      printf '%s\n' '*filter' ':INPUT ACCEPT [0:0]' \
        ':FORWARD ACCEPT [0:0]' ':OUTPUT ACCEPT [0:0]' 'COMMIT' \
        >> "$fwdir/before.$family"
    fi
  done
  touch "$fwdir/SAVED"
)

# Replace with actual host values.
iface=eth0
server=192.0.2.10
jump=192.0.2.5/32
sshport=22
clients=198.51.100.0/24
resolver=192.0.2.53
manager=192.0.2.20
timeserver=192.0.2.123

cat > "$fwdir/services.v4" <<EOF
*filter
:INPUT DROP [0:0]
:FORWARD DROP [0:0]
:OUTPUT DROP [0:0]
-A INPUT -i lo -j ACCEPT
-A OUTPUT -o lo -j ACCEPT
-A INPUT -m conntrack --ctstate INVALID -j DROP
-A OUTPUT -m conntrack --ctstate INVALID -j DROP
# Administrative SSH: new connections only from the jump box, and their replies.
-A INPUT -i $iface -d $server -s $jump -p tcp --dport $sshport -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
-A OUTPUT -o $iface -s $server -d $jump -p tcp --sport $sshport -m conntrack --ctstate ESTABLISHED -j ACCEPT
# Web server: change the client range and remove unused ports.
-A INPUT -i $iface -d $server -s $clients -p tcp -m multiport --dports 80,443 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
-A OUTPUT -o $iface -s $server -d $clients -p tcp -m multiport --sports 80,443 -m conntrack --ctstate ESTABLISHED -j ACCEPT
# DNS client: UDP and TCP to this resolver only. Repeat for each required resolver.
-A OUTPUT -o $iface -s $server -d $resolver -p udp --dport 53 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
-A INPUT -i $iface -d $server -s $resolver -p udp --sport 53 -m conntrack --ctstate ESTABLISHED -j ACCEPT
-A OUTPUT -o $iface -s $server -d $resolver -p tcp --dport 53 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
-A INPUT -i $iface -d $server -s $resolver -p tcp --sport 53 -m conntrack --ctstate ESTABLISHED -j ACCEPT
# Existing Wazuh enrollment: verify the configured protocol/port.
-A OUTPUT -o $iface -s $server -d $manager -p tcp --dport 1514 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
-A INPUT -i $iface -d $server -s $manager -p tcp --sport 1514 -m conntrack --ctstate ESTABLISHED -j ACCEPT
# Time synchronization: keep only if this is the host's actual NTP server.
-A OUTPUT -o $iface -s $server -d $timeserver -p udp --dport 123 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
-A INPUT -i $iface -d $server -s $timeserver -p udp --sport 123 -m conntrack --ctstate ESTABLISHED -j ACCEPT
# Related IPv4 errors, including path-MTU feedback; this does not allow ping.
-A INPUT -p icmp --icmp-type 3 -m conntrack --ctstate RELATED -j ACCEPT
-A INPUT -p icmp --icmp-type 11 -m conntrack --ctstate RELATED -j ACCEPT
-A INPUT -p icmp --icmp-type 12 -m conntrack --ctstate RELATED -j ACCEPT
-A OUTPUT -p icmp --icmp-type 3 -m conntrack --ctstate RELATED -j ACCEPT
-A OUTPUT -p icmp --icmp-type 11 -m conntrack --ctstate RELATED -j ACCEPT
-A OUTPUT -p icmp --icmp-type 12 -m conntrack --ctstate RELATED -j ACCEPT
COMMIT
EOF
```

Stop if either save fails or `SAVED` was not created. The backup block records explicit ACCEPT policies when a family has no filter table, so rollback can undo a newly introduced DROP policy. Keep `fwdir`'s printed path for another session. There is deliberately **no blanket ESTABLISHED accept**: an old unrelated outbound session does not gain an exemption. Each allowed service has a reply rule. An existing unwanted connection to an approved endpoint can still match that flow; this policy restricts network paths, not which process owns them. Review `ss -ntup` and the hunt findings separately.

If the scoring sources are unknown and the web service must be public, use `clients=0.0.0.0/0` for its service ports, rather than guessing a scoring subnet. Other interfaces, secondary IPs and IPv6 need their own rules. There is no unrestricted outbound HTTP/HTTPS rule.

## Add required service pairs before COMMIT

These are **restore-file lines**, not shell commands. Substitute real addresses, add them above `COMMIT`, and remove unneeded examples. Every new flow needs its reply allowance.

```text
# Web application initiating MySQL to its DB host:
-A OUTPUT -o eth0 -s 192.0.2.10 -d 192.0.2.30 -p tcp --dport 3306 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
-A INPUT -i eth0 -d 192.0.2.10 -s 192.0.2.30 -p tcp --sport 3306 -m conntrack --ctstate ESTABLISHED -j ACCEPT
# A DNS server answering its approved clients (both UDP and TCP):
-A INPUT -i eth0 -d 192.0.2.10 -s 198.51.100.0/24 -p udp --dport 53 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
-A OUTPUT -o eth0 -s 192.0.2.10 -d 198.51.100.0/24 -p udp --sport 53 -m conntrack --ctstate ESTABLISHED -j ACCEPT
-A INPUT -i eth0 -d 192.0.2.10 -s 198.51.100.0/24 -p tcp --dport 53 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
-A OUTPUT -o eth0 -s 192.0.2.10 -d 198.51.100.0/24 -p tcp --sport 53 -m conntrack --ctstate ESTABLISHED -j ACCEPT
# If scoring/admin clients require ping, allow only their requests and replies:
-A INPUT -i eth0 -d 192.0.2.10 -s 198.51.100.0/24 -p icmp --icmp-type echo-request -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
-A OUTPUT -o eth0 -s 192.0.2.10 -d 198.51.100.0/24 -p icmp --icmp-type echo-reply -m conntrack --ctstate ESTABLISHED -j ACCEPT
```

Use the same client/server patterns for PostgreSQL 5432, SMTP 25/465/587, IMAP 143/993, LDAP/Kerberos and approved APIs. Include passive FTP data ranges or other negotiated ports if scored. A recursive DNS server also needs its upstream query flows; an authoritative-only server may not.

Wazuh agents normally initiate TCP 1514 to the manager. Enrollment may need TCP 1515 temporarily; API enrollment may use 55000. An agent does not need all manager/indexer/dashboard ports. A manager has a different inbound/outbound flow table. Check the [actual Wazuh component ports](https://documentation.wazuh.com/current/getting-started/architecture.html#required-ports).

DHCP needs explicit client UDP 68 → server/broadcast 67 and server 67 → client 68 allowances, including initial broadcasts without the assigned source IP. Static-address rules above do not cover lease acquisition. DHCPv6 is separate. Preserve actual DHCP, directory/authentication, backup, monitoring, mail-relay and storage dependencies. For package downloads, prefer an approved jump-box proxy or specific repository endpoints; hostnames in iptables resolve at rule insertion and do not track CDN address changes automatically.

## Close unused IPv6; preserve required IPv6 explicitly

Only use this file if **SSH, scored services, DNS and other dependencies do not require IPv6**. It denies all non-loopback IPv6 traffic without changing IPv6 sysctls.

```sh
cat > "$fwdir/closed.v6" <<'EOF'
*filter
:INPUT DROP [0:0]
:FORWARD DROP [0:0]
:OUTPUT DROP [0:0]
-A INPUT -i lo -j ACCEPT
-A OUTPUT -o lo -j ACCEPT
COMMIT
EOF
```

For a dual-stack host, build a separate `services.v6` using the same explicit service/reply pairs with IPv6 addresses and `ip6tables-restore`. Also allow necessary ICMPv6 errors (types 1–4), neighbor discovery (135/136), and router discovery (133/134) when using it. Constrain neighbor/router discovery to the relevant interface and hop limit 255; router advertisements should come from the expected link-local router. Include DHCPv6 if used. Do not paste the closed IPv6 policy onto an IPv6-managed host. The [IPv6 operational security guidance](https://www.rfc-editor.org/rfc/rfc9099.html) explains these dependencies.

## Apply with automatic rollback

Validate without committing rules. **Do not run these examples on the jump box itself.** `--test` still needs the target's netfilter permissions and may autoload kernel modules; a permission error is not a successful syntax check.

If both families already had filter tables (`APPLY_OK` exists), the interactive apply tools are an option. Otherwise skip to the independent rollback below, which uses the normalized backups: restoring empty save output would not remove a newly added DROP policy.

```sh
[ -f "$fwdir/SAVED" ] &&
[ -f "$fwdir/APPLY_OK" ] &&
iptables-restore --test < "$fwdir/services.v4" &&
ip6tables-restore --test < "$fwdir/closed.v6" &&
iptables-apply -t 180 "$fwdir/services.v4" &&
ip6tables-apply -t 180 "$fwdir/closed.v6"
```

During each prompt, use another terminal to make a **fresh** SSH connection and test the scored service from the jump box/client network. Test an actual app/DB transaction, name resolution, Wazuh reporting and an expected-denied destination too. Answer yes only after the tests pass. If cut off, let the timeout restore that family's prior rules. IPv4 and IPv6 apply are separate transactions; substitute `services.v6` above for a dual-stack policy. See [iptables-apply rollback behavior](https://man7.org/linux/man-pages/man8/iptables-apply.8.html).

For an initially absent filter table, unavailable apply tools, or a single rollback covering both families, **arm a detached rollback before restore**, using the unique `fwdir` already created:

```sh
if [ -f "$fwdir/SAVED" ] &&
   iptables-restore --test < "$fwdir/services.v4" &&
   ip6tables-restore --test < "$fwdir/closed.v6"; then
cat > "$fwdir/rollback.sh" <<'EOF'
#!/bin/sh
rollback_dir=$1
[ ! -f "$rollback_dir/KEEP" ] || exit 0
result=0
iptables-restore < "$rollback_dir/before.v4" || result=1
ip6tables-restore < "$rollback_dir/before.v6" || result=1
exit "$result"
EOF
chmod 700 "$fwdir/rollback.sh"
if command -v systemd-run >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
  fwunit=rollback-$(basename "$fwdir")
  systemd-run --unit="$fwunit" --on-active=180s \
    /bin/sh "$fwdir/rollback.sh" "$fwdir" &&
  systemctl is-active --quiet "$fwunit.timer" &&
  iptables-restore < "$fwdir/services.v4" &&
  ip6tables-restore < "$fwdir/closed.v6"
else
  nohup sh -c 'sleep 180; exec sh "$1/rollback.sh" "$1"' sh "$fwdir" \
    </dev/null > "$fwdir/rollback.log" 2>&1 &
  printf '%s\n' "$!" > "$fwdir/rollback.pid"
  ps -p "$(cat "$fwdir/rollback.pid")" -o pid,args &&
  iptables-restore < "$fwdir/services.v4" &&
  ip6tables-restore < "$fwdir/closed.v6"
fi
else
  printf 'Stopped: backup marker or rule validation failed.\n' >&2
fi
```

Now perform the fresh SSH and service tests in the 180-second window. **Only after they pass**, cancel rollback with:

```sh
touch "$fwdir/KEEP"
```

Keep the same root shell/`fwdir` value for that sequence. The systemd branch schedules rollback outside the SSH session. For the nohup fallback, first establish that the host permits background jobs to survive logout; nohup ignores SIGHUP but cannot defeat a session manager that terminates the whole session. Use the apply tools or an independent scheduler if that behavior is unknown. A failed test means **do not create KEEP**; wait for rollback. After the deadline, inspect active rules to confirm which policy is in effect. A marker created too late cannot undo a rollback that already ran.

## Inspect, troubleshoot and persist

```sh
iptables -L INPUT -n -v --line-numbers
iptables -L OUTPUT -n -v --line-numbers
iptables -S
ip6tables -S
```

Zero counters suggest wrong interface/address or traffic taking another path. Allowed requests with failed replies suggest a missing reply/dependency rule. Use a narrow tcpdump capture; do not temporarily set OUTPUT ACCEPT. A timeout can be a deliberate DROP. Avoid logging every dropped packet; if needed, insert a rate-limited LOG rule before the final policy drop and remove it after investigation.

Persist **after** live verification, using the system's existing firewall service: Debian/Ubuntu commonly use `netfilter-persistent` with `/etc/iptables/rules.v4` and `rules.v6`; RHEL-family `iptables-services` uses `/etc/sysconfig/iptables` and `ip6tables`; Alpine/OpenRC and Arch installations use their installed iptables service's configured save paths. openSUSE often uses firewalld. Inspect its service/configuration rather than assuming a path or enabling a second manager. Restore both families at boot; an unsaved runtime policy disappears on reboot. Do not reboot an SSH-only host just to test persistence during the tryout.

References: [iptables](https://man7.org/linux/man-pages/man8/iptables.8.html), [restore and --test](https://man7.org/linux/man-pages/man8/iptables-restore.8.html), [conntrack/extension matches](https://man7.org/linux/man-pages/man8/iptables-extensions.8.html). Return to [[Linux Hardening Checklist]] · [[00 CCDC Runbook]].
