---
updated: 2026-11-20
tags: [ccdc, pcap, wireshark, logging, wazuh]
---
# Packet capture — Wireshark and injects

**Use Wazuh for service/security alerts and tcpdump or dumpcap for packet files.** Wazuh does not replace a continuous PCAP recorder or Wireshark. Passive capture can start during phase 1 when permitted; firewall changes and blocking belong to phase 2. Nothing here starts capture automatically through hunter-setup.

| Need | Use |
| --- | --- |
| Know a service went down or recovered | [[Service Watchdogs and Alerts]] → Wazuh rules/notifications |
| Preserve packets for an inject | tcpdump rolling PCAP, or dumpcap rolling PCAPNG |
| Search conversations, requests and timing | Wireshark on the local analysis machine |
| Send network intrusion alerts to Wazuh | Suricata IDS → EVE JSON → Wazuh agent |

## Pick a capture point

Capture on the actual service host/interface, a gateway carrying that traffic, or an available SPAN/TAP sensor. A jump box normally sees its own traffic, not all traffic between other machines on a switched network. Promiscuous mode alone does not change that. An independent sensor also avoids relying entirely on a compromised host's packet view.

On the Linux target:

```sh
date -u '+%Y-%m-%dT%H:%M:%SZ'
ip -br address
ip route
sudo tcpdump -D
```

Use the service-facing interface for fewer duplicates and Ethernet visibility. Linux `-i any` includes interfaces in the current network namespace, including loopback; it does not enter every container namespace and can show multiple observations of forwarded packets. Record host, interface, UTC window and capture filter in the inject notes. See [[Host Info Commands]].

If tcpdump is missing, install tooling from the native repositories during preparation:

| Manager | Command |
| --- | --- |
| apt | `sudo apt-get install tcpdump` |
| dnf / yum | `sudo dnf install tcpdump` or `sudo yum install tcpdump` |
| zypper | `sudo zypper install tcpdump` |
| pacman | `sudo pacman -S --needed tcpdump` |
| apk | `sudo apk add tcpdump` |

## Continuous bounded capture

Run on the target in a persistent terminal, such as tmux if already available. Replace `eth0`. This saves full packets, rotates at about **25 MB per file**, and reuses **20 files**: roughly **500 MB total**, plus small overhead. Older packets are overwritten. Preserve an incident window promptly.

```sh
sudo sh -c '
  umask 077
  mkdir -p /var/log/hunter-pcaps
  chmod 700 /var/log/hunter-pcaps
  exec tcpdump -i eth0 -nn -s 0 -U -B 4096 -Z root \
    -C 25 -W 20 -w /var/log/hunter-pcaps/traffic.pcap
'
```

`-s 0` retains full packets, `-U` flushes each packet to the capture output, and `-B` requests a larger capture buffer. Explicit `-Z root` lets this root-run recorder create rotated files in the private directory across distro privilege-drop defaults. Files contain potentially sensitive payloads; keep them private and out of Git. Check available disk first and confirm the file sizes are increasing.

For a recorder that survives SSH disconnection without tmux, use this **instead of** the foreground command:

```sh
sudo sh -c '
  umask 077
  mkdir -p /var/log/hunter-pcaps
  chmod 700 /var/log/hunter-pcaps
  nohup tcpdump -i eth0 -nn -s 0 -U -B 4096 -Z root \
    -C 25 -W 20 -w /var/log/hunter-pcaps/traffic.pcap \
    </dev/null > /var/log/hunter-pcaps/capture.log 2>&1 &
  printf "%s\n" "$!" > /var/log/hunter-pcaps/capture.pid
'
sudo cat /var/log/hunter-pcaps/capture.pid
sudo tail /var/log/hunter-pcaps/capture.log
sudo ls -lh /var/log/hunter-pcaps
```

Start one recorder per output prefix; do not run both commands against the same files. The PID is a record, not proof the process still runs: check `ps -p PID -o pid,args`. Stop your verified recorder with `sudo kill -INT PID`, or Ctrl-C in its foreground terminal. SIGINT closes the file and prints capture/drop counts; avoid SIGKILL. Packet drops mean incomplete evidence; review traffic rate, buffer and disk pressure.

## Focus on an inject

If broad capture is too busy, append a quoted **capture filter** to tcpdump, for example `'host 192.0.2.10 and (tcp port 80 or tcp port 443)'`. Use `'not tcp port 22'` only if you deliberately accept losing SSH evidence. A narrow filter cannot recover excluded packets later. For a short ad hoc capture, choose a new file and stop after reproducing the problem:

```sh
sudo tcpdump -i eth0 -nn -s 0 -U -Z root \
  -w /var/log/hunter-pcaps/inject-check.pcap \
  'host 192.0.2.10 and (port 53 or tcp port 80 or tcp port 443)'
```

Create the private directory as above first. Do not reuse an evidence filename: `-w` can overwrite it. tcpdump's `-C`/`-W` combination is a size ring. Do not replace it casually with `-G`/`-W`; that combination can stop after a fixed number of time-rotated files instead of retaining a continuous size ring. See [tcpdump options](https://man7.org/linux/man-pages/man8/tcpdump.8.html).

If dumpcap is already installed, its PCAPNG ring is another option:

```sh
sudo sh -c '
  umask 077
  mkdir -p /var/log/hunter-pcaps
  chmod 700 /var/log/hunter-pcaps
  exec dumpcap -i eth0 -s 0 -b filesize:25000 -b files:20 \
    -w /var/log/hunter-pcaps/traffic.pcapng
'
```

dumpcap's file-size value is in kB; this is also approximately 500 MB retained. Wireshark reads both PCAP and PCAPNG. See the [official dumpcap ring-buffer manual](https://www.wireshark.org/docs/man-pages/dumpcap.html).

## Freeze, export and analyze

Stop the recorder before copying the ring, or select completed files that will not be reused during the copy. Copying a file while it is being overwritten can produce inconsistent evidence. From a regular target-user shell, stage selected closed captures privately for SCP:

```sh
pcap_copy=$(mktemp -d "$HOME/ccdc-pcaps.XXXXXXXX")
# Replace this with the actual closed file shown by ls.
sudo cp /var/log/hunter-pcaps/traffic.pcap00 "$pcap_copy/"
sudo chown "$(id -u):$(id -g)" "$pcap_copy/traffic.pcap00"
chmod 600 "$pcap_copy/traffic.pcap00"
sha256sum "$pcap_copy/traffic.pcap00"
printf 'Export directory: %s\n' "$pcap_copy"
```

From the jump box/analysis machine, use the printed absolute path and actual SSH port:

```sh
mkdir -p reports/pcap
chmod 700 reports/pcap
scp -P 22 defender@192.0.2.10:/home/defender/ccdc-pcaps.REPLACE/traffic.pcap00 reports/pcap/
sha256sum reports/pcap/traffic.pcap00
wireshark reports/pcap/traffic.pcap00
```

Match the source and destination hashes. In Wireshark, display timestamps in UTC to compare with Wazuh and the inject window. Useful **display filters**:

| Investigate | Display filter / action |
| --- | --- |
| One IPv4/IPv6 host | `ip.addr == 192.0.2.10` / `ipv6.addr == 2001:db8::10` |
| DNS questions and answers | `dns` |
| New TCP connection attempts | `tcp.flags.syn == 1 && tcp.flags.ack == 0` |
| HTTP requests/responses | `http.request || http.response` |
| Connection problems | `tcp.analysis.retransmission || tcp.flags.reset == 1` |
| One conversation | Right-click → Follow → TCP Stream; retain `tcp.stream eq N` |

Capture-filter syntax and Wireshark display-filter syntax differ. TLS and SSH payloads remain encrypted without appropriate session secrets; use metadata and application logs rather than expecting plaintext from a PCAP alone. For an inject, retain the original file/hash, relevant UTC window, endpoints, selected stream/packet numbers and a short explanation of the evidence.

## Network IDS events in Wazuh

Suricata can inspect traffic and emit structured events. For a sensor already configured for passive IDS, add this inside its Wazuh agent's `ossec_config`, then restart that agent and verify actual alert arrival:

```xml
<localfile>
  <log_format>json</log_format>
  <location>/var/log/suricata/eve.json</location>
</localfile>
```

The [official Wazuh Suricata integration](https://documentation.wazuh.com/current/proof-of-concept-guide/integrate-network-ids-suricata.html) covers sensor configuration and existing rules. EVE JSON is metadata/alerts, not the packet archive. Keep the PCAP recorder separately. During preparation, use passive monitoring without inline blocking or automatic response.

Return to [[Service Watchdogs and Alerts]] · [[Firewall - Default Deny with iptables]] · [[00 CCDC Runbook]].
