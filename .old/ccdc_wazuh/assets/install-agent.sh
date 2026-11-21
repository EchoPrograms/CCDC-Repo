#!/bin/sh
# Invoked as root with one controller-created, private staging directory.
set -eu
umask 077

fail() { printf '%s\n' "ERROR: $*" >&2; exit 1; }
[ "$(id -u)" = 0 ] || fail 'root required'
[ "$(uname -s)" = Linux ] || fail 'Linux required'
[ "$#" -eq 1 ] || fail 'expected one absolute staging directory'
case $1 in /*) stage=$1 ;; *) fail 'staging directory must be absolute' ;; esac
[ -d "$stage" ] && [ ! -L "$stage" ] || fail 'invalid staging directory'
for field in manager agent_name version package.sha512 client.keys; do
    [ -f "$stage/$field" ] && [ ! -L "$stage/$field" ] || fail "missing or invalid $field"
done
read_one() {
    [ "$(wc -l < "$1" | tr -d ' ')" -le 1 ] || fail 'invalid staging field'
    value=$(cat "$1")
    [ -n "$value" ] || fail 'empty staging field'
}
read_one "$stage/manager"; manager=$value
case $manager in *[!a-zA-Z0-9.:-]* | -* | *:) fail 'invalid manager address' ;; esac
read_one "$stage/agent_name"; agent_name=$value
case $agent_name in *[!a-zA-Z0-9_.-]* | -* ) fail 'invalid agent name' ;; esac
read_one "$stage/version"; version=$value
case $version in *[!0-9.]* | .* | *.) fail 'invalid version' ;; esac
port=1514
if [ -e "$stage/manager_port" ]; then
    [ -f "$stage/manager_port" ] && [ ! -L "$stage/manager_port" ] || fail 'invalid manager port'
    read_one "$stage/manager_port"; port=$value
fi
case $port in *[!0-9]* | '') fail 'invalid manager port' ;; esac
[ "$port" -ge 1 ] 2>/dev/null && [ "$port" -le 65535 ] 2>/dev/null || fail 'invalid manager port'
read_one "$stage/package.sha512"; expected=$value
case $expected in *[!a-fA-F0-9]*) fail 'invalid SHA-512 digest' ;; esac
[ "${#expected}" -eq 128 ] || fail 'invalid SHA-512 digest'
[ -s "$stage/client.keys" ] || fail 'empty client key'

control=/var/ossec/bin/wazuh-control
if [ -x "$control" ]; then
    info=$($control info 2>/dev/null || :)
    printf '%s\n' "$info" | grep -Eiq '(^|[^a-z])(server|manager)([^a-z]|$)' && fail 'Wazuh manager detected'
else
    info=
fi
if command -v pgrep >/dev/null 2>&1; then
    for proc in wazuh-analysisd wazuh-remoted; do pgrep -x "$proc" >/dev/null 2>&1 && fail 'Wazuh manager process detected'; done
fi
if [ -f "$stage/package.deb" ] && [ ! -L "$stage/package.deb" ] && [ ! -e "$stage/package.rpm" ]; then
    package=$stage/package.deb; package_type=deb
elif [ -f "$stage/package.rpm" ] && [ ! -L "$stage/package.rpm" ] && [ ! -e "$stage/package.deb" ]; then
    package=$stage/package.rpm; package_type=rpm
else
    fail 'expected exactly one package'
fi
if command -v sha512sum >/dev/null 2>&1; then
    actual=$(sha512sum "$package"); actual=${actual%% *}
elif command -v openssl >/dev/null 2>&1; then
    actual=$(openssl dgst -sha512 "$package"); actual=${actual##* }
else
    fail 'SHA-512 utility unavailable'
fi
[ "$(printf '%s' "$actual" | tr 'A-F' 'a-f')" = "$(printf '%s' "$expected" | tr 'A-F' 'a-f')" ] || fail 'package digest mismatch'
printf '%s\n' 'STATUS: package verified'

config=/var/ossec/etc/ossec.conf
keys=/var/ossec/etc/client.keys
backup=
if [ -f "$config" ] && [ ! -L "$config" ]; then
    backup=$(mktemp -d /var/ossec/etc/ccdc-backup.XXXXXXXX) || fail 'cannot create backup'
    cp -p "$config" "$backup/ossec.conf"
    if [ -f "$keys" ] && [ ! -L "$keys" ]; then cp -p "$keys" "$backup/client.keys"; else : > "$backup/no-client.keys"; fi
fi
installed=no
if [ -x "$control" ] && printf '%s\n' "$info" | grep -Fq "v$version\""; then installed=yes; fi
if [ "$installed" = no ]; then
    case $package_type in
        deb) command -v dpkg >/dev/null 2>&1 || fail 'dpkg unavailable'; WAZUH_MANAGER="$manager" WAZUH_AGENT_NAME="$agent_name" dpkg -i "$package" ;;
        rpm) command -v rpm >/dev/null 2>&1 || fail 'rpm unavailable'; WAZUH_MANAGER="$manager" WAZUH_AGENT_NAME="$agent_name" rpm -Uvh "$package" ;;
    esac
fi
[ -x "$control" ] || fail 'agent control unavailable after installation'
[ -f "$config" ] && [ ! -L "$config" ] || fail 'agent configuration unavailable'
if [ -z "$backup" ]; then
    backup=$(mktemp -d /var/ossec/etc/ccdc-backup.XXXXXXXX) || fail 'cannot create backup'
    cp -p "$config" "$backup/ossec.conf"
    if [ -f "$keys" ] && [ ! -L "$keys" ]; then cp -p "$keys" "$backup/client.keys"; else : > "$backup/no-client.keys"; fi
fi

# The intentionally conservative line-oriented editor accepts the standard
# Wazuh layout and refuses ambiguous XML rather than guessing at its meaning.
if ! awk -v address="$manager" -v port="$port" '
# BEGIN CONFIG EDITOR
BEGIN { client=0; server=0; clients=0; servers=0; addresses=0; ports=0; bad=0 }
{
    line=$0
    if (line ~ /<!--[[:space:]]*<\/?(client|server|address|port)/ || line ~ /<(client|server)([[:space:]>])/ && line ~ /<\/(client|server)>/) bad=1
    if (line ~ /<client([[:space:]>])/) { if (client || server) bad=1; client=1; clients++ }
    if (line ~ /<server([[:space:]>])/) { if (!client || server) bad=1; server=1; servers++ }
    if (server && line ~ /<address>/) {
        addresses++; if (line !~ /^[[:space:]]*<address>[^<]*<\/address>[[:space:]]*$/) bad=1
        sub(/<address>[^<]*<\/address>/, "<address>" address "</address>", line)
    }
    if (server && line ~ /<port>/) {
        ports++; if (line !~ /^[[:space:]]*<port>[^<]*<\/port>[[:space:]]*$/) bad=1
        sub(/<port>[^<]*<\/port>/, "<port>" port "</port>", line)
    }
    if (line ~ /<\/server>/) { if (!server) bad=1; server=0 }
    if (line ~ /<\/client>/) { if (!client || server) bad=1; client=0 }
    print line
}
END { if (bad || client || server || clients != 1 || servers != 1 || addresses != 1 || ports != 1) exit 1 }
# END CONFIG EDITOR
' "$config" > "$backup/ossec.conf.new"; then fail 'ambiguous client configuration; backup retained'; fi
cp -p "$config" "$backup/install.conf"
cat "$backup/ossec.conf.new" > "$backup/install.conf"
mv -f "$backup/install.conf" "$config"
install -m 0640 "$stage/client.keys" "$backup/install.keys"
chown root:wazuh "$backup/install.keys" 2>/dev/null || chown root:root "$backup/install.keys"
mv -f "$backup/install.keys" "$keys"

service_kind=manual
if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
    service_kind=systemd
    mkdir -p /etc/systemd/system/wazuh-agent.service.d
    printf '%s\n' '[Service]' 'Restart=on-failure' 'RestartSec=5' 'NoNewPrivileges=true' > /etc/systemd/system/wazuh-agent.service.d/ccdc.conf
    systemctl daemon-reload
elif command -v rc-service >/dev/null 2>&1 && [ -d /run/openrc ]; then
    service_kind=openrc
    if [ ! -f /etc/init.d/wazuh-agent ]; then
        cat > /etc/init.d/wazuh-agent <<'EOF'
#!/sbin/openrc-run
description="Wazuh agent"
start() { /var/ossec/bin/wazuh-control start; }
stop() { /var/ossec/bin/wazuh-control stop; }
status() { /var/ossec/bin/wazuh-control status; }
EOF
        chmod 755 /etc/init.d/wazuh-agent
    fi
elif [ -x /etc/init.d/wazuh-agent ]; then service_kind=sysv
fi
restart() {
    case $service_kind in
        systemd) systemctl enable wazuh-agent && systemctl restart wazuh-agent ;;
        openrc) if command -v rc-update >/dev/null 2>&1; then rc-update add wazuh-agent default >/dev/null; fi; rc-service wazuh-agent restart ;;
        sysv) /etc/init.d/wazuh-agent restart ;;
        manual) printf '%s\n' 'WARNING: no supported service manager; starting manually' >&2; "$control" restart ;;
    esac
}
rollback() {
    cp -p "$backup/ossec.conf" "$config"
    if [ -f "$backup/client.keys" ]; then cp -p "$backup/client.keys" "$keys"; else rm -f "$keys"; fi
    restart >/dev/null 2>&1 || :
    printf '%s\n' 'ERROR: validation or startup failed; prior configuration restored; backup retained' >&2
    exit 1
}
if [ -x /var/ossec/bin/wazuh-agentd ]; then /var/ossec/bin/wazuh-agentd -t >/dev/null 2>&1 || rollback; fi
restart || rollback
status=$($control status 2>/dev/null) || rollback
printf '%s\n' "$status" | grep -Eq 'wazuh-agentd.*(running|started)' || rollback
printf '%s\n' 'STATUS: agent running; backup retained'
