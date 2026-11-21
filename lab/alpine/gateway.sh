#!/bin/sh
# Fixed TCP forwarding only; the vulnerable target has no external network.
set -eu
socat TCP-LISTEN:2222,reuseaddr,fork TCP:target:22 &
ssh_forwarder=$!
socat TCP-LISTEN:8080,reuseaddr,fork TCP:target:8080 &
web_forwarder=$!
cleanup() {
    trap '' HUP INT TERM
    kill "$ssh_forwarder" "$web_forwarder" 2>/dev/null || :
    wait "$ssh_forwarder" "$web_forwarder" 2>/dev/null || :
}
trap cleanup 0
trap 'exit 0' HUP INT TERM
# If the SSH forwarder exits, stop this gateway; HTTP is also health-checked.
wait "$ssh_forwarder"
