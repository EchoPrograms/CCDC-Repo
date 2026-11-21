#!/bin/sh
set -eu
ssh-keygen -A
/usr/sbin/sshd
exec dnsmasq --keep-in-foreground
