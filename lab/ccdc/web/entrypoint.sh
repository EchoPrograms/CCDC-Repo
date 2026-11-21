#!/bin/sh
set -eu
ssh-keygen -A
/opt/site-tools/on-start
service cron start
/usr/sbin/sshd
exec apache2-foreground
