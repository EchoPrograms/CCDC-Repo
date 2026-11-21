#!/bin/sh
set -eu
[ -s /run/sshd.pid ]
kill -0 "$(cat /run/sshd.pid)"
wget -q -O /dev/null http://127.0.0.1:8080/health.txt
