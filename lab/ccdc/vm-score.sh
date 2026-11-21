#!/bin/sh
set -eu
case "${1:-score}" in
 score)
   response=$(curl -fsS --max-time 10 -X POST http://127.0.0.1:18080/) || { echo 'web transaction: FAIL'; exit 1; }
   printf '%s' "$response" | grep -q '"ok":true' || { echo 'web transaction: FAIL'; exit 1; }
   echo "web transaction: PASS $response"
   systemctl is-active --quiet ssh && echo 'SSH daemon: PASS' || { echo 'SSH daemon: FAIL'; exit 1; }
   ;;
 outage) touch /var/lib/ccdc-practice/offline ;;
 restore) rm -f /var/lib/ccdc-practice/offline ;;
 *) echo 'Usage: vm-score.sh [score|outage|restore]' >&2; exit 2 ;;
esac
