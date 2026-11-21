#!/bin/sh
set -eu
umask 077
unset ENV BASH_ENV CDPATH
PATH=/usr/sbin:/usr/bin:/sbin:/bin:/usr/local/sbin:/usr/local/bin
export PATH
D=$(CDPATH= cd -P "$(dirname "$0")" && pwd)
STATE=/.x86 ROOT= CONFIG= OWNER= ACTION= START=yes
fail() { printf 'hunter-watch: %s\n' "$*" >&2; exit 1; }
while [ "$#" -gt 0 ]; do
 case $1 in
 install|check|status|enable-recovery|disable-recovery) [ -z "$ACTION" ] || fail 'Multiple actions'; ACTION=$1; shift ;;
 --state-dir|--root|--config|--owner) [ "$#" -ge 2 ] && [ -n "$2" ] || fail "Missing value for $1"; case $1 in --state-dir) STATE=$2;; --root) ROOT=$2;; --config) CONFIG=$2;; --owner) OWNER=$2;; esac; shift 2 ;;
 --no-start) START=no; shift ;;
 -h|--help) printf 'Usage: hunter-watch.sh install|check|status|enable-recovery|disable-recovery [--config FILE] [--state-dir PATH] [--owner local|wazuh] [--root DIR] [--no-start]\n'; exit 0 ;;
 *) fail "Unknown argument: $1" ;;
 esac
done
[ -n "$ACTION" ] || ACTION=status
[ "$(id -u)" = 0 ] || fail 'Root required'
for p in "$STATE" ${ROOT:+"$ROOT"}; do
 case $p in /*) ;; *) fail 'Paths must be absolute';; esac
 case $p in *[!A-Za-z0-9_./-]*|*//*|*/../*|*/./*|*/..|*/.) fail 'Unsafe path';; esac
done
[ -z "$ROOT" ] || { [ -d "$ROOT" ] && [ ! -L "$ROOT" ] || fail 'Invalid fixture root'; START=no; }
[ -z "$OWNER" ] || { [ "$ACTION" = enable-recovery ] && { [ "$OWNER" = local ] || [ "$OWNER" = wazuh ]; }; } || fail 'Invalid owner'
[ "$ACTION" != enable-recovery ] || [ -n "$OWNER" ] || fail 'Specify --owner local or wazuh'
BIN=$ROOT/usr/local/libexec/hunter-watch
DEST=$ROOT/etc/hunter-watch/services.conf
if [ "$ACTION" != install ]; then
 [ -z "$ROOT" ] || fail '--root is only supported for install'
 [ -x "$BIN" ] && [ ! -L "$BIN" ] || fail 'Installed helper missing or unsafe'
 if [ "$ACTION" = enable-recovery ]; then exec "$BIN" "$ACTION" --state-dir "$STATE" --owner "$OWNER"; fi
 exec "$BIN" "$ACTION" --state-dir "$STATE"
fi
[ -n "$CONFIG" ] && [ -f "$CONFIG" ] && [ ! -L "$CONFIG" ] || fail 'Install requires a regular manifest via --config'
SRC=${HUNTER_WATCH_COLLECTOR:-}
if [ -z "$SRC" ]; then
 case $(uname -m) in x86_64) arch=amd64;; aarch64) arch=arm64;; i?86) arch=386;; arm*) arch=arm;; *) fail 'Unsupported architecture';; esac
 SRC=$D/watchdog/bin/hunter-watch-linux-$arch
fi
[ -f "$SRC" ] && [ ! -L "$SRC" ] && [ -x "$SRC" ] || fail 'Helper missing or unsafe'
# Stage as root before validation: sudo callers can supply their own manifest.
# Reject source files writable by others; copy into a root-private temporary directory.
perm=$(stat -c %A "$CONFIG") || fail 'Cannot inspect manifest'
case $perm in ?????w*|????????w*) fail 'Manifest is group/world writable';; esac
srcuid=$(stat -c %u "$CONFIG") || fail 'Cannot inspect manifest'
[ "$srcuid" = 0 ] || [ "$srcuid" = "${SUDO_UID:-0}" ] || fail 'Manifest owner is not the invoking user'
stage=$(mktemp -d /tmp/hunter-watch-stage.XXXXXXXX)
trap 'rm -rf "$stage"' 0
trap 'exit 1' 1 2 15
cp "$CONFIG" "$stage/config"; chmod 600 "$stage/config"
cp "$SRC" "$stage/helper"; chmod 700 "$stage/helper"
"$stage/helper" validate --config "$stage/config" --state-dir "$STATE" || fail 'Manifest validation failed'
# Reject symlinks and writable directory components under the chosen root.
secure_dir() {
 path=$1; current=; oldifs=$IFS; IFS=/; set -- $path; IFS=$oldifs
 for part do
  [ -n "$part" ] || continue
  current=$current/$part
  [ ! -L "$current" ] || fail "Symlink in path: $current"
  if [ ! -e "$current" ]; then mkdir "$current" || fail "Cannot create $current"; chmod 700 "$current"; fi
  [ -d "$current" ] || fail "Not a directory: $current"
  mode=$(stat -c %a "$current") || fail 'Cannot inspect directory'
  uid=$(stat -c %u "$current") || fail 'Cannot inspect directory'
  [ "$uid" = 0 ] || fail "Directory not root owned: $current"
  # World/group writable directories permit replacement of staged files.
  perm=$(stat -c %A "$current")
  case $perm in ?????w*|????????w*) fail "Writable directory: $current";; esac
 done
}
# Fixture roots often live under /tmp; validate from the fixture itself, not its parents.
if [ -n "$ROOT" ]; then
 [ "$(stat -c %u "$ROOT")" = 0 ] || fail 'Fixture root must be root-owned'
fi
secure_target_dir() {
 if [ -n "$ROOT" ]; then
  rel=${1#"$ROOT"}; current=$ROOT; oldifs=$IFS; IFS=/; set -- $rel; IFS=$oldifs
  for part do [ -n "$part" ] || continue; current=$current/$part; [ ! -L "$current" ] || fail "Symlink: $current"; if [ ! -e "$current" ]; then mkdir "$current"; chmod 700 "$current"; fi; [ -d "$current" ] && [ "$(stat -c %u "$current")" = 0 ] || fail "Unsafe directory: $current"; perm=$(stat -c %A "$current"); case $perm in ?????w*|????????w*) fail "Writable directory: $current";; esac; done
 else secure_dir "$1"; fi
}
secure_target_dir "$ROOT/usr/local/libexec"
secure_target_dir "$ROOT/etc/hunter-watch"
for f in "$BIN" "$DEST"; do [ ! -L "$f" ] || fail "Symlink target: $f"; if [ -e "$f" ]; then [ -f "$f" ] && [ "$(stat -c %u "$f")" = 0 ] || fail "Unsafe target: $f"; perm=$(stat -c %A "$f"); case $perm in ?????w*|????????w*) fail "Writable target: $f";; esac; fi; done
# Prepare all files and verify scheduler paths before replacing installed files.
bstage=$(mktemp "$BIN.new.XXXXXXXX")
cstage=$(mktemp "$DEST.new.XXXXXXXX")
backup=$(mktemp -d "$ROOT/etc/hunter-watch/.rollback.XXXXXXXX")
committed=no changed=no sched_changed=no cron_changed=no sched= sched_files= activation=no was_enabled=no was_active=no
cleanup() {
 if [ "$committed" != yes ]; then
  if [ "$cron_changed" = yes ]; then crontab "$backup/crontab" || printf 'hunter-watch: failed to restore crontab\n' >&2; fi
  if [ "$activation" = yes ]; then
   if [ "$kind" = systemd ]; then
    [ "$was_active" = yes ] || systemctl stop hunter-watch.timer >/dev/null 2>&1 || :
    [ "$was_enabled" = yes ] || systemctl disable hunter-watch.timer >/dev/null 2>&1 || :
   elif [ "$kind" = openrc ]; then
    [ "$was_active" = yes ] || rc-service hunter-watch stop >/dev/null 2>&1 || :
    [ "$was_enabled" = yes ] || rc-update del hunter-watch default >/dev/null 2>&1 || :
   fi
  fi
  if [ "$sched_changed" = yes ]; then
   for f in $sched_files; do
    if [ -f "$backup/$f" ]; then cp -p "$backup/$f" "$sched/$f" || :; else rm -f "$sched/$f"; fi
   done
   if [ "$activation" = yes ] && [ "$kind" = systemd ]; then systemctl daemon-reload >/dev/null 2>&1 || :; fi
  fi
  if [ "$changed" = yes ]; then
   if [ -f "$backup/bin" ]; then cp -p "$backup/bin" "$BIN" || :; else rm -f "$BIN"; fi
   if [ -f "$backup/config" ]; then cp -p "$backup/config" "$DEST" || :; else rm -f "$DEST"; fi
  fi
  if [ "$activation" = yes ] && [ "$was_active" = yes ]; then
   if [ "$kind" = systemd ]; then systemctl restart hunter-watch.timer >/dev/null 2>&1 || :
   elif [ "$kind" = openrc ]; then rc-service hunter-watch restart >/dev/null 2>&1 || :; fi
  fi
 fi
 rm -f "$bstage" "$cstage"
 rm -rf "$backup" "$stage"
}
trap cleanup 0
trap 'exit 1' 1 2 15
cp "$stage/helper" "$bstage"; chmod 700 "$bstage"
cp "$stage/config" "$cstage"; chmod 600 "$cstage"
"$bstage" validate --config "$cstage" --state-dir "$STATE" || fail 'Staged manifest validation failed'
[ ! -e "$BIN" ] || cp -p "$BIN" "$backup/bin"
[ ! -e "$DEST" ] || cp -p "$DEST" "$backup/config"
# An offline fixture selects its init system with the corresponding run marker.
if [ -d "$ROOT/run/systemd/system" ] && { [ -n "$ROOT" ] || command -v systemctl >/dev/null 2>&1; }; then
 kind=systemd; sched=$ROOT/etc/systemd/system; sched_files='hunter-watch.service hunter-watch.timer'
elif [ -f "$ROOT/run/openrc/softlevel" ] && { [ -n "$ROOT" ] || { command -v rc-update >/dev/null 2>&1 && command -v rc-service >/dev/null 2>&1 && command -v supervise-daemon >/dev/null 2>&1; }; }; then
 kind=openrc; sched=$ROOT/etc/init.d; sched_files=hunter-watch
else
 kind=cron
fi
if [ "$kind" != cron ]; then
 secure_target_dir "$sched"
 for f in $sched_files; do
  [ ! -L "$sched/$f" ] || fail 'Unsafe scheduler target'
  if [ -e "$sched/$f" ]; then
   [ -f "$sched/$f" ] && [ "$(stat -c %u "$sched/$f")" = 0 ] || fail 'Unsafe scheduler target'
   perm=$(stat -c %A "$sched/$f"); case $perm in ?????w*|????????w*) fail 'Writable scheduler target';; esac
   cp -p "$sched/$f" "$backup/$f"
  fi
 done
fi
case $kind in
 systemd)
  cat > "$backup/service.new" <<END
[Unit]
Description=Hunter service watchdog check
[Service]
Type=oneshot
TimeoutStartSec=0
ExecStart=/usr/local/libexec/hunter-watch check --state-dir $STATE
END
  cat > "$backup/timer.new" <<'END'
[Unit]
Description=Hunter service watchdog timer
[Timer]
OnBootSec=30s
OnUnitInactiveSec=30s
AccuracySec=1s
[Install]
WantedBy=timers.target
END
  chmod 644 "$backup/service.new" "$backup/timer.new" ;;
 openrc)
  cat > "$backup/openrc.new" <<END
#!/sbin/openrc-run
description="Hunter service watchdog"
supervisor=supervise-daemon
command=/usr/local/libexec/hunter-watch
command_args="watch --interval 30 --state-dir $STATE"
respawn_delay=5
END
  chmod 755 "$backup/openrc.new" ;;
 cron)
  if [ -n "$ROOT" ] || [ "$START" = no ]; then
   # Offline and no-start installs leave a reviewable inactive cron entry.
   sched=$ROOT/etc/hunter-watch; sched_files=cron.example
   [ ! -L "$sched/cron.example" ] || fail 'Unsafe cron example'
   if [ -e "$sched/cron.example" ]; then
    [ -f "$sched/cron.example" ] && [ "$(stat -c %u "$sched/cron.example")" = 0 ] || fail 'Unsafe cron example'
    perm=$(stat -c %A "$sched/cron.example"); case $perm in ?????w*|????????w*) fail 'Writable cron example';; esac
    cp -p "$sched/cron.example" "$backup/cron.example"
   fi
   printf '* * * * * /usr/local/libexec/hunter-watch check --state-dir %s\n' "$STATE" > "$backup/cron.new"
   chmod 600 "$backup/cron.new"
  else
   command -v crontab >/dev/null 2>&1 || fail 'No supported init or crontab command found'
   if ! crontab -l > "$backup/crontab" 2> "$backup/cron.err"; then
    # Common cron implementations report an absent crontab this way.
    if ! grep -qi 'no crontab' "$backup/cron.err"; then fail 'Cannot read existing root crontab'; fi
    : > "$backup/crontab"
   fi
   awk '/^# BEGIN hunter-watch$/ {if (inside || seen) exit 1; inside=1; seen=1; next} /^# END hunter-watch$/ {if (!inside) exit 1; inside=0} END {if (inside) exit 1}' "$backup/crontab" || fail 'Malformed hunter-watch crontab markers'
   awk '/^# BEGIN hunter-watch$/ {skip=1; next} /^# END hunter-watch$/ {skip=0; next} !skip {print}' "$backup/crontab" > "$backup/cron.new"
   printf '# BEGIN hunter-watch\n* * * * * /usr/local/libexec/hunter-watch check --state-dir %s\n# END hunter-watch\n' "$STATE" >> "$backup/cron.new"
  fi ;;
esac
changed=yes
mv -f "$bstage" "$BIN"; mv -f "$cstage" "$DEST"
case $kind in
 systemd)
  sched_changed=yes
  mv "$backup/service.new" "$sched/hunter-watch.service"; mv "$backup/timer.new" "$sched/hunter-watch.timer"
  if [ "$START" = yes ]; then
   systemctl is-enabled --quiet hunter-watch.timer && was_enabled=yes || :
   systemctl is-active --quiet hunter-watch.timer && was_active=yes || :
   activation=yes
   systemctl daemon-reload && systemctl enable --now hunter-watch.timer || fail 'Systemd activation failed; restoring files'
  fi ;;
 openrc)
  sched_changed=yes
  mv "$backup/openrc.new" "$sched/hunter-watch"
  if [ "$START" = yes ]; then
   rc-update show default | awk '$1 == "hunter-watch" {found=1} END {exit !found}' && was_enabled=yes || :
   rc-service hunter-watch status >/dev/null 2>&1 && was_active=yes || :
   activation=yes
   rc-update add hunter-watch default && rc-service hunter-watch restart || fail 'OpenRC activation failed; restoring files'
  fi ;;
 cron)
  if [ -n "$ROOT" ] || [ "$START" = no ]; then
   sched_changed=yes
   mv "$backup/cron.new" "$sched/cron.example"
  else
   cron_changed=yes
   crontab "$backup/cron.new" || fail 'Crontab activation failed; restoring files'
  fi ;;
esac
committed=yes
printf 'Installed monitor (%s); recovery ownership was not changed.\n' "$kind"
