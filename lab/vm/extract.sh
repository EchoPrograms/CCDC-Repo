#!/bin/sh
# Stream only the known archive members into a fresh staging directory.
set -eu
[ "$#" -eq 2 ] || { echo 'Usage: extract.sh ARCHIVE DESTINATION' >&2; exit 2; }
archive=$1
destination=$2
[ -f "$archive" ] || { echo 'Archive not found.' >&2; exit 1; }
command -v unzip >/dev/null || { echo 'unzip is required.' >&2; exit 1; }
mkdir -p "$destination"
target="$destination/Aperture Science Ubuntu"
[ ! -e "$target" ] || { echo "Refusing to overwrite $target" >&2; exit 1; }
staging=$(mktemp -d "$destination/.extract.XXXXXXXX")
cleanup() { [ -z "$staging" ] || rm -rf "$staging"; }
trap cleanup 0 HUP INT TERM
unzip -Z1 "$archive" > "$staging/members"
for name in 'Aperture Science Ubuntu.vmdk' 'Aperture Science Ubuntu.vmx' 'Aperture Science Ubuntu-s001.vmdk' 'Aperture Science Ubuntu-s002.vmdk' 'Aperture Science Ubuntu-s003.vmdk' 'Aperture Science Ubuntu-s004.vmdk' 'Aperture Science Ubuntu-s005.vmdk' 'Aperture Science Ubuntu-s006.vmdk' 'Aperture Science Ubuntu-s007.vmdk' 'Aperture Science Ubuntu-s008.vmdk' 'Aperture Science Ubuntu-s009.vmdk'; do
  member="Aperture Science Ubuntu/$name"
  count=$(awk -v expected="$member" '$0 == expected {n++} END {print n+0}' "$staging/members")
  [ "$count" -eq 1 ] || { echo "Expected one archive entry: $member" >&2; exit 1; }
  printf 'Extracting %s\n' "$name"
  unzip -p "$archive" "$member" > "$staging/$name"
done
rm "$staging/members"
mv "$staging" "$target"
staging=
trap - 0 HUP INT TERM
