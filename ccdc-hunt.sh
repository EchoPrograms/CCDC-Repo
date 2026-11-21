#!/bin/sh
# Compatibility entry point; deploy hunter-hunt.sh alongside this launcher.
script_dir=$(CDPATH= cd -P "$(dirname "$0")" && pwd) || exit 1
exec /bin/sh "$script_dir/hunter-hunt.sh" "$@"
