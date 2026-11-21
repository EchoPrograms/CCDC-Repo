#!/bin/sh
# Exercise the actual controller against deterministic Docker/SSH responses.
set -eu
REPO=$(CDPATH= cd "$(dirname "$0")/.." && pwd)
TMP=$(mktemp -d "${TMPDIR:-/tmp}/ccdc-ctl-test.XXXXXXXX")
trap 'rm -rf "$TMP"' 0
trap 'exit 1' 1 2 15
mkdir "$TMP/bin" "$TMP/lab"
cp "$REPO/lab/alpine/ctl" "$TMP/lab/ctl"
chmod +x "$TMP/lab/ctl"
cat > "$TMP/bin/docker" <<'DOCKER'
#!/bin/sh
set -eu
[ "$1" = compose ]; shift
[ "$1" = --project-directory ]; shift 2
[ "$1" = -f ]; shift 2
case $1 in
    port)
        [ "$2" = gateway ] || { printf 'Wrong service for port lookup\n' >&2; exit 8; }
        case $3 in
            2222) printf '%s\n' "$FAKE_SSH_ENDPOINT" ;;
            8080) printf '%s\n' '127.0.0.1:8088' ;;
            *) exit 9 ;;
        esac ;;
    up) exit 0 ;;
    *) exit 10 ;;
esac
DOCKER
cat > "$TMP/bin/ssh" <<'SSH'
#!/bin/sh
printf '%s\n' "$@" > "$SSH_ARGS"
SSH
chmod +x "$TMP/bin/docker" "$TMP/bin/ssh"
PATH="$TMP/bin:$PATH"
SSH_ARGS="$TMP/ssh-args"
export PATH SSH_ARGS
for endpoint in '127.0.0.1:0' '0.0.0.0:0' '' '127.0.0.1:notaport' '127.0.0.1:65536' '127.0.0.1:99999999999999999999' '0.0.0.0:2222'; do
    FAKE_SSH_ENDPOINT=$endpoint
    export FAKE_SSH_ENDPOINT
    if "$TMP/lab/ctl" ssh > "$TMP/output" 2> "$TMP/errors"; then
        printf 'FAIL: controller accepted invalid mapping "%s"\n' "$endpoint" >&2
        exit 1
    fi
    [ ! -e "$SSH_ARGS" ] || { printf 'FAIL: SSH was invoked with an invalid mapping\n' >&2; exit 1; }
    grep 'No valid localhost mapping' "$TMP/errors" > /dev/null
 done
printf 'PASS: zero/missing/malformed/out-of-range/non-local port mappings fail before SSH\n'
FAKE_SSH_ENDPOINT=127.0.0.1:42222
export FAKE_SSH_ENDPOINT
"$TMP/lab/ctl" ssh
awk 'previous=="-p" && $0=="42222" {found=1} {previous=$0} END {exit !found}' "$SSH_ARGS"
printf 'PASS: SSH connects using the gateway actual published port\n'
"$TMP/lab/ctl" up > "$TMP/up-output"
grep 'ssh -p 42222 defender@127.0.0.1' "$TMP/up-output" > /dev/null
grep 'http://127.0.0.1:8088/' "$TMP/up-output" > /dev/null
FAKE_SSH_ENDPOINT=127.0.0.1:0
export FAKE_SSH_ENDPOINT
if "$TMP/lab/ctl" up > "$TMP/bad-up-output" 2> "$TMP/bad-up-errors"; then
    printf 'FAIL: startup accepted an absent SSH publication\n' >&2; exit 1
fi
printf 'PASS: startup prints real ports and rejects an unpublished gateway\n'
