#!/usr/bin/env bash
# Starts hik-f2b with deploy/compose.yaml the way its header describes, on
# the runner's Docker Compose, and checks that it runs. Two passes: the file
# as it is, then with the commented-out Telegram secret enabled. Only the
# image is replaced, by the one built in this CI run.
#
#   .github/scripts/deploy-compose-check.sh IMAGE
#
# Run from the repository root on a throwaway runner: it changes the
# routing table (see fast_unreachable).
set -euo pipefail

[ "$#" -eq 1 ] || { echo "usage: deploy-compose-check.sh IMAGE" >&2; exit 1; }
image=$1
# shellcheck source=deploy-lib.sh
. .github/scripts/deploy-lib.sh

docker compose version
version=$(docker run --rm "$image" --version)
version=${version#hik-f2b }
fast_unreachable

work=$(mktemp -d)
cp deploy/compose.yaml "$work/compose.yaml"
printf 'services:\n  hik-f2b:\n    image: %s\n' "$image" > "$work/ci-image.yaml"
make_config "$work/hik-f2b.ini" /run/secrets/hik-f2b- off
make_ca "$work/router-ca.crt"
make_secrets "$work/secrets"
cd "$work"

compose() {
    docker compose -f compose.yaml -f ci-image.yaml "$@"
}

# The permissions from the header of compose.yaml.
chmod 644 hik-f2b.ini router-ca.crt
sudo chown 65532 secrets/*
sudo chmod 400 secrets/*

container() {
    compose ps --all --quiet hik-f2b
}

state_volume() {
    docker inspect --format \
        '{{range .Mounts}}{{if eq .Destination "/var/lib/hik-f2b"}}{{.Name}}{{end}}{{end}}' \
        "$(container)"
}

logs() {
    compose logs --no-color --no-log-prefix hik-f2b > log.txt
    grep -Fq "$1" log.txt
}

state_is() {
    [ "$(sudo cat "$1")" = "$2" ]
}

# check_running TELEGRAM: assertions on the running container.
check_running() {
    local telegram=$1 id info
    wait_for 60 logs "WARNING nvr1: poll failed:" || fail "no poll within 60 s"
    # Long enough for a crash loop to show up as a restart.
    sleep 5
    id=$(container)
    info=$(docker inspect --format \
        '{{.State.Status}} {{.RestartCount}} {{.Config.User}} {{.HostConfig.ReadonlyRootfs}}' "$id")
    echo "container: $info"
    [ "$info" = "running 0 65532:65532 true" ] \
        || fail "expected 'running 0 65532:65532 true' (status, restarts, user, read-only root)"
    check_process "$(docker inspect --format '{{.State.Pid}}' "$id")" 65532
    compose logs --no-color --no-log-prefix hik-f2b > log.txt
    cat log.txt
    check_log log.txt "$version" "$telegram"
}

# check_stop: hik-f2b stops cleanly on SIGTERM.
check_stop() {
    compose stop
    compose logs --no-color --no-log-prefix hik-f2b > log.txt
    tail -n 1 log.txt | grep -q " INFO stopped$" \
        || fail "the last log line is not 'stopped'"
    [ "$(docker inspect --format '{{.State.ExitCode}}' "$(container)")" = 0 ] \
        || fail "hik-f2b exited with a non-zero code"
}

echo "=== pass 1: compose.yaml as it is"
compose up -d
check_running off
volume=$(state_volume)
mountpoint=$(docker volume inspect --format '{{.Mountpoint}}' "$volume")
owner=$(sudo stat -c '%u:%g' "$mountpoint")
echo "state volume $volume: owner $owner"
[ "$owner" = 65532:65532 ] || fail "the state volume belongs to $owner, not 65532:65532"
check_stop
compose down

echo "=== pass 2: with the Telegram secret enabled"
replace_line compose.yaml "      # - hik-f2b-telegram" "      - hik-f2b-telegram"
replace_line compose.yaml "  # hik-f2b-telegram:" "  hik-f2b-telegram:"
replace_line compose.yaml "  #   file: ./secrets/telegram" "    file: ./secrets/telegram"
make_config hik-f2b.ini /run/secrets/hik-f2b- on
chmod 644 hik-f2b.ini
# The volume is kept from pass 1. A state file that the first poll changes
# shows that hik-f2b can write to it.
printf '%s\n' "$STATE_SEED" > seed
sudo install -o 65532 -g 65532 -m 600 seed "$mountpoint/state"
compose up -d
check_running on
wait_for 30 state_is "$mountpoint/state" "$STATE_EMPTY" \
    || fail "hik-f2b did not write the state file"
echo "state file: $(sudo stat -c '%u:%g %a' "$mountpoint/state"), rewritten by hik-f2b"
check_stop
compose down --volumes
echo "ok: compose.yaml starts hik-f2b, with and without the Telegram secret"
