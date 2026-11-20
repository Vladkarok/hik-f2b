#!/usr/bin/env bash
# Installs the binary from IMAGE with deploy/hik-f2b.service the way the
# unit's header describes, starts it with systemctl and checks that it runs
# in its sandbox. Two passes: the unit as it is, then with the commented-out
# Telegram credential enabled.
#
#   .github/scripts/deploy-systemd-check.sh IMAGE
#
# Run from the repository root on a throwaway runner: it installs into
# /usr/local/bin, /etc and /etc/systemd/system and changes the routing table.
set -euo pipefail

[ "$#" -eq 1 ] || { echo "usage: deploy-systemd-check.sh IMAGE" >&2; exit 1; }
image=$1
# shellcheck source=deploy-lib.sh
. .github/scripts/deploy-lib.sh

systemctl --version | head -n 1
version=$(docker run --rm "$image" --version)
version=${version#hik-f2b }
fast_unreachable

work=$(mktemp -d)
credentials=/run/credentials/hik-f2b.service/
make_config "$work/hik-f2b.ini" "$credentials" off
make_ca "$work/router-ca.crt"
make_secrets "$work/secrets"
cp deploy/hik-f2b.service "$work/hik-f2b.service"

# The commands from the header of hik-f2b.service, with docker in place of
# podman.
docker create --name hik-f2b-copy "$image" > /dev/null
docker cp hik-f2b-copy:/hik-f2b "$work/hik-f2b"
docker rm hik-f2b-copy > /dev/null
cd "$work"
sudo install -m 755 hik-f2b /usr/local/bin/hik-f2b
sudo install -D -m 644 hik-f2b.ini /etc/hik-f2b/hik-f2b.ini
sudo install -D -m 644 router-ca.crt /etc/hik-f2b/router-ca.crt
sudo install -D -m 600 secrets/router /etc/hik-f2b/secrets/router
sudo install -D -m 600 secrets/nvr /etc/hik-f2b/secrets/nvr
sudo install -m 644 hik-f2b.service /etc/systemd/system/hik-f2b.service
sudo systemctl daemon-reload

cursor=
journal() {
    sudo journalctl --no-pager --output cat --unit hik-f2b --after-cursor "$cursor" > log.txt
}

logs() {
    journal
    grep -Fq "$1" log.txt
}

state_is() {
    [ "$(sudo cat /var/lib/private/hik-f2b/state)" = "$1" ]
}

# start TELEGRAM: verifies the unit, starts it and checks it.
start() {
    local telegram=$1 pid
    sudo systemd-analyze verify /etc/systemd/system/hik-f2b.service
    cursor=$(sudo journalctl --lines 0 --show-cursor | sed -n 's/^-- cursor: //p')
    sudo systemctl start hik-f2b
    wait_for 60 logs "WARNING nvr1: poll failed:" || { journal; cat log.txt; fail "no poll within 60 s"; }
    # Long enough for a crash loop to show up as a restart.
    sleep 5
    [ "$(systemctl is-active hik-f2b)" = active ] || fail "hik-f2b.service is not active"
    [ "$(systemctl show --property NRestarts --value hik-f2b)" = 0 ] \
        || fail "hik-f2b.service has restarted"
    pid=$(systemctl show --property MainPID --value hik-f2b)
    check_process "$pid" hik-f2b
    sudo grep -Eq '^Seccomp:\s+2$' "/proc/$pid/status" || fail "no system call filter"
    echo "credentials:"
    sudo ls -l "$credentials"
    journal
    cat log.txt
    check_log log.txt "$version" "$telegram"
    sudo systemd-analyze security --no-pager hik-f2b | tail -n 1
}

# stop: hik-f2b stops cleanly on SIGTERM.
stop() {
    sudo systemctl stop hik-f2b
    journal
    grep -q " INFO stopped$" log.txt || fail "no 'stopped' line"
    [ "$(systemctl show --property Result --value hik-f2b)" = success ] \
        || fail "hik-f2b.service did not stop cleanly"
}

echo "=== pass 1: hik-f2b.service as it is"
start off
stop

echo "=== pass 2: with the Telegram credential enabled"
replace_line hik-f2b.service "#LoadCredential=telegram:/etc/hik-f2b/secrets/telegram" \
    "LoadCredential=telegram:/etc/hik-f2b/secrets/telegram"
make_config hik-f2b.ini "$credentials" on
sudo install -D -m 600 secrets/telegram /etc/hik-f2b/secrets/telegram
sudo install -D -m 644 hik-f2b.ini /etc/hik-f2b/hik-f2b.ini
sudo install -m 644 hik-f2b.service /etc/systemd/system/hik-f2b.service
sudo systemctl daemon-reload
# StateDirectory= is /var/lib/private/hik-f2b with DynamicUser=. A state
# file that the first poll changes shows that hik-f2b can write to it.
owner=$(sudo stat -c '%u:%g' /var/lib/private/hik-f2b)
printf '%s\n' "$STATE_SEED" > seed
sudo install -o "${owner%:*}" -g "${owner#*:}" -m 600 seed /var/lib/private/hik-f2b/state
start on
wait_for 30 state_is "$STATE_EMPTY" || fail "hik-f2b did not write the state file"
echo "state file: $(sudo stat -c '%U %a' /var/lib/private/hik-f2b/state), rewritten by hik-f2b"
stop
echo "ok: hik-f2b.service starts hik-f2b, with and without the Telegram credential"
