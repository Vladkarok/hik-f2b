#!/usr/bin/env bash
# Checks that the runner's Quadlet generator accepts deploy/hik-f2b.container
# (a dry run: nothing is started), as it is and with the commented-out
# Telegram secret enabled.
#
#   .github/scripts/deploy-quadlet-check.sh
#
# Run from the repository root on a throwaway runner: it writes to
# ~/.config/containers/systemd.
set -euo pipefail

# shellcheck source=deploy-lib.sh
. .github/scripts/deploy-lib.sh

podman --version
quadlet=/usr/libexec/podman/quadlet
[ -x "$quadlet" ] || fail "$quadlet is missing"

dir=$HOME/.config/containers/systemd
mkdir -p "$dir"

# generate: the service Quadlet makes from the unit in $dir.
generate() {
    local out
    out=$("$quadlet" -dryrun -user 2>&1) || { echo "$out"; fail "Quadlet rejected hik-f2b.container"; }
    echo "$out"
    if grep -Eiq "unsupported|converting|error" <<< "$out"; then
        fail "Quadlet complained about hik-f2b.container"
    fi
    grep -q '^ExecStart=.*podman run' <<< "$out" || fail "Quadlet made no podman run command"
    for want in "$@"; do
        grep '^ExecStart=' <<< "$out" | grep -Fq -- "$want" || fail "the podman run command has no '$want'"
    done
}

image=$(sed -n 's/^Image=//p' deploy/hik-f2b.container)
cp deploy/hik-f2b.container "$dir/hik-f2b.container"
echo "=== hik-f2b.container as it is"
generate "$image" --read-only --network host \
    "--secret hik-f2b-router,uid=65532,mode=0400" "--secret hik-f2b-nvr,uid=65532,mode=0400"

echo "=== with the Telegram secret enabled"
replace_line "$dir/hik-f2b.container" "#Secret=hik-f2b-telegram,uid=65532,mode=0400" \
    "Secret=hik-f2b-telegram,uid=65532,mode=0400"
generate "--secret hik-f2b-telegram,uid=65532,mode=0400"
rm "$dir/hik-f2b.container"
echo "ok: Quadlet accepts hik-f2b.container"
