# Shared by the deploy checks (deploy-compose-check.sh,
# deploy-systemd-check.sh). Sourced, not run.
#
# The checks start hik-f2b from the files in deploy/ with a throwaway config
# made from hik-f2b.example.ini. The router and the NVR are RFC 5737
# addresses that nothing answers; the secrets are dummy values.

EXAMPLE=$PWD/hik-f2b.example.ini

fail() {
    echo "::error::$*" >&2
    exit 1
}

# Makes connections to the RFC 5737 test networks fail at once ("no route to
# host") instead of after the 10-second connect timeout, so the first poll
# ends within seconds. Changes only the runner's routing table.
fast_unreachable() {
    local net
    for net in 192.0.2.0/24 198.51.100.0/24 203.0.113.0/24; do
        sudo ip route replace unreachable "$net"
    done
}

# replace_line FILE OLD NEW: replaces the line that is exactly OLD.
replace_line() {
    local file=$1 old=$2 new=$3
    grep -Fxq -- "$old" "$file" || fail "$file has no line '$old'"
    OLD=$old NEW=$new awk '$0 == ENVIRON["OLD"] { print ENVIRON["NEW"]; next } { print }' \
        "$file" > "$file.new"
    mv "$file.new" "$file"
}

# make_config OUT PREFIX TELEGRAM
#   Writes hik-f2b.example.ini to OUT with RFC 5737 addresses, with the
#   secret paths /run/secrets/hik-f2b-<name> changed to PREFIX<name>, and,
#   if TELEGRAM is "on", with the [telegram] section enabled.
make_config() {
    local out=$1 prefix=$2 telegram=$3
    cp "$EXAMPLE" "$out"
    replace_line "$out" "url           = https://192.168.88.1" "url           = https://192.0.2.1"
    replace_line "$out" "url           = http://192.168.88.10" "url           = http://192.0.2.10"
    replace_line "$out" "password_file = /run/secrets/hik-f2b-router" "password_file = ${prefix}router"
    replace_line "$out" "password_file = /run/secrets/hik-f2b-nvr" "password_file = ${prefix}nvr"
    if [ "$telegram" = on ]; then
        replace_line "$out" ";[telegram]" "[telegram]"
        replace_line "$out" ";bot_token_file    = /run/secrets/hik-f2b-telegram" \
            "bot_token_file    = ${prefix}telegram"
        replace_line "$out" ";chat_id           = -1001234567890" "chat_id           = -1001234567890"
    fi
}

# make_secrets DIR: dummy secret files router, nvr and telegram in DIR.
make_secrets() {
    local dir=$1
    mkdir -p "$dir"
    printf '%s\n' 'ci-router-password' > "$dir/router"
    printf '%s\n' 'ci-nvr-password' > "$dir/nvr"
    printf '%s\n' '123456789:ci-dummy-token' > "$dir/telegram"
}

# make_ca OUT: a throwaway self-signed CA certificate (the key is discarded).
make_ca() {
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
        -keyout /dev/null -subj "/CN=hik-f2b CI test CA" -days 2 -out "$1" 2> /dev/null
}

# A state file with one failed login from 1970. The first poll forgets it
# (it is older than findtime), so hik-f2b writes the state file again.
STATE_SEED='hik-f2b-state 2
fail 198.51.100.7 1000'
STATE_EMPTY='hik-f2b-state 2'

# check_log FILE VERSION TELEGRAM: the startup lines are there and nothing
# could not be read.
check_log() {
    local log=$1 version=$2 telegram=$3
    # The startup line comes after the config, every secret file and the CA
    # file have been read; hik-f2b exits before it if one cannot be read.
    grep -Fq "INFO hik-f2b $version started: 1 NVR(s), maxretry=5 findtime=3600s bantime=86400s telegram=$telegram" "$log" \
        || fail "no startup line with telegram=$telegram"
    grep -Fq "INFO mode: ban on MikroTik, address-list cctv_ban" "$log" \
        || fail "no mode line"
    # The router and the NVR do not exist, so these fail; that they are
    # logged shows the startup check and the first poll ran.
    grep -Fq "ERROR firewall check failed:" "$log" || fail "no firewall check line"
    grep -Fq "WARNING nvr1: poll failed:" "$log" || fail "no poll line"
    if grep -Ei "cannot read|permission denied|cannot save state|bad CA|no certificates|does not look like" "$log"; then
        fail "hik-f2b could not read or write a file"
    fi
}

# wait_for SECONDS COMMAND...: runs COMMAND every second until it succeeds.
wait_for() {
    local seconds=$1
    shift
    local i
    for ((i = 0; i < seconds; i++)); do
        if "$@" > /dev/null 2>&1; then
            return 0
        fi
        sleep 1
    done
    "$@"
}

# check_process PID USER: the process runs as USER (a name or uid, not
# root), with no capabilities and no_new_privs.
check_process() {
    local pid=$1 user=$2 status uid
    status=$(sudo cat "/proc/$pid/status")
    uid=$(awk '/^Uid:/ { print $2 }' <<< "$status")
    [ "$uid" != 0 ] || fail "hik-f2b runs as root"
    if [ "$(ps -o user= -p "$pid" | tr -d ' ')" != "$user" ] \
        && [ "$uid" != "$user" ]; then
        fail "hik-f2b runs as uid $uid, expected $user"
    fi
    grep -Eq '^CapEff:\s+0+$' <<< "$status" || fail "hik-f2b has capabilities: $(grep CapEff <<< "$status")"
    grep -Eq '^CapBnd:\s+0+$' <<< "$status" || fail "hik-f2b has a capability bounding set: $(grep CapBnd <<< "$status")"
    grep -Eq '^NoNewPrivs:\s+1$' <<< "$status" || fail "no_new_privs is not set"
    # The root filesystem as the process sees it.
    local root_opts
    root_opts=$(sudo awk '$5 == "/" { print $6 }' "/proc/$pid/mountinfo" | tail -n 1)
    case ",$root_opts," in
        *,ro,*) ;;
        *) fail "the root filesystem is writable for hik-f2b ($root_opts)" ;;
    esac
    echo "pid $pid: uid $uid, $(grep -E '^(CapEff|NoNewPrivs|Seccomp):' <<< "$status" | tr -s '\t' ' ' | tr '\n' ' ')root $root_opts"
}
