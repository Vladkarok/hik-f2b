#!/usr/bin/env bash
# A long run of the simulation test (tests/sim.rs) in release mode, as the
# scheduled workflow .github/workflows/sim.yml runs it.
#
#   .github/scripts/sim-long.sh [SEEDS [START]]
#   .github/scripts/sim-long.sh --self-test
#
# SEEDS is the number of seeds per scenario class (default 1500, at most
# 4000); START is the first seed. The run covers the seeds START to
# START + 5 * SEEDS - 1: tests/sim.rs gives each of its 5 classes the seeds
# of its remainder mod 5, SEEDS of them, from START on.
#
# Without START, on GitHub Actions the start comes from the run number N:
# START = N * 100000 + 1. Run number N owns the seeds N * 100000 + 1 to
# (N + 1) * 100000, and a run uses at most 5 * 4000 = 20000 of them, so no
# two run numbers share a seed, whatever SEEDS each one had. A re-run of a
# run keeps its run number and repeats its seeds. A START given by hand may
# repeat seeds of other runs. Outside GitHub Actions the default START is 1
# (the seeds CI also runs).
#
# The environment variables SIM_SEEDS and SIM_START are used when the
# arguments are not given (the workflow passes its inputs so). SIM_TIME_LIMIT
# (minutes) stops the test in time to write the summary before the job's
# timeout. Each value must be a plain positive integer within its bound.
#
# Output: the engine's own log lines (hundreds per seed) are left out; the
# rest of the test's output is printed and kept in target/sim-long/sim.log
# (or $SIM_LOG_DIR/sim.log). Each violation is printed again at the end with
# its seed, class and replay command, and, on GitHub Actions, written to the
# job summary. Exits 1 on a violation or any other failed test.
#
# The release build keeps debug assertions (and overflow checks, which the
# release profile already has), so that a violation found here replays the
# same way with the debug build that the replay command uses.
#
# --self-test checks the input validation, the seed ranges and the parsing
# of the test output on sample output. It needs no Rust toolchain.
set -euo pipefail
export LC_ALL=C

CLASSES=5               # tests/sim.rs: CLASSES, `seed % 5` picks the class
DEFAULT_SEEDS=1500
MAX_SEEDS=4000
STRIDE=100000           # seeds that belong to one run number
MAX_START=1000000000000000
MAX_RUN_NUMBER=1000000000
MAX_TIME_LIMIT=350      # minutes; GitHub stops a job after 360
MAX_SHOWN=20            # violations listed at the end and in the summary

usage() {
    sed -n '2,/^set -euo/ { /^set -euo/d; s/^# \{0,1\}//; p; }' "$0" >&2
    exit 2
}

fail() {
    echo "sim-long: $*" >&2
    exit 2
}

# check_int NAME VALUE MAX: VALUE is a positive integer without leading
# zeros or signs, at most MAX. The length is checked before the arithmetic.
check_int() {
    local name=$1 value=$2 max=$3
    if [[ ! "$value" =~ ^[1-9][0-9]{0,15}$ ]] || [ "$value" -gt "$max" ]; then
        echo "sim-long: $name must be a whole number from 1 to $max, not '$value'" >&2
        return 1
    fi
}

# The first seed for run number RUN.
run_start() {
    echo $(($1 * STRIDE + 1))
}

# Reads the test output on stdin and writes it to stdout without the
# engine's log lines (`<time> INFO|WARNING|ERROR ...`). The test's own lines
# (`<time> SIM ...`), cargo's and libtest's lines and the failures section
# stay.
filter_log() {
    awk '
        $1 ~ /^[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9]Z$/ && $2 != "SIM" { left++; next }
        { print; fflush() }
        END { printf "sim-long: %d lines of the engine log left out\n", left }
    '
}

# The violations in LOG, one per line: violation, "seed N, class C: ..." and
# the replay command, separated by \037. They are taken from libtest's
# failures section (the panic message of each class), where a report is not
# interleaved with the other classes; there the lines have no time stamp.
violations() {
    awk '
        want { print v "\037" s "\037" ($0 ~ /^replay: / ? substr($0, 9) : ""); want = 0 }
        /^seed [0-9]+, class [A-Za-z]+: / { v = prev; s = $0; want = 1 }
        { prev = $0 }
    ' "$1"
}

# The first panic in LOG: its "thread ... panicked at" line and the message
# lines after it, up to a blank line, the next panic or a line of libtest
# (at most 8 lines).
first_panic() {
    awk '
        on && (/^$/ || / panicked at / || /^test / || /^---- / || ++lines > 8) { exit }
        on { print; next }
        / panicked at / { print; on = 1 }
    ' "$1"
}

# verdict STATUS LOG SUMMARY HEADER: writes the end of the console output to
# stdout and a Markdown summary to SUMMARY. Returns 0 if the run passed.
#
# A failure without a violation report (a panic outside the scenarios, a
# process killed for lack of memory, a time limit) is a failure of the test
# run itself, not a finding about the engine: the first line of the summary
# says so, and the first panic message follows.
verdict() {
    local status=$1 log=$2 summary=$3 header=$4
    local found n shown passed=true reason= panic
    found=$(violations "$log")
    n=0
    [ -n "$found" ] && n=$(grep -c '' <<<"$found")
    if [ "$n" -gt 0 ]; then
        passed=false
        reason="$n violation(s) found"
    elif [ "$status" -eq 124 ]; then
        passed=false
        reason="time limit reached (exit 124): the test was stopped"
    elif [ "$status" -eq 137 ]; then
        passed=false
        reason="the test was killed (exit 137, SIGKILL): by the time limit, or for lack of memory"
    elif grep -q 'signal: 9, SIGKILL' "$log"; then
        passed=false
        reason="the test process was killed (SIGKILL; exit $status), probably for lack of memory"
    elif [ "$status" -ne 0 ]; then
        passed=false
        reason="the test failed (exit $status) without a violation report"
    elif ! grep -q "^test result: ok\. $CLASSES passed;" "$log"; then
        passed=false
        reason="the test passed, but not with $CLASSES tests passed; see the log"
    fi
    panic=$(first_panic "$log")
    {
        if [ "$passed" = true ]; then
            echo "## Long simulation: passed"
        elif [ "$n" -gt 0 ]; then
            echo "## Long simulation: FAILED"
            echo
            echo "**$reason**"
        else
            echo "## Long simulation: FAILED: the test run itself failed, not a finding about the engine"
            echo
            echo "**$reason**"
            echo
            echo 'First panic message:'
            echo
            echo '~~~~text'
            echo "${panic:-(no panic in the log)}"
            echo '~~~~'
        fi
        echo
        echo "$header"
        echo
        echo '~~~~text'
        # A line may follow libtest's "test NAME ... " on the same line.
        sed -n 's/^.* SIM \(sim [A-Za-z]*: [0-9]* seed.*\)$/\1/p' "$log"
        grep -E '^test result: ' "$log" || true
        echo '~~~~'
    } >"$summary"
    echo
    if [ "$passed" = true ]; then
        echo "sim-long: passed"
        return 0
    fi
    if [ "$n" -eq 0 ]; then
        echo "sim-long: FAILED: the test run itself failed, not a finding about the engine: $reason"
        echo "sim-long: first panic message:"
        sed 's/^/sim-long:   /' <<<"${panic:-(no panic in the log)}"
    else
        echo "sim-long: FAILED: $reason"
    fi
    if [ "$n" -gt 0 ]; then
        shown=0
        while IFS=$'\037' read -r violation seed_line replay; do
            shown=$((shown + 1))
            [ "$shown" -le "$MAX_SHOWN" ] || break
            local where=${seed_line%%: *}
            echo "sim-long: $where: $violation"
            echo "sim-long:   replay: ${replay:-(no replay line)}"
            {
                echo
                echo "### ${where^}"
                echo
                echo '~~~~text'
                echo "$violation"
                echo "$seed_line"
                echo '~~~~'
                echo
                echo 'Replay (debug build, prints the trace):'
                echo
                echo '~~~~bash'
                echo "$replay"
                echo '~~~~'
            } >>"$summary"
        done <<<"$found"
        if [ "$n" -gt "$MAX_SHOWN" ]; then
            echo "sim-long: and $((n - MAX_SHOWN)) more in the failures section of the log"
            printf '\nAnd %d more in the failures section of the log.\n' "$((n - MAX_SHOWN))" >>"$summary"
        fi
    elif [ "$status" -ne 0 ]; then
        {
            echo
            echo 'Panic messages from the log:'
            echo
            echo '~~~~text'
            grep -A 6 ' panicked at ' "$log" | head -n 60 || true
            echo '~~~~'
        } >>"$summary"
    fi
    return 1
}

self_test() {
    local errors=0 v
    tmp=$(mktemp -d)   # global: the EXIT trap runs after the function returns
    trap 'rm -rf "$tmp"' EXIT
    check() {
        if ! eval "$2"; then
            echo "self-test: FAILED: $1" >&2
            errors=$((errors + 1))
        fi
    }

    # Input validation.
    for v in 1 30 4000; do
        check "seeds '$v' accepted" "check_int seeds '$v' $MAX_SEEDS 2>/dev/null"
    done
    for v in 0 -1 +5 01 4001 1e3 1.5 ' 5' '5 ' '' abc '$(id)' '1;id' 99999999999999999999; do
        check "seeds '$v' refused" "! check_int seeds '$v' $MAX_SEEDS 2>/dev/null"
    done
    check "start 10^15 accepted" "check_int start $MAX_START $MAX_START 2>/dev/null"
    check "start 10^15+1 refused" "! check_int start $((MAX_START + 1)) $MAX_START 2>/dev/null"

    # Seed ranges: one run number's seeds never reach the next one's.
    check "a run fits its run number's seeds" "[ $((CLASSES * MAX_SEEDS)) -le $STRIDE ]"
    local run
    for run in 1 2 41 $MAX_RUN_NUMBER; do
        local last=$(($(run_start "$run") + CLASSES * MAX_SEEDS - 1))
        check "run $run ends before run $((run + 1)) starts" "[ $last -lt $(run_start $((run + 1))) ]"
    done
    check "the largest start does not overflow" \
        "[ $((MAX_START + CLASSES * MAX_SEEDS)) -gt $MAX_START ] && [ $(run_start $MAX_RUN_NUMBER) -le $MAX_START ]"

    # Output parsing, on sample output in the format of tests/sim.rs
    # (Sim::report, run_class) and of libtest.
    local ts=2026-01-01T00:00:00Z
    cat >"$tmp/pass.out" <<EOF
     Running tests/sim.rs (target/release/deps/sim-0)

running 5 tests
$ts INFO nvr1: failed login from 192.0.2.7 (user="admin") at 2026-01-10T08:01:44Z [1/8]
$ts WARNING nvr1: cannot read the log
$ts ERROR router: unreachable
$ts SIM sim Firewall: 2 seed(s), 150 cycles, 0.5 s, 0 violation(s); bans 4
test sim_firewall ... ok
$ts SIM sim Backlog: 2 seed(s), 150 cycles, 0.5 s, 0 violation(s); bans 4
test sim_backlog ... ok
$ts SIM sim DryRun: 2 seed(s), 150 cycles, 0.5 s, 0 violation(s); bans 0
test sim_dry_run ... ok
$ts SIM sim NotifyOnly: 2 seed(s), 150 cycles, 0.5 s, 0 violation(s); bans 0
test sim_notify_only ... ok
$ts SIM sim Clock: 2 seed(s), 150 cycles, 0.5 s, 0 violation(s); bans 3
test sim_clock ... ok

test result: ok. 5 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 2.50s

EOF
    filter_log <"$tmp/pass.out" >"$tmp/pass.log"
    check "engine log lines left out" "! grep -q ' INFO \| WARNING \| ERROR ' '$tmp/pass.log'"
    check "the count of left-out lines" "grep -q '^sim-long: 3 lines of the engine log left out$' '$tmp/pass.log'"
    check "SIM lines kept" "[ \$(grep -c ' SIM sim ' '$tmp/pass.log') -eq 5 ]"
    check "a passing run passes" "verdict 0 '$tmp/pass.log' '$tmp/pass.md' header >/dev/null"
    check "its summary says passed" "grep -q '^## Long simulation: passed$' '$tmp/pass.md'"
    check "its summary has the class lines" "grep -q '^sim Clock: 2 seed' '$tmp/pass.md'"
    check "exit 0 with 4 tests passed fails" \
        "! verdict 0 <(sed 's/ok\. 5 passed/ok. 4 passed/' '$tmp/pass.log') '$tmp/x.md' header >/dev/null"
    check "a time limit fails" "! verdict 124 '$tmp/pass.log' '$tmp/x.md' header >/dev/null"
    check "it says so" "grep -q 'time limit reached' '$tmp/x.md'"
    check "a time limit is a failure of the run" \
        "head -n 1 '$tmp/x.md' | grep -q 'the test run itself failed, not a finding about the engine'"
    check "a kill fails" "! verdict 137 '$tmp/pass.log' '$tmp/x.md' header >/dev/null"
    check "it says so" "grep -q 'killed (exit 137' '$tmp/x.md' && head -n 1 '$tmp/x.md' | grep -q 'test run itself'"
    sed '$a\
process didn'"'"'t exit successfully: `sim` (signal: 9, SIGKILL: kill)' "$tmp/pass.log" >"$tmp/oom.log"
    check "a test process killed for memory fails" "! verdict 101 '$tmp/oom.log' '$tmp/x.md' header >/dev/null"
    check "it says so" "grep -q 'lack of memory' '$tmp/x.md' && head -n 1 '$tmp/x.md' | grep -q 'test run itself'"

    {
        sed -n '1,4p' "$tmp/pass.out"
        cat <<EOF
$ts SIM sim Clock: 2 seed(s), 150 cycles, 0.5 s, 1 violation(s); bans 3
$ts SIM [count/shift] nvr1: a failed login of 192.0.2.7 counted 3600 s from its true host time
$ts SIM seed 4, class Clock: maxretry 8, findtime 600
$ts SIM replay: HIK_F2B_SIM_SEED=4 cargo test --test sim -- --nocapture
$ts SIM trace (last 1 of 1 lines):
$ts SIM +0s poll
test sim_clock ... FAILED

failures:

---- sim_clock stdout ----

thread 'sim_clock' panicked at tests/sim.rs:1918:9:
sim Clock: 2 seed(s), 150 cycles, 0.5 s, 1 violation(s); bans 3

[count/shift] nvr1: a failed login of 192.0.2.7 counted 3600 s from its true host time
seed 4, class Clock: maxretry 8, findtime 600
replay: HIK_F2B_SIM_SEED=4 cargo test --test sim -- --nocapture
trace (last 1 of 1 lines):
+0s poll

[panic] index out of bounds
seed 9, class Clock: maxretry 3, findtime 60
replay: HIK_F2B_SIM_SEED=9 cargo test --test sim -- --nocapture
trace (last 0 of 0 lines):

note: run with \`RUST_BACKTRACE=1\` environment variable to display a backtrace


failures:
    sim_clock

test result: FAILED. 4 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out; finished in 2.50s

EOF
    } | filter_log >"$tmp/fail.log"
    check "two violations found" "[ \$(violations '$tmp/fail.log' | grep -c '') -eq 2 ]"
    check "the first one's fields" \
        "violations '$tmp/fail.log' | head -n 1 | grep -q \$'^\\\\[count/shift\\\\] nvr1: .*\\037seed 4, class Clock: maxretry 8, findtime 600\\037HIK_F2B_SIM_SEED=4 cargo test --test sim -- --nocapture\$'"
    check "a violation fails" "! verdict 101 '$tmp/fail.log' '$tmp/fail.md' header >'$tmp/fail.end'"
    check "a violation fails with exit 0 too" "! verdict 0 '$tmp/fail.log' '$tmp/x.md' header >/dev/null"
    check "the end of the log names seed and class" "grep -q '^sim-long: seed 4, class Clock: \\[count/shift\\]' '$tmp/fail.end'"
    check "the end of the log has the replay" \
        "grep -q '^sim-long:   replay: HIK_F2B_SIM_SEED=9 cargo test --test sim -- --nocapture$' '$tmp/fail.end'"
    check "the summary says FAILED" "grep -q '^## Long simulation: FAILED$' '$tmp/fail.md'"
    check "a violation is not a failure of the run" "! grep -q 'test run itself' '$tmp/fail.md' '$tmp/fail.end'"
    check "the summary has both seeds" "grep -q '^### Seed 4, class Clock$' '$tmp/fail.md' && grep -q '^### Seed 9, class Clock$' '$tmp/fail.md'"
    check "the summary has the replay" "grep -qx 'HIK_F2B_SIM_SEED=4 cargo test --test sim -- --nocapture' '$tmp/fail.md'"

    # A failed test without a violation report: its panic is shown.
    printf 'thread %s panicked at tests/support/fake.rs:689:43:\ncalled `Result::unwrap()` on an `Err` value\ntest result: FAILED. 0 passed; 5 failed\n' \
        "'sim_clock'" >"$tmp/panic.log"
    check "a panic without a report fails" "! verdict 101 '$tmp/panic.log' '$tmp/panic.md' header >/dev/null"
    check "its summary shows the panic" "grep -q 'called .Result::unwrap()' '$tmp/panic.md'"

    # A thread that the system refuses to start, outside the scenarios: the
    # classes fail without a violation report (as with 4000 seeds per class
    # before a dropped harness ended its fakes' threads).
    local spawn='failed to spawn thread: Os { code: 11, kind: WouldBlock, message: "Resource temporarily unavailable" }'
    {
        sed -n '1,3p' "$tmp/pass.out"
        cat <<EOF
thread '<unnamed>' panicked at library/std/src/thread/functions.rs:131:29:
$spawn
note: run with \`RUST_BACKTRACE=1\` environment variable to display a backtrace
$ts INFO nvr1: first run
test sim_firewall ... FAILED
test sim_backlog ... FAILED

failures:

---- sim_firewall stdout ----

thread 'sim_firewall' panicked at tests/support/fake.rs:575:5:
$spawn

failures:
    sim_backlog
    sim_firewall

test result: FAILED. 3 passed; 2 failed; 0 ignored; 0 measured; 0 filtered out; finished in 120.00s

EOF
    } | filter_log >"$tmp/spawn.log"
    check "a failed spawn fails" "! verdict 101 '$tmp/spawn.log' '$tmp/spawn.md' header >'$tmp/spawn.end'"
    check "it has no violation" "[ -z \"\$(violations '$tmp/spawn.log')\" ]"
    check "its first line: a failure of the run" \
        "head -n 1 '$tmp/spawn.md' | grep -qx '## Long simulation: FAILED: the test run itself failed, not a finding about the engine'"
    check "its reason" "grep -qx '\*\*the test failed (exit 101) without a violation report\*\*' '$tmp/spawn.md'"
    sed -n '/^First panic message:$/,/^~~~~$/p' "$tmp/spawn.md" | sed -n '4,$p' | sed '$d' >"$tmp/spawn.first"
    printf '%s\n%s\n%s\n' "thread '<unnamed>' panicked at library/std/src/thread/functions.rs:131:29:" \
        "$spawn" 'note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace' >"$tmp/spawn.want"
    check "the first panic message, in the summary" "cmp -s '$tmp/spawn.first' '$tmp/spawn.want'"
    check "the console says so too" \
        "grep -qx 'sim-long: FAILED: the test run itself failed, not a finding about the engine: the test failed (exit 101) without a violation report' '$tmp/spawn.end' && grep -qxF 'sim-long:   $spawn' '$tmp/spawn.end'"

    if [ "$errors" -gt 0 ]; then
        echo "self-test: $errors check(s) failed" >&2
        exit 1
    fi
    echo "sim-long self-test: ok"
}

case "${1-}" in
    --self-test)
        [ "$#" -eq 1 ] || usage
        self_test
        exit 0
        ;;
    -h | --help) usage ;;
    -*) echo "sim-long: unknown option '$1'" >&2; usage ;;
esac
[ "$#" -le 2 ] || usage

seeds=${1-${SIM_SEEDS-}}
start=${2-${SIM_START-}}
limit=${SIM_TIME_LIMIT-}
[ -n "$seeds" ] || seeds=$DEFAULT_SEEDS
check_int seeds "$seeds" "$MAX_SEEDS" || exit 2
if [ -n "$start" ]; then
    check_int start "$start" "$MAX_START" || exit 2
    start_from="given by hand; it may repeat seeds of other runs"
elif [ -n "${GITHUB_RUN_NUMBER-}" ]; then
    check_int GITHUB_RUN_NUMBER "$GITHUB_RUN_NUMBER" "$MAX_RUN_NUMBER" || exit 2
    start=$(run_start "$GITHUB_RUN_NUMBER")
    start_from="from run number $GITHUB_RUN_NUMBER, which owns the seeds $start to $(run_start $((GITHUB_RUN_NUMBER + 1)) | awk '{print $1 - 1}')"
else
    start=1
    start_from="the default outside GitHub Actions"
fi
if [ -n "$limit" ]; then
    check_int SIM_TIME_LIMIT "$limit" "$MAX_TIME_LIMIT" || exit 2
fi
(( CLASSES * MAX_SEEDS <= STRIDE )) || fail "MAX_SEEDS is too large for STRIDE"
last=$((start + CLASSES * seeds - 1))

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
cd "$root"
command -v cargo >/dev/null 2>&1 || fail "cargo is not on PATH: install Rust with rustup (https://rustup.rs)"
log_dir=${SIM_LOG_DIR:-$root/target/sim-long}
mkdir -p "$log_dir"
log=$log_dir/sim.log
summary=$log_dir/summary.md
commit=$(git rev-parse --short=12 HEAD 2>/dev/null || echo unknown)

header="Seeds $start to $last: $seeds per class, $CLASSES classes. Start: $start_from. Commit $commit."
echo "sim-long: seeds $start to $last ($seeds per class, $CLASSES classes)"
echo "sim-long: start $start_from"
echo "sim-long: commit $commit${limit:+, time limit for the test: $limit min}"

export HIK_F2B_SIM_SEEDS=$seeds
export HIK_F2B_SIM_START=$start
unset HIK_F2B_SIM_SEED
export CARGO_PROFILE_RELEASE_DEBUG_ASSERTIONS=true

echo
echo "==> build (release, with debug assertions)"
begin=$SECONDS
if ! cargo test --locked --release --test sim --no-run; then
    echo "sim-long: FAILED: the build failed; the compiler errors are above"
    if [ -n "${GITHUB_STEP_SUMMARY-}" ]; then
        printf '## Long simulation: FAILED\n\n**The build failed**; the compiler errors are in the log.\n\n%s\n' \
            "$header" >>"$GITHUB_STEP_SUMMARY"
    fi
    exit 1
fi
echo "sim-long: built in $((SECONDS - begin)) s"

echo
echo "==> cargo test --locked --release --test sim"
runner=()
[ -n "$limit" ] && runner=(timeout -k 60 "${limit}m")
begin=$SECONDS
set +e
${runner[@]+"${runner[@]}"} cargo test --locked --release --test sim 2>&1 | filter_log | tee "$log"
status=${PIPESTATUS[0]}
set -e
took=$((SECONDS - begin))
header="$header Test time $((took / 60))m $((took % 60))s."
echo "sim-long: test exit status $status after $((took / 60))m $((took % 60))s; log: $log"

result=0
verdict "$status" "$log" "$summary" "$header" || result=1
if [ -n "${GITHUB_STEP_SUMMARY-}" ]; then
    cat "$summary" >>"$GITHUB_STEP_SUMMARY"
fi
exit "$result"
