#!/usr/bin/env bash
# Runs every check that CI runs on a push, cheapest first, and prints a
# summary: the repository guard on the tracked files and its self-test, the
# documentation check, cargo fmt --check, cargo clippy and cargo test.
#
#   .github/scripts/check-all.sh                stop at the first failed step
#   .github/scripts/check-all.sh --keep-going   run every step, report all
#
# Works from any directory of the repository, in Git Bash on Windows and on
# Linux. Calls the existing scripts; the commands are the ones in
# .github/workflows/ci.yml. Not run by the hooks: they must stay fast.
#
# Needs git, Python 3.8 or newer (the documentation check) and a Rust
# toolchain with clippy and rustfmt. If cargo is not on PATH, it is taken
# from $CARGO_HOME/bin or ~/.cargo/bin. If neither python3 nor python works
# and the Windows launcher `py -3` does, the documentation check uses it.
#
# The checks of CI that this does not run: the guard on every pushed commit
# (the pre-push hook does that), the arm64 tests, cargo audit and the image
# checks.
set -euo pipefail

usage() {
    sed -n '2,/^set -euo/ { /^set -euo/d; s/^# \{0,1\}//; p; }' "$0" >&2
    exit 2
}

keep_going=false
case "${1-}" in
    "") ;;
    -k | --keep-going) keep_going=true ;;
    -h | --help) usage ;;
    *) echo "check-all: unknown argument '$1'" >&2; usage ;;
esac
[ "$#" -le 1 ] || usage

scripts=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
root=$(cd "$scripts/../.." && pwd)
cd "$root"

# cargo: on PATH, or where rustup puts it for the current user.
cargo_missing=
if ! command -v cargo >/dev/null 2>&1; then
    candidates=()
    [ -n "${CARGO_HOME-}" ] && candidates+=("$CARGO_HOME/bin")
    [ -n "${HOME-}" ] && candidates+=("$HOME/.cargo/bin")
    if [ -n "${USERPROFILE-}" ] && command -v cygpath >/dev/null 2>&1; then
        candidates+=("$(cygpath -u "$USERPROFILE")/.cargo/bin")
    fi
    for dir in ${candidates[@]+"${candidates[@]}"}; do
        if [ -x "$dir/cargo" ] || [ -x "$dir/cargo.exe" ]; then
            PATH="$dir:$PATH"
            echo "check-all: cargo is not on PATH; using $dir"
            break
        fi
    done
    if ! command -v cargo >/dev/null 2>&1; then
        cargo_missing="cargo is not on PATH, in \$CARGO_HOME/bin or in ~/.cargo/bin: install Rust with rustup (https://rustup.rs)"
    fi
fi

# Python for docs-check.sh, which tries python3 and python itself. Only the
# Windows launcher is added here, as a python3 on PATH that calls it.
python_ok() {
    "$1" -c 'import sys; sys.exit(sys.version_info < (3, 8))' >/dev/null 2>&1
}
python_missing=
if ! python_ok python3 && ! python_ok python; then
    if command -v py >/dev/null 2>&1 && py -3 -c 'import sys; sys.exit(sys.version_info < (3, 8))' >/dev/null 2>&1; then
        shim=$(mktemp -d)
        trap 'rm -rf "$shim"' EXIT
        printf '#!/usr/bin/env bash\nexec py -3 "$@"\n' >"$shim/python3"
        chmod +x "$shim/python3"
        PATH="$shim:$PATH"
        echo "check-all: neither python3 nor python is Python 3.8 or newer; using py -3"
    else
        python_missing="Python 3.8 or newer is needed: neither python3, python nor py -3 runs it"
    fi
fi

names=()
results=()
times=()
failed=0
stopped=false
started=$SECONDS
total=6
step_no=0

# step NAME MISSING COMMAND...: MISSING is empty, or why the step cannot run.
step() {
    local name=$1 missing=$2 begin status
    shift 2
    step_no=$((step_no + 1))
    names+=("$name")
    if [ "$stopped" = true ]; then
        results+=("skip")
        times+=("")
        return 0
    fi
    echo
    echo "==> [$step_no/$total] $name"
    begin=$SECONDS
    if [ -n "$missing" ]; then
        echo "check-all: $missing" >&2
        status=1
    elif "$@"; then
        status=0
    else
        status=$?
    fi
    times+=("$((SECONDS - begin))s")
    if [ "$status" -eq 0 ]; then
        results+=("ok")
    else
        results+=("FAIL")
        failed=$((failed + 1))
        echo "check-all: '$name' failed (exit $status)" >&2
        [ "$keep_going" = true ] || stopped=true
    fi
}

step "repository guard, tracked files" "" bash "$scripts/repo-guard.sh"
step "repository guard, self-test" "" bash "$scripts/repo-guard.sh" --self-test
step "documentation check" "$python_missing" bash "$scripts/docs-check.sh"
step "cargo fmt --check" "$cargo_missing" cargo fmt --check
step "cargo clippy" "$cargo_missing" cargo clippy --locked --all-targets -- -D warnings
step "cargo test" "$cargo_missing" cargo test --locked

elapsed=$((SECONDS - started))
echo
echo "check-all: summary"
for i in "${!names[@]}"; do
    case "${results[$i]}" in
        skip) printf '  %-5s %s (not run: stopped after the first failed step)\n' skip "${names[$i]}" ;;
        *) printf '  %-5s %s (%s)\n' "${results[$i]}" "${names[$i]}" "${times[$i]}" ;;
    esac
done
duration="$((elapsed / 60))m $((elapsed % 60))s"
if [ "$failed" -eq 0 ]; then
    echo "check-all: all $total steps passed in $duration"
    exit 0
fi
echo "check-all: $failed of $total steps failed, $duration" >&2
if [ "$keep_going" = false ]; then
    echo "check-all: run with --keep-going to run the remaining steps too" >&2
fi
exit 1
