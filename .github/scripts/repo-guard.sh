#!/usr/bin/env bash
# Repository guard: fails if the checked content holds something that must
# never be published from this repository.
#
#   .github/scripts/repo-guard.sh               tracked files in the working tree
#   .github/scripts/repo-guard.sh --staged      staged content of the files being
#                                               committed (.githooks/pre-commit)
#   .github/scripts/repo-guard.sh --range REV...
#                                               every commit that `git rev-list REV...`
#                                               selects: the lines each one adds,
#                                               its file names and its message
#                                               (.githooks/pre-push)
#   .github/scripts/repo-guard.sh --ci-range    --range with the commits of the push
#                                               or pull request that started the
#                                               GitHub Actions run (CI only)
#   .github/scripts/repo-guard.sh --self-test   runs the guard on sample content
#
# What it reports:
#   - an IPv4 address that is not a documentation address (RFC 5737), not a
#     loopback address, not one of the ranges listed in allowed_by_rule
#     below, and not listed in .github/repo-guard-allow.txt;
#   - a letter that only Russian uses: the documentation is English and
#     Ukrainian only;
#   - a binary file: its content cannot be checked;
#   - with `git config hikf2b.denylist FILE`: any entry of that file. FILE
#     lives outside the repository and is never committed. Each non-empty
#     line that does not start with # is a fixed string (matched ignoring
#     ASCII case) or, after a "re:" prefix, an extended regex (grep -E).
#
# A report names the place and the matching token only, never the whole line,
# because this output may be public. A denylist hit names only the line of the
# denylist entry, not the private string.
#
# Needs git, grep, sed and awk. --ci-range also needs python3, to read the
# event file.
set -euo pipefail
export LC_ALL=C

usage() {
    sed -n '2,/^set -euo/ { /^set -euo/d; s/^# \{0,1\}//; p; }' "$0" >&2
    exit 2
}

fail() {
    echo "repo-guard: $*" >&2
    exit 2
}

script=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/$(basename "${BASH_SOURCE[0]}")

# The scanner. Reads unified diff output (`git diff -U0` or `git log -p -U0`)
# on stdin and checks every added line, every file name and every commit
# message line. Prints one report line per hit; writes each checked text and
# its place to CONTENT and PLACES (same line numbers) for the denylist.
read -r -d '' scanner <<'AWK' || true
function allowed_by_rule(tok, addr, p, n,    i) {
    # Documentation networks (RFC 5737): any address in them.
    if (p[1] "." p[2] "." p[3] == "192.0.2" || p[1] "." p[2] "." p[3] == "198.51.100" ||
        p[1] "." p[2] "." p[3] == "203.0.113")
        return n == "" || n + 0 >= 24
    # Loopback: names no device.
    if (p[1] == "127")
        return n == "" || n + 0 >= 8
    # Ranges as the docs and the code describe them, written exactly so.
    return tok in ranges
}
function report(place, what, tok) {
    printf "%s: %s: %s\n", place, what, tok
    hits++
}
function check(place, text,    s, tok, addr, cut, p, i, ok, n) {
    sub(/\r$/, "", text)
    checked++
    if (want_content) {
        print text > content
        print place > places
    }
    s = text
    while (match(s, /[0-9]+(\.[0-9]+)+(\/[0-9]+)?/)) {
        tok = substr(s, RSTART, RLENGTH)
        s = substr(s, RSTART + RLENGTH)
        cut = index(tok, "/")
        if (cut) { addr = substr(tok, 1, cut - 1); n = substr(tok, cut + 1) }
        else { addr = tok; n = "" }
        # Exactly four parts of 1 to 3 digits, each at most 255. Version
        # numbers (1.100.0, 4.72.109), longer dotted runs and invalid values
        # are not addresses.
        if (split(addr, p, ".") != 4) continue
        ok = 1
        for (i = 1; i <= 4; i++)
            if (length(p[i]) > 3 || p[i] + 0 > 255) ok = 0
        if (n != "" && (length(n) > 2 || n + 0 > 32)) n = 99
        if (!ok) continue
        if (tok in allow || addr in allow) continue
        if (allowed_by_rule(tok, addr, p, n)) continue
        report(place, "IPv4 address not in .github/repo-guard-allow.txt", tok)
    }
    s = text
    while (match(s, /\321\212|\321\213|\321\215|\321\221|\320\201|\320\252|\320\253|\320\255/)) {
        report(place, "letter that only Russian uses", substr(s, RSTART, RLENGTH))
        s = substr(s, RSTART + RLENGTH)
    }
}
function strip_path(s) {
    sub(/\t$/, "", s)
    if (s ~ /^".*"$/) s = substr(s, 2, length(s) - 2)
    sub(/^b\//, "", s)
    return s
}
BEGIN {
    split("0.0.0.0 0.0.0.0/0 0.0.0.0/8 10.0.0.0 10.0.0.0/8 100.64.0.0 100.64.0.0/10 " \
          "169.254.0.0 169.254.0.0/16 172.16.0.0 172.16.0.0/12 192.168.0.0 192.168.0.0/16 " \
          "224.0.0.0 224.0.0.0/4 240.0.0.0 240.0.0.0/4 255.255.255.255 255.255.255.255/32", r, " ")
    for (i in r) ranges[r[i]] = 1
    while ((getline line < allowfile) > 0) {
        sub(/\r$/, "", line); sub(/#.*/, "", line)
        gsub(/^[ \t]+|[ \t]+$/, "", line)
        if (line != "") allow[line] = 1
    }
    state = "between"; commit = ""; file = ""
}
# Between files and commits.
state != "hunk" && /^commit [0-9a-f]+$/ {
    commit = substr($2, 1, 10); msgline = 0; state = "message"; next
}
state == "message" && /^    / {
    msgline++
    check(commit ": commit message, line " msgline, substr($0, 5)); next
}
state == "message" && /^$/ { next }
state != "hunk" && /^diff --git / { state = "header"; file = ""; next }
state == "header" && /^\+\+\+ / {
    file = strip_path(substr($0, 5))
    if (file != "/dev/null")
        check((commit != "" ? commit ":" : "") file ": file name", file)
    next
}
state == "header" && /^Binary files / {
    f = $0
    sub(/^Binary files .* and /, "", f); sub(/ differ$/, "", f)
    f = strip_path(f)
    if (f != "/dev/null" && !(("binary:" f) in allow))
        report((commit != "" ? commit ":" : "") f, "binary file, its content cannot be checked", "(binary)")
    next
}
state != "hunk" && /^@@ / {
    # @@ -a[,b] +c[,d] @@
    h = $0
    sub(/^@@ -/, "", h); sub(/ @@.*$/, "", h)
    split(h, ab, " ")
    nold = (index(ab[1], ",") ? substr(ab[1], index(ab[1], ",") + 1) : 1) + 0
    newstart = substr(ab[2], 2); nnew = 1
    if (index(newstart, ",")) { nnew = substr(newstart, index(newstart, ",") + 1) + 0; newstart = substr(newstart, 1, index(newstart, ",") - 1) }
    lineno = newstart + 0
    state = (nold + nnew > 0) ? "hunk" : "header"
    next
}
state == "hunk" {
    c = substr($0, 1, 1)
    if (c == "+") { check((commit != "" ? commit ":" : "") file ":" lineno, substr($0, 2)); lineno++; nnew-- }
    else if (c == "-") nold--
    else if (c == " ") { lineno++; nnew--; nold-- }
    if (nnew <= 0 && nold <= 0) state = "header"
    next
}
END {
    printf "%d %d\n", hits + 0, checked + 0 > countfile
}
AWK

# Checks the diff on stdin; returns 1 if anything was reported.
scan() {
    local tmp=$1 allowfile=.github/repo-guard-allow.txt
    [ -f "$allowfile" ] || allowfile=/dev/null
    : > "$tmp/content"
    : > "$tmp/places"
    awk -v allowfile="$allowfile" -v content="$tmp/content" -v places="$tmp/places" \
        -v want_content="$want_content" -v countfile="$tmp/count" "$scanner"
    local hits checked
    read -r hits checked < "$tmp/count"

    if [ "$want_content" = 1 ]; then
        local n=0 entry pattern found
        while IFS= read -r entry || [ -n "$entry" ]; do
            n=$((n + 1))
            entry=${entry%$'\r'}
            entry=$(printf '%s' "$entry" | sed 's/^[[:space:]]*//; s/[[:space:]]*$//')
            case "$entry" in ''|'#'*) continue ;; esac
            if [ "${entry#re:}" != "$entry" ]; then
                pattern=${entry#re:}
                set +e
                found=$(grep -n -E -e "$pattern" "$tmp/content" 2>/dev/null)
                rc=$?
                set -e
                [ "$rc" -le 1 ] || { echo "repo-guard: denylist line $n: invalid regex" >&2; hits=$((hits + 1)); continue; }
            else
                # ASCII case folded by tr: grep -F -i is unreliable on some builds.
                [ -f "$tmp/content.lower" ] || tr 'A-Z' 'a-z' < "$tmp/content" > "$tmp/content.lower"
                found=$(grep -n -F -e "$(printf '%s' "$entry" | tr 'A-Z' 'a-z')" "$tmp/content.lower" || true)
            fi
            [ -n "$found" ] || continue
            while IFS=: read -r line _; do
                printf '%s: matches denylist entry on line %d\n' "$(sed -n "${line}p" "$tmp/places")" "$n"
                hits=$((hits + 1))
            done <<<"$found"
        done < "$denylist"
    fi

    if [ "$hits" -gt 0 ]; then
        echo "repo-guard: $hits problem(s) in $checked checked line(s)" >&2
        return 1
    fi
    echo "repo-guard: ok, $checked line(s) checked"
}

git_quiet() {
    # Settings that would change the diff format are overridden.
    git -c core.quotePath=false -c diff.noprefix=false -c diff.mnemonicPrefix=false \
        -c color.ui=false -c diff.external= -c log.showSignature=false "$@"
}

diff_opts=(--no-color --no-ext-diff --no-textconv --no-renames --no-relative -U0 --src-prefix=a/ --dst-prefix=b/)

run_guard() {
    local mode=$1
    shift
    cd "$(git rev-parse --show-toplevel)"

    denylist=$(git config --type=path --get hikf2b.denylist || true)
    want_content=0
    if [ -n "$denylist" ]; then
        if command -v cygpath >/dev/null 2>&1; then
            denylist=$(cygpath -u "$denylist")
        fi
        [ -r "$denylist" ] && [ -f "$denylist" ] \
            || fail "the file named by git config hikf2b.denylist cannot be read"
        want_content=1
        echo "repo-guard: denylist: $(grep -cv -e '^[[:space:]]*#' -e '^[[:space:]]*$' "$denylist" || true) entr(ies)"
    else
        echo "repo-guard: denylist: not configured (git config hikf2b.denylist), skipped"
    fi

    local tmp
    tmp=$(mktemp -d)
    # shellcheck disable=SC2064
    trap "rm -rf '$tmp'" EXIT
    local empty_tree
    empty_tree=$(git hash-object -t tree /dev/null)

    case "$mode" in
        tree)
            echo "repo-guard: checking the tracked files in the working tree"
            git_quiet diff "${diff_opts[@]}" "$empty_tree" | scan "$tmp"
            ;;
        staged)
            local files=()
            while IFS= read -r -d '' f; do files+=("$f"); done \
                < <(git -c core.quotePath=false diff --cached --name-only -z --diff-filter=d)
            if [ "${#files[@]}" -eq 0 ]; then
                echo "repo-guard: nothing staged"
                return 0
            fi
            echo "repo-guard: checking the staged content of ${#files[@]} file(s)"
            git_quiet --literal-pathspecs diff --cached "${diff_opts[@]}" "$empty_tree" -- "${files[@]}" \
                | scan "$tmp"
            ;;
        range)
            [ "$#" -gt 0 ] || fail "--range needs revisions, for example A..B"
            local count
            count=$(git rev-list --count "$@" --)
            echo "repo-guard: checking $count commit(s)"
            [ "$count" -gt 0 ] || return 0
            git_quiet log "${diff_opts[@]}" -p --root --diff-merges=first-parent \
                --format='commit %H%n%w(0,4,4)%B' "$@" -- | scan "$tmp"
            ;;
    esac
}

# The commits of the push or pull request that started this GitHub Actions
# run, from the variables the runner sets. Needs the full history
# (actions/checkout with fetch-depth: 0).
ci_range() {
    local zero='^0+$' sha='^[0-9a-f]{40}$' before base
    event() {
        python3 -c 'import json, os, sys
e = json.load(open(os.environ["GITHUB_EVENT_PATH"], encoding="utf-8"))
for k in sys.argv[1].split("."):
    e = e.get(k) if isinstance(e, dict) else None
print(e if isinstance(e, str) else "")' "$1"
    }
    case "${GITHUB_EVENT_NAME:-}" in
        push)
            before=$(event before)
            if [[ "$before" =~ $sha ]] && [[ ! "$before" =~ $zero ]] \
                && git cat-file -e "$before^{commit}" 2>/dev/null; then
                run_guard range "$before..$GITHUB_SHA"
            else
                # A new branch or tag, or a force push whose old commit is
                # gone: every commit that no other branch has.
                local others=()
                while IFS= read -r ref; do
                    [ "$ref" = "refs/remotes/origin/HEAD" ] && continue
                    [ "${GITHUB_REF_TYPE:-}" = branch ] && [ "$ref" = "refs/remotes/origin/${GITHUB_REF_NAME:-}" ] && continue
                    others+=("$ref")
                done < <(git for-each-ref --format='%(refname)' refs/remotes/origin)
                echo "repo-guard: new ref or rewritten history; checking the commits no other branch has"
                run_guard range "$GITHUB_SHA" --not "${others[@]}"
            fi
            ;;
        pull_request)
            base=$(event pull_request.base.sha)
            [[ "$base" =~ $sha ]] || fail "the event has no pull_request.base.sha"
            git cat-file -e "$base^{commit}" 2>/dev/null \
                || fail "the base commit is not in the checkout; use fetch-depth: 0"
            run_guard range "$base..$GITHUB_SHA"
            ;;
        *)
            echo "repo-guard: event '${GITHUB_EVENT_NAME:-none}' pushes no commits; the tree check covers it"
            ;;
    esac
}

# Sample content with known hits and non-hits. Every address written here is
# a documentation address; the public one is put together at run time, so
# that this file holds none.
self_test() {
    local t
    t=$(mktemp -d)
    # shellcheck disable=SC2064
    trap "rm -rf '$t'" EXIT
    # No global or system git config, so the private denylist is never read
    # and no hooks or signing settings of the developer apply.
    export GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null HOME="$t" XDG_CONFIG_HOME="$t"
    # A path with spaces and non-ASCII letters, as on some developer machines.
    local repo
    repo="$t/repo with space $(printf 'r\321\226\320\272')"
    mkdir -p "$repo/.github/scripts" "$repo/docs"
    cd "$repo"
    git init -q .
    git config user.name "Self Test"
    git config user.email "self-test@example.invalid"
    git config core.autocrlf false
    git config commit.gpgsign false

    local public private ru_y ru_yo uk_i uk_yi uk_ye uk_g fi
    public="198.51.$((100 + 1)).7"
    private="10.$((10 + 10)).0.0/16"
    ru_y=$(printf '\321\213')   # Russian-only lower-case letter
    ru_yo=$(printf '\320\201')  # Russian-only capital letter
    uk_i=$(printf '\321\226')
    uk_yi=$(printf '\321\227')
    uk_ye=$(printf '\321\224')
    uk_g=$(printf '\322\221')
    fi=$(printf '\321\204')

    # Commit 1: clean.
    printf '%s\n' "192.0.2.200   # allowed on purpose" > .github/repo-guard-allow.txt
    printf '%s\n' "documentation 192.0.2.1" > docs/clean.txt
    git add -A
    git commit -q -m "clean start"
    local first
    first=$(git rev-parse HEAD)

    # Commit 2: hits and non-hits.
    {
        echo "public $public SENTINEL-NOT-PRINTED"
        echo "documentation 203.0.113.5 and 198.51.100.0/24 and 192.0.2.1:8000"
        echo "device nvr-example-07 at 192.0.2.77:8000"
        echo "versions V4.72.109, 255.4-1ubuntu8.18, 1.100.0, 1.2.3.4.5, 2026.11.20.1, 999.1.1.1"
        echo "ranges 10.0.0.0/8 127.0.0.1 0.0.0.0 255.255.255.255 192.0.2.200"
        echo "private range $private"
        echo "sentence end 203.0.113.9."
    } > docs/sample.txt
    printf 'Ц%s речення з л%sтерою, %s %s %s.\n' "$uk_i" "$uk_i" "$uk_yi" "$uk_ye" "$uk_g" > docs/uk-ok.txt
    printf 'Ц%s речення м%sстить л%sтеру %s, а це %s.\n' "$uk_i" "$uk_i" "$uk_i" "$ru_y" "$ru_yo" > docs/uk-bad.txt
    printf '\000\001\002' > docs/blob.bin
    git add -A
    git commit -q -m "samples"

    local deny="$t/deny list.txt" out failures=0
    printf '%s\n' "# throwaway denylist" "" "192.0.2.77" "re:nvr-[a-z]+-[0-9]{2}" "NOT-IN-CONTENT" > "$deny"

    expect() { # expect yes|no TEXT WHAT
        if grep -Fq -e "$2" <<<"$out"; then
            [ "$1" = yes ] || { echo "self-test FAILED: reported: $3"; failures=$((failures + 1)); }
        else
            [ "$1" = no ] || { echo "self-test FAILED: not reported: $3"; failures=$((failures + 1)); }
        fi
    }
    local ip_hit="IPv4 address not in .github/repo-guard-allow.txt"

    # 1. The tree, without a denylist.
    out=$(bash "$script" 2>&1 || true)
    expect yes "docs/sample.txt:1: $ip_hit: $public" "public address"
    expect no "SENTINEL" "the rest of a line with a hit"
    expect no "docs/sample.txt:2:" "documentation addresses"
    expect no "docs/sample.txt:3:" "device line without a denylist"
    expect no "docs/sample.txt:4:" "version numbers"
    expect no "docs/sample.txt:5:" "ranges, loopback, allowlisted address"
    expect yes "docs/sample.txt:6: $ip_hit: $private" "private network other than the RFC 1918 blocks"
    expect no "docs/sample.txt:7:" "documentation address at a sentence end"
    expect yes "docs/uk-bad.txt:1: letter that only Russian uses: $ru_y" "Russian-only lower-case letter"
    expect yes "docs/uk-bad.txt:1: letter that only Russian uses: $ru_yo" "Russian-only capital letter"
    expect no "docs/uk-ok.txt" "Ukrainian letters"
    expect yes "docs/blob.bin: binary file" "binary file"
    expect yes "denylist: not configured" "the skipped denylist"

    # 2. The tree, with the throwaway denylist.
    git config hikf2b.denylist "$deny"
    out=$(bash "$script" 2>&1 || true)
    expect yes "docs/sample.txt:3: matches denylist entry on line 3" "device address on the denylist"
    expect yes "docs/sample.txt:3: matches denylist entry on line 4" "denylist regex"
    expect no "nvr-example-07" "the private string itself"
    expect no "entry on line 5" "an entry that does not occur"

    # 3. A secret committed and removed again: the tree is clean, the commits
    #    are not. The commit message and file names are checked too.
    git rm -q docs/blob.bin docs/uk-bad.txt
    printf '%s\n' "documentation 203.0.113.5" > docs/sample.txt
    git commit -q -am "clean up"
    local base
    base=$(git rev-parse HEAD)
    printf '%s\n' "a b c" "router at 192.0.2.77" > "docs/new ${fi}ile.txt"
    printf '%s\n' "empty" > "docs/nvr-example-99.txt"
    git add -A
    git commit -q -m "add files" -m "seen on $public"
    git rm -q "docs/new ${fi}ile.txt" "docs/nvr-example-99.txt"
    git commit -q -m "remove them again"
    out=$(bash "$script" 2>&1 || true)
    expect yes "repo-guard: ok" "clean tree after the removal"
    out=$(bash "$script" --range "$base..HEAD" 2>&1 || true)
    expect yes "docs/new ${fi}ile.txt:2: matches denylist entry on line 3" "a secret removed in a later commit"
    expect yes "docs/nvr-example-99.txt: file name: matches denylist entry on line 4" "file name"
    expect yes ": commit message, line 3: $ip_hit: $public" "commit message"
    expect no "docs/sample.txt" "lines outside the range"

    # 4. Staged content: only the files being committed.
    printf '%s\n' "x" "camera nvr-example-12" > docs/staged.txt
    git add docs/staged.txt
    printf '%s\n' "not staged $public" >> docs/sample.txt
    out=$(bash "$script" --staged 2>&1 || true)
    expect yes "docs/staged.txt:2: matches denylist entry on line 4" "staged file"
    expect no "docs/sample.txt" "a change that is not staged"

    # 5. The hooks of this repository, run by git in the sample repository.
    local hooks
    hooks=$(cd "$(dirname "$script")/../.." && pwd)/.githooks
    if [ -f "$hooks/pre-commit" ] && [ -f "$hooks/pre-push" ]; then
        cp "$script" .github/scripts/repo-guard.sh   # untracked, as the hooks find it
        git config core.hooksPath "$hooks"
        if git commit -q -m "refused" >/dev/null 2>&1; then
            echo "self-test FAILED: pre-commit let a denylisted string through"; failures=$((failures + 1))
        fi
        git reset -q
        git checkout -q -- docs/sample.txt
        rm docs/staged.txt
        printf '%s\n' "documentation 198.51.100.9" > docs/clean2.txt
        git add docs/clean2.txt
        git commit -q -m "clean change" >/dev/null 2>&1 \
            || { echo "self-test FAILED: pre-commit refused clean content"; failures=$((failures + 1)); }
        git init -q --bare "$t/remote.git"
        git remote add origin "$t/remote.git"
        git push -q origin "$first:refs/heads/main" >/dev/null 2>&1 \
            || { echo "self-test FAILED: pre-push refused a clean commit"; failures=$((failures + 1)); }
        if git push -q origin HEAD:refs/heads/main >/dev/null 2>&1; then
            echo "self-test FAILED: pre-push let a removed secret through"; failures=$((failures + 1))
        fi
        git config --unset core.hooksPath
    else
        echo "self-test FAILED: .githooks/pre-commit or .githooks/pre-push is missing"
        failures=$((failures + 1))
    fi

    if [ "$failures" -gt 0 ]; then
        echo "repo-guard self-test: $failures failure(s)" >&2
        return 1
    fi
    echo "repo-guard self-test: ok"
}

case "${1:-}" in
    "") run_guard tree ;;
    --staged) [ "$#" -eq 1 ] || usage; run_guard staged ;;
    --range) shift; run_guard range "$@" ;;
    --ci-range) [ "$#" -eq 1 ] || usage; ci_range ;;
    --self-test) [ "$#" -eq 1 ] || usage; self_test ;;
    *) usage ;;
esac
