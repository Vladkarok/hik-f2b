#!/usr/bin/env bash
# Prints the body of the "## [VERSION]" section of CHANGELOG.md: everything
# after that heading up to the next "## " heading or the link definitions at
# the end. Prints nothing if there is no such section.
#
#   .github/scripts/changelog-notes.sh 0.3.0
set -euo pipefail

[ "$#" -eq 1 ] || { echo "usage: changelog-notes.sh VERSION" >&2; exit 1; }

awk -v want="## [$1]" '
    index($0, "## ") == 1 {
        if (found) exit
        # "## [X.Y.Z]" alone or followed by " - date".
        if ($0 == want || index($0, want " ") == 1) { found = 1; next }
    }
    found && /^\[[^]]+\]: / { exit }
    found { print }
' CHANGELOG.md
