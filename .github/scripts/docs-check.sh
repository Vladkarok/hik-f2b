#!/usr/bin/env bash
# Checks the documentation: README.md and README.uk.md in step, internal
# links, terms from GLOSSARY.md, the length of sentences in numbered steps
# and the lines of hik-f2b.example.ini that other files depend on. See
# docs-check.py for the rules and their exception lists.
#
#   .github/scripts/docs-check.sh
#
# Needs Python 3 (standard library only).
set -euo pipefail

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
for python in python3 python; do
    # On Windows, "python3" may be a stub that only opens the app store.
    if "$python" -c 'import sys; sys.exit(sys.version_info < (3, 8))' >/dev/null 2>&1; then
        exec "$python" "$here/docs-check.py" "$@"
    fi
done
echo "docs-check: Python 3.8 or newer is needed" >&2
exit 2
