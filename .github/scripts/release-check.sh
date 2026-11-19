#!/usr/bin/env bash
# Checks that a release tag matches the repository contents, and prints the
# values the release workflow needs as key=value lines on stdout.
#
#   .github/scripts/release-check.sh TAG IMAGE
#   e.g. .github/scripts/release-check.sh v0.3.0 ghcr.io/vladkarok/hik-f2b
#
# Run from the repository root. Needs the git tags to be present (for the
# "is this the newest release" decision). Can be run locally before tagging.
set -euo pipefail

fail() {
    echo "::error::$*" >&2
    exit 1
}

[ "$#" -eq 2 ] || fail "usage: release-check.sh TAG IMAGE"
tag=$1
image=$2

# Strict tag format: vX.Y.Z or vX.Y.Z-rc.N, no leading zeros.
num='(0|[1-9][0-9]*)'
if [[ ! "$tag" =~ ^v${num}\.${num}\.${num}(-rc\.([1-9][0-9]*))?$ ]]; then
    fail "tag '$tag' is not vX.Y.Z or vX.Y.Z-rc.N"
fi
major=${BASH_REMATCH[1]}
minor=${BASH_REMATCH[2]}
patch=${BASH_REMATCH[3]}
version="$major.$minor.$patch"
if [ -n "${BASH_REMATCH[4]}" ]; then
    prerelease=true
    image_version="$version-rc.${BASH_REMATCH[5]}"
else
    prerelease=false
    image_version="$version"
fi

if [[ ! "$image" =~ ^ghcr\.io/[a-z0-9][a-z0-9._-]*/[a-z0-9][a-z0-9._-]*$ ]]; then
    fail "image name '$image' is not ghcr.io/owner/name in lower case"
fi

# The version in [package] of Cargo.toml.
cargo_version=$(sed -n '/^\[package\]/,/^\[/ s/^version *= *"\([^"]*\)".*/\1/p' Cargo.toml)
if [ "$cargo_version" != "$version" ]; then
    fail "tag $tag needs version = \"$version\" in Cargo.toml, found \"$cargo_version\""
fi

# Used for the image description; it goes into labels and annotations, so
# keep it to plain characters.
description=$(sed -n '/^\[package\]/,/^\[/ s/^description *= *"\([^"]*\)".*/\1/p' Cargo.toml)
if [[ ! "$description" =~ ^[A-Za-z0-9\ ._-]+$ ]]; then
    fail "description in [package] of Cargo.toml is missing or has characters other than letters, digits, space and . _ -"
fi

# A CHANGELOG.md section "## [X.Y.Z]" with some text in it. The date after
# the heading is not checked.
notes=$(bash .github/scripts/changelog-notes.sh "$version")
if ! grep -q '[^[:space:]]' <<<"$notes"; then
    fail "CHANGELOG.md has no section '## [$version]', or the section is empty"
fi
if [ "$prerelease" = false ] && ! grep -Eq "^## \[${version//./\\.}\] - [0-9]{4}-[0-9]{2}-[0-9]{2}" CHANGELOG.md; then
    echo "::warning::the CHANGELOG.md heading for $version has no release date" >&2
fi

# Final releases only: the install files and docs must use this version, and
# no other one. Pre-releases are tried before the docs are switched over.
if [ "$prerelease" = false ]; then
    repo_image=${image#ghcr.io/}
    for file in deploy/hik-f2b.container deploy/compose.yaml deploy/hik-f2b.service README.md README.uk.md; do
        [ -f "$file" ] || fail "$file is missing"
        if ! grep -Fq "ghcr.io/$repo_image:$version" "$file"; then
            fail "$file does not reference ghcr.io/$repo_image:$version"
        fi
        stale=$(grep -Eo "ghcr\.io/[A-Za-z0-9._-]+/hik-f2b:[A-Za-z0-9._-]+" "$file" \
            | grep -Fvx "ghcr.io/$repo_image:$version" || true)
        if [ -n "$stale" ]; then
            fail "$file references another image tag: $(echo "$stale" | sort -u | tr '\n' ' ')"
        fi
    done
fi

# Moving tags. "X.Y" moves only if this is the newest final release in the
# X.Y line, "latest" only if it is the newest final release overall, so a
# fix for an older line does not move them backwards.
tags="$image_version"
latest=false
if [ "$prerelease" = false ]; then
    finals=$( { git tag --list 'v*' 2>/dev/null | grep -E "^v${num}\.${num}\.${num}$" || true; echo "$tag"; } | sed 's/^v//' | sort -u -V)
    newest_line=$(grep -E "^$major\.$minor\." <<<"$finals" | tail -n 1)
    newest=$(tail -n 1 <<<"$finals")
    if [ "$newest_line" = "$version" ]; then
        tags="$tags $major.$minor"
    else
        echo "::warning::$version is older than $newest_line; not moving tag $major.$minor" >&2
    fi
    if [ "$newest" = "$version" ]; then
        tags="$tags latest"
        latest=true
    else
        echo "::warning::$version is older than $newest; not moving tag latest" >&2
    fi
fi

echo "tag=$tag"
echo "version=$version"
echo "image_version=$image_version"
echo "prerelease=$prerelease"
echo "image=$image"
echo "tags=$tags"
echo "latest=$latest"
echo "description=$description"
