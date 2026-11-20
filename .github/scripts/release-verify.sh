#!/usr/bin/env bash
# Checks what a release actually published to the registry, rather than
# trusting the exit codes of the tools that pushed it. Reads the registry
# anonymously, as a user pulling the image does.
#
#   .github/scripts/release-verify.sh [--run] IMAGE IMAGE_VERSION REVISION [TAG...]
#   e.g. .github/scripts/release-verify.sh ghcr.io/vladkarok/hik-f2b 0.3.1 \
#            "$(git rev-parse 'v0.3.1^{commit}')" 0.3.1 0.3 latest
#
# Fails unless:
#   - IMAGE:IMAGE_VERSION is a multi-arch image with exactly linux/amd64 and
#     linux/arm64, each the image of its per-architecture tag
#     (IMAGE_VERSION-amd64, IMAGE_VERSION-arm64);
#   - every TAG (default: IMAGE_VERSION) points to that same image;
#   - each architecture's image has the labels release.yml sets, with title
#     hik-f2b, version IMAGE_VERSION, revision REVISION and licenses MIT; with
#     EXPECT_SOURCE, EXPECT_DESCRIPTION or EXPECT_CREATED set in the
#     environment, also that source, description or created;
#   - with --run: the image of this host's architecture, pulled by its
#     digest, prints "hik-f2b X.Y.Z" (IMAGE_VERSION without -rc.N). Needs
#     docker, and runs the image natively, never under emulation.
#
# A tag that moved on since (0.3, latest) fails the check: run it by hand
# with the tags that still point to the release.
#
# Needs bash, curl, perl (JSON::PP), sha256sum and, for --run, docker.
set -euo pipefail
export LC_ALL=C

fail() {
    echo "::error::release-verify: $*" >&2
    exit 1
}

run=false
if [ "${1:-}" = --run ]; then
    run=true
    shift
fi
[ "$#" -ge 3 ] || fail "usage: release-verify.sh [--run] IMAGE IMAGE_VERSION REVISION [TAG...]"
image=$1
image_version=$2
revision=$3
shift 3
tags=("$@")
[ "${#tags[@]}" -gt 0 ] || tags=("$image_version")

[[ "$image" =~ ^ghcr\.io/[a-z0-9][a-z0-9._-]*/[a-z0-9][a-z0-9._-]*$ ]] ||
    fail "image name '$image' is not ghcr.io/owner/name in lower case"
num='(0|[1-9][0-9]*)'
[[ "$image_version" =~ ^${num}\.${num}\.${num}(-rc\.[1-9][0-9]*)?$ ]] ||
    fail "'$image_version' is not X.Y.Z or X.Y.Z-rc.N"
version=${image_version%%-*}
[[ "$revision" =~ ^[0-9a-f]{40}$ ]] || fail "revision '$revision' is not a full commit hash"
for tag in "${tags[@]}"; do
    [[ "$tag" =~ ^[A-Za-z0-9_][A-Za-z0-9._-]{0,127}$ ]] || fail "'$tag' is not a tag"
done

repo=${image#ghcr.io/}
registry=https://ghcr.io/v2/$repo
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

# Prints what a perl expression makes of a JSON file ($j is the document).
json() {
    perl -MJSON::PP -0777 -ne '$j = JSON::PP->new->decode($_); '"$2" "$1"
}

curl_get() {
    curl --fail --silent --show-error --location --retry 3 --retry-delay 5 \
        --proto '=https' --max-time 60 "$@"
}

curl_get --output "$work/token" "https://ghcr.io/token?scope=repository:$repo:pull" ||
    fail "no anonymous pull token for $repo: is the package public?"
token=$(json "$work/token" 'print $j->{token} // ""')
[ -n "$token" ] || fail "the registry gave no token"
auth="Authorization: Bearer $token"

list_types='application/vnd.docker.distribution.manifest.list.v2+json,application/vnd.oci.image.index.v1+json'
image_types='application/vnd.docker.distribution.manifest.v2+json,application/vnd.oci.image.manifest.v1+json'

# Fetches the manifest REF (a tag or a digest) into FILE and prints its
# digest, computed from the bytes received.
manifest() {
    curl_get --header "$auth" --header "Accept: $3" --output "$2" "$registry/manifests/$1" ||
        fail "cannot read the manifest $image:$1"
    echo "sha256:$(sha256sum "$2" | cut -d' ' -f1)"
}

# The multi-arch image and the tags that must point to it.
index=$(manifest "$image_version" "$work/index" "$list_types")
kind=$(json "$work/index" 'print $j->{mediaType} // ""')
case "$kind" in
    application/vnd.docker.distribution.manifest.list.v2+json | application/vnd.oci.image.index.v1+json) ;;
    *) fail "$image:$image_version is not a multi-arch image (media type '$kind')" ;;
esac
echo "$image:$image_version: $kind $index"
for tag in "${tags[@]}"; do
    digest=$(manifest "$tag" "$work/tag" "$list_types")
    [ "$digest" = "$index" ] || fail "$image:$tag is $digest, not $index"
    echo "$image:$tag: $digest"
done

# Exactly the two platforms, once each.
json "$work/index" 'for (@{$j->{manifests}}) { my $p = $_->{platform} // {};
    printf "%s/%s%s %s\n", $p->{os} // "?", $p->{architecture} // "?",
        defined $p->{variant} ? "/$p->{variant}" : "", $_->{digest} }' |
    sort > "$work/platforms"
platforms=$(cut -d' ' -f1 "$work/platforms" | tr '\n' ' ')
[ "$platforms" = "linux/amd64 linux/arm64 " ] ||
    fail "$image:$image_version has the platforms '$platforms', expected exactly linux/amd64 and linux/arm64"

host_arch=
case "$(uname -m)" in
    x86_64 | amd64) host_arch=amd64 ;;
    aarch64 | arm64) host_arch=arm64 ;;
esac
run_digest=

# A label of the image config in $work/config.
label() {
    json "$work/config" 'my $l = $j->{config}{Labels} // {};
        print $l->{"org.opencontainers.image.'"$1"'"} // ""'
}

# Label NAME must be set, and be VALUE if VALUE is not empty.
expect() {
    local value
    value=$(label "$1")
    [ -n "$value" ] || fail "$platform: label org.opencontainers.image.$1 is missing"
    if [ -n "$2" ] && [ "$value" != "$2" ]; then
        fail "$platform: label org.opencontainers.image.$1 is '$value', expected '$2'"
    fi
    echo "$platform: org.opencontainers.image.$1=$value"
}

while read -r platform digest; do
    arch=${platform#linux/}
    # The image the per-architecture tag holds, which the build checked.
    built=$(manifest "$image_version-$arch" "$work/built" "$image_types")
    [ "$built" = "$digest" ] ||
        fail "$platform in $image:$image_version is $digest, but $image:$image_version-$arch is $built"
    got=$(manifest "$digest" "$work/manifest" "$image_types")
    [ "$got" = "$digest" ] || fail "$platform: the registry returned $got for $digest"
    config=$(json "$work/manifest" 'print $j->{config}{digest} // ""')
    [[ "$config" =~ ^sha256:[0-9a-f]{64}$ ]] || fail "$platform: no config in $digest"
    curl_get --header "$auth" --output "$work/config" "$registry/blobs/$config" ||
        fail "$platform: cannot read the config $config"
    [ "sha256:$(sha256sum "$work/config" | cut -d' ' -f1)" = "$config" ] ||
        fail "$platform: the config does not match its digest $config"
    found=$(json "$work/config" 'print(($j->{os} // "?") . "/" . ($j->{architecture} // "?"))')
    [ "$found" = "$platform" ] || fail "$platform: the image itself is for $found"
    expect title hik-f2b
    expect version "$image_version"
    expect revision "$revision"
    expect licenses MIT
    expect source "${EXPECT_SOURCE:-}"
    expect description "${EXPECT_DESCRIPTION:-}"
    expect created "${EXPECT_CREATED:-}"
    if [ "$arch" = "$host_arch" ]; then
        run_digest=$digest
    fi
done < "$work/platforms"

if [ "$run" = true ]; then
    [ -n "$run_digest" ] || fail "--run: this host ($(uname -m)) is neither amd64 nor arm64"
    command -v docker >/dev/null || fail "--run needs docker"
    ref="$image@$run_digest"
    docker pull --quiet "$ref" >/dev/null || fail "cannot pull $ref"
    pulled=$(docker image inspect --format '{{.Os}}/{{.Architecture}}' "$ref")
    [ "$pulled" = "linux/$host_arch" ] || fail "$ref is $pulled, expected linux/$host_arch"
    printed=$(docker run --rm --network none "$ref" --version) || fail "$ref does not run"
    [ "$printed" = "hik-f2b $version" ] ||
        fail "$ref prints '$printed', expected 'hik-f2b $version'"
    echo "linux/$host_arch: $ref prints '$printed'"
fi
echo "release-verify: $image:$image_version is as expected"
