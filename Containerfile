# Works with both `podman build` and `docker build -f Containerfile`.
# The base image is pinned by digest, so that the Rust toolchain changes
# only when the pin does; the tag stays for the reader. Dependabot (docker
# ecosystem) proposes a new digest when the tag moves. The Alpine packages
# below are not pinned.
FROM docker.io/library/rust:1-alpine@sha256:8d0e82abfdf9a38071e07cabc5afba4ddbe077631a80e4e742a760c38beadc33 AS build
RUN apk add --no-cache musl-dev gcc
WORKDIR /src
# Only what `cargo build` needs: a change to the tests or the docs does not
# invalidate the build cache.
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --release --locked \
 && mkdir -p /out/var/lib/hik-f2b \
 && cp target/release/hik-f2b /out/hik-f2b

# The final image holds one static binary and an empty state directory:
# no shell, no package manager, no libraries.
FROM scratch
COPY --from=build /out/hik-f2b /hik-f2b
COPY --from=build --chown=65532:65532 /out/var/lib/hik-f2b /var/lib/hik-f2b
USER 65532:65532
VOLUME ["/var/lib/hik-f2b"]
ENTRYPOINT ["/hik-f2b"]
