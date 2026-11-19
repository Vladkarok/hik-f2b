# Works with both `podman build` and `docker build -f Containerfile`.
FROM docker.io/library/rust:1-alpine AS build
RUN apk add --no-cache musl-dev gcc
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY tests ./tests
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
