# Releasing hik-f2b

Releases are made by pushing a tag. [release.yml](.github/workflows/release.yml)
then checks the repository, runs CI, builds the image natively for
`linux/amd64` and `linux/arm64`, pushes it to `ghcr.io/vladkarok/hik-f2b` and
creates the GitHub Release with the changelog section as its notes.

| Tag | Image tags | GitHub Release |
| --- | --- | --- |
| `vX.Y.Z-rc.N` | `X.Y.Z-rc.N` | pre-release |
| `vX.Y.Z` | `X.Y.Z`, `X.Y`, `latest` | release |

`X.Y` and `latest` move only if the tag is the newest final release in its
line or overall. Each build also leaves a per-architecture tag
(`X.Y.Z-amd64`, `X.Y.Z-arm64`) from which the multi-arch image is joined.

The workflow refuses a tag unless `version` in `Cargo.toml` is `X.Y.Z` and
`CHANGELOG.md` has a `## [X.Y.Z]` section; for a final tag the deploy files
and both READMEs must also reference `ghcr.io/vladkarok/hik-f2b:X.Y.Z` and no
other version. Run the same check locally before tagging:

```bash
bash .github/scripts/release-check.sh vX.Y.Z ghcr.io/vladkarok/hik-f2b
```

## Checklist

1. Bump `version` in `Cargo.toml`, then run `cargo build` so `Cargo.lock`
   follows. Commit both.
2. In `CHANGELOG.md`, turn the changes into a `## [X.Y.Z] - YYYY-MM-DD`
   section with the release date, and add its compare link at the bottom.
3. Change the image tag to `X.Y.Z` in `deploy/hik-f2b.container`,
   `deploy/compose.yaml`, `deploy/hik-f2b.service`, `README.md` and
   `README.uk.md` (search for `ghcr.io/vladkarok/hik-f2b:`). Keep the two
   READMEs in step.
4. Push to `main` and wait for CI to pass.
5. Tag a release candidate and push the tag:
   `git tag -a vX.Y.Z-rc.1 -m "hik-f2b X.Y.Z-rc.1" && git push origin vX.Y.Z-rc.1`.
6. Try `ghcr.io/vladkarok/hik-f2b:X.Y.Z-rc.1` on real hardware: pull it, run
   `--check` with the production config, then run it as the service for a
   while (with `dry_run = true` first if the change touches banning). Fix and
   tag `-rc.2` if needed.
7. Update "Tested hardware" / "Not yet tried" in both READMEs with what was
   tried, if anything changed.
8. Tag the release from the same commit as the last rc (or a later one with
   only doc changes): `git tag -a vX.Y.Z -m "hik-f2b X.Y.Z" && git push origin vX.Y.Z`.
9. Check the GitHub Release and the package page. After the very first
   release, make the package public once: the package's settings on GitHub →
   "Change visibility" → Public. A package pushed for the first time is
   private, whatever the repository's visibility.

A tag that failed the checks can be deleted (`git push origin :vX.Y.Z-rc.1`),
fixed and pushed again. Do not move a final tag once its image is published;
make the next patch release instead.
