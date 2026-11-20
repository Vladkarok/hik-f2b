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
other version. Before you tag, run the same check locally:

```bash
bash .github/scripts/release-check.sh vX.Y.Z ghcr.io/vladkarok/hik-f2b
```

## Checklist

1. Update the version:
   1. Set `version` in `Cargo.toml` to `X.Y.Z`.
   2. Run `cargo build`. `Cargo.lock` then has the new version too.
   3. Commit both files.
2. Update `CHANGELOG.md`:
   1. Turn the changes into a `## [X.Y.Z] - YYYY-MM-DD` section with the
      release date.
   2. Add the compare link of this section at the bottom.
3. Change the image tag to `X.Y.Z` in these files:
   - `deploy/hik-f2b.container`
   - `deploy/compose.yaml`
   - `deploy/hik-f2b.service`
   - `README.md`
   - `README.uk.md`

   To find the places, search for `ghcr.io/vladkarok/hik-f2b:`. Keep the two
   READMEs in step.
4. Push to `main`. Then wait for CI to pass.
5. Tag a release candidate and push the tag with this command:
   `git tag -a vX.Y.Z-rc.1 -m "hik-f2b X.Y.Z-rc.1" && git push origin vX.Y.Z-rc.1`.
6. Try `ghcr.io/vladkarok/hik-f2b:X.Y.Z-rc.1` on real hardware:
   1. Pull the image.
   2. Run `--check` with the production config.
   3. If the change touches banning, run it as the service with
      `dry_run = true` first.
   4. Run it as the service for a while.
   5. If needed, fix the problem. Then tag `-rc.2`.
7. If anything changed, update "Tested hardware" / "Not yet tried" in both
   READMEs with what was tried.
8. Tag the release from the same commit as the last rc, or from a later commit
   with only doc changes. Use this command:
   `git tag -a vX.Y.Z -m "hik-f2b X.Y.Z" && git push origin vX.Y.Z`.
9. Check these:
   - the GitHub Release;
   - the package page;
   - that the image can be pulled without logging in.

   The first image, pushed from the public repository, was public at once. If
   a package is ever private, change it in the package's settings on GitHub →
   "Change visibility".

If a tag failed the checks:

1. Delete the tag (`git push origin :vX.Y.Z-rc.1`).
2. Fix the problem.
3. Push the tag again.

Do not move a final tag once its image is published. Make the next patch
release instead.
