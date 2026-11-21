# Changelog

All notable changes to hik-f2b are listed here, newest first. The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and version
numbers follow [Semantic Versioning](https://semver.org/). Each version is
published as the container image `ghcr.io/vladkarok/hik-f2b:<version>`
(from 0.3.0 on); see "Versions and updates" in the [README](README.md).

## [Unreleased]

## [0.3.3] - YYYY-MM-DD

### Fixed

- `bantime` accepted timed bans of up to 365 days, but RouterOS accepts an
  address-list timeout of at most 35w3d13h13m56s (21474836 seconds, about
  248 days) and refuses a longer one. Such a config passed `--check` and
  `--test-ban` (which always bans for 60 seconds), and then every real ban
  failed. A longer `bantime` is now a config error that names the limit and
  points to `bantime = permanent`. The limit is the same in notify-only
  mode.
- A URL such as `http://[::1]evil.example` counted as a local address, so
  plain http was allowed for it. A URL is now accepted only as
  `scheme://host` with an optional port from 1 to 65535 and nothing after
  it.
- `--hours` above 8760 said that it must be a positive number; it now names
  the range 1 to 8760.

### Changed

- A setting that hik-f2b does not know is now an error that names the line,
  the section and, when a known setting is close, the setting probably
  meant. Before, it was ignored without a word: a typo such as `ignore_ip`
  or `dryrun` left an address unprotected by `ignoreip` or turned a dry run
  into live bans. A setting given twice in one section is an error too
  (before, the second line replaced the first, so of two `ignoreip` lines
  only the last one applied), and so is an empty `state_file` (before, every
  save of the state failed). **A config with a stray or repeated setting
  that used to start no longer starts:** run `--check` with the new version
  before you update, and remove or correct the line it names.

- `--dump` exits non-zero when an NVR cannot be read, and prints that
  error to stderr instead of stdout.
- Options that cannot work together are an error instead of being ignored:
  more than one of `--check`, `--dump`, `--test-ban`, `--test-notify` and
  `--country`; `--hours` or `--raw` without `--dump`; `--once` or
  `--dry-run` with one of those five. `--help` says so and describes the
  exit status.
- The startup warning about secrets that other users can read now also
  looks at the files named by `password_file` and `bot_token_file`, and
  counts a file that its group can read, not only one that every user can
  read.

<!-- second group -->

## [0.3.2] - 2026-11-20

### Fixed

- After some corrections of an NVR's clock, hik-f2b counted failed logins it
  had already counted, so an address could be banned (or, in notify-only
  mode and in a dry run, reported) after fewer than `maxretry` real failed
  logins. Both cases were found by the new simulation test; neither was seen
  on real devices.
  - The clock was set back by less than `lookback` (120 s by default), to
    before the newest log entry already read. The next poll read part of the
    log again and counted the failed logins in it a second time. hik-f2b now
    handles every such step back like a larger one: it records what the log
    holds as already seen, without counting it, and reads on from the new
    time.
  - The clock changed while the NVR's log could not be read, and hik-f2b
    skipped the unreadable stretch after 10 polls. The next read did not
    notice the change and counted failed logins from before it again (after
    the end of DST, those of the repeated hour). The skip now leaves the
    resync due, also across a restart, and the next read that works does
    it.

### Added

- `--check` shows what hik-f2b relies on for each NVR it can read: the
  difference between the NVR's clock and the host's clock on the NVR's line,
  and on a new second line whether a log search lists entries oldest or
  newest first and how many entries one page holds (`not known` if the
  search returned too few entries to tell). Neither makes `--check` fail.
- `tests/sim.rs`: a randomized simulation that drives the engine against
  the fake NVR, router and Telegram through generated scenarios (router and
  NVR outages, restarts, floods, device clock changes) and checks after
  every poll that no failed login is counted twice, no ban lacks `maxretry`
  failed logins, exempt addresses are never banned, the rate limit holds and
  the health alerts follow their rules.
- The release workflow checks what it published before it creates the
  GitHub Release: `.github/scripts/release-verify.sh` reads the registry
  without logging in and fails unless the image has exactly `linux/amd64`
  and `linux/arm64`, each with the labels of the version and commit, every
  image tag of the release points to it, and each architecture's image,
  run on its own runner, prints its version. It can also be run by hand
  against a published release.
- `.githooks/pre-push` runs `cargo fmt --check` if the push changes Rust code
  and cargo is installed.
- `.github/scripts/repo-guard.sh` fails on addresses that are not
  documentation addresses or listed in `.github/repo-guard-allow.txt`, on
  letters that only Russian uses, on binary files and, with
  `git config hikf2b.denylist`, on the entries of a private denylist. It
  runs on the tracked files and on every commit of a push or pull request,
  in CI and through the hooks in `.githooks/`.
- `.github/scripts/docs-check.sh` checks that the two READMEs are in step,
  that internal links resolve, that no term from the "Do not use" column of
  `GLOSSARY.md` is used, that sentences in numbered steps have at most 20
  words, and that `hik-f2b.example.ini` has the lines the deploy files rely
  on.
- A CI job runs both checks and the guard's self-test, also before a release.
- `AGENTS.md`: how to run the checks, and the rules they cannot express.

### Changed

- The log search of `--check` covers the 24 hours before the NVR's time
  (at most two pages) instead of the 2 minutes around it.
- In the state file, `-` in place of an NVR's clock offset now means that a
  resync is due; hik-f2b writes it only after skipping a stretch of the log
  across a clock change. The format version stays 2, and older files load
  as before. hik-f2b 0.3.1 also loads such a file, but does not resync.

## [0.3.1] - 2026-11-20

### Added

- `deploy/compose.yaml`: an optional, commented-out secret for the Telegram
  bot token, and the steps in the READMEs.
- CI starts the image it builds with `deploy/compose.yaml` and with
  `deploy/hik-f2b.service` (each also with the Telegram secret), with a dummy
  config, checks `deploy/hik-f2b.container` with Quadlet's dry run, and runs
  the test suite on arm64 as well. The release workflow runs these checks
  too.

### Fixed

- A ban that waited for the router was applied even if its address had been
  added to `ignoreip` in the meantime (with a restart). Waiting bans and
  counted failed logins of an address that is now in `ignoreip`, or in a
  range that is never banned, are dropped at startup and before bans are
  applied, with one INFO line per address.
- The first poll of an NVR did not record what the `lookback` overlap before
  the start held, so the second poll counted failed logins from before the
  start. The first poll now reads that overlap and records it as already
  seen. If that read fails, the next poll tries again.
- If a search stopped at its cap (50 pages or 5000 entries) and the NVR
  lists the newest entries first, the older entries were skipped without a
  word. hik-f2b now tells the order from the entries it got, reads the older
  part in the same poll (at most 4 searches per NVR and poll), counts each
  entry once, and logs an ERROR with the time range for entries it cannot
  reach. Both tested NVRs list the oldest entries first, so they were not
  affected.
- A router that answers but refuses every ban (for example a user without
  the `write` policy) raised no health alert. Refused bans now have their
  own health alert, `ban-refused`, which only a ban the router accepts ends.
  If every refused ban expires or is dropped while it is alerted, one notice
  says that the outcome is unknown and the reminders stop. The README says
  that `--check` cannot see this and `--test-ban` can.

## [0.3.0] - 2026-11-20

### Added

- Published container image `ghcr.io/vladkarok/hik-f2b`, built and pushed by
  GitHub Actions for every release tag, for `linux/amd64` and `linux/arm64`
  (the arm64 image is built but has not been tried on real hardware). Tags:
  `0.3.0`, `0.3` and `latest`; release candidates only as `0.3.0-rc.N`.
  Nothing has to be compiled on the host any more.
- Health checks and health alerts. At startup and every 5 minutes hik-f2b
  checks that the router answers and that an enabled rule in
  `/ip/firewall/raw` or `/ip/firewall/filter` uses the address-list. An NVR
  that cannot be read, a router that cannot be used, a missing drop rule, or
  bans held back by `max_bans_per_hour` is reported once it has lasted
  `alert_after` (new setting, default `10m`): one alert, a daily reminder
  while it lasts, one recovery notice. Alerts go to the log and, with
  `[telegram]`, to the chat.
- New settings: `alert_after` in `[general]`, `check_rule` in `[mikrotik]`,
  `health_alerts` in `[telegram]`.
- `--check`: runs every check once (each NVR's login, clock and log search,
  the router and its drop rule, whether Telegram is configured), prints one
  line per item and exits non-zero if anything failed. It bans nothing, sends
  nothing and does not touch the state file.
- Optional country lookup: `country_db` points to an offline `.mmdb` file
  (DB-IP Lite or MaxMind GeoLite2), read by hik-f2b's own reader with no new
  dependency. The two-letter country code of a banned address is shown in the
  log, in the Telegram message (with a flag) and in the router entry's
  comment. It is for display only and never decides a ban.
- `--country IP` prints the country the database gives for an address, and
  `--check` has a line for the country database.
- This changelog.

### Changed

- The deploy files (`deploy/hik-f2b.container`, `deploy/compose.yaml`) and the
  install commands in the READMEs use the published image pinned to a version
  (`ghcr.io/vladkarok/hik-f2b:0.3.0`) instead of a locally built
  `localhost/hik-f2b:latest`. Building the image yourself is still
  documented.
- Each log entry from the NVR is parsed on its own, so one malformed entry
  costs only itself; there is no separate salvage path for broken pages any
  more. The paging status is read only from text outside the entries.
- When the router refuses a ban, hik-f2b asks the router whether the address
  is already listed instead of relying only on the wording of the error
  message.
- Dependencies: md-5 0.11, roxmltree 0.21, signal-hook 0.4, webpki-roots 1.0.

### Security

- XML handed to the parser may hold at most 256 `<`. Deeply nested markup
  (possible only through firmware that does not escape the login name, or
  through tampering with plain HTTP) could otherwise exhaust the stack and
  abort the daemon.

## [0.2.0] - 2026-11-19

First version in the repository. It was not published as an image; it had to
be built from source.

### Added

- Polls the NVR log over ISAPI (MD5 Digest authentication, http or https) for
  failed logins, counts them per source IPv4 address across all NVRs, and
  bans an address that reaches `maxretry` failures within `findtime` through
  the RouterOS REST API, as an address-list entry with a timeout (`bantime`)
  or permanently (`bantime = permanent`).
- Notify-only mode without a router, `dry_run`, `ignoreip`,
  `max_bans_per_hour`, `auth_backoff` after a rejected login, and a state
  file that keeps progress, counters and the rate limit across restarts.
- Optional Telegram notification for every ban or detection, with a
  configurable message, forum topics and retries.
- Passwords and tokens from secret files (`<name>_file`); CA certificate
  verification for the router.
- `--dump` (with `--raw`), `--test-ban` and `--test-notify` for checking a
  setup before enabling it.
- One static binary with no unsafe code, a container image `FROM scratch`
  running as an unprivileged user, a Podman Quadlet unit, a Compose file and
  a sandboxed systemd unit, unit and end-to-end tests, CI, and documentation
  in English and Ukrainian.

[Unreleased]: https://github.com/Vladkarok/hik-f2b/compare/v0.3.3...HEAD
[0.3.3]: https://github.com/Vladkarok/hik-f2b/compare/v0.3.2...v0.3.3
[0.3.2]: https://github.com/Vladkarok/hik-f2b/compare/v0.3.1...v0.3.2
[0.3.1]: https://github.com/Vladkarok/hik-f2b/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/Vladkarok/hik-f2b/compare/1e9edea...v0.3.0
[0.2.0]: https://github.com/Vladkarok/hik-f2b/commit/1e9edea
