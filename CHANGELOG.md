# Changelog

All notable changes to hik-f2b are listed here, newest first. The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and version
numbers follow [Semantic Versioning](https://semver.org/). Each version is
published as the container image `ghcr.io/vladkarok/hik-f2b:<version>`
(from 0.3.0 on); see "Versions and updates" in the [README](README.md).

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

[0.3.0]: https://github.com/Vladkarok/hik-f2b/compare/1e9edea...v0.3.0
[0.2.0]: https://github.com/Vladkarok/hik-f2b/commit/1e9edea
