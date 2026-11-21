# hik-f2b

**English** | [Українська](README.uk.md) | [Glossary](GLOSSARY.md)

fail2ban-style protection for Hikvision NVRs that sit behind a MikroTik router
with their ports forwarded to the internet.

hik-f2b polls the NVR's own log for failed logins and counts them per source
IPv4 address. When an address reaches `maxretry` failed logins within `findtime`
seconds, hik-f2b adds it to a firewall address-list on the router, with a
timeout (`bantime`) or permanently. The router blocks that address from then
on. Optionally it reports every ban to a Telegram chat, and tells you when it
cannot do its job (see [Health alerts](#health-alerts)). Without a router it
can run in [notify-only mode](#notify-only-mode-no-router): it reports such
addresses and bans nothing.

The container image holds one static binary of about 2 MB. While running it
uses about 2 MB of memory. It listens on no port.

> **Status: beta.** Verified on real devices (see
> [Tested hardware](#tested-hardware)): failed logins are read, the address is
> banned, and the router blocks its traffic. It has not yet run unattended for
> days or weeks, and several parts have not been tried at all (listed under
> [Tested hardware](#tested-hardware)). Start with `dry_run = true`.

## Why

A router cannot tell a wrong password from a right one: it only sees TCP
connections, and a client app opens a burst of connections just to show a
camera grid, so rate limits on the router block real users. The NVR does know,
and it writes every failed login with the source address to its log. hik-f2b
connects the two.

```
attacker ──► MikroTik ──dst-nat──► NVR ── writes "Illegal Login" + IP to its log
                 ▲                                │
                 │  REST: add IP to               │  ISAPI: POST /ISAPI/ContentMgmt/logSearch
                 │  address-list, timeout=bantime ▼
                 └──────────────────────────── hik-f2b ──► Telegram (optional)
```

## Is this the right tool?

Exposing an NVR to the internet is a risk that no ban fully removes:
several Hikvision vulnerabilities needed no password at all. In order of
preference:

1. Do not forward ports. Use a VPN, or the vendor's cloud relay.
2. If you must forward ports, do all of these:
   - Keep the firmware current.
   - Forward only the ports that the client app needs.
   - If you can, restrict access by source country or network.
   - Turn off UPnP on the router.
   - Keep the NVR's built-in illegal login lock enabled.
3. Then add hik-f2b. It turns the NVR's 30-minute lock into a ban of any
   length on the router. It covers all your NVRs at once.

Related projects: [fail2ban](https://github.com/fail2ban/fail2ban) with a
[MikroTik action](https://github.com/pincioc/fail2ban_mikrotik) works if your
NVR can send logs to syslog, and
[mikrotik-fwban](https://github.com/middelink/mikrotik-fwban) bans from syslog
messages directly. hik-f2b exists because many Hikvision NVRs have no usable
syslog output, so the log has to be pulled over ISAPI (Hikvision's HTTP API).

## Requirements

- Hikvision NVR/DVR with ISAPI log search (`/ISAPI/ContentMgmt/logSearch`).
- MikroTik RouterOS 7.1 or newer (REST API). Not needed in notify-only mode.
- An always-on Linux host that can reach the NVRs and the router, with Podman
  or Docker, or without a container, see [Host](#3-host).
- The NVR must see the real client address: your port-forward must not
  masquerade traffic coming from the internet.

## Setup

### 1. Router

Before you start:

- In the commands, replace `192.168.88.1` with the router address that the
  host connects to.
- Replace `HOST_IP` with the address of the host that runs hik-f2b.
- Use only Latin characters. The RouterOS terminal rejects other characters.
- Run the commands one at a time. Signing takes a few seconds.

1. Set up HTTPS for the REST API. RouterOS does not self-sign a server
   certificate, so a small local CA (certificate authority) signs it:

```
/certificate add name=f2b-ca common-name=f2b-ca days-valid=3650 key-usage=key-cert-sign,crl-sign
/certificate sign f2b-ca
/certificate add name=rest-api common-name=192.168.88.1 subject-alt-name=IP:192.168.88.1 days-valid=3650 key-usage=digital-signature,key-encipherment,tls-server
/certificate sign rest-api ca=f2b-ca
/ip service set www-ssl certificate=rest-api address=HOST_IP/32 disabled=no
```

The REST API is now reachable over HTTPS, and only from the hik-f2b host.

2. Create a dedicated account. It can only be used from the hik-f2b host:

```
/user group add name=f2b policy=read,write,api,rest-api
/user add name=f2b group=f2b address=HOST_IP/32 password=CHANGE_ME
```

`write` is needed to add bans. `read` lets hik-f2b read the firewall rules.
hik-f2b reads them to check that the drop rule from step 3 exists.

3. Add the drop rule. This is the rule that blocks banned addresses:

```
/ip firewall raw add chain=prerouting in-interface-list=WAN src-address-list=cctv_ban action=drop comment="hik-f2b: drop banned"
```

The rule lives in `raw`, ahead of connection tracking and fasttrack, so it also
cuts connections the banned address already has open. It drops packets by
source address on the WAN side. So it also drops replies from a banned address
to connections that your own LAN opened. hik-f2b checks at startup and every 5
minutes that such a rule exists and is enabled. If the rule is gone, hik-f2b
sends a health alert (see [Health alerts](#health-alerts)).

4. Export the CA certificate:

```
/certificate export-certificate f2b-ca
```

The router now has the file `cert_export_f2b-ca.crt` in its files.

5. Copy this file to the host. The [Host](#3-host) step saves it as
   `router-ca.crt`, the name that the example config expects. With Compose or
   without a container, name it `router-ca.crt` yourself.

hik-f2b trusts only this CA when it connects to the router.

### 2. NVR

Do not use the admin account for hik-f2b. hik-f2b only needs to search the log.
With the admin account, a leaked password from the config gives full control
of the NVR. Create a separate user instead:

1. Create a user named `f2b` with the *Operator* level.
2. Give the user a single permission:
   **Remote: Log Search / Interrogate Working Status**.

### 3. Host

1. Copy [hik-f2b.example.ini](hik-f2b.example.ini) to `hik-f2b.ini`.
2. Edit `hik-f2b.ini`. Addresses and thresholds go in the config.
3. Put passwords in separate secret files. The config only points to them
   (`password_file = ...`).

The container image is published on GitHub's container registry as
`ghcr.io/vladkarok/hik-f2b`, for `linux/amd64` and `linux/arm64`. The arm64
image is built natively but has not been tried on real hardware. The deploy
files use an exact version. To get it, run:

```bash
podman pull ghcr.io/vladkarok/hik-f2b:0.3.2
```

For how versions are tagged and how to update, see
[Versions and updates](#versions-and-updates).

**Building the image yourself** instead of pulling it: run this command in the
repository. It uses the [Containerfile](Containerfile):

```bash
podman build -t hik-f2b -f Containerfile .
```

Podman then knows the image as `localhost/hik-f2b:latest`. Put that name in
these places:

- the `Image=` line of the Quadlet unit (or `image:` in the Compose file);
- the commands below.

The deploy files have that name as a commented-out line.

**Podman (rootless), recommended.** Use
[deploy/hik-f2b.container](deploy/hik-f2b.container), a Quadlet unit (a file
from which Podman generates a systemd service).

Inside the container hik-f2b runs as uid 65532. In a rootless container that
user is not you. So it can read the config and the CA certificate only if they
are world-readable. That is why the commands below make them `644`. They hold
no secrets as long as the passwords come from Podman secrets (`password_file`).
Do not put passwords inline in a world-readable config. Any local user of the
host could read them.

Run these commands:

```bash
mkdir -p ~/.config/hik-f2b ~/.config/containers/systemd
cp hik-f2b.ini ~/.config/hik-f2b/hik-f2b.ini
cp cert_export_f2b-ca.crt ~/.config/hik-f2b/router-ca.crt
chmod 755 ~/.config/hik-f2b
chmod 644 ~/.config/hik-f2b/hik-f2b.ini ~/.config/hik-f2b/router-ca.crt
printf '%s' 'ROUTER_PASSWORD' | podman secret create hik-f2b-router -
printf '%s' 'NVR_PASSWORD'    | podman secret create hik-f2b-nvr -
cp deploy/hik-f2b.container ~/.config/containers/systemd/
systemctl --user daemon-reload
```

**Docker Compose:** see [deploy/compose.yaml](deploy/compose.yaml). Its header
lists the files to put next to it and the owner and mode they need. If uid
65532 cannot read a secret file, hik-f2b stops at startup with
`cannot read /run/secrets/...`. `docker compose pull` fetches the image it
names. To build the image yourself:

1. Run `docker build -t hik-f2b -f Containerfile .`.
2. Use the commented-out `image: hik-f2b:latest` line.

**No container:** the systemd unit
[deploy/hik-f2b.service](deploy/hik-f2b.service) runs the binary in a sandbox.
It passes the secrets as systemd credentials. Its header lists the commands
that install the binary, the config, the secret files and the unit. A plain
`cargo build --release`
on a glibc system gives a dynamically linked binary. To get the same static
binary as in the image, use one of these two ways.

**Way 1: copy the binary out of the image.** Podman pulls the image for the
host's architecture. For an image that you built yourself, use
`localhost/hik-f2b:latest`. Run:

```bash
podman create --name hik-f2b-copy ghcr.io/vladkarok/hik-f2b:0.3.2
podman cp hik-f2b-copy:/hik-f2b ./hik-f2b
podman rm hik-f2b-copy
```

**Way 2: build for the musl target.** This way needs a C compiler for musl,
because the TLS library contains C code. This path has not been tested.

1. Run `rustup target add x86_64-unknown-linux-musl`.
2. Run `cargo build --release --target x86_64-unknown-linux-musl`.

The binary is in `target/x86_64-unknown-linux-musl/release/`.

### 4. Verify before enabling

Run these commands the same way as you run the service. For the plain binary:

```bash
# Every NVR (login, clock, log search), the router and its drop rule,
# whether Telegram is configured, and the country database if set. One line
# per item; exits non-zero if anything failed. Bans nothing, sends nothing,
# does not touch the state file.
hik-f2b --config hik-f2b.ini --check

# What the NVR returns. Failed logins must be flagged MATCH and carry ip=...
hik-f2b --config hik-f2b.ini --dump --hours 72

# Router access. The address shows up in the list for 60 seconds.
hik-f2b --config hik-f2b.ini --test-ban 203.0.113.1

# Telegram, if configured.
hik-f2b --config hik-f2b.ini --test-notify

# The country of an address, if country_db is set. Reads only that file.
hik-f2b --config hik-f2b.ini --country 203.0.113.1
```

With rootless Podman, give the container the same config and secrets as the
Quadlet unit does. Put the options after the image name. For example:

```bash
podman run --rm --network host \
  -v ~/.config/hik-f2b:/etc/hik-f2b:ro,Z \
  --secret hik-f2b-router,uid=65532,mode=0400 \
  --secret hik-f2b-nvr,uid=65532,mode=0400 \
  ghcr.io/vladkarok/hik-f2b:0.3.2 --dump --hours 72
```

To run `--check` in the container, put `--check` in place of
`--dump --hours 72`. `--check` prints one line per part. In a healthy setup,
every configured part prints `ok`. `off` marks a part that is not configured:
Telegram, the country database, or the router in notify-only mode. `FAILED`
marks a problem, and then `--check` exits non-zero. For example:

```
ok       nvr nvr1: login accepted, device time 2026-01-10T10:00:00Z (2:00:00 ahead of the host clock), log search works
ok       nvr nvr1 log: oldest first, 64 entries per page
ok       firewall: 1 enabled rule(s) in /ip/firewall/raw with src-address-list=cctv_ban
off      telegram: not configured
ok       country database: DBIP-Country-Lite, built 2026-11-01
```

The first line of an NVR also shows how far its clock is from the host's
clock. hik-f2b converts the NVR's times with this difference, so a difference
of hours is normal (see [Time and clock changes](#time-and-clock-changes)).
For an NVR that can be read, a second line shows what one search of the last
24 hours returned, at most two pages: whether the NVR lists log entries oldest
first or newest first, and how many entries one page holds. hik-f2b reads
both orders. If the search returned too few entries to tell, the line says
`not known`. These lines never make `--check` fail. Include them when you
report a problem.

`--check` only reads from the router, so it cannot show whether the router
accepts a ban. A router user whose group has no `write` policy passes
`--check`, but every ban fails. To try the write access, run `--test-ban`.

If the `--dump` output is not as expected:

- If failed logins are listed without `MATCH`, look at their `metaId`. Then
  adjust `log_filter`.
- If nothing is listed, or the NVR answers `badXmlFormat`:
  1. Run the command again with `--raw`.
  2. Remove the addresses from the output.
  3. Open an issue with the output.

Entries flagged `AMBIG` have a repeated field and are never counted (see
[Security design](#security-design)). `--dump` prints times as the NVR's own
clock shows them.

### 5. Enable

Run these commands in this order:

1. Start the service.
2. Let the service run without a login session.
3. Follow the service log.

```bash
systemctl --user start hik-f2b
loginctl enable-linger "$USER"
journalctl --user -u hik-f2b -f
```

At startup the log shows:

- the mode: `mode: ban on MikroTik`, `mode: DRY RUN` or `mode: notify-only`;
- with a router, how many entries the address-list has;
- with a router, the result of the firewall check (`firewall check ok: ...`
  or `firewall check failed: ...`);
- with `country_db` set, the name of the country database, or a warning that
  it cannot be read.

## Versions and updates

hik-f2b uses [Semantic Versioning](https://semver.org/). Every release is
described in [CHANGELOG.md](CHANGELOG.md), published as a GitHub Release and
as these image tags:

| Tag | Meaning |
| --- | --- |
| `0.3.2` | Exactly this release. It never changes. Use this one. |
| `0.3` | The newest `0.3.x` release; moves with every bug-fix release. |
| `latest` | The newest release; moves with every release, including ones that need config changes. |
| `0.3.2-rc.1` | A release candidate, for trying out before `0.3.2`. Never `latest`, never `0.3`. |

Pin an exact version, as the deploy files do. Before 1.0, a new second number
(`0.3` to `0.4`) may need changes to your config; the changelog says so.

**Update:**

1. Read the changelog from your version up to the new one.
2. Try the new image with `--check`. Put the new image in the `podman run`
   command from [Verify before enabling](#4-verify-before-enabling).
3. Change the tag in the `Image=` line of
   `~/.config/containers/systemd/hik-f2b.container`.
4. Run these commands to pull the new image and restart the service:

```bash
podman pull ghcr.io/vladkarok/hik-f2b:<new version>
systemctl --user daemon-reload
systemctl --user restart hik-f2b
journalctl --user -u hik-f2b -f
```

With Compose:

1. Change `image:`.
2. Run `docker compose pull`.
3. Run `docker compose up -d`.

**Roll back:** do the same steps with the previous tag. Old tags stay
published.

Podman can also update a container by itself (`AutoUpdate=registry` in the
unit with `podman-auto-update.timer`), and there are similar tools for Docker.
We recommend against unattended updates here: hik-f2b changes your firewall,
so an update should be a step you take and then watch. If you use it anyway,
it needs a moving tag such as `0.3`, since an exact version never changes.

How a release is made: [RELEASING.md](RELEASING.md).

## Configuration

See [hik-f2b.example.ini](hik-f2b.example.ini). The settings in `[general]`:

| Setting | Default | Allowed | Meaning |
| --- | --- | --- | --- |
| `maxretry` | 5 | 1–1000 | Failed-login log entries that trigger a ban. |
| `findtime` | 3600 | 10–2592000 | Window in which they must happen. |
| `bantime` | 86400 | 60–31536000 or `permanent` | Ban length; the router expires the entry itself. `permanent`: see [Permanent bans](#permanent-bans). |
| `ignoreip` | private ranges | | Addresses and networks that are never banned. Setting it replaces the default list. |
| `max_bans_per_hour` | 20 | 1–10000 | Upper limit on new bans (or reports) per hour. |
| `poll_interval` | 30 | 5–3600 | Time between log polls. |
| `lookback` | 120 | 10–172800 | Overlap between consecutive log queries. |
| `auth_backoff` | 900 | 60–86400 | Pause after an NVR rejects hik-f2b's own login. |
| `alert_after` | 600 | 60–604800 | How long a problem must last before it is alerted, see [Health alerts](#health-alerts). |
| `log_filter` | `ill\w*(access\|login)` | | Regex on the log entry type that marks a failed login. |
| `meta_id` | `log.std-cgi.com/Exception` | | Log type requested from the NVR. |
| `state_file` | `/var/lib/hik-f2b/state` | | Where progress, counters and the rate limit are kept. |
| `dry_run` | false | | Log bans without applying them (also `--dry-run`). |
| `country_db` | off | | An offline `.mmdb` file for the country of banned addresses, display only, see [Country of a banned address](#country-of-a-banned-address). |

The time settings (`findtime`, `bantime`, `poll_interval`, `lookback`,
`auth_backoff`, `alert_after`) are in seconds, or a whole number with one suffix: `s`, `m`,
`h`, `d` or `w` (seconds, minutes, hours, days, weeks), for example `10m`,
`12h` or `7d`. A plain number is seconds. The limits in the table are in
seconds and are checked after the conversion, so `365d` is the longest timed
ban.

The default `ignoreip` is `127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12,
192.168.0.0/16`. If you set `ignoreip`, repeat the private ranges you still
need.

Failed logins are counted across all configured NVRs together.

Every password or token can be given as `<name>_file = /path` (preferred) or
inline as `<name> = value`. If the config holds an inline secret and other
users can read it, hik-f2b logs a warning at startup.

`ca_file` in the `[mikrotik]` section is required when the router URL is
https. It is either the path of the CA certificate that signed the router's
certificate, or the word `public` to trust the public CA roots built into
hik-f2b instead. The router URL may be plain http only when the router is this
host (`localhost`, `127.0.0.1`, `::1`). An NVR URL may be http or https; for
https, `ca_file` in the `[nvr:...]` section is the path of its CA certificate,
and without it (or with `public`) the public roots are used.

`check_rule` in the `[mikrotik]` section (default `true`) turns the check for
the drop rule on or off, see [Health alerts](#health-alerts). If the
address-list is blocked some other way, set it to `false`. Examples: a rule
that uses the address-list as `dst-address-list`, or blocking on another
device.

A state file written by an older version (format 1) is ignored: hik-f2b
starts fresh, watches each NVR log from the current time on, and the hourly
ban counter starts at zero.

### Permanent bans

With `bantime = permanent` the address is added without a timeout. RouterOS
keeps such an entry as a static one: it is saved in the router's
configuration, survives a reboot, shows up in `/export`, and stays until you
remove it. Entries with a timeout live in the router's memory only and are
gone after a reboot. Before choosing `permanent`, read about its cost under
[Avoiding false positives](#avoiding-false-positives).

hik-f2b itself still remembers a permanent ban for 24 hours: a ban the router
does not accept within that time is dropped, and in notify-only mode or a dry
run an address is reported again after 24 hours at the earliest. Log lines and
`{action}` say `banned permanently`; `{bantime}` is `permanent`. `--test-ban`
always adds a 60-second entry.

If the address is already in the address-list, the router refuses a second
entry and hik-f2b counts the address as already banned; it does not change the
existing entry. Whenever the router refuses an entry and the error is not the
known duplicate message, hik-f2b asks the router whether the address is
listed. So this does not depend on the wording of RouterOS error messages. An
address that is still listed with a timeout when you switch to `permanent`
therefore gets a permanent entry only the next time it is banned, after the
timed entry has expired. If you want that sooner, remove the timed entry by
hand.

### Telegram notifications

1. Create a bot with [@BotFather](https://t.me/BotFather).
2. Add the bot to the chat.
3. Add a `[telegram]` section to the config:

```ini
[telegram]
bot_token_file    = /run/secrets/hik-f2b-telegram
chat_id           = -1001234567890
message_thread_id = 42
```

`chat_id` is a user, group or supergroup id (supergroups look like `-100…`) or
`@channelname`. `message_thread_id` is the topic of a forum supergroup. For
ordinary chats, leave it out. `silent = true` delivers without sound, and
`enabled = false` turns the section off. `health_alerts = false` keeps
[health alerts](#health-alerts) out of the chat; they still go to the log.

With the Quadlet unit, give the container the bot token as a Podman secret:

1. Create the Podman secret `hik-f2b-telegram` with the bot token:

```bash
printf '%s' 'BOT_TOKEN' | podman secret create hik-f2b-telegram -
```

2. Enable the `Secret=hik-f2b-telegram` line in
   `~/.config/containers/systemd/hik-f2b.container`.
3. Run `systemctl --user daemon-reload`.
4. Restart the service with `systemctl --user restart hik-f2b`.
5. Run `--test-notify` as in [Verify before enabling](#4-verify-before-enabling).
   In the `podman run` command, add `--secret hik-f2b-telegram,uid=65532,mode=0400`.

hik-f2b then prints `ok: test message sent`, and the test message appears in
the chat.

With Compose, give the container the bot token as a Compose secret. The
`[telegram]` example above already reads it from
`/run/secrets/hik-f2b-telegram`.

1. Put the bot token in `secrets/telegram`, next to `compose.yaml`.
2. With rootful Docker, run
   `sudo chown 65532 secrets/telegram && sudo chmod 400 secrets/telegram`.
3. In `compose.yaml`, enable the `- hik-f2b-telegram` line under the service's
   `secrets:`.
4. Enable the two `hik-f2b-telegram` lines under the top-level `secrets:`.
5. Run `docker compose up -d`.

The startup line in `docker compose logs hik-f2b` then ends with
`telegram=on`.

Without a container, systemd hands the bot token over as a credential:

1. Run `sudo install -D -m 600 telegram-token /etc/hik-f2b/secrets/telegram`.
2. Enable the `LoadCredential=telegram:/etc/hik-f2b/secrets/telegram` line in
   `/etc/systemd/system/hik-f2b.service`.
3. In the config, set
   `bot_token_file = /run/credentials/hik-f2b.service/telegram`.
4. Run `sudo systemctl daemon-reload`.
5. Run `sudo systemctl restart hik-f2b`.

The startup line in `journalctl -u hik-f2b` then ends with `telegram=on`.

The message text is set with `message`. `\n` starts a new line. Placeholders:
`{ip}`, `{country}`, `{action}`, `{bantime}`, `{nvr}`, `{user}`, `{count}`,
`{findtime}`. `{action}` is one of `banned for 1d00:00:00`,
`banned permanently`, `would be banned for 1d00:00:00 (dry run)`,
`would be banned permanently (dry run)` or
`detected, no firewall configured`. `{country}` is empty when there is no
country (no `country_db`, or none found for the address). Otherwise it is a
space followed by the flag and the code in brackets, ` (🇲🇩 MD)`. So write it
right after `{ip}`. A `message` of your own shows the country only if it
contains `{country}`. The default message is:

```
⛔ hik-f2b: {ip}{country} {action}
NVR: {nvr}
User tried: {user}
Failed logins: {count} within {findtime} s
```

The text is sent without a parse mode, so nothing in it is read as markup.

A ban is applied before any notification is attempted. Notifications that
fail are retried on later polls, at most 5 attempts each; at most 100 wait at
a time, and they are kept in memory only, so a restart loses them. An
unreachable Telegram costs at most one 10-second timeout per poll.

### Country of a banned address

Optional, like GoAccess's `geoip-database`: point `country_db` in `[general]`
at an offline MaxMind DB (`.mmdb`) file, and hik-f2b adds the two-letter
country code of each banned (or detected) address:

- at the end of the router comment:
  `hik-f2b nvr1 user=admin 2026-01-10T08:01:14Z country=MD`;
- next to the address in the `BAN`, `DRY RUN` and `DETECTED` log lines:
  `BAN 198.51.100.7 [MD] for 1d00:00:00 (...)`;
- in the Telegram message, with the flag:
  `⛔ hik-f2b: 198.51.100.7 (🇲🇩 MD) banned for 1d00:00:00`.

The country is for display only. It never decides whether or when an address
is banned; it is looked up after that has been decided. hik-f2b never
downloads anything: you provide the file and keep it up to date.

Files that work:

- DB-IP IP to Country Lite (`dbip-country-lite-YYYY-MM.mmdb`): free, no
  account needed. Tried.
- MaxMind GeoLite2 Country (`GeoLite2-Country.mmdb`): free with a MaxMind
  account. Tried. Its licence asks you to replace the file within 30 days of
  each new release. If you use it, set up updates. GeoLite2 City has the
  same layout (`country` → `iso_code`) and is not tried.
- IPinfo Lite: a top-level `country_code`. Supported by its schema, not tried.

Only a code of exactly two capital letters is used. An address that is not in
the file, or whose record holds anything else, has no country.

The file is opened at every ban and read with a few small reads, never loaded
into memory, so replacing it needs no restart. If it is missing or cannot be
read, the ban goes ahead without a country and a WARNING says why. That
warning is repeated only when the reason changes, and an INFO line
`country lookups work again` follows once the file can be read again. A broken
file is not a [health alert](#health-alerts). At startup the log shows
`country database: DBIP-Country-Lite, built 2026-11-01`, or a warning that the
file cannot be read; the service starts either way. `--check` shows the same
as its last line and exits non-zero when `country_db` is set but the file
cannot be read. `--country 203.0.113.1` prints one address and its code (or
`unknown`); it reads only the file and contacts nothing.

To get the DB-IP Lite file, put it into the config directory. The Quadlet
unit mounts this directory read-only at `/etc/hik-f2b`. The systemd unit reads
`/etc/hik-f2b` itself. Compose mounts single files, see the comment in
[deploy/compose.yaml](deploy/compose.yaml).

1. Download the current month's file. The URL pattern is
   `https://download.db-ip.com/free/dbip-country-lite-YYYY-MM.mmdb.gz`.
2. Unpack the file into the config directory.

These commands do steps 1 and 2:

```bash
cd ~/.config/hik-f2b
month=$(date -u +%Y-%m)
curl -fsS "https://download.db-ip.com/free/dbip-country-lite-$month.mmdb.gz" \
  | gunzip > country.mmdb.new \
  && chmod 644 country.mmdb.new \
  && mv country.mmdb.new country.mmdb
```

3. Set `country_db = /etc/hik-f2b/country.mmdb` in the config.

The file is world-readable (`644`) for the same reason as the config (see
[Host](#3-host)).

DB-IP publishes a new file every month. To update the file, run the same
commands again. For example, run them from cron a few days into each month
(`0 6 3 * *`). The new file is written under a temporary name in the same
directory and then renamed over the old one. So a ban never reads a
half-written file, and a failed download leaves the old file in place.

The DB-IP Lite data is licensed under CC BY 4.0, which asks for this
attribution:

IP geolocation by [DB-IP](https://db-ip.com)

### Notify-only mode (no router)

Leave out the `[mikrotik]` section. hik-f2b then bans nothing. When an address
reaches `maxretry` failed logins within `findtime`, it logs a `DETECTED` line and,
if `[telegram]` is configured, sends a message whose `{action}` is
`detected, no firewall configured`. The address is not reported again until
`bantime` has passed (24 hours with `bantime = permanent`). Reports count
towards `max_bans_per_hour`.

```ini
[general]
maxretry = 5
findtime = 3600
bantime  = 86400

[nvr:nvr1]
url           = http://192.168.88.10
user          = f2b
password_file = /run/secrets/hik-f2b-nvr

[telegram]
bot_token_file = /run/secrets/hik-f2b-telegram
chat_id        = -1001234567890
```

If you use the Quadlet unit:

1. Remove the `Secret=hik-f2b-router` line.
2. Enable the `Secret=hik-f2b-telegram` line.

`--test-ban` does not work in this mode.

With neither `[mikrotik]` nor `[telegram]`, detections are only written to the
log, and hik-f2b warns about it at startup. A dry run (`dry_run = true`) also
reports an address only once per `bantime` (or 24 hours).

Notify-only mode is covered by tests but has not been tried on real devices.

## Health alerts

hik-f2b watches its own ability to protect you and reports trouble through
Telegram (if `[telegram]` is configured and `health_alerts` is not `false`)
and always in its log. It watches:

- **Each NVR:** it cannot be read, because it does not answer or rejects
  hik-f2b's login (for example after a password change). While hik-f2b waits
  `auth_backoff` after a rejected login, the problem counts as ongoing.
- **The router:** it cannot be reached, refuses the login, or answers with an
  error. This is seen when a ban fails to reach the router and by a check at
  startup and every 5 minutes.
- **The drop rule:** no enabled rule in `/ip/firewall/raw` or
  `/ip/firewall/filter` has `src-address-list` set to `address_list`. Without
  such a rule the address-list fills up and nothing is blocked. hik-f2b asks
  each table for the rules with that `src-address-list`
  (`GET /rest/ip/firewall/raw?src-address-list=cctv_ban&.proplist=.id,disabled`,
  then the same for `filter`). It counts a rule as enabled unless the reply
  says `"disabled":"true"`: RouterOS 7.18 leaves the `disabled` property out
  of enabled `raw` rules altogether. The check does not look at the rule's
  chain, interface or action. So a rule that matches the address-list but
  accepts the traffic still passes. To turn the check off, set
  `check_rule = false` in `[mikrotik]`.
- **The ban rate limit:** addresses are waiting because `max_bans_per_hour` has
  been reached.
- **Refused bans:** the router answers, but refuses to add an address to the
  address-list. For example, the router user's group has lost the `write`
  policy. The checks every 5 minutes only read, so they cannot clear this
  problem. Only a ban that the router accepts ends it. If every refused ban
  expires or is dropped while the problem is alerted, nothing is left to show
  whether it is over. Then hik-f2b sends one message that says so, sends no
  more reminders, and does not claim a recovery. The next refused ban starts
  a new problem.

The router checks also run in a dry run, where they help with the setup. A dry
run sends no bans, so the refused-ban check does not run in a dry run. In
notify-only mode there is no router to check.

A problem is reported once it has lasted `alert_after` (default 10 minutes),
so a single failed poll is not news. While it lasts, it is reported again once
every 24 hours. When an alerted problem is over, one more message says so; a
problem that ends before `alert_after` produces no message at all. For
example:

```
⚠️ hik-f2b: nvr2 cannot be read for 10 min: login rejected (HTTP 401)
⚠️ hik-f2b: banned addresses are not blocked for 10 min: no enabled rule in /ip/firewall/raw or /ip/firewall/filter has src-address-list=cctv_ban
✅ hik-f2b: banned addresses are blocked again (after 25 min)
```

These texts are fixed; `message` applies to ban messages only. Reasons are
taken from error messages, cut short, and URLs are left out. Health messages go
through the same queue as ban messages, so a Telegram outage costs no more
than before and never holds up polling or banning. In the log each report is
one ERROR line (`health alert [nvr:nvr2]: ...`, `health reminder [...]`) and
each recovery one INFO line (`health recovered [...]`). The message about
refused bans that no longer wait is an INFO line too
(`health unknown [ban-refused]: ...`); in the chat it starts with ℹ️. What
hik-f2b remembers
about problems is kept in memory only: after a restart a problem that is still
there is reported again once it has lasted `alert_after`.

Health alerts cannot report that hik-f2b itself has stopped, crashed or hangs,
or that its host is down or offline: then nothing is left to send a message.
To detect this, watch the service from outside. For example, let your
monitoring system check that the systemd unit or container is running.

## Time and clock changes

Each NVR's log is in that device's local time. On every poll hik-f2b reads the
NVR's clock and converts the time of each failed login to the host's clock with
that NVR's current offset. So NVRs may have different clocks or time zones. Times in
hik-f2b's own log lines and in the router comment are host time in UTC. Lines
marked "(device time)" and the output of `--dump` show the NVR's clock.

On the first poll of an NVR (no state for it yet), hik-f2b reads the log from
the NVR's current time. It also reads the `lookback` overlap before that time
and records those entries as already seen, without counting them. So failed
logins from before the start are never counted. If this first read fails,
the next poll tries again from its own time.

If an NVR's clock goes back to before the newest log entry that hik-f2b has
read (a DST change, a reset real-time clock, or a correction of a few
minutes), or jumps forward by more than 15 minutes, hik-f2b logs a warning,
records the entries the log holds at that moment as already seen without
counting them, and reads on from the new time. Failed logins in the short
window around the change are not counted. A smaller forward correction, or a
backward one that does not reach the newest entry read, needs nothing of this:
the entries read before stay known, so none is counted again.

If the clock changes while the NVR's log cannot be read, and hik-f2b skips
the unreadable stretch after 10 polls (see [Limitations](#limitations)), the
next read that works does the same: it records the entries the log holds as
already seen and reads on from there. Failed logins logged while the log
could not be read are then not counted. If the clock did not change, only
the skipped stretch is lost.

Entries older than `findtime` are never counted, and neither are entries more
than 5 minutes in the future (host time).

## Avoiding false positives

- `maxretry` counts log entries. On the tested devices one failed login gives
  one entry, so three mistyped passwords count as three. This was checked over
  HTTP (web interface, ISAPI) on both devices and from iVMS-4200 over the
  device (SDK) port on one. A wrong password and a user name that does not
  exist are both logged and count the same. Other firmware or client apps may
  differ. If this matters to you, make one failed login on purpose. Then look
  at the `--dump` output.
- The counter for an address empties once its failed logins are older than
  `findtime`.
- LAN and hairpin-NAT clients, and VPN clients with private addresses, are
  covered by the default `ignoreip`. Some VPNs use 100.64.0.0/10 (Tailscale,
  carrier-grade NAT), which the default does not cover. Add such ranges to
  `ignoreip`. Also add your own public addresses (office, monitoring host).
  Keep the private ranges in `ignoreip`.
- A client app with a stale saved password retries on its own and reaches the
  threshold quickly. After you change a password, update the saved password
  in the client apps at once.
- Mobile carriers put many subscribers behind one address (CGNAT). A ban on
  such an address can hit a legitimate user on the same carrier, which is a
  reason to keep `bantime` moderate.
- `bantime = permanent` has a cost. Many attacking addresses are dynamic or
  shared (CGNAT, cloud and hosting ranges). Once the attacker has moved on, the
  address can go to someone else, who then cannot reach your NVR, perhaps
  months later. Nothing ever removes a permanent entry, so the address-list
  only grows and you have to review and prune it by hand. The comment of each
  entry holds the NVR, the user name tried and the time (UTC) of the failed
  login that triggered the ban.
- To see the address-list on the router, run:
  `/ip firewall address-list print where list=cctv_ban`
- To remove a ban, remove its entry on the router:
  `/ip firewall address-list remove [find list=cctv_ban address=X.X.X.X]`
- To empty the whole address-list (timed and permanent bans), run:
  `/ip firewall address-list remove [find list=cctv_ban]`

## Security design

hik-f2b holds credentials for your NVRs and for a router account that can
change almost all of the router's configuration (see "Router account" below),
and it reads text that attackers control (the user name in a failed login is
whatever they typed). It is built accordingly:

- **Memory safety.** Rust with `unsafe` forbidden in this crate, and integer
  overflow checks kept on in release builds.
- **Hostile input.** The address is taken only from the entry's address field,
  never from free text or the user name, and must parse as an IP address.
  If the entry has an `<ipAddress>` field (both tested NVRs write one), the
  address comes from that field only, also when other fields have names that
  look like an address. `::ffff:a.b.c.d` is treated as the IPv4 address it wraps; other IPv6
  addresses are logged and not counted. User names are cut to 32 characters
  and reduced to printable ASCII before they reach a log line, the router or
  Telegram. Request bodies are built with escaping, Telegram messages are sent
  without a parse mode, and control characters never reach the log. Invalid
  UTF-8 and characters that XML forbids are replaced, and a bare `&` is read
  as text. Each log entry is parsed
  on its own: one that cannot be parsed (not well-formed XML, or more markup
  than any real entry has) is skipped with a warning, and the rest of the page
  is still read.
- **Markup in the user name.** Both tested firmware versions escape `<` in the
  logged user name, but hik-f2b does not rely on that: a firmware that does
  not would let an attacker type XML elements. Elements inside the user-name
  element are treated as part of the name, never as fields. An entry in which
  the address, time, user or type field appears more than once is never
  counted (`--dump` lists it as `AMBIG`).
- **Limits.** One result page may be at most 512 KiB, and one search reads at
  most 50 pages or 5000 entries. If a search stops at that cap, hik-f2b looks
  at the times of the entries it got. If the NVR lists the oldest entries
  first (both tested NVRs do), the next poll reads on from the newest entry
  read. If the NVR lists the newest first, the same poll reads the older part
  with further searches, at most 4 searches per NVR and poll. Each entry is
  counted once, also when a search stops in the middle of a second. Entries
  that 4 searches cannot reach are skipped with an ERROR line that gives
  their time range. A search that gets the same page twice (the NVR ignores
  the search position) is handled like one that stopped at the cap. A page
  without a paging status that hik-f2b knows is never taken for the last
  page. At most 10,000 addresses are tracked
  (the one whose latest failed login is the oldest is forgotten first), and at
  most 1000 bans
  wait to be applied (the oldest is dropped). A ban that cannot be applied
  within `bantime` (24 hours for a permanent ban) is dropped.
  `max_bans_per_hour` limits new bans and is kept across restarts; an address
  the router already lists does not use up the allowance. These bounds keep
  memory use from growing without limit, and the router's address-list as
  long as bans are timed. Permanent entries add up, by at most
  `max_bans_per_hour` an hour.
- **Never banned.** Networks in `ignoreip`, plus loopback (127.0.0.0/8),
  unspecified (0.0.0.0), broadcast (255.255.255.255), multicast, link-local
  (169.254.0.0/16), 0.0.0.0/8 and 240.0.0.0/4 whatever the config says.
  Setting `ignoreip` replaces the default list instead of adding to it, so
  repeat the private ranges if you still want them exempt. A ban that waits
  for the router is checked against `ignoreip` again before it is applied,
  and at startup. So if you add an address to `ignoreip` and restart
  hik-f2b, its waiting ban and its counted failed logins are dropped, with an
  INFO line for each address.
- **TLS.** Certificate verification cannot be turned off. An https router URL
  needs `ca_file`: with a path, only that CA is trusted; `ca_file = public`
  trusts the public CA roots built into hik-f2b, which has to be written out.
  Endpoints that receive a password or token must be https unless they are on
  this host. Redirects are not followed.
- **Passwords.** Only Digest authentication is used towards an NVR; a Basic
  challenge is never answered, even when the NVR offers both. The router's
  REST API uses Basic authentication, which is why it must be https. Secrets
  can come from files (`*_file`) or be written in the config; a warning is
  logged when a config with inline secrets is readable by other users. Secrets
  are never logged, and the Telegram token is removed from error messages.
  Health alerts quote error messages without the URLs in them.
- **Router account.** RouterOS grants rights by policy, not by menu. The
  `write` policy from the setup lets the account change almost all of the
  router's configuration, not only the firewall: for example NAT, routes,
  addresses, interfaces and DNS. Someone with the router password could open
  your network to the internet or take it offline. The `read` policy lets the
  account read the configuration. Passwords and other secrets stay hidden from
  it, because the group has no `sensitive` policy. These limits apply today:
  the account can log in only from the host's address
  (`address=HOST_IP/32`), and the REST API answers only that address
  (`www-ssl` with `address=HOST_IP/32`). The `api` policy also lets the
  account use the RouterOS API, which the setup does not limit by address;
  the account's own address limit applies there too. The group has no
  `policy` policy, so the account cannot add users or change their rights.
  It has no `reboot` policy, and no policy to log in over SSH, WinBox, the
  web interface, FTP, Telnet or the console. Keep the router password as
  safe as the router's admin password.
- **Country database.** The `.mmdb` file is untrusted input too. The reader
  (`src/country.rs`) checks every offset, bounds the search-tree walk, the
  nesting, the pointers followed and the number of fields decoded, never
  allocates much, and lets nothing out of the file but a code of two capital
  letters. A broken file costs the country, never a ban.
- **Self-restraint.** If an NVR rejects hik-f2b's own login, it makes at most
  two refused login attempts (the second only when the NVR's reply shows its
  nonce has changed), then leaves that NVR alone for `auth_backoff` seconds.
- **Small footprint.** No listening sockets, no shell, no interpreter. The
  container image is a single static binary running as an unprivileged user;
  the deploy files run it with a read-only filesystem and no capabilities.
- **Dependencies.** Versions are pinned in `Cargo.lock`, and CI runs
  `cargo audit` on every push and pull request and weekly. GitHub disables
  scheduled workflows after 60 days without activity in the repository, so the
  weekly run stops on a quiet repository until it is re-enabled.

What it does not protect against:

- Vulnerabilities in the NVR that need no login.
- An attacker already inside your network.
- Tampering with plain HTTP between the host and an NVR. Someone who can change
  that traffic can forge log entries and get arbitrary public addresses banned
  (no more than `max_bans_per_hour`; with `bantime = permanent` they stay
  until removed by hand). Because the drop rule works by source address on the
  WAN side, a banned address is also blocked for your LAN. They can also
  capture a Digest exchange and try to guess the password offline. Keep the
  host and the NVRs on a network you trust. Or, if the NVR supports https, use
  https to the NVR.
- A firmware that both leaves `<` unescaped in the logged user name and
  stores names of roughly 150 characters or more. Such a name can form a
  complete, well-formed forged entry with another address in it, which the
  rules above cannot tell from a real one. Both NVRs tested here escape `<`
  and cut the logged name to 15 characters, so they are not affected.
- A ban is per address, so it also affects anyone sharing that address.

Never attach your real config, router export or `--dump --raw` output to an
issue unchanged. They hold passwords, public addresses and serial numbers, and
an issue is public. First remove passwords and public addresses. To report a
vulnerability, see [SECURITY.md](SECURITY.md).

## Limitations

- IPv4 only.
- Detection lags by up to `poll_interval` seconds.
- Timed bans are address-list entries with a timeout, which RouterOS does not
  keep across a reboot. After a router reboot an address is banned again once
  it reaches `maxretry` new failed logins. Permanent bans (`bantime = permanent`)
  are static entries and survive a reboot.
- Field names in log search results vary between firmware versions. hik-f2b
  looks for the time, address and user under several field names, but unusual
  firmware may need a `log_filter` or `meta_id` change. If an entry has
  `<ipAddress>`, the other address names are not used.
- A firmware that does not escape `<` in the logged user name: a user name
  with `<` can make its entry unreadable. Such an entry is skipped with a
  WARNING line that names the NVR, and its failed login is not counted. So
  an attacker on such a firmware could avoid a ban. Both tested firmware
  versions escape `<`.
- If the NVR answers but its log cannot be read 10 polls in a row, hik-f2b
  skips the unreadable stretch of the log with an ERROR line; failed logins in
  it are not counted.
- An NVR that lists the newest entries first can have more entries in one
  poll's window than 4 searches read. Then the oldest part is skipped with an
  ERROR line, and failed logins in it are not counted. Both tested NVRs list
  the oldest entries first.
- More entries in one second than one search returns (3200 on the tested
  NVRs) cannot all be read. hik-f2b logs a warning and moves on.
- A clock change on an NVR together with a flood of log entries: after the
  change hik-f2b records what the log holds as already seen, with one search.
  If the `lookback` overlap alone holds more entries than one search returns,
  the rest is counted on the next poll, also entries from before the change.
  This is known and not fixed yet.
- Only MD5 Digest authentication is supported towards the NVR.
- Only MikroTik RouterOS is supported as the firewall.
- The drop-rule check only looks for an enabled `raw` or `filter` rule with
  the address-list as `src-address-list`. A rule in the wrong chain, on the
  wrong interface or with an action that does not drop still passes it.
- Health alerts need hik-f2b to be running. A stopped service or a host that
  is down sends nothing. To detect this, watch the service from outside.

## Tested hardware

| Device | Firmware | Result |
| --- | --- | --- |
| DS-7616NI-Q1 | V4.72.109 build 230107 | Failed logins are read and counted; a real brute-forcer was banned and stopped appearing in the log. |
| DS-7732NXI-K4 | V4.83.013 build 241227 | Failed logins made on purpose over HTTP and from iVMS-4200 are read correctly: same format as above, over HTTP with an extra `additionInformation` field. No real attack to test a ban against. |
| MikroTik RB5009, RouterOS | 7.18.1 | Setup commands work as written. Bans are added over REST with the CA certificate verified, repeated bans are recognised, entries expire on time, and the `raw` rule drops the banned address's packets. |

The container image was run with a read-only filesystem, no capabilities,
Podman secrets and a memory limit. A 25-minute unattended dry run against both
NVRs had no rejected logins and no failed polls.

The published `linux/amd64` image was pulled from ghcr.io (first as release
candidate 0.3.0-rc.1) and run against both NVRs and the router with `--check`,
`--country` and `--dump`, and 0.3.0 runs as the service; the earlier tries
above used an image built on the host from the Containerfile.

The country reader was tried with the DB-IP Country Lite file of November
2026 and the MaxMind GeoLite2 Country file of 17 November 2026 (both an IPv6
tree with 24-bit records): for 3000 addresses in each, `--country` gave
exactly what a separately written reader of the format gave, and `--check`
showed the database. The two files gave a different answer for about 4 % of
those addresses.

A real ban by the running service was reported in a Telegram forum topic.

A permanent ban was tried on the RB5009 (RouterOS 7.18.1) with the request
that hik-f2b sends for `bantime = permanent`: a PUT to the address-list
without a timeout. It created a static entry (`dynamic` false, no timeout).
The same request sent again was refused with "already have such entry", and
`--test-ban` for that address reported it as already in the address-list. The
entry was removed afterwards.

Health alerts were tried with a second hik-f2b instance in dry run, with
`alert_after = 1m`, one NVR made unreachable and an address-list that no drop
rule uses. One minute after the start it sent both health alerts (an NVR that
cannot be read, banned addresses that are not blocked) to a Telegram forum
topic. When the NVR was reachable again, it sent the recovery notice. The
checks behind the alerts were also run with `--check` against both NVRs and
the router: the drop-rule check found enabled rules in `raw` and in `filter`
and left a disabled one out.

CI (GitHub Actions) tries the deploy files on every push, with a dummy config
only: the router and the NVR are addresses that nothing answers, the secrets
are dummy values.

- The image built in CI is started with `deploy/compose.yaml` on Docker
  Compose, and its binary with `deploy/hik-f2b.service` on systemd 255
  (Ubuntu 24.04). Each runs once as it is and once with the Telegram secret
  enabled. The checks: hik-f2b reads the config, the CA file and every secret
  file, runs as the unprivileged user without capabilities on a read-only
  root filesystem, writes its state file and stops cleanly.
- Quadlet (Podman 4.9) accepts `deploy/hik-f2b.container` in a dry run.
- The test suite (fake NVR, fake router, fake Telegram, the country reader)
  runs on GitHub's arm64 runner as well as on amd64.

Not yet tried:

- A permanent ban made by the running service after real failed logins, and
  whether a permanent entry is still there after a router reboot.
- The Compose file and the systemd unit with real devices: CI starts them
  with a dummy config only. The Quadlet unit runs rootless on Debian 13 with
  Podman 5.4.
- Compose with podman-compose or rootless Docker.
- The `linux/arm64` image on any arm64 device. It is built natively on
  GitHub's arm64 runner, the build checks that it prints its version, and the
  test suite runs on that runner, but the image has not been run with real
  devices.
- The daily health reminder, and a health alert for a real unplanned outage.
- The refused-ban alert with a real router user that has no `write` policy.
  The tests use a fake router that answers HTTP 400 with "not enough
  permissions"; the exact answer of RouterOS was not checked.
- An NVR that lists log entries newest first: no such NVR is known, so only
  the fake NVR of the tests does this.
- The page size in the second `--check` line with real NVRs: their logs held
  too few entries to show it. The order was shown for one NVR (oldest first;
  the other had no entries in the last 24 hours), and the clock difference
  for both.
- The handling of clock changes from 0.3.2 (a small correction backward, a
  change while the log cannot be read) on real NVRs: only the tests and the
  simulation make these happen.
- Notify-only mode on real devices.
- A ban with a country on real devices: only `--country` and `--check` were
  run against a real database file.
- MaxMind GeoLite2 City and IPinfo Lite database files.
- Running for days or weeks.

What real devices showed:

- A failed login is logged as `log.hikvision.com/Exception/illlegealAccess`
  (the spelling is the firmware's), with the remote address in `<ipAddress>`.
- One failed login gives one entry: over HTTP on both devices, and from
  iVMS-4200 over the device (SDK) port on the DS-7732NXI-K4.
- A wrong password is logged with the user name that was tried. A user name
  that does not exist is logged as `illegal usernam` when it comes over the
  device port, and under the name itself over HTTP. Every entry is counted.
- `<` and `>` in a user name are stored escaped, and the name is cut to 15
  characters (both firmware versions).
- Timestamps are the device's local time with a `Z` suffix.
- A page holds at most 64 entries regardless of `maxResults`.
- A log search lists the entries oldest first (both devices, checked in
  November 2026).
- An unknown log type in `meta_id` gives HTTP 400 on one firmware and an empty
  result on the other, so narrow `meta_id` only after `--dump` confirms it.

`--check` shows the order and the page size of the NVR it talks to.

If you run hik-f2b on other hardware, please open an issue or PR. Include your
NVR model, firmware version, RouterOS version and the output of `--check`.

## Development

```bash
cargo test
cargo clippy --all-targets -- -D warnings
```

The tests run the real client code against an in-process fake NVR (which
verifies the Digest response), a fake RouterOS REST API and a fake Telegram
Bot API. The country reader is tested against small databases made by a
test-only writer (`tests/support/mmdb.rs`), including thousands of corrupted
ones. A Rust toolchain is all that `cargo test` needs.

`tests/sim.rs` runs the real engine through generated scenarios against the
fakes and checks invariants after every poll; its module comment lists them.
Each scenario comes from a seed. To run more seeds, set `HIK_F2B_SIM_SEEDS`
(seeds per class) and `HIK_F2B_SIM_START` (the first seed). To replay one
seed and print its trace, set `HIK_F2B_SIM_SEED`.

The decision logic (`src/engine.rs`) talks to the router and to Telegram only
through the `Firewall` and `Notifier` traits in `src/action.rs`, so another
firewall or messenger can be added by implementing one trait. When a problem
is worth a health alert is decided in `src/health.rs`, which does no I/O and
is tested on its own.

CI also runs `.github/scripts/repo-guard.sh`, which keeps addresses of real
devices and other private data out of the repository, and
`.github/scripts/docs-check.sh`, which keeps the two READMEs in step and
checks links and terms. How to run them and enable the git hooks:
[AGENTS.md](AGENTS.md).

## License

MIT, see [LICENSE](LICENSE). Not affiliated with Hikvision or MikroTik.
