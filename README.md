# hik-f2b

**English** | [Українська](README.uk.md)

fail2ban-style protection for Hikvision NVRs that sit behind a MikroTik router
with their ports forwarded to the internet.

hik-f2b polls the NVR's own log for failed logins and counts them per source
IPv4 address. When an address reaches `maxretry` failures within `findtime`
seconds, hik-f2b adds it to a firewall address-list on the router, with a
timeout (`bantime`) or permanently. The router drops that address from then
on. Optionally it reports every ban to a Telegram chat, and tells you when it
cannot do its job (see [Health alerts](#health-alerts)). Without a router it
can run in [notify-only mode](#notify-only-mode-no-router): it reports such
addresses and bans nothing.

The container image holds one static binary of about 2 MB. While running it
uses about 2 MB of memory. It listens on no port.

> **Status: beta.** Verified on real devices (see
> [Tested hardware](#tested-hardware)): failed logins are read, the address is
> banned, and the router drops its traffic. It has not yet run unattended for
> days or weeks, and several parts have not been tried at all (listed under
> [Tested hardware](#tested-hardware)). Start with `dry_run = true`.

## Why

A router cannot tell a wrong password from a right one: it only sees TCP
connections, and a client app opens a burst of connections just to show a
camera grid, so rate limits on the router ban real users. The NVR does know,
and it writes every failed login with the remote IP to its log. hik-f2b
connects the two.

```
attacker ──► MikroTik ──dst-nat──► NVR ── writes "Illegal Login" + IP to its log
                 ▲                                │
                 │  REST: add IP to               │  ISAPI: POST /ISAPI/ContentMgmt/logSearch
                 │  address-list, timeout=bantime ▼
                 └──────────────────────────── hik-f2b ──► Telegram (optional)
```

## Is this the right tool?

Exposing an NVR to the internet is a risk that no ban list fully removes:
several Hikvision vulnerabilities needed no password at all. In order of
preference:

1. Do not forward ports. Use a VPN, or the vendor's cloud relay.
2. If you must forward ports, keep firmware current, forward only what the
   client app needs, restrict by source country or network if you can, turn
   UPnP off on the router, and keep the NVR's built-in illegal login lock
   enabled.
3. Then add hik-f2b, which turns the NVR's 30-minute lock into a router-level
   ban of any length and covers all your NVRs at once.

Related projects: [fail2ban](https://github.com/fail2ban/fail2ban) with a
[MikroTik action](https://github.com/pincioc/fail2ban_mikrotik) works if your
device can send logs to syslog, and
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

Replace `192.168.88.1` with the router address the host will connect to, and
`HOST_IP` with the address of the host running hik-f2b. Run the commands one at
a time; signing takes a few seconds. Use only Latin characters: the RouterOS
terminal rejects others.

HTTPS for the REST API, reachable only from the hik-f2b host. RouterOS will not
self-sign a server certificate, so a small local CA (certificate authority)
signs it:

```
/certificate add name=f2b-ca common-name=f2b-ca days-valid=3650 key-usage=key-cert-sign,crl-sign
/certificate sign f2b-ca
/certificate add name=rest-api common-name=192.168.88.1 subject-alt-name=IP:192.168.88.1 days-valid=3650 key-usage=digital-signature,key-encipherment,tls-server
/certificate sign rest-api ca=f2b-ca
/ip service set www-ssl certificate=rest-api address=HOST_IP/32 disabled=no
```

A dedicated account that can only be used from that host:

```
/user group add name=f2b policy=read,write,api,rest-api
/user add name=f2b group=f2b address=HOST_IP/32 password=CHANGE_ME
```

`write` is needed to add bans. `read` lets hik-f2b read the firewall rules,
which it does to check that the rule below exists.

The rule that actually blocks:

```
/ip firewall raw add chain=prerouting in-interface-list=WAN src-address-list=cctv_ban action=drop comment="hik-f2b: drop banned"
```

The rule lives in `raw`, ahead of connection tracking and fasttrack, so it also
cuts connections the banned address already has open. It drops packets by
source address on the WAN side, so it also drops replies from a banned address
to connections that your own LAN opened. hik-f2b checks at startup and every 5
minutes that such a rule exists and is enabled, and alerts you if it is gone
(see [Health alerts](#health-alerts)).

Export the CA certificate:

```
/certificate export-certificate f2b-ca
```

This creates the file `cert_export_f2b-ca.crt` in the router's files. Copy it to
the host and name it `router-ca.crt`; the steps below and the example config
expect that name. hik-f2b trusts only this CA when it talks to the router.

### 2. NVR

Create a user named `f2b` with the *Operator* level and a single permission:
**Remote: Log Search / Interrogate Working Status**. Do not use the admin
account.

### 3. Host

Copy [hik-f2b.example.ini](hik-f2b.example.ini) to `hik-f2b.ini` and edit it.
Addresses and thresholds go in the config. Passwords should go in separate
secret files that the config only points to (`password_file = ...`).

The container image is published on GitHub's container registry as
`ghcr.io/vladkarok/hik-f2b`, for `linux/amd64` and `linux/arm64` (the arm64
image is built natively but has not been tried on real hardware). The deploy
files use an exact version; fetch it with:

```bash
podman pull ghcr.io/vladkarok/hik-f2b:0.3.0
```

How versions are tagged and how to update: see
[Versions and updates](#versions-and-updates).

**Building the image yourself** instead of pulling it: build it from the
repository with the [Containerfile](Containerfile):

```bash
podman build -t hik-f2b -f Containerfile .
```

Podman then knows it as `localhost/hik-f2b:latest`. Put that name in the
`Image=` line of the unit (or `image:` in the Compose file) and in the
commands below; the deploy files have it as a commented-out line.

**Podman (rootless), recommended.** Use
[deploy/hik-f2b.container](deploy/hik-f2b.container), a Quadlet unit (a file
from which Podman generates a systemd service):

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

Inside the container hik-f2b runs as uid 65532. In a rootless container that
user is not you, so it can read the config and the CA certificate only if they
are world-readable. That is why they are `644` here. They hold no secrets as
long as the passwords come from Podman secrets (`password_file`). Do not put
passwords inline in a world-readable config.

**Docker Compose:** see [deploy/compose.yaml](deploy/compose.yaml).
`docker compose pull` fetches the image it names. To build the image yourself,
run `docker build -t hik-f2b -f Containerfile .` and use the commented-out
`image: hik-f2b:latest` line.

**No container:** the systemd unit
[deploy/hik-f2b.service](deploy/hik-f2b.service) runs the binary in a sandbox
and passes the secrets as systemd credentials. A plain `cargo build --release`
on a glibc system gives a dynamically linked binary. To get the same static
binary as in the image, either copy it out of the image (Podman pulls the
image for the host's architecture; use `localhost/hik-f2b:latest` for one you
built yourself):

```bash
podman create --name hik-f2b-copy ghcr.io/vladkarok/hik-f2b:0.3.0
podman cp hik-f2b-copy:/hik-f2b ./hik-f2b
podman rm hik-f2b-copy
```

or build for the musl target (`rustup target add x86_64-unknown-linux-musl`,
then `cargo build --release --target x86_64-unknown-linux-musl`; the binary is
in `target/x86_64-unknown-linux-musl/release/`). The musl build needs a C
compiler for musl (the TLS library contains C code); this path has not been
tested.

### 4. Verify before enabling

Run these the same way you run the service. For the plain binary:

```bash
# Every NVR (login, clock, log search), the router and its drop rule, and
# whether Telegram is configured. One line per item; exits non-zero if
# anything failed. Bans nothing, sends nothing, does not touch the state file.
hik-f2b --config hik-f2b.ini --check

# What the NVR returns. Failed logins must be flagged MATCH and carry ip=...
hik-f2b --config hik-f2b.ini --dump --hours 72

# Router access. The address shows up in the list for 60 seconds.
hik-f2b --config hik-f2b.ini --test-ban 203.0.113.1

# Telegram, if configured.
hik-f2b --config hik-f2b.ini --test-notify
```

With rootless Podman, give the container the same config and secrets as the
unit does, and put the options after the image name, for example:

```bash
podman run --rm --network host \
  -v ~/.config/hik-f2b:/etc/hik-f2b:ro,Z \
  --secret hik-f2b-router,uid=65532,mode=0400 \
  --secret hik-f2b-nvr,uid=65532,mode=0400 \
  ghcr.io/vladkarok/hik-f2b:0.3.0 --dump --hours 72
```

`--check` works the same way: put `--check` in place of `--dump --hours 72`.
A healthy setup prints `ok` on every line, for example:

```
ok       nvr nvr1: login accepted, device time 2026-01-10T10:00:00Z, log search works
ok       firewall: 1 enabled rule(s) in /ip/firewall/raw with src-address-list=cctv_ban
off      telegram: not configured
```

If failed logins are listed without `MATCH`, look at their `metaId` and adjust
`log_filter`. If nothing is listed or the NVR answers `badXmlFormat`, rerun
with `--raw` and open an issue with the output (remove addresses first).
Entries flagged `AMBIG` have a repeated field and are never counted (see
[Security design](#security-design)). `--dump` prints times as the NVR's own
clock shows them.

### 5. Enable

```bash
systemctl --user start hik-f2b
loginctl enable-linger "$USER"
journalctl --user -u hik-f2b -f
```

At startup the log shows the mode (`mode: ban on MikroTik`, `mode: DRY RUN`
or `mode: notify-only`) and, with a router, how many entries the address-list
has and the result of the firewall check (`firewall check ok: ...` or
`firewall check failed: ...`).

## Versions and updates

hik-f2b uses [Semantic Versioning](https://semver.org/). Every release is
described in [CHANGELOG.md](CHANGELOG.md), published as a GitHub Release and
as these image tags:

| Tag | Meaning |
| --- | --- |
| `0.3.0` | Exactly this release. It never changes. Use this one. |
| `0.3` | The newest `0.3.x` release; moves with every bug-fix release. |
| `latest` | The newest release; moves with every release, including ones that need config changes. |
| `0.3.0-rc.1` | A release candidate, for trying out before `0.3.0`. Never `latest`, never `0.3`. |

Pin an exact version, as the deploy files do. Before 1.0, a new second number
(`0.3` to `0.4`) may need changes to your config; the changelog says so.

**Update:** read the changelog from your version up to the new one, try the
new image with `--check` (put it in the `podman run` command from
[Verify before enabling](#4-verify-before-enabling)), then change the tag in
the `Image=` line of `~/.config/containers/systemd/hik-f2b.container`, pull
and restart:

```bash
podman pull ghcr.io/vladkarok/hik-f2b:<new version>
systemctl --user daemon-reload
systemctl --user restart hik-f2b
journalctl --user -u hik-f2b -f
```

With Compose: change `image:`, then `docker compose pull` and
`docker compose up -d`.

**Roll back:** the same steps with the previous tag. Old tags stay published.

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

The time settings (`findtime`, `bantime`, `poll_interval`, `lookback`,
`auth_backoff`, `alert_after`) are in seconds, or a whole number with one suffix: `s`, `m`,
`h`, `d` or `w` (seconds, minutes, hours, days, weeks), for example `10m`,
`12h` or `7d`. A plain number is seconds. The limits in the table are in
seconds and are checked after the conversion, so `365d` is the longest timed
ban.

The default `ignoreip` is `127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12,
192.168.0.0/16`. If you set `ignoreip`, repeat the private ranges you still
need.

Failures are counted across all configured NVRs together.

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
the drop rule on or off, see [Health alerts](#health-alerts). Set it to
`false` if the address-list is blocked some other way, for example by a rule
that uses it as `dst-address-list` or on another device.

A state file written by an older version (format 1) is ignored: the daemon
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

If the address is already in the list, the router refuses a second entry and
hik-f2b counts the address as already banned; it does not change the existing
entry. Whenever the router refuses an entry and the error is not the known
duplicate message, hik-f2b asks the router whether the address is listed, so
this does not depend on the wording of RouterOS error messages. An address that is still listed with a timeout when you switch to
`permanent` therefore gets a permanent entry only the next time it is banned,
after the timed entry has expired. Remove the timed entry by hand if you want
that sooner.

### Telegram notifications

Create a bot with [@BotFather](https://t.me/BotFather), add it to the chat, and
add a `[telegram]` section:

```ini
[telegram]
bot_token_file    = /run/secrets/hik-f2b-telegram
chat_id           = -1001234567890
message_thread_id = 42
```

`chat_id` is a user, group or supergroup id (supergroups look like `-100…`) or
`@channelname`. `message_thread_id` is the topic of a forum supergroup; leave
it out for ordinary chats. `silent = true` delivers without sound, and
`enabled = false` turns the section off. `health_alerts = false` keeps
[health alerts](#health-alerts) out of the chat; they still go to the log.

The message text is set with `message`. `\n` starts a new line. Placeholders:
`{ip}`, `{action}`, `{bantime}`, `{nvr}`, `{user}`, `{count}`, `{findtime}`.
`{action}` is one of `banned for 1d00:00:00`, `banned permanently`,
`would be banned for 1d00:00:00 (dry run)`,
`would be banned permanently (dry run)` or
`detected, no firewall configured`. The default message is:

```
⛔ hik-f2b: {ip} {action}
NVR: {nvr}
User tried: {user}
Failed logins: {count} within {findtime} s
```

The text is sent without a parse mode, so nothing in it is read as markup.

A ban is applied before any notification is attempted. Notifications that
fail are retried on later cycles, at most 5 attempts each; at most 100 wait at
a time, and they are kept in memory only, so a restart loses them. An
unreachable Telegram costs at most one 10-second timeout per cycle.

### Notify-only mode (no router)

Leave out the `[mikrotik]` section. hik-f2b then bans nothing. When an address
reaches `maxretry` failures within `findtime`, it logs a `DETECTED` line and,
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

With the Quadlet unit, remove the `Secret=hik-f2b-router` line and enable the
`Secret=hik-f2b-telegram` line. `--test-ban` does not work in this mode.

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
  such a rule the list fills up and nothing is blocked. hik-f2b asks each table
  for the rules with that `src-address-list`
  (`GET /rest/ip/firewall/raw?src-address-list=cctv_ban&.proplist=.id,disabled`,
  then the same for `filter`) and counts a rule as enabled unless the reply
  says `"disabled":"true"`: RouterOS 7.18 leaves the `disabled` property out
  of enabled `raw` rules altogether. The check does not look
  at the rule's chain, interface or action, so a rule that matches the list
  but accepts the traffic still passes. Turn the check off with
  `check_rule = false` in `[mikrotik]`.
- **The ban rate limit:** addresses are waiting because `max_bans_per_hour` has
  been reached.

The router checks also run in a dry run, where they help with the setup. In
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
each recovery one INFO line (`health recovered [...]`). What hik-f2b remembers
about problems is kept in memory only: after a restart a problem that is still
there is reported again once it has lasted `alert_after`.

Health alerts cannot report that hik-f2b itself has stopped, crashed or hangs,
or that its host is down or offline: then nothing is left to send a message.
Watch the service from outside for that, for example with your monitoring
system checking that the systemd unit or container is running.

## Time and clock changes

Each NVR's log is in that device's local time. On every poll hik-f2b reads the
NVR's clock and converts each failure to the host's clock with that NVR's
current offset. So NVRs may have different clocks or time zones. Times in
hik-f2b's own log lines and in the router comment are host time in UTC. Lines
marked "(device time)" and the output of `--dump` show the NVR's clock.

If an NVR's clock goes back further than the `lookback` overlap (a DST change,
a reset real-time clock), or jumps forward by more than 15 minutes, hik-f2b
logs a warning, records the entries the log holds at that moment as already
seen without counting them, and reads on from the new time. Failures in the
short window around the jump are not counted. Smaller corrections are covered
by the overlap.

Entries older than `findtime` are never counted, and neither are entries more
than 5 minutes in the future (host time).

## Avoiding false positives

- `maxretry` counts log entries. On the tested devices one failed login gives
  one entry, so three mistyped passwords count as three. This was checked over
  HTTP (web interface, ISAPI) on both devices and from iVMS-4200 over the
  device (SDK) port on one. A wrong password and a user name that does not
  exist are both logged and count the same. Other firmware or client apps may
  differ: make one deliberate mistake and look at `--dump` if it matters to
  you.
- The counter for an address empties once its failures are older than
  `findtime`.
- LAN and hairpin-NAT clients, and VPN clients with private addresses, are
  covered by the default `ignoreip`. Some VPNs use 100.64.0.0/10 (Tailscale,
  carrier-grade NAT), which the default does not cover. Add such ranges, and
  your own public addresses (office, monitoring host), to `ignoreip`, keeping
  the private ranges in the list.
- A client app with a stale saved password retries on its own and reaches the
  threshold quickly. Update saved passwords right after changing one.
- Mobile carriers put many subscribers behind one address (CGNAT). A ban on
  such an address can hit a legitimate user on the same carrier, which is a
  reason to keep `bantime` moderate.
- `bantime = permanent` has a cost. Many attacking addresses are dynamic or
  shared (CGNAT, cloud and hosting ranges). Once the attacker has moved on, the
  address can go to someone else, who is then shut out of your NVR, perhaps
  months later. Nothing ever removes a permanent entry, so the list only grows
  and you have to review and prune it by hand. The comment of each entry holds
  the NVR, the user name tried and the time (UTC) of the failure that triggered
  the ban.
- To see the list on the router:
  `/ip firewall address-list print where list=cctv_ban`
- To lift a ban, remove the entry on the router:
  `/ip firewall address-list remove [find list=cctv_ban address=X.X.X.X]`
- To empty the whole list (timed and permanent bans):
  `/ip firewall address-list remove [find list=cctv_ban]`

## Security design

hik-f2b holds credentials for your NVRs and write access to your router's
firewall, and it reads text that attackers control (the user name in a failed
login is whatever they typed). It is built accordingly:

- **Memory safety.** Rust with `unsafe` forbidden in this crate, and integer
  overflow checks kept on in release builds.
- **Hostile input.** The address is taken only from the entry's address field,
  never from free text or the user name, and must parse as an IP address.
  `::ffff:a.b.c.d` is treated as the IPv4 address it wraps; other IPv6
  addresses are logged and not counted. User names are cut to 32 characters
  and reduced to printable ASCII before they reach a log line, the router or
  Telegram. Request bodies are built with escaping, Telegram messages are sent
  without a parse mode, and control characters never reach the log. Invalid
  UTF-8 and characters that XML forbids are replaced. Each log entry is parsed
  on its own: one that cannot be parsed (not well-formed XML, or more markup
  than any real entry has) is skipped with a warning, and the rest of the page
  is still read.
- **Markup in the user name.** Both tested firmware versions escape `<` in the
  logged login name, but hik-f2b does not rely on that: a firmware that does
  not would let an attacker type XML elements. Elements inside the user-name
  element are treated as part of the name, never as fields. An entry in which the address, time, user or type field appears more
  than once is never counted (`--dump` lists it as `AMBIG`).
- **Limits.** One result page may be at most 512 KiB, and one poll reads at
  most 50 pages or 5000 entries per NVR. At most 10,000 addresses are tracked
  (the one with the oldest failure is forgotten first), and at most 1000 bans
  wait to be applied (the oldest is dropped). A ban that cannot be applied
  within `bantime` (24 hours for a permanent ban) is dropped.
  `max_bans_per_hour` limits new bans and is kept across restarts; an address
  the router already lists does not use up the allowance. These bounds keep
  memory use from growing without limit, and the router's address-list as
  long as bans are timed. Permanent entries add up, by at most
  `max_bans_per_hour` an hour.
- **Never banned.** Networks in `ignoreip`, plus loopback (127.0.0.0/8),
  unspecified (0.0.0.0), broadcast (255.255.255.255), multicast, link-local
  (169.254.0.0/16), 0.0.0.0/8 and 240.0.0.0/4 whatever the configuration says.
  Setting `ignoreip` replaces the default list instead of adding to it, so
  repeat the private ranges if you still want them exempt.
- **TLS.** Certificate verification cannot be turned off. An https router URL
  needs `ca_file`: with a path, only that CA is trusted; `ca_file = public`
  trusts the public CA roots built into hik-f2b, which has to be written out.
  Endpoints that receive a password or token must be https unless they are on
  this host. Redirects are not followed.
- **Passwords.** Only Digest authentication is used towards an NVR; a Basic
  challenge is never answered, even when the device offers both. The router's
  REST API uses Basic authentication, which is why it must be https. Secrets
  can come from files (`*_file`) or be written in the config; a warning is
  logged when a config with inline secrets is readable by other users. Secrets
  are never logged, and the Telegram token is removed from error messages.
  Health alerts quote error messages without the URLs in them.
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
  WAN side, a banned address is also cut off for your LAN. They can also
  capture a Digest exchange and try to guess the password offline. Keep the
  host and the NVRs on a network you trust, or use https to the NVR where the
  device supports it.
- A firmware that both leaves `<` unescaped in the logged login name and
  stores names of roughly 150 characters or more. Such a name can form a
  complete, well-formed forged entry with another address in it, which the
  rules above cannot tell from a real one. Both devices tested here escape `<`
  and cut the logged name to 15 characters, so they are not affected.
- A ban is per address, so it also affects anyone sharing that address.

Never attach your real config, router export or `--dump --raw` output to an
issue without removing passwords and public addresses. To report a
vulnerability, see [SECURITY.md](SECURITY.md).

## Limitations

- IPv4 only.
- Detection lags by up to `poll_interval` seconds.
- Timed bans are address-list entries with a timeout, which RouterOS does not
  keep across a reboot. After a router reboot an address is banned again once
  it reaches `maxretry` new failures. Permanent bans (`bantime = permanent`)
  are static entries and survive a reboot.
- Field names in log search results vary between firmware versions. hik-f2b
  looks for the time, address and user under several field names, but unusual
  firmware may need a `log_filter` or `meta_id` change.
- If the NVR answers but its log cannot be read 10 polls in a row, hik-f2b
  skips the unreadable stretch of the log with an ERROR line; failed logins in
  it are not counted.
- Only MD5 Digest authentication is supported towards the NVR.
- Only MikroTik RouterOS is supported as the firewall.
- The drop-rule check only looks for an enabled `raw` or `filter` rule with
  the address-list as `src-address-list`. A rule in the wrong chain, on the
  wrong interface or with an action that does not drop still passes it.
- Health alerts need hik-f2b to be running. A stopped service or a host that
  is down sends nothing; watch the unit from outside for that.

## Tested hardware

| Device | Firmware | Result |
| --- | --- | --- |
| DS-7616NI-Q1 | V4.72.109 build 230107 | Failed logins are read and counted; a real brute-forcer was banned and stopped appearing in the log. |
| DS-7732NXI-K4 | V4.83.013 build 241227 | Failed logins made on purpose over HTTP and from iVMS-4200 are read correctly: same format as above, over HTTP with an extra `additionInformation` field. No real attack to test a ban against. |
| MikroTik RB5009, RouterOS | 7.18.1 | Setup commands work as written. Bans are added over REST with the CA certificate verified, repeated bans are recognised, entries expire on time, and the `raw` rule drops the banned address's packets. |

The container image was run with a read-only filesystem, no capabilities,
Podman secrets and a memory limit. A 25-minute unattended dry run against both
NVRs had no rejected logins and no failed polls.

Not yet tried:

- A ban notification through the real Telegram service. Only `--test-notify`
  to a forum topic was tried; the tests use a fake Bot API.
- A permanent ban (`bantime = permanent`) on a real router.
- The Compose file and the systemd unit in `deploy/`. The Quadlet unit runs
  rootless on Debian 13 with Podman 5.4.
- The published image `ghcr.io/vladkarok/hik-f2b`. The image tried above was
  built on the host from the Containerfile; no image pulled from ghcr.io has
  been run yet.
- The `linux/arm64` image on any arm64 device. It is built natively on
  GitHub's arm64 runner and the build checks that it prints its version, but
  it has not been run on real hardware.
- A health alert on real devices. The checks behind the alerts were run with
  `--check` against both NVRs and the router, where the rule check found
  enabled rules in `raw` and in `filter` and left a disabled one out; no real
  outage was provoked.
- Notify-only mode on real devices.
- Running for days or weeks.

What real devices showed:

- A failed login is logged as `log.hikvision.com/Exception/illlegealAccess`
  (the spelling is the firmware's), with the remote address in `<ipAddress>`.
- One failed login gives one entry: over HTTP on both devices, and from
  iVMS-4200 over the device (SDK) port on the DS-7732NXI-K4.
- A wrong password is logged with the user name that was tried. A user name
  that does not exist is logged as `illegal usernam` when it comes over the
  device port, and under the name itself over HTTP. Every entry is counted.
- `<` and `>` in a login name are stored escaped, and the name is cut to 15
  characters (both firmware versions).
- Timestamps are the device's local time with a `Z` suffix.
- A page holds at most 64 entries regardless of `maxResults`.
- An unknown log type in `meta_id` gives HTTP 400 on one firmware and an empty
  result on the other, so narrow `meta_id` only after `--dump` confirms it.

If you run hik-f2b on other hardware, please open an issue or PR with your NVR
model, firmware version and RouterOS version.

## Development

```bash
cargo test
cargo clippy --all-targets -- -D warnings
```

The tests run the real client code against an in-process fake NVR (which
verifies the Digest response), a fake RouterOS REST API and a fake Telegram
Bot API.

The decision logic (`src/engine.rs`) talks to the router and to Telegram only
through the `Firewall` and `Notifier` traits in `src/action.rs`, so another
firewall or messenger can be added by implementing one trait. When a problem
is worth a health alert is decided in `src/health.rs`, which does no I/O and
is tested on its own.

## License

MIT, see [LICENSE](LICENSE). Not affiliated with Hikvision or MikroTik.
