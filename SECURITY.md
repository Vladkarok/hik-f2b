# Security policy

hik-f2b holds credentials for your NVRs and write access to your router's
firewall, so bugs here can matter. How it is built to limit that, and what it
does not protect against, is described in the README under
[Security design](README.md#security-design).

**Reporting a vulnerability:** please do not open a public issue. Its details
would be public before a fix exists.

1. Use GitHub's "Report a vulnerability" button (Security tab → Advisories)
   on this repository.
2. Include these:
   - the hik-f2b version;
   - the RouterOS version;
   - the NVR model and firmware;
   - steps to reproduce.

**Supported versions:** fixes go into a new release of the newest version
line only (published as `ghcr.io/vladkarok/hik-f2b:X.Y.Z`, see
[CHANGELOG.md](CHANGELOG.md)). Update to it. Do not expect a fix for an older
line.

Things that are in scope: anything that lets a remote party get an arbitrary
address banned or get a ban removed, inject content into the router request,
the log or a Telegram message, leak credentials from the config, the logs or error
messages, exhaust the host's memory, or execute code on the host running
hik-f2b.

The limits the README already lists under "What it does not protect against"
(for example forged log entries from someone who can tamper with plain HTTP
between the host and an NVR) are known. A report that shows they are worse
than described is welcome.

Never attach your real config, router export or `--dump --raw` output to an
issue unchanged. They hold passwords, public addresses and serial numbers, and
an issue is public. First remove passwords, public addresses and serial
numbers.
