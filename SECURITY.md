# Security policy

hik-f2b holds credentials for your NVRs and write access to your router's
firewall, so bugs here can matter. How it is built to limit that, and what it
does not protect against, is described in the README under
[Security design](README.md#security-design).

**Reporting a vulnerability:** please do not open a public issue. Use
GitHub's "Report a vulnerability" button (Security tab → Advisories) on this
repository. Include the hik-f2b version, RouterOS version, NVR model and
firmware, and steps to reproduce.

**Supported versions:** fixes go into a new release of the newest version
line only (published as `ghcr.io/vladkarok/hik-f2b:X.Y.Z`, see
[CHANGELOG.md](CHANGELOG.md)). Update to it rather than expecting a fix for
an older line.

Things that are in scope: anything that lets a remote party get an arbitrary
address banned or un-banned, inject content into the router request, the log
or a Telegram message, leak credentials from the config, the logs or error
messages, exhaust the host's memory, or execute code on the host running
hik-f2b.

The limits the README already lists under "What it does not protect against"
(for example forged log entries from someone who can tamper with plain HTTP
between the host and an NVR) are known. A report that shows they are worse
than described is welcome.

Never attach your real config, router export or `--dump --raw` output to an
issue without removing passwords, public IP addresses and serial numbers.
