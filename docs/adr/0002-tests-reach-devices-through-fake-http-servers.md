# Tests reach the devices through fake HTTP servers, not through trait fakes

The end-to-end tests and the simulation test start fake NVR, router and
Telegram servers on loopback and give hik-f2b their URLs. A reader of
`src/action.rs` sees the `Firewall` and `Notifier` traits and may expect
in-memory fakes of them instead. We keep the HTTP fakes as the main way to
test, because the defects that came from the devices were in parsing, paging
and authentication, which a trait fake would skip.

In-memory adapters exist in two places only, where a module is pure enough
for unit tests without a network: the log source of the NVR log reader, and
a `Notifier` that records what it was given. The `Firewall` trait has no
in-memory adapter: the ban ledger has no I/O and needs none.

## Consequences

The fake servers cost threads and sockets, and a long simulation run needs
its loopback traffic out of the kernel's connection tracking (see
`.github/workflows/sim.yml`). `tests/fake_leak.rs` checks that a test leaves
no thread or socket behind.
