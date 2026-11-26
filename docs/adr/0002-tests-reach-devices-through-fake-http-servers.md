# Tests reach the devices through fake HTTP servers, not through trait fakes

The end-to-end tests and the simulation test start fake NVR, router and
Telegram servers on loopback and give hik-f2b their URLs. A reader of
`src/action.rs` sees the `Firewall` and `Notifier` traits and may expect
in-memory fakes of them instead. We keep the HTTP fakes as the main way to
test, because the defects that came from the devices were in parsing, paging
and authentication, which a trait fake would skip.

In-memory adapters exist in three places only, where a module is pure
enough for unit tests without a network: the log source of the NVR log
reader, a `Notifier` that records what it was given, and a `Firewall` in
the unit tests of the firewall check round (`src/round.rs`). Up to 0.5.0
the `Firewall` trait had none: the ban ledger has no I/O and needs none.
The rules that drive the firewall (the write of the safe list, the removal
of an own address, what ends a round) now live outside the ledger, in the
round, which calls the firewall itself
([ADR 0008](0008-the-firewall-check-round-is-a-module-of-its-own.md)); an
in-memory adapter lets its unit tests set each answer of the router and
see each request. It answers in intents and holds no RouterOS reply. The
HTTP fakes stay the main way to test: they still cover the parsing, the
paging and the authentication, and the end-to-end tests and the simulation
drive the round through them.

## Consequences

The fake servers cost threads and sockets, and a long simulation run needs
its loopback traffic out of the kernel's connection tracking (see
`.github/workflows/sim.yml`). `tests/fake_leak.rs` checks that a test leaves
no thread or socket behind.
