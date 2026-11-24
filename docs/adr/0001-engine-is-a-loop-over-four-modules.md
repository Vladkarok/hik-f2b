# The engine is a loop over a ban ledger, NVR log readers, health and an outbox

Until 0.4.0 `src/engine.rs` held every rule of a poll in one struct with
public fields, and had no unit test: the rules were reachable only through
the end-to-end tests. Most defects of 0.3.x and 0.4.0 were in those rules.
We decided to give each set of rules its own module with a small interface
and its own unit tests, and to leave the engine as the loop that connects
them:

- the **ban ledger** counts failed logins and decides which bans are due. It
  has no I/O;
- an **NVR log reader** per NVR owns the read cursor and the device clock,
  and gives the engine failed logins in host time;
- **health** turns what happened in a poll into health checks;
- the **outbox** queues notifications and sends them again after a failure.

The engine's fields are private. A change to how a ban is decided gets a
unit test at the ledger's interface, and an end-to-end test when it also
changes what a device is asked.

## Considered options

- Keep one engine and add unit tests of its private functions. Rejected:
  the tests would depend on the order of calls inside the engine, which is
  what kept changing.
- Split by device (NVR, router, Telegram). Rejected: the rules that broke
  are about time and counting, not about a device.

## Consequences

The split must not change what an operator sees: the hik-f2b log, the
notifications, the config and the state file stay as they were. The
simulation test gives the same counts for the same seeds before and after
each step.
