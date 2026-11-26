# The firewall check round is a module of its own

Release 0.5.0 added two steps to every firewall check that the router
answers: the write of the safe list (ADR 0006) and the look-up and removal
of own addresses in the address-list (ADR 0005). Both went into
`src/engine.rs`, with the two sets they remember between checks, and the
check at the start and the periodic check became near copies of each
other. That put rules back into the engine, the module that ADR 0001 had
left as a loop, and the engine's unit tests did not reach them.

We decided to give the round its own module, `src/round.rs`: a firewall
check, then, when the router answered it, the write of the safe list and
the look-up of the own addresses. The round calls the `Firewall` interface
itself, writes its log lines itself and keeps the own addresses it has kept
in the safe list and those it has reported as listed. It hands the engine
one outcome (`round::Ended`), which the engine passes on to health in one
call (`Health::round_ended`) and, for the notifications, to the outbox.
The engine only decides when a round runs (at the start, and when health
says a check is due) and passes the stop flag on. The check at the start
and the periodic check are one function with a parameter: they differ only
in the level of their log lines and in one suffix.

The `Firewall` interface became narrower with it: it speaks in intents (is
this own address listed; remove the entries of this own address), and the
router's entry ids stay inside the RouterOS adapter.

## Considered options

- A round shaped like the ban ledger, with no I/O, that is told what the
  router answered. Rejected: the round asks the router one or two
  questions per own address, and what it asks next depends on the answer
  before (a write that finds the router unusable ends the writes, a failed
  look-up ends the look-ups, the stop flag is looked at before each
  request). That would need an exchange of asks and answers per address
  between the engine and the round, which is the round's logic split in
  two.
- Leave the round in the engine and test it through the end-to-end tests
  only. Rejected for the reason of ADR 0001: those rules are where defects
  came from, and they had no test at their own interface.

## Consequences

The round's unit tests use an in-memory `Firewall` adapter, the only one
(ADR 0002). The end-to-end tests and the simulation still drive the round
through the fake router over HTTP. The service now uses one router client:
the size of the address-list that the start logs is asked through the
engine (`Firewall::count`).
