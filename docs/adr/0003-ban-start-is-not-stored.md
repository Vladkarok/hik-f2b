# The start of a ban is not stored

The ban ledger derives when a ban began from the end it remembers less the
current `bantime`, so after a restart with another `bantime` failed logins
logged just before a ban can raise a false `ban-bypassed` warning. We store
no start and keep the state file at version 2; instead, for one grace
period (two polls and a minute) after the engine starts, an address found
already listed is not taken for a bypass, because a real bypass repeats and
is reported after that period.

## Considered options

- A version 3 state file that stores the start of each ban. Rejected: an
  image of an earlier version, started after a rollback, could not read it,
  and the gain is one false alert in a narrow case.

## Consequences

For one grace period after every start, also without a change of
`bantime`, a banned address that reaches an NVR is logged at INFO only. A
ban that does not block is reported from its next sighting after that
period. A host clock that goes back ends the period, so it never lasts
longer than one grace period.
