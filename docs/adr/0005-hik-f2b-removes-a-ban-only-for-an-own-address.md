# hik-f2b removes a ban only for an own address

hik-f2b adds entries to the address-list and leaves their end to the
router (the timeout) or to the operator (a permanent ban). An own address
in the address-list can cut hik-f2b off from the router and the NVRs, and
it was not put there by this version: hik-f2b never bans an own address
(ADR 0004). We decided that with every firewall check the router answers
(at startup and every 5 minutes) hik-f2b looks up each own address outside
the reserved ranges in the address-list and removes the entries it finds,
with a WARNING and a notification at once. This is the only case in which
hik-f2b removes a ban, and the `Firewall` interface says so.

## Considered options

- Only report it. Rejected: the router may block the host before anyone
  reads the message, and then hik-f2b cannot even remove the entry.
- Remove any entry that hik-f2b did not make. Rejected: the address-list is
  the operator's too, and hik-f2b does not remember what it made.

## Consequences

A dry run reports the entry once while it stays listed and removes
nothing; notify-only mode has no router to ask. A removal that fails is the
health check `own-address-listed`, which only a look-up that finds no own
address listed ends. Each firewall check costs one more request per own
address outside the reserved ranges, and none when the devices are on this
host.
