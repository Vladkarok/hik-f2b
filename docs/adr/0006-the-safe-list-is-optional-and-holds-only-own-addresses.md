# The safe list is optional and holds only own addresses

hik-f2b never bans an own address (ADR 0004) and removes one that it finds
in the address-list (ADR 0005). Neither helps when the entry was made by
someone else and the router blocks the host before the next firewall check.
We decided to offer one more layer: with `safe_list` set in `[mikrotik]`,
hik-f2b keeps its own address toward the router (the local address of
`OwnAddresses::toward_router`, nothing else, and above all nothing read from
an NVR log) in that address-list, with a timeout of six firewall checks,
renewed at every check the router answers. The operator adds one rule above
the drop rule, in the same table and chain, that accepts packets from the
safe list. hik-f2b maintains the entry and checks that the rule exists and
comes first (`safe-list-rule`); it never adds or changes a firewall rule.

The setting is off by default. It costs a write to the router at every
check (four requests instead of none), and most setups do not need it: the
documented drop rule matches only packets from the WAN, and the host
reaches the router from the LAN.

## Considered options

- Always on. Rejected: a write to the router that most setups do not need,
  and an accept rule that the operator must add anyway.
- hik-f2b adds the accept rule itself. Rejected: hik-f2b changes no
  firewall rule; the operator decides where the rule goes, and a rule that
  a program moves can end up below the drop rule unseen.
- A static entry without a timeout. Rejected: an address that is no longer
  the host's would stay safe until removed by hand. With a timeout, an old
  address expires by itself, half an hour after the last check that renewed
  it.

## Consequences

The entry is renewed with `PATCH /rest/ip/firewall/address-list/<id>`, which
has not been tried on a real router yet; the README says so under "Not yet
tried". An entry without a timeout (made by hand) is left as it is. A dry
run writes nothing to the router and says once what it would write. The
protection ends where the router account ends: whoever holds it can remove
the rule or the entry.
