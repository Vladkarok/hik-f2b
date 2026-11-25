# Host names in ignoreip only exempt addresses

An administrator whose public address changes (a home connection) cannot
write it into `ignoreip`. Five wrong passwords from that address then ban
the administrator for `bantime`, and the administrator cannot reach the NVRs
until the ban ends or someone removes it on the router. Of the ways this tool
can hurt its owner, this lockout is the likeliest. We decided that
`ignoreip` also takes host names, for example a dynamic DNS name that
follows the administrator's address.

An item that is not an address or a network is a host name; its form is
checked when the config is read (at least two labels, letters, digits and
hyphens). hik-f2b resolves each name at startup and then at most every
5 minutes (`src/names.rs`), IPv4 only, with the resolver of the host
(`src/ignored.rs`, through the `Source` seam of `src/own.rs`). An address
that a name resolves to is exempt exactly like an address written in
`ignoreip`: it is not counted, and its waiting ban and counted failed logins
are dropped, also before a ban is applied. A failed look-up keeps the
addresses last found; a name that has never resolved exempts nothing. A name
that does not resolve is not a config error, because the resolver may be
down when hik-f2b starts.

The answer for a name is a source of exemption and of nothing else. These
addresses are not own addresses: hik-f2b never removes a ban for them (ADR
0005) and never writes them to the safe list (ADR 0006). The only other
names hik-f2b resolves are the hosts of the device URLs: it has to reach
those devices anyway, and their addresses are own addresses (ADR 0004).
Names are trusted for nothing more. A name that hik-f2b does not need for
reaching a device never gives an own address, and never a reason to remove
or write anything on the router.

## Considered options

- No names: write the address and change it by hand. Rejected: the address
  changes without notice, and the administrator learns it when the ban has
  already happened.
- Use the names for more: remove a ban of such an address from the
  address-list, or keep it in the safe list. Rejected: whoever controls the
  answer for the name could then also remove bans and get past the drop
  rule. An exemption only stops new bans, and an operator who reads the log
  sees each one with its name.
- Make a name that does not resolve a config error. Rejected: a resolver
  that is down at startup would stop the service, which then protects
  nothing at all.

## Consequences

Whoever controls the answer for the name can exempt any address from bans:
the DNS provider, whoever holds the account at the dynamic DNS service, and
whoever can forge answers on the path to the resolver. The README says so,
recommends a name under the operator's control and says that an address
written out is safer where it is stable.

When the name moves, the old address is counted again from its next failed
login; what was dropped while it was exempt does not come back. The
resolution on a real host has not been tried yet; the README says so under
"Not yet tried".
