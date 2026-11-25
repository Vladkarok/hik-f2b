# Own addresses come only from the host's sockets and the config

hik-f2b never bans an own address: the router's and each NVR's address,
taken from the URLs in the config (resolved when they are names), and the
local address the operating system sends from to reach each of them (a UDP
socket connected to the device reports it; no packet is sent). We decided
that the set is built from these two sources and from nothing else, above
all from nothing read from an NVR log, and that this holds by construction:
`OwnAddresses::new` in `src/own.rs` takes the config and a `Source`, and no
method takes an address to add. The ban ledger is told the set with its
rules and looks nothing up.

## Considered options

- Treat the source address of hik-f2b's own rejected logins (as the NVR
  logs them) as an own address. Rejected: whoever can forge a log entry
  could then make any address exempt, or make hik-f2b's own address look
  like someone else's.
- An `own_address` setting. Rejected: the address changes with DHCP or a
  VPN, and a setting that is wrong protects nothing. `ignoreip` stays for
  what hik-f2b cannot find (an address behind NAT).

## Consequences

The set is looked up at startup and in every poll (a host name at most
every 5 minutes, `src/names.rs`); a failed look-up keeps what was last
found for that device. With NAT between the host and a
device, the device sees another address, which hik-f2b cannot know; the
operator puts it into `ignoreip`. `src/own.rs` has an in-memory adapter,
`Fixed`, next to the one of the operating system: a third place beside the
two that ADR 0002 names, because the fakes of the tests all listen on
loopback, which is never banned anyway, so only fixed answers can exercise
the rule.
