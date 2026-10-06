# The two modes

conflux runs an anchor one of two ways, and they are mutually exclusive. Not by
conflux's choice — anchor refuses a configuration that asks for both, before anything
starts.

This page is about what the machine gets out of the realm. What the anchor reaches
the realm *over* is a separate question with its own page — the host's IP network by
default, or a link named by `--uplink`, which works with either mode below. See
[uplink.md](uplink.md).

## TUN — `conflux up`

The daemon creates a real network interface — `anchor0` on Linux and Windows; macOS
numbers its own `utunN` and the BSDs their own `tunN` — and the host kernel owns the
overlay addresses. `ping`, `ssh`, a browser, anything on the machine can use the
overlay without knowing it exists. This needs `CAP_NET_ADMIN` on Linux, root on macOS
and the BSDs, Administrator and `wintun.dll` on Windows.

Because the kernel owns the address, a service published on the overlay is an ordinary
`bind` — there is no proxy to configure and conflux offers none.

### Exits

Both exit flags work in either mode, on `up` and on `proxy`:

```console
$ sudo conflux up --serve-exit      # be a way out to the public internet for the realm
$ sudo conflux up --use-exit        # send this machine's own internet over the overlay
```

They are alternatives — a machine can do either or neither, and anchor refuses both,
since an exit sends the internet out of this host and `--use-exit` sends this host's
internet to an exit — and both are off unless asked for. conflux passes them explicitly in whichever direction they were set
rather than letting the enrolment manifest supply them, because an anchor that became
an internet exit because a document said so is the worst kind of surprise. `--no-serve-exit`
and `--no-use-exit` are the way back.

An exit with an interface forwards out of the host, which anchor sets up on Linux; see
[`--subnet`, and what the host has to be](#--subnet-and-what-the-host-has-to-be),
which has the same requirement for the same reason. In userspace `--use-exit` covers only
the anchor's own traffic, since nothing else on the host sees the overlay.

## Userspace — `conflux proxy`

The overlay lives entirely inside the daemon, in a userspace network stack. Nothing on
the host can see it, there is no interface, and no privilege is required to run it.
The way in is a reverse proxy you name:

```console
$ sudo conflux proxy 8080=127.0.0.1:3000
```

A peer connecting to overlay port 8080 gets a fresh connection to `127.0.0.1:3000`.
The backend is dialled per connection and is not resolved in advance, so a name that
does not resolve yet is legitimate.

conflux still needs root to *register the boot service* — a proxy that vanishes on the
next reboot is not what anyone asked for — but the anchor itself needs nothing.

The way out is a subnet or an exit, which this mode serves too: a **userspace router**.
Every connection a peer sends through it ends inside the anchor's own process, which
dials the destination from an ordinary socket of its own, TCP and UDP, so the far end
sees this host's address, as it would behind a translating router. Nothing on the host
is set up and no privilege is needed for that either. With `--subnet` or `--serve-exit`
the port specs may be left out:

```console
$ sudo conflux proxy --subnet 192.168.1.0/24 --serve-exit
```

An IPv4 works in both modes. Here the anchor's own stack holds it, so a peer reaches
the published ports at it as well as at the overlay IPv6 address.

## Why they cannot be combined

A rule of anchor's, and a fact about it:

**A reverse proxy needs userspace.** With a host interface the kernel owns the overlay
address, so binding it is an ordinary `bind` and a proxy would be a second, redundant
path to the same port. anchor refuses the combination rather than pick one.

**And one daemon holds one anchor.** So even setting the rule aside, a machine is in
one mode at a time. The same sentence is why an anchor has one uplink or one socket
and never both, though that is the medium and not the mode.

conflux checks all of this locally, before it starts anything, so the error names the
flag you typed rather than arriving from a child process as a gRPC status.

## Finding the realm, in either mode

Neither mode changes how an anchor finds its realm, and `--lan-discovery` is available
on both because of it. Three sources are tried together: the bootstrap list enrolment
supplied (or `--peers`), the addresses that have worked before, and a link-scoped probe
of the networks this host is attached to. The third is the one that setting names.

It is additive and cannot be anything else. The probe is sealed under the realm's root
public key, which a machine holds only after it has enrolled — so discovery decides who
is worth dialling, never who is let in, and a node with discovery off still finds the
realm through the list it was given. Turning it off is a privacy choice, not a
connectivity one: a probe tells every host on the link that an anchor is here and which
tree it belongs to, and a laptop repeats that on every network it joins. Nothing in it
identifies the anchor.

With `--uplink` it is off — there is no host network to probe and nothing on a cable to
answer — and only an explicit `--lan-discovery yes` is refused there. `auto` is passed to
anchor as `no` on a link, because anchor refuses a yes there and would otherwise take one
from the manifest. A machine configured once and later moved onto a link keeps starting.

## Switching

Running one replaces the other, and conflux says so:

```console
$ sudo conflux proxy 8080=127.0.0.1:3000
conflux: this machine was running in TUN mode with interface anchor0.
  Userspace mode replaces that: one daemon holds one anchor, and an anchor with
  a host interface cannot also serve a reverse proxy …
```

The identity does not change. Only the mode does — along with what belonged to the
other one: switching to TUN clears the proxy specs, which only userspace serves.
Everything else is kept — the subnets and exits, which either mode routes, and the IPv4,
the taints, which are the credential's, the uplink, the peers, the port and low latency.
`--no-subnet`, `--no-serve-exit` and `--no-use-exit` are the way back from routing on
either verb.

## Proxy specs

The grammar is `OVERLAYPORT[/NETWORK]=BACKEND`.

| Spec | Means |
|---|---|
| `8080=127.0.0.1:3000` | TCP on overlay port 8080 → `127.0.0.1:3000` |
| `53/udp=127.0.0.1:53` | UDP on overlay port 53 → `127.0.0.1:53` |
| `5432=[::1]:5432` | an IPv6 backend, bracketed |

The network defaults to `tcp` and must be `tcp` or `udp`. The port is 1–65535. The
backend is `host:port`, dialled per connection, so a named port is as good as a number.
Repeat the argument for more than one; conflux refuses a duplicate overlay port rather
than silently keeping the last.

## `--subnet`, and what the host has to be

`conflux up --subnet 192.168.1.0/24` — or the same on `conflux proxy` — offers to
forward that network to the rest of the realm. An entry is an interface name, a prefix,
or `*`. An interface name expands to every private network on it, so `eth1` follows
DHCP, and `*` is every private network on every interface — quote it, `--subnet '*'`,
or the shell expands it. Private networks only — RFC 1918, carrier-grade NAT
`100.64.0.0/10` and unique local IPv6, each wholly inside one of those — because
reaching the public internet through an anchor is what an exit is for. A prefix is the
network, so `192.168.1.7/24` is refused with the `192.168.1.0/24` it meant.

**An entry can be bound to some of this machine's own taints**, as `SPEC@a+b`:
`--subnet 192.168.1.0/24@office` offers that network only to peers whose taints pass the
containment rule in [concepts.md](concepts.md#taints) against `{office}` as well, rather
than to every peer this machine exchanges data with; `eth1@office+lab` binds `eth1` to
`{office, lab}`. A binding must name taints this machine is in, so a machine with no
taints can bind nothing. anchor's limits are checked here first: at most 64 entries,
each at most 255 bytes, and at most 16 distinct compartments bound across the list.

**In userspace there is nothing to set up**: the anchor forwards from its own process.

**With an interface the host forwards, and on Linux anchor sets it up.** As the anchor
starts it turns forwarding on, translates the realm's sources, clamps TCP's MSS and lets
its interface past a firewall that drops forwarded traffic; as it stops it puts each back.
That needs `nft` (on a kernel with NAT in the inet family, 5.2 or later) or `iptables`
with `ipset` and `ip6tables`, and a writable `/proc/sys` — a container cannot write one, so
start it with forwarding already on (`--sysctl net.ipv4.ip_forward=1 --sysctl
net.ipv6.conf.all.forwarding=1`). A host that will not be set up stops the anchor with the
reason, before anything is offered, and conflux gives up on it rather than retrying. On
macOS, the BSDs and Windows anchor sets nothing up and names the commands for that host
as it starts: forwarding, a NAT rule, and on macOS and the BSDs MSS clamping in
`pf.conf`. conflux adds nothing to either.

One thing to know before you type it: an entry that matches no private network the
machine is actually attached to **stops the anchor** rather than being advertised on
faith. conflux checks what it can locally first, so the refusal arrives from conflux
and not as a daemon that will not start.

### The last set wins

conflux starts the anchor with the list in `conflux.json`, as `-serve-subnets`. A member
whose credential grants the `subnets` capability can replace it while it runs, with a
Subnets order (`conflux subnets -peer ID -set …`; see
[commands.md](commands.md#realm-control)). anchor keeps that list in its directory —
`/var/lib/conflux/anchor/subnets.json` on Linux, as `{"subnets", "by", "at"}` — and serves
it in place of the configured one from every start, a reboot included. Unlike the
configured list, an entry in it that matches nothing on the host is withheld until it
does rather than stopping the anchor.

A plain re-run of `up` or `proxy`, `conflux start` and a reboot all keep the order's
list. An `up` or `proxy` with `--subnet` or `--no-subnet` sets the list again: conflux
removes the order's file before it restarts the anchor, and says whose order it
replaced. While an order's list is served, `conflux status` and the report after `up`
or `proxy` say so:

```
  forwarding   10.9.0.0/24@lab — set by an order from anchor… at 2026-10-06T09:00:00Z, in place of conflux.json's; --subnet or --no-subnet sets it again
```
