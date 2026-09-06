# The two modes

conflux runs an anchor one of two ways, and they are mutually exclusive. Not by
conflux's choice — anchor refuses a configuration that asks for both, before anything
starts.

## TUN — `conflux up`

The daemon creates a real network interface, `anchor0`, and the host kernel owns the
overlay addresses. `ping`, `ssh`, a browser, anything on the machine can use the
overlay without knowing it exists. This needs `CAP_NET_ADMIN` on Linux, root on macOS
and the BSDs, Administrator and `wintun.dll` on Windows.

Because the kernel owns the address, a service published on the overlay is an ordinary
`bind` — there is no proxy to configure and conflux offers none.

## Userspace — `conflux proxy`

The overlay lives entirely inside the daemon, in a userspace network stack. Nothing on
the host can see it, there is no interface, and no privilege is required to run it.
The only way in is a reverse proxy you name:

```console
$ sudo conflux proxy 8080=127.0.0.1:3000
```

A peer connecting to overlay port 8080 gets a fresh connection to `127.0.0.1:3000`.
The backend is dialled per connection and is not resolved in advance, so a name that
does not resolve yet is legitimate.

conflux still needs root to *register the boot service* — a proxy that vanishes on the
next reboot is not what anyone asked for — but the anchor itself needs nothing.

## Why they cannot be combined

Two separate rules, both anchor's:

**A reverse proxy needs userspace.** With a host interface the kernel owns the overlay
address, so binding it is an ordinary `bind` and a proxy would be a second, redundant
path to the same port. anchor refuses the combination rather than pick one.

**A subnet, an exit and an overlay IPv4 all need a host interface.** There is nothing
to forward out of, and no interface to assign an address to, in userspace.

**And one daemon holds one anchor.** So even setting the rules aside, a machine is in
one mode at a time.

conflux checks all of this locally, before it starts anything, so the error names the
flag you typed rather than arriving from a child process as a gRPC status.

## Switching

Running one replaces the other, and conflux says so:

```console
$ sudo conflux proxy 8080=127.0.0.1:3000
conflux: this machine was running in TUN mode with interface anchor0.
  Userspace mode replaces that: one daemon holds one anchor, and an anchor with
  a host interface cannot also serve a reverse proxy …
```

The identity does not change. Only the mode does.

## Proxy specs

The grammar is `OVERLAYPORT[/NETWORK]=BACKEND`.

| Spec | Means |
|---|---|
| `8080=127.0.0.1:3000` | TCP on overlay port 8080 → `127.0.0.1:3000` |
| `53/udp=127.0.0.1:53` | UDP on overlay port 53 → `127.0.0.1:53` |
| `5432=[::1]:5432` | an IPv6 backend, bracketed |

The network defaults to `tcp` and must be `tcp` or `udp`. The port is 1–65535. Repeat
the argument for more than one; conflux refuses a duplicate overlay port rather than
silently keeping the last.

## `--subnet`, and what the host has to be

`conflux up --subnet 192.168.1.0/24` offers to forward that network to the rest of the
realm. An entry is an interface name or a prefix; an interface name expands to every
private network on it, so `eth1` follows DHCP. Private networks only — reaching the
public internet through an anchor is what an exit is for, and conflux does not offer
one.

**anchor deliberately does not configure the host for this, and neither does conflux.**
Forwarding a subnet also needs, on the host:

- `net.ipv4.ip_forward=1` (and the v6 equivalent, if you are forwarding v6)
- a MASQUERADE rule narrowed to the overlay range
- MSS clamping, written `--tcp-flags SYN,RST SYN` and **not** `--syn`, which clamps one
  direction and fails identically to no clamping at all

conflux warns when forwarding is off and prints what to change. It will not change it
for you: a wrapper that quietly enables IP forwarding on somebody's laptop is a worse
program than one that prints two lines.

One thing to know before you type it: an entry that matches no private network the
machine is actually attached to **stops the anchor** rather than being advertised on
faith. conflux checks what it can locally first, so the refusal arrives from conflux
and not as a daemon that will not start.
