# The generic uplink

Layer 1 binds a UDP socket, so an anchor needs a host IP network under it. An uplink
is what replaces that: a file descriptor becomes the medium, and no socket is bound at
all.

```console
$ sudo conflux up --uplink /dev/ttyUSB0:115200
```

Everything above the medium is unchanged. An anchor on the far end of a serial cable
is admitted by the same realm gate, proves the same identity, opens the same session
and speaks the same wire format as one on the internet. conflux adds nothing here
either — it passes `-uplink` to the anchor and keeps the answer in
[the configuration](config.md), so a reboot brings the link back. anchor's own
[docs/uplink.md](https://github.com/veil-net/anchor/blob/main/docs/uplink.md) is what
describes the framing, the addressing and the reasoning.

## The medium is not the mode

Two independent questions, and conflux keeps them independent:

| | decides | exclusive? |
|---|---|---|
| `up` / `proxy` | what this machine gets out of the realm | yes — one daemon holds one anchor |
| `--uplink` / nothing | what the anchor reaches the realm over | yes — one uplink or one socket, never both |

So `--uplink` goes on either verb, and means the same thing on both:

```console
$ sudo conflux up --uplink /dev/ttyUSB0:115200                 # a cable, and a host interface
$ sudo conflux proxy 8080=127.0.0.1:3000 --uplink /dev/ttyS1   # a cable, and no host interface
$ sudo conflux up --no-uplink                                  # back to the host's network
```

`--no-uplink` is there because the answer is persisted. A second `conflux up` with no
flag keeps the link the configuration names — the same rule the overlay address
follows, and for the same reason: moving a machine onto a different network because
somebody re-ran a command is not something conflux will do.

## What conflux accepts

| Spec | Means |
|---|---|
| `/dev/ttyUSB0` | open the device and leave the line as it is |
| `/dev/ttyUSB0:115200` | open it and set the line speed |
| `fd:3` | **refused** — see below |

A trailing `:digits` is a line speed, split from the right, so a device whose own path
holds a colon still parses. Anything else is a device path.

**`fd:N` is anchor's and not conflux's.** It adopts a descriptor the daemon was handed
by whatever started it, and what starts `anchord` here is conflux's supervisor, which
passes it none. Rather than let that arrive as a "bad file descriptor" from a child
process, conflux refuses the form and names the two things that do work:

```console
$ sudo conflux up --uplink fd:3
conflux: fd:3 adopts a descriptor from whatever started the daemon, and conflux's
  supervisor starts anchord with none to adopt. Name the device instead, which
  conflux's anchor opens itself:

    conflux up --uplink /dev/ttyUSB0:115200

  To drive an anchor you hand a descriptor to yourself, that is anchorctl's:

    conflux anchorctl start -uplink fd:3 ...
```

**Unix only.** anchor has no way to open a link on Windows, so conflux refuses
`--uplink` there rather than letting a service fail at boot on a flag nobody can see.

## Enrol before the cable is the only thing plugged in

Enrolment is an HTTPS call to the realm's API, and the link cannot carry it: the
credential is what admits this machine to the realm, so it has to exist before the
realm is reachable at all. There is no way around this ordering and conflux does not
pretend otherwise.

```console
$ sudo conflux up --uplink /dev/ttyUSB0:115200 --taint mynet   # while it still has the internet
                                                               # then move the machine
```

A second `conflux up` re-uses the identity and enrols nothing, so the machine may be
brought up again on the cable as often as you like.

**Renewal has the same requirement.** The credential lasts seven days and the renewer
needs the same API. A machine that is permanently on a cable and never sees the
internet again is therefore a seven-day deployment, not an indefinite one — the anchor
stops being admitted when the credential lapses. See [credentials.md](credentials.md).

## What the line has to be able to do

A realm handshake is a full TLS 1.3 exchange with ML-DSA certificates in both
directions, plus the post-handshake proof and the credential chain — twenty to thirty
kilobytes.

| Line speed | Handshake | |
|---|---|---|
| 115200 baud | ~2 s | comfortable |
| 57600 baud | ~4 s | fine |
| 19200 baud | ~12 s | usable |
| 9600 baud | ~25 s | marginal against a 60-second idle timeout |
| LoRa, and the other duty-cycled radios | hours | no |

conflux prints a warning when the speed you give is under 19200, and does not refuse
one: the number is a rate rather than a limit, and a slow link that completes is a
working link.

**The floor is the identity model's, not the transport's.** A lighter transport would
still leave the credential exchange, which alone is hours of duty-cycled airtime at
LoRa rates. Reaching those media means changing what is exchanged, not what carries
it.

## What is refused beside it

anchor refuses these rather than ignoring them, because a setting quietly dropped
leaves a deployment behaving unlike its own configuration file:

| Setting | Refused because |
|---|---|
| a listen address | the link is the medium; no socket is bound, so an address names nothing |
| port mapping | there is no gateway on a cable and no port to forward |
| hole punching | a point-to-point link has no translator to punch through |

None of the three is a conflux flag, so none of them can collide with one: conflux
does not pass a listen address, and it does not ask for port mapping or hole punching
either, which is exactly what lets `conflux up --uplink /dev/ttyUSB0` work without
also passing two flags to turn off.

Everything conflux *does* offer works over a link, including `--subnet` and both
modes: the uplink is beneath all of it.

## The two limits it still has

**One link carries one peer.** The framing carries no address, so a link is
point-to-point. Two machines on a cable are a realm of their own.

**An anchor has one uplink or one socket, never both.** So a machine on a cable cannot
also bridge that cable into an IP-reachable realm — the wider realm learns an uplink
anchor's record through gossip, since a record with no addresses still travels, but
nothing in that realm can reach it.

And one thing that reads like a limit and is one for now: **a link that ends, ends.**
A device is not reopened, so an unplugged adapter needs the anchor restarted —
`conflux up` with no flags does it, and reads the configuration for the rest.
