# Commands

conflux keeps a closed set of names for itself. Every other argument vector is handed
to the embedded `anchorctl` unchanged — not parsed, not rewritten, not validated.

## The split

conflux's: `up`, `proxy`, `observe`, `enrol`, `start`, `down`, `install`, `uninstall`,
`renew`, `status`, `version`, `update`, `cert`, `help`, plus `anchorctl` as an escape hatch
and a hidden `serve` the boot service runs.

anchorctl's, reached by typing them: `peers`, `route`, `routes`, `connect`, `punch`,
`events`, `metrics`, `export`, `inventory`, `telemetry`, `block`, `unblock`, `blocks`, `taints`,
`subnets`, `send`, `subscribe`, `keygen`, `issue`, `delegate`, `renew-link`,
`install-link`, `id`, `inspect`, `config`, `mint-realm`, `mint-anchor`. The two `mint-*`
verbs exist only in the lockdown build, which is the one conflux embeds; `root`, which
mints a realm root, is not in that build at all, and answers as an unknown command.

`export` is worth naming separately now, because there are two ways to set it and they
do not last equally long. `conflux anchorctl export -endpoint …` configures the running
daemon and is discarded at the next restart or SIGHUP; the `export` block in
`conflux.json` is rendered to anchord's config file on every start and is the durable
one. `conflux status` says which the daemon is currently obeying. See
[config.md](config.md#export--where-telemetry-goes).

### Realm control

Six of anchorctl's commands are the realm's control over its members. They pass
through unchanged, none of them is a conflux verb, and `conflux help` names them:

| Command | What it does | Needs the capability |
|---|---|---|
| `block -target ID [-days N] [-reason TEXT]` | shuts another member out of the realm, on every member, until the block ends or is lifted | `block` |
| `unblock -target ID` | lifts a block | `block` |
| `blocks` | lists the blocks in force | none |
| `taints -peer ID [-set A,B] [-timeout D]` | reads another member's compartments, or moves it to others | `taint` |
| `subnets -peer ID [-set A,B \| -clear] [-timeout D]` | reads what another member forwards for the realm, or replaces its list | `subnets` |
| `telemetry -from ID [-timeout D]` | asks another member how it is | `telemetry` |

Every one but `blocks` acts on **another** member of the same realm, never on this
machine, and needs its capability in this machine's credential. Capabilities are the
issuer's to grant, as taints are: an alpha credential grants none, so on an alpha
machine these orders are refused with anchor's explanation, and a guardian may grant
them. They take a full 58-character AnchorID, `anchor…`, as `conflux status` prints it —
not the ten-character short form in the tables `peers` and `blocks` print. For every
private network on the member, use `subnets -set '*'`: anchorctl's help says `all`,
which anchor does not accept.

A block does not stop anything. A blocked anchor keeps running, outside the realm, and
shows `DATA no` on every peer; nothing on the blocked machine needs to be done when the
block is lifted. Stopping the anchor on *this* machine is `conflux down`, which closes it
gracefully and leaves the registration; see [service.md](service.md).

conflux starts every anchor with a directory, so a conflux machine can be the one an
order moves. A Taints order's grant is kept there and reapplied over the credential's
set at every start; conflux still starts from the credential's set, and `conflux status`
shows the credential's taints, since anchor reports no live set locally. A Subnets
order's list is served in place of `conflux.json`'s until `up` or `proxy` sets the list
again; see [modes.md](modes.md#the-last-set-wins).

### The five collisions

`start`, `proxy`, `renew`, `status` and `observe` exist on both sides. Each is resolved
explicitly. `TestTheCollisionsAreTheDocumentedOnes` reads the set off the embedded
binary, so a future anchor adding a colliding name fails CI here rather than shadowing
something silently.

**`help`** is conflux's, always, and is not counted among the five: anchorctl's `help`
only prints its usage, and conflux's prints that same usage in full, so owning the word
loses nothing. Bare, it prints conflux's usage and then anchorctl's whole usage beneath
a rule, so one page covers both surfaces. `conflux help COMMAND` prints that command's
own usage instead, whichever binary it belongs to. A help flag is any spelling Go's flag
package answers with usage — `-h`, `--h`, `-help`, `--help`, with a value or without — and
conflux reads every one as help, wherever it meets one.

**`status`** is resolved by arity. Bare `conflux status` is conflux's, and it prints
`anchorctl status` underneath — additive, so nothing is lost by conflux owning that
spelling. Given any argument it forwards, so `conflux status -watch 5s` and
`conflux status -h` do what an anchor user expects.

**`proxy`** is resolved by shape, and the ambiguous case is refused rather than
guessed. Positional `PORT=BACKEND` specs and the flags `conflux proxy -h` lists —
`--taint`, `--subnet` and the rest — are conflux's; any other dash-prefixed argument
prints both meanings and exits 2. A "leading dash means
anchorctl" heuristic was considered and rejected: `--taint` leads with a dash too, and
Go's flag package treats `-x` and `--x` identically, so the double dash carries no
signal.

**`renew`** is resolved by shape, like `proxy`. conflux's takes no arguments at all:
it fetches a fresh credential from the enrolment API and installs it. anchorctl's
takes `-cred FILE` and installs one the caller already holds. So any flag reaching
`conflux renew` other than a help flag names anchorctl's, and is answered with the escape
hatch rather than guessed at.

**`start`** is resolved by shape, like `renew`. conflux's takes no arguments at all:
it starts the anchor this machine is already configured for. anchorctl's builds one
from arguments the caller supplies. So any flag reaching `conflux start` other than a
help flag names anchorctl's, and is answered with the escape hatch rather than guessed at.

**`observe`** is resolved by shape, like `proxy`. conflux's takes its own flags and no
argument, and decides what this machine runs from every boot: the observer, and no anchor.
anchorctl's reports on the observer of the running daemon, and starts it under a credential it
is handed, or stops it, until the daemon next starts. Any other flag reaching `conflux observe` names anchorctl's: `-start` and
`-stop` are answered with conflux's way to say each — `conflux observe`, `conflux down`,
`--observe` and `--no-observe` — and with the escape hatch, `-start` with the `-manifest FILE`
anchorctl needs, and the rest with the escape hatch alone. Bare, it is conflux's, and since anchorctl's bare form only reports, a bare one on a
machine running an anchor asks before it stops it (`conflux observe`, above). `inventory` is
anchorctl's alone and passes straight through.

**`stop` and `restart`** are anchorctl's and conflux refuses to pass them through.
Running them directly would stop an anchor conflux believes is running, or build one
its configuration does not describe, and the next reboot would silently disagree. The
refusal names `down` and `start` and the escape hatch.

## A root another account could change

`status`, `down`, `renew`, `uninstall`, `update` with the boot service installed, and a
pass-through to conflux's daemon read what is in a root by its name — the configuration, the pid
record, the token, the socket — so each holds the root to the
[readers' check](security.md#the-file-and-the-directory-around-it) first: its owner root or the
account running conflux, and nobody else able to write it or point it elsewhere. A root that fails
is refused, exit 1, naming it and who else could change it, and nothing in it is read, run or
stopped: `down` stops nothing; `update` downloads and replaces nothing. `uninstall` reads and
signals nothing in such a root either, and removes it all the same, following nothing in it
([`conflux uninstall`](#conflux-uninstall)). Nothing is narrowed either. That
is for `up`, `proxy`, `observe`, `install`, `enrol` and `start`, which make the roots, or make them
conflux's: they narrow one of conflux's own and refuse one another account owns. A root that is not
there is a machine with nothing installed, and read as one.

Help is the exception, since it needs nothing of the machine's: it runs the `anchorctl` extracted
in the root only where the root passes that check and a whole extraction is there, and otherwise
— the root refused, or not there — a private temporary copy, reading nothing in the root
([Pass-through](#pass-through)).

## `conflux up`

```
conflux up [--taint T]... [--ipv4 ADDRESS | --no-ipv4] [--subnet CIDR... | --no-subnet] [--interface NAME | --no-interface]
           [--uplink DEV | --no-uplink] [--peers HOST:PORT]... [--no-peers] [--api URL]
           [--port N | --no-port] [--low-latency | --no-low-latency] [--lan-discovery yes|no|auto]
           [--serve-exit | --no-serve-exit] [--use-exit | --no-use-exit]
           [--observe | --no-observe] [--observe-loopback] [--observe-hide-names]
           [--export HOST:PORT [--export-insecure]]
```

Enrols this machine if it has never been, starts an anchor in TUN mode, writes the
configuration, and registers the boot service.

| Flag | Meaning |
|---|---|
| `--taint T` | the taint to enrol in; repeat for more than one. On a machine with no credential yet it is the enrolment's request: the first machine of a network omits it, and conflux mints one and prints it; every other machine passes that one to join. Once a machine holds a credential its taints are fixed: the same set is accepted, and any other is refused, naming `conflux uninstall --yes` and then `conflux up --taint`, which is a new identity. See [concepts.md](concepts.md#taints) and [credentials.md](credentials.md#taints-are-the-credentials). |
| `--ipv4 ADDRESS` | this machine's IPv4: an address, or an address and the length of the range routed to peers, `10.128.0.7/24`. Any unicast address outside `198.18.0.0/15`; see below. |
| `--no-ipv4` | no IPv4 of its own, without prompting. It still reaches IPv4 peers. |
| `--subnet CIDR` | a network this machine forwards for the realm: an interface, a private network with no host bits set, or `'*'` for every private network on every interface, each optionally bound to some of this machine's taints as `SPEC@a+b`; repeat for more. It replaces a list a member's Subnets order set. See [modes.md](modes.md#--subnet-and-what-the-host-has-to-be). |
| `--no-subnet` | forward nothing for the realm; the way back from `--subnet`, and from a member's Subnets order. |
| `--interface NAME` | the network interface name. Default: the anchor's own, `anchor` and the start of its AnchorID, which `conflux status` shows. Linux and Windows honour it; macOS numbers its own `utunN` and the BSDs their own `tunN`, taking a name of that form as the unit to ask for, and `conflux status` says so rather than naming one that is not there. A name anchor would refuse — on Linux anything but 1 to 15 of letters, digits and `_.+@-` (what a firewall rule can match once the interface routes subnets or an exit, which a member's Subnets order can turn on at any time); on macOS `utun` followed by anything but a number — is refused here, for good, rather than retried. Kept by every re-run that names none. |
| `--no-interface` | go back to the anchor's own name on a machine given one with `--interface`. |
| `--uplink DEV` | reach the realm over a link rather than the host's network: `/dev/ttyUSB0`, or `/dev/ttyUSB0:115200` with a line speed. See [uplink.md](uplink.md). |
| `--no-uplink` | go back to the host's network on a machine configured for a link. |
| `--peers HOST:PORT` | where to start looking for the realm; repeat for more. `ANCHORID@host:port` also names the anchor expected there. Enrolment supplies this, so it is an override — see below. |
| `--no-peers` | forget an override and go back to the list enrolment supplies. |
| `--api URL` | the enrolment API base. Default `https://api.veilnet.com.au`. |
| `--port N` | the UDP port to bind, 1–65535. Omit it and the kernel picks one. |
| `--no-port` | go back to letting the kernel pick. |
| `--low-latency` | carry frames on QUIC datagrams: no head-of-line blocking between flows to one peer, and a lost frame stays lost rather than holding up the ones behind it. |
| `--no-low-latency` | go back to carrying frames on streams. |
| `--lan-discovery` | `yes`, `no`, or `auto`. Probe the networks this host is attached to for anchors of the same realm tree — a third bootstrap source, tried *with* the configured and remembered ones rather than as a fallback when they are empty. `auto` is the default and passes nothing, which leaves the answer to enrolment's own `lanDiscovery` and, failing that, to anchor, where it is on. Typing `auto` is the way back from a persisted `yes` or `no`. Refused as an explicit `yes` beside `--uplink`: there is no host network to probe and nothing on a cable to answer. It never replaces enrolment — the probe is sealed under the realm's root public key, which a machine only holds once it has enrolled. |
| `--serve-exit` | offer this machine as a way out to the public internet. |
| `--use-exit` | send this machine's own internet traffic over the overlay. |
| `--no-serve-exit`, `--no-use-exit` | the way back from either. Every pair here takes `--x=false` as `--no-x`, and `--no-x=false` as neither, so a script that templates `--serve-exit=$X` never turns on what `X=false` meant to leave off. |
| `--observe` | run the observer beside the anchor: an inventory of the cryptography of this host's traffic. See [observe.md](observe.md#beside-an-anchor). Naming it, or either option below, says what the observer is now, and an option not given is off; naming none keeps what is configured. |
| `--observe-loopback`, `--observe-hide-names` | observe the loopback interfaces too; leave the names flows were reached by out of the records. Each implies `--observe`. |
| `--no-observe` | stop observing. |
| `--export HOST:PORT` | send telemetry, each record the observer makes and each circuit the anchor relays, to the OTLP/gRPC collector there: the export on, that endpoint, `flows` and `metrics` on, and everything else `conflux.json`'s `export` block says kept — headers and TLS above all, which no command line takes. See [config.md](config.md#export--where-telemetry-goes). |
| `--export-insecure` | reach that collector without TLS. |
| `--ephemeral` | run in the foreground and keep nothing: the credential is held in memory, nothing is written or registered, and when anchord stops, or on Ctrl-C, everything is gone. Asks nothing; with neither `--ipv4` nor `--no-ipv4`, the IPv4 is the handed credential's or none. See [ephemeral.md](ephemeral.md). |
| `--manifest FILE`, `--manifest -` | with `--ephemeral`, run on this issued credential, read from FILE or stdin and never written, rather than enrolling. Without `--ephemeral` it is refused: a credential to keep is `conflux enrol`'s. |

An anchor listens on **every** interface, so `--port` is a port and not an address:
the host's addresses change underneath it, and pinning one is a promise the host
cannot keep. Name a port to write a firewall rule or a port-forward against; leave it
alone otherwise. It is refused beside `--uplink`, which binds no socket at all.

Neither exit is ever inherited from the enrolment manifest: conflux passes both in
whichever direction they were set, because an anchor that became an internet exit
because a document said so is the worst kind of surprise. They, and the subnets, are
kept when a machine switches to `proxy`, which routes them from the anchor's own process.

`--uplink` is the medium and the verb is the mode, so the flag means the same thing
on `proxy`, and neither answer constrains the other. A malformed spec, and the `fd:N`
form anchor takes but conflux's supervisor cannot hand over, are both refused here
rather than by a daemon at the next boot.

`--peers` is an override and its default — naming nothing — is a decision rather than
an omission. The enrolment manifest carries its issuer's own bootstrap list, and
anchorctl fills that field from the manifest only when no flag named it, so passing
nothing is what lets the API move a bootstrap node without every machine needing an
edit. Name one only to reach a realm the manifest does not describe, which in practice
means a test node. It persists like every other setting, so a machine brought up
against one comes back to it after a reboot.

With neither `--ipv4` nor `--no-ipv4`, conflux asks — once in the machine's life. The
answer is kept, "none" included, so re-running `up` or `proxy` asks nothing and never
changes the address. With nobody at a terminal to answer and neither flag given, it
exits 1 rather than hang, which is what makes it safe in a script.

The address is anchor's to interpret ([ipv4.md](https://github.com/veil-net/anchor/blob/main/docs/ipv4.md)):
it never reaches the overlay, which carries it translated, so any unicast address
works and two machines may share one — except one inside `198.18.0.0/15`, where anchor
answers the IPv4 peers it translates for, and which it will not send from. A private one is advertised, and peers reach
this machine at it; a public one is sent from and not advertised. Without one, the
machine still reaches IPv4 peers from anchor's shared default and is reached by its
IPv6 address.

Needs root.

## `conflux proxy`

```
conflux proxy PORT[/NETWORK]=BACKEND ... [--taint T]... [--ipv4 ADDRESS | --no-ipv4]
              [--subnet CIDR... | --no-subnet] [--serve-exit | --no-serve-exit] [--use-exit | --no-use-exit]
              [--uplink DEV | --no-uplink] [--peers HOST:PORT]... [--no-peers] [--api URL]
              [--port N | --no-port] [--low-latency | --no-low-latency] [--lan-discovery yes|no|auto]
              [--observe | --no-observe] [--observe-loopback] [--observe-hide-names]
              [--export HOST:PORT [--export-insecure]]
```

Starts in userspace mode serving those backends. Same taint, IPv4, subnet, exit,
uplink, peers, API, `--port`, `--low-latency`, `--lan-discovery`, observer and export
flags as `up`, and the IPv4 is asked the same once. Specs and flags may be written in either order.

With an IPv4 the anchor's own stack holds it, so a peer reaches these ports at it as
well as at the IPv6 address.

`--subnet` and `--serve-exit` make it a userspace router: anchor forwards each
connection from its own process, with nothing on the host set up and no privilege.
With either, the port specs may be left out, and a machine offering none of the three
is refused. `--use-exit` here covers only the anchor's own traffic, since nothing else
on the host sees the overlay.

The grammar is `OVERLAYPORT[/NETWORK]=BACKEND`: the network defaults to `tcp` and must
be `tcp` or `udp`, the port is 1–65535, the backend is `host:port`, and a duplicate
overlay port is refused rather than silently keeping the last. See [modes.md](modes.md) for the spec table, and
`conflux anchorctl proxy` for adding and removing them on an anchor already running.

Needs root, only to register the boot service.

## `conflux observe`

```
conflux observe [--taint T] [--api URL] [--loopback] [--hide-names]
                [--export HOST:PORT [--export-insecure]] [--yes]
```

Enrols this machine if it holds no credential, exactly as `up` does, runs the daemon's observer
under that credential and no anchor, writes the configuration, and registers the boot service:
from now and from every boot, until it is stopped. The host copies the start of every flow to
the daemon, which records each flow's cryptography. The credential is renewed as an anchor's
is; a guardian's, installed beforehand with `conflux enrol --manifest`, is run under as it is.
See [observe.md](observe.md#the-credential-it-runs-under).

| Flag | Meaning |
|---|---|
| `--taint T` | the taint to enrol in, as on `up`: on a machine with no credential yet the enrolment's request, minted when omitted; with one, it may only restate the taints it grants. |
| `--api URL` | the enrolment API, as on `up`. |
| `--loopback` | observe the loopback interfaces too. Windows' capture never sees them. |
| `--hide-names` | leave every name a flow was reached by out of the records and the inventory, the server's address in its place. |
| `--export HOST:PORT` | send each record, as it is made, and the daemon's telemetry to that collector, as on `up`. Without an export with `flows`, the records stay in the daemon's inventory, and conflux says so. |
| `--export-insecure` | reach it without TLS. |
| `--yes` | stop the anchor this machine runs without asking. |

The options say what the observer is now, as anchorctl's `observe -start` does: one not given
is off.

On a machine that runs an anchor, this stops it and the anchor leaves its realm, with every
setting kept for the next `up` or `proxy` — the proxy specs aside, which it clears as `up` does —
and the observer runs under the same identity meanwhile. So it asks first at a terminal, and off one is refused without `--yes`:
anchorctl's bare `observe` only reports, and a script that meant that one must not stop an
anchor. It asks once everything typed has been checked, so a `--taint` the credential does not
grant is refused with nothing asked, and before a taint is minted for a machine with neither a
credential nor a taint, so a no leaves none minted. `conflux up --observe` observes beside the
anchor instead.

FreeBSD and OpenBSD have no capture, and are refused with exit 2 before anything is asked or
written.

Needs root, only to register the boot service. What the observer has seen is anchorctl's
`inventory`, which passes straight through: `conflux inventory`, or `conflux inventory -cbom` for a
CycloneDX CBOM.

## `conflux start`

```
conflux start
```

Starts the anchor now, from the configuration already on disk, in whichever mode it
names. Takes no arguments: it decides nothing, enrols nothing, and invents no
configuration.

The counterpart to `down`, and the reason it exists. `down` deliberately leaves the
boot registration and the configuration in place, so there has to be a word for
"bring that back now" that is not a reboot.

It is mode-agnostic on purpose. `up` would do for a TUN machine, but `up` is not a
resume: it re-decides the configuration, and on a userspace machine it changes the
mode and drops the proxies. A machine serving eight ports cannot be brought back by
retyping eight specs correctly from memory.

Before it reads the configuration, places its copy for the service or registers it, `start`
secures the roots as the service does at every start, and as `up` and `install` do: one of
conflux's own left wider is narrowed, and one another account owns is refused, exit 1, naming it
— on Windows, where the service runs as SYSTEM, what the administrator running it owns in the root,
or what grants them a right, among it, as the service would refuse it at every start
([windows.md](windows.md#file-permissions)). With the service registered and its roots gone, they
are made again, as the service would make them.

`update` hands a running service to the conflux it put in place through that conflux's `start`.
Where the service's copy is not this conflux — an update, or a newer conflux put in place by hand —
or the roots fail the [readers' check](#a-root-another-account-could-change), so that the copy is
not read to find out, `start` first removes what earlier conflux left, before anything judges the
roots, as [`update`](#conflux-update) describes, the service stopped for it, and writes the copy
afresh. A start of the conflux the service already runs is no update, and removes nothing of what
`update` does but this: where no supervisor serves the root, it first removes what conflux makes
again there and an earlier conflux left failing the service's rule — on Windows, what an older
conflux on a client left as the administrator's own — before anything judges the root, as `update`
does, and says what it removed; with a supervisor serving it, the service has taken the root
already.

| Situation | |
|---|---|
| not installed | exit 69, naming `install`, `up`, `proxy` and `observe` — there is no service to start |
| installed, no configuration | exit 78, naming `up`, `proxy` and `observe` — there is nothing to start |
| already running | restarts it. A `start` that refused would be answering a question nobody asked |

Needs root.

## `conflux down`

Stops the anchor now. The boot service stays registered and the configuration and
identity stay on disk, so the next reboot brings the machine back exactly as it was,
and `conflux start` brings it back before then. Refuses with exit 69 if conflux is not
installed, because there would be nothing for a reboot to bring back and the word
would be a lie. An anchor stopped by hand is not one the supervisor gave up on, so it clears
that record, `conflux status`'s `given up` line.

## `conflux install`

Registers the boot service. If a configuration exists it is also started; if not, it
registers the service, says plainly that there is nothing to start, and exits 0. No
configuration is invented.

`up` and `proxy` call it internally after writing their configuration, so there is one
path for "register and run" and one for "configure, persist, then register and run".

Registration is the point here. To start a machine that is already registered, that is
`conflux start` — the two share the starting, so neither can drift into starting a
different anchor from the other.

## `conflux enrol`

```
conflux enrol --manifest FILE [--api URL] [--ipv4 ADDRESS]
```

Installs a credential this machine was **given** rather than one it drew.

The public alpha realm hands out identities to anyone who asks and records none of
them, which is why `up` can enrol by itself. A self-hosted guardian does the opposite:
it serves no enrolment route at all, commissions each machine in advance, and hands its
operator one file per machine. This is how that file gets in, and on a guardian
deployment it is the only way a node is provisioned.

`--manifest -` reads the document from stdin, so it need never land on disk at whatever
mode the shell's umask chose. anchorctl spells the same thing the same way.

**The file is enough on its own, and the two flags are overrides.** A guardian
document carries an absolute `renewalUrl`, the overlay address the guardian allocated
out of its realm's range, and the taints it granted the machine — because a guardian
knows all three and the operator would only be retyping them. That is the difference
between this and the public alpha realm, whose document carries an identity, the taints
its enrolment asked for, and little else.

| | overrides | when you would |
|---|---|---|
| `--api URL` | the API base read out of `renewalUrl` | the guardian is reached at a different name from here — a split-horizon DNS, a bastion |
| `--ipv4 ADDRESS` | the address the issuer allocated | you are rebuilding a machine onto an address something else already hardcodes |

`--api` is also an assertion when given: the document must renew against the same host,
and a mismatch is refused naming both rather than discovered at the first renewal weeks
later. It is not required: the same document carries the identity seed and the renewal
bearer, so anybody able to rewrite its `renewalUrl` already holds everything a redirect
would steal.

**Taints are the credential's, and are validated rather than copied through.** The
credential commits to the set its issuer granted, anchor starts the identity under no
other, and a renewal restates it — so there is no flag to overrule it, and `conflux.json`
is written with the manifest's set, which every start then checks it against. An issued
credential granting none — a guardian's, or a node's in one of VeilNet's own ghost realms —
is taken as it is, and puts the machine in its issuer realm's default compartment. An
alpha manifest granting none is refused: that is the public realm's shared compartment,
which conflux never puts a machine in. A label conflux cannot carry — a comma, an `@` or
a `+`, a space of any kind or a character that does not print, bytes that are not UTF-8,
over 64 bytes, more than 32 of them — is refused here rather than at the next start,
where the complaint would come from anchor instead of from the document that caused it.

**It refuses to replace an existing manifest.** `up` enrols only when there is none,
because a second enrolment is a second AnchorID and a second overlay address with every
peer orphaned and nothing said; a verb that writes manifests must not be the way around
that rule. `conflux uninstall` first if replacing the identity is genuinely what you
mean.

Everything is checked before a byte is written — the format version, the `kind` (a
`realm` manifest mints anchors and does not start one), the `renewalAuth`, the renewal
host, the address and the export block. A refused import leaves the machine exactly as
it found it.

**A document with no renewal fields at all is fixed-term, not broken.** That is what
traveller hands out for a node in one of VeilNet's own ghost realms: a century-long
credential and no renewal route. It installs with no `--api`, prints `renewal: none`,
and is refused only if it has already expired, because nothing will ever bring it back.
A document that names a `renewalAuth` but no `renewalUrl` is still refused: it says how
to authenticate a renewal but not where to send it. If the document says `exit: true`,
the closing hint adds that `--serve-exit`, on `up` or `proxy`, serves it. conflux still serves
an exit only when it is told to. See [credentials.md](credentials.md#a-credential-that-does-not-renew).

Two fields are copied out of the document **once** and into `conflux.json`, where
`conflux status` shows them and you can change them: `ipv4`, the overlay address the
issuer allocated, and `export`, where it suggests telemetry goes. Neither is re-read on
a later start. That is the difference from the two exit flags, which conflux refuses to
inherit at all — an exit flag would go on deciding what this machine does for other
people, and these are a suggestion made once at commissioning time. `--ipv4` overrides
the document.

Then, as root, `conflux up`, `conflux proxy` or `conflux observe`, which the closing hint
names: each finds the manifest and starts from it without enrolling, an anchor with an
interface or in userspace, or the observer alone, which runs under the same credential.

Needs root.

## `conflux renew`

```
conflux renew
```

Fetches a fresh credential from the enrolment API and installs it in what is already running:
the anchor, and the observer, which runs under the same credential and which a renewal of the
anchor's does not reach. Takes no arguments.

The swap is hot — `anchorctl renew`, which calls `SetRealmCred`, and `anchorctl observe -cred`,
which calls `SetObserverCred` — so the identity does not change and not one session is dropped.
It is not a restart and does not need to be treated as one. The request restates the taints the
manifest names, which a renewal cannot change. The fresh chain is written into the stored
manifest, and so is the bootstrap list the answer carries, when it carries a usable one; the
installs carry only the chain, so the list is the next start's. An anchor or an observer the
daemon is not running has nothing to replace, and its next start is handed the manifest the
chain is already in.

Renewal is automatic in two places already: once at every start, before the anchor or the
observer is started, and again on a timer at two thirds of the credential's life. So this
command is not part of normal operation. It is for the machine whose renewals have been failing
— `conflux status` prints `renewal: failing since ...`, or an observer's line says its
credential lapsed and nothing is exported — where the alternative was restarting the service
and paying every session for a swap that needs none of them.

It does not enrol. A machine with no manifest has nothing to renew, and drawing an
identity here would replace the one a reboot expects; it says so and exits 69, as it does for
one whose anchor or observer has never started to report the AnchorID a renewal names. It also
exits 69 when nothing is running, because a credential is installed *into* what runs, and a
machine that is meant to be down renews on its next start anyway. And it
exits 69 on a [fixed-term credential](credentials.md#a-credential-that-does-not-renew),
which names nowhere to renew it.

Needs root.

## `conflux uninstall`

Removes everything conflux made here, the identity included, and keeps nothing for a
reinstall:

- the boot service: the systemd unit and its `wants` link, the launchd plist (leaving nothing
  in launchd's disabled database), the rc script and, on FreeBSD, its `rc.conf` line, or the
  Windows service and its registry key; a `CONFLUX_DIR` installation's scoped one for that
  installation;
- every root and all it holds: the configuration (`conflux.json`), the credential
  (`manifest.b64`), the state (`state.json`, the record of an anchor given up on among it,
  `anchord.priv`, `anchord.json`), the anchor directories, the extracted anchor binaries and,
  on Windows, `wintun.dll` beside them, the service's copy of conflux, the lock files, the run
  directory's token, readiness marker, pid record and socket, and the log: the `logs`
  directory on Windows and in a `CONFLUX_DIR`, `/var/log/conflux.log` and `conflux.log.1` on
  macOS and FreeBSD, never `/var/log` itself;
- every ephemeral run's root kept for the account running it, a killed run's once the anchord
  it left is stopped;
- what an update left beside this conflux: a download that never went in place, and on Windows
  the image moved aside, `conflux.exe.old` (elsewhere a file of that name is yours, and kept);
- the folders conflux made on the way to its roots, which it records as it makes them — a
  `CONFLUX_DIR`'s parents it made among them — each once it is empty, deepest first;
- the account `anchord` ran as, and `conflux-ephemeral`, once nothing runs as either, when
  conflux made them (an account of either name that conflux did not make is left alone), with
  the BPF devices given back to root on macOS first.

The conflux you ran is yours, and stays. It says what it removed. Asks first, because there is
no other copy of the credential anywhere; `--yes` skips the question, and a non-interactive
run without `--yes` refuses rather than destroy an identity silently.

Nothing in a root is followed. Each is removed through the directory holding it, held open from
the top of its volume down, and a name at a time below it: a link or junction found anywhere in
it is removed as the link, and where it leads is never touched; a file another account planted
there is removed as itself, never read. A root whose own name is a link or junction — one moved to
another disk — is followed only where conflux would follow it every day: owned by root (SYSTEM or the
Administrators on Windows) or the account running conflux, nobody else able to point it elsewhere,
and leading to a directory the readers' check would take. Then what that directory holds is removed
through the handle held on it, and the link after, the directory itself left empty; a link that
fails is removed as itself, and where it leads is not touched. A `CONFLUX_DIR`'s way is
held to the rule the [readers' check](#a-root-another-account-could-change) holds it to as it is
walked, so a way another account could change cannot lead the removal elsewhere; the platform's
own roots are on the system's way. No root is refused: one the readers' check refuses is removed
the same way, with nothing in it read or signalled first — no identity shown in the question, no
`anchord` stopped by its pid record. The record of the folders made on the way to it is read all
the same, as a file anybody may have put there, never through a link: all it can lead to is an
empty folder above conflux's roots being removed. An ephemeral run's root inside a `CONFLUX_DIR`
goes with it.

While an [ephemeral run](ephemeral.md) is live — kept for the account running it, or inside a
`CONFLUX_DIR`, whose root it would go with — it refuses, exit 2, naming it, before asking anything,
and again once the question is answered, before anything is removed: the run's anchord may run as
the account it would remove, so the run is stopped first, with Ctrl-C where it runs. A run that
starts once uninstall has begun is left running, with its root, the root that holds it and the
account it runs as, and uninstall says so, exit 1. The root a killed run left behind — its extracted pair, token and
socket — it removes, stopping the anchord the run left, under the root's lock, so a run
starting at that moment keeps its own; one another account could have made or changed is
removed reading and signalling nothing in it.

## `conflux status`

conflux's state — service, mode, exit, taint, AnchorID, credential expiry, API, the
uplink reopen tally if there is one, and while it runs, who `anchord` runs as and with
what — and then `anchorctl status` beneath it. Exits 78 when the machine has no
configuration and no ephemeral run is live; with one live, it reports the run and exits 0.
An installed machine's configuration is root's alone (Administrators' on Windows), so asked by
another account it exits 13, naming the command to run again, as every verb needing root does.

A `given up` line says when the supervisor gave up on the anchor, refused for good, and why,
then that `conflux start` tries the anchor again. It is there while none runs — the daemon
answering with no anchor, or not answering because the service ended on it — since `anchorctl
status` beneath says only that none runs, and never on a machine that only observes. The
supervisor records it where it stops trying the anchor: beside an observer, once the watcher
gives up rebuilding it — after a start's refusal, three rebuilds refused in a row, four tries in
all — and with nothing else running, once the service ends on it (exit 70). An anchor that comes
up clears it, and so do `conflux down`, a new identity, and the supervisor wherever it is to try
the anchor again: as the service starts (`conflux start`, a reboot), however far that start gets,
and once anchord has ended and is to be started again, before the wait. Whether the observer runs
is its own line's to say.

The `anchord` line says what it keeps and why: `conflux, with no privilege` in userspace,
`conflux, with CAP_NET_ADMIN for its interface` for a TUN on Linux, `conflux, with CAP_NET_RAW
to copy what the host's interfaces carry, for the observer` observing on Linux, or root and the
reason the host needs it. See [security.md](security.md#what-anchord-runs-as).

Where the observer runs, an `observer` line is its row from `anchorctl status` — `af_packet, 12
flows held, 3480 packets taken; credential valid until …`, the credential `lapsed at …` with
`conflux renew` named to renew it, or `not observing` and why a capture that was running ended —
with its options, and a `records` line says where its records go: to the collector the export
names, as each is made, or nowhere but the daemon's inventory. Observing alone, the mode line
says so and the taint follows it; the credential's lines are reported as an anchor's are, with
the identity the observer runs as on an `identity` line, and the anchor's address, exits and
subnets are left out: they describe nothing that runs.

The `taint` line is the set `conflux.json` names, which after enrolment mirrors the one
the credential grants — `none: the realm's default compartment` for an issued
credential granting none. A member's Taints order may have moved the running anchor
since, and that does not show here: anchor reports no live set locally.

The `exit` line appears only when this machine is an exit one way or the other.
conflux goes to some trouble not to become one by accident, so a machine that *is*
one should not need a config file read to find out.

A `refused` line appears when the machine is configured for taints its credential does
not grant, which every start refuses for good. It names the set granted and the set
configured, and the way out: `conflux uninstall --yes`, then `conflux up --taint` (or,
for an issued credential, `conflux enrol` with one granted in the taints wanted) — a new
identity, since a credential's taints never change. The usual cause is an alpha machine
enrolled before the realm granted taints, whose credential grants none; nothing
re-enrols it automatically. See
[credentials.md](credentials.md#taints-are-the-credentials).

The `forwarding` lines are the networks this machine forwards for the realm. When a
member's Subnets order replaced `conflux.json`'s list there is one line, saying whose:

```
  forwarding   10.9.0.0/24@lab — set by an order from anchor… at 2026-10-06T09:00:00Z, in place of conflux.json's; --subnet or --no-subnet sets it again
```

## `conflux version`

conflux's version and commit, whether it runs in FIPS 140-3 mode and against which Go
Cryptographic Module, and the SHA-256 of both embedded anchor binaries. Put this in a bug
report; it names the exact anchor build without running it.

```console
$ conflux version
conflux 1.0.0 (1fea995613e4326c6a70a1a87f57dc120f6b98c9) linux/amd64
fips140 on, Go Cryptographic Module v1.26.0
anchor set 1c647d7e06874286
  anchord    be6edb0db7ae…
  anchorctl  dfe2e7a147fd…
```

A conflux built against the module refuses every command, `version` included, when GODEBUG
switches FIPS 140-3 mode off; see [security.md](security.md#fips-140-3-and-cmvp).

## `conflux update`

```
conflux update
conflux update --check
conflux update --yes
```

Replaces this conflux with the one the `latest` release of
[veil-net/conflux](https://github.com/veil-net/conflux/releases/latest) holds for this
platform, and moves the boot service onto it. Only when typed: nothing checks on a
schedule, so a machine changes version when somebody decides it should. It reads `latest`
alone, so a dev build installed from `dev-latest` updates to the release, never to a newer dev
build: that is the install script's to fetch again, by name ([install.md](install.md)). And since
a dev build's anchor is pinned to the dev tree and the release's to the production tree, where
the credential the machine holds is not valid, `update` on a dev build says so and changes
nothing until it is asked again with `--yes`; after that, the machine enrols again with
`conflux up --api` naming the production API. `conflux version` says when it is a dev build.

"Up to date" is a digest rather than a version string. This file is the release's
binary, byte for byte, or it is not, so a rebuild of the same version (which a merge
that leaves `VERSION` alone publishes) is an update too. `--check` says which, names
the release and the commit it was built from, and changes nothing.

An update is held to the SHA-256 the release document lists for the asset, which the
API answers directly; the binary comes through GitHub's redirect to its storage and is
compared before it is put anywhere it could run from. Then the new conflux is run once,
for its `version`, and only a conflux that answers replaces this one. It is renamed over
the file conflux was started from, symlinks followed, so whatever is running keeps the
file it has; on Windows the running image is moved aside to `conflux.exe.old` first. That
image is the conflux handing the service over, which runs the new one's `start` or `register`,
so it is still running as they remove what earlier conflux left; it goes with the next update,
or `uninstall`. No token is needed or sent: the repository is public.

Before the new conflux judges the roots, places its copy or registers the service — through its
`start` or its `register`, whichever the update hands the service over by — it removes what
earlier conflux left everywhere conflux keeps files, every time, and makes afresh what it removed,
so an update works on an older install as it is:

- the service is stopped where a supervisor still serves the root, asked of the supervisor's lock
  without trusting the root, and started again, on the new conflux, however the command ends: by
  `start`'s restart, by `register`, which starts nothing it did not stop, and by either where
  anything after this fails. A supervisor that still serves the root with the service stopped —
  one started by hand — is refused, exit 1, naming the root, with nothing removed;
- on Windows, what conflux makes again by its name in the root — `logs\`, `run\`, the lock files,
  `bin\`, the service's copy and the image moved aside, `anchord.json`, and what an atomic write or
  a copy left before its rename — that the service, running as SYSTEM, would refuse is removed
  through handles, never through a link: what an older conflux on a Windows client left as the
  administrator's own, which a handle opened then could still change. Anything else the service
  would refuse — the identity, the configuration, the state — is refused, naming it, with nothing
  removed after ([windows.md](windows.md#file-permissions)). Then the roots are secured, as at
  every start, and the supervisor's lock held, so none starts meanwhile;
- the `anchord` a supervisor that died left running is stopped, and the run directory emptied —
  token, readiness marker, pid record, `anchord`'s socket directory — for the next supervisor to
  make again;
- every extracted anchor set, the current one among them, and whatever a crashed extraction left
  staged, are removed, and this build's pair is extracted afresh, so nothing planted among them is
  kept or run;
- a killed ephemeral run's root is removed, the `anchord` it left stopped; a live run's is left;
- where nothing holds the state's lock, what an atomic write that never went in place left in the
  configuration and state directories goes;
- the lock files — the state's, the supervisor's and `bin`'s — are kept on Unix, where a lock
  waited for on a file removed meanwhile would be held beside one taken on the file made again at
  its name; on Windows, which removes no file anybody has open, each is removed once nothing holds
  it, with the `bin` directory, for whatever next takes it to make again;
- the service's copy is written afresh, whatever it holds, with the image Windows moved aside
  and a copy that never went in place beside it removed;
- what an earlier update left beside conflux goes: a download that never went in place, and on
  Windows an earlier update's `conflux.exe.old` (elsewhere a file of that name is yours, and
  kept).

The configuration, the identity, the state, the anchor directories and the log are kept. It
lists what it removed, and nothing it did not. What the next start clears again as it starts —
the `anchord` a dead supervisor left, the run directory, a killed ephemeral run's root — it warns
of where it cannot remove it, and goes on; any other failure, the `bin` directory not emptied among
them, fails it, the service it stopped started again.

| Situation | |
|---|---|
| this is the latest release | says so, exit 0, nothing changed |
| the anchor is running | the new conflux's `start` restarts it on the new version, and its exit code is `update`'s |
| installed, not running | left stopped, as `down` left it; the new conflux removes what earlier conflux left and registers the boot service itself, its copy and its definition, through a hidden `register` that starts nothing, so it starts on the new version next time; its exit code is `update`'s |
| not installed | the file is replaced, and that is all |
| installed, its root refused by the [readers' check](security.md#the-file-and-the-directory-around-it) | exit 1, naming the root and why, before anything is downloaded: nothing changed, the service left on the conflux it runs |
| the release has no build for this platform, lists no digest, or is still uploading | refused, nothing changed |

Needs root, except `--check`.

## `conflux cert`

```
conflux cert genkey | req | selfsign | sign | verify | show | convert | match | fingerprint | crl | ca | p12 | probe | serve  ...
```

Keys, certificate signing requests, certificates and revocation lists, made and checked with the
Go Cryptographic Module in FIPS 140-3 mode: ML-DSA-87 by default, with ECDSA, RSA and Ed25519
beside it; a certificate authority kept in a directory (`ca init`, `issue`, `revoke`, `list`, `crl`);
PKCS#12 bundles in the one profile FIPS 140-3 approves throughout (`p12 export`, `import`);
and a FIPS 140-3 mode TLS client and server (`probe`, `serve`) that say what a handshake
negotiated, post-quantum or not. It needs no root, no configuration and no anchor. A conflux that
does not run in FIPS 140-3 mode (OpenBSD's) refuses every `cert` command, with exit 70. `verify`,
`match` and `probe` exit 3 when the check does not hold. [cert.md](cert.md) has every command and flag.

It is not anchorctl's `keygen` or `issue`, which make an anchor's identity and its
credentials; `cert` makes X.509, for TLS and anything else that takes a certificate.

## `conflux anchorctl ARGS...`

Runs the embedded `anchorctl` with those arguments and no interpretation. This is how
to reach a shadowed command, or one conflux refuses to pass through. A leading `--` is
accepted and ignored.

## Pass-through

Anything else is handed to `anchorctl` verbatim. On Unix conflux replaces its own
process with it, so the stdio, the exit code and the signals are the child's with no
translation.

Two kinds of command need nothing of conflux's: usage (`help`, or a help flag), which reaches
no daemon, and one naming a socket of your own (`-socket`, or `ANCHOR_SOCKET`), which reaches a
daemon conflux does not manage. Both run `anchorctl` as a child, from the extraction already
there, where the root passes the [readers' check](#a-root-another-account-could-change) and a whole
one is, or otherwise — the root refused, or not there — a private temporary copy removed afterwards,
reading nothing in the root. They extract nothing and make none of conflux's directories, so an
account that cannot write them still reaches its own daemon. The copy goes
in the system's temporary directory, which must exist, or, where that is mounted noexec, in
your cache directory, which is made if it is not there yet; no other directory is. A SIGTERM, SIGHUP
or SIGINT sent to conflux is passed on to that child, so nothing outlives conflux, and conflux
ends as the child ends: with its exit code, or by the same signal. The copy goes either way. A
SIGHUP or SIGINT conflux was started ignoring, as `nohup` starts it ignoring SIGHUP, stays
ignored by conflux, and the child starts with it ignored, as it would from your shell; a
command of anchorctl's that watches (`status -watch`, `events`, `subscribe`) takes SIGINT for
itself either way.

On Windows every pass-through runs `anchorctl` as a child, since there is no replacing a
process. Nothing is passed on there, and nothing needs to be: what a console sends — Ctrl+C,
Ctrl+Break, its closing, a logoff or a shutdown — reaches every process attached to it, and the
child shares conflux's. A process ended outright (`taskkill /F`, `Stop-Process`) is the one
case it misses.

conflux supplies the connection details through the environment (`ANCHOR_SOCKET`,
`ANCHORD_TOKEN`) rather than injecting flags, and only where they are not already set. One
exported empty is unset, as anchorctl reads it, and conflux's takes its place.
A `-socket` you type, or `ANCHOR_SOCKET` set, runs anchorctl with your environment alone.

A command that makes the daemon itself open a path you name — `keygen -out` and
`priv -out`, which write "on the daemon's filesystem", or export certificates given by path
— opens it with `anchord`'s rights, which are an account of its own's wherever its mode
allows. A path that account cannot reach is refused by `anchord`, naming it: choose one it
can, or leave out `-out` and the key comes back to your terminal.

One case is intercepted: when no daemon is running, conflux says so and names `start`,
`up`, `proxy` and `observe`. anchorctl's own answer at that point asks whether anchord is running on
that socket, which is true and no help to somebody holding conflux, who never started
anchord. Everything else — including anchorctl's genuinely good explanations of every
other refusal — passes through untouched.

## Environment

| Variable | Effect |
|---|---|
| `CONFLUX_DIR` | roots a whole separate conflux installation in one directory — config, identity, socket and the boot service, which is named after the root so it cannot replace the machine's own. What the tests use. See [testing.md](testing.md). |
| `CONFLUX_DEBUG=1` | pass `-v` to anchord. |
| `CONFLUX_EPHEMERAL=1` | send pass-through to the ephemeral anchor while an installed one runs too, which it otherwise reaches first. See [ephemeral.md](ephemeral.md#reaching-it-from-another-terminal). |
| `CONFLUX_ALLOW_INSECURE_API=1` | permit a plain-http API base. For tests only. |
| `ANCHOR_SOCKET`, `ANCHORD_TOKEN` | if set, conflux leaves them alone and pass-through uses yours; set empty, each is unset, and conflux's is used; with `ANCHOR_SOCKET` naming a daemon, pass-through makes nothing of conflux's and needs no root (see [Pass-through](#pass-through)). conflux's own calls — `up`, `status`, `renew`, an ephemeral run's start — always use conflux's daemon, whatever these say. |

## Exit codes

| Code | Meaning |
|---|---|
| 0 | success |
| 1 | failure |
| 2 | usage |
| 3 | `conflux cert verify`, `match` or `probe`: the check ran and did not hold |
| 13 | needs root or Administrator: a verb that changes the machine, `status` where the configuration is closed to this account, or a pass-through that cannot read the daemon's token |
| 69 | nothing here to act on: nothing running, or no credential to renew |
| 70 | a configuration conflux or anchor refuses for good, or a conflux built for FIPS 140-3 mode run with it switched off, or `conflux cert` where it does not run in that mode; on Windows, a build older than 1803's, and, run elevated, every command but `version`, `help` and `cert` where the Administrators could not be made the owner of what it makes ([windows.md](windows.md#file-permissions)); the systemd unit does not restart on it |
| 78 | no configuration — the code the systemd unit keys `RestartPreventExitStatus` on |
| other | for pass-through, anchorctl's own code, verbatim |
