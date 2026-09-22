# Commands

conflux keeps a closed set of names for itself. Every other argument vector is handed
to the embedded `anchorctl` unchanged — not parsed, not rewritten, not validated.

## The split

conflux's: `up`, `proxy`, `enrol`, `start`, `down`, `install`, `uninstall`, `renew`,
`status`, `version`, `help`, plus `anchorctl` as an escape hatch and a hidden `serve`
the boot service runs.

anchorctl's, reached by typing them: `peers`, `route`, `routes`, `connect`, `punch`,
`kill`, `events`, `metrics`, `export`, `children`, `telemetry`, `send`, `subscribe`,
`keygen`, `issue`, `delegate`, `renew-link`, `install-link`, `id`, `inspect`, `config`,
`root`, `mint-realm`, `mint-anchor`. The last three are absent from the binary conflux
embeds: `root` mints a realm and is not in the lockdown build, and the two `mint-*`
verbs exist only in it.

`export` is worth naming separately now, because there are two ways to set it and they
do not last equally long. `conflux anchorctl export -endpoint …` configures the running
daemon and is discarded at the next restart or SIGHUP; the `export` block in
`conflux.json` is rendered to anchord's config file on every start and is the durable
one. `conflux status` says which the daemon is currently obeying. See
[config.md](config.md#export).

`kill` is worth naming separately, because it is not what the word suggests and is not
related to `down`. It makes another anchor **a realm-wide target** — `-target ANCHORID
-days N` — needs a credential issued with `-admin`, travels by gossip, and nothing can
end one early. Stopping the anchor on *this* machine is `conflux down`, which closes it
gracefully and leaves the registration; see [service.md](service.md).

### The four collisions

`start`, `proxy`, `renew` and `status` exist on both sides. Each is resolved
explicitly.

This page, the README and two comments in the source used to disagree about the
number — they said nine, ten, three and five between them, and one of them counted
`help` as anchorctl's, which it is not: anchorctl has no `help` command and forwarding
an unrecognised name to it prints its general usage. `TestTheCollisionsAreTheDocumentedOnes`
now reads the set off the embedded binary, so a future anchor adding a colliding name
fails CI here rather than shadowing something silently.

**`help`** is conflux's, always, and is not one of the four. It prints conflux's usage
and then anchorctl's whole usage beneath a rule, so one page covers both surfaces.

**`status`** is resolved by arity. Bare `conflux status` is conflux's, and it prints
`anchorctl status` underneath — additive, so nothing is lost by conflux owning that
spelling. Given any argument it forwards, so `conflux status -watch 5s` and
`conflux status -h` do what an anchor user expects.

**`proxy`** is resolved by shape, and the ambiguous case is refused rather than
guessed. Positional `PORT=BACKEND` specs and `--taint` are conflux's; any other
dash-prefixed argument prints both meanings and exits 2. A "leading dash means
anchorctl" heuristic was considered and rejected: `--taint` leads with a dash too, and
Go's flag package treats `-x` and `--x` identically, so the double dash carries no
signal.

**`renew`** is resolved by shape, like `proxy`. conflux's takes no arguments at all:
it fetches a fresh credential from the enrolment API and installs it. anchorctl's
takes `-cred FILE` and installs one the caller already holds. So any flag reaching
`conflux renew` other than `-h` names anchorctl's, and is answered with the escape
hatch rather than guessed at.

**`start`** is resolved by shape, like `renew`. conflux's takes no arguments at all:
it starts the anchor this machine is already configured for. anchorctl's builds one
from arguments the caller supplies. So any flag reaching `conflux start` other than
`-h` names anchorctl's, and is answered with the escape hatch rather than guessed at.

**`stop` and `restart`** are anchorctl's and conflux refuses to pass them through.
Running them directly would stop an anchor conflux believes is running, or build one
its configuration does not describe, and the next reboot would silently disagree. The
refusal names `down` and `start` and the escape hatch.

## `conflux up`

```
conflux up [--taint T]... [--ipv4 PREFIX | --no-ipv4] [--subnet CIDR]... [--interface NAME]
           [--uplink DEV | --no-uplink] [--peers HOST:PORT]... [--no-peers] [--api URL]
           [--port N | --no-port] [--low-latency] [--lan-discovery yes|no|auto]
           [--serve-exit] [--use-exit]
```

Enrols this machine if it has never been, starts an anchor in TUN mode, writes the
configuration, and registers the boot service.

| Flag | Meaning |
|---|---|
| `--taint T` | a compartment label; repeat to carry more than one. Omit it and conflux mints one and prints it. |
| `--no-taint` | join the realm's shared compartment instead. A deliberate choice; see [concepts.md](concepts.md). |
| `--ipv4 PREFIX` | the overlay IPv4, as a prefix: `10.128.0.7/24`. |
| `--no-ipv4` | IPv6-only, without prompting. |
| `--subnet CIDR` | a private network this machine forwards for the realm; repeat for more. See [modes.md](modes.md). |
| `--interface NAME` | the network interface name. Default `anchor0`. |
| `--uplink DEV` | reach the realm over a link rather than the host's network: `/dev/ttyUSB0`, or `/dev/ttyUSB0:115200` with a line speed. See [uplink.md](uplink.md). |
| `--no-uplink` | go back to the host's network on a machine configured for a link. |
| `--peers HOST:PORT` | where to start looking for the realm; repeat for more. `anchorxxx@host:port` also works. Enrolment supplies this, so it is an override — see below. |
| `--no-peers` | forget an override and go back to the list enrolment supplies. |
| `--api URL` | the enrolment API base. Default `https://api.veilnet.com.au`. |
| `--port N` | the UDP port to bind, 1–65535. Omit it and the kernel picks one. |
| `--no-port` | go back to letting the kernel pick. |
| `--low-latency` | carry frames on QUIC datagrams: no head-of-line blocking between flows to one peer, and a lost frame stays lost rather than holding up the ones behind it. |
| `--no-low-latency` | go back to carrying frames on streams. |
| `--lan-discovery` | `yes`, `no`, or `auto`. Probe the networks this host is attached to for anchors of the same realm tree — a third bootstrap source, tried *with* the configured and remembered ones rather than as a fallback when they are empty. `auto` is the default and passes nothing, which leaves the answer to enrolment's own `lanDiscovery` and, failing that, to anchor, where it is on. Typing `auto` is the way back from a persisted `yes` or `no`. Refused as an explicit `yes` beside `--uplink`: there is no host network to probe and nothing on a cable to answer. It never replaces enrolment — the probe is sealed under the realm's root public key, which a machine only holds once it has enrolled. |
| `--serve-exit` | offer this machine as a way out to the public internet. |
| `--use-exit` | send this machine's own internet traffic over the overlay. |
| `--no-serve-exit`, `--no-use-exit` | the way back from either. |

An anchor listens on **every** interface, so `--port` is a port and not an address:
the host's addresses change underneath it, and pinning one is a promise the host
cannot keep. Name a port to write a firewall rule or a port-forward against; leave it
alone otherwise. It is refused beside `--uplink`, which binds no socket at all.

Both exits need a host interface, so both are `up`'s and not `proxy`'s. Neither is
ever inherited from the enrolment manifest: conflux passes both in whichever
direction they were set, because an anchor that became an internet exit because a
document said so is the worst kind of surprise. Switching a machine to `proxy` clears
them.

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

With neither `--ipv4` nor `--no-ipv4`, conflux prompts — once. Re-running it on a
machine that already has a configuration keeps the existing address and asks nothing.
With no terminal to prompt at and neither flag given, it exits 2 rather than hang,
which is what makes it safe in a script.

Needs root.

## `conflux proxy`

```
conflux proxy PORT[/NETWORK]=BACKEND ... [--taint T]... [--uplink DEV | --no-uplink]
              [--peers HOST:PORT]... [--no-peers] [--api URL]
              [--port N | --no-port] [--low-latency] [--lan-discovery yes|no|auto]
```

Starts in userspace mode serving those backends. Same taint, uplink, peers, API,
`--port`, `--low-latency` and `--lan-discovery` flags as `up`. Specs and flags may be written in either
order.

`--serve-exit` and `--use-exit` are not here: routing the public internet either way
needs a host interface, which userspace mode has none of.

The grammar is `OVERLAYPORT[/NETWORK]=BACKEND`: the network defaults to `tcp` and must
be `tcp` or `udp`, the port is 1–65535, and a duplicate overlay port is refused rather
than silently keeping the last. See [modes.md](modes.md) for the spec table, and
`conflux anchorctl proxy` for adding and removing them on an anchor already running.

Needs root, only to register the boot service.

## `conflux start`

```
conflux start
```

Starts the anchor now, from the configuration already on disk, in whichever mode it
names. Takes no arguments: it decides nothing, enrols nothing, and invents no
configuration.

The counterpart to `down`, and the reason it exists. `down` deliberately leaves the
boot registration and the configuration in place, so there has to be a word for
"bring that back now" that is not a reboot. That word used to be `conflux install`,
whose name and usage line both say *register the boot service* — it started one as a
side effect, and pointing an operator at it was papering over a missing verb.

It is mode-agnostic on purpose. `up` would do for a TUN machine, but `up` is not a
resume: it re-decides the configuration, and on a userspace machine it changes the
mode and drops the proxies. A machine serving eight ports cannot be brought back by
retyping eight specs correctly from memory.

| Situation | |
|---|---|
| not installed | exit 69, naming `install`, `up` and `proxy` — there is no service to start |
| installed, no configuration | exit 78, naming `up` and `proxy` — there is nothing to start |
| already running | restarts it. A `start` that refused would be answering a question nobody asked |

Needs root.

## `conflux down`

Stops the anchor now. The boot service stays registered and the configuration and
identity stay on disk, so the next reboot brings the machine back exactly as it was,
and `conflux start` brings it back before then. Refuses with exit 69 if conflux is not
installed, because there would be nothing for a reboot to bring back and the word
would be a lie.

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
conflux enrol --manifest FILE [--api URL] [--ipv4 PREFIX] [--taint T]...
```

Installs a credential this machine was **given** rather than one it drew.

The public alpha realm hands out identities to anyone who asks and records none of
them, which is why `up` can enrol by itself. A self-hosted guardian does the opposite:
it serves no enrolment route at all, commissions each machine in advance, and hands its
operator one file per machine. This is how that file gets in, and on a guardian
deployment it is the only way a node is provisioned.

`--manifest -` reads the document from stdin, so it need never land on disk at whatever
mode the shell's umask chose. anchorctl spells the same thing the same way.

**The file is enough on its own, and the three flags are overrides.** A guardian
document carries an absolute `renewalUrl`, the overlay address the guardian allocated
out of its realm's range, and the compartment it put the machine in — because a guardian
knows all three and the operator would only be retyping them. That is the difference
between this and the public alpha realm, whose document carries an identity and little
else.

| | overrides | when you would |
|---|---|---|
| `--api URL` | the API base read out of `renewalUrl` | the guardian is reached at a different name from here — a split-horizon DNS, a bastion |
| `--ipv4 PREFIX` | the address the issuer allocated | you are rebuilding a machine onto an address something else already hardcodes |
| `--taint T` | the compartment the issuer chose; repeat for more | this machine belongs in a different compartment from the one it was commissioned into |

`--api` is also an assertion when given: the document must renew against the same host,
and a mismatch is refused naming both rather than discovered at the first renewal weeks
later. It stopped being *required* because the argument for requiring it does not hold —
the same document carries the identity seed and the renewal bearer, so anybody able to
rewrite its `renewalUrl` already holds everything a redirect would steal.

**Taints are validated, not copied through.** A label conflux cannot carry — a comma, a
space, over 64 bytes, more than 32 of them — is refused here rather than at the next
start, where the complaint would come from anchor instead of from the document that
caused it. A document carrying none leaves the configuration with none, and `up` then
mints one and says so; choosing a compartment quietly is the one thing conflux will not
do.

**It refuses to replace an existing manifest.** `up` enrols only when there is none,
because a second enrolment is a second AnchorID and a second overlay address with every
peer orphaned and nothing said; a verb that writes manifests must not be the way around
that rule. `conflux uninstall` first if replacing the identity is genuinely what you
mean.

Everything is checked before a byte is written — the format version, the `kind` (a
`realm` manifest mints anchors and does not start one), the `renewalAuth`, the renewal
host, the address and the export block. A refused import leaves the machine exactly as
it found it.

Two fields are copied out of the document **once** and into `conflux.json`, where
`conflux config` shows them and you can change them: `ipv4`, the overlay address the
issuer allocated, and `export`, where it suggests telemetry goes. Neither is re-read on
a later start. That is the difference from the two exit flags, which conflux refuses to
inherit at all — an exit flag would go on deciding what this machine does for other
people, and these are a suggestion made once at commissioning time. `--ipv4` overrides
the document.

Then `sudo conflux up`, which finds the manifest and starts from it without enrolling.

Needs root.

## `conflux renew`

```
conflux renew
```

Fetches a fresh credential from the enrolment API and installs it on the anchor that
is already running. Takes no arguments.

The swap is hot — `anchorctl renew`, which calls `SetRealmCred` — so the identity does
not change and not one session is dropped. It is not a restart and does not need to be
treated as one.

Renewal is automatic in two places already: once at every start, before the anchor is
built, and again on a timer at two thirds of the credential's life. So this command is
not part of normal operation. It is for the machine whose renewals have been failing —
`conflux status` prints `renewal: failing since ...` — where the alternative was
restarting the service and paying every session for a swap that needs none of them.

It does not enrol. A machine with no manifest has nothing to renew, and drawing an
identity here would replace the one a reboot expects; it says so and exits 69. It also
exits 69 when nothing is running, because a credential is installed *into* a running
anchor, and a machine that is meant to be down renews on its next start anyway.

Needs root.

## `conflux uninstall`

Removes the boot service, the configuration and the identity. Asks first, because
there is no other copy of the credential anywhere; `--yes` skips the question, and a
non-interactive run without `--yes` refuses rather than destroy an identity silently.

## `conflux status`

conflux's state — service, mode, exit, taint, AnchorID, credential expiry, API, and
the uplink reopen tally if there is one — and then `anchorctl status` beneath it.
Exits 78 when the machine has no configuration.

The `exit` line appears only when this machine is an exit one way or the other.
conflux goes to some trouble not to become one by accident, so a machine that *is*
one should not need a config file read to find out.

## `conflux version`

conflux's version and commit, and the SHA-256 of both embedded anchor binaries. Put
this in a bug report; it names the exact anchor build without running it.

## `conflux anchorctl ARGS...`

Runs the embedded `anchorctl` with those arguments and no interpretation. This is how
to reach a shadowed command, or one conflux refuses to pass through. A leading `--` is
accepted and ignored.

## Pass-through

Anything else is handed to `anchorctl` verbatim. On Unix conflux replaces its own
process with it, so the stdio, the exit code and the signals are the child's with no
translation.

conflux supplies the connection details through the environment (`ANCHOR_SOCKET`,
`ANCHORD_TOKEN`) rather than injecting flags, and only where they are not already set.
anchorctl resolves the socket as `firstNonEmpty(-socket, global -socket,
ANCHOR_SOCKET)`, so a flag you typed still wins and conflux never rewrites an argv.

One case is intercepted: when no daemon is running, conflux says so and names `up`,
`proxy` and `install`. anchorctl's own hint at that point reads `anchorctl start
-identity FILE -root FILE -cred FILE`, which is correct for anchor and useless to
somebody holding conflux. Everything else — including anchorctl's genuinely good
explanations of every other refusal — passes through untouched.

## Environment

| Variable | Effect |
|---|---|
| `CONFLUX_DIR` | roots a whole separate conflux installation in one directory — config, identity, socket and the boot service, which is named after the root so it cannot replace the machine's own. What the tests use. See [testing.md](testing.md). |
| `CONFLUX_DEBUG=1` | pass `-v` to anchord. |
| `CONFLUX_ALLOW_INSECURE_API=1` | permit a plain-http API base. For tests only. |
| `ANCHOR_SOCKET`, `ANCHORD_TOKEN` | if already set, conflux leaves them alone and pass-through uses yours. |

## Exit codes

| Code | Meaning |
|---|---|
| 0 | success |
| 1 | failure |
| 2 | usage |
| 13 | needs root or Administrator |
| 69 | nothing is running here |
| 70 | anchord itself would not start |
| 78 | no configuration — the code the systemd unit keys `RestartPreventExitStatus` on |
| other | for pass-through, anchorctl's own code, verbatim |
