# Commands

conflux keeps eight names for itself. Every other argument vector is handed to the
embedded `anchorctl` unchanged — not parsed, not rewritten, not validated.

## The split

conflux's: `up`, `proxy`, `down`, `install`, `uninstall`, `status`, `version`, `help`,
plus `anchorctl` as an escape hatch and a hidden `serve` the boot service runs.

anchorctl's, reached by typing them: `peers`, `route`, `routes`, `connect`, `punch`,
`events`, `metrics`, `export`, `children`, `telemetry`, `send`, `subscribe`, `keygen`,
`issue`, `delegate`, `renew-link`, `install-link`, `id`, `inspect`, `config`, `renew`,
`mint-realm`, `mint-anchor`.

### The four collisions

`proxy`, `renew`, `status` and `help` exist on both sides. Each is resolved
explicitly.

**`help`** is conflux's, always. It prints conflux's usage and then anchorctl's whole
usage beneath a rule, so one page covers both surfaces.

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

**`start`, `stop` and `restart`** are anchorctl's and conflux refuses to pass them
through. Running them directly would build an anchor conflux's configuration does not
describe, or stop one conflux believes is running, and the next reboot would silently
disagree. The refusal names `up` and `down` and the escape hatch.

## `conflux up`

```
conflux up [--taint T]... [--ipv4 PREFIX | --no-ipv4] [--subnet CIDR]... [--interface NAME]
           [--uplink DEV | --no-uplink] [--peers HOST:PORT]... [--no-peers] [--api URL]
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
```

Starts in userspace mode serving those backends. Same taint, uplink and API flags as
`up`. Specs and flags may be written in either order.

The grammar is `OVERLAYPORT[/NETWORK]=BACKEND`: the network defaults to `tcp` and must
be `tcp` or `udp`, the port is 1–65535, and a duplicate overlay port is refused rather
than silently keeping the last. See [modes.md](modes.md) for the spec table, and
`conflux anchorctl proxy` for adding and removing them on an anchor already running.

Needs root, only to register the boot service.

## `conflux down`

Stops the anchor now. The boot service stays registered and the configuration and
identity stay on disk, so the next reboot brings the machine back exactly as it was.
Refuses with exit 69 if conflux is not installed, because there would be nothing for a
reboot to bring back and the word would be a lie.

## `conflux install`

Registers the boot service. If a configuration exists it is also started; if not, it
registers the service, says plainly that there is nothing to start, and exits 0. No
configuration is invented.

`up` and `proxy` call it internally after writing their configuration, so there is one
path for "register and run" and one for "configure, persist, then register and run".

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

conflux's state — service, mode, taint, AnchorID, credential expiry, API — and then
`anchorctl status` beneath it. Exits 78 when the machine has no configuration.

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
| `CONFLUX_DIR` | roots every conflux path in one directory. What the tests use. |
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
