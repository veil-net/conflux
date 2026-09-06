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

### The three collisions

`proxy`, `status` and `help` exist on both sides. Each is resolved explicitly.

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

**`start`, `stop` and `restart`** are anchorctl's and conflux refuses to pass them
through. Running them directly would build an anchor conflux's configuration does not
describe, or stop one conflux believes is running, and the next reboot would silently
disagree. The refusal names `up` and `down` and the escape hatch.

## `conflux up`

```
conflux up [--taint T]... [--ipv4 PREFIX | --no-ipv4] [--subnet CIDR]... [--interface NAME] [--api URL]
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
| `--api URL` | the enrolment API base. Default `https://api.veilnet.com.au`. |

With neither `--ipv4` nor `--no-ipv4`, conflux prompts — once. Re-running it on a
machine that already has a configuration keeps the existing address and asks nothing.
With no terminal to prompt at and neither flag given, it exits 2 rather than hang,
which is what makes it safe in a script.

Needs root.

## `conflux proxy`

```
conflux proxy PORT[/NETWORK]=BACKEND ... [--taint T]... [--api URL]
```

Starts in userspace mode serving those backends. Same taint and API flags as `up`.
Specs and flags may be written in either order.

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
