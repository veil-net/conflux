# Testing

```console
$ make anchor-bins # populate anchor/bin; see docs/build.md
$ make test        # everything
$ make race        # under the race detector
$ make golden      # rewrite the argv fixtures after an intended change
```

Most of the suite runs without the real anchor binaries — the tests that need them
skip, and say so. The ones that do need them are the extraction tests, the flag
cross-check, and everything under `test/`.

## The split

The interesting question for a wrapper is which parts can be checked without a kernel,
a daemon or a network. Most of conflux can be.

| Package | What is asserted |
|---|---|
| `anchor` | the embedded binaries are real executables of the right architecture, and `SetID` is stable |
| `internal/config` | JSON round-trips, the tuning fields included; the mode rule matches anchor's; an exit needs a host interface and a port is refused beside an uplink; proxy specs, IPv4 prefixes and taint names parse and refuse exactly as anchor does; atomic writes leave old-or-new and never a truncated file, and narrow a file that was `0644` |
| `internal/enrol` | the manifest decodes, refuses a realm manifest and a future format version, and **survives a renewal losslessly** |
| `internal/enrol` (client) | against `httptest`: the happy path, malformed base64, 4xx and 5xx, an oversized body, a cross-host renewal URL, a plain-http base, cancellation, and clock skew |
| `internal/taint` | generated names satisfy anchor's rule, avoid ambiguous glyphs, and do not repeat |
| `internal/daemon` | the renewal arithmetic: two thirds of the *observed* window, expiry, absent timestamps, and the clamp; and the link watcher's device parsing and its grace against anchor's own dial timeout |
| `internal/anchorctl` | the argv goldens, that every flag they use exists, and the output parsers, including the metrics gauge the link watcher reads |
| `internal/libexec` | extraction, idempotence, eight concurrent callers, and repair of a truncated set |
| `internal/cli` | the collision rules — `start` and `renew` by shape, `proxy` and `status` by arity — and that nothing shadows anchorctl unintentionally |

## The three tests worth knowing about

**`anchor.TestPairIsRealExecutables`** parses each embedded binary's ELF, Mach-O or PE
header and checks the machine field against `GOARCH`. It exists because a wrong file in
`anchor/bin` — a truncated copy, one named for the wrong architecture, a CRLF-mangled
one — builds and links perfectly and fails at exec on somebody else's machine.

It skips when `anchor/bin` holds the placeholders `make anchor-bins` writes with no
anchor checkout available, which is the state CI is in. `anchor.Supported` is a size
check for the same reason, so a placeholder build reports that it carries no anchor
binaries rather than pretending.

**The argv goldens**, in `internal/anchorctl/testdata/argv/`, hold one file per
scenario, one argument per line. Argv construction is where a wrapper's bugs live and
it is invisible in a review diff — anchor's flag is `-taints`, plural — so a change to
what conflux passes anchorctl shows up as a reviewable text diff instead. `make golden`
rewrites them; CI runs `git diff --exit-code`.

Paired with them is `TestEveryFlagWeUseExists`, which runs the **embedded** anchorctl,
scrapes `start -h`, and fails if a golden names a flag that no longer exists. Go's flag
package refuses an unknown flag rather than ignoring it, so that would otherwise be a
daemon that will not start — discovered after the binaries were dropped into
`anchor/bin` and shipped.

**`enrol.TestSetChainIsLossless`** renews a manifest and compares every field. The
document carries `telemetrySecret`, `bootstrap`, `genesis` and `renewalAuth`, which
conflux has no opinion about and anchor reads. Round-tripping through a struct with
only the known fields would delete them on the first renewal, and the anchor would come
back after the next reboot with no peers to bootstrap from — days later, with nothing
pointing at the renewal that caused it.

## Testing the boot service

The part that matters most is the hardest to check: that a machine which was up before
is up again afterwards with nothing typed. A container that boots systemd is the way,
and restarting it is the reboot.

`test/systemd/Dockerfile` builds a Debian image running `systemd` as PID 1. Copy a
built `conflux` in beside it, then:

```console
$ make anchor-bins && make dist
$ cp dist/conflux-linux-amd64 test/systemd/conflux
$ docker build -t conflux-systemd-test test/systemd
$ docker run -d --name cfx-a --privileged --cgroupns=host \
    -v /sys/fs/cgroup:/sys/fs/cgroup:rw --device /dev/net/tun conflux-systemd-test
$ docker exec cfx-a conflux up --taint mynet --ipv4 10.128.0.1/24
$ docker restart cfx-a && sleep 25
$ docker exec cfx-a conflux status      # same AnchorID, nothing typed
```

A second container joining with the same taint gives a real two-node reachability
test. Allow up to a minute after the second node starts for gossip to find it — the
observed range is 15 to 60 seconds — and `conflux peers` shows `DATA yes` on the peer
once the taints have been compared.

## The genesis test node

`genesis.veilnet.com.au:4700` is a bootstrap node kept up for our own testing. It is
not a default and must never become one: end users get their bootstrap list from the
enrolment manifest, which is what lets the API move a node without touching a single
machine. Point a dev build at it explicitly:

```console
$ sudo CONFLUX_DIR=/tmp/cfx-test conflux up --peers genesis.veilnet.com.au:4700
$ sudo CONFLUX_DIR=/tmp/cfx-test conflux status     # peers > 0, up=yes
```

`CONFLUX_DIR` keeps the config, the identity, the state and the socket out of
`/etc/conflux` and `/var/lib/conflux`. Port 4700 is UDP; a TCP probe of it is refused,
and that is expected rather than a fault.

> **`CONFLUX_DIR` does not isolate the boot service.** `unitPath` is a constant —
> `/etc/systemd/system/conflux.service`, and the launchd and SCM equivalents are
> constants too — and the service package never reads `CONFLUX_DIR`. So `up` and
> `proxy` under it still rewrite that one unit and restart it, because both call
> `install` on their way through.
>
> On a machine that is already a conflux node, that replaces the running node with the
> dev build. Do this in the systemd container above, or on a machine that is not one,
> or `conflux down` and note the `ExecStart` first so it can be put back. There is no
> flag that makes the registration temporary, and inventing one to make a test tidier
> would be a boot-time behaviour nobody asked for.

To check reachability *without* touching the service, drive the embedded anchorctl
directly against a daemon you start yourself — that is what the escape hatch is for,
and it registers nothing:

```console
$ conflux anchorctl start -peers genesis.veilnet.com.au:4700 -identity … -root … -cred …
```

Two things worth checking deliberately, because neither is obvious from a passing run:

- **The no-flag path still works.** `conflux up` with no `--peers` must bootstrap from
  the manifest's own list. If `--peers` ever became load-bearing, every machine that
  never names one would stop finding the realm, and the test that names one would not
  notice.
- **The realm matches.** The embedded binaries are pinned to a genesis realm ID at
  build time (`-X anchor.pinnedGenesis`, see [build.md](build.md)). A test node minted
  from a different root will enrol fine and then never handshake, because the pin is
  what refuses it. That failure is on the anchor side, not conflux's.

## What has no coverage, and why

- **FreeBSD and OpenBSD** beyond `go vet` and `go build`. No runner exists, which is
  the same position anchor is in.
- **macOS TUN under a LaunchDaemon.** CI can build and test on macOS, but not open a
  utun from a system daemon.
- **The Windows service's recovery actions.**
- **A real uplink.** What is covered here is the spec parser, the argv, the refusals
  — the `fd:N` form conflux's supervisor cannot hand over, and Windows, where anchor
  has no way to open a link — and the link watcher's decision function against
  synthetic inputs. Nothing in this tree opens a device or a pseudo-terminal: the link
  itself is anchor's to test, and it does, over a real pty. Two machines on a cable
  have no runner, so the watcher's *reopen* path is reasoned about rather than run.
- **The boot service and the two-node integration test, in CI.** Both need the real
  anchor binaries, which are not in git and which a runner has no way to fetch, so
  both are `workflow_dispatch` only. They are run locally: `./test/integration.sh`.
  When `anchor/bin` gains a source CI can reach, remove the `if:` on those two jobs.

A local fake for the enrolment API is used for the client's error paths, but it cannot
stand in for a full end-to-end test: the shipped `anchord` is pinned to the production
genesis and the `anchorctl` beside it is the lockdown build, so nothing can mint a
credential those binaries will accept.
