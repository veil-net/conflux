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
| `internal/config` | JSON round-trips; the mode rule matches anchor's; proxy specs, IPv4 prefixes and taint names parse and refuse exactly as anchor does; atomic writes leave old-or-new and never a truncated file, and narrow a file that was `0644` |
| `internal/enrol` | the manifest decodes, refuses a realm manifest and a future format version, and **survives a renewal losslessly** |
| `internal/enrol` (client) | against `httptest`: the happy path, malformed base64, 4xx and 5xx, an oversized body, a cross-host renewal URL, a plain-http base, cancellation, and clock skew |
| `internal/taint` | generated names satisfy anchor's rule, avoid ambiguous glyphs, and do not repeat |
| `internal/daemon` | the renewal arithmetic: two thirds of the *observed* window, expiry, absent timestamps, and the clamp |
| `internal/anchorctl` | the argv goldens, that every flag they use exists, and the output parsers |
| `internal/libexec` | extraction, idempotence, eight concurrent callers, and repair of a truncated set |
| `internal/cli` | the collision rules, and that nothing shadows anchorctl unintentionally |

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

## What has no coverage, and why

- **FreeBSD and OpenBSD** beyond `go vet` and `go build`. No runner exists, which is
  the same position anchor is in.
- **macOS TUN under a LaunchDaemon.** CI can build and test on macOS, but not open a
  utun from a system daemon.
- **The Windows service's recovery actions.**
- **A real uplink.** What is covered here is the spec parser, the argv, and the
  refusals — the `fd:N` form conflux's supervisor cannot hand over, and Windows, where
  anchor has no way to open a link. Nothing in this tree opens a device or a
  pseudo-terminal: the link itself is anchor's to test, and it does, over a real pty.
  Two machines on a cable have no runner.
- **The boot service and the two-node integration test, in CI.** Both need the real
  anchor binaries, which are not in git and which a runner has no way to fetch, so
  both are `workflow_dispatch` only. They are run locally: `./test/integration.sh`.
  When `anchor/bin` gains a source CI can reach, remove the `if:` on those two jobs.

A local fake for the enrolment API is used for the client's error paths, but it cannot
stand in for a full end-to-end test: the shipped `anchord` is pinned to the production
genesis and the `anchorctl` beside it is the lockdown build, so nothing can mint a
credential those binaries will accept.
