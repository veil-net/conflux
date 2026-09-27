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
| `internal/config` | JSON round-trips, the tuning fields included; the mode rules match anchor's — a subnet and a served exit need an interface, an IPv4 and `useExit` do not, a port is refused beside an uplink; proxy specs, IPv4 addresses, subnets, bootstrap entries, AnchorIDs and taint names parse and refuse exactly as anchor does; atomic writes leave old-or-new and never a truncated file, and narrow a file that was `0644` |
| `internal/enrol` | the manifest decodes exactly as anchorctl reads it, refuses a realm manifest and a future format version, and **survives a renewal losslessly** |
| `internal/enrol` (client) | against `httptest`: the alpha exchange byte for byte, the guardian bearer, 4xx and 5xx, an oversized body, a cross-host renewal URL and a downgrading redirect, a plain-http base, cancellation, and clock skew; and that an enrolment is handed back as it arrived, to be written before it is read |
| `internal/taint` | generated names satisfy anchor's rule, avoid ambiguous glyphs, and do not repeat |
| `internal/daemon` | the renewal arithmetic: two thirds of the *observed* window, expiry, absent timestamps, and the clamp; a renewal against a stand-in issuer, spliced into the manifest and mirrored into the state, and a failed one recorded; an enrolment kept before it is read; a bad clock measured again rather than trusted; anchord's last words kept when it dies; the link watcher's device parsing and its grace against anchor's own dial timeout; and which failures stop the supervisor rather than being retried |
| `internal/anchorctl` | the argv goldens, that every flag they use exists, and the output parsers against anchor's current `start`, `status` and `metrics` shapes |
| `internal/libexec` | extraction, idempotence, eight concurrent callers, and repair of a truncated set |
| `internal/cli` | the collision rules — `start` and `renew` by shape, `proxy` and `status` by arity — and that nothing shadows anchorctl unintentionally; the IPv4 asked once; `enrol` refusing before it writes |
| `internal/service` | the rc scripts the BSDs get, rendered and parsed by `sh`, quoting included; the service's scope |
| `internal/paths` (Windows) | the root made Administrators', and files restricted to them trusted |

## The three tests worth knowing about

**`anchor.TestPairIsRealExecutables`** parses each embedded binary's ELF, Mach-O or PE
header and checks the machine field against `GOARCH`. It exists because a wrong file in
`anchor/bin` — a truncated copy, one named for the wrong architecture, a CRLF-mangled
one — builds and links perfectly and fails at exec on somebody else's machine.

It skips when `anchor/bin` holds the placeholders `make anchor-bins` writes with no
anchor checkout available. `anchor.Supported` is a size check for the same reason, so
a placeholder build reports that it carries no anchor binaries rather than pretending.

A skip is green, so the job that fetches the real binaries asserts that none of the
tests needing them skipped: a job that provides the binaries and then reports "no
anchor pair" has lost them, and saying so is the difference between a gate and a
decoration.

**The argv goldens**, in `internal/anchorctl/testdata/argv/`, hold one file per
scenario, one argument per line. Argv construction is where a wrapper's bugs live and
it is invisible in a review diff — anchor's flag is `-taints`, plural — so a change to
what conflux passes anchorctl shows up as a reviewable text diff instead. `make golden`
rewrites them after an intended change, and `TestArgvGoldens` fails on any other.

Paired with them is `TestEveryFlagWeUseExists`, which runs the **embedded** anchorctl,
scrapes each command's `-h`, and fails if conflux's argv names a flag that no longer
exists — every flag conflux can pass, including the ones it passes only when set. Go's flag
package refuses an unknown flag rather than ignoring it, so that would otherwise be a
daemon that will not start — discovered after the binaries were dropped into
`anchor/bin` and shipped.

**`enrol.TestWithChainIsLossless`** renews a manifest and compares every field. The
document carries `bootstrap`, `genesis`, `realm` and `renewalAuth`, which conflux has no
opinion about and anchor reads. Round-tripping through a struct with only the known
fields would delete them on the first renewal, and the anchor would come back after the
next reboot with no peers to bootstrap from — days later, with nothing pointing at the
renewal that caused it.

## Testing the boot service

The part that matters most is the hardest to check: that a machine which was up before
is up again afterwards with nothing typed. A container that boots systemd is the way,
and restarting it is the reboot.

`test/systemd/Dockerfile` builds a Debian 13 image running `systemd` as PID 1. Copy a
built `conflux` in beside it, then:

```console
$ make anchor-bins && make integration   # the whole suite, three nodes
$ make service-test                      # or just the unit, which enrols nothing
```

By hand, which is what those run:

```console
$ make anchor-bins && make image
$ docker run -d --name cfx-a --privileged --cgroupns=host \
    -v /sys/fs/cgroup:/sys/fs/cgroup:rw --device /dev/net/tun conflux-systemd-test
$ docker exec cfx-a conflux up --taint mynet --ipv4 10.128.0.1/24
$ docker restart cfx-a && sleep 25
$ docker exec cfx-a conflux status      # same AnchorID, nothing typed
```

A second container joining with the same taint gives a real two-node reachability
test. The suite polls every second for up to two minutes and prints how long it took —
around twenty seconds on the Docker bridge — and `conflux peers` shows `DATA yes` on
the peer once the taints have been compared.

All of that is `make integration`, and the two assertions above on their own are
`make service-test`. Both build the image first, and CI runs the same command a
developer does.

### Local network discovery, the bootstrap list, and `conflux enrol`

Two containers on one Docker bridge are on the same link, which is the one thing no Go
test in this tree can arrange: a real kernel, real multicast, a real answer. anchor
probes the link only until its first connection, though, and the live realm answers
within a second — so A and B are started with `--peers 192.0.2.1:4700`, an RFC 5737
documentation address that never answers, in place of the realm's own list. The only way
they can meet is then discovery on the bridge: their reachability proves it, and
`make integration` asserts `anchor_lan_peers_found_total` is **non-zero** on one of them
— non-zero and not merely present, because the series is created the first time it is
written. Reachability is waited for in both directions, since each learns the other's
IPv4 from a signed advertisement and the two need not arrive together.

The third node takes the other paths, and it is why the suite enrols three times:

- **It is enrolled from a live alpha manifest** — fetched on the host and handed to
  `conflux enrol --manifest -` on stdin — and `up` must start from it without enrolling
  again. That is the path a commissioned machine takes, and otherwise it would only ever
  see hand-written fixtures.
- **It reaches the realm through the manifest's own bootstrap list.** It names no
  `--peers` and runs `--lan-discovery no`, and A and B reach no realm node themselves,
  so a connection can only have come from the list the issuer shipped.
- **Its discovery counter stays at zero** on the link where A and B found each other,
  which proves `--lan-discovery no` reached anchor rather than being accepted by conflux
  and dropped.

Note what discovery cannot do, and anchor's own `docs/discovery.md` is the reference:
the probe is sealed under the realm's **root public key**, which a node only holds after
it has enrolled. So it never replaces enrolment — it decides who is worth dialling,
never who is let in. Loopback is not probed, so two anchors on one machine still need
`--peers`.

## What CI runs, and on what

CI verifies that the code builds and runs. The utility checks — `gofmt`, `staticcheck`,
`go mod tidy`, `govulncheck`, the docs links — are `make all` on a developer's machine
and not CI's.

Every job fetches the **pinned** release build from the `shelf` release of
`veil-net/anchor` and verifies every digest, with no anchor checkout. It needs a
credential, since anchor is private: CI stores a GitHub App's ID and private key and
mints an hour-long token per job, so the secret held here is not itself a key to
anything — see [build.md](build.md) for why the grant is wider than it wants to be and
why it is nonetheless contained.

| job | machine | what it runs |
|---|---|---|
| `linux` | veilnet-dev | the whole suite under `-race` with the real binaries and nothing skipped; `make cross`; then `make service-test integration` — `dist` with the size gate for every target, the image, the boot service, and three nodes against the live API |
| `platforms` | GitHub macOS and Windows | the suite with that platform's own pair, the tests that need it included; on Windows, that the pinned wintun digest is the published one |

`linux` is one job because veilnet-dev is one machine with one runner process: separate
jobs would queue anyway, each paying a checkout and a fetch. Its fetch goes through the
runner's tool cache, which survives between runs, so an unchanged shelf costs a read of
the files the fetcher already holds rather than three hundred megabytes. Every job that
runs on it refuses a fork's pull request — a machine that survives the job does not run
a stranger's code — and the hosted `platforms` need the anchor credential a fork is not
given, so a fork's pull request runs nothing.

**The release** runs on a merge to `version3`, and it only releases: it does not re-run
any of the above. A merge lands only when CI is green, which rests on branch protection
on `version3` — require a pull request, require these checks, and require the branch to
be up to date before merging — and is unsafe without it. It refuses to run anywhere but
`version3`, fetches the shelf, runs `make dist`, attests the artifacts and publishes
them at the tag the `VERSION` file names, verbatim, replacing the artifacts already
there. The shelf moves, so a release carries whatever anchor published most recently,
which is the intent — conflux ships the newest anchor, not a remembered one. All seven
targets are cross-built from the one Linux machine, `CGO_ENABLED=0` throughout.

**The binaries CI uses are the pinned ones**, which a locally-built `make dist` cannot
be: an anchor pinned to the genesis realm refuses to handshake with any other tree. So
`integration` exercises the binaries that ship, against the **production realm** and
nothing else, and a join there proves the pin as well as conflux.

**A machine that is not thrown away.** Both container suites reap their fixed container
names before themselves as well as after, because a cancelled run fires neither an
`EXIT` trap nor an `if: always()` step, and the leftover name fails the *next* run for a
reason that has nothing to do with the commit under test. `test/preflight.sh` says what
the machine gives them — Docker, `/dev/net/tun`, cgroup v2, IPv6 — before anything is
built, because each of those otherwise fails much later and names something else. The
runner may be root, so `TestWriteFileAtomicPreservesOnFailure` probes whether making a
directory read-only took rather than assuming it did.

## The genesis test node

`genesis.veilnet.com.au:4700` is a bootstrap node kept up for our own testing. It is
not a default and must never become one: end users get their bootstrap list from the
enrolment manifest, which is what lets the API move a node without touching a single
machine. Point a dev build at it explicitly:

```console
$ sudo CONFLUX_DIR=/var/lib/cfx-dev conflux up --peers genesis.veilnet.com.au:4700 \
      --interface anchor1
$ sudo CONFLUX_DIR=/var/lib/cfx-dev conflux status  # peers > 0, up=yes
```

`CONFLUX_DIR` roots the whole installation somewhere else — the config, the identity,
the state, the socket, **and the boot service**. Port 4700 is UDP; a TCP probe of it is
refused, and that is expected rather than a fault.

The service is included because it has to be. A run rooted elsewhere is a separate
installation of conflux, not the machine's own, so:

- the service is named after the root — `conflux-e7616592.service`,
  `org.veilnet.conflux-e7616592`, or the same SCM entry — and cannot be registered
  over a real node's;
- the root is written into the argv the service is registered with, because no
  service manager carries the operator's environment into what it starts; without it
  the service would come back at boot reading `/etc/conflux`.

So a dev run and a real node coexist on one machine:

```console
$ conflux status                                    # the machine's own
  service      active (systemd: conflux.service, enabled at boot)
$ CONFLUX_DIR=/var/lib/cfx-dev conflux status       # the dev one
  service      active (systemd: conflux-e7616592.service, enabled at boot)
```

**They still share the interface name.** Both default to `anchor0`, and the second to
start gets `device or resource busy` — pass `--interface anchor1` to the dev one, as
above. That is the one thing `CONFLUX_DIR` does not name, because an interface belongs
to the host and not to a conflux installation. The failure is treated as permanent
rather than retried to the unit's ninety-second timeout, so it arrives in a few
seconds and says what it is.

**Not `/tmp`.** systemd clears it on boot, so a dev root there is gone by the time the
service starts and the unit exits 78 — correctly, but it makes the reboot test
meaningless. Anywhere persistent will do.

Two things worth checking deliberately, because neither is obvious from a passing run:

- **The no-flag path still works.** `conflux up` with no `--peers` must bootstrap from
  the manifest's own list — `make integration` asserts it for its third node, and a dev
  node named `--peers` is exactly the case that would not notice it breaking.
- **The realm matches.** The embedded binaries are pinned to a genesis realm ID at
  build time (`-X anchor.pinnedGenesis`, see [build.md](build.md)). A test node minted
  from a different root will enrol fine and then never handshake, because the pin is
  what refuses it. That failure is on the anchor side, not conflux's.

  This node carries **the same pin as production**, which is what makes it usable from
  an ordinary fetched build at all. Worth checking rather than assuming after the node
  is ever rebuilt: `make anchor-bins FETCH=1` prints the realm it fetched, and it has to
  be the one the test node answers for.

## The other half of the contract is tested in the other repository

`renewalAuth`, `conflux enrol` and the `export` block are half of an exchange
whose other half is guardian. Everything here asserts what conflux *sends* and
what it *accepts*; nothing here can assert that a document guardian writes is one
conflux installs, because no guardian is running.

That test lives in guardian, at `api/test/conflux.e2e-spec.ts`. It builds a
machine image from **this checkout's** `bin/conflux` — so what runs is what this
repository currently produces, not a release that may predate the change — puts
it on the deployment's own network, and drives the whole life of a node:

```
commission → conflux enrol → conflux up → conflux renew → reboot → same anchor
```

The reboot is the one that matters most and is hardest to fake. An overlay
address is derived from an identity, so a machine that comes back as a different
anchor has silently orphaned every peer that knew it — which is what a renewal
falling back to enrolment would do. Restarting the container is the reboot.

It needs `make build` here first, and refuses rather than skipping when the
checkout is missing: a suite that quietly covers nothing is one that covers
nothing on CI the day somebody moves a directory.

The shape of the exchange is written down once, in
[guardian's contract document](https://github.com/veil-net/guardian/blob/main/docs/contracts/guardian-node.md).

## What has no coverage, and why

- **FreeBSD and OpenBSD** beyond `make cross` and the rc scripts, which are rendered and
  parsed by `sh` on Linux but have not run under `rc.subr`. No runner exists, which is
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
- **A Windows TUN, and the Windows service.** The `platforms` job runs the suite on
  Windows, extraction and ownership included, but no job opens a wintun interface or
  runs conflux under the SCM.

A local fake for the enrolment API is used for the client's error paths, but it cannot
stand in for a full end-to-end test: the shipped `anchord` is pinned to the production
genesis and the `anchorctl` beside it is the lockdown build, so nothing can mint a
credential those binaries will accept.
