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
anchor checkout available. `anchor.Supported` is a size check for the same reason, so
a placeholder build reports that it carries no anchor binaries rather than pretending.

That used to be the state CI was in, and a skip is green — so this test and seven
others had never run on any machine but a developer's. The `linux` job builds anchor
beside conflux now, and asserts afterwards that none of the eight skipped: a job that
provides the binaries and then reports "no anchor pair" has lost them, and saying so is
the difference between a gate and a decoration.

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
test. Allow up to a minute after the second node starts for gossip to find it — the
observed range is 15 to 60 seconds — and `conflux peers` shows `DATA yes` on the peer
once the taints have been compared.

All of that is `make integration`, and the two assertions above on their own are
`make service-test`. Both build the image first. They were a recipe here and a copy of
the same three lines in `ci.yml` until the targets existed, which is two places for one
sequence to drift; CI runs the same command a developer does.

### Local network discovery, and the control for it

Two containers on one Docker bridge are on the same link, which is the one thing no Go
test in this tree can arrange: a real kernel, real multicast, a real answer. So
`make integration` asserts `anchor_lan_peers_found_total` is **non-zero** on a node —
non-zero and not merely present, because the series is created the first time it is
written and a grep for the name alone passes on an anchor that never found anything.

The third node is the control, and it is why the suite enrols three times. It joins
with `--lan-discovery no` and names no `--peers` at all, and it must *still* reach the
realm: the manifest's own bootstrap list is what carries it, which is what proves
discovery is a third source rather than a load-bearing one. Its own counter staying at
zero is what proves the flag reached anchor rather than being accepted by conflux and
dropped.

Note what discovery cannot do, and anchor's own `docs/discovery.md` is the reference:
the probe is sealed under the realm's **root public key**, which a node only holds after
it has enrolled. So it never replaces enrolment — it decides who is worth dialling,
never who is let in. Loopback is not probed, so two anchors on one machine still need
`--peers`.

## What CI runs, and on what

Every Linux job that needs Docker is on **veilnet-dev**, a self-hosted runner. What
makes the two container suites possible, though, is not the machine — it is that
`anchor/bin` finally has a source CI can reach. `make anchor-bins FETCH=1` fetches the
**pinned** release build from the `shelf` release of `veil-net/anchor` and verifies every
digest, with no anchor checkout. It needs a credential, since anchor is private: CI stores
a GitHub App's ID and private key and mints an hour-long token per job, so the secret held
here is not itself a key to anything — see [build.md](build.md) for why the grant is wider
than it wants to be and why it is nonetheless contained.

| job | machine | what it adds |
|---|---|---|
| `linux` | veilnet-dev | the suite under `-race`, with real pinned binaries — eight tests that had only ever skipped |
| `cross` | veilnet-dev | vet and compile all seven targets, on placeholders |
| `platforms` | GitHub macOS, Windows | path handling, file modes, the DACL |
| `windows-tun` | GitHub Windows | the wintun pin, fetched the way an operator would |
| `service` | veilnet-dev | `make service-test` — install registers, uninstall leaves nothing |
| `integration` | veilnet-dev | `make integration` — three nodes against the live API |
| `docs` | veilnet-dev | two greps |

A release runs all of it first. `release.yml` calls this workflow and waits on it, which
is new: a release used to be gated on nothing but a check that the binaries it was about
to embed were real. Whether the code around them still worked was a convention — the tag
is cut from a commit that was green on main — and a convention is not a check.

It runs on a **merge to `main`**, not on a tag — and `ci.yml` no longer triggers on `main`
at all, so the suite runs once per merge rather than twice. A `gate` job reads the
`VERSION` file; the tests run either way, and only `verify` and `build` are skipped when
that version already has a release. So an ordinary merge costs the suite, and a release
merge costs the suite plus seven cross-builds.

Two things that were previously possible are now not: a release built from a commit nobody
had tested, and a `workflow_dispatch` on a feature branch publishing
`make dist VERSION=<branch-name>` to the public.

The PR run and the merge run are both wanted, and they are not the same thing. GitHub
tests `refs/pull/N/merge` — the branch already merged into its base — so as a *test* the
second is redundant whenever the base has not moved. But the merge run is the release
build: it produces the seven binaries and publishes them, and artifacts cannot come from a
run of a different commit.

It also fetches those binaries now, which is what made a release from CI possible at all.
`anchor/bin` is not in git, so a release runner had no source for it and the workflow
failed on its own error message saying so. Both release jobs fetch the `shelf` release,
and neither pins a version of it: the tag moves, so a conflux release carries whatever
anchor published most recently, which is the intent — conflux ships the newest anchor,
not a remembered one. All seven targets are cross-built from the one Linux machine,
`CGO_ENABLED=0` throughout.

`release.yml` calls `ci.yml` with `secrets: inherit`. Without that the called workflow
gets no secrets at all — they are not inherited by default — and every `anchor-bins` step
inside it would fail on a token that is set in one file and empty in the other.

**The binaries CI uses are the pinned ones.** That is what the release serves, and it is
the property a locally-built `make dist` cannot have: an anchor pinned to the genesis
realm refuses to handshake with any other tree. So `integration` now exercises the
binaries that actually ship, rather than a development cross-build that would join
anything.

It follows that CI tests against the **production realm** and nothing else, which is the
right answer here and a thing to keep true. `genesis.veilnet.com.au:4700` carries the
same pin, so the dev procedure below still works from a fetched build; a test node
minted from its own root would not, and the failure would be the one the next section
describes — enrols fine, never handshakes.

**conflux is public and anchor is not**, which is the one thing that shaped this more
than the runner itself. Using a self-hosted runner from a public repository is a
separate organisation setting from repository access, and GitHub keeps it separate for
a reason: `pull_request` runs the workflow from the *head* of the pull request, so
without a guard a fork could propose a workflow that runs its own code on a machine that
survives the job, beside a Docker socket and a token that reads a private repository.

Every Linux job refuses a fork's pull request, and nothing stands in for them. Since the
platform legs need the gate, a fork's pull request runs nothing at all.

That is the deliberate position rather than an oversight. A machine that survives the job
does not run a stranger's code, and the alternative — a hosted copy of the gate, for
forks only — was tried here and is worse than the gap. Two near-identical jobs with
complementary conditions means one is always skipped, and the one that rots is the one
nobody is watching.

A fork's change is therefore reviewed rather than gated. If that becomes the wrong trade,
the honest fix is a second machine, not a second copy of the gate.

**One runner process, deliberately.** The four Linux jobs queue rather than run beside
each other, so a push costs their sum. Do not register a second process to win that
back — anchor's `docs/ci.md` records the measurement that argues against it. More
parallelism wants a second machine.

**A machine that is not thrown away.** Both container suites reap their fixed container
names before themselves as well as after, because a cancelled run fires neither an
`EXIT` trap nor an `if: always()` step, and the leftover name fails the *next* run for a
reason that has nothing to do with the commit under test. `test/preflight.sh` says what
the machine gives them — Docker, `/dev/net/tun`, cgroup v2, IPv6 — before anything is
built, because each of those otherwise fails much later and names something else.

One consequence of leaving hosted VMs: their runner user is unprivileged and a
self-hosted one may not be. `TestWriteFileAtomicPreservesOnFailure` makes a directory
read-only and expects the write to fail, which is not true for root — it now probes
whether the chmod took and says so rather than failing. Nothing else in the suite
depends on not being root.

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
- the root is written into the argv the service is registered with, because none of
  the three service managers carries the operator's environment into what it starts.
  Without that the unit came back at boot reading `/etc/conflux`, and the CLI waited
  out its ninety seconds for a socket that was never going to appear.

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
  the manifest's own list. If `--peers` ever became load-bearing, every machine that
  never names one would stop finding the realm, and the test that names one would not
  notice.
- **The realm matches.** The embedded binaries are pinned to a genesis realm ID at
  build time (`-X anchor.pinnedGenesis`, see [build.md](build.md)). A test node minted
  from a different root will enrol fine and then never handshake, because the pin is
  what refuses it. That failure is on the anchor side, not conflux's.

  This node carries **the same pin as production**, which is what makes it usable from
  an ordinary fetched build at all. Worth checking rather than assuming after the node
  is ever rebuilt: `make anchor-bins FETCH=1` prints the realm it fetched, and it has to
  be the one the test node answers for.

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
- **A conflux built from pinned binaries, in CI.** This is the one that replaced
  "the boot service and the integration test, in CI", which are now run on every push
  — see [the CI section](#what-ci-runs-and-on-what) below. What CI cannot do is build
  what ships: `make release` needs a genesis key that never leaves the maintainer's
  machine, so CI builds `make dist` and the realm-pin path is exercised by hand.
  A green `integration` says conflux drives anchor correctly; it does not say the
  shipped artifact carries the right pin.

A local fake for the enrolment API is used for the client's error paths, but it cannot
stand in for a full end-to-end test: the shipped `anchord` is pinned to the production
genesis and the `anchorctl` beside it is the lockdown build, so nothing can mint a
credential those binaries will accept.
