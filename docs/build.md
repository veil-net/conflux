# Building from source

```console
$ git clone https://github.com/veil-net/conflux && cd conflux
$ make anchor-bins            # populate anchor/bin -- see below; a bare clone has none
$ make build
  48.2 MB  bin/conflux
```

Go 1.27.1 or newer, and nothing else. The only dependency is `golang.org/x/sys`.

`make anchor-bins` is the one step a fresh clone needs and does not get for free. It
looks in `../anchor` by default. Without it, `//go:embed` has nothing to embed and the
build fails.

## Where the anchor binaries come from

**They are not in git.** Fourteen release builds are about 284 MB, and committing that
costs it permanently — on every clone, for every contributor, every time they are
refreshed. So `anchor/bin/` is ignored, and a build populates it:

```console
$ make anchor-bins                              # from ../anchor
$ make anchor-bins ANCHOR_SRC=/path/to/anchor   # from somewhere else
anchor-bins: 14/14 copied from ../anchor/release (release)
```

The script looks for `release/` first and falls back to `dist/`. Those are not
interchangeable: `release/` is the pinned, garbled build users get, and `dist/` is the
unpinned development cross-build, which will join **any** realm tree. A conflux built
from `dist/` is fine for development and wrong for anything shipped, and the script
says so loudly when it uses one.

`anchoradmin` sits beside the other two in `release/` and is deliberately never
copied. It can mint realm roots, and anything in `anchor/bin` is a candidate for being
embedded into every conflux a user runs. The release workflow fails on its presence.

### A clone with no anchor checkout

`make anchor-bins` writes fourteen placeholder files instead, and says what it did.
This is not a working conflux — it is what lets a machine with no access to the real
binaries still run `gofmt`, `go vet`, `staticcheck` and the unit tests, which is
exactly what CI needs.

CI is no longer in that state for the jobs that matter. `linux`, `service` and
`integration` check anchor out beside conflux on the self-hosted runner and build
`make dist`, so the eight tests that gate on `anchor.Supported` actually run; `cross`
stays on placeholders deliberately, because what it asks is whether every target still
compiles. See [testing.md](testing.md).

A placeholder build is not able to masquerade as a real one:

```console
$ go build -o conflux . && ./conflux version
conflux dev (55a5810) linux/amd64
no anchor binaries for linux/amd64
```

`anchor.Supported` is a size check rather than only a build tag, precisely because an
empty `anchor/bin` is now an ordinary state to be in. Tests that need real binaries
skip, and `make dist` refuses:

```
  FAIL dist/conflux-linux-amd64 is 7 MB, under 30 MB
       anchor/bin holds placeholders, not binaries. Run:
         make anchor-bins ANCHOR_SRC=/path/to/anchor
```

### Why not committed, fetched, or LFS

**Committed** was tried and reverted: 324 MB per refresh, permanently, and `.git`
reached 840 MB from a single commit.

**Git LFS** is worse than it looks. The Go module proxy serves LFS *pointer files*, so
`go install github.com/veil-net/conflux@latest` would embed 130 bytes of text and ship
an `anchord` that is not one — failing at exec on a user's machine rather than at build
time here.

**Building it in CI** is what the runner does, and it is not a substitute for either.
`make dist` needs only Go, so a machine that keeps a checkout can produce the fourteen
on every push — but they are unpinned, which is fine for testing against a live realm
and wrong for anything shipped. Note the trap if you automate this anywhere else:
anchor's `make release` depends on `genesis/genesis.pin`, and with no `genesis/`
directory its rule **mints a new genesis root** instead of failing. The resulting
binaries enrol perfectly and never handshake. The CI action refuses to run in a
checkout that has a `genesis/` at all.

**Fetching at build time** from `GET /anchor/release` is the obvious next step and is
not wired up: that shelf currently serves 2 of the 14 it needs (linux/amd64 only). If
it is widened to all seven platforms, or its per-binary `url` is pointed at object
storage, a lockfile-driven fetcher replaces `make anchor-bins` and a fresh clone
becomes self-sufficient. The manifest already carries what such a fetcher needs —
`sha256` per binary, `ETag` as the digest, and the genesis `pin`.

Note that `go install` cannot work under any of these, fetch included: the module zip
the proxy serves will not contain the binaries. conflux is distributed as release
artifacts.

## Embedding, and the size gate

Seven build-tagged files in `anchor/`, one per platform, each naming exactly two files:

```go
//go:build linux && amd64

//go:embed bin/anchord-linux-amd64
var anchord []byte

//go:embed bin/anchorctl-linux-amd64
var anchorctl []byte
```

A file whose build tag is false is never compiled, so its `//go:embed` never runs — a
linux/amd64 conflux carries the ~43 MB it needs and not the 284 MB in `bin/`.

**Never `//go:embed bin`, and never a glob.** That would pull in all fourteen and
produce a 300 MB binary per platform. `make dist` gates every artifact between 30 and
75 MB precisely so that mistake fails the build rather than reaching a release.

There is also an eighth file with the negation of all seven tags, so that
`GOOS=linux GOARCH=riscv64 go build ./...` still succeeds — it produces a conflux that
reports it carries no anchor binaries, rather than failing at an embed of a file that
was never built.

## Cross-compiling

```console
$ make cross
  vet  linux/amd64
  …
  ok   dist/conflux-linux-amd64  48 MB
  ok   dist/conflux-darwin-arm64  46 MB
  …
  wrote dist/SHA256SUMS
```

`cross` vets every target as well as building it, because `go build ./...` does not
compile test files and a platform-specific test that no longer builds would otherwise
go unnoticed until CI.

`CGO_ENABLED=0` throughout. No garble: anchor garbles its own release build to hide
the genesis pin inside it, and conflux hides nothing — garbling would only make every
stack trace a user sends back useless.

## Targets

| | |
|---|---|
| `make build` | this machine |
| `make test` / `make race` | the tests |
| `make cross` | vet and build all seven, with the size gate |
| `make dist` | build all seven into `dist/`, with `SHA256SUMS` |
| `make golden` | rewrite the argv fixtures after an intended change |
| `make image` | the systemd test image, from `dist/conflux-linux-amd64` |
| `make service-test` | install and uninstall, in a container that boots systemd |
| `make integration` | three nodes, one taint, over the real API (needs Docker) |
| `make fmtcheck` `make vet` `make lint` `make tidycheck` | what CI checks |
| `make all` | everything CI runs |

## Version stamping

```console
$ make build VERSION=v0.2.0
```

`VERSION` and `COMMIT` default to `git describe` and `git rev-parse`. An unstamped
build says `dev`, which is the honest answer rather than a number nobody released.

## Reproducibility

`-trimpath` is set, so paths do not leak into the binary. Builds are otherwise
reproducible for a given Go toolchain version and a given `anchor/bin`: the embedded
bytes are in git, so two people on the same toolchain produce the same artifact.

What is *not* reproducible from this repository is anchor itself. Those binaries are
built elsewhere, pinned to a genesis key that never leaves the maintainer's machine.
`conflux version` prints their SHA-256s so that what you have can be compared against
what was published.
