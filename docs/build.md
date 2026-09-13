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
$ make anchor-bins FETCH=1                      # from anchor's release; needs a token
anchor-bins: 14/14 copied from ../anchor/release (release)
```

The script looks for `release/` first, falls back to `dist/`, and with `FETCH=1` falls
back again to anchor's published release. Those are not
interchangeable: `release/` is the pinned, garbled build users get, and `dist/` is the
unpinned development cross-build, which will join **any** realm tree. A conflux built
from `dist/` is fine for development and wrong for anything shipped, and the script
says so loudly when it uses one.

`anchoradmin` sits beside the other two in `release/` and is deliberately never
copied. It can mint realm roots, and anything in `anchor/bin` is a candidate for being
embedded into every conflux a user runs. The release workflow fails on its presence.

### The shelf

`make anchor-bins FETCH=1` fetches the **pinned** build from the `shelf` release of
`veil-net/anchor`, with no anchor checkout:

```console
$ export ANCHOR_RELEASE_TOKEN=github_pat_…
$ make anchor-bins FETCH=1
anchor-fetch: shelf:   veil-net/anchor @ shelf
anchor-fetch: commit:  0aea0f77bb77f8bbaa23c5055d9fe245d3a9bee2
anchor-fetch: realm:   realmtglwuedqqa33e364nv73p46jk3kwi67lxjmnntz2mv3mb3mklasq
anchor-fetch:   ok   anchord-linux-amd64           28.0 MB  95ca77b697e5
  …
anchor-fetch: 14/14 fetched, digests verified
```

The tag is fixed and moves: `shelf` always names anchor's newest release build, which is
the intent — conflux ships the newest anchor, not a remembered one. Fetched by tag rather
than by "latest", because latest is a heuristic over publication dates that a real product
release cut in anchor would win.

`ANCHOR_REPO=`, `ANCHOR_TAG=` and `ANCHOR_API=` point it elsewhere. The fetcher is
`cmd/anchor-fetch` over `internal/shelf` — Go rather than curl and a JSON parser, because
the promise at the top of this page is "Go 1.27.1 or newer, and nothing else", and a fresh
clone should not have to acquire anything else to become buildable.

#### The token

`ANCHOR_RELEASE_TOKEN` is any GitHub token with **Contents: read** on `veil-net/anchor`.
The fetcher takes a bearer token and does not care where it came from, so locally you can
export a personal access token and it works.

**CI does not store one.** It stores the private key of a GitHub App and mints a token per
job — see `.github/actions/anchor-bins`, which passes the result through this same
variable. The two repository secrets are:

| secret | what it is |
|---|---|
| `ANCHOR_APP_ID` | the App's numeric ID |
| `ANCHOR_APP_PRIVATE_KEY` | its private key, whole, including the BEGIN and END lines |

A credential is needed at all because anchor is private, and GitHub has no releases-only
read scope — releases live under Contents, the same permission that grants the source. So
whatever reads two binaries could also clone the repository. There is no narrower grant to
ask for, in any credential type, and it is worth saying plainly rather than glossing.

What the App changes is not what can be read but what is *kept here*:

- **The stored secret is not a credential.** A personal access token in a repository secret
  *is* the key. A private key has to be exchanged for one first, so the secret on its own
  opens nothing.
- **The minted token lasts an hour** and is revoked when the job ends, rather than being
  valid until somebody notices.
- **It does not expire and belongs to no person**, so CI does not go red a year from now
  for a reason unrelated to any code change, and the credential does not die when somebody
  leaves the org.
- GitHub never passes secrets to workflows triggered by **fork** pull requests, and
  conflux's Linux jobs refuse fork pull requests outright, so none of this is reachable by
  anyone who does not already have write access to conflux.

A deploy key cannot do this job. Deploy keys authenticate git transport only — `clone`,
`fetch`, `push` over SSH — and release assets are API objects, not git objects. The REST
API does not accept SSH keys at all.

What it refuses, and why each is worth a refusal:

| | |
|---|---|
| a digest that does not match | the failure no later gate catches — a real binary of the right size passes the size gate, and one of the right architecture passes `TestPairIsRealExecutables` |
| `anchoradmin` on the shelf | it mints realm roots, and every file in `anchor/bin` is a candidate for being embedded into every conflux a user runs |
| `anchoradmin` attached to the release | refused on sight, before anything is downloaded — if it is being published, that is worth stopping over rather than quietly not selecting |
| an asset still uploading | a half-finished release is not yet what its manifest claims |
| a manifest with no `pin` | nothing then says which realm these binaries are for |
| an unknown `formatVersion` | a future shape may mean anything, so it is refused rather than guessed at |
| a short body, or plain http | a truncated download, and an unencrypted one |

A rejected download is never renamed into place, so a failed fetch leaves what was there
before rather than a half-written binary.

A failed fetch under `FETCH=1` is fatal rather than falling back to placeholders: asking
for the real binaries and silently getting two-line text files answers a different
question, and it buries the useful error — the fetcher has just printed which binaries
are missing, and a fallback puts "holds placeholders" underneath it as the last word.
The placeholder path is still there for when nothing was asked for, which is what lets a
machine with no anchor and no network run `gofmt` and the unit tests.

**`FETCH=1` is opt-in for now.** The macOS and Windows CI jobs run `anchor-bins` too and
need only the two files their own build tag names, so fetching all fourteen there would
move 284 MB to compile 43. Once per-target narrowing exists, the default is one line to
flip.

**There is no URL anywhere.** An earlier version of this fetched a manifest that named a
download URL per binary, and refused any whose host differed from the manifest's — because
a document conflux had just downloaded was deciding where conflux would fetch from next.
Nothing reads a URL out of a document now: every request is built from `internal/shelf`'s
own constants, and binaries are resolved by asset **name** within one release. The set of
places a fetch can reach is fixed by conflux's configuration rather than by anything on
the wire, which is the stronger form of the same property.

### A clone with no anchor checkout

`make anchor-bins` writes fourteen placeholder files instead, and says what it did.
This is not a working conflux — it is what lets a machine with no access to the real
binaries still run `gofmt`, `go vet`, `staticcheck` and the unit tests, which is
exactly what CI needs.

CI is no longer in that state for the jobs that matter. `linux`, `service` and
`integration` fetch the pinned binaries from anchor's release, so the eight tests that
gate on `anchor.Supported` actually run; `cross` stays on placeholders deliberately,
because what it asks is whether every target still compiles. See [testing.md](testing.md).

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

**Building them in CI** was tried and replaced by the fetch below. `make dist` needs
only Go, so a machine keeping a checkout can produce the fourteen on every push — but
they are unpinned, which is fine for testing and wrong for anything shipped, and it puts
anchor's source on a machine that only wanted its output. Note the trap if you automate
it anywhere else: anchor's `make release` depends on `genesis/genesis.pin`, and with no
`genesis/` directory its rule **mints a new genesis root** instead of failing. Binaries
pinned to a realm nobody else has ever seen enrol perfectly and then never handshake.

**Fetching at build time** is what `FETCH=1` does, and it is the answer the three above
were circling. `GET /anchor/release` serves a manifest — `sha256` and a `url` per
binary, plus the genesis `pin` — and what it names is the pinned release build. No
credential: what the shelf serves is what conflux already ships, since `//go:embed` puts
these exact bytes inside every published conflux, so a public shelf discloses nothing a
release download does not.

That is also why it can be public while anchor stays private. conflux needs anchor's
*output*, and the output is not the secret.

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

`VERSION` defaults to the contents of the `VERSION` file, and `COMMIT` to `git rev-parse`.
A tree with no `VERSION` file says `dev`, which is the honest answer rather than a number
nobody released.

The file rather than a tag, deliberately: a tag is a claim about a commit, and the file is
a claim about the tree — and it is the tree that gets built. It is also what decides
whether a release happens at all. `release.yml` runs on every merge to `main`, reads this
file, and stops immediately if a release already exists for it. So cutting a release is
bumping `VERSION` and merging; the tag is created afterwards, at the commit that has
already passed the whole suite, rather than being a promise made before any of it ran.

## Reproducibility

`-trimpath` is set, so paths do not leak into the binary. Builds are otherwise
reproducible for a given Go toolchain version and a given `anchor/bin`: the embedded
bytes are in git, so two people on the same toolchain produce the same artifact.

What is *not* reproducible from this repository is anchor itself. Those binaries are
built elsewhere, pinned to a genesis key that never leaves the maintainer's machine.
`conflux version` prints their SHA-256s so that what you have can be compared against
what was published.
