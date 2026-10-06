# Building from source

```console
$ git clone https://github.com/veil-net/conflux && cd conflux
$ make anchor-bins            # populate anchor/bin -- see below; a bare clone has none
$ make build
  50.1 MB  bin/conflux
```

Go 1.27.1 or newer, and nothing else. The only dependency is `golang.org/x/sys`.

`make anchor-bins` is the one step a fresh clone needs and does not get for free. It
looks in `../anchor` by default. Without it, `//go:embed` has nothing to embed and the
build fails.

## Where the anchor binaries come from

**They are not in git.** Fourteen release builds are about 300 MB, and committing that
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

**`FETCH=1` is the last of the three and not an override**, which is the one thing about
that order worth saying out loud. On a machine that has an anchor checkout, a local
`release/` wins outright and the fetch never runs — so a developer who has just watched
anchor merge something and types `make anchor-bins FETCH=1` gets whatever `../anchor/release`
was last built from, which is usually older than the branch they are trying to test against.
The line it prints is the only thing that distinguishes the two:

```console
anchor-bins: 14/14 copied from ../anchor/release (release)   # a local build, whatever age
anchor-bins: 14/14 fetched from anchor's release (pinned build)   # the shelf
```

To take the shelf while a local checkout exists, point the script at a path that has
neither directory:

```console
$ make anchor-bins FETCH=1 ANCHOR_SRC=/nonexistent
```

Blunt rather than elegant, and deliberately not a fourth environment variable: the
precedence is right for the case it was written for — CI, and a fresh clone with no
checkout at all — and a flag that inverted it would be one more thing to get wrong on the
path that matters.

`anchoradmin` sits beside the other two in `release/` and is deliberately never
copied. It can mint realm roots, and anything in `anchor/bin` is a candidate for being
embedded into every conflux a user runs. The shelf fetcher refuses a release that carries
it, before downloading anything.

### The shelf

`make anchor-bins FETCH=1` fetches the **pinned** build from the `shelf` release of
`veil-net/anchor`, with no anchor checkout:

```console
$ export ANCHOR_RELEASE_TOKEN=github_pat_…
$ make anchor-bins FETCH=1
anchor-fetch: shelf:   veil-net/anchor @ shelf
anchor-fetch: commit:  0e68ba25f3019fdfc331cd8763f40fbdd641538a
anchor-fetch: realm:   realmtglwuedqqa33e364nv73p46jk3kwi67lxjmnntz2mv3mb3mklasq
anchor-fetch:   ok   anchord-linux-amd64           29.7 MB  06cc7917c8fc  fetched
  …
anchor-fetch: 14/14 in place, digests verified
```

The `commit:` line is the whole of what "which anchor is this" means here. There is no
anchor version string anywhere — `conflux version` names the pair by SHA-256 and nothing
else — so that line, and the digests the fetcher prints beside each file, are the only
way to say which anchor a given conflux carries.

`manifest.json`, which gives the digests, is itself held to the SHA-256 the release
document lists for it. The binaries and the manifest both arrive through GitHub's
redirect to its storage, and the release document, which the API answers directly, is
what vouches for the manifest — so nothing past the API can substitute both.

A file already in place whose SHA-256 is the one the manifest gives is kept and marked
`cached` rather than downloaded again; one that differs is replaced. So a directory that
survives between fetches costs a read instead of a download, and cannot hand back
anything the manifest does not describe.

Every file is fetched at once, each checked against its own digest as it lands, and the
first failure stops the rest. A fresh fetch then waits for the slowest file rather than
for all fourteen in turn — about six seconds rather than forty — and the `ok` lines
arrive in the order the files finish.

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
variable. The two secrets are:

| secret | what it is |
|---|---|
| `ANCHOR_APP_CLIENT_ID` | the App's Client ID, which is public; a secret so the workflows read it from one place |
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

**`FETCH=1` is opt-in**, because it needs the token and a clone with neither a checkout
nor a token should still build against placeholders. `ONLY=darwin-arm64` (space-separated,
any of the targets) narrows any of the three sources to the pairs one platform's build
needs — the macOS and Windows CI jobs fetch their own two files and no others — and
`DEST=` puts them somewhere other than `anchor/bin`.

**There is no URL anywhere.** Nothing reads a URL out of a document: every request is
built from `internal/shelf`'s own constants, and binaries are resolved by asset **name**
within one release. The set of places a fetch can reach is fixed by conflux's
configuration rather than by anything on the wire.

### A clone with no anchor checkout

`make anchor-bins` writes fourteen placeholder files instead, and says what it did.
This is not a working conflux — it is what lets a machine with no access to the real
binaries still run `gofmt`, `make cross`, `staticcheck` and the unit tests. Every CI job
fetches the real ones, so the tests that gate on `anchor.Supported` run there on Linux,
macOS and Windows. See [testing.md](testing.md).

A placeholder build is not able to masquerade as a real one:

```console
$ go build -o conflux . && ./conflux version
conflux 1.0.0-pre (f47de0fac83d24489664ca15fc6a317ac9c9f683) linux/amd64
no anchor binaries for linux/amd64
```

`anchor.Supported` is a size check rather than only a build tag, precisely because an
empty `anchor/bin` is now an ordinary state to be in. Tests that need real binaries
skip, and `make dist` refuses:

```
  FAIL dist/conflux-linux-amd64 is 7 MB, under 45 MB
       anchor/bin holds placeholders, not binaries. Run:
         make anchor-bins ANCHOR_SRC=/path/to/anchor
```

### Why not committed, or LFS

**Committed**, the fourteen cost about 300 MB per refresh, permanently, on every clone.

**Git LFS** is worse than it looks. The Go module proxy serves LFS *pointer files*, so
`go install github.com/veil-net/conflux@latest` would embed 130 bytes of text and ship
an `anchord` that is not one — failing at exec on a user's machine rather than at build
time here.

**Building them in CI** from an anchor checkout puts anchor's source on a machine that
only wanted its output, and anchor's `make release` depends on `genesis/genesis.pin`:
with no `genesis/` directory its rule **mints a new genesis root** instead of failing,
and binaries pinned to a realm nobody else has ever seen enrol perfectly and then never
handshake. The shelf is anchor's own CI doing that build once, with the real pin, and
publishing the output.

Note that `go install` cannot work under any of these: the module zip the proxy serves
will not contain the binaries. conflux is distributed as release artifacts.

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
linux/amd64 conflux carries the ~45 MB pair it needs and not the ~300 MB in `bin/`.

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
  ok   linux/amd64
  …
$ make dist
  ok   dist/conflux-linux-amd64  50 MB
  ok   dist/conflux-darwin-arm64  48 MB
  …
  wrote dist/SHA256SUMS
```

`cross` vets every target, which compiles each one's packages and test files: `go build
./...` compiles no test files, and a platform-specific test that no longer builds would
otherwise go unnoticed. It works on placeholders. `dist` builds every target with the
real binaries and the size gate.

`CGO_ENABLED=0` throughout. No garble: anchor garbles its own release build to hide
the genesis pin inside it, and conflux hides nothing — garbling would only make every
stack trace a user sends back useless.

## Targets

| | |
|---|---|
| `make build` | this machine |
| `make test` / `make race` | the tests |
| `make cross` | vet all seven, test files included |
| `make dist` | build all seven into `dist/`, with `SHA256SUMS` and the size gate |
| `make golden` | rewrite the argv fixtures after an intended change |
| `make image` | the systemd test image, from `dist/conflux-linux-amd64` |
| `make service-test` | install and uninstall, in a container that boots systemd |
| `make integration` | three nodes, one taint, over the real API (needs Docker) |
| `make fmtcheck` `make lint` `make tidycheck` `make vulncheck` `make docscheck` | the utility checks, which run here rather than in CI |
| `make all` | every check that needs neither Docker nor the network |

## Version stamping

```console
$ make build VERSION=v0.2.0
```

`VERSION` defaults to the contents of the `VERSION` file, and `COMMIT` to `git rev-parse`.
A tree with no `VERSION` file says `dev`, which is the honest answer rather than a number
nobody released.

The file rather than a tag, deliberately: a tag is a claim about a commit, and the file is
a claim about the tree — and it is the tree that gets built. It names the release; it does
not decide whether one happens. `release.yml` runs on every merge to `version3` and
**every merge builds and publishes**, replacing the artifacts on the release this file
names. The tag is whatever it says, verbatim.

So bumping `VERSION` is how a merge becomes a *new* release rather than a rebuild of the
current one. Leaving it alone is not "do not release" — it is "release this again, with
what just landed".

The tag is not moved. GitHub leaves it at the commit it was first cut from, so after the
first rebuild it names an older commit than the binaries hanging off the release; the
release job warns on every run where that has happened. `conflux version` reports the
commit it was actually built from, which is the one to trust.

## Reproducibility

`-trimpath` is set, so paths do not leak into the binary. Builds are otherwise
reproducible for a given Go toolchain version and a given `anchor/bin`: two people on
the same toolchain with the same shelf produce the same artifact.

What is *not* reproducible from this repository is anchor itself. Those binaries are
built elsewhere, pinned to a genesis key that never leaves the maintainer's machine.
`conflux version` prints their SHA-256s so that what you have can be compared against
what was published.
