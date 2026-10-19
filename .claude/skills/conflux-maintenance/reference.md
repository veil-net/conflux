# Conflux maintenance: reference

The concrete facts the workflow relies on. Step 8 of every run keeps this file true. Where it disagrees with the tree, the tree wins, and this file gets fixed.

## Layout

- `main.go` → `internal/cli.Main`.
- `anchor/`: `anchor.go` (`Supported` = build tag plus a ≥ 5 MiB size check on both binaries; `Digests`, the two SHA-256s `conflux version` prints, stamped by make through `-X …/anchor.anchordSHA256`/`anchorctlSHA256` and computed when a stamp is absent or malformed; `SetID`, the extraction directory's name, 16 hex of `sha256("anchord <d>\nanchorctl <c>\n<GOOS>/<GOARCH>")`), seven build-tagged `bin_<os>_<arch>.go` files (each `//go:embed`s `bin/anchord-<os>-<arch>[.exe]` and `bin/anchorctl-<os>-<arch>[.exe]` by name), `bin_unsupported.go` (every other platform: no pair), `bin/` (gitignored).
- `cmd/anchor-fetch/`: the CLI that fetches anchor's release.
- `internal/`
  - `anchorctl`: `args.go` (`StartMode`, `ModeFromConfig`, the argv builders; no `-taints`: anchorctl takes them from the manifest), `ctl.go` (runs `start`, `stop`, `status` (also the readiness probe and the watcher's question), `metrics`, `renew`; `Env`; `Error` carries stderr and the run's own error), `parse.go` (`ParseStarted`, `ParseStatus`, `ParseMetric`, `MetricConnections`), `testdata/argv/*.golden`, `flags_test.go` (flag cross-check)
  - `cli`: verbs, pass-through (`passthrough.go`: the socket and token are checked before anything is extracted; `wantsUsage`), refusal of `stop`/`restart`, `up`/`proxy`/`enrol`/`renew`/`status`/`serve`, `proxyFlags` (the one flag set proxy's unknown-flag check and spec splitter read), `registerExits`/`chooseSubnets` (the routing flags both verbs take), `chooseTaints` (the enrolment request before a credential, checked against it after; `heldCredential`), `dropSubnetsOrder`/`reportSubnets` (a member's Subnets order, replaced by an explicit `--subnet`/`--no-subnet`), `chooseIPv4` (asked once), `interfaceLine` (the TUN name only where the kernel honours it), `needsRoot` and `typed` (a privilege refusal that repeats the command typed, quoted, through `privcheck.Retry`), per-OS glue (`service_windows.go` logs the service to `LogFile`; `scmExit` maps the supervisor's exit to the SCM's)
  - `config`: `Config` (`IPv4 *string`: nil never asked, `""` declined; `Taints` the request before enrolment and the grant's mirror after), `Validate` (anchor's mode, exit and uplink rules, conflux's comma and descriptor-uplink refusals, `ValidateSubnets` against the taints, `ValidateTUNName` for TUN mode, and `Export.Validate`), `DefaultAPIBaseURL`, `DefaultTUNName`; `spec.go` (taint, proxy, IPv4, uplink, peer, AnchorID, subnet and TUN-name grammar, `*` and `SPEC@a+b` bindings included, each anchor's); `atomic.go` (`WriteFileAtomic`, `writeAtomic` for content in pieces); `secret.go` (redacting `Envelope` and `Secret`; `SaveManifest`); `export.go` (`Export.UnmarshalJSON` reads the block as protojson does; redacting headers); `state.go` (`ClockSkew`, link reopens, `NewIdentity` for a new manifest)
  - `daemon`: `supervisor.go` (`Run` takes `<state>/serve.lock` — a second supervisor for the root is refused — and reaps an orphan; `loadConfig`, the one reading of `conflux.json`: missing is `ErrNotConfigured`, unparsable or invalid permanent, unreadable transient; spawn into a `child` whose exit is a closed channel, `WaitDelay` bounding the wait, one line writer for both streams, a fixed-size tail ring, readiness, shutdown — SIGTERM to the group where a signal reaches, `anchorctl stop` then a group kill where none does, nothing for a daemon already gone — `renewLoop`, `Permanent`, which decides `serve`'s exit 70 against 1), `pidfile.go` (`<run>/anchord.pid`, `pid\nexe\n`, written after start and removed once waited; `ReapOrphan` stops a recorded anchord only when it runs the recorded executable — `proc_exe_*.go`: `/proc`, `kern.procargs2`, `kern.proc.pathname`, `QueryFullProcessImageName` — or, where none is reported (OpenBSD), holds the socket's lock; `Reap` for `uninstall`), `proc_unix.go`/`proc_windows.go` (group signals; on Windows a job object with KILL_ON_JOB_CLOSE), `bringup.go` (`bringUp` under the lock, counting an uplink reopen in its own state write, `credential`: enrols in `cfg.Taints`, refuses none, checks the manifest's taints first and for good, and refuses an expired credential with no AnchorID to renew it by, `MaxSkew` = anchor's `realm.CredSkew`, 10 min, `permanentError`), `renew.go` (`renewStored`, the one renewal body, restating the manifest's taints and splicing `WithRenewal`; `RenewNow`), `renewal.go` (the two-thirds arithmetic, unexported), `ready.go`, `watch.go` (the watcher: every 30 s asks whether anchord still holds an anchor and rebuilds it through `bringUp`, giving up after 3 rebuilds in a row refused for good; on an uplink every 10 s reads `anchor_connections` instead, rebuilding when the device is gone or the count stays 0 for 90 s), `export.go` (anchord's `-config`, with no export block when none is configured); `bench_test.go`, `main_test.go` (the test binary as a stand-in anchorctl/anchord, told apart by argv: anchord is started `-socket` first; `dirs`), `supervisor_test.go` (shutdown of a dead and a live daemon, the tail's order), `pidfile_test.go` (the reap)
  - `enrol`: `client.go` (`Enrol(taints)` refuses none and returns the envelope undecoded; `Renew(…, taints)` needs the manifest's `renewalUrl` and an AnchorID `config.ValidateAnchorID` accepts, and returns the answer's bootstrap list when every entry is usable; per-client `Skew`; shared transport), `manifest.go` (`Decode`, `Alpha`, `CheckTaints`/`TaintsError`, `WithRenewal`, redacting `String`/`GoString`), `auth.go`
  - `paths`: `Dirs`, `Root` (absolute), `EnsureAll` (the shared `/var/log` excepted), `LogFile`, `LockFile` and `ServeLockFile` (in State: systemd recreates Run), `DaemonPIDFile` (in Run), `ServiceExecutable` (the copy the boot service runs), `SubnetsOrderFile` (anchor's `subnets.json` in the anchor directory), `acl_windows.go` (`Restrict`, `Trusted` — SYSTEM, Administrators or the account running conflux — the root's ownership and DACL), `acl_other.go` (`secure`: a root, or a symlinked one, owned by another uid is refused before anything changes; ours is narrowed to `0700`)
  - the rest: `anchorrelease` (fetching anchor's release), `anchortest` (`Require`: the one "no anchor pair" skip CI keys on), `flock` (`Acquire`, `TryAcquire`), `libexec` (extraction, through `EnsureAll` so a Windows root is secured by whichever conflux makes it, each binary's pages touched as it is written; Windows runs only binaries `Trusted` accepts; `Sweep`, called only by the supervisor; `quarantine_other.go`), `privcheck` (`Elevated`, a variable tests stub; `Retry`, `doas` on OpenBSD), `service` (`New`; `Place` copies conflux into the state directory for the service to run, restoring the old copy if the rename fails; every definition written by `WriteFileAtomic`; systemd, whose unit and `ExecStart=` quoting render in the untagged `service_systemd.go`, refused before anything is written where systemd is not running, a CONFLUX_DIR unit claiming none of the machine's directories, `Restart` clearing a failed unit first; launchd, whose plist renders in the untagged `service_launchd.go`, enabled only when its label is disabled; rc for FreeBSD and OpenBSD via `service_rc.go`, both refusing words rc.subr cannot carry unquoted; the SCM, one `stopService` waiting for the process to exit, recovery on non-crash failures; scope; `logfile.go`; `exists` for the file-registered managers), `taint` (minting, uniform by rejection sampling), `ui` (`Errf` for failures and warnings; `term_*.go`: a real isatty), `version`, `wintun` (`pinned.go`: `Version`, `ZipSHA256`; at most 10 redirects)
- `scripts/anchor-bins.sh`, `test/`, `.github/`, `docs/`, `VERSION`.

## Make targets

`VERSION` comes from the `VERSION` file and `COMMIT` from `git rev-parse HEAD` (`:=`, so an exported variable cannot restamp them; `make VERSION=x` still can), stamped via ldflags into `internal/version`. `build` and `dist` also stamp each target's two SHA-256s (`STAMP`: `sha256sum` or `shasum -a 256`).

| Target | Does |
|---|---|
| `all` | `fmtcheck lint tidycheck docscheck test cross dist`: what needs no Docker (no `vulncheck`; `tidycheck` can fetch modules). A maintenance run uses § Local checks instead, since `test`, `cross` and `dist` are CI's |
| `anchor-bins` | `scripts/anchor-bins.sh` with `ANCHOR_SRC` (default `../anchor`), `FETCH` (default `0`), `ANCHOR_API`/`ANCHOR_REPO`/`ANCHOR_TAG` (empty means the `internal/anchorrelease` defaults); `ONLY` and `DEST` pass through the environment |
| `build` | `CGO_ENABLED=0 go build -trimpath`, stamped, → `bin/conflux$GOEXE` |
| `test` / `race` / `vet` | `go test ./...` / `go test -race ./...` / `go vet ./...` |
| `fmt` / `fmtcheck` | `gofmt -w .` / fail if `gofmt -l .` lists anything |
| `lint` | `staticcheck ./...` once per target OS (`GOOS=…`); **exits 0 printing "staticcheck not installed; skipping"** when absent |
| `vulncheck` | `govulncheck ./...`; same skip behaviour |
| `tidycheck` | `go mod tidy -diff` (changes nothing) |
| `docscheck` | every `docs/*.md` named in `README.md`, every `docs/<name>.md` the README links exists, every `](<name>.md)` link in `docs/` resolves |
| `golden` | `go test ./internal/anchorctl -update` |
| `cross` | every `TARGETS` entry at once: `go vet ./...` (compiles packages and test files), CGO off, each target's output held and printed in `TARGETS` order; works with placeholders |
| `dist` | every `TARGETS` entry built at once into `dist/conflux-<os>-<arch>[.exe]`, then the size gate `MIN_MB=45`..`MAX_MB=75` (MiB; a real anchord beside a placeholder anchorctl is about 40) read in `TARGETS` order, `dist/SHA256SUMS`; clears old artifacts first, leaves no build logs |
| `image` | `dist`, then copies `dist/conflux-linux-amd64` to `test/systemd/conflux` and runs `docker build -q -t $(IMAGE)` (default `conflux-systemd-test`). A buildx builder with the Actions cache was tried in CI and lost: 6 s to create the builder and 16 s to build and `--load`, against 14 s for a plain build |
| `service-test` / `integration` | `image`, then `test/service.sh` / `test/integration.sh` |
| `clean`, `help` | |

`TARGETS := linux/amd64 linux/arm64 darwin/arm64 windows/amd64 windows/arm64 freebsd/amd64 openbsd/amd64`. `dist` is phony and `image` depends on it: one invocation (`make dist image`, `make -j2 service-test integration`) builds it once, and two invocations build all seven targets twice.

## Binary pipeline

- **`scripts/anchor-bins.sh`**
  - Its own `TARGETS=(…)` array (dash form) must equal the Makefile's. Runs on bash 3.2.
  - `ONLY="darwin-arm64 …"` narrows any source to those pairs; an unknown target is refused. `DEST` (default `anchor/bin`) moves where they land.
  - It prunes anything in `DEST` that is not one of the 14 names, and the `.anchor-fetch-*` temporaries a killed fetch left.
  - Sources, in order:
    1. `$ANCHOR_SRC/release` (pinned)
    2. `$ANCHOR_SRC/dist` (unpinned; warns loudly)
    3. with `FETCH=1`, anchor's `latest` release (needs `ANCHOR_RELEASE_TOKEN`; failure is fatal)
    4. placeholders
  - It copies and sets `chmod 0755`. The prune is what keeps `anchoradmin-*` out: nothing copies a name that is not one of the 14.
  - Final line: `N/N copied from <src> (release|dist)`, `N/N fetched from anchor's release (pinned build)`, or `N placeholders written to <dest>`, N being 14 without `ONLY`.
  - A local `release/` always beats `FETCH=1`. `ANCHOR_SRC=/nonexistent` forces the fetch.
- **`cmd/anchor-fetch`**
  - Usage: `go run ./cmd/anchor-fetch [-api URL] [-repo owner/name] [-tag T] [-dest DIR] -want a,b,…` (`-dest` defaults to `anchor/bin`).
  - The token comes only from `ANCHOR_RELEASE_TOKEN`.
  - Logs to stderr: `release:`, `commit:` (the release's `target_commitish`, which anchor sets to the commit SHA), `realm:` (the pin), one line per file with its digest and `fetched` or `cached`, then `N/N in place, digests verified`.
- **`internal/anchorrelease`**
  - Source: GitHub API, repo `veil-net/anchor`, tag `latest`. The tag moves; it names the newest build from anchor `main`, which anchor also releases at a dated tag `YYYYMMDD-HHMMSS` that stays.
  - It refuses any `anchoradmin*` asset and any asset not in state `uploaded`.
  - It reads `manifest.json`: `{"formatVersion":1,"pin":"realm…","binaries":[{"name","program","os","arch","bytes","sha256"}]}`, held to the `sha256:` digest the release document gives for it (it arrives through the same storage redirect as the binaries). There are no URLs; assets are resolved by name within the one release.
  - A file already at the destination with the manifest's size and SHA-256 is kept (`cached`); anything else is downloaded to a temp file, checked for size and SHA-256, and renamed into place.
  - Every file at once; the first failure cancels the rest and is the one reported. `ok` lines arrive in completion order. All 14 fresh: ~6 s (37 s one at a time); cached: ~1 s.
  - HTTPS only; `CONFLUX_ALLOW_INSECURE_API=1` allows plain HTTP for tests. Redirects must stay HTTPS, at most 5.
  - Bounds: manifest 1 MiB, binary 200 MiB.

## Test harness

- **`test/preflight.sh`:** checks the Docker daemon, `/dev/net/tun`, `/sys/fs/cgroup` (v1 accepted), and IPv6. Reports whether the API is reachable (`curl …/docs`); that line is informational only.
- **`test/service.sh`:** container `$NAME` (default `cfx`) from `$IMAGE`. Asserts:
  - systemd reaches `running`
  - `conflux install` leaves the unit `enabled` and `inactive`
  - its `ExecStart` runs `/var/lib/conflux/conflux`, which is `700 root`
  - `conflux uninstall --yes` leaves no unit file, no `multi-user.target.wants` link, and none of `/etc/conflux`, `/var/lib/conflux`, `/run/conflux`
  It enrols nothing.
- **`test/service-host.sh CONFLUX`:** the same lifecycle on macOS (as root) and Windows (Git Bash, as Administrator), against launchd and the SCM, run by CI's `platforms` legs only: `install` registers and starts nothing (Windows: `sc qfailureflag` TRUE, three RESTART actions), `status` exits 78 saying "installed, not running", `down` succeeds, `uninstall --yes` leaves no plist, no `launchctl print-disabled system` entry, no SCM service and no root directory. bash 3.2. Enrols nothing.
- **`test/integration.sh`:** random taint `cfx-ci-<12 hex>`, which every credential is issued in. Makes three live enrolments and one renewal. Waits poll each second and print how long they took. A and B get `--peers 192.0.2.1:4700` (RFC 5737; never answers): anchor probes the link only until its first connection and the live realm answers at once, so without it they would meet through the realm and the link would prove nothing. Stages:
  1. `cfx-a up --ipv4 10.128.0.1/24`: `anchorId` in `state.json`, `manifest.b64` is `0600`, `/run/conflux` is `0700`, the credential grants `$TAINT`, a second `up` keeps the identity, an `up --taint` with another taint is refused naming `conflux uninstall` and changes nothing, and `conflux renew` installs a renewed chain hot with the identity and taint unchanged.
  2. `cfx-b` (`10.128.0.2/24`): `conflux blocks` passes through to anchorctl's table, and `conflux telemetry -from <B>` is refused for want of the capability; reachable both ways (waited for), v4 pings both ways, plus a v6 ping.
  3. `anchor_lan_peers_found_total` (labelled per interface; summed) is above 0 on A or B.
  4. `cfx-c`: enrolled from `POST /ghosts/alpha` with `{"taints":["$TAINT"]}` fetched on the host and piped to `conflux enrol --manifest -`; its credential grants `$TAINT`; `up --taint "$TAINT" --lan-discovery no` (restating it) with no `--peers` must not enrol again, must reach the realm through the manifest's bootstrap list (`anchor_connections` > 0), and its discovery counter stays 0.
  5. Reboot A: the service must come back active (Type=notify, so the anchor is up), same identity.
  6. `anchord` SIGKILLed on A (`docker exec cfx-a sh -c "kill -9 …"`; `kill` is a builtin): the supervisor brings it back without a reboot — a new pid, `/run/conflux/ready` rewritten, same identity, B reachable at its IPv6.
  7. B `down`: keeps the registration, config and identity, and drops `anchor0`. `start` restores it. `down` then reboot restores it, the service active again.
  8. `uninstall` removes the unit, its wants link, `/etc/conflux`, `/var/lib/conflux`, `/run/conflux` and `anchor0`.
- **`test/systemd/Dockerfile`:** `debian:trixie-slim` plus systemd, systemd-sysv, ca-certificates, iproute2, iputils-ping and dbus, with getty, udev, console, timesyncd, logind and modules-load units stripped (a container cannot load modules, and the failed unit leaves systemd `degraded`), every `multi-user.target.wants` link removed and dbus's put back; `COPY conflux /usr/local/bin/conflux`; `STOPSIGNAL SIGRTMIN+3`; boots systemd. Containers run with `--privileged --cgroupns=host -v /sys/fs/cgroup:/sys/fs/cgroup:rw --device /dev/net/tun`.
- **Tests that skip without real binaries** (`anchortest.Require`, or its copy in `anchor`, which `anchortest` imports; the reason is always "no anchor pair"):
  - `anchor`: `TestPairIsRealExecutables`
  - `libexec`: `TestEnsureExtractsAndRuns`, `TestEnsureIsIdempotent`, `TestEnsureIsConcurrencySafe`, `TestEnsureRepairsATruncatedExtraction`
  - `anchorctl`: `TestEveryFlagWeUseExists`
  - `cli`: `TestNoUnintendedShadowing`, `TestTheCollisionsAreTheDocumentedOnes`, `TestRealmControlPassesThrough`
  - `daemon`: `BenchmarkDaemonLifecycle` (a benchmark; not part of the no-skip gate)
- Platform skips, outside the real-binary gate, all on Windows: `daemon.TestShutdownSignalsARunningDaemon` and `TestSpawnRecordsTheDaemon` (a console control event), and the mode-bit tests. `TestWriteFileAtomicPreservesOnFailure` skips only where a directory cannot be made read-only.
- On Linux with real binaries nothing in the module skips (232 top-level passes; `go test -list . ./... | grep -c ^Test`); CI's gate requires at least 150.

## CI/CD

**`.github/workflows/ci.yml`**
- Triggers: `pull_request` and `workflow_dispatch`. `permissions: contents: read`. Concurrency group `ci-${{ github.ref }}`, cancel-in-progress.
- Fork guard on every job: `if: github.event_name != 'pull_request' || github.event.pull_request.head.repo.full_name == github.repository`.
- Every checkout `persist-credentials: false`.
- The utility checks (gofmt, staticcheck, tidy, govulncheck, docs links, actionlint, shellcheck, golden diff) are not in CI; they are § Local checks.

| Job | Runner | Steps |
|---|---|---|
| `linux` | `[self-hosted, linux]` | setup, anchor-bins (all 14, via the tool cache), `go test -race -count=1 -v ./...` with the gate (no `--- SKIP` anywhere, ≥ 150 PASS), `make cross`, and the stamped digests are the pair's own (`bin/conflux version` against `go run . version`, the version line aside) |
| `integration` | `ubuntu-latest` | setup, anchor-bins (all 14; `dist` builds every target), `./test/preflight.sh`, `make -j2 -O service-test integration` (`dist` and the image once, then both suites side by side, output grouped per suite). Hosted because node C's QUIC handshake to the manifest's bootstrap node gets no answer from veilnet-dev |
| `platforms` | `macos-latest` (pair `darwin-arm64`), `windows-latest` (pair `windows-amd64`), `ubuntu-24.04-arm` (pair `linux-arm64`); job env `CGO_ENABLED=0`, `GOFLAGS=-trimpath` | setup, anchor-bins (that pair only), on Windows the wintun pin check (digest of the published zip against `internal/wintun/pinned.go`), `go test -count=1 -v ./...` failing if any test skipped saying "no anchor pair", then on macOS and Windows `make build` and `test/service-host.sh` (`sudo` on macOS) |

**`.github/workflows/release.yml`**
- Triggers: push to `version3`, and `workflow_dispatch`. Concurrency `release-${{ github.ref }}`, never cancelled.
- One job, `build`, self-hosted, `if: github.ref == 'refs/heads/version3'`, 30-minute timeout; permissions `contents`/`id-token`/`attestations: write`. Steps: checkout without persisted credentials and with `fetch-depth: 0` (for the notes), setup, anchor-bins, version and tag = `VERSION` verbatim (`latest` refused), `make dist`, `actions/attest-build-provenance`, notes from `scripts/release-notes.sh <version>` (the changes since the nearest other version tag on `version3`'s first-parent history) plus `./dist/conflux-linux-amd64 version` and the wintun pin. Then, for the version and then `latest`: `actions/github-script` deletes the release at that tag and the tag itself (404, and 422 on the tag, mean nothing there), and `softprops/action-gh-release` creates it at the commit with files `dist/conflux-*` plus `dist/SHA256SUMS` and the same notes; `make_latest` is `false` for the version and `true` for `latest`. Nothing re-verifies what CI checked.

**Composite actions (`.github/actions/`)**
- `setup`: `actions/setup-go` with `go-version-file: go.mod` and `cache-dependency-path: go.sum`; `cache` is off on a self-hosted runner, which keeps `GOCACHE`/`GOMODCACHE` on disk (shared with other repositories, about 6 GB: restoring and re-saving it cost ~630 s a run).
- `anchor-bins`: inputs `client-id`, `private-key`, `targets` (space-separated pairs; empty = all). Runs `actions/create-github-app-token` (owner `veil-net`, repositories `anchor`), then `make anchor-bins FETCH=1` with the token as `ANCHOR_RELEASE_TOKEN`, `ANCHOR_SRC=no-anchor-checkout` (anchor's release only, never a stray local build; relative, since Git Bash rewrites an absolute path it hands to make) and `ONLY` from `targets`. On a self-hosted runner `DEST` is `$RUNNER_TOOL_CACHE/conflux-anchor-bin` (persistent; the fetcher reuses files whose digest matches) and the files are copied into `anchor/bin`; a hosted runner fetches straight into `anchor/bin`.
- Secrets: `ANCHOR_APP_CLIENT_ID` (an organisation secret: the `anchor-access` App's public Client ID) and `ANCHOR_APP_PRIVATE_KEY`, the read-only anchor GitHub App (Contents: read on `veil-net/anchor`) and the only credential. The repository secret `ANCHOR_APP_ID` is no longer read.

Actions in use, each pinned to its release's commit with the tag in a comment: `actions/checkout` v7.0.1, `actions/setup-go` v7.0.0, `actions/create-github-app-token` v3.3.0, `actions/attest-build-provenance` v4.2.2, `actions/github-script` v9.0.0, `softprops/action-gh-release` v3.0.3. After a major bump, check that the self-hosted runner supports the Node runtime the action's `action.yml` names. Validate locally with `actionlint` (with `shellcheck` on `PATH` it also checks `run:` scripts, and it validates the inputs passed to the local actions). `act` is not installed.

## Docs and config

- `VERSION`: `1.0.0`. It is both the release tag and the stamped version, verbatim, `MAJOR.MINOR.PATCH`. Every run moves it on in step 9: a new major for a major new feature from anchor, otherwise a new minor.
- `docs/`: `build`, `commands`, `concepts`, `config`, `credentials`, `install`, `modes`, `security`, `service`, `testing`, `troubleshooting`, `uplink`, `windows` (`.md`). Each is linked from `README.md`.
- `config.DefaultAPIBaseURL` = `https://api.veilnet.com.au` (`internal/config/config.go`). `enrol.Client` falls back to it. The renewal URL comes from the manifest and must be on the same host as the configured API (`enrol.SameHost`); `conflux enrol` derives the API from it unless `--api` is given.

## Local checks

`make fmtcheck lint tidycheck vulncheck docscheck`, plus `actionlint` and `shellcheck scripts/*.sh test/*.sh`. These are the utility checks, which run here and not in CI. `lint` and `vulncheck` exit 0 printing `not installed; skipping` when their tool is absent, which a maintenance run counts as a failure.

## Anchor surface map

Paths are relative to the anchor checkout.

| Surface | Anchor source of truth | Conflux consumer |
|---|---|---|
| realm control | `cmd/anchorctl/block.go` (`block`, `unblock`, `blocks`), `taints.go`, `subnets.go`, `telemetry.go`; capabilities `block`/`taint`/`subnets`/`telemetry` (`internal/realm/cred.go`, `internal/order/order.go`), refusals in `orders.go`; an order goes to another member of the same realm, by full AnchorID | pass-through, `TestRealmControlPassesThrough`, `conflux help`, `docs/commands.md` |
| anchorctl commands | `cmd/anchorctl/main.go` dispatch (and its error hints: `Unavailable` for a socket with no daemon, `REASON_NOT_RUNNING` for a daemon holding no anchor); `root` is built only without `lockdown` (`priv.go`), and the lockdown build adds `mint-realm`/`mint-anchor` (`manifest.go` `buildCommand`; constants in `locked.go`) | `internal/cli` `verbs()`, `anchorLifecycleVerbs`, shadowing and collision tests, `docs/commands.md` |
| start flags | `configFlags` in `cmd/anchorctl/lifecycle.go` (`describedByFile`) | `internal/anchorctl/args.go`, argv goldens, `flags_test.go` |
| output formats | `printStarted` in `cmd/anchorctl/lifecycle.go` (fixed-width `Println` rows: `anchor`, `underlay`, `overlay `, `hardware`) and `statusCmd` (one tabwriter block, every row padded to the widest key; the `ipv4` row is a bare address and a note, printed on every running anchor; realm paths are short IDs; overlay addresses carry a length; proxy rows name the IPv4 listener too), `peers` in `node.go`, metric samples in `format.go` (`%d` counters, `%g` gauges, `n= mean= min= max=` summaries), `export`'s `set by` row (`printExport`/`sourceName`, `observability.go`), the `blocks` header `ANCHOR\tBY…` (`block.go`) and an order's refusal naming its capability (the root `orders.go`, the hint in `cmd/anchorctl/main.go`) | `internal/anchorctl/parse.go`, `parse_test.go` fixtures (take them from a live anchor), `internal/cli/status.go` (the `set by` row), `test/integration.sh` (`blocks`, the telemetry refusal), `docs/troubleshooting.md` samples |
| metric names | `metrics.go` (`Metric*` constants; labelled series such as `anchor_lan_peers_found_total{iface=…}`) | `parse.go` (`MetricConnections`), `test/integration.sh`, docs |
| daemon flags | `cmd/anchord/main.go` (`-socket`, `-token-file`, `-config`, `-v`, `-credentials-dir`, `-allow-credentials`, `-allow-observability`) | `daemon.anchordArgs` |
| daemon config | `proto/anchor/v1/daemon.proto` (`DaemonConfig`), `observability.proto` (`ExportConfig`, signals metrics/traces/logs/flows; `Secret` is a oneof, `common.proto`); what anchord refuses, fatally at startup with `-config`: `cmd/anchord/otelbridge/bridge.go` (`check`, `tlsConfig`), `cmd/anchord/internal/export/controller.go` (`configFrom`), `cmd/anchord/internal/rpc/rpc.go` (`Secret`) | `internal/config/export.go` (`Export.Validate`; whether TLS material parses is anchord's to say, since checking it here links in ~370 KB of key parsing), `daemon/export.go`, `spawn` (validates before rendering) |
| control socket | `cmd/anchord/internal/control/server.go` (`Listen`: AF_UNIX on every OS, clears a stale socket itself; `<socket>.lock`, held by the daemon serving it and never removed, `socklock_unix.go`/`socklock_windows.go`, refusing a second daemon with "control: … is already served by a running daemon"), `sockpath_unix.go`, `sockpath_other.go` (limit: `sun_path`, 108 on Windows) | `paths` (`socketName`, `sockPathMax`, `CheckSocketLen`), the supervisor's probe, `daemon.ReapOrphan` (the lock as identity where no executable path is reported), `main_test.go`'s stand-in last words |
| lifecycle RPC semantics | `cmd/anchord/internal/control/lifecycle.go` (`Stop` with nothing running succeeds); `supervisor.go` (`watchForEnd`: an anchor closing on its own empties the slot while anchord runs on; a blocked anchor keeps running) | `anchorctl.Ctl.Stop`, `daemon.watch` |
| mode, exit and IPv4 rules | `config.go` (`Config.check` behind `validate`: a proxy needs userspace; ServeSubnets and ServeExit refused only beside a HostDevice, so without `EnableTUN` they make a userspace router; ServeExit and UseExit are alternatives; `validateUplink`; `StaticIPv4`; `DefaultTranslatePool`, which `New` refuses the IPv4 inside), `cmd/anchord/internal/control/config.go` (bare address → /32), `hostsetup.go` (with a TUN on Linux, Start sets the router host up), `docs/ipv4.md`, `docs/operations.md` | `internal/config` (`Validate`, `ParseOverlayIPv4`), `docs/modes.md` |
| manifest/credential format | `cmd/anchorctl/manifest.go` (`anchorManifest`, `manifestVersion`, `kind`, `checkEnvelope`, `loadAnchorManifest`; `mergeManifest` fills every field no flag named, `taints`, `listenPort` and `lanDiscovery` included) | `internal/enrol/manifest.go`, `auth.go`; `anchorctl.StartMode.Args` (types no `-taints`; types `-port 0` and `-lan-discovery=no` beside an uplink) |
| taints | `internal/realm/taint.go` (`checkTaintName`, `TaintsGranted`), `config.go` (`Config.check`: the set must be the one the credential's digest grants, `ErrCredTaints`), `cred.go` (a renewal granting another set is refused), root `taints.go` (a Taints order's grant, reapplied from `-dir` over the base set) | `internal/taint`, `config.ValidateTaint(s)`, `enrol.Manifest.CheckTaints`, `daemon.Permanent` |
| subnets | `internal/hostnet/local.go` (`Select`, `matchOffer`: compares the entry as written against unmapped host prefixes; `AllNetworks` = `*`), `classify.go` (`privateNetworks`, `IsPrivateNetwork`), `served.go` (`splitBinding` for `SPEC@a+b`, `checkSubnetList` bounds, `checkBindings`; a Subnets order's list is kept in `<dir>/subnets.json` and served over `-serve-subnets` from every start), `internal/proto` (`MaxSubnetEntries`, `MaxSubnetEntry`, `MaxBoundTags`) | `config.ValidateSubnet(s)`, `cli.dropSubnetsOrder`, `reportSubnets` |
| bootstrap entries | `internal/discovery/bootstrap.go` (`ParseEntry`), `internal/id/id.go` (`Parse`); `api.go` skips a bad entry with a warning | `config.ValidatePeer`, `ValidateAnchorID` (also `enrol.Client.Renew`) |
| proxy spec | `reverseproxy.go` (`parseProxySpec`, `canonicalProxyNetwork`, `StartReverseProxy`) | `config.ParseProxySpec`, `ValidateProxies`, `internal/cli/proxy.go` |
| uplink spec | `internal/uplink/spec.go` | `config.ParseUplinkSpec` |
| permanent refusals | the messages of `ErrRealmRootPinned` (`config.go`), `ErrTUNUnavailable` and `ErrRouterHost` (`errors.go`), `ErrCredTaints` (`cred.go`, "does not grant this anchor's taints", exit 1), the kernel's `device or resource busy` from `tundev: creating`, anchorctl's exit 2 for a usage error (`cmd/anchorctl/main.go` `finish`), and `ErrCredRefused` for an expired chain (defined in `cred.go`, returned from `config.go`; permanent only for a credential that does not renew); reasons are mapped in `cmd/anchord/internal/control/lifecycle.go` (`hostRefused`) and `credentials.go` (`refuseInvalid`) | `daemon.Permanent`, `daemon.credential` |
| release names and targets | `Makefile` (`release`, `dist`, `DIST_TARGETS`) | `Makefile` `TARGETS`, `anchor-bins.sh`, `anchor/bin_*.go` |
| release | `scripts/release-manifest.sh`, `scripts/publish-release.sh`, `.github/workflows/release.yml` | `internal/anchorrelease`, `cmd/anchor-fetch`, `.github/actions/anchor-bins` |
| TUN name | `internal/tundev/name.go` and `tun_*.go` (a request: honoured on Linux and Windows; `utunN` on macOS, `tunN` on the BSDs; Linux refuses past IFNAMSIZ, macOS a `utun` name that is not `utun`+digits), reported back by nothing | `config.ValidateTUNName`, `cli.interfaceLine` |
| Go version | the `go` line in each `go.mod` | `go.mod`, the `setup` action |

When a rule is unclear, anchor's docs cover it: `docs/control.md`, `reverse-proxy.md`, `uplink.md`, `ipv4.md`, `identity.md`, `realm.md`, `observability.md`, `tun.md`, `build.md`.

## Anchor's release build

- **`make release`**
  - Prerequisites: `.bin/garble` (built from anchor's `tools/go.mod`) and `$(GENESIS_DIR)/genesis.pin`, where `GENESIS_DIR ?= genesis`.
  - **When the pin file is absent, its rule mints a new genesis root** (writes `genesis.key`, `genesis.pub`, `genesis.pin`). Anchor's own CI writes the pin from its public repository variable `GENESIS_PIN` and asserts afterwards that no `genesis.key` appeared. Step 3 mirrors that. A local checkout's `genesis/` may hold exactly such a minted development root, whose pin is not production's.
  - It first runs `rm -rf release/`. Then, for each anchor `DIST_TARGETS` entry (linux/amd64, linux/arm64, darwin/amd64, darwin/arm64, windows/amd64, windows/arm64, freebsd/amd64, openbsd/amd64), with `CGO_ENABLED=0 GOWORK=off`, it builds three programs:
    - `anchord`, garbled, with `-ldflags -X github.com/veil-net/anchor.pinnedGenesis=<pin>`
    - `anchorctl`, garbled, `-tags lockdown`
    - `anchoradmin`, plain and unrestricted, **always**
  - Output: `release/{anchord,anchorctl,anchoradmin}-<os>-<arch>[.exe]`, 24 files, then `release: 24 binaries in release/, pinned to realm…`. About 25 s with a warm build cache.
  - Garbled builds are not byte-reproducible, so a local release and anchor's release built from the same commit have different digests.
  - darwin/amd64 is not in conflux's `TARGETS`, and `anchor-bins.sh` ignores it.
- **`make dist`:** the unpinned, unobfuscated cross-build for the same 8 targets. Only `anchord` and the `-tags lockdown` `anchorctl` go into `dist/` (16 files). It joins any realm tree: development only, never shippable.
- **`scripts/client-is-locked.sh DIR [ADMIN_DIR]`:** runs the host's `DIR/anchorctl-<os>-<arch> root` with no daemon and requires the lockdown refusal (`unknown command "root"`). Fails if any `anchorctl` is byte-identical to its `anchoradmin` twin in `ADMIN_DIR`.
- **Release publishing:** anchor's `release.yml` runs on every push to anchor `main`. It runs `make release` with `GENESIS_PIN`, then `scripts/release-manifest.sh` (copies `anchord`/`anchorctl` only, runs `client-is-locked.sh`, writes `manifest.json`, whose `pin` is `GENESIS_PIN`), then `scripts/publish-release.sh` twice with the same assets and notes: at a dated tag `YYYYMMDD-HHMMSS` (the commit's time in UTC; it stays) and at `latest`, which moves and is marked Latest. Each is deleted and recreated with `target_commitish` set to the commit SHA; the build is also uploaded as a workflow artifact.

## Live traveller API

The schema is served by Swagger UI at `/docs`. The OpenAPI 3.0 document is embedded as `swaggerDoc` in `/docs/swagger-ui-init.js`; `/openapi.json` and similar paths return 404. Extract it:

```bash
python3 - "$S" <<'EOF'
import json, sys, pathlib
d = pathlib.Path(sys.argv[1]); s = (d / 'swagger-ui-init.js').read_text()
i = s.index('"swaggerDoc":') + len('"swaggerDoc":')
doc, _ = json.JSONDecoder().raw_decode(s[i:].lstrip())
(d / 'openapi.json').write_text(json.dumps(doc, indent=1, sort_keys=True))
for p, ops in sorted(doc['paths'].items()):
    for m, op in ops.items():
        print(m.upper(), p, op.get('tags'), sorted(op.get('responses', {})))
EOF
```

**Routes conflux calls** (the only ones this skill may call):

- `POST /ghosts/alpha`: body `{"taints": [...]}` (`EnrolAlphaDto`, required; at most 32 names matching `^[^\s@+\p{C}]+$`; empty is the realm's shared compartment), no auth. Returns `201 {"credentials": "<base64 anchor manifest>"}` (`GhostCredentialsResponseDto_Output`, no other properties). The credential commits to the taints and lasts thirty days, nothing is stored server-side, and the response is the only copy.
- `POST /ghosts/alpha/renew`: body `{"anchorId": "anchor…", "taints": [...]}` (`RenewAlphaCredentialDto`; anchorId pattern `^anchor.*`, max 128; the taints the anchor was enrolled with, since nothing records them and the running anchor refuses another set). Returns `200 {"chain": "<base64>", "notAfter": "<date-time>", "bootstrap": [...]}` (`GhostRenewalResponseDto_Output`, all required; bootstrap read afresh, as `anchorId@host:port` or `host:port`; live it answers `["genesis.veilnet.com.au:4700"]`). Unauthenticated; renew on launch and at two thirds of `notAfter`.

The schema documents only success responses. A refusal is NestJS's `{"message": …, "error": …, "statusCode": …}` — the renewal route answers a malformed AnchorID with `400 {"message":"member: id: wrong length: want 58 characters, got 28",…}` — and `enrol.HTTPError` shows the message.

**Enrolment check** (step 2; one call):

```bash
curl -sS -X POST -H 'Accept: application/json' -H 'Content-Type: application/json' -d "{\"taints\":[\"$T\"]}" \
  -o "$S/alpha.json" -w '%{http_code} %{time_total}s\n' "$API/ghosts/alpha"   # expect 201
python3 - "$S/alpha.json" <<'EOF'
import json, sys, base64
m = json.loads(base64.b64decode(json.load(open(sys.argv[1]))['credentials']))
secret = {'identity', 'chain', 'renewalSecret'}
print(json.dumps({k: '<redacted>' if k in secret else v for k, v in m.items()}, indent=1))
EOF
```

Expected fields, in the order the API sends them:
- `formatVersion: 1`, `kind: "anchor"`
- `realm` (hex), `genesis`, `identity` and `chain` present
- `notAfter` and `issuedAt` in `2006-01-02T15:04:05.000Z` form, about thirty days apart (`issuedAt` is written just after the chain is signed, so the window is a fraction of a second short of thirty days)
- `taints: ["$T"]` (the request, echoed), `useExit: false`, `bootstrap: ["genesis.veilnet.com.au:4700"]`; no `telemetrySecret`
- `renewalUrl` = `https://api.veilnet.com.au/ghosts/alpha/renew` (same host)
- `renewalAuth: "anchor-id"`

Check every field against `internal/enrol` and anchor's `anchorManifest`. Never print `identity`. Delete `$S/alpha.json` at the end.

**Pin** (step 3): the pin is the realm the live genesis derives to: `realm` plus lowercase unpadded base32 of `SHA3-256("veilnet/anchor/id/v1" || 0x00 || suite 0x01 || genesis)`, anchor's `internal/id` `Derive`. It must equal the pin anchor publishes, the `pin` in the manifest of anchor's `latest` release (`GENESIS_PIN` as published), which `anchor-fetch` prints as `realm:` after fetching one binary into scratch (any token that can read anchor's releases, in the environment):

```bash
PIN=$(python3 - "$S/alpha.json" <<'EOF'
import json, sys, base64, hashlib
g = bytes.fromhex(json.loads(base64.b64decode(json.load(open(sys.argv[1]))['credentials']))['genesis'])
print('realm' + base64.b32encode(hashlib.sha3_256(b'veilnet/anchor/id/v1\x00\x01' + g).digest()).decode().lower().rstrip('='))
EOF
)
ANCHOR_RELEASE_TOKEN=… go run ./cmd/anchor-fetch -dest "$S/release" -want anchord-linux-amd64 2>&1 | grep -E '^(commit|realm):'   # realm: must be $PIN
```

**Guardian contracts** (read in the schema, never call):

- Conflux's self-hosted guardian renewal: the manifest carries `renewalAuth: "node-secret"` and `renewalSecret: "<nodeId>.<secret>"`, sent verbatim as `Authorization: Bearer …` to the manifest's same-host `renewalUrl` on the guardian's own API, with the alpha renewal's body and answer (`{anchorId, taints}` to `{chain, notAfter, bootstrap}`). That route is not in traveller's schema; conflux follows the manifest. The guardian node-manifest fields conflux also reads (`ipv4`, `export`) are defined in a sibling repository's contract (`docs/credentials.md` links it), not in the schema.
- `POST /guardians/{id}/delegation`: `Authorization: Bearer <guardianId>.<secret>` (the guardian credentials' `renewalToken`). Returns `{chain, link, notAfter, severedAt}`. Every refusal is the same 403.
- `GET /orgs/{orgId}/guardians/{id}/credentials`: the base64 guardian credentials document (realm root to pin, guardian realm root with its private key, delegation, bootstrap, renewal) that a guardian stack ingests.
- `GET /ghosts/realms/{realm}/nodes/{id}/credentials`: the base64 node document (realm, anchor key, credential, taints, run flags) for veilnet's own `alpha`/`beta` infrastructure nodes.

Schema quirks: only a `firebase` oauth2 security scheme is declared, `guardian-token` is referenced without being declared, and most authenticated routes carry no `security` field. Decide what is authenticated from each route's description, not from `security`.

**Never call** anything else, including `/`, `/health`, `/genesis*`, `/ghosts/realms*`, `/ghosts/me*` (including `/ghosts/me/beta*` and `/ghosts/me/backups*`), `/auth*`, `/orgs*`, `/guardians*`, `/anchor/release*`, `/billing*` and `/users*`. (`GET /anchor/release` serves a manifest shaped like the release's, whose `pin` is an array and whose binaries carry a `url`. It is not conflux's binary source.)

## Probe node

A single live node from the freshly built image, used in step 3 (pin proof, the one renewal), for the step 5 baseline (a fresh probe after `make image` if step 4 changed anything), and for the step 7 after numbers.

```bash
docker rm -f cfx-probe >/dev/null 2>&1 || true
docker run -d --name cfx-probe --privileged --cgroupns=host \
  -v /sys/fs/cgroup:/sys/fs/cgroup:rw --device /dev/net/tun conflux-systemd-test
for _ in $(seq 40); do [ "$(docker exec cfx-probe systemctl is-system-running 2>/dev/null)" = running ] && break; sleep 1; done
time docker exec cfx-probe conflux up --taint "$T" --no-ipv4   # enrolment + bring-up to ready; no TTY, so --ipv4 or --no-ipv4 is required
docker exec cfx-probe conflux status
time docker exec cfx-probe conflux renew                        # the renewal round trip plus hot install
```

- Behind an egress proxy that re-signs TLS, append its CA to the container's `/etc/ssl/certs/ca-certificates.crt` (`docker cp`, then `cat >>`) before `up`.
- Where Docker has no IPv6, a TUN `up` cannot start: use `conflux proxy --taint "$T" --no-ipv4 8080=127.0.0.1:3000`, which proves the pin and the renewal the same way.
- `serve` beside the running service must be refused ("another conflux supervisor is already serving …", exit 1).

## Baseline

Record each number before (step 5) and after (step 7; the CI suite durations once the PR is green, in step 9):

- **Artifact sizes:** `ls -l dist/conflux-*` (bytes, per target).
- **Extraction:** after `make build`, run `D=$(mktemp -d "$HOME/.cache/cfx-x.XXXX"); time CONFLUX_DIR=$D bin/conflux anchorctl help >/dev/null 2>&1` (the first run in a fresh `$D` extracts into `$D/bin/<SetID>/`), then the same command again for the warm figure. On a real disk, not `$S`: a scratchpad under `/tmp` is usually tmpfs, where the fsyncs that dominate a cold extraction are free. Take the median of 5 fresh directories, and delete them. Single runs are noisy. `bin/conflux version` (the SHA-256s) is worth recording beside it.
- **`up` → ready, and renewal:** the `time` lines from the probe node. The enrolment round trip itself is the `time_total` of the step 2 `curl`.
- **`status` latency**, measured inside the container so `docker exec` overhead is excluded:
  `docker exec cfx-probe sh -c 'for i in $(seq 10); do s=$(date +%s%N); conflux status >/dev/null; echo $(( ($(date +%s%N)-s)/1000000 )); done'`
- **A shared host drifts** between the before and after numbers. For the after figures, keep the before binary (`cp bin/conflux "$S/conflux-old"` at step 5) and compare the two interleaved: in the probe, `docker cp` both in (the same overlay layer; the image's own copy reads differently) and alternate them, and locally alternate them over fresh directories.
- **Goroutines and allocations:** `go test -run '^$' -bench . -benchmem -count 6 ./internal/daemon/` — `BenchmarkAnchorCheck`, `BenchmarkLinkCheck` and `BenchmarkLinkCheckWithDevice` (the watcher's ticks), `BenchmarkBringUp` (the stand-in anchorctl), `BenchmarkAnchordOutput` (the line writer and tail ring), `BenchmarkRenewal`, `BenchmarkDaemonLifecycle` (real anchord) in `internal/daemon/bench_test.go`, each reporting allocations and, where goroutines are involved, `goroutines-left`, which must be 0. Compare runs with `benchstat` (six samples each for a confidence interval). Trace a regression with `-memprofile` from a worktree at the before commit (hard-link `anchor/bin` in) and `go tool pprof -diff_base`.
- **Suite durations**, from CI rather than run locally: each job's time in the last successful `ci` run before the branch (`gh run list --workflow ci.yml --status success --limit 1`, then `gh run view <run> --json jobs --jq '.jobs[] | [.name, .startedAt, .completedAt]'`) and in the PR's final green run.

## Tools

```bash
go install honnef.co/go/tools/cmd/staticcheck@latest
go install golang.org/x/vuln/cmd/govulncheck@latest
go install github.com/rhysd/actionlint/cmd/actionlint@latest
go install golang.org/x/perf/cmd/benchstat@latest
go install golang.org/x/tools/cmd/goimports@latest
curl -fsS 'https://go.dev/dl/?mode=json' | python3 -c 'import json,sys; print(json.load(sys.stdin)[0]["version"])'   # latest stable Go
git ls-remote https://github.com/<owner>/<repo> 'refs/tags/v*' | sort -t/ -k3 -V | tail -4   # an action's newest tags; pin the peeled ^{} line of an annotated tag
```

Also needed:
- A Go toolchain installed outside the module cache (the go.dev tarball, `GOTOOLCHAIN=local`) for anchor's `make release`: garble refuses a toolchain `GOTOOLCHAIN` auto-downloaded into `GOMODCACHE` ("overlay contains a replacement for …").
- `shellcheck`, for actionlint and `shellcheck scripts/*.sh test/*.sh`: the distro package, `pip install shellcheck-py`, or the release binary (`curl -fsSL https://github.com/koalaman/shellcheck/releases/download/$V/shellcheck-$V.linux.x86_64.tar.xz | tar -xJ -C "$S"`), on `PATH`.
- Docker with `/dev/net/tun` and cgroups, for the container suites and the probe; where no daemon runs, `dockerd` can be started by hand. `docker run bash:3.2` checks `anchor-bins.sh` and `test/service-host.sh` against the bash a Mac has.
- `gh`, authenticated, or the GitHub MCP tools, for the PR and its runs; `GENESIS_PIN` only where the variables API is reachable.
