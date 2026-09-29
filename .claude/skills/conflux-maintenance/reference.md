# Conflux maintenance: reference

The concrete facts the workflow relies on. Step 8 of every run keeps this file true. Where it disagrees with the tree, the tree wins, and this file gets fixed.

## Layout

- `main.go` → `internal/cli.Main`.
- `anchor/`: `anchor.go` (`Supported` = build tag plus a ≥ 5 MiB size check on both binaries; `SetID`, the extraction directory's name, from a CRC-32C and the length of each binary; `Digests`, the SHA-256s `conflux version` prints), seven build-tagged `bin_<os>_<arch>.go` files (each `//go:embed`s `bin/anchord-<os>-<arch>[.exe]` and `bin/anchorctl-<os>-<arch>[.exe]` by name), `bin_unsupported.go` (every other platform: no pair), `bin/` (gitignored).
- `cmd/anchor-fetch/`: the shelf fetcher CLI.
- `internal/`
  - `anchorctl`: `args.go` (`StartMode`, `ModeFromConfig`, the argv builders), `ctl.go` (runs `start`, `stop`, `status`, `metrics`, `renew`; `Ping`; `Env`), `parse.go` (`ParseStarted`, `ParseStatus`, `ParseMetric`, `MetricConnections`), `testdata/argv/*.golden`, `flags_test.go` (flag cross-check)
  - `cli`: verbs, pass-through, refusal of `stop`/`restart`, `up`/`proxy`/`enrol`/`renew`/`status`/`serve`, `chooseIPv4` (asked once), `needsRoot` (a privilege refusal that repeats the command typed, quoted), per-OS glue (`service_windows.go` logs the service to `LogFile`)
  - `config`: `Config` (`IPv4 *string`: nil never asked, `""` declined), `Validate`, `DefaultAPIBaseURL`, `DefaultTUNName`; `spec.go` (taint, proxy, IPv4, uplink, peer, AnchorID and subnet grammar, each anchor's); `atomic.go`; `secret.go` (redacting `Envelope`); `export.go`; `state.go` (`ClockSkew`, link reopens)
  - `daemon`: `supervisor.go` (spawn into a `child` whose exit is a closed channel, line writers, a fixed-size tail ring, readiness, shutdown — SIGTERM where a signal reaches, `anchorctl stop` then kill where none does, nothing for a daemon already gone — `renewLoop`, `isPermanent`), `bringup.go` (`BringUp` under the lock, `credential`, `MaxSkew` = anchor's `realm.CredSkew`, 10 min, `permanentError`), `renew.go` (`renewStored`, the one renewal body; `RenewNow`), `renewal.go` (the two-thirds arithmetic), `ready.go`, `link.go` (link watcher), `export.go` (anchord's `-config`), `proc_*.go`; `bench_test.go`, `main_test.go` (the test binary as a stand-in anchorctl/anchord, told apart by argv: anchord is started `-socket` first), `supervisor_test.go` (shutdown of a dead and a live daemon, the tail's order)
  - `enrol`: `client.go` (`Enrol` returns the envelope undecoded; `Renew` needs the manifest's `renewalUrl`; per-client `Skew`; shared transport), `manifest.go` (`Decode`, `WithChain`), `auth.go`
  - `paths`: `Dirs`, `EnsureAll`, `LogFile`, `acl_windows.go` (`Restrict`, `Trusted`, the root's ownership and DACL), `acl_other.go`
  - the rest: `flock`, `libexec` (extraction; Windows trusts only Administrators-owned binaries), `privcheck`, `service` (systemd, whose unit and `ExecStart=` quoting render in the untagged `service_systemd.go`, launchd, rc for FreeBSD and OpenBSD via `service_rc.go`, the SCM; scope; `exists` for the file-registered managers), `shelf`, `taint` (minting, uniform by rejection sampling), `ui` (`term_*.go`: a real isatty), `version`, `wintun` (`pinned.go`: `Version`, `ZipSHA256`)
- `scripts/anchor-bins.sh`, `test/`, `.github/`, `docs/`, `VERSION`.

## Make targets

`VERSION` comes from the `VERSION` file and `COMMIT` from `git rev-parse HEAD`, stamped via ldflags into `internal/version`.

| Target | Does |
|---|---|
| `all` | `fmtcheck lint tidycheck docscheck test cross dist`: every check that needs neither Docker nor the network |
| `anchor-bins` | `scripts/anchor-bins.sh` with `ANCHOR_SRC` (default `../anchor`), `FETCH` (default `0`), `ANCHOR_API`/`ANCHOR_REPO`/`ANCHOR_TAG` (empty means the `internal/shelf` defaults); `ONLY` and `DEST` pass through the environment |
| `build` | `CGO_ENABLED=0 go build -trimpath` → `bin/conflux` |
| `test` / `race` / `vet` | `go test ./...` / `go test -race ./...` / `go vet ./...` |
| `fmt` / `fmtcheck` | `gofmt -w .` / fail if `gofmt -l .` lists anything |
| `lint` | `staticcheck ./...` once per target OS (`GOOS=…`); **exits 0 printing "staticcheck not installed; skipping"** when absent |
| `vulncheck` | `govulncheck ./...`; same skip behaviour |
| `tidycheck` | `go mod tidy`, then compare `go.mod` and `go.sum` (both restored on failure) |
| `docscheck` | every `docs/*.md` named in `README.md`, every `docs/<name>.md` the README links exists, every `](<name>.md)` link in `docs/` resolves |
| `golden` | `go test ./internal/anchorctl -update` |
| `cross` | every `TARGETS` entry at once: `go vet ./...` (compiles packages and test files), CGO off, each target's output held and printed in `TARGETS` order; works with placeholders |
| `dist` | every `TARGETS` entry built at once into `dist/conflux-<os>-<arch>[.exe]`, then the size gate `MIN_MB=30`..`MAX_MB=75` read in `TARGETS` order, `dist/SHA256SUMS`; clears old artifacts first, leaves no build logs |
| `image` | `dist`, then copies `dist/conflux-linux-amd64` to `test/systemd/conflux` and runs `docker build -t $(IMAGE)` (default `conflux-systemd-test`) |
| `service-test` / `integration` | `image`, then `test/service.sh` / `test/integration.sh` |
| `clean`, `help` | |

`TARGETS := linux/amd64 linux/arm64 darwin/arm64 windows/amd64 windows/arm64 freebsd/amd64 openbsd/amd64`. `dist` is phony and `image` depends on it, so `make dist image` or two separate invocations build all seven targets twice.

## Binary pipeline

- **`scripts/anchor-bins.sh`**
  - Its own `TARGETS=(…)` array (dash form) must equal the Makefile's. Runs on bash 3.2.
  - `ONLY="darwin-arm64 …"` narrows any source to those pairs; an unknown target is refused. `DEST` (default `anchor/bin`) moves where they land.
  - It prunes anything in `DEST` that is not one of the 14 names.
  - Sources, in order:
    1. `$ANCHOR_SRC/release` (pinned)
    2. `$ANCHOR_SRC/dist` (unpinned; warns loudly)
    3. with `FETCH=1`, the shelf (needs `ANCHOR_RELEASE_TOKEN`; failure is fatal)
    4. placeholders
  - It copies, sets `chmod 0755`, and deletes any `anchoradmin-*`.
  - Final line: `N/N copied from <src> (release|dist)`, `N/N fetched from anchor's release (pinned build)`, or `N placeholders written to <dest>`, N being 14 without `ONLY`.
  - A local `release/` always beats `FETCH=1`. `ANCHOR_SRC=/nonexistent` forces the shelf.
- **`cmd/anchor-fetch`**
  - Usage: `go run ./cmd/anchor-fetch [-api URL] [-repo owner/name] [-tag T] -dest DIR -want a,b,…`.
  - The token comes only from `ANCHOR_RELEASE_TOKEN`.
  - Logs to stderr: `shelf:`, `commit:` (the release's `target_commitish`, which anchor sets to the commit SHA), `realm:` (the pin), one line per file with its digest and `fetched` or `cached`, then `N/N in place, digests verified`.
- **`internal/shelf`**
  - Source: GitHub API, repo `veil-net/anchor`, tag `shelf`. The tag moves; it names the newest build from anchor `main`.
  - It refuses any `anchoradmin*` asset and any asset not in state `uploaded`.
  - It reads `manifest.json`: `{"formatVersion":1,"pin":"realm…","binaries":[{"name","program","os","arch","bytes","sha256"}]}`. There are no URLs; assets are resolved by name within the one release.
  - A file already at the destination with the manifest's size and SHA-256 is kept (`cached`); anything else is downloaded to a temp file, checked for size and SHA-256, and renamed into place.
  - Every file at once; the first failure cancels the rest and is the one reported. `ok` lines arrive in completion order. All 14 fresh: ~6 s (37 s one at a time); cached: ~1 s.
  - HTTPS only; `CONFLUX_ALLOW_INSECURE_API=1` allows plain HTTP for tests. Redirects must stay HTTPS, at most 5.
  - Bounds: manifest 1 MiB, binary 200 MiB.

## Test harness

- **`test/preflight.sh`:** checks the Docker daemon, `/dev/net/tun`, `/sys/fs/cgroup` (v1 accepted), and IPv6. Reports whether the API is reachable (`curl …/docs`); that line is informational only.
- **`test/service.sh`:** container `$NAME` (default `cfx`) from `$IMAGE`. Asserts:
  - systemd reaches `running`
  - `conflux install` leaves the unit `enabled` and `inactive`
  - `conflux uninstall --yes` leaves no unit file and no `/var/lib/conflux`
  It enrols nothing.
- **`test/integration.sh`:** random taint `cfx-ci-<12 hex>`. Makes three live enrolments. Waits poll each second and print how long they took. A and B get `--peers 192.0.2.1:4700` (RFC 5737; never answers): anchor probes the link only until its first connection and the live realm answers at once, so without it they would meet through the realm and the link would prove nothing. Stages:
  1. `cfx-a up --ipv4 10.128.0.1/24`: `anchorId` in `state.json`, `manifest.b64` is `0600`, `/run/conflux` is `0700`, and a second `up` keeps the identity.
  2. `cfx-b` (`10.128.0.2/24`): reachable both ways (waited for), v4 pings both ways, plus a v6 ping.
  3. `anchor_lan_peers_found_total` (labelled per interface; summed) is above 0 on A or B.
  4. `cfx-c`: enrolled from `POST /ghosts/alpha` fetched on the host and piped to `conflux enrol --manifest -`; `up --lan-discovery no` with no `--peers` must not enrol again, must reach the realm through the manifest's bootstrap list (`anchor_connections` > 0), and its discovery counter stays 0.
  5. Reboot A: same identity.
  6. `anchord` SIGKILLed on A (`docker exec cfx-a sh -c "kill -9 …"`; `kill` is a builtin): the supervisor brings it back without a reboot — a new pid, `/run/conflux/ready` rewritten, same identity, B reachable at its IPv6.
  7. B `down`: keeps the registration, config and identity, and drops `anchor0`. `start` restores it. `down` then reboot restores it.
  8. `uninstall` removes everything.
- **`test/systemd/Dockerfile`:** `debian:trixie-slim` plus systemd, iproute2, iputils-ping and dbus, with getty, udev, console, timesyncd, logind and modules-load units stripped (a container cannot load modules, and the failed unit leaves systemd `degraded`); `COPY conflux`; boots systemd. Containers run with `--privileged --cgroupns=host -v /sys/fs/cgroup:/sys/fs/cgroup:rw --device /dev/net/tun`.
- **Tests that skip without real binaries (`anchor.Supported`):**
  - `anchor`: `TestPairIsRealExecutables`, `TestSetIDIsStable`
  - `libexec`: `TestEnsureExtractsAndRuns`, `TestEnsureIsIdempotent`, `TestEnsureIsConcurrencySafe`, `TestEnsureRepairsATruncatedExtraction`
  - `anchorctl`: `TestEveryFlagWeUseExists`
  - `cli`: `TestNoUnintendedShadowing`, `TestTheCollisionsAreTheDocumentedOnes`
  - `daemon`: `BenchmarkDaemonLifecycle` (a benchmark; not part of the no-skip gate)
- Platform skips, outside the real-binary gate: `daemon.TestShutdownSignalsARunningDaemon` on Windows, and the mode-bit tests on Windows.
- On Linux with real binaries nothing in the module skips (167 top-level passes); CI's gate requires at least 150.

## CI/CD

**`.github/workflows/ci.yml`**
- Triggers: `pull_request` and `workflow_dispatch`. `permissions: contents: read`. Concurrency group `ci-${{ github.ref }}`, cancel-in-progress.
- Fork guard on every job: `if: github.event_name != 'pull_request' || github.event.pull_request.head.repo.full_name == github.repository`.
- The utility checks (gofmt, staticcheck, tidy, govulncheck, docs links, golden diff) are not in CI; they are `make all` locally.

| Job | Runner | Steps |
|---|---|---|
| `linux` | `[self-hosted, linux]` | setup, anchor-bins (all 14, via the tool cache), `go test -race -count=1 -v ./...` with the gate (no `--- SKIP` anywhere, ≥ 150 PASS), `make cross` |
| `integration` | `ubuntu-latest` | setup, anchor-bins (all 14; `dist` builds every target), `./test/preflight.sh`, `make -j2 -O service-test integration` (`dist` and the image once, then both suites side by side, output grouped per suite). Hosted because node C's QUIC handshake to the manifest's bootstrap node gets no answer from veilnet-dev |
| `platforms` | `macos-latest` (pair `darwin-arm64`), `windows-latest` (pair `windows-amd64`) | setup, anchor-bins (that pair only), on Windows the wintun pin check (digest of the published zip against `internal/wintun/pinned.go`), `go test -count=1 -v ./...` failing if any real-binary test skipped |

**`.github/workflows/release.yml`**
- Triggers: push to `version3`, and `workflow_dispatch`. Concurrency `release-${{ github.ref }}`, never cancelled.
- One job, `build`, self-hosted, `if: github.ref == 'refs/heads/version3'`; permissions `contents`/`id-token`/`attestations: write`. Steps: setup, anchor-bins, version and tag = `VERSION` verbatim (warns when the tag is behind the commit), `make dist`, `actions/attest-build-provenance@v4`, notes from `./dist/conflux-linux-amd64 version` plus the wintun pin, `softprops/action-gh-release@v3` with files `dist/conflux-*` plus `dist/SHA256SUMS`. Nothing re-verifies what CI checked.

**Composite actions (`.github/actions/`)**
- `setup`: `actions/setup-go@v7` with `go-version-file: go.mod` and `cache-dependency-path: go.sum`.
- `anchor-bins`: inputs `app-id`, `private-key`, `targets` (space-separated pairs; empty = all), `repo`, `tag`. Runs `actions/create-github-app-token@v3` (owner `veil-net`, repositories `anchor`), then `make anchor-bins FETCH=1` with the token as `ANCHOR_RELEASE_TOKEN` and `ONLY` from `targets`. On a self-hosted runner `DEST` is `$RUNNER_TOOL_CACHE/conflux-anchor-bin` (persistent; the fetcher reuses files whose digest matches) and the files are copied into `anchor/bin`; a hosted runner fetches straight into `anchor/bin`.
- Secrets: `ANCHOR_APP_ID` and `ANCHOR_APP_PRIVATE_KEY`, the read-only anchor GitHub App and the only credential. `create-github-app-token@v3` deprecates `app-id` in favour of `client-id`, which needs a new secret holding the App's client ID.

Actions in use: `actions/checkout@v7`, `actions/setup-go@v7`, `actions/create-github-app-token@v3`, `actions/attest-build-provenance@v4`, `softprops/action-gh-release@v3`. The v3/v4 majors run on Node 24 and need Actions Runner 2.327.1+ on the self-hosted machine. Validate locally with `actionlint` (with `shellcheck` on `PATH` it also checks `run:` scripts, and it validates the inputs passed to the local actions). `act` is not installed.

## Docs and config

- `VERSION`: `1.0.0-pre`. It is both the release tag and the stamped version, verbatim. This skill never bumps it.
- `docs/`: `build`, `commands`, `concepts`, `config`, `credentials`, `install`, `modes`, `security`, `service`, `testing`, `troubleshooting`, `uplink`, `windows` (`.md`). Each is linked from `README.md`.
- `config.DefaultAPIBaseURL` = `https://api.veilnet.com.au` (`internal/config/config.go`). `enrol.Client` falls back to it. The renewal URL comes from the manifest and must be on the same host as the configured API (`enrol.SameHost`); `conflux enrol` derives the API from it unless `--api` is given.

## Local checks

`make fmtcheck lint tidycheck vulncheck docscheck`, plus `actionlint` and `shellcheck scripts/*.sh test/*.sh`. These are the utility checks, which run here and not in CI. `lint` and `vulncheck` exit 0 printing `not installed; skipping` when their tool is absent, which a maintenance run counts as a failure.

## Anchor surface map

Paths are relative to the anchor checkout.

| Surface | Anchor source of truth | Conflux consumer |
|---|---|---|
| anchorctl commands | `cmd/anchorctl/main.go` dispatch; the lockdown build drops `root` and adds `mint-realm`/`mint-anchor` (`cmd/anchorctl/locked.go`, `manifest.go`) | `internal/cli` `verbs()`, `anchorLifecycleVerbs`, shadowing and collision tests, `docs/commands.md` |
| start flags | `configFlags` in `cmd/anchorctl/lifecycle.go` (`describedByFile`) | `internal/anchorctl/args.go`, argv goldens, `flags_test.go` |
| output formats | `printStarted` and `statusCmd` in `cmd/anchorctl/lifecycle.go` (tabwriter rows; the `ipv4` row has three cells; realm paths are short IDs; overlay addresses carry a length) | `internal/anchorctl/parse.go`, `parse_test.go` fixtures |
| metric names | `metrics.go` (`Metric*` constants; labelled series such as `anchor_lan_peers_found_total{iface=…}`) | `parse.go` (`MetricConnections`), `test/integration.sh`, docs |
| daemon flags | `cmd/anchord/main.go` (`-socket`, `-token-file`, `-config`, `-v`, `-credentials-dir`, …) | `daemon.anchordArgs` |
| daemon config | `proto/anchor/v1/daemon.proto` (`DaemonConfig`), `observability.proto` (`ExportConfig`) | `internal/config/export.go`, `daemon/export.go` |
| control socket | `cmd/anchord/internal/control/server.go` (`Listen`: AF_UNIX on every OS, clears a stale socket itself), `sockpath_*.go` (limit: `sun_path`, 108 on Windows) | `paths` (`socketName`, `sockPathMax`, `CheckSocketLen`), the supervisor's probe |
| lifecycle RPC semantics | `cmd/anchord/internal/control/lifecycle.go` (`Stop` with nothing running succeeds) | `anchorctl.Ctl.Stop` |
| mode, exit and IPv4 rules | `config.go` (`Config.validate`, `validateUplink`, `StaticIPv4`), `cmd/anchord/internal/control/config.go` (bare address → /32), `docs/ipv4.md` | `internal/config` (`Validate`, `ParseOverlayIPv4`) |
| manifest/credential format | `cmd/anchorctl/manifest.go` (`anchorManifest`, `manifestVersion`, `kind`, `checkEnvelope`, `loadAnchorManifest`) | `internal/enrol/manifest.go`, `auth.go` |
| taints | `internal/realm/taint.go` | `internal/taint`, `config.ValidateTaint(s)` |
| subnets | `internal/hostnet/local.go` (`Select`, `matchOffer`), `classify.go` (`privateNetworks`, `IsPrivateNetwork`) | `config.ValidateSubnet` |
| bootstrap entries | `internal/discovery/bootstrap.go` (`ParseEntry`), `internal/id/id.go` (`Parse`) | `config.ValidatePeer`, `ValidateAnchorID` |
| proxy spec | `reverseproxy.go` (`parseProxySpec`, `canonicalProxyNetwork`, `StartReverseProxy`) | `config.ParseProxySpec`, `ValidateProxies`, `internal/cli/proxy.go` |
| uplink spec | `internal/uplink/spec.go` | `config.ParseUplinkSpec` |
| permanent refusals | the messages behind `ErrRealmRootPinned` (`config.go`), the TUN-unavailable hint (`cmd/anchorctl/main.go`), and the kernel's `device or resource busy` | `daemon.isPermanent` |
| release names and targets | `Makefile` (`release`, `dist`, `DIST_TARGETS`) | `Makefile` `TARGETS`, `anchor-bins.sh`, `anchor/bin_*.go` |
| shelf | `scripts/shelf-manifest.sh`, `scripts/publish-shelf.sh`, `.github/workflows/release.yml` | `internal/shelf`, `cmd/anchor-fetch`, `.github/actions/anchor-bins` |
| Go version | the `go` line in each `go.mod` | `go.mod`, the `setup` action |

When a rule is unclear, anchor's docs cover it: `docs/control.md`, `reverse-proxy.md`, `uplink.md`, `ipv4.md`, `identity.md`, `realm.md`, `observability.md`, `tun.md`, `build.md`.

## Anchor's release build

- **`make release`**
  - Prerequisites: `.bin/garble` (built from anchor's `tools/go.mod`) and `$(GENESIS_DIR)/genesis.pin`, where `GENESIS_DIR ?= genesis`.
  - **When the pin file is absent, its rule mints a new genesis root** (writes `genesis.key`, `genesis.pub`, `genesis.pin`). Anchor's own CI writes the pin from its public repository variable `GENESIS_PIN` and asserts afterwards that no `genesis.key` appeared. Step 3 mirrors that.
  - It first runs `rm -rf release/`. Then, for each anchor `DIST_TARGETS` entry (linux/amd64, linux/arm64, darwin/amd64, darwin/arm64, windows/amd64, windows/arm64, freebsd/amd64, openbsd/amd64), with `CGO_ENABLED=0 GOWORK=off`, it builds three programs:
    - `anchord`, garbled, with `-ldflags -X github.com/veil-net/anchor.pinnedGenesis=<pin>`
    - `anchorctl`, garbled, `-tags lockdown`
    - `anchoradmin`, plain and unrestricted, **always**
  - Output: `release/{anchord,anchorctl,anchoradmin}-<os>-<arch>[.exe]`, 24 files, then `release: 24 binaries in release/, pinned to realm…`. About 25 s with a warm build cache.
  - Garbled builds are not byte-reproducible, so a local release and the shelf built from the same commit have different digests.
  - darwin/amd64 is not in conflux's `TARGETS`, and `anchor-bins.sh` ignores it.
- **`make dist`:** the unpinned, unobfuscated cross-build for the same 8 targets. Only `anchord` and the `-tags lockdown` `anchorctl` go into `dist/` (16 files). It joins any realm tree: development only, never shippable.
- **`scripts/client-is-locked.sh DIR [ADMIN_DIR]`:** runs the host's `DIR/anchorctl-<os>-<arch> root` with no daemon and requires the lockdown refusal (`cannot create realm roots`). Fails if any `anchorctl` is byte-identical to its `anchoradmin` twin in `ADMIN_DIR`.
- **Shelf publishing:** anchor's `release.yml` runs on merge to anchor `main`. It runs `make release` with `GENESIS_PIN`, then `scripts/shelf-manifest.sh` (copies `anchord`/`anchorctl` only, runs `client-is-locked.sh`, writes `manifest.json`), then `scripts/publish-shelf.sh`, which moves the `shelf` release with `target_commitish` set to the commit SHA.

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

- `POST /ghosts/alpha`: no body, no auth. Returns `201 {"credentials": "<base64 anchor manifest>"}` (`GhostCredentialsResponseDto`). The credential lasts thirty days, nothing is stored server-side, and the response is the only copy.
- `POST /ghosts/alpha/renew`: body `{"anchorId": "anchor…"}` (`RenewGhostCredentialDto`, pattern `^anchor.*`, max 128). Returns `200 {"chain": "<base64>", "notAfter": "<date-time>"}` (`GhostRenewalResponseDto`, no other properties). Unauthenticated; renew on launch and at two thirds of `notAfter`.

The schema documents only success responses. A refusal is NestJS's `{"message": …, "error": …, "statusCode": …}` — the renewal route answers a malformed AnchorID with `400 {"message":"member: id: wrong length: want 58 characters, got 28",…}` — and `enrol.HTTPError` shows the message.

**Enrolment check** (step 2; one call):

```bash
curl -sS -X POST -H 'Accept: application/json' -o "$S/alpha.json" -w '%{http_code} %{time_total}s\n' "$API/ghosts/alpha"   # expect 201
python3 - "$S/alpha.json" <<'EOF'
import json, sys, base64
m = json.loads(base64.b64decode(json.load(open(sys.argv[1]))['credentials']))
secret = {'identity', 'chain', 'telemetrySecret', 'renewalSecret'}
print(json.dumps({k: '<redacted>' if k in secret else v for k, v in m.items()}, indent=1))
EOF
```

Expected fields, in the order the API sends them:
- `formatVersion: 1`, `kind: "anchor"`
- `realm` (hex), `genesis`, `identity` and `chain` present
- `notAfter` and `issuedAt` in `2006-01-02T15:04:05.000Z` form, about thirty days apart (`issuedAt` is written just after the chain is signed, so the window is a fraction of a second short of thirty days)
- `taints: []`, `useExit: false`, `bootstrap: ["genesis.veilnet.com.au:4700"]`
- `renewalUrl` = `https://api.veilnet.com.au/ghosts/alpha/renew` (same host)
- `renewalAuth: "anchor-id"`

Check every field against `internal/enrol` and anchor's `anchorManifest`. Never print `identity`. Delete `$S/alpha.json` at the end.

**Guardian contracts** (read in the schema, never call):

- Conflux's self-hosted guardian renewal: the manifest carries `renewalAuth: "node-secret"` and `renewalSecret: "<nodeId>.<secret>"`, sent verbatim as `Authorization: Bearer …` to the manifest's same-host `renewalUrl` on the guardian's own API. That route is not in traveller's schema; conflux follows the manifest. The guardian node-manifest fields conflux also reads (`ipv4`, `export`) are defined in a sibling repository's contract (`docs/credentials.md` links it), not in the schema.
- `POST /guardians/{id}/delegation`: `Authorization: Bearer <guardianId>.<secret>` (the guardian credentials' `renewalToken`). Returns `{chain, link, notAfter, severedAt}`. Every refusal is the same 403.
- `GET /orgs/{orgId}/guardians/{id}/credentials`: the base64 guardian credentials document (realm root to pin, guardian realm root with its private key, delegation, bootstrap, renewal) that a guardian stack ingests.
- `GET /ghosts/realms/{realm}/nodes/{id}/credentials`: the base64 node document (realm, anchor key, credential, taints, run flags) for veilnet's own `alpha`/`beta` infrastructure nodes.

Schema quirks: only a `firebase` oauth2 security scheme is declared, `guardian-token` is referenced without being declared, and most authenticated routes carry no `security` field. Decide what is authenticated from each route's description, not from `security`.

**Never call** anything else, including `/`, `/health`, `/genesis*`, `/ghosts/realms*`, `/ghosts/me*` (including `/ghosts/me/beta*` and `/ghosts/me/backups*`), `/auth*`, `/orgs*`, `/guardians*`, `/anchor/release*`, `/billing*` and `/users*`. (`GET /anchor/release` serves a shelf-shaped manifest whose `pin` is an array and whose binaries carry a `url`. It is not conflux's binary source.)

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

## Baseline

Record each number before (step 5) and after (step 7; the CI suite durations once the PR is green, in step 9):

- **Artifact sizes:** `ls -l dist/conflux-*` (bytes, per target).
- **Extraction:** after `make build`, run `D=$(mktemp -d "$S/x.XXXX"); time CONFLUX_DIR=$D bin/conflux anchorctl help >/dev/null` (the first run in a fresh `$D` extracts into `$D/bin/<SetID>/`), then the same command again for the warm figure. Take the median of 5 fresh directories. Single runs are noisy. `bin/conflux version` (the SHA-256s) is worth recording beside it.
- **`up` → ready, and renewal:** the `time` lines from the probe node. The enrolment round trip itself is the `time_total` of the step 2 `curl`.
- **`status` latency**, measured inside the container so `docker exec` overhead is excluded:
  `docker exec cfx-probe sh -c 'for i in $(seq 10); do s=$(date +%s%N); conflux status >/dev/null; echo $(( ($(date +%s%N)-s)/1000000 )); done'`
- **Goroutines and allocations:** `go test -run '^$' -bench . -benchmem -count 6 ./internal/daemon/ ./internal/libexec/` — `BenchmarkLinkCheck`, `BenchmarkRenewal`, `BenchmarkDaemonLifecycle` (real anchord) in `internal/daemon/bench_test.go`, each reporting allocations and `goroutines-left`, which must be 0. Compare runs with `benchstat` (six samples each for a confidence interval).
- **Suite durations**, from CI rather than run locally: each job's time in the last successful `ci` run before the branch (`gh run list --workflow ci.yml --status success --limit 1`, then `gh run view <run> --json jobs --jq '.jobs[] | [.name, .startedAt, .completedAt]'`) and in the PR's final green run.

## Tools

```bash
go install honnef.co/go/tools/cmd/staticcheck@latest
go install golang.org/x/vuln/cmd/govulncheck@latest
go install github.com/rhysd/actionlint/cmd/actionlint@latest
go install golang.org/x/perf/cmd/benchstat@latest
go install golang.org/x/tools/cmd/goimports@latest
curl -fsS 'https://go.dev/dl/?mode=json' | python3 -c 'import json,sys; print(json.load(sys.stdin)[0]["version"])'   # latest stable Go
```

Also needed:
- `shellcheck`, for actionlint and `shellcheck scripts/*.sh test/*.sh`. Without the distro package or sudo, the release binary works: `curl -fsSL https://github.com/koalaman/shellcheck/releases/download/$V/shellcheck-$V.linux.x86_64.tar.xz | tar -xJ -C "$S"`, then put it on `PATH`.
- Docker with `/dev/net/tun` and cgroups, for the container suites; `docker run bash:3.2` checks `anchor-bins.sh` against the bash a Mac has.
- `gh`, authenticated, for action release tags and `GENESIS_PIN`
