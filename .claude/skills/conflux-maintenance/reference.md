# Conflux maintenance: reference

The concrete facts the workflow relies on. Step 8 of every run keeps this file true. Where it disagrees with the tree, the tree wins, and this file gets fixed.

## Layout

- `main.go` → `internal/cli.Main`.
- `anchor/`: `anchor.go` (`Supported` = build tag plus a ≥ 5 MiB size check on both binaries; `SetID`, the content hash the extraction directory is keyed on; `Digests`), seven build-tagged `bin_<os>_<arch>.go` files (each `//go:embed`s `bin/anchord-<os>-<arch>[.exe]` and `bin/anchorctl-<os>-<arch>[.exe]` by name), `bin_unsupported.go` (every other platform: no pair), `bin/` (gitignored).
- `cmd/anchor-fetch/`: the shelf fetcher CLI.
- `internal/`
  - `anchorctl`: `args.go` (argv builders, `Validate`), `ctl.go` (runs `start`, `stop`, `status`, `metrics`, `renew`, `config`, `peers`, `export`, `telemetry`), `parse.go` (`ParseStarted`, `ParseStatus`, `ParseMetrics`), `testdata/argv/*.golden`, `flags_test.go` (flag cross-check)
  - `cli`: verbs, pass-through, refusal of `stop`/`restart`, `up`/`proxy`/`enrol`/`renew`/`status`/`serve`, per-OS service glue
  - `config`: `Mode`, `Validate`, `DefaultAPIBaseURL`, `DefaultTUNName`; `spec.go` (taint, proxy, uplink and peer grammar); `atomic.go`; `secret.go` (redacting `Envelope`); `dacl_*.go`; `export.go`; `state.go`
  - `daemon`: supervisor, bring-up, readiness, renewal, `renew_once`, link watcher, per-OS process handling
  - `enrol`: `client.go`, `manifest.go`, `auth.go`
  - the rest: `flock`, `libexec` (extraction), `paths` (`CONFLUX_DIR`), `privcheck`, `service` (per OS, plus scope), `shelf`, `taint`, `ui`, `version`, `wintun` (`pinned.go`: `Version`, `ZipSHA256`)
- `scripts/anchor-bins.sh`, `test/`, `.github/`, `docs/`, `VERSION`.

## Make targets

`VERSION` comes from the `VERSION` file and `COMMIT` from `git rev-parse HEAD`, stamped via ldflags into `internal/version`.

| Target | Does |
|---|---|
| `all` | `fmtcheck vet lint tidycheck test cross dist` |
| `anchor-bins` | `scripts/anchor-bins.sh` with `ANCHOR_SRC` (default `../anchor`), `FETCH` (default `0`), `ANCHOR_API`/`ANCHOR_REPO`/`ANCHOR_TAG` (empty means the `internal/shelf` defaults) |
| `build` | `CGO_ENABLED=0 go build -trimpath` → `bin/conflux` |
| `test` / `race` / `vet` | `go test ./...` / `go test -race ./...` / `go vet ./...` |
| `fmt` / `fmtcheck` | `gofmt -w .` / fail if `gofmt -l .` lists anything |
| `lint` / `vulncheck` | `staticcheck ./...` / `govulncheck ./...`; each **exits 0 printing "… not installed; skipping"** when its tool is absent |
| `tidycheck` | `go mod tidy`, then compare `go.mod` (restored on failure) |
| `golden` | `go test ./internal/anchorctl -update` |
| `cross` | for each `TARGETS` entry: `go vet ./...` (compiles test files) and `go build -o /dev/null .`, CGO off; works with placeholders |
| `dist` | for each `TARGETS` entry: `dist/conflux-<os>-<arch>[.exe]`, size gate `MIN_MB=30`..`MAX_MB=75`, `dist/SHA256SUMS`; clears old artifacts first |
| `image` | `dist`, then copies `dist/conflux-linux-amd64` to `test/systemd/conflux` and runs `docker build -t $(IMAGE)` (default `conflux-systemd-test`) |
| `service-test` / `integration` | `image`, then `test/service.sh` / `test/integration.sh` |
| `clean`, `help` | |

`TARGETS := linux/amd64 linux/arm64 darwin/arm64 windows/amd64 windows/arm64 freebsd/amd64 openbsd/amd64`. `dist` is phony and `image` depends on it, so `make dist image` or two separate invocations build all seven targets twice.

## Binary pipeline

- **`scripts/anchor-bins.sh`**
  - Its own `TARGETS` line (dash form) must equal the Makefile's.
  - It prunes anything in `DEST` (default `anchor/bin`, overridable from the environment) that is not one of the 14 names.
  - Sources, in order:
    1. `$ANCHOR_SRC/release` (pinned)
    2. `$ANCHOR_SRC/dist` (unpinned; warns loudly)
    3. with `FETCH=1`, the shelf (needs `ANCHOR_RELEASE_TOKEN`; failure is fatal)
    4. placeholders
  - It copies, sets `chmod 0755`, and deletes any `anchoradmin-*`.
  - Final line: `14/14 copied from <src> (release|dist)`, `14/14 fetched from anchor's release (pinned build)`, or `14 placeholders written`.
  - A local `release/` always beats `FETCH=1`. `ANCHOR_SRC=/nonexistent` forces the shelf.
- **`cmd/anchor-fetch`**
  - Usage: `go run ./cmd/anchor-fetch [-api URL] [-repo owner/name] [-tag T] -dest DIR -want a,b,…`.
  - The token comes only from `ANCHOR_RELEASE_TOKEN`.
  - Logs to stderr: `shelf:`, `commit:` (the release's `target_commitish`, which anchor sets to the commit SHA), `realm:` (the pin), then one line per file with its digest.
- **`internal/shelf`**
  - Source: GitHub API, repo `veil-net/anchor`, tag `shelf`. The tag moves; it names the newest build from anchor `main`.
  - It refuses any `anchoradmin*` asset and any asset not in state `uploaded`.
  - It reads `manifest.json`: `{"formatVersion":1,"pin":"realm…","binaries":[{"name","program","os","arch","bytes","sha256"}]}`. There are no URLs; assets are resolved by name within the one release.
  - HTTPS only; `CONFLUX_ALLOW_INSECURE_API=1` allows plain HTTP for tests. Redirects must stay HTTPS, at most 5.
  - Bounds: manifest 1 MiB, binary 200 MiB. Each binary goes to a temp file, is checked for size and SHA-256, and is renamed into place.

## Test harness

- **`test/preflight.sh`:** checks the Docker daemon, `/dev/net/tun`, `/sys/fs/cgroup` (v1 accepted), and IPv6. Reports whether the API is reachable (`curl …/docs`); that line is informational only.
- **`test/service.sh`:** container `$NAME` (default `cfx`) from `$IMAGE`. Asserts:
  - systemd reaches `running`
  - `conflux install` leaves the unit `enabled` and `inactive`
  - `conflux uninstall --yes` leaves no unit file and no `/var/lib/conflux`
  It enrols nothing.
- **`test/integration.sh`:** random taint `cfx-ci-<12 hex>`. Makes three live enrolments. Stages:
  1. `cfx-a up --ipv4 10.128.0.1/24`: `anchorId` in `state.json`, `manifest.b64` is `0600`, `/run/conflux` is `0700`, and a second `up` keeps the identity.
  2. `cfx-b` (`10.128.0.2/24`): v4 pings both ways, plus a v6 ping.
  3. `anchor_lan_peers_found_total` is above 0 on A.
  4. `cfx-c --lan-discovery no`: the counter stays 0 while C serves `anchor_` metrics. This is the control; whether C reaches the realm is reported, not asserted.
  5. Reboot A: same identity.
  6. B `down`: keeps the registration, config and identity, and drops `anchor0`. `start` restores it. `down` then reboot restores it.
  7. `uninstall` removes everything.
- **`test/systemd/Dockerfile`:** `debian:bookworm-slim` plus systemd, iproute2, iputils-ping and dbus; `COPY conflux`; boots systemd. Containers run with `--privileged --cgroupns=host -v /sys/fs/cgroup:/sys/fs/cgroup:rw --device /dev/net/tun`.
- **Tests that skip without real binaries (`anchor.Supported`):**
  - `anchor`: `TestPairIsRealExecutables`, `TestSetIDIsStable`
  - `libexec`: `TestEnsureExtractsAndRuns`, `TestEnsureIsIdempotent`, `TestEnsureIsConcurrencySafe` (also skips under `-short`, so never pass `-short`), `TestEnsureRepairsATruncatedExtraction`
  - `anchorctl`: `TestEveryFlagWeUseExists`
  - `cli`: `TestNoUnintendedShadowing`, `TestTheCollisionsAreTheDocumentedOnes`

## CI/CD

**`.github/workflows/ci.yml`**
- Triggers: `pull_request` and `workflow_dispatch`. `permissions: contents: read`. Concurrency group `ci-${{ github.ref }}`, cancel-in-progress.
- Fork guard on self-hosted jobs: `if: github.event_name != 'pull_request' || github.event.pull_request.head.repo.full_name == github.repository`.

| Job | Runner | Needs | Steps |
|---|---|---|---|
| `linux` | `[self-hosted, linux]` | – | setup, anchor-bins (shelf), fmtcheck, vet, tidycheck, staticcheck@v0.8.1, govulncheck@v1.8.0, race, the no-`SKIP` gate over the four real-binary packages (≥ 30 PASS), golden diff |
| `cross` | self-hosted | – | placeholders, `make cross` |
| `platforms` | `macos-latest`, `windows-latest` | linux, cross | placeholders, `go build ./...`, `go test ./...` |
| `windows-tun` | `windows-latest` | linux, cross | placeholders, wintun installed from `internal/wintun/pinned.go` (digest checked), `go test -run 'TestEnsure\|TestPairIsRealExecutables'` |
| `service` | self-hosted | linux, cross | shelf, preflight, `make service-test`, `docker rm -f cfx` |
| `integration` | self-hosted | linux, cross | shelf, preflight, `make integration`, `docker rm -f cfx-a cfx-b cfx-c` |
| `docs` | self-hosted | – | README ↔ docs links, internal links |

**`.github/workflows/release.yml`**
- Triggers: push to `version3`, and `workflow_dispatch`. Concurrency `release-${{ github.ref }}`, never cancelled. All jobs run self-hosted.
- `gate`: refuses anything but `refs/heads/version3`. Version and tag are both `VERSION`, verbatim. Warns when the tag is behind the commit being built.
- `verify`: shelf; no `anchoradmin*`; every file ≥ 5,000,000 bytes; all 14 present (its own hardcoded target list).
- `build`: permissions `contents`/`id-token`/`attestations: write`. Shelf, `make dist`, `actions/attest-build-provenance@v1`, notes from `go run . version` plus the wintun pin, then `softprops/action-gh-release@v2` with tag = `VERSION` and files `dist/conflux-*` plus `dist/SHA256SUMS`.

**Composite actions (`.github/actions/`)**
- `setup`: `actions/setup-go@v7` with `go-version-file: go.mod` and `cache-dependency-path: go.sum`.
- `anchor-bins`: inputs `app-id`, `private-key`, `repo`, `tag`. Runs `actions/create-github-app-token@v2` (owner `veil-net`, repositories `anchor`), passes the token as `ANCHOR_RELEASE_TOKEN` in the environment to `make anchor-bins FETCH=1`, then checks the smallest file is ≥ 5,000,000 bytes.
- Secrets: `ANCHOR_APP_ID` and `ANCHOR_APP_PRIVATE_KEY`, the read-only anchor GitHub App and the only credential.

Actions in use: `actions/checkout@v7`, `actions/setup-go@v7`, `actions/create-github-app-token@v2`, `actions/attest-build-provenance@v1`, `softprops/action-gh-release@v2`. Validate locally with `actionlint` (with `shellcheck` installed it also checks `run:` scripts). `act` is not installed.

## Docs and config

- `VERSION`: `1.0.0-pre`. It is both the release tag and the stamped version, verbatim. This skill never bumps it.
- `docs/`: `build`, `commands`, `concepts`, `config`, `credentials`, `install`, `modes`, `security`, `service`, `testing`, `troubleshooting`, `uplink`, `windows` (`.md`). Each is linked from `README.md`.
- `config.DefaultAPIBaseURL` = `https://api.veilnet.com.au` (`internal/config/config.go`). `enrol.Client` falls back to it. The renewal URL comes from the manifest and must be on the same host (`enrol.SameHost`).

## Local checks

`make fmtcheck lint tidycheck vulncheck docscheck`. The docs checks are:

1. every `docs/*.md` is named in `README.md`
2. every `docs/<name>.md` that `README.md` links exists
3. every `](<name>.md)` link inside `docs/` resolves

These currently run as the `docs` job in `ci.yml`, and fmtcheck, tidycheck, staticcheck and govulncheck run inside the `linux` job. Under the CI rules they leave CI. When that happens, the docs checks become a `docscheck` Make target built from the `docs` job's commands and added to `all`, and this section and SKILL.md step 7 are updated to match.

## Anchor surface map

Paths are relative to the anchor checkout.

| Surface | Anchor source of truth | Conflux consumer |
|---|---|---|
| anchorctl commands | `cmd/anchorctl/main.go` dispatch; the lockdown build drops `root` (`cmd/anchorctl/locked.go`) | `internal/cli` `verbs()`, `anchorLifecycleVerbs`, shadowing and collision tests, `docs/commands.md` |
| flags | each command's flag set in `cmd/anchorctl/*.go` | `internal/anchorctl/args.go`, argv goldens, `flags_test.go` |
| output formats | `cmd/anchorctl/format.go` and the printing in each command | `internal/anchorctl/parse.go` |
| metric names | `metrics.go` (`Metric*` constants) | `parse.go`, `test/integration.sh`, docs |
| daemon config, mode and exit rules | `config.go` (`Config.validate`) | `internal/config` (`Mode`, `Validate`), `internal/anchorctl.Validate` |
| manifest/credential format | `cmd/anchorctl/manifest.go` (`anchorManifest`, `realmManifest`, `formatVersion`, `kind`) | `internal/enrol/manifest.go`, `auth.go` |
| taints | `internal/realm/taint.go` | `internal/taint`, `internal/config/spec.go` |
| IPv4 prefix | `config.go`, `docs/ipv4.md` | `internal/config` |
| proxy spec | `cmd/anchorctl/proxy.go`, `reverseproxy.go` | `internal/config/spec.go`, `internal/cli/proxy.go` |
| uplink spec | `internal/uplink/spec.go` | `internal/config/spec.go` |
| release names and targets | `Makefile` (`release`, `dist`, `DIST_TARGETS`) | `Makefile` `TARGETS`, `anchor-bins.sh`, `anchor/bin_*.go`, `release.yml` `verify` |
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
  - Output: `release/{anchord,anchorctl,anchoradmin}-<os>-<arch>[.exe]`, 24 files, then `release: 24 binaries in release/, pinned to realm…`.
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

- `POST /ghosts/alpha`: no body, no auth. Returns `201 {"credentials": "<base64 anchor manifest>"}` (`GhostCredentialsResponseDto`). The credential lasts seven days, nothing is stored server-side, and the response is the only copy.
- `POST /ghosts/alpha/renew`: body `{"anchorId": "anchor…"}` (`RenewGhostCredentialDto`). Returns `200 {"chain": "<base64>", "notAfter": "<date-time>"}` (`GhostRenewalResponseDto`). Unauthenticated; renew at two thirds of `notAfter`.

The schema documents only success responses. Error shapes come from real behaviour and conflux's `HTTPError` handling.

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

Expected fields:
- `formatVersion: 1`, `kind: "anchor"`
- `identity`, `genesis` and `chain` present
- `issuedAt` and `notAfter` in `2006-01-02T15:04:05.000Z` form, about seven days apart
- `renewalUrl` = `https://api.veilnet.com.au/ghosts/alpha/renew` (same host)
- `renewalAuth` absent or `"anchor-id"`
- `taints: []`

Check every field against `internal/enrol` and anchor's `anchorManifest`. Never print `identity`. Delete `$S/alpha.json` at the end.

**Guardian contracts** (read in the schema, never call):

- Conflux's self-hosted guardian renewal: the manifest carries `renewalAuth: "node-secret"` and `renewalSecret: "<nodeId>.<secret>"`, sent verbatim as `Authorization: Bearer …` to the manifest's same-host `renewalUrl` on the guardian's own API. That route is not in traveller's schema; conflux follows the manifest.
- `POST /guardians/{id}/delegation`: `Authorization: Bearer <guardianId>.<secret>` (the guardian credentials' `renewal.token`). Returns `{chain, link, notAfter, severedAt}`. Every refusal is the same 403.
- `GET /orgs/{orgId}/guardians/{id}/credentials`: the base64 guardian credentials document (realm secret, root to pin, guardian realm root with its private key, delegation, bootstrap, renewal) that a guardian stack ingests.
- `GET /ghosts/realms/{realm}/nodes/{id}/credentials`: the base64 node document (realm root, anchor key, credential, taints, run flags, machine renewal token).

Schema quirks: only a `firebase` oauth2 security scheme is declared, `guardian-token` is referenced without being declared, and most authenticated routes carry no `security` field. Decide what is authenticated from each route's description, not from `security`.

**Never call** anything else, including `/`, `/health`, `/genesis*`, `/ghosts/realms*`, `/ghosts/me*`, `/auth*`, `/orgs*`, `/guardians*`, `/anchor/release*`, `/billing*` and `/users*`. (`GET /anchor/release` serves a shelf-shaped manifest with `pin` and per-binary `url`. It is not conflux's binary source.)

## Probe node

A single live node from the freshly built image, used in step 3 (pin and join proof, the one renewal), for the step 5 baseline (a fresh probe after `make image` if step 4 changed anything), and for the step 7 after numbers.

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

Record each number before (step 5) and after (step 7):

- **Artifact sizes:** `ls -l dist/conflux-*` (bytes, per target).
- **Extraction:** after `make build`, run `D=$(mktemp -d "$S/x.XXXX"); time CONFLUX_DIR=$D bin/conflux anchorctl help >/dev/null` (the first run in a fresh `$D` extracts into `$D/bin/<SetID>/`), then the same command again for the warm figure. Take the median of 5 fresh directories. Single runs are noisy.
- **`up` → ready, and renewal:** the `time` lines from the probe node. The enrolment round trip itself is the `time_total` of the step 2 `curl`.
- **`status` latency**, measured inside the container so `docker exec` overhead is excluded:
  `docker exec cfx-probe sh -c 'for i in $(seq 10); do s=$(date +%s%N); conflux status >/dev/null; echo $(( ($(date +%s%N)-s)/1000000 ))ms; done'`
- **Goroutines and allocations:** `go test -run '^$' -bench . -benchmem -count 5 ./internal/daemon/ ./internal/libexec/`. Benchmarks for the supervisor, renewal and link-watcher paths are added if missing, using `b.ReportAllocs()` and a goroutine delta via `runtime.NumGoroutine()` reported with `b.ReportMetric`. Compare runs with `benchstat` if installed.
- **Suite durations:** `time make test`, `time make race`, and, after `make image`, `time IMAGE=conflux-systemd-test ./test/integration.sh`.

## Tools

```bash
go install honnef.co/go/tools/cmd/staticcheck@latest
go install golang.org/x/vuln/cmd/govulncheck@latest
go install github.com/rhysd/actionlint/cmd/actionlint@latest
curl -fsS 'https://go.dev/dl/?mode=json' | python3 -c 'import json,sys; print(json.load(sys.stdin)[0]["version"])'   # latest stable Go
```

Also needed:
- `shellcheck` (distro package), for actionlint and `shellcheck scripts/*.sh test/*.sh`
- Docker with `/dev/net/tun` and cgroups, for the container suites
- `gh`, authenticated, for action release tags and `GENESIS_PIN`
