---
name: conflux-maintenance
description: Full audit, optimization and consolidation pass over the whole conflux repo (code, tests, scripts, docs, CI/CD and this skill), brought in line with the current anchor checkout and the live traveller API at https://api.veilnet.com.au, with the embedded anchor binaries rebuilt from anchor's pinned `make release`. Use when asked to run maintenance on conflux; to audit, optimize, clean up or consolidate conflux; to sync or align conflux with anchor, anchorctl, or the traveller/enrolment API; to rebuild, refresh or re-embed the anchor binaries (anchord, anchorctl, anchor/bin, make anchor-bins); or when /conflux-maintenance is invoked.
---

# Conflux maintenance

A run starts from a freshly pulled `version3`, works on a new branch, and ends with that branch merged into `version3` through a PR whose CI is green, plus a summary message. Supporting files:

- [reference.md](reference.md): repo map, Make targets, binary pipeline, harness, CI/CD, anchor surface map, anchor's release build, live API contract, baseline commands, tools.
- [standards.md](standards.md): audit goals, performance, CI/CD and test rules, threat model, design references, audit areas, invariants.

## Project context (authoritative; changes only on the user's explicit instruction)

`conflux` puts one machine on a VeilNet overlay with a single command. It is a thin CLI over anchor: it embeds `anchord` and `anchorctl`, extracts and drives them, and adds only enrolment, credential renewal, a configuration file, and a boot service.

- **Pass-through:** everything `anchorctl` can do, conflux can do. Any command conflux doesn't recognise goes to `anchorctl` unchanged. Conflux commands never shadow an `anchorctl` command unintentionally.
- **Embedded binaries:** exactly one pinned, garbled anchor pair (`anchord` + lockdown `anchorctl`) per build, selected by the build-tagged `anchor/bin_GOOS_GOARCH.go` files, each naming its two files explicitly. The binaries are not in git; `anchor/bin/` is populated by `make anchor-bins`. `anchoradmin` is never embedded, copied, or shipped. A placeholder build compiles, reports it carries no anchor pair, and is refused by the `dist` size gate.
- **Targets:** exactly the Makefile's `TARGETS` (linux amd64/arm64, darwin arm64, windows amd64/arm64, freebsd amd64, openbsd amd64). `anchor-bins.sh` agrees with them.
- **Two modes, mutually exclusive:** `conflux up` is TUN mode (host interface `anchor0`, exits via `--serve-exit`/`--use-exit`, subnets). `conflux proxy` is userspace reverse-proxy mode (no interface, no privilege; specs `OVERLAYPORT[/NETWORK]=BACKEND`, backend dialled fresh per connection). Running either replaces the other. Exits are passed explicitly, never taken from the manifest.
- **Uplink:** `--uplink` picks the medium (e.g. a serial line) independently of the mode.
- **Addresses:** IPv6 is derived from identity. IPv4 is asked once; a re-run never changes a machine's address.
- **Taints:** always generated or given. Machines sharing a taint reach each other; others have no address for them.
- **Two issuers:**
  - Public alpha realm, served by traveller at `https://api.veilnet.com.au` (conflux's default API): anonymous stateless enrolment (`POST /ghosts/alpha`), unauthenticated renewal, seven-day window, no revocation.
  - Self-hosted guardian: operator-commissioned manifest installed by `conflux enrol --manifest FILE --api URL`, bearer-authenticated renewal against that guardian's own API, revocation by refusing to renew.
  - Renewal happens at two thirds of the observed window and never changes identity.
- **Secrets on disk:** the manifest is the identity. It is written before anything else is done with an enrolment response, `0600` with the mode set on the descriptor, in a `0700` directory (a replaced DACL on Windows). Never in argv (stdin to `anchorctl start -manifest -`), never in a log (redacting `String`/`GoString`). Config writes are atomic.
- **Boot service:** systemd, launchd, rc, or a Windows service. `down` and `start` leave it registered; `uninstall` leaves nothing behind.
- **Public repository:** conflux is public, anchor is private. Nothing from anchor's source, no token, no private material is ever committed. CI refuses fork PRs on self-hosted runners.
- **Anchor relationship:** anchor is the source of truth for `anchorctl` commands and flags, daemon config and mode rules, manifest/credential format, taint and address rules, proxy spec rules, uplink rules, metrics names, release names, and the `shelf` release format. Conflux consumes it through the embedded binaries, `internal/anchorctl` (argv builders, output and metrics parsers, argv goldens, flag cross-check), `internal/config` (rules matching anchor's), `internal/enrol` (manifest decoding), `internal/shelf` and `anchor-fetch`, `anchor-bins.sh`, and the CI actions.
- **Traveller relationship:** traveller is live in production at `https://api.veilnet.com.au`; that deployment is the source of truth for the enrolment, renewal, and guardian manifest/bearer HTTP contracts. The live OpenAPI schema (served at `/docs`) plus real calls to the anonymous alpha routes are the reference. No traveller checkout is needed.

This context is authoritative. Docs describe the design but may be wrong: where code or docs disagree with it, fix them to match. If the right answer is unclear, flag it in the summary.

## Rules (fixed; change only on the user's explicit instruction)

1. Don't read commit history in any repo. Audit the code as it stands. Reading anchor's current tree and the live schema and diffing them against conflux is required and is not history.
2. Scope: the whole conflux repo, including CI/CD and `.claude/skills/conflux-maintenance/`. `anchor` is a read-only reference: never modify, commit to, or push it. Running its build (`make release`, `make dist`) is allowed, but only build output may appear, and its tracked files must be unchanged afterwards. Traveller is referenced only through `https://api.veilnet.com.au`; don't read or change the traveller repo or any other sibling project.
3. No backward-compatibility shims, deprecation paths, or version bumps unless told. Breaking changes (CLI flags, config file and state layout, service definitions, output formats) are allowed and go in the summary. Never keep support for an older anchor or API contract.
4. Don't fix defects in dependencies unless critical (workflow step 4).
5. Do every optimization that can be done, however small, within the performance rules ([standards.md](standards.md)).
6. Never hand-edit generated files or golden fixtures. Regenerate (`make golden`) and review the diff.
7. Docs and comments (`README.md`, `docs/`) change in the same change as the code they describe. No end-of-run docs sweep.
8. No audit or maintenance report files.
9. WireGuard is forbidden anywhere in the project.
10. Production API: never mint a genesis, a pin, or guardian credentials. Against `api.veilnet.com.au` use only the anonymous alpha enrolment and renewal routes, with random taints, and only as much as verification needs (step 2 checks, the baseline, `make integration`). Never call authenticated, admin, or billing routes; never load-test production.
11. `anchoradmin` never enters conflux: not in `anchor/bin/`, not embedded, not in a release artifact.
12. This repository is public. Never commit anchor source, tokens, keys, manifests (including ones enrolled during the run), or any private material. Never weaken the fork guard on self-hosted jobs.
13. The skill maintains itself to the same standard as the code: accurate, concise, no dead steps, no report files. The Project Context and these Rules change only when the user explicitly says so.

## Workflow

**Plan mode:** change nothing (no checkout, pull, branch, build, enrolment, or edit). Read conflux, anchor's current tree as it is, and the live schema, then produce the plan for steps 2–9.

Shell variables used below (set them in each shell):

```bash
A=${ANCHOR_SRC:-../anchor}        # the anchor checkout
API=https://api.veilnet.com.au
S=<session scratchpad dir>        # outside both repos; holds the pin, schema, worktree, enrolment output
T=cfx-maint-$(head -c6 /dev/urandom | od -An -tx1 | tr -d ' \n')   # random taint for live nodes
```

### 1. Sync

1. **Conflux.** `git status --porcelain` must be empty; if not, stop and ask (never stash or discard someone's work). Then:
   `git fetch origin && git switch version3 && git pull --ff-only origin version3 && git switch -c maintenance/$(date +%F)` (add `-2`, `-3` if the name is taken). Don't use `main`; it exists on the remote but is not the development branch.
2. **Anchor.** No `$A/.git` means stop and say so. Record `git -C "$A" status --porcelain` (compared again at the end) and `git -C "$A" rev-parse origin/main` (the synced-from commit). Then `git -C "$A" fetch origin main`.
   - Clean and on `main`: `git -C "$A" pull --ff-only origin main`, and set `AS=$A`.
   - Dirty or on another branch (someone's work in progress): leave that checkout alone. Build from a detached worktree with `git -C "$A" worktree add --detach "$S/anchor" origin/main`, and set `AS=$S/anchor`.
   - Record `git -C "$AS" rev-parse HEAD` as the synced-to commit.
3. **Live API.** Fetch the schema: `curl -fsS --max-time 15 "$API/docs/swagger-ui-init.js" -o "$S/swagger-ui-init.js"`, then extract `swaggerDoc` into `$S/openapi.json` (snippet in [reference.md § Live API](reference.md#live-traveller-api)). If the API is unreachable, note it, skip the live comparison and every live-API test (`make integration`, the probe node, live baseline numbers), and flag it. Never point conflux at another host to work around it.

### 2. Sync with anchor and the live API (before dependencies)

1. Diff anchor's current surface against what conflux uses, using the map in [reference.md § Anchor surface](reference.md#anchor-surface-map): anchorctl commands, subcommands and flags; output formats and metric names the parsers read; daemon config, mode and exit rules; manifest/credential format and version; taint, IPv4 prefix, proxy spec and uplink rules; `make release`/`make dist` output names and targets; the shelf layout and digest manifest; the Go version.
2. Diff the live schema's alpha enrolment, alpha renewal and guardian manifest/bearer contracts (routes, methods, payloads, status codes, error shapes, window lengths) against `internal/enrol`, its `httptest` fixtures, `config.DefaultAPIBaseURL`, and `docs/credentials.md`, `docs/config.md`, `docs/commands.md`.
3. Confirm the alpha flow for real with **one** anonymous enrolment. The checks are in [reference.md § Live API](reference.md#live-traveller-api). The enrolment response is a live identity: keep it only under `$S` and delete it at the end. The one renewal needs an AnchorID, which only a started anchor reports, so it happens as `conflux renew` on the step 3 probe node.
4. Adapt code, tests, `httptest` fixtures, scripts, CI and docs to match. Adopt breaking changes directly. Regenerate argv goldens with `make golden`, then review `git diff internal/anchorctl/testdata/` so every change is intended.
5. If anchor or the live API looks wrong, or contradicts the context above, don't work around it in conflux. Flag it.

The checks that need the real binaries (flag cross-check, shadowing, collisions) run after step 3.

### 3. Build and copy the binaries from anchor

1. **Pin.** `make release` reads `$(GENESIS_DIR)/genesis.pin` (default `genesis/`) and **mints a brand-new genesis if that file is missing**, so it must never run without the pin in place. The production pin comes from `$A/genesis/genesis.pin` (read only that file, never `genesis.key`) or anchor's public repository variable (`gh variable get GENESIS_PIN --repo veil-net/anchor`). It must start with `realm`, and the two must match if both exist. With neither available, go to the fallback. Never mint or invent a pin.
   ```bash
   mkdir -p "$S/genesis" && printf '%s' "$PIN" > "$S/genesis/genesis.pin"
   make -C "$AS" release GENESIS_DIR="$S/genesis"
   test ! -e "$S/genesis/genesis.key"   # present = the mint rule fired: discard $AS/release, stop, flag
   ```
   Never substitute anchor's unpinned `make dist` for a shippable run. If the build fails, stop and report it. Never copy partial output, and never patch anchor.
2. **Copy.** Run `make anchor-bins ANCHOR_SRC="$AS"`. It must end with `14/14 copied from …/release (release)`.
3. **Verify.**
   ```bash
   ls anchor/bin                                                    # exactly anchord-/anchorctl-<os>-<arch>[.exe] for each TARGETS entry
   ! ls anchor/bin/anchoradmin* 2>/dev/null                         # none
   "$AS/scripts/client-is-locked.sh" anchor/bin "$AS/release"       # anchorctl is the lockdown build
   for f in anchor/bin/*; do cmp "$f" "$AS/release/${f##*/}" || echo "DIFFERS $f"; done   # from the synced build
   go test -v -count=1 ./anchor/ ./internal/libexec/ ./internal/anchorctl/ ./internal/cli/ 2>&1 | grep -B1 -- '--- SKIP'   # must print nothing
   make image                                                       # runs `dist` (size gate, every target), then builds the test image
   ```
   Then bring up the probe node ([reference.md § Probe node](reference.md#probe-node)): `conflux up` against the live realm with `--taint "$T"`, then `conflux status`, then the one `conflux renew`. A pinned `anchord` refuses at start any realm whose root isn't its pin, so a successful `up` proves the pin. The join between peers is proven by CI's `integration` job on the PR (step 9).
4. **Fallback.** Use this only when the pin or `make release` is unavailable. Fetch the pinned shelf into scratch first, so `anchor/bin/` stays untouched unless the shelf qualifies:
   `DEST="$S/shelf" make anchor-bins FETCH=1 ANCHOR_SRC=/nonexistent` (`ANCHOR_RELEASE_TOKEN` in the environment, never argv). Accept it only if the `commit:` line equals the synced-to commit. Then copy the 14 files into `anchor/bin/` and run the same verification, except: `"$AS/scripts/client-is-locked.sh" anchor/bin` (no admin directory to compare against), and no `cmp`, since the fetcher already checked every digest. If the shelf is at a different commit, stop the binary step, leave `anchor/bin/` untouched, and flag it. Never test or ship against placeholders or stale binaries without saying so.
5. `for p in anchor/bin/x dist/x test/systemd/conflux; do git check-ignore -q "$p" || echo "NOT IGNORED $p"; done` must print nothing (`-q` takes one path). Binaries are never committed.

### 4. Update dependencies

1. Update the `go` line to the latest stable Go (`go mod edit -go=<version>`, never older than anchor's `go.mod`), then run `go get -u ./... && go mod tidy`. Update every `uses:` in `.github/` to its latest stable release (`gh api repos/<owner>/<repo>/releases/latest --jq .tag_name`). Install the latest `staticcheck` and `govulncheck` ([reference.md § Tools](reference.md#tools)).
2. `make build cross`, then `make vulncheck`. If the newest version of a dependency fails, revert it to the most recent stable version that passes, and repeat until clean or until only findings with no passing stable version remain. Flag those.
3. If an update breaks the build or tests, adapt conflux to the new API. Don't patch or work around defects inside dependencies unless critical (security, crash, or data corruption on a main path).

### 5. Baseline

Record the before numbers with the commands in [reference.md § Baseline](reference.md#baseline): `dist` sizes per target, extraction time, `conflux up` → ready overlay against the live API, enrolment and renewal round-trips, `conflux status` latency, goroutines and allocations in the supervisor, renewal and link-watcher paths, and the CI suite durations (taken from CI, not run locally). The benchmarks are `internal/daemon/bench_test.go`; add one first for any of those paths that lacks it.

### 6. Audit and fix, area by area

Work through the areas in [standards.md § Audit areas](standards.md#audit-areas) against the audit goals, performance rules, threat model, CI/CD rules and test rules in the same file. For each area, fix issues and apply optimizations and consolidation. Update docs, comments and affected tests in the same change, then run only the affected tests (`go test [-race] ./internal/<pkg>/…`). A change touching goroutine lifecycle, child-process supervision, renewal timing or the link watcher must pass its tests under `-race` now and CI's `integration` on the PR, with no leaked processes or goroutines.

### 7. Final local checks

Nothing CI runs is run locally here: `test`, `race`, `cross`, `dist`, `service-test`, `integration` and the macOS and Windows suites are verified by the PR in step 9. Locally, before pushing, only what CI does not run:

```bash
make fmtcheck lint tidycheck vulncheck docscheck       # the utility checks (see reference.md § Local checks)
actionlint && shellcheck scripts/*.sh test/*.sh        # workflows, the actions they use, and the scripts
```

plus the affected-package tests of whatever was last touched, and anything no CI job runs: the `make golden` diff review, `docker run bash:3.2` over `anchor-bins.sh` if it changed, and the after numbers (sizes, extraction, benchmarks, the probe node). A check that prints `not installed; skipping` counts as a failure.

### 8. Maintain this skill

Check every file in `.claude/skills/conflux-maintenance/` against conflux, anchor and the live API as they now stand: Make targets, scripts and paths, the target list and binary names, CI job and action names, the anchor surface map and API routes, the invariants and audit areas, and the trigger description. Fix whatever is stale, missing or dead, including what this run changed. Keep SKILL.md concise. Don't edit the Project Context or Rules; propose changes to them in the summary. Commit skill updates on the same branch.

### 9. Finish

Commit on the branch, push it, and open a PR with `--base version3`. Then watch its CI (`gh pr checks <n> --watch`) until every check is green:

- A failure is read from the job's log (`gh run view <run> --log-failed`), fixed on the branch, re-checked locally as in step 7 (the affected tests plus the utility checks), pushed, and watched again. Never weaken a test, a gate or the fork guard to get green.
- A run that failed for the Actions budget, a runner outage or an unreachable API rather than the code is not a failure to fix: say so and do not merge.
- With every check green, confirm from the `integration` log that `service-test` and `integration` booted systemd containers and that `integration` enrolled against the live API, then `gh pr merge <n> --merge`. A merge to `version3` publishes a release (`release.yml`); don't bump `VERSION` or trigger one by hand.

Clean up: `docker rm -f cfx-probe`, `git -C "$A" worktree remove --force "$S/anchor"` if one was made, and delete the enrolment output under `$S`. `git -C "$A" status --porcelain` must match the step 1 snapshot. Don't write a report file. End with a brief summary covering:

- the anchor commit synced from and to, and what changed as a result
- live API contract changes found, and what changed as a result
- binaries built and copied, from which source (release or shelf), and anything skipped, with the reason
- before/after numbers, including artifact sizes
- the PR, what its CI caught and how it was fixed, and the merge
- CI/CD changes, and any (such as `release.yml`) a PR run cannot exercise
- breaking changes (CLI, config file, state layout, service)
- dependencies held back for vulnerabilities, and non-critical dependency defects found
- anchor and live API issues flagged, including whether the API was reachable
- guardian flows that couldn't be exercised live
- changes to this skill, and proposed changes to its Project Context or Rules
- anything else that was unclear
