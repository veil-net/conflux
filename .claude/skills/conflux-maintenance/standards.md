# Conflux maintenance: standards

What the audit aims for, the rules it works under, and what must hold at the end of every run. The Project Context and Rules in SKILL.md override anything here.

## Audit goals

1. **Issues:** bugs, race conditions, and resource leaks (child processes, goroutines, file descriptors, locks, extracted files). Incorrect assumptions, especially stale assumptions about anchor behaviour, flags, or the live API. Platform-specific breakage.
2. **Optimization:** fewer goroutines, copies, allocations and syscalls; faster extraction, bring-up and status; smaller artifacts where that doesn't change what is embedded.
3. **Consolidation:** remove
   - unnecessary mechanisms, gates and guards
   - single-use helpers not tied to a public API
   - handling for cases that can't occur given this design or the current anchor and API
   - duplicated logic that anchor already enforces, except where conflux must pre-validate to give a clear error
4. **Docs and comments:** accurate to the implementation, the current anchor, and the live API.

## Audit areas

Work through them in this order:

1. CLI, and the pass-through and collision rules
2. `up`, `proxy`, `enrol`, `renew`, `status` and the lifecycle commands (`start`, `down`, `install`, `uninstall`, `serve`)
3. Config, atomic writes, and secrets
4. The enrolment and renewal client
5. The daemon supervisor: bring-up, readiness, renewal, link watcher
6. anchorctl argv and parsers
7. libexec extraction
8. The embedded binary set and the shelf fetcher
9. The boot service, per OS
10. Platform code: Windows ownership and DACLs, wintun, the BSDs, macOS
11. flock, privcheck, paths
12. UI and reporter
13. Tests and harness
14. CI/CD
15. Release

## Performance rules

- **Performance over resource usage.** Never add caps, limits or throttling that trade performance for resources, and remove existing ones that do. The `dist` size gate is a correctness check, not a resource cap, and stays.
- Copy and GC reductions are wanted only with no lifecycle errors or races. Any change touching goroutine lifecycle, child-process supervision, renewal timing or the link watcher must pass its affected tests under `-race`, plus `make integration`, with no leaked processes or goroutines at teardown.
- Anchor's own tuning (stream vs datagram and so on) belongs to anchor. Conflux passes it through faithfully and never overrides it.

## CI/CD rules

- **CI verifies that the code builds and runs.** That means:
  - builds: `cross` for every target, including a per-target vet compile of test files; `dist` with the size gate; platform builds on macOS and Windows
  - tests: `test`, `race`, the macOS and Windows suites, `service-test`, and `integration` against the live API
  - the release pipeline
- **Utility checks run locally, not in CI.** gofmt, staticcheck, tidycheck, govulncheck, docs and link checks, commit checks and the like leave CI and run in steps 4 and 7 (see reference.md § Local checks).
- **Faster, with the same verification power.** Never drop, skip or weaken a build or test that verifies the code. Speed comes from:
  - caching: the Go module and build cache, fetched anchor binaries keyed by shelf digest, Docker layers
  - fetching or building anchor binaries once and sharing them across jobs as artifacts
  - fetching only the binaries a platform job needs
  - building, vetting and fetching every target at once, and running independent suites side by side
  - removing duplicated builds and steps
  - reusing the `dist` artifact for the image jobs
  - cancelling superseded runs
  - job ordering suited to the runners: self-hosted `veilnet-dev` for the Linux Go suite, hosted runners for the container suites (they need the live realm's bootstrap node over UDP) and for macOS and Windows
- Keep the fork guard on every self-hosted job. The only credential stays the read-only anchor GitHub App. Release stays gated to `version3`.
- **Release only releases.** The user merges to `version3` only when CI is all green, so `release.yml` doesn't re-verify anything. On a merge it fetches the pinned binaries, runs `make dist` (the size gate comes with it), attests, and publishes at the `VERSION` tag. Jobs or steps that repeat CI's checks are removed; the `version3` gate is the one guard it keeps.
- CI can't run without pushing. Validate workflow and composite-action changes locally (`actionlint`; `act` if available), and name in the summary the CI changes that couldn't be verified locally.

## Threat model

- Anchor nodes are assumed to run genuine, unmodified anchor binaries. Don't raise overlay findings that hold only against a modified peer. The protocol, handshake and credential chain are anchor's threat model, not conflux's.
- `api.veilnet.com.au` is assumed to be the genuine traveller deployment. Transport handling is still in scope: TLS only, no plain-http base, no cross-host renewal URLs, bounded response sizes, and malformed responses.
- Conflux's own surface is in scope:
  - the executable it writes to disk and runs (a dropper shape)
  - the private key in a file
  - local privilege boundaries: other local users, file modes, DACLs, service definitions, PATH, and the extraction location
  - responses from the shelf fetcher: redirects, bad digests
  - CI running on a persistent self-hosted machine in a public repository

## Design references

Anchor is the reference for overlay behaviour, and the live API at `api.veilnet.com.au` for the enrolment and renewal contracts. Conflux doesn't reimplement or second-guess anchor logic, except to pre-validate input for clear errors, and then it matches anchor exactly. Where conflux's docs describe anchor or the API differently from how they currently behave, fix conflux's docs. Where anchor's own docs and code disagree, or the live schema and live behaviour disagree, flag it rather than guessing.

## Test rules

- Unit tests, argv goldens, `httptest` API fixtures, `test/*.sh`, and the `test/systemd` image are code under maintenance, held to the same standard as production code.
- Assertions or fixtures that encode outdated behaviour, including outdated anchor behaviour or API contracts, are updated in the same change.
- Tests that need the real anchor binaries skip without them. Confirm they actually ran against the freshly built binaries (no `--- SKIP` in `go test -v` output for `./anchor/ ./internal/libexec/ ./internal/anchorctl/ ./internal/cli/`). A skip caused by missing binaries or a missing tool (staticcheck, govulncheck, shellcheck, Docker) counts as a failure.
- Code behind a build tag is checked where the tag is true: `make cross` vets and `make lint` runs staticcheck per target OS. Windows-only tests (`internal/paths/acl_windows_test.go`) run only in CI's `platforms` job.
- Confirm `service-test` and `integration` really booted systemd containers, and that `integration` enrolled against the live API.
- Per area, run only the affected tests. Run the full suite once at the end.

## Invariants (verify every run)

**Embedded binaries**
- Every `TARGETS` entry embeds exactly its own pinned `anchord` and lockdown `anchorctl`, built from the synced anchor commit and pinned to the genesis `api.veilnet.com.au` issues under.
- `make dist` passes the size gate for every target.
- A placeholder build reports no anchor pair.
- No `anchoradmin*` file exists anywhere in conflux.
- No binary is tracked by git.

**anchorctl**
- Every command and flag conflux emits exists in current anchor with the same meaning (argv goldens plus the flag cross-check against the real binary).
- Every parsed output and metric name matches current anchor.

**Config rules** (a proxy needs userspace; a subnet and a served exit need an interface, an IPv4 and `useExit` do not; no port or explicit LAN discovery beside an uplink; taint, IPv4, subnet, bootstrap-entry and proxy-spec parsing) accept and refuse exactly what current anchor does, plus conflux's one rule of its own: a machine always carries a taint.

**Manifest decoding** handles anchor's current format, refuses a realm manifest and a future version, and survives renewal losslessly.

**Live API**
- `config.DefaultAPIBaseURL` is `https://api.veilnet.com.au`.
- An anonymous enrolment and a renewal against it succeed and match `internal/enrol`'s expectations (payload, window, error handling).
- The client's `httptest` contract tests mirror the live schema.
- The guardian flows match the live schema.

**The manifest**
- It is written before any other processing, decoding included.
- It is `0600` from creation, in a `0700` directory (a replaced DACL on Windows).
- It never appears in argv, `ps`, or logs.

**Writes and state**
- Config and state writes are atomic, and every writer of the manifest or state holds the lock.
- A re-run of `up` or `proxy` never changes an existing machine's address or identity, and the IPv4 question is asked once, a declined answer included.
- `up` and `proxy` replace each other cleanly.
- `uninstall` leaves nothing behind.

**Pass-through**
- Unknown commands pass through to `anchorctl` unchanged.
- No conflux command shadows an `anchorctl` command unintentionally.

**Overlay join:** two nodes with one taint, enrolled against the live API, reach each other over the overlay (the first stage of `make integration`). Nothing may depend on a third peer; the third node exists only as the LAN-discovery control.

**This skill:** every command, path, script, URL and file name it references exists and works as described at the end of the run.
