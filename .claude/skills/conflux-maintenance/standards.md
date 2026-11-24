# Conflux maintenance: standards

What the audit aims for, the rules it works under, and what must hold at the end of every run. The Project Context and Rules in SKILL.md override anything here.

## Audit goals

1. **Issues:** bugs, race conditions, and resource leaks (child processes, goroutines, file descriptors, locks, extracted files). Incorrect assumptions, especially stale assumptions about anchor behaviour, flags, or the live API. Platform-specific breakage. Code that departs from the Project Context's design. Performance regressions: an extraction, bring-up, status, enrolment, renewal or watcher time, or an artifact size, worse than step 5's figures or the benchmarks of the code a change touches.
2. **Optimization:** fewer goroutines, copies, allocations and syscalls; faster extraction, bring-up and status; smaller artifacts where that doesn't change what is embedded.
3. **Consolidation:** one mechanism for each job, and none the design does not need. Consolidation unifies and removes; it does not change behaviour. A mechanism is redundant when removing it changes no outcome on any path, because something else already has its effect there. The kinds to look for:
   - unnecessary mechanisms, gates and guards, and single-use helpers not tied to a public API
   - double guards: a check, lock, retry or validation repeated where another already holds on every path to it; a caller's check that saves work first is an early exit, not a double
   - subsumed mechanisms: one whose effect another always has first, such as a timeout an enclosing one always beats, or a cleanup a teardown already does
   - duplicated state: two sources of truth for one fact
   - repeated code: the same logic written out in more than one place, a test's scaffolding copied into another test among it, merged into one that every place uses
   - a mechanism reimplemented instead of reused: a second retry loop, parser, atomic write or supervisor where the standard library, an existing package, or one shared by both callers would do
   - handling for cases that can't occur given this design or the current anchor and API
   - duplicated logic that anchor already enforces, except where conflux must pre-validate to give a clear error

   Not redundant, however alike they look: copies that serve different purposes, such as each platform's boot service (systemd, launchd, rc, the SCM); a check repeated under a lock or after a wait, which sees state that may have changed since the first; a check that also orders, locks or counts, which does more than guard; validation of what comes from outside the process (the API, anchor's output, disk, the host); and a backstop that something can still reach. Redundancy is proven before anything goes, never argued alone, by whoever removes it, path by path, error, exit and restart paths included, through every caller in every package, test and build-tagged file: a duplicated mechanism goes only once the one kept is shown to act on every path the other did, by a mechanical equivalence (the same calls in the same order, with the same errors) or a temporary count through the area's tests; duplicated state, only once an assertion that the two agree has held through the area's tests under `-race`. What cannot be proven stays. Two copies are diffed before they are merged: a constant, an error, a lock or an edge case that differs is a behaviour change. The outcomes stay the same, and the area's tests pass unchanged, except those of a removed mechanism's own internals; one that has to change marks a design question, as does merging copies that differ where one behaviour has to be chosen.

   Every mechanism a run adds, for a fix, a design question's answer or a CI failure, meets this goal before it lands: it does a job nothing else in the tree does, or whatever did that job goes in the same change. A design question that would add one names any mechanism with the same purpose and says what becomes of it.
4. **Docs and comments:** accurate to the implementation, the current anchor, and the live API, and describing the code rather than its history.
5. **Tests:** held to the test rules below, and to the same standard as production code.

## Audit areas

Work through them in this order:

1. CLI, and the pass-through and collision rules
2. `up`, `proxy`, `enrol`, `renew`, `status`, `update` and the lifecycle commands (`start`, `down`, `install`, `uninstall`, `serve`)
3. Config, atomic writes, and secrets
4. The enrolment and renewal client
5. The daemon supervisor: bring-up, readiness, renewal, the watcher (a lost anchor, an ended link)
6. anchorctl argv and parsers
7. libexec extraction
8. The embedded binary set and the fetcher for anchor's release
9. The boot service, per OS
10. Platform code: Windows ownership and DACLs, wintun, the BSDs, macOS
11. flock, privcheck, paths
12. UI and reporter
13. Tests and harness
14. CI/CD
15. Release, and the install scripts

## Performance rules

- **Performance over resource usage.** Never add caps, limits or throttling that trade performance for resources, and remove existing ones that do. The `dist` size gate is a correctness check, not a resource cap, and stays.
- Copy and GC reductions are wanted only with no lifecycle errors or races. Any change touching goroutine lifecycle, child-process supervision, renewal timing or the watcher must pass its affected tests under `-race`, plus CI's `integration` on the PR, with no leaked processes or goroutines at teardown.
- Anchor's own tuning (stream vs datagram and so on) belongs to anchor. Conflux passes it through faithfully and never overrides it.

## CI/CD rules

- **CI verifies that the code builds and runs.** That means:
  - builds: `cross` for every target, including a per-target vet compile of test files; `dist` with the size gate; platform builds on macOS, Windows and Linux arm64, as a release builds them, and `buildcheck` on Linux and each of those (the stamped digests, FIPS 140-3 mode), FreeBSD's build held to its FIPS half in the `bsd` VM
  - tests: `test`, `race`, the macOS, Windows and Linux arm64 suites, each held to the tests the source declares for its platform (`scripts/tests-ran.sh`), `service-test`, the launchd and SCM lifecycle (`test/service-host.sh`), rc on FreeBSD and OpenBSD (`test/service-bsd.sh`), the install scripts against the published `latest` (on the BSDs with the base system's own tools), and `integration` against the live API
  - the release pipeline
- **Utility checks run locally before every push, never in CI; CI does the code testing, and only CI does it.** gofmt, staticcheck, tidycheck, govulncheck, docs and link checks, actionlint, shellcheck, commit checks and the like stay out of CI and run in steps 4 and 7 and before each fix is pushed (see reference.md § Local checks). The suites CI runs are not repeated locally: the PR's run is the verification.
- **Faster, with the same verification power.** Never drop, skip or weaken a build or test that verifies the code. Speed comes from:
  - caching: the Go module and build cache, fetched anchor binaries keyed by the release manifest's digest, Docker layers
  - fetching or building anchor binaries once and sharing them across jobs as artifacts
  - fetching only the binaries a platform job needs
  - building, vetting and fetching every target at once, and running independent suites side by side
  - removing duplicated builds and steps
  - reusing the `dist` artifact for the image jobs
  - cancelling superseded runs
  - job ordering suited to the runners: self-hosted `veilnet-dev` for the Linux Go suite, hosted runners for the container suites (they need the live realm's bootstrap node over UDP) and for macOS and Windows
- Keep the fork guard on every self-hosted job. The only credential stays the read-only anchor GitHub App. Release stays gated to `version3` and `dev`, and `branch-flow` to a PR into `version3` from `dev` alone and into `dev` holding `version3`, run on `pull_request_target` so the check is the base branch's own, reading the PR as data and running nothing of it.
- Every external action is pinned to its release's commit, with the tag in a comment, and bumped by moving both. No checkout persists its token.
- **Release only releases.** A PR merges into `dev`, and the user merges `dev` into `version3`, only when CI is all green, so `release.yml` doesn't re-verify anything. On a PR's merge, and never on a direct push, it builds with the Go `go.mod` names downloaded from go.dev and held to the SHA-256 go.dev publishes (`scripts/go-toolchain.sh`), not the runner's tool cache, from empty `GOCACHE` and `GOMODCACHE` of its own run, the modules downloaded and verified (`go mod verify`) first, fetches the pinned binaries (anchor's `dev-latest` on `dev`, its `latest` on `version3`), runs `make dist` (the size gate comes with it), attests, and publishes: on `dev` the pre-release `dev-latest`; on `version3` twice, at the `VERSION` tag and at `latest`, each deleted and released again, then the back-merge into `dev`. Jobs or steps that repeat CI's checks are removed; it keeps two guards, the merge gate and the `version3`/`dev` gate.
- Validate workflow and composite-action changes with `actionlint` (and `act` if available) before pushing; the PR's own run is what proves them. Name in the summary any change a PR run cannot exercise, such as `release.yml`.

## Threat model

- Anchor nodes are assumed to run genuine, unmodified anchor binaries. Don't raise overlay findings that hold only against a modified peer. The protocol, handshake and credential chain are anchor's threat model, not conflux's.
- `api.veilnet.com.au` and `api-dev.veilnet.com.au` are assumed to be the genuine traveller deployments. Transport handling is still in scope: TLS only, no plain-http base, no cross-host renewal URLs, bounded response sizes, and malformed responses.
- Conflux's own surface is in scope:
  - the executable it writes to disk and runs (a dropper shape)
  - the private key in a file
  - local privilege boundaries: other local users, file modes, DACLs, service definitions, PATH, and the extraction location
  - responses to the release fetcher: redirects, bad digests
  - CI running on a persistent self-hosted machine in a public repository

## Design references

Anchor is the reference for overlay behaviour, and the live API for the enrolment and renewal contracts: `api-dev.veilnet.com.au` for `dev`, `api.veilnet.com.au` for the release. Conflux doesn't reimplement or second-guess anchor logic, except to pre-validate input for clear errors, and then it matches anchor exactly. Where conflux's docs describe anchor or the API differently from how they currently behave, fix conflux's docs. Where anchor's own docs and code disagree, or the live schema and live behaviour disagree, flag it rather than guessing.

## Test rules

- Unit tests, argv goldens, `httptest` API fixtures, `test/*.sh`, and the `test/systemd` image are code under maintenance, held to the same standard as production code.
- Assertions or fixtures that encode outdated behaviour, including outdated anchor behaviour or API contracts, are updated in the same change.
- Tests that need the real anchor binaries skip without them, through `anchortest.Require` alone. CI's gates confirm they ran — the `linux` job fails on any `--- SKIP` and the `platforms` jobs on a skipped real-binary test, and every job that tests fails on a test the source declares for its platform that did not run, read from the source because a `TestMain` returning before `m.Run` hides its tests from `go test -list` as well — so they are not run locally to check. A local check skipped for a missing tool (staticcheck, govulncheck, shellcheck, Docker) counts as a failure.
- Code behind a build tag is checked where the tag is true: `make cross` vets and `make lint` runs staticcheck per target OS. Windows-only tests (every `*_windows_test.go` but `internal/daemon/tidy_windows_test.go`, which holds only the Windows half of the tidy tests' helpers: `internal/cli/service_windows_test.go`, `internal/cli/uninstall_windows_test.go`, `internal/config/untrusted_windows_test.go`, `internal/daemon/drop_windows_test.go`, `internal/daemon/proc_windows_test.go`, `internal/libexec/usage_windows_test.go`, `internal/paths/acl_windows_test.go`, `internal/paths/owner_windows_test.go`, `internal/paths/paths_windows_test.go`, `internal/wintun/wintun_windows_test.go`) run only in CI's `platforms` job; a change to one, or to those helpers, is vetted locally with `GOOS=windows go vet`.
- Confirm from the PR's `integration` job log that `service-test` and `integration` really booted systemd containers, and that `integration` enrolled against the live API.
- Per area, run only the affected tests locally. The full suites run once, in CI on the PR.

## Invariants (verify every run)

**Embedded binaries**
- Every `TARGETS` entry embeds exactly its own pinned `anchord` and lockdown `anchorctl`, built from the synced anchor commit and pinned to the genesis of the tree its branch is tested in: on `dev`, the one `api-dev.veilnet.com.au` issues under, as anchor's `dev-latest` is.
- `make dist` passes the size gate for every target.

**FIPS 140-3**
- Every target is built against the Go Cryptographic Module v1.26.0 (`GOFIPS140`, named once, in the Makefile, which CI's `setup` action and, in the BSD VM, `scripts/fips-check.sh` read) except OpenBSD's, built with it off; `make dist` holds each artifact to it, `make buildcheck` the build the `linux` job and each `platforms` leg runs, and `test/service-bsd.sh` FreeBSD's to the half that needs no Go, in a VM that has none, through the script `buildcheck` runs for it (`scripts/fips-check.sh`: the module named, `fips140: verified`, exit 70 with the mode off).
- Every cryptographic service conflux's own code uses is approved in module v1.0.0's Security Policy (CMVP #5247), used as it approves, with ML-DSA the one exception, as docs/security.md "FIPS 140-3 and CMVP" states. No SHA-1, MD5, DES, RC4 or DSA in conflux's code; a new use goes into that section's table in the same change.
- The tests run under `GODEBUG=fips140=only`, locally (`make test`) and in every CI job that tests.
- A build against the module run with `GODEBUG=fips140=off` refuses every command, exit 70.
- `internal/pki/approved_test.go` passes, every rule with its control: no x/crypto, MD5, SHA-1, DES, RC4, DSA or crypto/ecdh; no AES block or AES-CBC outside `internal/pki/pbes2.go`; no CTR, CFB, OFB or caller-nonce GCM; no RSA PKCS #1 v1.5 encryption, legacy PEM encryption, Ed25519ctx/ph or `WithoutEnforcement`.

**Certificates**
- `conflux cert` refuses every command where `fips140.Enabled()` is false, exit 70, before reading anything.
- ML-DSA keys are written seed-only; the both form is read only when its expanded half matches its seed; the expanded-only form is refused.
- An encrypted key is written PBKDF2-HMAC-SHA-256, 600,000 iterations, a 16-byte salt, AES-256-CBC, and only PBES2 with a SHA-2 PRF, a salt of 16 bytes or more and AES-CBC is read; every refusal names `reencrypt`'s pipe.
- A clear key is written 0600, never over an existing file without `--force`, never to a terminal; a passphrase comes from a file, an environment variable or the terminal, never a flag's value or stdin.
- A certificate never outlives its issuer, starts five minutes back, carries a random 128-bit serial and an RFC 7093 SKI; a request contributes its subject and names alone. No certificateHold. No SHA-1 or MD5 fingerprint.
- `verify` exits 3 for a chain that does not hold, a revoked certificate, a list out of date, or `--require-pq` on a classical chain; authentication is `pqc` only when the leaf key and every signature below the root are ML-DSA.
- The `show` goldens' fixtures are public material alone; no private key, encrypted or not, is committed.
- `cert ca`: a CA directory is 0700 and refused when another account owns it or (Unix) others may write it; one command at a time, by `.lock`; a certificate is recorded in `issued/` under its serial, never over another, before it is handed out; a CRL number is recorded before its list is written; no subscriber key is ever in the directory; the CA issues no CA; its keys are encrypted unless `--no-encrypt`.
- `cert p12` writes PBES2 bags (PBKDF2-HMAC-SHA-256, 600,000 iterations, 16-byte salts, AES-256-CBC) under a PBMAC1 MAC with its key length present, and reads only that profile, the MAC checked before any bag; PKCS#12's own KDF, SHA-1, 3DES, RC2 and keyBags are refused, naming the rewrite line.
- `cert probe` sends nothing but the handshake, checks the chain itself with `pki.Verify` (the one `InsecureSkipVerify` in conflux, and only so a failing chain is described), and exits 3 for a chain that does not verify or an unmet `--require-pq*`; X25519 is never offered alone. CI's `linux` job probes every host conflux reaches (both APIs, GitHub's API, web and asset hosts, wintun.net); a new host conflux talks to joins that list.
- A placeholder build reports no anchor pair.
- No `anchoradmin*` file exists anywhere in conflux.
- No binary is tracked by git.

**anchorctl**
- Every command and flag conflux emits exists in current anchor with the same meaning (argv goldens plus the flag cross-check against the real binary).
- Every parsed output and metric name matches current anchor.

**Config rules** (a proxy needs userspace; a subnet, an exit and an IPv4 work in either mode; the two exits are alternatives; no port or explicit LAN discovery beside an uplink, and there both are typed off so a manifest cannot supply them; taint, IPv4 (translation pool included), subnet (`*`, `SPEC@a+b` bindings to the machine's own taints, the list bounds), AnchorID, bootstrap-entry and proxy-spec parsing; the export block anchord reads at startup, read as protojson reads it, TLS material included) accept and refuse exactly what current anchor does, plus conflux's own rules: no list entry holds a comma, an uplink is a device rather than a descriptor, and on Linux every TUN name meets the rule anchor holds a routing TUN's to, since an order can make any TUN route. A file conflux refuses is refused before anchord starts on it, and is permanent. A persisted toggle is decided by whether its flag was written, and `--x=false` is read as `--no-x` (`typedFlags`), never as `--x`. `apiBaseUrl` is an absolute URL with a host name (a port alone is none), https, or plain http only under `CONFLUX_ALLOW_INSECURE_API=1` (`config.CheckAPIURL`, the one such check, which `conflux enrol` holds the API it installs and the renewal URL to before it writes anything, and which the enrolment client, `update` and the release fetcher use too).

**Taints**
- An alpha enrolment always asks for a taint, minted or given; conflux never asks for none.
- The credential's taints are the machine's for the life of its identity. Starts take them from the manifest, renewals restate them, and a configuration that disagrees is refused for good, naming the way out (a new identity); one whose list was emptied is given the grant back at the next start.
- An imported credential's taints are taken as granted, none included.
- Served subnets are the last set: conflux's at start, or after an explicit `--subnet`/`--no-subnet`, otherwise a member's Subnets order.

**Manifest decoding** handles anchor's current format, refuses a realm manifest and a future version, and survives renewal losslessly, a stale `severedAt` aside, which a renewal drops.

**Live API**
- `config.DefaultAPIBaseURL` is `https://api.veilnet.com.au`.
- An anonymous enrolment in a random taint and a renewal against it succeed and match `internal/enrol`'s expectations (request bodies, the taints echoed, window, bootstrap, error handling).
- The client's `httptest` contract tests mirror the live schema.
- The guardian flows match the live schema.

**The manifest**
- It is written before any other processing, decoding included.
- It is `0600` from creation, root's, in a directory only root can write (a replaced DACL on Windows).
- It never appears in argv, `ps`, or logs.

**Writes and state**
- Config and state writes are atomic, and every writer of the configuration, the manifest or the state holds the lock: `up`, `proxy`, `observe` and `conflux enrol` included.
- A new manifest, enrolled or imported, starts with no state carried over from the identity before it.
- A Unix root owned by another account is refused before anything in it changes; one of ours is `0700`, or a root's `0710` that lets anchord's account through.
- Everything conflux keeps is in the one `.conflux` of the platform; nothing a person sets moves it, and no older layout is read.
- At every start, once it holds `serve.lock` (a refused second supervisor changes nothing), the supervisor puts `.conflux` back to what conflux writes: whatever neither conflux nor anchor wrote is deleted (a write in progress spared), owners, modes and DACLs are repaired, `conflux.json` (read once, under the lock) and `state.json` are rewritten in conflux's form only where their bytes differ, a modified pair is extracted again, and the registration and the service copy are rewritten where they differ, a registration holding conflux's bytes under a widened mode given its mode back, and one another account owns written again (`config.WriteFileIfChanged`).
- A file conflux cannot take is refused for good and left as it is, never rewritten or replaced: a `conflux.json` that does not parse or that `Validate` refuses, a `state.json` that does not parse or a newer conflux wrote, an empty `manifest.b64` (`daemon.fileErr`: a read that failed is retried, anything else is permanent); and a lost `manifest.b64` while `state.json` names the anchor it was is refused for good, never enrolled over. `manifest.b64` is never rewritten.
- The boot service runs the copy of conflux in `.conflux`, never the file conflux was run from.
- A re-run of `up` or `proxy` never changes an existing machine's address or identity, and the IPv4 question is asked once, a declined answer included.
- `up` and `proxy` replace each other cleanly.
- `uninstall` leaves no trace of conflux: no definition or drop-in, no `wants` link, no launchd disabled-database entry, no SCM entry or event source, no `rc.conf` line, no OpenBSD login class, no `.conflux`, no account conflux made, no stale ephemeral root, no installed executable or its `/usr/bin` link or `Path` entry, no Wintun driver; what the service wrote to the system's log stays. A trace it could not take is said, never passed over: a file systemd's `Remove` could not remove, an `rc.conf` or `rc.conf.local` line FreeBSD's `sysrc -x` or OpenBSD's `rcctl disable` left (`rcEnabled`), each BSD's `Remove` asking after the command whether the line is still there and removing the rc script only once it is not, so the next `uninstall` can ask again (`rcctl get` exits 2 for a service with no script, which is no answer, never a no).

**Supervision**
- One supervisor per root: `serve` holds `serve.lock`, and a second is refused.
- anchord runs as root, or with a capability, only where the host or the configuration needs it, and keeps whatever losing would cost an operation or a function; `status` says why. Nothing is re-owned in a directory the account can write, a root anchord never works in one, and what the account wrote is read as untrusted (`flock.HeldUntrusted`, `config.ReadUntrusted`, `copyTree`), each refusing on Unix a file with a second name: `flock.HeldUntrusted` a lock with one, which a hard link to root's `serve.lock` under the socket lock's name would be. A lock asked for by its own name where the account writes nothing, an ephemeral run's `serve.lock` (`flock.Held`), is answered whatever the account linked to it.
- The anchord a dead supervisor left is stopped by the next one only when it is the recorded process (its executable, or anchor's socket lock where none is reported), and `uninstall` reaps it too. On Windows anchord dies with its own job, which its supervisor holds.
- A supervisor that exits 1 is restarted by systemd, launchd and the SCM; on the BSDs nothing does, and the docs say so. One that exits 78 or 70 is restarted by none: systemd names them in `RestartPreventExitStatus`, launchd is told 0 (`cli.launchdExit`), and the SCM a clean stop (`scmExit`).
- Readiness: the service manager is told the unit started once the anchor is up, or, beside an anchor that does not come up, even one refused for good, once the observer is (`signalStarted`), so a start timeout never takes the observer down; the marker waits for the anchor.
- The service's output is the system's log, and conflux writes no log file: the journal, syslog (FreeBSD's `daemon -S`, OpenBSD's rc.subr), the unified log through a `logger` child on macOS (a dead logger never takes the supervisor down), the Event Log under the `conflux` source on Windows.
- The service has the protections its platform normally gives a system service, and none that takes what the supervisor, anchord or anchor's host setup needs: systemd's `UMask=0077`, `PrivateTmp`, `ProtectHome=read-only`, `ProtectHostname`, `ProtectControlGroups`, `LockPersonality`, `RestrictRealtime`, `RestrictSUIDSGID` and `SystemCallArchitectures=native`, with no `ProtectSystem`, `ProtectKernel*`, `NoNewPrivileges` or `ProtectClock` (whose implied `DeviceAllow=` would close `/dev/net/tun` and an uplink's device to anchord) and no drop-in in any of the unit's four drop-in directories; a root-owned plist and rc scripts, OpenBSD's own login class with the unit's open files; the SCM's own SID and an explicit DACL. The supervisor is privileged, anchord only where `decide` says.
- The observer outlives an anchor the watcher gives up on, and one whose start beside it fails, a refusal for good counted by the watcher as the first of those that give the anchor up; on Windows a TUN anchor's Wintun driver is fetched before the start takes `conflux.lock`, and by every rebuild before it does (`daemon.FetchDriver`, which `up` asks too, before it installs the service), and one that cannot be had is that start's failure, returned where the anchor's start would be, after the observer's: an anchor that does not come up. A stop during the fetch ends the start there, before the lock, and one while the start waits for the lock ends it as soon as the lock is had, before anything under it; a start or a rebuild a stop cuts short later is no failure, warned of and redecided on by neither, and an observer's start a stop cuts short is none either, beside the anchor, where the start ends there, the anchor not started without it, or the watcher's, charged to no keeper; a rebuild, or the watcher's start of the observer, that the cycle's end cuts short, `anchord` exiting under it, is none either, the exit logged instead, with anchord's last lines. The observer is still watched, started again when its capture ends, and renewed; the watch gives up only once nothing the configuration runs is left. Every renewal reaches the observer where it is configured, a rebuild's included (`installRenewal`), and one stands where nothing running takes it: no anchor running, or an observer stopped by hand.
- Renewal never asks in a loop: both timers (`renewLoop` and an ephemeral run's) wait at least `minSleep` after a renewal as after a failure, and the enrolment client refuses a renewal whose `notAfter` has already passed.
- conflux's own anchorctl calls reach conflux's daemon whatever the shell exports (`Ctl.Env`); only pass-through defers to `ANCHOR_SOCKET`/`ANCHORD_TOKEN`. Help, usage and a pass-through to a socket the user names make nothing of the installation's: no directory and no extraction (`libexec.ForUsage`: a whole extraction where one is readable, else an anchorctl in memory on Linux, else a temporary copy removed after, the caller's own on Windows).

**Ephemeral runs**
- `uninstall` refuses a live run and removes a killed run's root, stopping the anchord it left, under the root's lock.
- On Linux the pair runs from sealed memory files and no file of it is on disk (integration asserts it); elsewhere, or where the kernel refuses, it is extracted into the root. The root is where a reboot empties it: the system's runtime directory, or a user's `$XDG_RUNTIME_DIR` on every Unix, else `$TMPDIR`, which FreeBSD keeps across a reboot unless `clear_tmp_enable` is set, as docs/ephemeral.md says.
- No other conflux writes into a run's root: status and pass-through run their own anchorctl from memory on Linux, and elsewhere take the run's pair through `libexec.Extracted`, and ask it nothing before the run's `MarkReady`, which follows its anchor's start, and only while the process that wrote the marker runs (`IsLiveReady`): a killed run leaves its marker, and the next run withdraws it once it holds the lock.
- Nothing of the machine's is read or written: no `conflux.json`, `manifest.b64`, `state.json`, `anchord.json`, anchor directory or service; no file holds the credential or the chain at any point (the renewal goes on stdin); anchord gets no `-dir` and no `-config`.
- The run ends when anchord does, and its root goes with it, removed while the run still holds the lock (`daemon.RemoveEphemeralRoot`); nothing restarts or rebuilds. On Windows every removal of a root — the run's own end, the next run's clearing of a killed run's (`clearKilled`), uninstall's — first asks for the Wintun driver to go through that root's own library, which Wintun keeps while any adapter is in use, and a driver kept is no failure. anchord ends with conflux on Linux (parent-death signal, started from a thread held for anchord's life) and Windows (the job); the next run reaps what a killed one left on macOS and the BSDs.
- As root, anchord drops by the installed rules to `conflux-ephemeral`, never the installation's account; otherwise it runs as the invoking user. Core dumps are off for the run and its anchord.
- An installed conflux is never read, stopped or changed by one; `uninstall` refuses while one is live, and removes its account.

**Extraction**
- `SetID` is the same function of the two SHA-256s whether stamped at build or computed; `make buildcheck`, on CI's `linux` job and every `platforms` leg, checks a stamped build against an unstamped one.

**Pass-through**
- Unknown commands pass through to `anchorctl` unchanged.
- No conflux command shadows an `anchorctl` command unintentionally.

**Overlay join:** two nodes with one taint, enrolled against the live API, reach each other over the overlay (the first stage of `make integration`). Nothing may depend on a third peer; the third node exists only as the LAN-discovery control.

**This skill:** every command, path, script, URL and file name it references exists and works as described at the end of the run.
