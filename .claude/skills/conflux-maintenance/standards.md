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
  - builds: `cross` for every target, including a per-target vet compile of test files; `dist` with the size gate; platform builds on macOS, Windows and Linux arm64, as a release builds them
  - tests: `test`, `race`, the macOS, Windows and Linux arm64 suites, `service-test`, the launchd and SCM lifecycle (`test/service-host.sh`), the install scripts against the published `latest`, and `integration` against the live API
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
- Keep the fork guard on every self-hosted job. The only credential stays the read-only anchor GitHub App. Release stays gated to `version3` and `dev`, and `branch-flow` to a PR into `version3` from `dev` alone.
- Every external action is pinned to its release's commit, with the tag in a comment, and bumped by moving both. No checkout persists its token.
- **Release only releases.** A PR merges into `dev`, and the user merges `dev` into `version3`, only when CI is all green, so `release.yml` doesn't re-verify anything. On a push it fetches the pinned binaries (anchor's `dev-latest` on `dev`, its `latest` on `version3`), runs `make dist` (the size gate comes with it), attests, and publishes: on `dev` the pre-release `dev-latest`; on `version3` twice, at the `VERSION` tag and at `latest`, each deleted and released again, then the back-merge into `dev`. Jobs or steps that repeat CI's checks are removed; the `version3`/`dev` gate is the one guard it keeps.
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
- Tests that need the real anchor binaries skip without them. CI's gates confirm they ran — the `linux` job fails on any `--- SKIP` and the `platforms` jobs on a skipped real-binary test — so they are not run locally to check. A local check skipped for a missing tool (staticcheck, govulncheck, shellcheck, Docker) counts as a failure.
- Code behind a build tag is checked where the tag is true: `make cross` vets and `make lint` runs staticcheck per target OS. Windows-only tests (`internal/paths/acl_windows_test.go`, `internal/daemon/proc_windows_test.go`, `internal/cli/service_windows_test.go`) run only in CI's `platforms` job.
- Confirm from the PR's `integration` job log that `service-test` and `integration` really booted systemd containers, and that `integration` enrolled against the live API.
- Per area, run only the affected tests locally. The full suites run once, in CI on the PR.

## Invariants (verify every run)

**Embedded binaries**
- Every `TARGETS` entry embeds exactly its own pinned `anchord` and lockdown `anchorctl`, built from the synced anchor commit and pinned to the genesis of the tree its branch is tested in: on `dev`, the one `api-dev.veilnet.com.au` issues under, as anchor's `dev-latest` is.
- `make dist` passes the size gate for every target.

**FIPS 140-3**
- Every target is built against the Go Cryptographic Module v1.26.0 (`GOFIPS140`, the Makefile and ci.yml equal) except OpenBSD's, built with it off; `make dist` holds each artifact to it.
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
- `cert probe` sends nothing but the handshake, checks the chain itself with `pki.Verify` (the one `InsecureSkipVerify` in conflux, and only so a failing chain is described), and exits 3 for a chain that does not verify or an unmet `--require-pq*`; X25519 is never offered alone. CI's `linux` job probes every host conflux reaches (both APIs, GitHub's API, web and asset hosts, wintun.net); a new host conflux talks to joins that list.
- A placeholder build reports no anchor pair.
- No `anchoradmin*` file exists anywhere in conflux.
- No binary is tracked by git.

**anchorctl**
- Every command and flag conflux emits exists in current anchor with the same meaning (argv goldens plus the flag cross-check against the real binary).
- Every parsed output and metric name matches current anchor.

**Config rules** (a proxy needs userspace; a subnet, an exit and an IPv4 work in either mode; the two exits are alternatives; no port or explicit LAN discovery beside an uplink, and there both are typed off so a manifest cannot supply them; taint, IPv4 (translation pool included), subnet (`*`, `SPEC@a+b` bindings to the machine's own taints, the list bounds), AnchorID, bootstrap-entry and proxy-spec parsing; the export block anchord reads at startup, read as protojson reads it, TLS material included) accept and refuse exactly what current anchor does, plus conflux's own rules: no list entry holds a comma, and an uplink is a device rather than a descriptor. A file conflux refuses is refused before anchord starts on it, and is permanent.

**Taints**
- An alpha enrolment always asks for a taint, minted or given; conflux never asks for none.
- The credential's taints are the machine's for the life of its identity. Starts take them from the manifest, renewals restate them, and a configuration that disagrees is refused for good, naming the way out (a new identity).
- An imported credential's taints are taken as granted, none included.
- Served subnets are the last set: conflux's at start, or after an explicit `--subnet`/`--no-subnet`, otherwise a member's Subnets order.

**Manifest decoding** handles anchor's current format, refuses a realm manifest and a future version, and survives renewal losslessly.

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
- Config and state writes are atomic, and every writer of the manifest or state holds the lock, `conflux enrol` included.
- A new manifest, enrolled or imported, starts with no state carried over from the identity before it.
- A Unix root owned by another account is refused before anything in it changes; one of ours is `0700`, or a root's `0710` that lets anchord's account through (the shared `/var/log` aside).
- The boot service runs the copy of conflux in the root-only state directory, never the file conflux was run from.
- A re-run of `up` or `proxy` never changes an existing machine's address or identity, and the IPv4 question is asked once, a declined answer included.
- `up` and `proxy` replace each other cleanly.
- `uninstall` leaves nothing behind: no definition, no `wants` link, no launchd disabled-database entry, no SCM entry, no directory.

**Supervision**
- One supervisor per root: `serve` holds `<state>/serve.lock`, and a second is refused.
- anchord runs as root, or with a capability, only where the host or the configuration needs it, and keeps whatever losing would cost an operation or a function; `status` says why. Nothing is re-owned in a directory the account can write, a root anchord never works in one, and what the account wrote is read as untrusted (`flock.Held`, `config.ReadUntrusted`, `copyTree`).
- The anchord a dead supervisor left is stopped by the next one only when it is the recorded process (its executable, or anchor's socket lock where none is reported), and `uninstall` reaps it too. On Windows anchord dies with its own job, which its supervisor holds.
- A supervisor that exits 1 is restarted by systemd, launchd and the SCM; on the BSDs nothing does, and the docs say so.

**Ephemeral runs**
- No other conflux writes into a run's root: status and pass-through take its pair through `libexec.Extracted`, and ask it nothing before the run's `MarkReady`, which follows its anchor's start, and only while the process that wrote the marker runs (`IsLiveReady`): a killed run leaves its marker, and the next run withdraws it once it holds the lock.
- Nothing of the machine's is read or written: no `conflux.json`, `manifest.b64`, `state.json`, `anchord.json`, anchor directory or service; no file holds the credential or the chain at any point (the renewal goes on stdin); anchord gets no `-dir` and no `-config`.
- The run ends when anchord does, and its root goes with it; nothing restarts or rebuilds. anchord ends with conflux on Linux (parent-death signal, started from a thread held for anchord's life) and Windows (the job); the next run reaps what a killed one left on macOS and the BSDs.
- As root, anchord drops by the installed rules to `conflux-ephemeral`, never the installation's account; otherwise it runs as the invoking user. Core dumps are off for the run and its anchord.
- An installed conflux is never read, stopped or changed by one; `uninstall` refuses while one is live, and removes its account.

**Extraction**
- `SetID` is the same function of the two SHA-256s whether stamped at build or computed; CI's `linux` job checks a stamped build against an unstamped one.

**Pass-through**
- Unknown commands pass through to `anchorctl` unchanged.
- No conflux command shadows an `anchorctl` command unintentionally.

**Overlay join:** two nodes with one taint, enrolled against the live API, reach each other over the overlay (the first stage of `make integration`). Nothing may depend on a third peer; the third node exists only as the LAN-discovery control.

**This skill:** every command, path, script, URL and file name it references exists and works as described at the end of the run.
