# Testing

```console
$ make anchor-bins # populate anchor/bin; see docs/build.md
$ make test        # everything
$ make race        # under the race detector
$ make golden      # rewrite every golden file after an intended change
```

Most of the suite runs without the real anchor binaries — the tests that need them
skip, each saying `no anchor pair` (`internal/anchortest`). The ones that need them are
the pair's own header check; the extraction tests, and help's temporary anchorctl; the flag
cross-check; the collision and realm-control checks; a pass-through to a socket the user
named, and help in every spelling Go's flag package answers; status and readers beside an
ephemeral run's pair, and an ephemeral run stopped by its first signal; the supervised-lifetime
benchmark; and everything under `test/`.

## The split

The interesting question for a wrapper is which parts can be checked without a kernel,
a daemon or a network. Most of conflux can be.

| Package | What is asserted |
|---|---|
| `anchor` | the embedded binaries are real executables of the right architecture; `SetID` is the same function of the two digests whether stamped or computed, and a malformed stamp is computed instead |
| `internal/config` | JSON round-trips, the tuning fields included; the mode rules match anchor's — a proxy needs userspace, a subnet, an exit and an IPv4 work in either mode, the two exits are alternatives, observing needs the observer and serves no proxy, the observer is refused where anchor has no capture, a port is refused beside an uplink, an empty taint set is accepted; proxy specs, IPv4 addresses, subnets — `*`, bindings to the machine's own taints and anchor's limits on a list included — AnchorIDs and taint names parse and refuse exactly as anchor does, and bootstrap entries by anchor's grammar (anchor skips a bad one with a warning, conflux refuses it), with conflux's own refusals of a comma in a list entry and of a descriptor uplink; the export block is read as protojson reads it and refuses what anchord refuses at startup; a `state.json` that does not parse refused, naming the file, rather than read as empty |
| `internal/enrol` | the manifest decodes exactly as anchorctl reads it, refuses a realm manifest and a future format version, and **survives a renewal losslessly**; which documents are alpha's, and the taints check every start holds a machine to, with a way out that fits who issued the credential |
| `internal/enrol` (client) | against `httptest`: the alpha exchange byte for byte, taints in the enrolment's body and restated in the renewal's, none refused before anything is sent; the guardian bearer, 4xx and 5xx, a refusal's words without control characters and never cut through a rune, an oversized body, a cross-host renewal URL and a downgrading redirect, a plain-http base, cancellation, and clock skew; a renewal's bootstrap list taken only when anchor would dial all of it; and that an enrolment is handed back as it arrived, to be written before it is read |
| `internal/taint` | generated names — 26 symbols, a little over 128 bits — satisfy anchor's rule, avoid ambiguous glyphs, are grouped for reading, and do not repeat |
| `internal/daemon` | the renewal arithmetic: two thirds of the *observed* window, expiry, absent timestamps, and the clamp; a renewal against a stand-in issuer, restating the manifest's taints whatever `conflux.json` says, spliced into the manifest with the issuer's bootstrap list and mirrored into the state, and a failed one recorded; an enrolment asking for the configured taints, never for none, and kept before it is read even when it grants others; a machine whose credential grants other taints, or an alpha one granting none, refused for good with no call, and an issued one granting none started; a bad clock measured again rather than trusted; anchord's last words kept when it dies, in order; shutdown returning once anchord has gone, and closing a running one with its signal alone; the anchord a dead supervisor left recorded, stopped by the next one only when it runs the recorded executable or, with none reported, holds the socket's lock, a record of one that has gone cleared, a second supervisor for one root refused, and an anchor directory whose chown to the account failed, or whose creation was interrupted, never left at its name; on Windows, a SYSTEM anchord's anchor directory made with its DACL as it is created, SYSTEM's and the Administrators', never holding what its parent passes on, a denial of `WRITE_DAC` that would refuse one given its DACL afterwards among it, and an account's ending with a DACL that grants the service SID, and anchord ended with its job; a conflux.json read one way by every reader -- none is nothing to start, unparsable is permanent, unreadable is retried; a corrupt `state.json` refused for good, whatever the configuration runs, and left as it was; an uplink reopen counted in the bring-up's own state write; the link watcher's device parsing, its grace against anchor's own dial timeout, its giving up after three rebuilds refused for good, an anchor given up on beside an observer still observing leaving the observer kept and the watch going on, until the observer is given up on too, and an observer given up on beside an anchor running tried no more, a link whose rebuilds bring no connection reopened less and less often, a rebuilt link that carried something rebuilt as any other once it ends again, and a gone device waited for, its readiness marker withdrawn, with nothing built or written until it is back, and a gone anchor directory made again by the rebuild as a spawn makes it, for anchord's identity, the anchor rebuilt in the same daemon with the observer beside it neither stopped nor started again, and one that cannot be made so left for the next spawn; observing alone, a cycle that enrols first, hands the observer the saved manifest on stdin, records the identity it reports running as and starts no anchor, and one the host refuses to capture for ending the restart loop for good; a credential that cannot be had ending the cycle with no observer started, alone and beside an anchor; beside an anchor, the observer started once the credential is held and before the anchor, and kept when the anchor cannot come up, for now or refused for good, while an anchor refused for good beside an observer that did not start either still ends the restart loop on the third with the error serve exits 70 on; an anchor refused for good recorded for status as given up on only where the supervisor stops trying it, the watcher giving up or the restart loop ending on it with nothing else running, not at a start beside an observer nor for a loop ended on the configuration or on an observer the host refuses, and the record cleared by an anchor that comes up, the watcher's rebuild among them, as a cycle's start of everything begins, whatever that start comes to, and as the service starts, one that goes no further among them, and gone whenever the restart loop waits to start anchord again, one written in the backoff before or in the cycle that ended among them, and with a daemon that dies before any bring-up, a `state.json` that does not parse left to the start to refuse, with nothing said of it as the record is cleared, while any other failure to clear it is warned of; the watcher starting an observer whose capture ended again, under the credential, and one whose start beside an anchor failed, leaving one stopped by hand alone, and giving up on one the host refuses; a renewal installed in everything the configuration runs, the observer by `observe -cred -`, a machine that only observes renewing by its observer's identity, the timer running for it, an observer or an anchor that is not running leaving the renewal standing rather than due, a renewal made before the watcher's start handed to the part that runs on, and a part started again leaving the state's window the one the part running on holds, due where a renewal did not reach it, a renewal on the way the part running on refuses among them, kept on disk and said, and everything started again leaving it the manifest's; anchord started with `-config`, an ephemeral run's with none, and none with `-allow-observer`; what anchord is given to observe on each platform, and the anchor's kept settings granting nothing while it only observes; which failures stop the supervisor rather than being retried, a start that fell back to the supervisor not taken for a decision that changed, the restart loop ending on the third refusal in a row with the error serve exits 70 on, and starting its backoff over after a healthy run, a backoff doubling to its cap and starting over once a try works, a probe that cannot recover ending the wait for readiness, and the renewal timer renewing what is due, stopping on a credential that does not renew, and waiting without a word while no AnchorID is recorded; the supervisor's start placing afresh, from its own image, the copy of conflux it runs from where that is not there or not as conflux makes it, leaving one that is, and removing a lock file that is not, and a folder at the copy's name failing the start, not for good; and an ephemeral run, against the stand-ins, that writes nothing of the credential and removes its root when cancelled, ends with its daemon, starts its observer on its credential, enrolled into memory first, renews a due credential in memory by the AnchorID it started with, with the chain on anchorctl's stdin for the anchor and the observer, is refused while another holds the root, empties its root under its lock so a run starting as it ends keeps its own, removes the folders it made on the way to a root under a `CONFLUX_DIR` whole, a file put in one among it, and leaves a `.conflux` an installation was made in, with the `CONFLUX_DIR` holding it, refuses an expired credential before anything starts, and, on Linux, whose anchord goes when the run is killed outright; a bring-up, a renewal and the record of a refusal waiting for the state's lock stopped, with the context's error, once their context ends |
| `internal/anchorctl` | the argv goldens, the observer's starts among them, on the manifest on stdin, and its renewal on stdin; that every flag they use exists; and the output parsers against anchor's current `start`, `status`, `observe` and `metrics` shapes: the `observer` row with an anchor and with none, its credential valid or lapsed, as anchor's printer writes it, and the identity on observe's `as` row |
| `internal/libexec` | extraction, making neither a root nor `bin/` and failing where uninstall removed them, the temporary copies killed readers left removed wherever readers may make them, on Unix the cache directory among them, asserted to be the test's own, each place read by its name and never as a pattern, a link at such a name removed as itself and what it names kept, nothing else there, one that will not go passed over, idempotence, eight concurrent callers leaving one set and nothing else, repair of a truncated set, a set under its name only once its anchorctl has run, and one that will not run removed and extracted again, and a sweep that leaves alone any set that may be in use, `Remake` waiting for an extraction in progress, what was in `bin/` still there as its holder lets go, under a deadline of the test's own, and a reader whose wait for one its context ends ending with the context's error, no temporary copy made, and help never making a temporary directory that is missing, nor running a whole extraction in a root every account may write, but a private copy; a reader's anchorctl (`ForUsage`) with no bin directory a temporary copy it removes after, nothing made, with this build's pair not extracted extracted into a bin directory as conflux makes it, the older set there kept and nothing left in the temporary directory, the pair extracted taken as it is found, its files unjudged, and with a bin directory every account may write a temporary copy, nothing extracted there; on Windows, an elevated reader's temporary anchorctl in a folder of its own in `%ProgramData%`, the folder and the copy SYSTEM's and the Administrators' alone and both removed once it has run, one not elevated granted to the account running it, and a set's binaries SYSTEM's and the Administrators' alone, read from the DACLs `ForUsage` and `Extract` wrote, and a set's staging directory made with its DACL as it is created, and on Linux kept in the cache directory, made if need be, where the temporary one is noexec, and the SELinux hint's commands quoting the extraction directory for the shell, given where SELinux is enforcing and not where it is not |
| `internal/cli` | a fresh install and its `uninstall` leaving the tree exactly as it was, both where conflux made the `CONFLUX_DIR`, on a way it made, which goes with it, and where the `CONFLUX_DIR` is the user's, holding a `bin/`, a `.ssh/` and a file, kept as it was, mode and all, whatever the user put in conflux's root, `run/`, `bin/` and `logs/` going with them, a killed run's root and a killed reader's temporary anchorctl among them; every command that reads a root without making it — `status`, `down`, `renew`, `update` with the boot service installed and a pass-through — refusing a root every account may write, sticky or not, or, on Linux, whose ACL lets another account write it, exit 1, naming it, with nothing in it read, made, changed or removed, the boot service neither registered, started, stopped nor removed, and nothing downloaded or replaced by `update`, while `uninstall` removes each such root, a link planted in it removed as the link and where it leads untouched, nothing in it read and no `anchord` reaped by its pid record, and off a terminal without `--yes` refuses it, nothing removed, as it refuses a `CONFLUX_DIR` holding an identity, saying the credential goes with it and has no other copy, while one holding none it removes asking nothing; a `start` of such a root removing it and making it afresh, the configuration and an earlier set with it, and exiting 78 with nothing to start; `uninstall` removing the folders conflux made on the way to a `CONFLUX_DIR`, recorded in its root, whole, whatever was put in them, the folder they were made in kept, and left, the record unread, where the readers' check refuses the root that holds it, and removing a `CONFLUX_DIR`'s root inside a directory every account may write, the boot service with it, that directory as it was, and a `CONFLUX_DIR` beneath a file, whose way cannot be walked, stopping it before it acts, saying so, the boot service not removed; `uninstall` of a scratch installation leaving nothing conflux made — the identity, configuration and state, the extracted set, the service's copy, the locks, the run directory, a killed ephemeral run's root, and what an update left beside conflux, a `conflux.old` there kept on Unix — a link planted in it (on Windows a junction) removed as the link with what it leads to untouched, and a file another account owns removed as itself, the `anchord` a dead supervisor left reaped and a killed ephemeral run's root inside it emptied under its lock first; `uninstall` refusing a live ephemeral run inside a `CONFLUX_DIR`, exit 2, before anything is removed, and again once its question is answered, for one started as it asked, and leaving one started once it has begun running, with its root and the ephemeral account, which goes with the installation's otherwise, listing what it removed all the same, and a run that takes a killed run's root as uninstall lets go of its lock keeping it, the root not taken for gone; a root, and an ephemeral run's, that uninstall could not empty not listed as removed, the failure naming why, an ephemeral run's it removes reading nothing in it among them, whoever runs it; an ephemeral root outside the installation's that is sticky, that another account may write, or that is a link removed by `uninstall` as itself, no lock taken in it and where a link led untouched, and a killed run's, at `0700` or `0755`, emptied under its lock, each listed; `serve --log` under a root `EnsureAll` refuses, a `CONFLUX_DIR` beneath a file, appending nothing where a link at the log's name leads, and saying why where the service manager sends its output, and under one it accepts writing to its log, and not there, what it says from then on, a second supervisor's refusal among it; a pass-through with nothing running makes nothing — no directory, no extraction; one to a socket the user named, by `-socket` or `ANCHOR_SOCKET`, usage asked beside it or not, and help take the readers' anchorctl, never told nothing runs: with no installation a temporary copy and nothing made, with one this build's set extracted into its `bin/`, and under a root the readers' check refuses a temporary copy, never a set planted there, the size of this build's, the temporary directory left empty each time; the service tidy stopped never started again in a root the readers' check refuses, nothing placed there; a reader (`toolsFor`) of an installation with no bin directory running a temporary copy it removes after, and with one extracting the pair there, the installation's run directory, not as conflux makes it, left as it was either way; `status`, with the daemon's token and without, a pass-through and usage, with this build's pair not extracted, leaving the temporary directory as empty as they found it, with a bin directory or without; `ANCHOR_SOCKET` and `ANCHORD_TOKEN` exported empty taken as unset, the pass-through reaching conflux's daemon; a SIGTERM, SIGHUP or SIGINT sent to conflux passed on to the anchorctl it runs as a child, conflux ending as that does, by its code or the signal, and the temporary copy removed either way, and a hangup under `nohup`, or an interrupt to a conflux started ignoring it, ending neither; only a temporary copy run as a child, the installation's anchorctl replacing conflux for a socket the user named, for usage and for conflux's daemon alike, as the parent of an anchorctl planted as this build's set shows: the test binary that started conflux, not conflux, which is the parent of a temporary copy; an ephemeral run, its anchord up, stopped cleanly by a first interrupt or SIGTERM, exiting 0 with its anchord stopped and its root removed, with the `.conflux` it made, the `CONFLUX_DIR` as it was; an ephemeral run ended by a hangup, and not under `nohup`, and a second hangup, SIGTERM or interrupt ending it at once (an ignored one staying ignored); `help` a command only first and a flag only as a flag, in every spelling Go's flag package answers; `renew` with no credential unavailable, and a machine that only observes renewed as any other; a refusal for privilege repeating the command, with the privilege check stubbed so a root runner tests it too, and `status` refused the same way where the configuration is closed to the account; an oversized manifest refused; `update` handing a stopped anchor's boot service to the conflux it put in place, whose `register` places its copy, registers it and starts nothing; that conflux's `register` and `start`, and the `install` of a conflux put in place by hand, leaving only what it makes in an installation an earlier conflux left — this build's set extracted again over one planted padded to its sizes, no other set and nothing staged, the lock files kept on Unix and made again on Windows, no atomic write that never went in place, the service's copy this conflux with nothing beside it, an empty run directory, no killed run's root, no killed reader's temporary anchorctl, listed, nothing an update left beside conflux, and on Unix a `conflux.old` beside it kept — the configuration, identity and state as they were, while a start of the conflux the service already runs removes none of that; a copy for the service that is this conflux byte for byte but not as conflux makes a file of its own left by the supervisor's making of the roots and taken by `start` and `install` for what earlier conflux left, removed with the rest and placed afresh; the service those stopped started again only on a copy of conflux's own, placed afresh first where tidy failed once `EnsureAll` had removed one; `up` into a `CONFLUX_DIR` with nothing of conflux's in it placing this conflux as the service's copy and registering it, and `up` again, `install` and `start` keeping that same file; the boot service stopped where a supervisor serves the root, or a root not as conflux makes one, before that is made afresh, and started again by `register`, `start` and `install`, however the command ends; the `up`, `proxy`, `observe`, `install`, `enrol` and `start` of a conflux put in place by hand stopping the service before anything in its roots is made afresh, and starting it again once, by their own restart, which failing is not tried again though the service manager then says the service is down, or, where they end before it — a configuration they cannot read, a manifest not there for `enrol`, which restarts nothing itself — as they exit; `start` finding no configuration, or failing to register the service, its code kept; a failure to start it failing `register` and warned of beside `start`'s own failure, and, where a supervisor the boot service did not start serves it — the service stopped, or not running and so not stopped — the update refused, naming it, nothing registered and nothing started; a supervisor gone as the service manager, saying the service is not running, is asked, neither stopped nor started again by `register`; a supervisor that takes the root once the service is stopped refusing the update, naming the root, nothing registered and nothing started, the service stopped included; the serve lock that cannot be asked after once the service is stopped refusing it, saying why, nothing registered, and the service started again; a service manager that cannot say whether the service runs refusing the update, saying why and not that a supervisor was run by hand, nothing stopped, registered or started; an ephemeral root not as conflux makes one — one every account may write, or a link — removed as itself by the conflux an update put in place, no lock taken in it, and one as conflux makes one, whatever it holds, emptied under its lock, each listed; on Windows, a junction at an ephemeral root's name removed by `uninstall` as itself, listed, where it led untouched, no lock taken there and nothing reaped; what an atomic write left kept, with the lock, while the state's lock is held; only what is gone listed as removed — not this build's set, extracted again, nor a killed ephemeral run's root a run took as its lock was let go of, which it keeps — the earlier sets kept and the update refused where `bin/` cannot be emptied, and what of the run directory could not be removed warned of, the update going on; the readiness marker withdrawn before `start` and `proxy` register the service, which can start it, and still there when they restart it; on Windows, every command refused on a build older than 1803's, 17134, exiting 70 with nothing made; on Unix, `register` waiting for an extraction in progress in `bin/`, saying so, and ended by Ctrl+C, exit 1, the supervisor's lock let go of and nothing registered or started; update's child sent SIGTERM on an interrupt and waited for, so its own finish runs and update ends with its code, and one that does not end killed past `childFinish`; on Windows, every command that registers the service — `install`, `up`, `proxy`, `observe`, `enrol`, `start` and `register` — refusing a `CONFLUX_DIR` holding a `%`, exit 1, with nothing made and the service manager asked nothing; where the Administrators could not be made the owner of what conflux makes, every command that can make something in a root refused, help and the readers among them, exiting 70 with nothing made, and `version` and `cert` run, only the supervisor's transient exit asking the SCM for a restart, a root the service's `EnsureAll` refuses among them, and `Stopped` reported once; the collision rules — `start`, `renew`, `proxy` and `observe` by shape, `status` by arity — and that nothing shadows anchorctl unintentionally, the realm-control commands included; the IPv4 asked once; the interface name kept, set, or reset by `--no-interface`; `--taint` as the enrolment's request before a credential is held, and checked against it after; `enrol` taking the credential's taints, refusing an alpha one granting none, refusing before it writes, a `state.json` it cannot read among the refusals, replacing one that does not parse, and naming up, proxy and observe to run next; a subnet list set from the terminal replacing a member's order; the observer kept, replaced or turned off by `up`'s and `proxy`'s flags, an option implying `--observe`; `--export` pointing the collector and keeping the headers and TLS `conflux.json` holds; where the observer's records go said either way; a lapsed observer pointing at `conflux renew`; `observe` taking `up`'s enrolment flags and saving the taints and API they give for the supervisor's enrolment, and `status` reporting its credential as an anchor's; `status` saying, on a `given up` line, when and why the supervisor gave up on the anchor, wherever none runs, the daemon answering or not, with nothing said of the observer, and nothing of it while an anchor runs or for a machine that only observes; `down` clearing that record; `status`, against a stand-in anchorctl, asking the machine's daemon for the export it reports and an ephemeral run's for its status alone, and taking who anchord runs as and the anchor directory a Subnets order is kept in from the privilege record; and switching an anchor to observing refused off a terminal without `--yes`, and asked only once a `--taint` the credential does not grant has been refused, and before a taint is minted, while `observe` run again on a machine that observes asks nothing; `--manifest` refused without `--ephemeral`, an ephemeral run taking a handed credential's API and taints and never asking for an IPv4, and an ephemeral proxy needing no root where an ephemeral `up` and observer do; an ephemeral root another account made, a held lock and a marker in it, passed over by every reader, and not looked into, nor one made just after the readers' check found it not there, its lock held or left |
| `internal/service` | the systemd unit, its `ExecStart=` quoted against splitting and expansion; systemd's `MainPID` read as whether the unit runs, `0` as not, and an answer naming no number refused; the launchd plist carrying any path, and what registering it asks of launchd: nothing for a plist already in place, a changed one reaching a loaded job, a running job left running, a disabled label lifted, and the restart after it starting the job once whatever it found; the rc scripts the BSDs get, rendered and parsed by `sh`, and a root they could not match refused; the copy the service runs, written afresh by `PlaceAfresh` even where it is this conflux, and kept, the same file, by `Keep`, and what a copy that never went in place left beside it removed, its folder read by its name and never as a pattern, so a copy in `x[1]` leaves what is in `x1`; one manager for the life of the process on macOS, and the log hint quoted for the shell; the service's scope, the same for every spelling of a root; the SCM's states that run, a stopping service's among them (Windows) |
| `internal/paths` | the one atomic write (`WriteAtomic`) leaving old-or-new and never a truncated file, setting the mode it is given under a `077` umask — the service definitions' `0644`, `0755` and `0555` among them — and narrowing a file that was `0644`; on Unix, a link made at a name on the way meanwhile refused with nothing made where it leads, and a directory, every account's to write or this account's own, gone into; `Check`, the readers' check, before a reader reads a root by name, passing a root of this account's at `0700` or `0750` and changing nothing, refusing one every account may write, sticky or not, and a link at its name, even to a directory of this account's own, naming it, passing a `CONFLUX_DIR` in a directory every account may write, and on Windows refusing one one whose DACL lets Users add a file to it, that only inherits %ProgramData%'s grant to them, or that passes them full control of what is made in it, and reporting none there as not there; every root `EnsureAll` makes, a `CONFLUX_DIR` installation's and an ephemeral one inside or outside it, passing `Check`; on Windows, the service SID asked again where Windows did not give it and kept once it did; the root absolute and clean, one layout with or without a `CONFLUX_DIR` — everything in `.conflux`, in the system's data folder or the `CONFLUX_DIR`, and a log directory inside it only where the platform writes the service's output to a file; no folder above a root judged: a `CONFLUX_DIR` every account may write, sticky or not, or inside a directory every account, or a group with another account in it, may write, or reached through a link or a chain of links through one, made at `0700` where it leads, passing `Check` and uninstall's walk, the folders above as they were, and no group asked who it lets in; on Linux, a root whose own POSIX ACL lets another account write it refused by `Check`, naming that account, and made afresh by `EnsureAll`, and one made under a default ACL that lets another account write taken; macOS's, FreeBSD's and Windows's ACLs read from their bytes, a Windows allow entry's callback and object forms counted where no object type narrows them, and its compound form by its client, one that only passes its rights on counted, an entry of a type Windows does not number and a malformed one refused, each right that writes a directory counted alone, and a deny entry let through; Windows's symbolic link and junction targets read from their reparse data as `os.Readlink` names them, one naming a share, a WebDAV server or a device, or a relative one naming a volume of its own (a UNC, device or NT path, or a drive, in either separator), refused, and data in no shape a file system returns refused too; on Windows, the root made Administrators' as it is created, never carrying a grant to Users its parent passes on, nor a denial that would refuse a directory given its DACL after it is made, files restricted to them trusted, a root `Check` may not open, its DACL denying everybody the right to read it, refused for that denial by `Check` and made afresh by `EnsureAll`, an ephemeral root the elevated administrator's own account owns, or that grants it anything, refused by `Check`, which trusts that account with no root, and made afresh by `EnsureAll`, one not there, or under a directory not there, reported as not there, a root on a network volume, by its UNC path or a mapped drive, refused by `Check` and `EnsureAll` alike, with nothing made there, a link at a root's name to the drive, to a share or to nothing refused by `Check` and replaced by `EnsureAll` with a root made here, a `CONFLUX_DIR` on the share refused before anything is made, a link naming a share or leading nowhere on the way to a `CONFLUX_DIR` refused by `Check` and `EnsureAll` before anything follows it, with nothing made where it leads, a `CONFLUX_DIR` inside a directory whose DACL lets Users rename what is in it, directly or with a folder made on the way, reached through a junction into one, or through a junction Users may point elsewhere, made where it leads, SYSTEM's and the Administrators' alone, and passing `Check` and uninstall's walk, and one inside the profile of the administrator running conflux made the same; an ephemeral root inside the `CONFLUX_DIR`'s `.conflux` and nowhere else, its record of the way made to it kept as an installation's is, and one the readers' check refuses, saying the next ephemeral run makes it afresh — another account's or one another account may write, a link leading nowhere, a link to a directory of this account's own, where it led untouched — removed as itself and made afresh there, and only one in a directory this account may not remove anything from passed over for the next candidate |
| `internal/paths` (the walk) | the way to a root walked from the top of its volume as the kernel looks it up, each link followed from where it is read, and `..` going back to the directory held before; nothing on it judged; through the `looking` hook, called before every lookup and every make, a link or a directory planted at each name the walk looks up, and each `makeWay` makes or goes into, on the way to a `CONFLUX_DIR`: a link the walk meets followed, and one made once conflux was making the name refused, naming it, with nothing made where it leads; a directory, every account's to write or this account's own, gone into, by the walk where it is looked up and by `makeWay` where it is made or gone into, the `CONFLUX_DIR` among them, and at the root's own name a link or a directory every account may write removed as itself, what the directory held gone, and the root made afresh, and a link put there once it is made refused, naming it, with nothing made where it leads; on Windows the same with a junction, and a folder Users may rename what is in; and a link leading nowhere refused, never taken for a root that is not there, a `CONFLUX_DIR` through a link to a directory not there refused by `EnsureAll`, with nothing made where it leads, and by `Check`, not as nothing installed; and one under a `0311` directory of this account's, held by its name on macOS and the BSDs, made and passing `Check`, and still once others may write that directory; `RemoveRoot` removing a root, one the readers' check refuses among them, following nothing — a link or junction in it removed as itself and what it leads to untouched, a read-only file removed with the rest on Windows, and a file and a folder another account owns under a DACL granting the Administrators nothing — a link or junction at its own name removed as itself, where it leads untouched, and the `CONFLUX_DIR` it is in kept; and removing a `CONFLUX_DIR`'s root inside a directory every account may write, its way passing `WalkWays`, unjudged; what is read in a root by a command that has not made it — the way record, the serve lock — opened through the root held (`OpenIn`) and only in a root as conflux makes one: a link or junction at the root's name, to a directory of this account's own, to the one it is in or to nothing, taken as no root, nothing in it opened, and so is a directory every account may write (on Windows one Users may add to, or the Guests own), the way record in it unread; what `OpenIn` reads is the held root's though another root is put at the name once it holds it; a removal asking for no right to read a file, which backup intent would grant; the folders `EnsureAll` made on the way to an installation's root recorded once in its state root, by the names a `CONFLUX_DIR` spelled through a link is spelled with, read back by `Way` deepest first, only above a root, none the top of a volume, and not where the readers' check refuses the state root, a record that is a link refused unfollowed, and removed whole by `RemoveWay` once the root is gone, a folder holding a file among them, while one holding the installation's root while that holds anything, and a link or junction put at a recorded name, is left; nothing recorded on the way to an ephemeral run's root outside a `CONFLUX_DIR`, and under one the `.conflux` it made recorded, and removed whole once it holds nothing, left while an installation made in it holds anything; and nothing taken from the record above no root; with a directory every account may write above a `CONFLUX_DIR`, the record read by `Way` and the folders recorded removed by `RemoveWay`, above it and inside it as an ephemeral run records its `.conflux`, unjudged; the record refused, unread, where it is a second name, past its size or a FIFO, which is not waited on; the roots conflux holds and removes (`Outer`) and what sits inside one (`Inside`) decided by one test, a name that only starts with `..` inside |
| `internal/paths` (roots conflux's by name) | a `CONFLUX_DIR` at the top of a volume, `/` or `C:\`, holding its one root, `.conflux`, which every root and ephemeral candidate is or is inside, asserted of the names alone, so nothing outside the test's own directories is made or removed; a `CONFLUX_DIR` that is a folder of the user's, holding a `bin/`, a `.ssh/` and a file, left exactly as it was by `EnsureAll`, mode and all, its root `.conflux` inside it, and on Windows its own owner and DACL as found; a link, a file or a directory every account may write at the root's name removed as itself and the root made afresh at `0700`, where the link led untouched and what the folder held gone, and on Windows a junction, a folder Users may read, one the Guests own and one granting this administrator, each refused by `Check` first and the root made SYSTEM's and the Administrators' alone; each folder conflux keeps in a root — `run/`, `logs/` where the platform writes a log, `bin/` and `anchor.root/` — that is a folder others may write, a link or a file removed as itself and made afresh at `0700`, what it held gone and where the link led untouched, one as conflux makes it kept with what it holds, and `run/`, `logs/` and `bin/` made at `0700`, while `anchor.root/`, which the supervisor makes, is not made; each file conflux keeps in a root — the configuration, the state, the identity, the record of the anchord last started and of the way, the lock files, the service's copy — that is a link, a folder or a file every account may write (on Windows a junction, one Users may read, or one this administrator owns) removed as itself, where the link led untouched, and one as conflux makes it kept, `anchord.json` not judged, the service's copy left by `EnsureServing`, the supervisor's, and `Ours` refusing such a copy, or a file in a folder every account may write or through a link, and holding one as conflux makes it; a file at a root's name refused by `Check`, naming it; a root not as conflux makes one that `EnsureAll` cannot remove refused saying why it is not conflux's and why it would not go; `ours` taking a directory root's or this account's at `0700`, `0710` or `0755`, and refusing `0777`, a sticky `0777` and another account's, from steps of the test's making |
| `internal/paths` (readers, Windows) | an ephemeral candidate not there judged by where it would be made, with nothing at its name read, though a link is made there once the readers' check has looked; one not as conflux makes a root on a filesystem mounted noexec passed over before anything is made there, left as it was, and the next taken, whose own refusal is then the answer and not that every place is noexec; on Windows, under a client's default-owner policy once conflux has made the Administrators the owner of what it makes, what an administrator's commands make in an installation's root — the root, `run\`, `logs\`, the lock files, `bin\`, its lock, the set and its binaries, the service's copy of conflux and the configuration — each the Administrators', granting the administrator nothing, as its maker returns, and the root passing the readers' check; an installation's `CONFLUX_DIR` inside a folder granting this account full control, as an administrator's profile does, made there, SYSTEM's and the Administrators' alone, and passing the readers' check, and an ephemeral run's root inside it too; the folders conflux makes on the way to a `CONFLUX_DIR`, the `CONFLUX_DIR` among them, the Administrators', under a protected DACL of exactly two entries, SYSTEM's and the Administrators' full control passed on to all they hold, and one of them taken as a root passing the readers' check; a file in a directory another account writes read (`ReadUntrusted`) only as one regular file of its own under the size asked, a symlink (on Windows, a reparse point), a second name and a FIFO refused |
| `internal/group` | who a group lets in, read from what getent and dscl answer — its listed members and every account it is the primary group of; and a `Lookup` kept answering as a new one does, asking for each group's record and for the account database once however often it is asked, where a new one asks for both at every question, a record it failed to read asked for again, and a new `Lookup` reading afresh. In `internal/paths`: who a group lets in asked of one `Lookup` for the whole process, `groupOf` asking it at each judgement of a root, or a folder or file of conflux's, its group may write, and never for a folder above a root |
| `internal/flock` | a held lock reported as held, not waited for, and one held for 25 ms outlasting the tries a TryAcquire makes; one `AcquireContext` waits for taken once let go of, the caller told once, after a second, that it waits, and the wait ended with the context's error when the context ends; asked without trusting the file — a symlink (on Windows, a reparse point), a FIFO and a second name for another file refused; `HeldIn` asking through the root held, nobody's where the root or the lock is not there, and nobody's where a link is at the root's name, to a directory of this account's own holding a held lock or to nothing |
| `internal/logfile` | each line stamped once however the writes are cut, a full log moved aside at a line's start, placed over the standard streams as the service's is, both files removed, and what the runtime writes to stderr itself landing in the log, on Windows as on Unix |
| `internal/privcheck` | a command repeated for the shell it is pasted into, each word quoted where that shell would read it |
| `internal/wintun` | a redirect of the download off HTTPS, to another host, or past the tenth request refused |

## The tests worth knowing about

**`anchor.TestPairIsRealExecutables`** parses each embedded binary's ELF, Mach-O or PE
header and checks the machine field against `GOARCH`. It exists because a wrong file in
`anchor/bin` — a truncated copy, one named for the wrong architecture, a CRLF-mangled
one — builds and links perfectly and fails at exec on somebody else's machine.

It skips when `anchor/bin` holds the placeholders `make anchor-bins` writes with no
anchor checkout available, with the same words as the rest; it keeps a copy of them
because `anchortest` imports `anchor`. `anchor.Supported` is a size check for the same reason, so
a placeholder build reports that it carries no anchor binaries rather than pretending.

A skip is green, so the job that fetches the real binaries asserts that none of the
tests needing them skipped: a job that provides the binaries and then reports "no
anchor pair" has lost them, and saying so is the difference between a gate and a
decoration. On macOS and Windows, where other tests skip for the platform, the gate
looks for that reason rather than a list of names a new test would be missing from.

On Windows the tests root what they make, every `CONFLUX_DIR` among it, in `conflux-tests` on the
volume Windows is installed on, read from the system rather than `SystemDrive`, a folder only SYSTEM
and the Administrators may change (`privtest.ServiceTemp`, which `paths`' tests and every test linking
`pathstest` set up first, and which leaves a `TMP` or `TEMP` already beneath that folder as it is, so a
child of a test binary keeps its test's),
rather than in `%TEMP%`, deep in the profile of the administrator running the tests, which grants
that account full control. The folder is made, or given again where it differs, as the
Administrators' by name, and the test process first makes them the owner of what it makes without
naming one, as every conflux process does as it starts (`paths.ElevatedDefaultOwner`);
`privtest.CreatorOwns` gives a test a client's policy, the administrator's own, for a while. What
conflux keeps in `%ProgramData%` — an elevated reader's temporary anchorctl, and the default root
where no `CONFLUX_DIR` is set — every test linking `pathstest` keeps in that temporary directory as
well (`paths.ProgramData`, which the system's `\ProgramData` is otherwise), or in a test's own where
it points `TMP` and `TEMP` at one; a test asserting what goes there, and what is removed from there,
gives it a folder of its own apart from them (`pathstest.ProgramData`). `paths`' test of the system's
`\ProgramData` asks `ProgramData` as the package's own initialisation leaves it, before `pathstest`'s
(`programDataAtInit`), so what conflux reads it through is what is tested.

Wherever a reader's temporary anchorctl is made, a test that makes one roots every place it may be
made in a directory of its own first (`pathstest.Temporary`: `TMPDIR`, `TMP` and `TEMP`, and on Unix
the cache directory's `XDG_CACHE_HOME`, or macOS's `HOME`), and removes the copy
once it ends however it ends, before it asserts anything of it; `cli`'s tests run with those rooted
in a temporary directory of their own besides (`TestMain`, `pathstest.SetTemporary`), so that the
uninstalls and tidies they run, which remove what killed readers left there, never look in the
machine's.

No conflux `cli`'s tests run can hang the suite, nor keep it waiting past one bound. `Main` run in the
test's own process, as help and usage are, runs on a goroutine of its own (`capture`, `captureOf`, and
the test of Ctrl+C ending a wait for `bin/`), and one that has not returned within thirty seconds
(`childDeadline`) fails the test. A conflux run as a child of the test binary — a pass-through, which
on Unix replaces the process, or `serve`, which puts its log over its output — goes through
`confluxChild`, which kills the child past thirty seconds, gives what it left five more to let go of
its output (`WaitDelay`), and fails the test, and fails it on a panic too. The signal tests
(`exec_unix_test.go`), which start their children themselves so as to signal them, wait a bounded
time for each — ten seconds for what a signal does, thirty for a run to end, sixty for an ephemeral run
to reach its enrolment — fail the test past it, and kill what they started as they end, with
`WaitDelay` where they read its output. The first run to pass its bound marks the suite (`overrun`):
one still running may hold what the next needs, a lock or a goroutine that never returns, so every run
after it, in the process or a child, fails at once (`bounded`), and the suite ends within one bound of
the first, its temporary directories removed, rather than at `go test`'s timeout with them left behind.
`libexec`'s test of `Remake` waiting for an extraction runs it on a goroutine under thirty seconds of
its own, on the test's context, which ends the wait as the test ends.

**The argv goldens**, in `internal/anchorctl/testdata/argv/`, hold one file per
scenario, one argument per line. Argv construction is where a wrapper's bugs live and
it is invisible in a review diff — anchor's flag is `-serve-subnets`, plural — so a
change to what conflux passes anchorctl shows up as a reviewable text diff instead.
`make golden` rewrites them after an intended change, and `TestArgvGoldens`, and
`TestObserveArgvGoldens` for the observer's starts, fail on any other. It rewrites every
golden file in the tree, running each package whose tests check one through
`internal/goldentest` with that package's `-update`.

Paired with them is `TestEveryFlagWeUseExists`, which runs the **embedded** anchorctl,
scrapes each command's `-h`, and fails if conflux's argv names a flag that no longer
exists — every flag conflux can pass, including the ones it passes only when set: every
golden, read from `testdata/argv`, for `start` and `observe -start`, and a vector of each other
command conflux runs. Go's flag
package refuses an unknown flag rather than ignoring it, so that would otherwise be a
daemon that will not start — discovered after the binaries were dropped into
`anchor/bin` and shipped.

**`pki.TestOnlyApprovedCryptographyIsUsed`** reads every non-test Go file for the
cryptography `fips140=only` does not refuse as it happens: anything from golang.org/x/crypto,
which the module never sees; an AES block alone, which is AES-ECB; AES-CBC outside
`internal/pki/pbes2.go`; and the rest of the list in
[security.md](security.md#fips-140-3-and-cmvp). Each rule's control is a file planted to
break it. **`pki.TestPBES2KnownAnswer`** holds an encrypted key's exact bytes under a fixed
salt and IV, which OpenSSL 3.5 opens to the same key; **`pki.TestEverySHA2PRFIsRead`** opens
that key as OpenSSL 4.1 encrypted it under PBKDF2 with HMAC-SHA-224, -384 and -512, each PRF
named as it is; **`pki.TestPBMAC1KnownAnswer`** holds a
PKCS#12 MAC to the digest Python's hashlib computes independently, and its parameters to RFC
9579's encoding; and **`pki.TestShowGoldens`** holds what
`cert show` prints of committed certificates, a request, a list and a public key, in
`internal/pki/testdata/show/`. They are public material alone; the keys that made them were
thrown away. `make golden` rewrites them with the argv goldens after an intended change.
**`cli.TestAManagedCAEndToEnd`** is the toolkit whole: a managed CA with an ML-DSA-87 root and
an ML-DSA-65 issuing CA issues a server certificate, a FIPS 140-3 mode client reaches it over a
hybrid group with its authentication pqc throughout, and once revoked `verify` fails it against
the CA's own lists; an ECDSA leaf from the same CA is classical.

**No test reaches a live API.** A configuration or a client that names no API enrols at
production's, so under `go test` the default is `https://127.0.0.1:1`, where nothing answers:
every package whose tests link `internal/config` imports `internal/apitest`, which sets it for
the whole test binary, and `apitest.TestEveryTestBinaryLinkingConfigImportsIt` reads the tree
for a package that does not. A test that wants a server names one, an `httptest` stand-in's.
Only `make integration` enrols, against `$VEILNET_API`.

**`enrol.TestWithRenewalIsLossless`** renews a manifest and compares every field.
Four are meant to change — `chain`, `notAfter`, `issuedAt` and `bootstrap`, which the
issuer's answer refreshes — and every other must not, `taints` above all. The document
carries fields conflux never reads — `genesis`, which anchor does, and `realm`, which
anchor carries — beside `renewalAuth`, which only conflux reads and a renewal must keep,
and `taints`, which the chain commits to. Round-tripping through a struct with only the
known fields would delete them on the first renewal, and the anchor would come back
after the next reboot unable to start — days later, with nothing pointing at the
renewal that caused it.

## Testing the boot service

The part that matters most is the hardest to check: that a machine which was up before
is up again afterwards with nothing typed. A container that boots systemd is the way,
and restarting it is the reboot.

`test/systemd/Dockerfile` builds a Debian 13 image running `systemd` as PID 1. Copy a
built `conflux` in beside it, then:

```console
$ make anchor-bins && make integration   # the whole suite, four nodes
$ make service-test                      # or just the unit, which enrols nothing
```

By hand, which is what those run:

```console
$ make anchor-bins && make image
$ docker run -d --name cfx-a --privileged --cgroupns=host \
    -v /sys/fs/cgroup:/sys/fs/cgroup:rw --device /dev/net/tun conflux-systemd-test
$ docker exec cfx-a conflux up --taint mynet --ipv4 10.128.0.1/24
$ docker restart cfx-a && sleep 25
$ docker exec cfx-a conflux status      # same AnchorID, nothing typed
```

A second container joining with the same taint gives a real two-node reachability
test. The suite polls every second for up to two minutes and prints how long it took —
around five seconds on the Docker bridge — and `conflux peers` shows `DATA yes` on
the peer once the taints have been compared.

Before B joins, A is held to its credential. The credential must grant the run's taint;
an `up --taint` naming another is refused, naming `conflux uninstall`, with the identity
and the credential left as they were; and `conflux renew` against the live API must
install a fresh chain hot with the identity and the taint unchanged — the running anchor
refuses a chain granting any other set, so a hot install that succeeds is the proof the
renewal restated it. Once B is up, the realm's control is shown to pass through:
`conflux blocks` prints anchorctl's table, and `conflux telemetry -from` B's AnchorID is
refused for want of the capability, since an alpha credential grants none.

A reboot proves a machine comes back; the suite also kills `anchord` on a running one,
with `SIGKILL` so nothing is said on the way out, and requires the supervisor to bring
it back — a new process, the readiness marker rewritten, the same identity, and the
peer reachable again at its IPv6 address — without a reboot or anything typed.

Every anchord in it is conflux's own account with `CAP_NET_ADMIN` alone — read from
`/proc` after `up`, after the reboot and after the kill, and from `status` — so the realm,
the overlay, the pings and the reboot are all proved of an anchord that is not root. The
image sets `/dev/net/tun` to `0666` at every boot through `tmpfiles.d`, as a stock host's
udev leaves it, so this holds whatever the runner's own device is.

All of that is `make integration`. `make service-test` is the unit on its own and enrols
nothing: `install` registers it without starting anything, the unit runs the root-only
copy in `/var/lib/.conflux` rather than the file conflux was run from, and `uninstall`
leaves no unit file, no `wants` link, no `/var/lib/.conflux`, and no `conflux` account. Both build the image first, and CI runs the same
command a developer does.

In between, it takes every branch of what `anchord` runs as, under the real unit. Its
configuration names an API that a `silent.socket` in the container accepts and never
answers, so `anchord` stays up while the enrolment waits, and each leg reads its uid,
capabilities, `no_new_privs` and groups from `/proc` and the reason from `status`:

| leg | anchord |
|---|---|
| userspace, and again after a restart | the account, no capabilities (`CAP_NET_ADMIN` where the host's `rmem_max`/`wmem_max` are low), `no_new_privs`; the state and run directories `710 root conflux`, its own `0700`, the token root's |
| port 443 | the account with `CAP_NET_BIND_SERVICE` |
| an uplink device of `dialout`'s, then one of root's | the account in `dialout`; then root, naming the device |
| a TUN, `/dev/net/tun` opened up | the account with `CAP_NET_ADMIN` alone |
| a TUN, `/dev/net/tun` root's | root, in `anchor.root/`, which got the account's file and not its symlink or hard link to a file of root's |
| stand-ins for firewalld and for legacy iptables | root, naming each |
| a stand-in for iptables on nf_tables, no nft | the account with `CAP_NET_ADMIN` and `CAP_NET_RAW` |
| back to userspace | the account, starting from root's state, as its own |
| observing alone | the account with `CAP_NET_RAW` alone, `no_new_privs` |
| the observer beside userspace, and beside a TUN | the mode's own, and `CAP_NET_RAW` |
| `start` with the unit running a changed copy | the service stopped, as systemd says it runs, and started again on this conflux, the copy replaced, never refused as a supervisor run by hand |
| `start` over an older unit | the unit replaced by this conflux's |
| an account named `conflux` that conflux did not make | root, saying so; `uninstall` leaves the account |

What `anchord` is given to observe with is decided as it is started, before any credential, so
the suite takes it; the observer itself runs only under the machine's credential, so that it
runs, is renewed, and records into the inventory and to a collector is `make integration`'s.

`test/service-host.sh` is the same lifecycle against launchd and the SCM, on the machine
itself, which is why only a CI runner that is thrown away afterwards runs it. On macOS a
`CONFLUX_DIR` under a directory whose ACL lets `nobody` write must have its root made, nothing
above a root judged; the root, once it carries such an entry, must be refused by `status`, naming
the ACL, and pass once only an `everyone deny delete` entry is left, the kernel's answer read as
conflux reads it nowhere else in CI. Then `install`
registers and starts nothing — on Windows with the three restarts and recovery that
covers a service stopping with an error — `status` exits 78 and says the service is
installed and not running, `down` succeeds on it, a userspace configuration started
through the service manager runs `anchord` as `_conflux` or `LOCAL SERVICE` and gets as far
as enrolling, which it does only once `anchord` has answered on the socket it made as that
account. An observing configuration starts `anchord` as that account too, with only what
capturing needs — on macOS the BPF devices given to its group — before any credential, and so
before the observer, which runs only under one; and an ephemeral run killed
outright takes its `anchord` with it on Windows, in its job, and on macOS leaves it for the
next run to stop. `uninstall` leaves no plist, no entry in launchd's disabled database, no
`_conflux` or `_conflux-ephemeral` account, the BPF devices root's again, no SCM service, no
directory, and no root a killed ephemeral run left.

`test/service-bsd.sh` is the same against `rc.subr`, in a FreeBSD and an OpenBSD VM. First
`conflux version` must report the FIPS 140-3 mode the build carries, and `conflux cert` make and
verify an ML-DSA certificate on FreeBSD and refuse with 70 on OpenBSD, which runs without the
module. On FreeBSD a `CONFLUX_DIR` under a directory whose ACL lets `nobody` write must have its
root made, nothing above a root judged; the root, once it carries such an entry, must be refused by
`status`, naming the ACL, and pass once the ACL is taken off, on a memory disk of each kind the
kernel keeps — POSIX.1e (UFS with `acls`) and NFSv4 (UFS with `nfsv4acls`, as ZFS keeps them) —
which no other job reads. Then install, a userspace `anchord` running as `conflux` or `_conflux` (the record, and
the process itself), port 80 and a TUN keeping it root with their reasons, the observer refused
for want of a capture, an ephemeral run killed outright leaving its `anchord` for the next run
to stop, and `uninstall` leaving no script, no directory, neither account, nothing enabling it
in `rc.conf` or `rc.conf.local`, and on FreeBSD no log.

### Local network discovery, the bootstrap list, and `conflux enrol`

Two containers on one Docker bridge are on the same link, which is the one thing no Go
test in this tree can arrange: a real kernel, real multicast, a real answer. anchor
probes the link only until its first connection, though, and the live realm answers
within a second — so A and B are started with `--peers 192.0.2.1:4700`, an RFC 5737
documentation address that never answers, in place of the realm's own list. The only way
they can meet is then discovery on the bridge: their reachability proves it, and
`make integration` asserts `anchor_lan_peers_found_total` is **non-zero** on one of them
— non-zero rather than present, because the assertion is that the probe found a peer,
and a check for the name alone would pass on whatever else writes it. Reachability is waited for in both directions, since each learns the other's
IPv4 from a signed advertisement and the two need not arrive together.

The third node takes the other paths, and with the ephemeral fourth it is why the suite enrols
five times:

- **It is enrolled from a live alpha manifest** — fetched on the host with
  `POST /ghosts/alpha` carrying `{"taints": ["$TAINT"]}`, and handed to
  `conflux enrol --manifest -` on stdin. Its credential must grant the run's taint;
  `up --taint "$TAINT"`, restating it, is accepted; and `up` must start from the
  manifest without enrolling again. That is the path a commissioned machine takes, and otherwise
  it would only ever see hand-written fixtures.
- **It reaches the realm through the manifest's own bootstrap list.** It names no
  `--peers` and runs `--lan-discovery no`, and A and B reach no realm node themselves,
  so a connection can only have come from the list the issuer shipped.
- **Its discovery counter stays at zero** on the link where A and B found each other,
  which proves `--lan-discovery no` reached anchor rather than being accepted by conflux
  and dropped.
- **Switched to `conflux observe --export`**, at a collector container that logs every record
  it is sent, it runs the observer and no anchor on the credential it holds, enrolling nothing:
  status shows the observer capturing, names C's identity, which the supervisor logs the
  observer running as, and says where the records go. `conflux renew` must reach the observer,
  its credential's expiry moving on with it still capturing — and the renewal's own HTTPS
  exchange is what it records: a connection to port 443 in `conflux inventory`, and its record,
  key exchange and all, at the collector.

A fourth node, D, runs **ephemeral** ([ephemeral.md](ephemeral.md)), and enrols twice more:

- `up --ephemeral`, enrolled in memory, must be reached by A over the overlay, with no
  configuration, manifest or state in `/var/lib/.conflux`, no unit, and none anywhere in its root,
  `/var/lib/.conflux/ephemeral`, and its anchord running as `conflux-ephemeral` with
  `CAP_NET_ADMIN` alone. SIGTERM must leave no anchord, no root and no interface, and the
  account, which is kept; the `.conflux` it made for its root goes with it.
- `proxy --ephemeral --manifest -`, from an alpha manifest piped in, must have
  `conflux uninstall` refused while it runs, since uninstall removes the account its anchord
  runs as, and nothing changed. Killed with SIGKILL, its anchord must go with it: the
  parent-death signal it was started with. Started again on the same credential, the run
  clears what the killed one left and comes up. Killed once more, what it leaves — its root
  under `/var/lib/.conflux/ephemeral` — is removed by `uninstall`, with the `conflux-ephemeral`
  account.

Note what discovery cannot do, and anchor's own `docs/discovery.md` is the reference:
the probe is sealed under the realm's **root public key**, which a node only holds after
it has enrolled. So it never replaces enrolment — it decides who is worth dialling,
never who is let in. Loopback is not probed, so two anchors on one machine still need
`--peers`.

## What CI runs, and on what

**The tests run with the FIPS 140-3 module refusing what it does not approve**:
`GODEBUG=fips140=only`, set on the test binaries alone through `go test -exec`, in `make test`,
`make race` and every CI job that tests. A non-approved algorithm, or an approved one used
outside its approved parameters, is then an error or a panic rather than a passing test. Every
build CI makes is against the module, as a release is ([build.md](build.md#fips-140-3)), and
`linux` also checks that the binary that ships passes the module's integrity check and refuses
to run with the mode switched off.

CI verifies that the code builds and runs. The utility checks — `gofmt`, `staticcheck`,
`go mod tidy`, the docs links, which `make all` runs, and `govulncheck`, `actionlint` and
`shellcheck`, which it does not since they need the network or tools of their own — run
on a developer's machine before a push, and not in CI.

Every job fetches the **pinned** release build of `veil-net/anchor` for the base it runs
against — `dev-latest` for a pull request into `dev` and a push to it, `latest` for
`version3` — and verifies every digest, with no anchor checkout. It needs a
credential, since anchor is private: CI stores a GitHub App's Client ID and private key and
mints an hour-long token per job, so the secret held here is not itself a key to
anything — see [build.md](build.md) for why the grant is wider than it wants to be and
why it is nonetheless contained.

| job | machine | what it runs |
|---|---|---|
| `linux` | veilnet-dev | the whole suite under `-race` and `fips140=only` with the real binaries and nothing skipped; `make cross`; the digests `make build` stamps are the pair's own; the built conflux in FIPS 140-3 mode, its integrity check passing, and refusing to run with the mode off; `conflux cert probe` handshaking, in that mode, with every host conflux reaches (both APIs, GitHub's API, web and asset hosts, wintun.net) |
| `integration` | GitHub Ubuntu | `test/preflight.sh`, then `make -j2 -O service-test integration` — `dist` with the size gate for every target and the image, once, then the boot service, three nodes and an ephemeral fourth against the live API of the base's tree (`$VEILNET_API`) side by side |
| `bsd` | FreeBSD 15.1 and OpenBSD 7.9, each a VM on GitHub Ubuntu | `test/service-bsd.sh` against `rc.subr`, with that platform's own pair; FreeBSD's conflux in FIPS 140-3 mode, making and verifying an ML-DSA certificate, and a root refused for its own POSIX.1e or NFSv4 ACL, nothing above it judged; OpenBSD's without the module, its `conflux cert` refusing with 70 |
| `platforms` | GitHub macOS, Windows and Linux arm64 | the suite under `fips140=only` with that platform's own pair, built as a release is (`CGO_ENABLED=0`, `-trimpath`), the tests that need the pair included; on macOS and Windows, `test/service-host.sh` against the real service manager; on Windows, that the pinned wintun digest is the published one; then the install scripts against the published `latest`, run as a person runs them and then again: `install.sh` on macOS and Linux arm64, `install.ps1` under Windows PowerShell 5.1 and then PowerShell 7 |

`linux` is one job because veilnet-dev is one machine with one runner process: separate
jobs would queue anyway, each paying a checkout and a fetch. Its fetch goes through the
runner's tool cache, which survives between runs, so an unchanged release costs a read of
the files the fetcher already holds rather than hundreds of megabytes. For the same
reason the Go build and module caches are not restored or saved there: the machine keeps
its own on disk, and round-tripping them through the Actions cache cost ten minutes a
run where the suite itself takes seconds. The hosted jobs start empty and do use it,
`integration` and each BSD job under a key of its own, since they build different things on the
same runner image and would otherwise share setup-go's one. The container
suites run on a hosted runner instead, because the third integration node reaches the
realm through its manifest's bootstrap node over UDP, and from veilnet-dev no handshake
gets through to it. No checkout leaves its token in `.git/config`, and every action outside
this repository is pinned to its release's commit, with the tag beside it in a comment.

**A fork's pull request from anyone outside the organisation and its collaborators runs
nothing until a maintainer approves it, and none ever does.** That is the fork guard: the
repository's setting that a run for a pull request from anyone who is neither a member of the
organisation nor a collaborator on this repository waits for a maintainer's approval
(`approval_policy: all_external_contributors`, under Settings, Actions, General). A machine
that survives the job does not run a stranger's code, and the hosted jobs need the anchor
credential a fork is not given, so such a run is never approved: its branch is pushed here
instead and tested from there. Unapproved, the run never starts, so the required checks never
report and the pull request cannot merge. A member's or a collaborator's fork is not held by
the setting: its pull request runs unapproved, from its own copies of the workflows and of
`scripts/branch-flow.sh`, held only by the refusals in them — each job's `if:` in `ci.yml`,
and `branch-flow`, which fails a fork's pull request — and it can edit those out. So adding a
member or a collaborator extends trust in the self-hosted runner to them. The setting stays as
it is; a change to it, or to who is a member or a collaborator, is a change to the threat
model. The refusals are a second line, for a run approved by mistake, and not the guard.

### Branches

Two long-lived branches, and every change reaches both the same way:

| Branch | Takes | A merge publishes | Embeds anchor's |
|---|---|---|---|
| `dev` | a pull request from a feature or maintenance branch cut from `dev` | the pre-release `dev-latest` | `dev-latest` |
| `version3` | a pull request from `dev`, opened by the owner | the release: `VERSION`'s tag and `latest` | `latest` |

1. Cut a branch from `dev`, do the work, and open its pull request against `dev`
   (`gh pr create --base dev`: `version3` is the default branch, so the base is always
   named). CI runs in full on it, against anchor's `dev-latest`.
2. Merged when it is green, it is published as the pre-release `dev-latest`, which the next
   merge into `dev` replaces and which nothing reads unless asked for it by name:
   `CONFLUX_VERSION=dev-latest` for the install scripts ([install.md](install.md)).
3. When `dev` is to be released, the owner opens a pull request from `dev` into `version3`.
   CI runs on it in full again, against anchor's `latest`; merged, it is released, and
   `version3` is merged back into `dev`.

**`dev` stays ahead of `version3`.** Nothing reaches `version3` but `dev`, and after every
release `release.yml`'s `back-merge` job (`scripts/back-merge.sh`) pushes the release back to
`dev`: a fast-forward, since the release is a merge whose second parent is `dev`'s tip, or a
merge where `dev` has taken something since. A release that will not merge cleanly is one that
holds something pushed to `version3` directly, and the job stops and says so; so does a push
refused because `dev` moved while the job ran, which a second run of it settles. The checkout
persists no token: the script gives the workflow's to git through git's environment, for the
push alone.

**`branch-flow.yml` holds the branches to that** (`scripts/branch-flow.sh`), on every pull
request and every edit of one — moving a pull request's base fires only `edited`: one from a
fork fails, whatever its base, as the second line behind the approval setting above; one into
`version3` whose head is not `dev` fails; one into `dev` whose merge does not hold `version3`'s
tip — a back-merge that did not land — fails; one into any other base fails. On a hosted
runner, since it reads the repository and holds no secret.

**Branch protection, on `dev` and on `version3` alike:** require a pull request, require CI's
checks and `branch-flow`, and require the branch to be up to date before merging. And on `dev`,
let the release workflow push, for the back-merge: GitHub Actions on a ruleset's bypass list.
Without that the push is refused, the release is out regardless, and `back-merge` fails saying
what to do: merge `version3` into `dev` by pull request.

**The release** runs on every push to `dev` or `version3`, a merge included, and it only
releases: it does not re-run any of the above. A merge lands only when CI is green, which rests
on that branch protection, and is unsafe without it. It refuses to run anywhere but those two,
fetches anchor's `dev-latest` on `dev` and its `latest` on `version3`, runs `make dist`, attests
the artifacts and writes one set of notes: the changes since the previous version — on
`version3` the pull requests `dev` merged, read from the `dev` side of the release's merge — and
what is inside. On `dev` it publishes the pre-release `dev-latest`, never Latest. On `version3`
it publishes twice, with the same artifacts and notes: at the tag the `VERSION` file names,
verbatim, and at `latest`, which is the repository's Latest release; then `back-merge` runs.
Each is deleted, with its tag, just before it is released again, so a push that leaves
`VERSION` alone replaces that version's release with one built from the commit that
landed, tag and all. anchor's `latest` moves, so a release carries whatever anchor
published most recently, which is the intent — conflux ships the newest anchor, not a
remembered one. All seven targets are cross-built from the one Linux machine,
`CGO_ENABLED=0` throughout. See [build.md](build.md#version-stamping) for how `VERSION`
moves.

**The binaries CI uses are the pinned ones**, which a locally-built `make dist` cannot
be: an anchor pinned to the genesis realm refuses to handshake with any other tree. So
`integration` exercises the binaries that ship, in **the tree they are pinned to** and
nothing else — the dev tree on a pull request into `dev`, the production one on the one
into `version3` ([The genesis node](#the-genesis-node)) — and a join there proves the pin
as well as conflux.

**A machine that is not thrown away.** Both container suites reap their fixed container
names before themselves as well as after, because a cancelled run fires no `EXIT` trap,
and on a developer's machine the leftover name fails the *next* run for a reason that
has nothing to do with the commit under test. `test/preflight.sh` says what
the machine gives them — Docker, `/dev/net/tun`, the cgroup mount (v2, or v1, which
works), IPv6 — before anything is built, because each of those otherwise fails much
later and names something else. The runner may be root, so
`TestWriteAtomicPreservesOnFailure` probes whether making a directory read-only took
rather than assuming it did, and the privilege refusal's test stubs the check rather
than skipping.

## The genesis node

There are two trees, and a build belongs to one of them by the anchor it embeds:

| Build | Embeds | Pinned to | Enrols at | Bootstrap the manifest names |
|---|---|---|---|---|
| a release, from `version3` | anchor's `latest` | the production genesis | `https://api.veilnet.com.au` | `genesis.veilnet.com.au:4700` |
| a dev build, from `dev` | anchor's `dev-latest` | the dev genesis | `https://api-dev.veilnet.com.au` | `genesis.veilnet.com.au:4701` |

A dev build cannot join the production tree, nor a release the dev one: each anchord
refuses a credential under a root other than its pin. conflux's default API is the
production one in every build, so a dev build is given the dev API with `--api`, as CI's
live suite does.

conflux never names a bootstrap node itself and must never: end users get their
bootstrap list from the enrolment manifest, which is what lets the API move a node
without touching a single machine. To exercise `--peers`, point a dev build at the dev
genesis explicitly:

```console
$ sudo CONFLUX_DIR=/var/lib/cfx-dev conflux proxy --api https://api-dev.veilnet.com.au \
      --peers genesis.veilnet.com.au:4701 8080=127.0.0.1:3000
$ sudo CONFLUX_DIR=/var/lib/cfx-dev conflux status  # peers > 0, up=yes
```

`CONFLUX_DIR` roots the whole installation somewhere else — the config, the identity,
the state, the socket, **and the boot service** — in `.conflux`, a folder conflux owns, makes inside
the directory it names, remakes as it makes it and removes at `uninstall`. The directory itself, and
every folder above it, is never changed and never judged: choosing it is yours. Port 4700 is UDP; a TCP probe of it is
refused, and that is expected rather than a fault.

The service is included because it has to be. A run rooted elsewhere is a separate
installation of conflux, not the machine's own, so:

- the service is named after the root — `conflux-e7616592.service`,
  `org.veilnet.conflux-e7616592`, or the same SCM entry — and cannot be registered
  over a real node's;
- the root is written into the argv the service is registered with, because no
  service manager carries the operator's environment into what it starts; without it
  the service would come back at boot reading the machine's own `.conflux`.

So a dev run and a real node coexist on one machine:

```console
$ conflux status                                    # the machine's own
  service      active (systemd: conflux.service, enabled at boot)
$ CONFLUX_DIR=/var/lib/cfx-dev conflux status       # the dev one
  service      active (systemd: conflux-e7616592.service, enabled at boot)
```

**The dev one runs in userspace, as above.** A host runs one TUN anchor. Two do not
collide on the interface's name, which each anchor takes from its own identity, but
they share everything else a TUN anchor sets up on the host — its routes, forwarding and
firewall rules, which carry fixed names — so a second's start replaces the first's and
its stop removes them (anchor's `docs/operations.md`, "Deploying"). That is the one thing
`CONFLUX_DIR` cannot separate, because the host's networking belongs to the host and not
to a conflux installation. `conflux proxy` sets nothing on the host up.

**Not `/tmp`.** systemd clears it on boot, so a dev root there is gone by the time the
service starts and the unit exits 78 — correctly, but it makes the reboot test
meaningless. Anywhere persistent will do.

Two things worth checking deliberately, because neither is obvious from a passing run:

- **The no-flag path still works.** `conflux up` with no `--peers` must bootstrap from
  the manifest's own list — `make integration` asserts it for its third node, and a dev
  node named `--peers` is exactly the case that would not notice it breaking.
- **The realm matches.** The embedded binaries are pinned to a genesis realm ID at
  build time (`-X anchor.pinnedGenesis`, see [build.md](build.md)). A test node minted
  from a different root will enrol fine and then never handshake, because the pin is
  what refuses it. That failure is on the anchor side, not conflux's.

  Each genesis node answers only a build carrying its tree's pin — `:4701` a dev build's,
  `:4700` a release's: `make anchor-bins FETCH=1` prints the realm the binaries it fetched
  are pinned to, and a local `make release` pins whatever `genesis/genesis.pin` says.

## The other half of the contract is tested in the other repository

`renewalAuth`, `conflux enrol` and the `export` block are half of an exchange
whose other half is guardian. Everything here asserts what conflux *sends* and
what it *accepts*; nothing here can assert that a document guardian writes is one
conflux installs, because no guardian is running.

That test lives in guardian, at `api/test/conflux.e2e-spec.ts`. It builds a
machine image from **this checkout's** `bin/conflux` — so what runs is what this
repository currently produces, not a release that may predate the change — puts
it on the deployment's own network, and drives the whole life of a node:

```
commission → conflux enrol → conflux up → conflux renew → reboot → same anchor
```

The reboot is the one that matters most and is hardest to fake. An overlay
address is derived from an identity, so a machine that comes back as a different
anchor has silently orphaned every peer that knew it — which is what a renewal
falling back to enrolment would do. Restarting the container is the reboot.

It needs `make build` here first, and refuses rather than skipping when the
checkout is missing: a suite that quietly covers nothing is one that covers
nothing on CI the day somebody moves a directory.

The shape of the exchange is written down once, in
[guardian's contract document](https://github.com/veil-net/guardian/blob/main/docs/contracts/guardian-node.md).

## What has no coverage, and why

- **FreeBSD and OpenBSD's Go suite.** `make cross` vets it and the `bsd` job runs the
  service under `rc.subr` in a VM, but the suite itself does not run there.
- **What anchord runs as, for the cases no runner has.** A TUN as the account against a
  real firewalld, or a real legacy iptables, or a router with ipset: CI stands in for the
  tools to take each decision, and anchor's own suite tests what they do. A kernel without
  an ambient set. A container whose supervisor has too few capabilities to drop. These
  are `decide`'s and `canGive`'s table tests.
- **macOS Local Network privacy for a LaunchDaemon's child that is `_conflux`.** No runner
  has a second machine on its network to be blocked from.
- **macOS TUN under a LaunchDaemon.** CI can build and test on macOS, but not open a
  utun from a system daemon.
- **The Windows service's recovery in action.** `test/service-host.sh` checks the
  actions and the flag are registered; nothing makes a supervisor fail under the SCM
  to watch it come back.
- **A real uplink.** What is covered here is the spec parser, the argv, the refusals
  — the `fd:N` form conflux's supervisor cannot hand over, and Windows, where anchor
  has no way to open a link — and the link watcher's decision function against
  synthetic inputs. Nothing in this tree opens a device or a pseudo-terminal: the link
  itself is anchor's to test, and it does, over a real pty. Two machines on a cable
  have no runner, so the watcher's *reopen* path is reasoned about rather than run.
- **A Windows TUN, and an anchor that runs.** The `platforms` job starts the supervisor
  under the SCM and launchd, and an `anchord` as `LOCAL SERVICE` and `_conflux` that answers
  on its socket, but none enrols, and no job opens a wintun interface.

- **`conflux cert` against OpenSSL.** OpenSSL 3.5 is the first to read ML-DSA and no runner
  ships it, so the interop in [cert.md](cert.md#checked-against-openssl) was checked by hand,
  in a container, TLS both ways included; the PBES2 known answer is what CI keeps of it. The passphrase prompt's
  echo, too, is checked by hand under a pseudo-terminal: CI has no terminal, and the tests
  replace the one it opens.

A local fake for the enrolment API is used for the client's error paths, but it cannot
stand in for a full end-to-end test: the shipped `anchord` is pinned — a release's to the
production genesis, a dev build's to the dev genesis — and the `anchorctl` beside it is the lockdown build, so nothing can mint a
credential those binaries will accept.
