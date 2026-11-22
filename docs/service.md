# The boot service

## What it does at boot

The service manager runs one process: `conflux serve`. That process is the supervisor,
and it is not itself the daemon:

```
systemd / launchd / rc / SCM
  └── conflux serve                     root, or SYSTEM
        ├── anchord -socket … -config …   its own account wherever that costs it nothing
        ├── the renewal timer, for the anchor and the observer
        ├── the watcher: a lost anchor, on an uplink an ended link, and an observer whose capture ended or that did not start
        └── the restart loop
```

Registering `anchord` directly was the obvious alternative and does not work: anchord
is configured with nothing and holds no anchor until something calls `start` over its
socket. Something has to make that call, and it may as well be the thing the service
manager watches.

At every boot the supervisor makes its roots as every command makes them, but for the copy of
conflux it runs from, takes the root's `serve.lock` — one supervisor per root — places that copy
afresh from its own image where it is not there or not as conflux makes it, failing the start where
it cannot, stops any `anchord` a supervisor that died left running (below), reads `conflux.json`,
extracts the anchor pair if it is not already on disk, writes a fresh bearer token,
decides what `anchord` runs as — its own account, with exactly the capabilities its mode
needs, wherever that costs it nothing; see [security.md](security.md#what-anchord-runs-as)
— makes the account the first time, lays out the directories that identity reaches,
starts `anchord`, waits until it answers an authenticated `status` call, enrols the machine if
it holds no credential or renews the one it holds if it is past two thirds of its window,
starts the observer where the configuration observes, and starts the anchor. No prompts, and
nothing typed.

The credential comes first because the observer runs under it as the anchor does, handed the
same manifest on stdin, so an enrolment the API does not answer starts neither, and the restart
loop tries again. The observer comes next, and is started on every start because anchord keeps
none across one; observing alone, it is what readiness waits for, and the identity it reports
running as is the AnchorID renewals name. Beside an anchor, an anchor that then cannot come up,
for now or refused for good, leaves the daemon running, and with it the observer and the
inventory it holds, for the watcher to bring the anchor up when it can, or to give up on it
alone. The renewal timer runs whatever the configuration
runs, and installs each renewed chain in the anchor and in the observer. anchord serves the
observer always; what lets it capture is the privilege the supervisor gives it, only where the
configuration observes. See [observe.md](observe.md). A start that fails because the decision no longer fits — the first
enrolment named a port below 1024, an uplink's device appeared — starts `anchord` again
with what it now needs.

Readiness is a real probe and not a sleep. A socket file on disk proves nothing —
a crashed daemon leaves one behind — so the supervisor polls until `anchorctl status`
succeeds, which proves the socket is bound, gRPC is serving, and the two sides agree
on the token. It also watches the child, so a daemon that dies during startup is
reported at once, with its own last lines attached, rather than after a timeout.

Once the anchor is up — or, observing alone, the observer — the supervisor writes a
**readiness marker** at `<run>/ready`, and removes it when the anchor goes. It is how `conflux up` and `conflux start` learn
the anchor is up the moment it happens. systemd's `Type=notify` already gives Linux the
answer — `systemctl restart conflux` returns once the supervisor has sent `READY=1` —
but launchd, rc and the Windows SCM say nothing, and without the marker the wait there
would be a status call, and a fork, once a second.

The marker is advisory. Every reader falls back to the status call it replaced, so a
marker that is missing, stale or half-written costs a second and never a start. It lives
in the run directory rather than the state directory, which is what stops it outliving
the anchor it describes: most systems empty the run directory at boot, systemd's
`RuntimeDirectory=` empties it whenever the service stops, and the supervisor clears the
marker as it starts, for Windows, where neither happens. Every path that restarts the service
and waits for it clears it *before* registering it — before anything can start it, since on
macOS registering a running job whose definition changed starts it again — and never after,
so the marker that appears can only have been written by an instance started since:
otherwise `up` could report success for an anchor that was seconds from being torn down, or
miss the marker of the one that had just come up.

Shutdown runs in one order everywhere: stop the renewal timer, withdraw the readiness
marker, close the anchor so it says goodbye, and only then let the daemon go. The close
is the important step — an announced departure saves every peer from working it out by
timeout — and nothing is killed before it has happened.

On Unix the close is a `SIGTERM` to anchord's process group: anchord closes its anchor
on it, flushes its telemetry and exits, and the twenty-second grace before `SIGKILL` is
a real grace. Inside a Windows service no signal can be delivered at all, so there the
anchor is closed over the socket with `anchorctl stop` and the daemon, holding nothing
by then, is killed; see the Windows section. The observer is stopped over the socket first
there: its capture is a kernel trace session, which would go on copying every packet the
host carries after the daemon that started it was killed. A daemon that has already died is asked
nothing: there is no anchor left to close, and its pid may belong to something else.

### When the supervisor itself dies

A supervisor that is killed, rather than stopped, does not stop its `anchord`. systemd
ends the unit's whole cgroup, and the job object every `anchord` is put in on Windows ends
with the process that made it; but launchd ends the job's process group, which `anchord`
has its own of, and rc ends only the process it started. The `anchord` left behind keeps
the control socket and anchor's lock on it, so every `anchord` the next supervisor starts
is refused as "already served by a running daemon", and a node nobody can reach goes on
running beside a service retrying for ever.

So the supervisor writes down the `anchord` it starts — its pid and its executable, in
`<run>/anchord.pid` — and removes the record once it has waited for it. A supervisor that
finds a record stops what it names before it starts its own: `SIGTERM` to its group, then
`SIGKILL` past the same twenty seconds, or on Windows `TerminateProcess`. A pid is only a
number, so it is taken for `anchord` only when the process runs the recorded executable
or, on OpenBSD, which reports none, when something holds the socket's lock — which only a
daemon serving it does. That is safe only with one supervisor per root, which
`serve.lock` makes so: a second `conflux serve` beside the service is refused rather than
left to stop the first one's daemon. `conflux uninstall` does the same once the service is
removed, so nothing is left running out of the directory it deletes.

A start that fails is retried with a backoff up to thirty seconds. One that no retry
changes — a configuration conflux refuses, taints the credential does not grant, an
expired credential with nowhere to renew it or no AnchorID recorded to renew it with, a
credential for another realm tree, a TUN the host will not give, a host that will not
be set up to forward, an argument vector anchorctl refuses, a daemon socket conflux may not
reach or a token the daemon refuses — stops the supervisor after three attempts with exit
70, and nothing to start at all is exit 78. An anchor refused for good beside an observer that
is running is the exception: the observer goes on, and the watcher gives up on the anchor
alone, below. Anything else the
supervisor stops on — an extraction onto a full disk, say — exits 1, which systemd,
launchd and the Windows SCM restart. On the BSDs nothing does: FreeBSD's `daemon(8)` runs
without `-r`, which would restart 78 and 70 as well, and OpenBSD's `rc.subr` does not
supervise, so there a supervisor that exits 1 waits for `conflux start` or the next boot.
What each does with 78 and 70 is below.

anchord can also lose its anchor without exiting, so the supervisor asks it every thirty
seconds whether it still holds one (every ten, through the link watcher's gauge, on an
uplink) and rebuilds it through the same bring-up when it does not, and starts the observer
again whose capture ended or whose start beside the anchor failed. A rebuild or a start that
fails is tried again at the next look and then after twice as long each time, up to thirty
seconds. A blocked anchor is not one of these: a realm's block leaves it running, outside the
realm, and rebuilding it would change nothing. A rebuild refused for good three times in a row — a
`conflux.json` edited under a running service into one that will not build an anchor,
say — makes the watcher give up on the anchor and say so in the log: the service stays up
holding no anchor until it is started again with `conflux start` or a reboot. An observer
beside it goes on observing, and the renewal timer goes on keeping its credential current;
the same holds the other way round for an observer the host will not let capture, beside an
anchor. With nothing left running, the service renews nothing until it is started again.

## One machine, one service — unless CONFLUX_DIR says otherwise

The unit, the launchd label, the rc script and the SCM entry are all named `conflux`,
one per machine, which is what "one configuration per machine" means in practice.

A run under `CONFLUX_DIR` is the exception, because it is a separate installation and
not the machine's own: the service takes a suffix derived from the directory
(`conflux-44a6e4f4.service`, or `conflux_44a6e4f4` for rc, whose names become shell
variables), and the directory is written into the argv it is registered with, so the
supervisor comes back to the same `.conflux` inside it at boot. Its
`anchord` runs as an account of its own too, `conflux-44a6e4f4`, so a test root's daemon
never shares an identity with the machine's. None of this happens without `CONFLUX_DIR`, so an ordinary install is
byte-for-byte what it always was.
See [testing.md](testing.md).

## The four verbs, and which pair is which

Two pairs that are easy to confuse, because both look like they turn something off:

| | Pair | What it touches |
|---|---|---|
| now | `conflux start` / `conflux down` | the running anchor. The registration and the configuration are untouched, so a reboot behaves the same either way. |
| permanently | `conflux install` / `conflux uninstall` | the boot registration. `uninstall` also deletes the configuration, the identity and everything else conflux made ([commands.md](commands.md#conflux-uninstall)). |

`down` then `start` is the restart. `install` starts a configured machine as well, but
registration is its subject and starting is a side effect — `start` is the verb whose
subject is starting.

Neither `up` nor `proxy` belongs in that table: they decide the configuration and then
do both. `start` decides nothing, which is exactly what makes it the way back from
`down` on a userspace machine, where `up` would change the mode and drop the proxies.

## systemd

Unit at `/etc/systemd/system/conflux.service`, and `conflux install` writes it,
`daemon-reload`s and `enable`s it — or, finding that exact unit already there and
enabled, as every re-run of `up` and `proxy` does, leaves it be. **It does not start
it**; that is the caller's decision, and it is what lets `conflux install` register a
service on a machine that has no configuration yet. `ExecStart=` names the copy of conflux
kept in the state directory, which only root can change, never the file conflux was run
from; see [install.md](install.md).

```ini
[Unit]
Description=Conflux — VeilNet anchor
Documentation=https://github.com/veil-net/conflux
After=network-online.target
Wants=network-online.target

[Service]
Type=notify
NotifyAccess=main
ExecStart=/var/lib/.conflux/conflux serve
Restart=on-failure
RestartSec=5
RestartPreventExitStatus=78 70
TimeoutStartSec=90
TimeoutStopSec=30
KillMode=mixed
KillSignal=SIGTERM
User=root
Group=root
RuntimeDirectory=conflux
RuntimeDirectoryMode=0700
ConfigurationDirectory=conflux
ConfigurationDirectoryMode=0700
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
```

Four of those lines are worth explaining.

`Type=notify`, with `sd_notify` from the supervisor, makes `systemctl start conflux`
return when the anchor is genuinely up rather than when `fork` succeeded. Anything
ordered `After=conflux.service` gets the same guarantee for free. Beside an anchor that
cannot come up, the supervisor sends `READY=1` once the observer is running and writes
no marker: a unit still waiting at `TimeoutStartSec` would be failed and stopped, observer and
inventory with it, which an anchor that cannot come up must never cause. The Windows SCM is
told the same.

`RestartPreventExitStatus=78 70` is the two answers a restart would only repeat.
`conflux serve` exits 78 when there is nothing to start and 70 when it has given up on
something no retry changes; without this the unit would restart into the same answer
every five seconds forever, where it now shows as failed.

`Restart=on-failure`, not `always`, so a deliberate clean exit stays exited.

`up`, `proxy` and `start` clear a failed unit before they restart it. systemd refuses
every start of a unit started more than five times in ten seconds until the ten seconds
are up, and a few quick attempts at a configuration that does not work are enough to get
there; the operator's next start, with it fixed, is not one more of them.

`User=root` and no capability line. The supervisor is root, and it is the supervisor
that gives `anchord`, as an account of its own, exactly the capabilities its mode needs —
`CAP_NET_ADMIN` for a TUN, none in userspace — and nothing else. An
`AmbientCapabilities=` here would go to the supervisor, which as root has them all
anyway, and reach nothing more.

Four things are deliberately absent. Every directory setting — conflux makes its one root,
`.conflux`, and all it keeps in it, itself, as under every service manager — and
`StateDirectory=` above all, because systemd gives a directory it claims back to `User=` and
`Group=`, recursively, at every start once its top belongs to anybody else — and the root's
group is `anchord`'s account, so every start would hand `anchord`'s own directory back to
root. `PrivateTmp=`
would be pointless and confusing — nothing conflux does touches `/tmp`. `ProtectSystem=strict`
would need a `ReadWritePaths=` list. And `NoNewPrivileges=`, which would hold for a root
`anchord` too, where the host's firewall answers only root, and stop its firewall commands'
SELinux transitions; the supervisor sets `no_new_privs` itself on the `anchord` that runs
nothing.

`up`, `proxy`, `install`, `start` and `update` all register the unit as this conflux
writes it, which is nothing at all when it is already exactly that — so an upgrade's unit
reaches the machine with the upgrade.

Logs go to the journal: `journalctl -u conflux -n 50`.

## launchd

Job at `/Library/LaunchDaemons/org.veilnet.conflux.plist`, label `org.veilnet.conflux`.

`KeepAlive` is `{SuccessfulExit: false}` rather than `true`, so a deliberate clean exit
stays exited. launchd has no way to name the exit codes that should not restart, so a
supervisor launchd started (`XPC_SERVICE_NAME` is the job's label) that would exit 78 or 70
writes why to the log and exits 0 instead, which `KeepAlive` leaves stopped, as the Windows
SCM is told; `conflux up`, `proxy`, `observe` or `start` starts it again. `ProcessType`
is `Interactive` rather than the `Background` daemons default to, because `Background`
brings a low-priority I/O class and App Nap eligibility, and a networking daemon the
scheduler throttles is a support ticket nobody can diagnose.

**`install` writes the plist and starts nothing that is not running.** That is what
registration means here: launchd bootstraps everything in `/Library/LaunchDaemons` at boot,
so the file on disk is the registration and nothing about coming back after a reboot depends
on loading it now. Loading would also start it — `bootstrap` honours `RunAtLoad`, and
`launchd.plist(5)` says `KeepAlive` implies it — so `install` never loads a job that was not
loaded. A loaded job runs from the plist it was loaded with, though, not from the file, so
where `install` changed the plist — an upgrade moving the executable, say — a loaded job is
unloaded, and one that was running is loaded again at once, which restarts it on the new
plist rather than leaving it stopped. A plist already exactly as `install` would write it is
left alone, and the job with it, loaded or not.

| The job, where the plist changed | `install` |
|---|---|
| not loaded | writes the plist |
| loaded, stopped | `bootout` |
| loaded, running | `bootout`, then `bootstrap` — a restart |

So `restart` asks first whether the `install` before it has just started the job, and then
whether the job is loaded:

| State | `restart` |
|---|---|
| started by the `install` before it | nothing |
| not loaded | `bootstrap` — loading is the start |
| loaded | `kickstart -k` |

Re-running `bootstrap` on a loaded job fails with `Bootstrap failed: 37: Operation
already in progress`, and a `kickstart -k` on a job that was *just* bootstrapped kills the
instance launchd had only now made. Asking which state it is in is what avoids both.

**A disabled label is enabled before `bootstrap`, and `uninstall` disables nothing.**
`launchctl(1)`: *"Once a service is disabled, it cannot be loaded in the specified domain
until it is once again enabled. This state persists across boots of the device."* A
disabled label makes `bootstrap` fail with `Bootstrap failed: 5: Input/output error`,
which names nothing; a `bootstrap` that still fails is answered with the four things
that actually cause error 5. `enable` is run only for a label `launchctl print-disabled`
shows disabled, because an enable is itself an entry in that database, outliving the plist
where `uninstall` cannot reach it.

`conflux down` uses `launchctl kill SIGTERM`, which stops the process and leaves the job
loaded — stopped now, back at the next boot, which is exactly the semantics `down` needs —
and waits for it to go, as `systemctl stop` does. A job that is not running, loaded or not,
is already in the state `down` asks for, and says so rather than passing on launchd's
"Could not find service" or its refusal to signal a job with no process.

macOS needs no driver: `utun` is in the kernel and a root LaunchDaemon can open it.

Logs: `logs/conflux.log` in the root, `/Library/Application Support/.conflux/logs/conflux.log`,
which `uninstall` removes with the plist and the one moved aside, and with the root. The plist names it, for what conflux cannot write itself, and `serve --log` is how
conflux writes everything else there: each line stamped with the time in UTC, and the file
moved aside to `conflux.log.1`, replacing the one before, once it passes 10 MiB. The file
is placed over conflux's own standard output and error each time, so a crash lands in it too.

## The Windows service

Service name `conflux`, display name `VeilNet Conflux`, running as `LocalSystem`,
automatic at boot, depending on `Tcpip`, `Dnscache` and `NSI`. Recovery actions restart
it after 5, 10 and 30 seconds, the last repeating, and apply to a service that stops with
an error as well as to one that dies.

The service name has no space in it deliberately: a name with one makes every `sc.exe`
invocation quoting-sensitive for no benefit.

The stop handler cancels the supervisor's context, which runs the full shutdown.

The signal it would send cannot work here. `GenerateConsoleCtrlEvent` needs a console
shared with the target process and a service has none, so `CTRL_BREAK` is refused every
time conflux runs the way conflux actually runs on Windows. Shutdown knows it was never
delivered, closes the anchor over the socket with `anchorctl stop` instead, and kills a
daemon that is holding nothing rather than waiting out a grace for a signal nobody
sent. The graceful alternatives — a named event `anchord` waits on, or a
daemon-shutdown RPC — are `anchord`'s to offer and it offers neither.

A supervisor that stops on what the next start may not meet — exit 1 — reports a
service-specific error, which the recovery actions restart. One that stops on nothing to
start, or on a configuration no restart changes — 78 or 70 — reports a clean stop, so they
do not restart it into the same answer, and writes why to the log. The SCM is told once,
with that exit, when the handler returns. The service accepts Stop from the moment it
starts, so `conflux down`, a restart and `uninstall` need not wait out a bring-up that is
slow or keeps failing.

`conflux down`, a restart and `uninstall` return once the service's process has exited, not
when the SCM first reports it stopped — which it does from inside the process, while
`conflux.exe`, `anchord.exe` and the log are still open. `down` on a service that is already
stopped succeeds. Reading the service's state, as `conflux status` does, needs no more
access than any account has.

`install` on an existing service re-registers it with the same type it was created with;
`up` and `proxy` do that on every run.

Windows also needs `wintun.dll` for TUN mode; see [windows.md](windows.md).

Logs: a service has no console, so the supervisor writes what it and `anchord` say to
`%ProgramData%\.conflux\logs\conflux.log`, each line stamped with the time in UTC and the file
moved aside to `conflux.log.1` past 10 MiB, as on macOS; `uninstall` removes both with the
rest. The file is the service's standard output and error, so a crash lands in it too; they
let go of it for the moment it is moved aside, since Windows moves no file that is open. It is
opened once the supervisor has made the root as conflux makes one, `logs\` with it, each made
afresh where it was not; a root it refuses — one whose way cannot be walked, or one it could not
remove to make afresh — gets no log: the start ends as any failed start does, exit 1,
which the System event log records and the recovery actions retry, and `conflux install`, run by
hand, says why.

## rc: FreeBSD and OpenBSD

**FreeBSD.** Script at `/usr/local/etc/rc.d/conflux`, enabled with
`sysrc conflux_enable=YES`. It runs `conflux serve --log /var/db/.conflux/logs/conflux.log` under
`daemon(8)`, which backgrounds it and records conflux's own pid, and conflux writes the log
itself, stamped and moved aside to `conflux.log.1` past 10 MiB, as on macOS — so
`service conflux stop` signals the supervisor, which closes the anchor before anything
is killed. `daemon(8)` is not told to restart it: conflux restarts `anchord` itself, and a
supervisor that exits 78 or 70 would only repeat the answer. `conflux down` on a service
that is not running succeeds rather than passing on `rc.subr`'s "not running?".
`uninstall` stops it, removes the `rc.conf` line, the script and both logs.

**OpenBSD.** Script at `/etc/rc.d/conflux`, enabled with `rcctl enable conflux`.
`rc.subr` backgrounds it and sends its output to syslog, so the logs are in
`/var/log/daemon`. `uninstall` stops and disables it and removes the script.

Both find the running service again by matching its command line, unquoted — FreeBSD's
`rc.subr` the first word `ps` prints against `procname`, OpenBSD's `rcctl` the whole of it
as a pattern — and OpenBSD's runs it through a shell as well, so no quoting survives: a
`CONFLUX_DIR` root holding a space, or a shell or pattern character, is refused at
`install` rather than registered as a service that starts and can then be neither stopped
nor asked about.

On both, `install` enables and starts nothing, and `restart` starts a service that was
not running. One platform note: OpenBSD's `tunN` device persists after close, so
`conflux down` leaves the device node behind. The routes are withdrawn before the close;
the node itself is the platform's, not conflux's.

## Running it in the foreground

```console
$ sudo conflux serve --foreground
```

Not to be confused with an ephemeral run (`conflux up --ephemeral`, on Linux,
[ephemeral.md](ephemeral.md)), which is in the foreground too but registers no service,
reads no configuration and keeps nothing, and does not come back when anchord ends.

Runs the supervisor attached to the terminal, with anchord's own output prefixed. This
is the first thing to try when the service starts and the anchor does not — see
[troubleshooting.md](troubleshooting.md). Stop the service first: a second supervisor for
the same root is refused, since each stops the `anchord` the last one left. `anchord` is
given what the service would give it; on Windows, a console has no `SeTcbPrivilege` to log
`LOCAL SERVICE` on with, so there it runs as the console's account, and says so.
