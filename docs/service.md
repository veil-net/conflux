# The boot service

## What it does at boot

The service manager runs one process: `conflux serve`. That process is the supervisor,
and it is not itself the daemon:

```
systemd / launchd / rc / SCM
  └── conflux serve                     root, or SYSTEM
        ├── anchord -socket … -config …   its own account wherever that costs it nothing
        ├── the renewal timer, beside an anchor
        ├── the watcher: a lost anchor, on an uplink an ended link, and an observer whose capture ended
        └── the restart loop
```

Registering `anchord` directly was the obvious alternative and does not work: anchord
is configured with nothing and holds no anchor until something calls `start` over its
socket. Something has to make that call, and it may as well be the thing the service
manager watches.

At every boot the supervisor takes the root's `serve.lock` — one supervisor per root —
stops any `anchord` a supervisor that died left running (below), empties `run/`, reads
`conflux.json`, extracts the anchor pair if it is not already on disk and holds the one that is
to this build's SHA-256s — a binary changed on disk is extracted again rather than run, and a
pair whose files are as they were when last checked is taken on a stat of each, so a start
reads it only when something touched it — writes a fresh bearer token,
decides what `anchord` runs as — its own account, with exactly the capabilities its mode
needs, wherever that costs it nothing; see [security.md](security.md#what-anchord-runs-as)
— removes from the root, `run/` and the anchor directories whatever neither conflux nor anchor
put there ([config.md](config.md#where)), makes the account the first time, lays out the directories that identity reaches,
starts `anchord`, waits until it answers an authenticated `status` call, enrols the machine
if it has no credential yet or renews the one it has if it is past two thirds of its window,
starts the observer under it where the configuration observes, and starts the anchor. No
prompts, and nothing typed.

The credential comes first because both run under it: anchor's observer runs as the identity
the credential names, checked as an anchor's start is, and the manifest reaches it on
anchorctl's stdin, as it reaches the anchor. The observer comes before the anchor, and is
started on every start because anchord keeps none across one. Observing alone, there is no
anchor, and the observer is what readiness waits for; the AnchorID the observer reports in full
is what the credential is renewed by, and the renewal timer runs as it does beside an anchor.
Beside an anchor, an anchor that cannot come up for now — a start that fails — leaves the daemon
running, and with it the observer and the inventory it holds, for the watcher to bring the
anchor up when it can; a credential that cannot be had, an enrolment nobody answers, starts
neither, and the start is tried again. anchord serves the observer unasked, so nothing on its
command line says whether it observes. See [observe.md](observe.md). A start that fails because the decision no longer fits — the first
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
in `run/` rather than beside the state, which is what stops it outliving the anchor it
describes: `run/` is on disk with the rest of the root, so the supervisor empties it as it
starts — once it has stopped any `anchord` a dead supervisor left, which the record there
names (below) — and withdraws the marker on the way down. Every path that restarts the service
clears it *before* restarting, so the marker that appears afterwards can only have been
written by the instance that restart started — otherwise `up` could report success for an
anchor that was seconds from being torn down.

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
be set up to forward, an argument vector anchorctl refuses — stops the supervisor after
three attempts with exit 70, and nothing to start at all is exit 78. Anything else the
supervisor stops on — an extraction onto a full disk, say — exits 1, which systemd,
launchd and the Windows SCM restart. On the BSDs nothing does: FreeBSD's `daemon(8)` runs
without `-r`, which would restart 78 and 70 as well, and OpenBSD's `rc.subr` does not
supervise, so there a supervisor that exits 1 waits for `conflux start` or the next boot.
What each does with 78 and 70 is below.

anchord can also lose its anchor without exiting, so the supervisor asks it every thirty
seconds whether it still holds one (every ten, through the link watcher's gauge, on an
uplink) and rebuilds it through the same bring-up when it does not. A blocked anchor is
not one of these: a realm's block leaves it running, outside the realm, and rebuilding
it would change nothing. A rebuild refused for good three times in a row — a
`conflux.json` edited under a running service into one that will not build an anchor,
say — makes the watcher give up on the anchor and say so in the log: the service stays up
holding none until it is started again with `conflux start` or a reboot. The observer, where
it runs beside the anchor, outlives that: it goes on observing, renewed and watched as
before. With no observer, the service renews nothing until then.

## One machine, one service

There is one installation per machine, in its one root, and its service is named `conflux`
everywhere: the unit, the launchd label `org.veilnet.conflux`, the rc script and the SCM
entry. That is what "one configuration per machine" means in practice.

## The four verbs, and which pair is which

Two pairs that are easy to confuse, because both look like they turn something off:

| | Pair | What it touches |
|---|---|---|
| now | `conflux start` / `conflux down` | the running anchor. The registration and the configuration are untouched, so a reboot behaves the same either way. |
| permanently | `conflux install` / `conflux uninstall` | the boot registration. `uninstall` also deletes the configuration, the identity and conflux itself, leaving nothing. |

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
kept in `/var/lib/.conflux`, which only root can change, never the file conflux was run
from; see [install.md](install.md).

The registration is the supervisor's to keep, as the root is: every start places the copy it
runs again if it differs and puts the definition back to what this conflux writes — on
systemd removing every drop-in, which would change the unit that runs: `conflux.service.d/` in
`/etc/systemd/system`, and in `system.control`, where `systemctl set-property` writes, and the
same two under `/run` — so a unit, plist, rc script or SCM entry changed by hand lasts until the next start and no
longer. What is already that is not written again: an unchanged unit, plist or rc script keeps
its inode and its mtime, and the BSDs' `rc.conf` line is set only where the service is not
enabled. On macOS the plist is rewritten without unloading the job that is running it, and
takes effect at its next load.

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
LimitNOFILE=1048576
UMask=0077
PrivateTmp=yes
ProtectHome=read-only
ProtectClock=yes
ProtectHostname=yes
ProtectControlGroups=yes
LockPersonality=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
SystemCallArchitectures=native

[Install]
WantedBy=multi-user.target
```

A few of those lines are worth explaining.

`Type=notify`, with `sd_notify` from the supervisor, makes `systemctl start conflux`
return when the anchor is genuinely up rather than when `fork` succeeded. Anything
ordered `After=conflux.service` gets the same guarantee for free. Beside an anchor that
cannot come up for now, the supervisor sends `READY=1` once the observer is running and writes
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

The last ten lines are the protections a system service is given wherever they take nothing
the supervisor or `anchord` needs: nothing either creates is anybody else's to read
(`UMask=0077`), `/tmp` is the unit's own, home directories are read-only, and the clock, the
hostname, the cgroup tree, the execution domain, realtime scheduling, set-user-ID files and
foreign system-call ABIs are out of reach — for `anchord` and what it runs as well.

No `RuntimeDirectory=` or `ConfigurationDirectory=`: everything conflux keeps is in its one
root, which the supervisor makes and holds to its modes itself, `run/` included, which it
empties as it starts. A few more things are deliberately absent. `StateDirectory=`, because
systemd gives a directory it claims back to `User=` and `Group=`, recursively, at every
start once its top belongs to anybody else — and the root's group is `anchord`'s account,
so every start would hand `anchord`'s own directory back to root. `ProtectSystem=`, because
the supervisor writes `/etc`: the account `anchord` runs as, and its own unit when it puts it
back. `ProtectKernelTunables=` and `ProtectKernelModules=`, because anchor's router sets
sysctls and its firewall commands load modules. And `NoNewPrivileges=`, which would hold for
a root `anchord` too, where the host's firewall answers only root, and stop its firewall
commands' SELinux transitions; the supervisor sets `no_new_privs` itself on the `anchord`
that runs nothing.

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

**`install` writes the plist and loads nothing.** That is what registration means here:
launchd bootstraps everything in `/Library/LaunchDaemons` at boot, so the file on disk is
the registration and nothing about coming back after a reboot depends on loading it now.
Loading would also start it — `bootstrap` honours `RunAtLoad`, and `launchd.plist(5)`
says `KeepAlive` implies it — so `install` leaving the job unloaded is what makes the
caller's restart the one start.

So `restart` asks first whether the job is loaded:

| State | `restart` |
|---|---|
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

Logs are the system's: the unified log, which keeps and trims them. launchd keeps no
output, so the supervisor launchd starts hands its standard output and error to a
`logger -t conflux` of its own, in a process group of its own so it reads to the end of
what conflux wrote when the job is stopped, and a crash's trace goes the same way. The plist
names no file. `log show --last 1h --predicate 'process == "logger"' | grep conflux` reads them.

## The Windows service

Service name `conflux`, display name `VeilNet Conflux`, running as `LocalSystem`,
automatic at boot, depending on `Tcpip`, `Dnscache` and `NSI`. Recovery actions restart
it after 5, 10 and 30 seconds, the last repeating, and apply to a service that stops with
an error as well as to one that dies. It runs with a SID of its own, `NT SERVICE\conflux`
(an unrestricted SID type), and its DACL is set explicitly: SYSTEM and the Administrators
control it, and an interactive or a service account may ask what it is and how it runs, and
nothing more.

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
do not restart it into the same answer, and writes why to the log. A service that cannot make
its root at all stops as exit 1 does, and writes why to the log too. The SCM is told once,
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

Logs: a service has no console, so the supervisor writes what it and `anchord` say to the
Application event log, a line an event, under its own source, `conflux`, which `install`
registers with the system's own message file and `uninstall` removes; the events are the
log's, which Windows keeps and trims. `Get-WinEvent -FilterHashtable @{LogName='Application';
ProviderName='conflux'}` reads them.

## rc: FreeBSD and OpenBSD

**FreeBSD.** Script at `/usr/local/etc/rc.d/conflux`, enabled with
`sysrc conflux_enable=YES` where `service conflux enabled` says it is not. It runs `conflux serve` under `daemon(8)`, which backgrounds it,
sends its output to syslog tagged `conflux` (`/var/log/messages`), and records conflux's own
pid in the root, `/var/db/.conflux/rc.pid` — so `service conflux stop` signals the supervisor, which closes the anchor before anything
is killed. It starts after the network and `syslogd` (`REQUIRE: NETWORKING syslogd`), so
nothing it says before the system log is up is lost. `daemon(8)` is not told to restart it: conflux restarts `anchord` itself, and a
supervisor that exits 78 or 70 would only repeat the answer. `conflux down` on a service
that is not running succeeds rather than passing on `rc.subr`'s "not running?".
`uninstall` stops it, removes the `rc.conf` line and the script.

**OpenBSD.** Script at `/etc/rc.d/conflux`, enabled with `rcctl enable conflux` where
`rcctl get conflux status` says it is not.
`rc.subr` backgrounds it and sends its output to syslog, so the logs are in
`/var/log/daemon`. It runs it through `su(1)` under the login class named after the script
where there is one, and conflux writes one, `/etc/login.conf.d/conflux`: the `daemon` class,
which holds a process to 1,024 open files, with both limits raised to 1,048,576, as systemd's
`LimitNOFILE=` raises them, which the kernel holds to `kern.maxfiles`. `anchord` starts with
the supervisor's limit. `login.conf(5)` reads a class in `login.conf.d` before one of that
name in `/etc/login.conf`, and `cgetent(3)` reads a `cap_mkdb(1)` database in place of the file
beside it, so a `conflux.db` there is removed rather than left to stand for the class. Every
start puts the class back as conflux writes it. `uninstall` stops and disables the service
and removes the script and the class.

Both find the running service again by matching its command line, unquoted — FreeBSD's
`rc.subr` the first word `ps` prints against `procname`, OpenBSD's `rcctl` the whole of it
as a pattern — and OpenBSD's runs it through a shell as well, so no quoting survives. The
command line is held to letters, digits and `. _ - /`, which the BSDs' root,
`/var/db/.conflux`, keeps to; a word with anything else in it would be refused at `install`
rather than registered as a service that starts and can then be neither stopped nor asked
about.

On both, `install` enables and starts nothing, and `restart` starts a service that was
not running. One platform note: OpenBSD's `tunN` device persists after close, so
`conflux down` leaves the device node behind. The routes are withdrawn before the close;
the node itself is the platform's, not conflux's.

## Running it in the foreground

```console
$ sudo conflux serve --foreground
```

Not to be confused with an ephemeral run (`conflux up --ephemeral`,
[ephemeral.md](ephemeral.md)), which is in the foreground too but registers no service,
reads no configuration and keeps nothing, and does not come back when anchord ends.

Runs the supervisor attached to the terminal, with anchord's own output prefixed. This
is the first thing to try when the service starts and the anchor does not — see
[troubleshooting.md](troubleshooting.md). Stop the service first: a second supervisor for
the same root is refused, since each stops the `anchord` the last one left. `anchord` is
given what the service would give it; on Windows, a console has no `SeTcbPrivilege` to log
`LOCAL SERVICE` on with, so there it runs as the console's account, and says so.
