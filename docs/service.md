# The boot service

## What it does at boot

The service manager runs one process: `conflux serve`. That process is the supervisor,
and it is not itself the daemon:

```
systemd / launchd / rc / SCM
  └── conflux serve
        ├── anchord -socket … -token-file …
        ├── the renewal timer
        ├── the link watcher, on a machine configured for an uplink
        └── the restart loop
```

Registering `anchord` directly was the obvious alternative and does not work: anchord
is configured with nothing and holds no anchor until something calls `start` over its
socket. Something has to make that call, and it may as well be the thing the service
manager watches.

At every boot the supervisor reads `conflux.json`, extracts the anchor pair if it is
not already on disk, writes a fresh bearer token, starts `anchord`, waits until it
answers an authenticated `status` call, renews the credential if it is past two thirds
of its window, and starts the anchor. No prompts, and nothing typed.

Readiness is a real probe and not a sleep. A socket file on disk proves nothing —
a crashed daemon leaves one behind — so the supervisor polls until `anchorctl status`
succeeds, which proves the socket is bound, gRPC is serving, and the two sides agree
on the token. It also watches the child, so a daemon that dies during startup is
reported at once, with its own last lines attached, rather than after a timeout.

Once the anchor is up the supervisor writes a **readiness marker** at `<run>/ready`,
and removes it when the anchor goes. It is how `conflux up` and `conflux start` learn
the anchor is up the moment it happens. systemd's `Type=notify` already gives Linux the
answer — `systemctl restart conflux` returns once the supervisor has sent `READY=1` —
but launchd, rc and the Windows SCM say nothing, and without the marker the wait there
would be a status call, and a fork, once a second.

The marker is advisory. Every reader falls back to the status call it replaced, so a
marker that is missing, stale or half-written costs a second and never a start. It lives
in the run directory rather than the state directory, which is what stops it outliving
the anchor it describes: the run directory is recreated on every daemon start, and
systemd's `RuntimeDirectory=` cleans it on stop. Every path that restarts the service
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
by then, is killed; see the Windows section. A daemon that has already died is asked
nothing: there is no anchor left to close, and its pid may belong to something else.

A start that fails is retried with a backoff up to thirty seconds. One that no retry
changes — a configuration conflux refuses, an expired credential with nowhere to renew
it, a credential for another realm tree, a TUN the host will not give, a host that will
not be set up to forward, an argument vector anchorctl refuses — stops the supervisor
after three attempts with exit 70, and nothing to start at all is exit 78.

anchord can also lose its anchor without exiting, so the supervisor asks it every thirty
seconds whether it still holds one (every ten, through the link watcher's gauge, on an
uplink) and rebuilds it through the same bring-up when it does not — unless anchord said
a realm admin's kill order stopped it. That one is left stopped, `conflux status` says
`stopped  by an admin credential at …`, and `conflux start` or a reboot builds it again. What each service manager does with those two is
below.

## One machine, one service — unless CONFLUX_DIR says otherwise

The unit, the launchd label, the rc script and the SCM entry are all named `conflux`,
one per machine, which is what "one configuration per machine" means in practice.

A run under `CONFLUX_DIR` is the exception, because it is a separate installation and
not the machine's own: the service takes a suffix derived from the root
(`conflux-44a6e4f4.service`, or `conflux_44a6e4f4` for rc, whose names become shell
variables), and the root is written into the argv it is registered with, so the
supervisor comes back to the same directory at boot. Neither happens
without `CONFLUX_DIR`, so an ordinary install is byte-for-byte what it always was.
See [testing.md](testing.md).

## The four verbs, and which pair is which

Two pairs that are easy to confuse, because both look like they turn something off:

| | Pair | What it touches |
|---|---|---|
| now | `conflux start` / `conflux down` | the running anchor. The registration and the configuration are untouched, so a reboot behaves the same either way. |
| permanently | `conflux install` / `conflux uninstall` | the boot registration. `uninstall` also deletes the configuration and the identity. |

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
service on a machine that has no configuration yet.

```ini
[Unit]
Description=Conflux — VeilNet anchor
Documentation=https://github.com/veil-net/conflux
After=network-online.target
Wants=network-online.target

[Service]
Type=notify
NotifyAccess=main
ExecStart=/usr/local/bin/conflux serve
Restart=on-failure
RestartSec=5
RestartPreventExitStatus=78 70
TimeoutStartSec=90
TimeoutStopSec=30
KillMode=mixed
KillSignal=SIGTERM
User=root
Group=root
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW
RuntimeDirectory=conflux
RuntimeDirectoryMode=0700
StateDirectory=conflux
StateDirectoryMode=0700
ConfigurationDirectory=conflux
ConfigurationDirectoryMode=0700
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
```

Four of those lines are worth explaining.

`Type=notify`, with `sd_notify` from the supervisor, makes `systemctl start conflux`
return when the anchor is genuinely up rather than when `fork` succeeded. Anything
ordered `After=conflux.service` gets the same guarantee for free.

`RestartPreventExitStatus=78 70` is the two answers a restart would only repeat.
`conflux serve` exits 78 when there is nothing to start and 70 when it has given up on
something no retry changes; without this the unit would restart into the same answer
every five seconds forever, where it now shows as failed.

`Restart=on-failure`, not `always`, so a deliberate clean exit stays exited.

`AmbientCapabilities=CAP_NET_ADMIN` is stated even though the unit runs as root,
because it documents the requirement and survives somebody adding `User=` later.

Two things are deliberately absent. `PrivateTmp=` would be pointless and confusing —
nothing conflux does touches `/tmp` — and `ProtectSystem=strict` would need a
`ReadWritePaths=` list and would break pass-through writes such as
`conflux keygen -out ~/key`.

Logs go to the journal: `journalctl -u conflux -n 50`.

## launchd

Job at `/Library/LaunchDaemons/org.veilnet.conflux.plist`, label `org.veilnet.conflux`.

`KeepAlive` is `{SuccessfulExit: false}` rather than `true`, so a deliberate clean exit
stays exited. launchd has no way to name the exit codes that should not restart, so a
supervisor that exits 78 or 70 is started again after `ThrottleInterval`. `ProcessType`
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

**`enable` comes before every `bootstrap`, and `uninstall` disables nothing.**
`launchctl(1)`: *"Once a service is disabled, it cannot be loaded in the specified domain
until it is once again enabled. This state persists across boots of the device."* A
disabled label makes `bootstrap` fail with `Bootstrap failed: 5: Input/output error`,
which names nothing; a `bootstrap` that still fails is answered with the four things
that actually cause error 5.

`conflux down` uses `launchctl kill SIGTERM`, which stops the process and leaves the job
loaded — stopped now, back at the next boot, which is exactly the semantics `down` needs.
A job that is not loaded at all is already in the state `down` asks for, and says so
rather than passing on launchd's "Could not find service".

macOS needs no driver: `utun` is in the kernel and a root LaunchDaemon can open it.

Logs: `/var/log/conflux.log`, which `uninstall` removes with the plist.

## The Windows service

Service name `conflux`, display name `VeilNet Conflux`, running as `LocalSystem`,
automatic at boot, depending on `Tcpip`, `Dnscache` and `NSI`. Recovery actions restart
it after 5, 10 and 30 seconds.

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

A supervisor that stops itself — exit 78 or 70 — reports the service stopped, which the
SCM does not count as a failure, so the recovery actions do not restart it into the
same answer.

Windows also needs `wintun.dll` for TUN mode; see [windows.md](windows.md).

Logs: a service has no console, so the supervisor writes what it and `anchord` say to
`%ProgramData%\conflux\logs\conflux.log`, which `uninstall` removes with the rest.

## rc: FreeBSD and OpenBSD

**FreeBSD.** Script at `/usr/local/etc/rc.d/conflux`, enabled with
`sysrc conflux_enable=YES`. It runs `conflux serve` under `daemon(8)`, which backgrounds
it, appends its output to `/var/log/conflux.log`, and records conflux's own pid — so
`service conflux stop` signals the supervisor, which closes the anchor before anything
is killed. `daemon(8)` is not told to restart it: conflux restarts `anchord` itself, and a
supervisor that exits 78 or 70 would only repeat the answer. `uninstall` stops it,
removes the `rc.conf` line, the script and the log.

**OpenBSD.** Script at `/etc/rc.d/conflux`, enabled with `rcctl enable conflux`.
`rc.subr` backgrounds it and sends its output to syslog, so the logs are in
`/var/log/daemon`. `uninstall` stops and disables it and removes the script.

On both, `install` enables and starts nothing, and `restart` starts a service that was
not running. One platform note: OpenBSD's `tunN` device persists after close, so
`conflux down` leaves the device node behind. The routes are withdrawn before the close;
the node itself is the platform's, not conflux's.

## Running it in the foreground

```console
$ sudo conflux serve --foreground
```

Runs the supervisor attached to the terminal, with anchord's own output prefixed. This
is the first thing to try when the service starts and the anchor does not — see
[troubleshooting.md](troubleshooting.md).
