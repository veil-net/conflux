# The boot service

## What it does at boot

The service manager runs one process: `conflux serve`. That process is the supervisor,
and it is not itself the daemon:

```
systemd / launchd / SCM
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
the anchor is up the moment it happens.

That mattered on two platforms and not on the third. systemd's `Type=notify` already
gave Linux the answer — `systemctl restart conflux` returns once the supervisor has sent
`READY=1`, so the first `anchorctl status` call afterwards already succeeded. launchd
infers readiness from the process staying alive and the Windows SCM tells only itself,
so on those two the wait was a second of polling per attempt for news that had already
happened, each attempt forking a 43 MB binary that Defender and Gatekeeper both want to
think about.

The marker is advisory. Every reader falls back to the status call it replaced, so a
marker that is missing, stale or half-written costs a second and never a start. It lives
in the run directory rather than the state directory, which is what stops it outliving
the anchor it describes: the run directory is recreated on every daemon start, and
systemd's `RuntimeDirectory=` cleans it on stop. Every path that restarts the service
clears it *before* restarting, so the marker that appears afterwards can only have been
written by the instance that restart started — otherwise `up` could report success for an
anchor that was seconds from being torn down.

Shutdown runs in one order everywhere: stop the renewal timer, `anchorctl stop` so the
anchor says goodbye, then signal the process, then kill it. The second step is the
important one — an announced departure saves every peer from working it out by
timeout — and killing is only safe because it has already happened.

The signal step reports whether it delivered anything, and the kill waits only if it
did. On Unix a `SIGTERM` to the process group is delivered and the ten-second grace
before `SIGKILL` is a real grace. Inside a Windows service nothing can be delivered at
all, so that grace was ten seconds of waiting for an answer to a question nobody was
asked — on every stop, every restart and every service shutdown. See the Windows section.

## One machine, one service — unless CONFLUX_DIR says otherwise

The unit, the launchd label and the SCM entry are all named `conflux`, one per
machine, which is what "one configuration per machine" means in practice.

A run under `CONFLUX_DIR` is the exception, because it is a separate installation and
not the machine's own: the service takes a suffix derived from the root
(`conflux-44a6e4f4.service`), and the root is written into the argv it is registered
with, so the supervisor comes back to the same directory at boot. Neither happens
without `CONFLUX_DIR`, so an ordinary install is byte-for-byte what it always was.
See [testing.md](testing.md).

## The four verbs, and which pair is which

Two pairs that are easy to confuse, because both look like they turn something off:

| | Pair | What it touches |
|---|---|---|
| now | `conflux start` / `conflux down` | the running anchor. The registration and the configuration are untouched, so a reboot behaves the same either way. |
| permanently | `conflux install` / `conflux uninstall` | the boot registration. `uninstall` also deletes the configuration and the identity. |

`down` then `start` is the restart. `install` happens to start a configured machine as
well, which is why it used to be what `down` pointed at, but registration is its
subject and starting is a side effect — `start` is the verb whose subject is starting.

Neither `up` nor `proxy` belongs in that table: they decide the configuration and then
do both. `start` decides nothing, which is exactly what makes it the way back from
`down` on a userspace machine, where `up` would change the mode and drop the proxies.

## systemd

Unit at `/etc/systemd/system/conflux.service`, and `conflux install` writes it,
`daemon-reload`s and `enable`s it. **It does not start it**; that is the caller's
decision, and it is what lets `conflux install` register a service on a machine that
has no configuration yet.

```ini
[Unit]
Description=Conflux — VeilNet anchor
After=network-online.target
Wants=network-online.target

[Service]
Type=notify
NotifyAccess=main
ExecStart=/usr/local/bin/conflux serve
Restart=on-failure
RestartSec=5
RestartPreventExitStatus=78
TimeoutStartSec=90
TimeoutStopSec=30
KillMode=mixed
KillSignal=SIGTERM
User=root
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

`RestartPreventExitStatus=78` is the no-configuration case. `conflux serve` exits 78
when there is nothing to start, and without this the unit would restart into the same
emptiness every five seconds forever.

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
stays exited — the launchd counterpart of `RestartPreventExitStatus`. `ProcessType` is
`Interactive` rather than the `Background` daemons default to, because `Background`
brings a low-priority I/O class and App Nap eligibility, and a networking daemon the
scheduler throttles is a support ticket nobody can diagnose.

**`install` writes the plist and loads nothing.** That is what registration means here:
launchd bootstraps everything in `/Library/LaunchDaemons` at boot, so the file on disk is
the registration and nothing about coming back after a reboot depends on loading it now.

It used to bootstrap and then `launchctl kill SIGTERM` what bootstrapping had started,
because `bootstrap` honours `RunAtLoad` and `install` is not meant to start anything. The
kill was right and the cost was not: the supervisor launchd started got as far as
enrolling, opening a `utun`, assigning addresses and dialling the realm before the signal
reached it, and then the caller started a second one for real. **Every `conflux up` on a
Mac brought an anchor up twice and threw the first away**, with a `ThrottleInterval` wait
between them. Linux never did this, because its `Install` writes a unit, reloads and
enables, and deliberately starts nothing.

Loading a job is a start and cannot be anything else. `launchd.plist(5)` on the
`SuccessfulExit` sub-key: *"This key implies that `RunAtLoad` is set to true, since the
job needs to run at least once before an exit status can be determined."* So this job
launches when it is loaded whatever the `RunAtLoad` key says, and `Start` and `Restart`
are built on that rather than trying to work around it:

| State | `Start` | `Restart` |
|---|---|---|
| not loaded | `bootstrap` — loading is the start | `bootstrap` — same, and one start |
| loaded | `kickstart` | `kickstart -k` |

Re-running `bootstrap` on a loaded job fails with `Bootstrap failed: 37: Operation
already in progress`, and a `kickstart -k` on a job that was *just* bootstrapped kills the
instance launchd had only now made. Asking which state it is in is what avoids both.

**`enable` comes before `bootstrap`, and `uninstall` no longer disables anything.**
`launchctl(1)`: *"Once a service is disabled, it cannot be loaded in the specified domain
until it is once again enabled. This state persists across boots of the device."*
`uninstall` used to `launchctl disable` on its way out, which left that state on a machine
whose plist had just been deleted — so it bought nothing and the next `conflux up` failed
with:

```
Bootstrap failed: 5: Input/output error
```

Error 5 is launchd's answer for most refusals and names none of them. The old `Install`
had the two calls in the wrong order — `bootstrap` first, `enable` on the line after —
so it returned the failure before the call that would have fixed it ever ran. `uninstall`
no longer disables, and `enable` now runs first, which also clears the landmine on a
machine that already has one. A `bootstrap` that still fails is answered with the four
things that actually cause error 5.

`conflux down` uses `launchctl kill SIGTERM`, which stops the process and leaves the job
loaded — stopped now, back at the next boot, which is exactly the semantics `down` needs.
A job that is not loaded at all is already in the state `down` asks for, and says so
rather than passing on launchd's "Could not find service".

macOS needs no driver: `utun` is in the kernel and a root LaunchDaemon can open it.

Logs: `/var/log/conflux.log`.

## The Windows service

Service name `conflux`, display name `VeilNet Conflux`, running as `LocalSystem`,
automatic at boot, depending on `Tcpip`, `Dnscache` and `NSI`. Recovery actions restart
it after 5, 10 and 30 seconds.

The service name has no space in it deliberately: a name with one makes every `sc.exe`
invocation quoting-sensitive for no benefit.

The stop handler cancels the supervisor's context, which runs the full shutdown —
close the anchor, then signal, then kill.

The signal cannot work here, and the fix was to stop pretending it might.
`GenerateConsoleCtrlEvent` needs a console shared with the target process and a service
has none, so `CTRL_BREAK` is refused every time conflux runs the way conflux actually runs
on Windows. The call used to discard its answer, so shutdown could not tell *asked and
waiting* from *never asked* and waited out the ten-second grace either way — on every
stop, every restart and every service shutdown, which is most of what made `conflux up`
slow here. It now reports whether it delivered anything, and a stop that was never
delivered goes straight to the kill it was always going to reach.

Killing is safe for the reason the ordering exists at all: `anchorctl stop` has already
closed the anchor and said goodbye, so what is killed is a daemon holding nothing. The
graceful alternatives — a named event `anchord` waits on, or a daemon-shutdown RPC — are
`anchord`'s to offer and it offers neither, so there is nothing better to send.

Windows also needs `wintun.dll` for TUN mode; see [windows.md](windows.md).

Logs: Event Viewer, under Windows Logs → Application.

## FreeBSD and OpenBSD get none

There is no boot integration for either yet, and saying so is better than a
half-working one. `conflux install` refuses and prints the command to register by
hand:

```
conflux serve
```

On FreeBSD that is an `rc.d` script plus `sysrc conflux_enable=YES`; on OpenBSD,
`/etc/rc.d/conflux` plus `rcctl enable conflux`. Everything else works on both:
pass-through, `up`, `proxy`, `down`, and the supervisor in the foreground.

One platform note: OpenBSD's `tunN` device persists after close, so `conflux down`
leaves the device node behind. The routes are withdrawn before the close; the node
itself is the platform's, not conflux's.

## Running it in the foreground

```console
$ sudo conflux serve --foreground
```

Runs the supervisor attached to the terminal, with anchord's own output prefixed. This
is the first thing to try when the service starts and the anchor does not — see
[troubleshooting.md](troubleshooting.md).
