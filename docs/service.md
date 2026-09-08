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

Shutdown runs in one order everywhere: stop the renewal timer, `anchorctl stop` so the
anchor says goodbye, then signal the process, then kill it. The second step is the
important one — an announced departure saves every peer from working it out by
timeout — and killing is only safe because it has already happened.

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

`Start` uses `launchctl kickstart`, which starts or restarts. Re-running `bootstrap` on
a loaded job fails with `Bootstrap failed: 37: Operation already in progress`.

`conflux down` uses `bootout`, which unloads the job and leaves the plist in
`/Library/LaunchDaemons` — and launchd re-reads that directory at boot. That is
exactly the semantics `down` needs.

macOS needs no driver: `utun` is in the kernel and a root LaunchDaemon can open it.

Logs: `/var/log/conflux.log`.

## The Windows service

Service name `conflux`, display name `VeilNet Conflux`, running as `LocalSystem`,
automatic at boot, depending on `Tcpip`, `Dnscache` and `NSI`. Recovery actions restart
it after 5, 10 and 30 seconds.

The service name has no space in it deliberately: a name with one makes every `sc.exe`
invocation quoting-sensitive for no benefit.

The stop handler cancels the supervisor's context, which runs the full shutdown —
close the anchor, then signal, then kill. Sending `CTRL_BREAK` fails inside a service,
which has no console, so that failure is expected rather than exceptional and the
handler falls through to a kill after its timeout.

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
