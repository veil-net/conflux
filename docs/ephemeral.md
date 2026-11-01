# Ephemeral: an anchor that keeps nothing

`--ephemeral` on `conflux up` or `conflux proxy` runs one anchor in the foreground from a
credential held in memory and nowhere else. Nothing of the machine's is read or written:
no `conflux.json`, no `manifest.b64`, no `state.json`, no boot service. The credential goes
from conflux's memory to anchorctl's stdin and from there inline to anchord, which keeps
it in memory too. When anchord stops — on Ctrl-C, on SIGTERM, because it crashed, or
because conflux was killed — everything is gone: the identity, the credential, the overlay
address, and the directory the run kept its socket in.

```console
$ sudo conflux up --ephemeral --taint brhk-2mq9-tzva-6pjs-k4xe-nw7d-qf --ipv4 10.128.0.9/24
Starting an ephemeral anchor: nothing is saved, and when it stops nothing of it remains.
  anchord: … anchord listening …
  enrolling, into memory alone

  anchor       anchor6btpa3gn6w4stipba4hekzho7caw6srfyy5puvbz7mfanaiept5a
  overlay      fd80:c4b9:99ae:4411:c531:fd4f:754f:f08a/48
  ipv4         10.128.0.9/24
  interface    anchor6btpa3gn6
  taint        brhk-2mq9-tzva-6pjs-k4xe-nw7d-qf
  credential   valid until 2026-12-01T07:54:04Z (29d 23h)
  anchord      conflux-ephemeral, with CAP_NET_ADMIN for its interface
  ephemeral    in memory alone; /run/conflux-ephemeral holds the socket and the binaries, and goes with the run

Running in the foreground. Ctrl-C stops it and removes what it made; conflux status, from another terminal, reports it.
^C
Stopped. Nothing of the run remains: no credential, no configuration, no state.
```

It is for a machine that should be on the overlay for as long as something runs and not
a moment longer: a CI job, a container, a laptop joining for one session, a host whose
disk is not trusted with a key.

## Where the credential comes from

- **Enrolled in memory**, as `up` and `proxy` enrol: an anonymous alpha enrolment in the
  taint given with `--taint`, or one minted for a network's first machine. The response is
  the only copy of the identity, as it always is, and this run means it to be lost with it.
- **Handed in**, with `--manifest FILE`, or `--manifest -` to read it from stdin: an issued
  credential, a guardian's for instance, as `conflux enrol` takes one, except that it is
  never written. Its taints are the run's, its API is the one it renews against (`--api`, if
  given, must name the same host), and its IPv4 allocation is the run's unless `--ipv4` or
  `--no-ipv4` says otherwise. The issuer's export block is not applied: its headers are
  credentials, and nothing here may put them on a command line or in a file.

```console
$ fetch-credential | conflux proxy --ephemeral --manifest - 8080=127.0.0.1:3000
```

`--manifest` without `--ephemeral` is refused: a credential to keep is `conflux enrol`'s.

## What it does while it runs

- **It never asks.** An ephemeral run is as often started by a script as by a person, so the
  IPv4 is `--ipv4`, else `--no-ipv4`, else the handed credential's own, else none.
- **It renews in memory**, at two thirds of the credential's window, by the same body every
  renewal goes through, with the renewed chain handed to anchorctl on its stdin
  (`anchorctl renew -cred -`). A failed renewal is tried again every minute until the
  credential runs out, and then the run ends. A credential that names nowhere to renew it
  runs to its expiry, and the run with it.
- **It never brings anything back.** anchord ending ends the run; so does the anchor
  leaving anchord, which the watcher looks for every 30 seconds (every 10 on an uplink).
  There is no restart and no rebuild.
- **`--observe` and `--export HOST:PORT` work**, both set in anchord over its socket, so
  nothing is written for them and both end with it. The inventory lasts as long as the
  run. Observing needs root, as it does anywhere.

### What the anchor cannot keep

anchord is given no `-dir`, so the anchor writes nothing at all. What that costs, beside
nothing a restart would have needed since there is none: a realm member's Taints order is
refused (`RefusedNoDir`), and so is a Subnets order that replaces the list this run started
with; the realm's knowledge — its blocks and its taint records — is held in memory, and
anchor says so as it starts.

## Who runs it, and as what

| Started as | `up --ephemeral` (TUN) | `proxy --ephemeral` (userspace) |
|---|---|---|
| root | anchord as `conflux-ephemeral`, with what an installed node's would hold: on Linux `CAP_NET_ADMIN` alone, root where `decide` keeps an installed one root; root on macOS and the BSDs | anchord as `conflux-ephemeral`, with no capability and `no_new_privs` on Linux |
| an ordinary user | refused: a TUN needs root | anchord as that user, with nothing; no root needed at all |
| Administrator on Windows | anchord as that Administrator | the same |

`conflux-ephemeral` (`_conflux-ephemeral` on macOS and OpenBSD) is an account of its own,
made the first time a root ephemeral run needs it and kept, as the installation's `conflux`
is, until `conflux uninstall` removes both. It is not the installation's: the installed
supervisor ends every process of its own account each time it starts anchord, and an
ephemeral anchord running as that account would go with them. On macOS an ephemeral observer
runs as root, since the BPF devices are the installation's to grant.

## Where it keeps its socket

One fixed directory per user, made when the run starts and removed when it ends:

| Started as | Root |
|---|---|
| root on Linux | `/run/conflux-ephemeral`, or `/var/lib/conflux-ephemeral` where `/run` is mounted `noexec` |
| root on macOS and the BSDs | `/var/run/conflux-ephemeral`, or beside the state directory where that is `noexec` |
| an ordinary user | `$XDG_RUNTIME_DIR/conflux-ephemeral` (or `/tmp/conflux-ephemeral-UID`), then the user's cache directory |
| Windows | `%ProgramData%\conflux-ephemeral` |
| `CONFLUX_DIR` set | `$CONFLUX_DIR/ephemeral` |

It holds the lock that makes it the only ephemeral run for that user, the bearer token and
the socket, the record of the anchord it started and what that runs as, and the extracted
pair: never a credential, a configuration or a state. A root that another account owns is
refused. A run is not refused because an installed conflux is running: that one is never
read, written, stopped or re-registered. Two anchors with a TUN on one host do contend for
the overlay's routes, so `conflux down` first where that matters.

## Reaching it from another terminal

`conflux status` reports an ephemeral run before the machine's own anchor, from its lock,
and says what a killed one left behind. Until the run's anchor is up it says the run is
starting, and asks it nothing: the run may still be clearing what a killed one left, and
another conflux reaching into its root then would get in its way. Neither `status` nor
pass-through ever writes into a run's root. Pass-through — `conflux peers`,
`conflux blocks`, every anchorctl command — reaches the ephemeral anchor when it is the
only one running, once it is up.
With an installed anchor running too, it reaches that one unless `CONFLUX_EPHEMERAL=1` is
set, so a command never switches anchors because one was started beside it. `conflux renew`
says the run renews itself.

## When conflux itself is killed

| Platform | conflux killed with SIGKILL |
|---|---|
| Linux | anchord is started with a parent-death signal, and gets SIGTERM: it closes its anchor and takes its interface down |
| Windows | anchord is in conflux's job object, which kills it however conflux ends |
| macOS, the BSDs | nothing can ask at the start, so anchord goes on until the next ephemeral run stops it, a reboot ends it, or it is killed. `conflux status` says a root was left behind |

The next run clears whatever a killed one left: its anchord, by the record of it, and every
process of the ephemeral account; then the rest of its root.

## What "nothing written" covers

What conflux and anchor write: no file holds the identity, the credential or the chain at
any point. And core dumps: the run sets `RLIMIT_CORE` to 0 before it starts anchord, which
inherits it, and on Linux marks conflux itself not dumpable, so the kernel writes no core
for it even to a `core_pattern` pipe.

Not swap, which is the operating system's to encrypt; not Windows Error Reporting, which
writes dumps by the machine's settings; and not root on a live machine, which can read any
process's memory. An ephemeral run keeps the credential off disk; it does not keep it from
the host's administrator.
