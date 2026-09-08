# Configuration and on-disk layout

Three files, three lifetimes, deliberately not one.

## Where

conflux is system-scoped: one configuration per machine, root-owned, with **no home
directory anywhere in it**. The boot service runs as root or LocalSystem, so a path
under `$HOME` is a path the service cannot read — and a `~/.config` layout also breaks
under a systemd unit with `User=` or `ProtectHome=`.

| | Linux | macOS | Windows | FreeBSD / OpenBSD |
|---|---|---|---|---|
| configuration | `/etc/conflux/` | `/Library/Application Support/conflux/` | `%ProgramData%\conflux\` | `/usr/local/etc/conflux/` |
| state, identity, binaries | `/var/lib/conflux/` | `/Library/Application Support/conflux/` | `%ProgramData%\conflux\` | `/var/db/conflux/` |
| socket and token | `/run/conflux/` | `/var/run/conflux/` | `%ProgramData%\conflux\run\` | `/var/run/conflux/` |

`CONFLUX_DIR` roots all of them in one directory, and the boot service with them — it is named after the root, so a run under it is a separate installation rather than a replacement for the machine's own. See [testing.md](testing.md).

Every directory is `0700` and every file `0600`.

## `conflux.json` — what you asked for

```json
{
  "version": 1,
  "mode": "tun",
  "taints": ["brhk-2mq9-tzva-6pjs"],
  "ipv4": "10.128.0.1/24",
  "subnets": ["192.168.1.0/24"],
  "uplink": "/dev/ttyUSB0:115200",
  "peers": ["genesis.veilnet.com.au:4700"],
  "port": 4711,
  "lowLatency": false,
  "serveExit": false,
  "useExit": false,
  "tunName": "anchor0",
  "apiBaseUrl": "https://api.veilnet.com.au",
  "createdAt": "2026-09-06T06:35:41Z",
  "updatedAt": "2026-09-06T06:35:41Z"
}
```

| Field | Meaning |
|---|---|
| `mode` | `tun` or `proxy`. See [modes.md](modes.md). |
| `taints` | never empty after `up` or `proxy`. |
| `ipv4` | a prefix, or absent for IPv6-only. `tun` only. |
| `subnets` | interface names or private prefixes. `tun` only. |
| `proxies` | `PORT[/NETWORK]=BACKEND` specs. `proxy` only. |
| `uplink` | a device, with an optional line speed. Absent means the host's IP network, which is the usual case. Either mode. See [uplink.md](uplink.md). |
| `peers` | bootstrap entries, `host:port` or `anchorxxx@host:port`. **Absent is the usual case and not a missing setting:** anchorctl takes the list from the enrolment manifest for exactly the fields no flag named, so an empty `peers` is what keeps the issuer's own nodes in play. Present, it overrides them. |
| `port` | the UDP port to bind on every interface. Absent means the kernel picks one, which is the usual case. A port and not an address: an anchor listens everywhere, and the host's addresses change under it. Refused beside `uplink`, which binds no socket. |
| `lowLatency` | carry layer-2 frames on QUIC datagrams instead of streams. Absent is false. Either mode. |
| `serveExit`, `useExit` | route the public internet out of and into the overlay. Absent is false, and both are `tun` only — switching a machine to `proxy` clears them. |
| `apiBaseUrl` | absent means the default. |

This file is the whole of what a reboot needs. Every `up` and every `proxy` rewrites
it, so it is always the current desired state.

Editing it by hand is supported; `conflux start` restarts from whatever it says, and
anything anchor would refuse is refused by conflux first, naming the field.

## `manifest.b64` — the identity

One base64 line: the anchor manifest the enrolment API returned, holding the identity
seed, the realm root, the credential chain, the bootstrap list, the expiry and the
renewal endpoint.

**Store it exactly as it arrived.** Do not decompose it — anchorctl reads an inline
identity as raw bytes and a path as an encrypted container, so writing the hex out to a
file and passing `-identity` fails as `identity: file is corrupt`.

conflux never writes it to a second file and never puts it in an argv. It goes to
`anchorctl start -manifest -` on stdin, becomes an inline secret on the wire, and is
never named as a path in the request at all.

**This file is the machine.** There is no other copy in existence: enrolment stores
nothing on the server, and the response was the only one. See
[credentials.md](credentials.md) and [security.md](security.md).

## `state.json` — what conflux worked out

```json
{
  "version": 1,
  "anchorId": "anchor6btpa3gn6w4stipba4hekzho7caw6srfyy5puvbz7mfanaiept5a",
  "issuedAt": "2026-09-06T06:35:43.5Z",
  "notAfter": "2026-09-13T06:35:43.871Z",
  "renewalUrl": "https://api.veilnet.com.au/ghosts/alpha/renew",
  "enrolledAt": "2026-09-06T06:35:43.559Z",
  "binSetId": "998ece52739a7c74",
  "linkReopens": 2,
  "lastLinkReopen": "2026-09-08T11:04:12Z"
}
```

`linkReopens` and `lastLinkReopen` count an uplink found dead and rebuilt, and are
here rather than in memory because the supervisor that does the reopening and the
`conflux status` that reports it are different processes. See [uplink.md](uplink.md).

Everything here is derived. Delete it and the next start re-learns the AnchorID and
the credential window at the cost of one extra call. That is why it is a separate file
from the manifest, which is recoverable from nowhere.

It is separate from `conflux.json` for a second reason: the renewal timer rewrites
`notAfter` every few days from the supervisor while a CLI may be rewriting `taints`
from a terminal, and one file would make that a lost update.

## `bin/<setID>/` — the extracted anchor pair

`anchord` and `anchorctl`, extracted from the conflux binary, in a directory named for
the SHA-256 of their contents.

Content-addressed rather than a fixed path, and that one decision removes four
problems at once. An upgraded conflux writes a *new* directory instead of over the file
a running anchord has open, so there is no `ETXTBSY` on Unix and no sharing violation
on Windows. Two conflux processes racing agree on the path. A stale set is
identifiable and sweepable. And "is it already extracted" is a stat rather than a hash
of forty megabytes on every invocation.

Old sets are swept after 24 hours. `conflux uninstall` removes the tree.

Emphatically **not** `/tmp`: systemd's `PrivateTmp=` would give the service a
different `/tmp` than your shell, `/tmp` is `noexec` on hardened hosts,
`systemd-tmpfiles` deletes it under a running daemon, and a LocalSystem service's
`%TEMP%` is `C:\Windows\Temp`.

On Windows this directory also holds `wintun.dll` — see [windows.md](windows.md).

## Atomic writes, and modes

Every write goes to a sibling temporary file, is fsynced, renamed over the target, and
the directory fsynced. A crash or a full disk leaves the previous content and never a
truncated file — which for `manifest.b64` is the difference between an inconvenience
and a destroyed identity.

The mode is set on the file descriptor *before* any content reaches it. Writing and
then chmod'ing leaves a window at the umask's mode, and on a shared machine that
window is the whole vulnerability.

**On Windows, `0600` is a no-op.** A Go program that calls `Chmod(0600)` there has
changed only the read-only bit, and `%ProgramData%` grants `Users` read by default. So
conflux replaces the DACL outright on secret files — SYSTEM and Administrators, full
control, inheritance off — before writing anything into them.

## What survives what

| | `conflux down` | `conflux start` | `conflux install` | `conflux uninstall` |
|---|---|---|---|---|
| running anchor | stopped | (re)started | (re)started | stopped |
| boot service | kept | kept | registered | removed |
| `conflux.json` | kept | kept | kept | deleted |
| `manifest.b64` | kept | kept | kept | **deleted, permanently** |
| `state.json` | kept | kept | kept | deleted |
| extracted binaries | kept | kept | deleted |
