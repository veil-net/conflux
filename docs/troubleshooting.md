# Troubleshooting

Start with `conflux status`. It prints conflux's own state and `anchorctl status`
beneath it, and most of what follows is a way of reading that output.

| Symptom | Cause | What to do |
|---|---|---|
| `nothing is running here` | no daemon on the socket | `conflux up`, `conflux proxy`, or `conflux install` if a configuration already exists |
| `this needs root` | every state-changing verb needs it | `sudo conflux …` |
| `status` exits 78 | never configured | `conflux up` or `conflux proxy` |
| `up` exits 2 with "needs `--ipv4` or `--no-ipv4`" | no terminal to prompt at | pass one of them; that is what they are for |
| `is not an address and a prefix` | a bare IPv4 was given | write it as `10.128.0.7/24` |
| `is the network address of its own prefix` | `10.128.0.0/24` | pick a host address, `10.128.0.1/24` |
| `a reverse proxy needs userspace mode` | `--subnet` or `--ipv4` given to `proxy`, or a proxy spec to `up` | the modes are exclusive; see [modes.md](modes.md) |
| `"-add" is not one of conflux proxy's flags` | anchorctl's proxy was meant | `conflux anchorctl proxy -add …` |
| `"start" is anchorctl's` | `conflux start` | `conflux up`, or the escape hatch |
| `the anchor binaries … will not run` | `noexec`, or SELinux | see below |
| `wintun.dll … could not be downloaded` | Windows, offline | see [windows.md](windows.md) |
| `taint … contains a comma` | a comma-separated list was passed to `--taint` | use `--taint` twice |
| `credential EXPIRED` in status | renewal has been failing | the next line names the error; see below |
| `clock is … away from the server's` | bad clock | fix NTP first; nothing will connect until you do |
| two machines up, cannot reach each other | almost always taints | see below |
| `subnet … is not a private network` | a public prefix | anchor forwards private networks only |
| `the control socket path is N bytes` | `CONFLUX_DIR` is too deep | use a shorter one; the kernel's limit is 104–108 bytes |

## Two machines are up and cannot reach each other

In order of likelihood.

**Give it a minute.** Peers find each other by gossip through the bootstrap node, not
instantly. Across test runs this took anywhere from 15 to 60 seconds after the second
machine started — it varies, so do not read the first failed ping as a fault.

**Then check the taints.** `conflux peers` has a `DATA` column:

```
ANCHOR      OVERLAY                                  IPV4           STATE      DATA
i46dpakhug  fd80:c4b9:99ae:df9b:5261:d178:18f1:783c  10.128.0.2/24  connected  yes
s5g3oefl2s  fd80:c4b9:99ae:a015:58f1:5b6e:b140:5e8e  -              connected  no
```

`DATA no` on a peer you expected to reach means taint separation, and it is working as
designed. Two anchors exchange data only if one carries every taint the other does —
so `{office,laptop}` and `{office,desktop}` cannot talk despite sharing `office`. Read
the table in [concepts.md](concepts.md) and make the sets identical.

`conflux status` prints this machine's taint. Compare it, character for character,
with the other machine's.

**If the peer is not listed at all**, the two are not seeing each other yet. Check that
both have `peers` greater than zero — if one has none, it has not reached the
bootstrap node, which is a network problem rather than a conflux one.

## The extracted binaries will not run

A "permission denied" on a `0700` file you own is the most confusing failure in this
design, and there are only two causes. conflux detects both and names them:

```
conflux: the anchor binaries were extracted to /var/lib/conflux/bin/998ece52 but will not run from there.
  that filesystem is mounted noexec.
  set CONFLUX_DIR to a directory on a filesystem that allows execution.
```

or

```
  SELinux is enforcing, and a binary under this path is probably labelled var_lib_t.
  try:  sudo semanage fcontext -a -t bin_t '/var/lib/conflux/bin(/.*)?' && sudo restorecon -R /var/lib/conflux/bin
```

On macOS, `killed: 9` instead means the signature was rejected — an Apple Silicon Mac
refuses a Mach-O with no code signature at all.

## The service starts and the anchor does not

Run the supervisor in the foreground and watch:

```console
$ sudo systemctl stop conflux
$ sudo conflux serve --foreground
```

anchord's own output is prefixed `anchord:`, so the daemon's explanation of its own
refusal is visible directly. The common causes are a `--subnet` that matches no
attached network (which stops the anchor rather than being advertised on faith), and a
configuration anchor refuses — in which case the supervisor gives up after three
attempts rather than looping, and the unit shows as failed.

Where the logs are: `journalctl -u conflux -n 50` on Linux,
`/var/log/conflux.log` on macOS, Event Viewer → Windows Logs → Application on Windows.

## Renewal is failing

`conflux status` says so and names the last error:

```
  credential   valid until 2026-09-13T06:35:43Z (2d 4h)
  renewal      failing since 2026-09-11T02:10:00Z: dial tcp: no route to host
```

While the credential is still valid this is a warning: conflux retries on a backoff
and there are days of budget. Once it says `EXPIRED`, the anchor is running but every
handshake it attempts is refused.

**It will recover on its own.** The renewal route works after expiry, so a machine that
has been off for a month renews on its next launch and keeps its address. conflux will
never re-enrol to work around a failed renewal, because that would draw a new identity
and orphan every peer — see [credentials.md](credentials.md).

## Collecting a bug report

```console
$ conflux version           # names the exact anchor binaries
$ conflux status
$ sudo journalctl -u conflux -n 100 --no-pager
$ conflux peers
$ conflux routes
```

`conflux version` prints both anchor SHA-256s, which is what identifies the build.
Nothing in that output contains key material.
