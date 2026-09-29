# Troubleshooting

Start with `conflux status`. It prints conflux's own state and `anchorctl status`
beneath it, and most of what follows is a way of reading that output.

| Symptom | Cause | What to do |
|---|---|---|
| `nothing is running here` | no daemon on the socket | `conflux start` if a configuration already exists, otherwise `conflux up` or `conflux proxy` |
| `… needs root` (`… needs Administrator` on Windows) | every state-changing verb needs it | run the command it names — yours, flags and all — with `sudo`, or from an elevated PowerShell |
| `status` exits 78 | never configured | `conflux up` or `conflux proxy` |
| `has not been given an IPv4 yet and there is no terminal to ask at` | `up` or `proxy` in a script, on a machine never asked | pass `--ipv4 ADDRESS` or `--no-ipv4`; that is what they are for |
| `is not a unicast address a host sends from` | a loopback, link-local, multicast or broadcast IPv4 | pick an address a host could send from; any other is accepted |
| `a reverse proxy needs userspace mode` | a proxy spec in a `tun` configuration | the modes are exclusive; see [modes.md](modes.md) |
| `"-add" is not one of conflux proxy's flags` | anchorctl's proxy was meant | `conflux anchorctl proxy -add …` |
| `"-identity" is anchorctl's start` | anchorctl's flags given to `conflux start`, which takes none | `conflux anchorctl start …` |
| `the anchor binaries … will not run` | `noexec`, or SELinux | see below |
| `wintun.dll, and it could not be fetched` | Windows, offline | see [windows.md](windows.md) |
| `taint … contains a comma` | a comma-separated list was passed to `--taint` | use `--taint` twice |
| `credential EXPIRED` in status | renewal has been failing | the next line names the error; see below |
| `clock is … away from the server's` | bad clock | fix NTP first; nothing will connect until you do |
| two machines up, cannot reach each other | almost always taints | see below |
| `subnet … is not a private network` | a public prefix | anchor forwards private networks only |
| `subnet … has host bits set` | `192.168.1.7/24` | write the network, `192.168.1.0/24` |
| `the control socket path is N bytes` | `CONFLUX_DIR` is too deep | use a shorter one; the kernel's limit is 104–108 bytes |
| `fd:3 adopts a descriptor …` | `--uplink fd:N` | conflux's supervisor hands anchord no descriptors; name the device, or use `conflux anchorctl start` |
| `anchor has no way to open a link on Windows` | `--uplink` on Windows | anchor opens a link on unix only; see [uplink.md](uplink.md) |
| an uplink machine is up and reaches nothing | usually the far end, the line speed, or an enrolment that never happened | see below |

## An uplink machine is up and reaches nothing

`conflux status` on a machine with an uplink shows the link and no underlay address,
which is correct and not the fault: an anchor on a cable advertises no way to be
reached, because a cable has none.

**Check that both ends are on the link.** One link carries one peer, and both ends
have to have been brought up with `--uplink`. An anchor on a socket and an anchor on
a cable have no medium in common.

**Check the line speed on both ends, and that they match.** A link opened without a
speed is left exactly as it is, so a device configured elsewhere at 9600 stays there.
A realm handshake is twenty to thirty kilobytes: comfortable at 115200, marginal at
9600 against a 60-second idle timeout. `/dev/ttyUSB0:115200` sets it.

**Check that this machine was ever enrolled.** Enrolment is an HTTPS call, and the
link cannot carry it. A machine that has only ever seen the cable has no credential
and is not a member of anything — `conflux status` says `credential none — nothing
enrolled yet`. Bring it up once where it has the internet.

**Check that the credential has not lapsed.** Renewal needs the same API. A machine
permanently on a cable stops being admitted after thirty days; `conflux status` says
`credential EXPIRED`.

**A link that ended is reopened for you.** A device is not reopened by anchor, so
conflux watches it: a device that leaves the filesystem is acted on at once, and a
link carrying nothing for 90 seconds is treated as ended. Either way the anchor is
rebuilt on it. `conflux status` shows the tally, which is the thing to look at when a
machine seems fine but keeps losing peers:

```console
$ conflux status
  uplink       7 reopens, last 2026-09-08T11:04:12Z
```

Seven reopens is a cable, a connector or a far end at fault — conflux is papering over
it, not fixing it. If it is reopening and never staying up, check the far end is
running at all: an idle link whose far end is switched off is indistinguishable from a
dead one, and gets restarted on the same 90-second grace.

To force one by hand: `sudo conflux start`.

## Two machines are up and cannot reach each other

In order of likelihood.

**Give it a minute.** Peers find each other by gossip through the bootstrap node, not
instantly. Across test runs this took anywhere from 15 to 60 seconds after the second
machine started — it varies, so do not read the first failed ping as a fault.

**Then check the taints.** `conflux peers` has a `DATA` column:

```
ANCHOR      OVERLAY                                  IPV4        HARDWARE           STATE      CONN     DATA  REACH     RTT
i46dpakhug  fd80:c4b9:99ae:df9b:5261:d178:18f1:783c  10.128.0.2  ae:70:60:82:85:68  connected  out*,in  yes   nat-cone  990µs
s5g3oefl2s  fd80:c4b9:99ae:a015:58f1:5b6e:b140:5e8e  -           5a:f0:a9:da:4e:32  connected  out      no    unknown   1.2ms
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

## A peer is connected, has a round-trip time, and every ping times out

`conflux peers` says `connected` and `DATA yes`, an RTT is reported, and `ping` gets
nothing back. That combination is not a peering problem at all — the control plane runs
over UDP on the host's own interface and is in perfect health. It is the host's routing
table: nothing sends overlay addresses to the overlay interface.

Check that the overlay networks route to the anchor's interface:

```console
$ netstat -rn -f inet | grep utun      # macOS; ip route on Linux, route print on Windows
$ netstat -rn -f inet6 | grep utun
```

anchor installs a route for each network it reaches, on every platform and for both
families, so an overlay network routed anywhere else — out of Wi-Fi by the default
route — is anchor's to fix, and worth reporting there with that output attached.

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

## macOS: "Bootstrap failed: 5: Input/output error"

Seen on `conflux up` or `conflux install` after a `conflux uninstall`:

```
conflux: launchctl bootstrap system /Library/LaunchDaemons/org.veilnet.conflux.plist:
Bootstrap failed: 5: Input/output error
```

Error 5 is launchd's answer for most refusals and names none of them. conflux enables
the label before every bootstrap — a disabled label
[persists across boots](https://keith.github.io/xcode-man-pages/launchctl.1.html) and
blocks loading until it is enabled again — so when it still fails, the message lists the
other causes: the plist is not root-owned, or is group- or world-writable; the job is
already loaded (`sudo launchctl bootout system/org.veilnet.conflux`); or the executable
the plist names is gone or sits on a volume that is not mounted yet — which is what the
ephemeral-path warning during `install` is about.

## The service starts and the anchor does not

Run the supervisor in the foreground and watch:

```console
$ sudo systemctl stop conflux
$ sudo conflux serve --foreground
```

anchord's own output is prefixed `anchord:`, so the daemon's explanation of its own
refusal is visible directly. The supervisor retries a failed start with a backoff up
to thirty seconds — a `--subnet` whose interface is not up yet does come right — and
gives up after three attempts on what no retry changes, so the unit shows as failed
rather than looping: a configuration or a manifest conflux refuses, a credential for a
realm tree other than the one these binaries are pinned to, and a TUN the host will
not give (no capability or device, or the name held by another interface).

Where the logs are: `journalctl -u conflux -n 50` on Linux, `/var/log/conflux.log` on
macOS and FreeBSD, `/var/log/daemon` on OpenBSD, and
`%ProgramData%\conflux\logs\conflux.log` on Windows. A start that times out names the
right one for the machine.

## Renewal is failing

`conflux status` says so and names the last error:

```
  credential   valid until 2026-10-06T06:35:43Z (8d 4h)
  renewal      failing since 2026-09-26T08:10:00Z: dial tcp: no route to host
```

While the credential is still valid this is a warning: conflux retries every minute
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
