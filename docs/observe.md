# Observing: an inventory of this host's cryptography

`conflux observe` runs the daemon's **observer** and no anchor. The host copies the start of
every flow its interfaces carry to `anchord`, which reads each handshake and records, for each
service the host reaches, serves or passes on, which protocol it spoke and whether its key
exchange was post-quantum, hybrid, classical or none at all — and, where it was not
post-quantum, which side held it back. It is anchor's Observer (anchor's `docs/observe.md` has
everything it reads, and how), run the way conflux runs everything else: from every boot, as an
account of its own, given exactly the privilege it needs.

```console
$ sudo conflux observe
  observer     af_packet, 0 flows held, 0 packets taken
  records      kept here, in the daemon's inventory until it restarts; --export HOST:PORT sends each to a collector
  service      active (systemd: conflux.service, enabled at boot)
  anchord      conflux, with CAP_NET_RAW to copy what the host's interfaces carry, for the observer

What it has seen, by service and key exchange:  conflux inventory   (-cbom for a CycloneDX CBOM)
```

It **carries nothing**: what it reads is a copy, so it can slow, break or reroute no connection,
and if it stops nothing on the host notices but the inventory. It **joins no realm**: nothing is
enrolled, no credential is needed and none is renewed, and the enrolment API is never asked.

## Where the records go

The observer makes a record of each flow every minute while it lasts, and when it ends. Each
goes to two places:

- **A collector, as it is made**, where an export with the `flows` signal is configured: each
  record is an `anchor.observed_flow` event, sent over OTLP/gRPC with the rest of the daemon's
  telemetry. `--export HOST:PORT` sets that up — the export on, that endpoint, `flows` and
  `metrics` on, `--export-insecure` for a collector without TLS — and keeps everything else
  `conflux.json`'s `export` block says: headers, which are credentials and are never taken on a
  command line, TLS material, intervals, other signals. With `metrics` on, the observer's own
  counters go too: flows by protocol and key exchange, flows held, copies the capture lost.
- **The daemon's inventory**, always: what the records add up to since the daemon started, one
  entry per service by protocol, key exchange, TLS version and suite, and owner. `conflux
  inventory` prints it, and `conflux inventory -cbom` gives it as a CycloneDX 1.6 cryptography
  bill of materials. It lasts as long as the daemon, so a restart begins it again; the
  collector is what keeps a record for good.

With no collector configured, conflux says so when it starts the observer and in `conflux
status`, rather than refusing: an inventory read on the machine is a use of its own.

## What it is given

Seeing what the host carries is the privilege, and it is all the observer is given. The
supervisor gives it at every start, as it gives every mode what it needs
([security.md](security.md#what-anchord-runs-as)); there is nothing to set up beforehand.

| Platform | How the host copies | What `anchord` runs as |
|---|---|---|
| Linux | a packet socket on every interface | conflux's account with `CAP_NET_RAW` alone, and `no_new_privs` |
| macOS | a BPF device on each interface | `_conflux`, its group given read access to `/dev/bpf*` |
| Windows | an ETW session with Microsoft-Windows-NDIS-PacketCapture | `LOCAL SERVICE`, as userspace mode is |
| FreeBSD, OpenBSD | nothing: anchor has no capture there | refused before anything starts |

On **macOS** only root may read a BPF device until a group is given that, and devfs makes the
devices afresh at every boot. So the supervisor, which launchd starts as root at every boot,
does what Wireshark's ChmodBPF does before it starts `anchord`: it opens each device up to the
kernel's limit, so that each exists, and gives the account's own group read access — read and
nothing more, so the account can see what the host carries and send nothing. Devices another
group can read already, such as ChmodBPF's `access_bpf`, are left as they are and the account is
given that group instead. A start that does not observe as the account, and `conflux
uninstall`, give the devices back to root alone.

On **Linux** `CAP_NET_RAW` reaches `anchord` as an ambient capability; a kernel without an
ambient set, or a container that will not give the capability, runs it as root or refuses it,
and `conflux status` says which. Who owns each flow is looked up from the kernel's socket
lists, which any user may read; the process holding a socket another user owns may go unnamed.

## Beside an anchor

`--observe` on `conflux up` or `conflux proxy` runs the observer beside the anchor, in the same
daemon, and its capture is added to what `anchord` is given for the anchor: `CAP_NET_RAW` beside
`CAP_NET_ADMIN` on Linux, `/dev/bpf*` beside nothing in userspace on macOS. The anchor's own
connections are observed with the rest.

```console
$ sudo conflux up --observe
$ sudo conflux proxy 8080=127.0.0.1:3000 --observe-hide-names --export collector.example:4317
$ sudo conflux up --no-observe
```

Naming the observer says what it is now, as anchorctl's `observe -start` does: `--observe`, or
either option, which implies it — `--observe-loopback`, `--observe-hide-names` — and an option
not given is off. Naming nothing keeps what is configured, and `--no-observe` turns it off.

The observer starts before the anchor, and needs nothing the anchor does, so an anchor that
cannot come up — an enrolment the API does not answer — leaves the observer and its inventory
running while the anchor is tried again.

## Switching

`conflux observe` on a machine that runs an anchor stops it: the machine leaves its realm until
the next `conflux up` or `conflux proxy`, which come back with the identity and every setting it
had — address, taints, subnets, exits, uplink — since none of them is cleared. The proxy specs
are, as `up` clears them. Because the switch takes a machine out of its realm, and because
anchorctl's bare `observe` only reports, it asks first at a terminal, and off one is refused
without `--yes`.

From observing, `conflux up` or `conflux proxy` starts an anchor beside the observer, which stays
on: `--no-observe` turns it off.

## Options

| `conflux observe` | `up` and `proxy` | Means |
|---|---|---|
| | `--observe` | observe beside the anchor |
| `--loopback` | `--observe-loopback` | observe the loopback interfaces too; Windows' capture never sees them |
| `--hide-names` | `--observe-hide-names` | leave every name a flow was reached by — a server name, a DNS answer's — out of the records and the inventory, the server's address in its place |
| | `--no-observe` | stop observing |
| `--export HOST:PORT` | `--export HOST:PORT` | send telemetry, and each record as it is made, to that collector |
| `--export-insecure` | `--export-insecure` | reach it without TLS |
| `--yes` | | stop the anchor this machine runs without asking |

anchorctl's own observe reaches the running observer, and is one word away: `conflux anchorctl
observe` reports, and `-start` and `-stop` start and stop it until the daemon next starts —
`conflux observe` answers either flag with where it belongs.

## What it cannot see

A copy made as a packet goes by can be lost when the host is busy, and a handshake among the
lost ones is not read; `conflux anchorctl observe` counts what was dropped. TLS 1.3's and QUIC's
server certificates are encrypted, so their authentication is unobservable. A flow already
running when the observer starts is joined midway, with its handshake unseen. anchor's
`docs/observe.md`, "Limits", has the rest.
