# conflux

conflux puts one machine on a VeilNet overlay with a single command. It bundles
`anchord` and `anchorctl`, enrols against the public realm with no account and no key
to manage, and comes back at the same overlay address after a reboot. Joining takes
one command; rejoining takes none.

Everything `anchorctl` can do, conflux can do too — any command conflux doesn't
recognise is passed straight through to it unchanged. What conflux adds on top is
enrolment, credential renewal, a configuration file, and a boot service.

> **Status: in development.** The credential lasts seven days and renews itself
> automatically; the wire format underneath is not yet stable. See [docs/](docs/).

## Quick start

Install the binary, run `conflux up` on one machine, then run it on every other
machine with the taint it printed. That's the whole setup.

### 1. Install the binary

Download the artifact for your platform from the releases page, verify it, and put it
somewhere that survives a reboot:

```console
$ sha256sum -c SHA256SUMS --ignore-missing
conflux-linux-amd64: OK
$ sudo install -m 0755 conflux-linux-amd64 /usr/local/bin/conflux
$ conflux version
```

Do this before the next step: the boot service records the path it was installed
from, so a service pointed at `~/Downloads/conflux` breaks the first time that file
gets cleaned up. To build from source instead, see [build.md](docs/build.md)
(`make anchor-bins && make build`); platform-specific notes are in
[install.md](docs/install.md).

### 2. Bring up the first machine

```console
$ sudo conflux up
An overlay IPv4 lets other machines reach this one by a v4 address.
Everyone on your network picks the same prefix and a different host part.
The IPv6 address is derived from this machine's identity and needs no answer.

  Overlay IPv4 [e.g. 10.128.0.7/24, blank for IPv6-only]: 10.128.0.1/24

Minted a taint for this network:

    brhk-2mq9-tzva-6pjs

Share it. Any machine that runs

    conflux up --taint brhk-2mq9-tzva-6pjs

joins this network and nothing else.

Starting.

  anchor       anchor6btpa3gn6w4stipba4hekzho7caw6srfyy5puvbz7mfanaiept5a
  overlay      fd80:c4b9:99ae:4411:c531:fd4f:754f:f08a/48
  overlay      10.128.0.1/24
  interface    anchor0
  taint        brhk-2mq9-tzva-6pjs
  credential   valid until 2026-09-13T06:35:43Z (6d 23h)
  service      active (systemd: conflux.service, enabled at boot)
```

There's no account to create and no key to manage — `up` enrols this machine against
the public realm, starts an anchor, writes the configuration, and registers the boot
service.

### 3. Bring up every other machine

Give each one the taint from step 2 and its own host part:

```console
$ sudo conflux up --taint brhk-2mq9-tzva-6pjs --ipv4 10.128.0.2/24
```

Passing `--taint` and `--ipv4` on the command line answers the prompt in advance, so
this is safe to run from a provisioning script.

### 4. Check that it worked

```console
$ ping 10.128.0.1
$ conflux status
$ conflux peers
```

`status` prints conflux's state — mode, taint, address, credential expiry, service —
and `anchorctl status` beneath it. `peers` isn't conflux's at all; it's one of the
commands handed straight to `anchorctl`.

**That's the whole setup.** A reboot needs nothing typed: the service is registered
and enabled, the credential renews itself, and the machine comes back at the same
overlay address. `conflux down` stops the anchor now and leaves the service and
configuration in place; `conflux uninstall` removes them.

### Reverse proxy: publish a service without an interface

On a machine where you can't get `CAP_NET_ADMIN` — a container, a locked-down host, a
CI runner — skip the interface and publish the ports you want reachable instead:

```console
$ sudo conflux proxy 8080=127.0.0.1:3000 53/udp=127.0.0.1:53
```

A peer that connects to this machine's overlay port 8080 gets a fresh connection to
`127.0.0.1:3000`. Enrolment, `--taint`, and the boot service all work the same as
`up`; nothing appears on the host, and the anchor itself needs no privilege at all —
`sudo` is only for registering the boot service, so the proxy survives a reboot.

Each spec is `OVERLAYPORT[/NETWORK]=BACKEND`; give more than one to publish more than
one port:

| Spec | Means |
|---|---|
| `8080=127.0.0.1:3000` | TCP on overlay port 8080 → `127.0.0.1:3000` |
| `53/udp=127.0.0.1:53` | UDP on overlay port 53 → `127.0.0.1:53` |
| `5432=[::1]:5432` | an IPv6 backend, bracketed |

The network defaults to `tcp`. The backend is dialled fresh per connection rather than
resolved up front, so a name that doesn't resolve yet is fine.

To add or remove a proxy on an anchor that's already running, without a restart, use
`anchorctl`'s own proxy command — it's a different thing from `conflux proxy`, which
decides the mode the machine boots into:

```console
$ conflux anchorctl proxy                            # what it is serving
$ conflux anchorctl proxy -add 9000=127.0.0.1:9000   # one more, now
```

Both are listed under [Commands](#commands).

### Generic uplink: join over a cable

An anchor normally binds a UDP socket, so it needs a host IP network underneath it. An
uplink replaces that: a file descriptor becomes the medium instead, and no socket is
bound at all. Point each end of a cable at its device, and the two machines share a
realm with no IP network between them:

```console
$ sudo conflux up --uplink /dev/ttyUSB0:115200 --taint brhk-2mq9-tzva-6pjs --no-ipv4
  anchor       anchor6btpa3gn6w4stipba4hekzho7caw6srfyy5puvbz7mfanaiept5a
  uplink       /dev/ttyUSB0:115200 — no socket bound, no address advertised
  interface    anchor0
  taint        brhk-2mq9-tzva-6pjs
  service      active (systemd: conflux.service, enabled at boot)
```

`--uplink` decides the *medium*; the verb you put it on decides what the machine gets
out of it. The two questions are independent, so it works on either command:

```console
$ sudo conflux up --uplink /dev/ttyUSB0:115200               # a cable, and an interface
$ sudo conflux proxy 8080=127.0.0.1:3000 --uplink /dev/ttyS1  # a cable, and no interface
$ sudo conflux up --no-uplink                                 # back to the host's network
```

Two things worth knowing before you rely on the cable alone:

**Enrol while the machine still has internet access.** Enrolment is an HTTPS call to
the realm's API, and the cable can't carry it — the credential that admits this
machine to the realm has to exist before the realm is reachable at all. Run the
command once on a network, then move the machine; a second `conflux up` reuses the
identity and enrols nothing. Renewal needs the same connectivity, so a machine that
never sees the internet again only stays enrolled for seven days.

**The line needs to be fast enough for a realm handshake.** That's a full TLS 1.3
exchange with ML-DSA certificates in both directions — twenty to thirty kilobytes,
comfortable at 115200 baud, usable at 19200, and marginal at 9600 against a
sixty-second idle timeout. conflux warns when the speed you give is under 19200. The
limit comes from the identity model, not the link, which is why LoRa and other
duty-cycled radios can't reach it at all rather than just being slow.

See [uplink.md](docs/uplink.md) for the device forms, what an uplink refuses beside
it, and the limits it still has.

### Three things worth knowing

**The prompt appears once.** conflux asks for an overlay IPv4 because thirty-two bits
are too few to derive without collisions; the IPv6 address comes from the machine's
identity and needs no answer. Blank is a valid answer, and a common one. A second
`conflux up` reads the existing configuration and prompts for nothing — conflux will
never change a machine's address just because a command got run again.

**The taint decides who can reach you.** conflux always generates one, because the
alternative isn't "no restriction" — an anchor with no taints sits in the realm's
default compartment, the same one every other unconfigured anchor sits in. Machines
that share a taint can exchange data; machines that don't share one aren't merely
unreachable, they have no address for each other at all. See
[concepts.md](docs/concepts.md).

**`up` and `proxy` are exclusive.** One daemon holds one anchor, and an anchor with a
host interface can't also serve a reverse proxy — the kernel owns the overlay address
in that mode, so a service just binds it directly. Running either command replaces
the other, and conflux says so when it does.

## The two modes

| | `conflux up` | `conflux proxy` |
|---|---|---|
| What the host gets | a TUN interface: `ping`, `ssh`, everything | nothing on the host |
| What the realm gets | this machine, at an overlay address | the named services, at overlay ports |
| Privilege to run | root / `CAP_NET_ADMIN` / Administrator | root, only to register the boot service |
| Needs `wintun.dll` on Windows | yes | no |
| Can forward a subnet | yes, `--subnet` | no |
| Can run over an uplink | yes, `--uplink` | yes, `--uplink` |
| Boot service | yes | yes |

**Mode and medium are different questions.** The mode is what this machine gets out
of the realm, and `up` and `proxy` are exclusive. The medium is what the anchor
reaches the realm over — the host's IP network by default, or a link named by
`--uplink` — and either mode works over either medium. See
[modes.md](docs/modes.md) and [uplink.md](docs/uplink.md).

## Commands

| Command | What it does |
|---|---|
| `conflux up [--taint T] [--ipv4 PREFIX \| --no-ipv4] [--subnet CIDR]... [--uplink DEV \| --no-uplink]` | enrol if needed, start in TUN mode, register the boot service |
| `conflux proxy PORT[/NETWORK]=BACKEND ... [--taint T] [--uplink DEV]` | enrol if needed, start in userspace mode serving those backends |
| `conflux down` | stop the anchor now; the boot service and the configuration stay |
| `conflux status` | conflux's state, and `anchorctl status` beneath it |
| `conflux install` | register the boot service; start it if a configuration exists |
| `conflux uninstall` | remove the boot service, the configuration and the identity |
| `conflux version` | conflux's version, and the anchor build it carries |
| `conflux anchorctl ARGS...` | run the embedded `anchorctl`, uninterpreted |
| *anything else* | passed to `anchorctl` unchanged: `peers`, `routes`, `events`, `metrics`, `send`, `inspect`, … |

**Eight names are conflux's; everything else is anchorctl's.** Two of them shadow a
command anchorctl already has, and each collision is resolved rather than guessed:
bare `conflux status` is conflux's, and prints anchorctl's status beneath it, while
`conflux status -watch 5s` forwards to anchorctl because it was given arguments.
`conflux proxy 8080=127.0.0.1:3000` starts userspace mode; `conflux anchorctl proxy
-add 8080=127.0.0.1:3000` adds a proxy to an anchor that's already running. `start`,
`stop`, and `restart` are refused outright rather than passed through — running them
directly would leave conflux's configuration describing an anchor that isn't the one
actually running.

## Where things live

| | Linux | macOS | Windows |
|---|---|---|---|
| configuration | `/etc/conflux/` | `/Library/Application Support/conflux/` | `%ProgramData%\conflux\` |
| identity and state | `/var/lib/conflux/` | `/Library/Application Support/conflux/` | `%ProgramData%\conflux\` |
| socket and token | `/run/conflux/` | `/var/run/conflux/` | `%ProgramData%\conflux\run\` |

One directory per machine, root-owned, with no home directory involved anywhere — the
boot service runs as root, and a path under `$HOME` is a path it can't read. See
[config.md](docs/config.md).

## Documentation

| Page | What it covers |
|---|---|
| [install.md](docs/install.md) | Getting a binary onto each platform, and verifying it. |
| [concepts.md](docs/concepts.md) | Realm, anchor, overlay address, and taints — including the arithmetic people get wrong. |
| [modes.md](docs/modes.md) | TUN and userspace, why they cannot be combined, subnets and their prerequisites. |
| [uplink.md](docs/uplink.md) | Running over a link instead of a host IP network: the device forms, the line speeds, the limits. |
| [commands.md](docs/commands.md) | Every command, every flag, what reaches anchorctl, and the exit codes. |
| [config.md](docs/config.md) | The configuration file, the manifest, file modes, and the layout on each OS. |
| [service.md](docs/service.md) | The boot service: systemd, launchd, the Windows service, and the two BSDs that get none. |
| [credentials.md](docs/credentials.md) | Enrolment, the seven-day window, renewal, and what "the only copy" means. |
| [windows.md](docs/windows.md) | `wintun.dll`, why it is not embedded, the pinned digest, and Defender. |
| [security.md](docs/security.md) | What conflux adds to anchor's threat model: an executable on disk and a key in a file. |
| [troubleshooting.md](docs/troubleshooting.md) | Symptom, cause, and what to do about it. |
| [build.md](docs/build.md) | Building from source, where the anchor binaries come from, cross-compiling. |
| [testing.md](docs/testing.md) | What is tested, how, and what has no coverage. |

## What conflux is not

It's not a second implementation of anything. Every packet decision, every credential
check, and every route belongs to [anchor](https://github.com/veil-net/anchor);
conflux just chooses the arguments and keeps the files. If something goes wrong on the
wire, anchor's documentation is where to look.

It doesn't change anchor's credential format or protocol, and it doesn't reimplement
anything `anchorctl` already does.

## License

[CC BY-NC-SA 4.0](LICENSE) — free to share and adapt, with attribution, for
non-commercial purposes, as long as anything built on it carries the same license.
