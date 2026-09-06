# conflux

conflux puts one machine on a VeilNet overlay with one command. It carries `anchord`
and `anchorctl` inside itself, enrols against the public realm with no account and no
key to manage, and comes back at the same overlay address after a reboot — so joining
is one command and rejoining is none.

Everything `anchorctl` can do, conflux can do: an argument vector conflux does not
recognise is handed to it unchanged. What conflux adds on top is enrolment, credential
renewal, a configuration file, and a boot service.

> **Status: in development.** The credential lasts seven days and renews itself; the
> wire format underneath is not yet stable. See [docs/](docs/).

## Quick start

Install the binary, run `conflux up` on one machine, run it on the next with the taint
the first one printed. That is the whole of it.

### 1. Install the binary

Download the artifact for your platform from the releases page, verify it, and put it
somewhere that survives a reboot:

```console
$ sha256sum -c SHA256SUMS --ignore-missing
conflux-linux-amd64: OK
$ sudo install -m 0755 conflux-linux-amd64 /usr/local/bin/conflux
$ conflux version
```

Install it *before* the next step. The boot service records the path it was started
from, so a service pointed at `~/Downloads/conflux` breaks the day that file is tidied
away. Building from source is `make anchor-bins && make build` — see
[build.md](docs/build.md); every platform's particulars are in
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

There is no account to create and no key to manage: `up` enrols this machine against
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
and `anchorctl status` beneath it. `peers` is not conflux's at all; it is one of the
commands handed straight to `anchorctl`.

**That is the end of the setup.** A reboot needs nothing typed: the service is
registered and enabled, the credential renews itself, and the machine comes back at
the same overlay address. `conflux down` stops the anchor now and leaves both the
service and the configuration in place; `conflux uninstall` removes them.

### Publishing a service instead: the reverse proxy

On a machine where you cannot get `CAP_NET_ADMIN` — a container, a locked-down host,
a CI runner — take no interface and publish the ports you want reachable instead:

```console
$ sudo conflux proxy 8080=127.0.0.1:3000 53/udp=127.0.0.1:53
```

A peer that connects to this machine's overlay port 8080 gets a fresh connection to
`127.0.0.1:3000`. Same enrolment, same `--taint`, same boot service; nothing appears
on the host, and the anchor itself needs no privilege at all — the `sudo` is for
registering the service, so that the proxy is still there after a reboot.

The grammar is `OVERLAYPORT[/NETWORK]=BACKEND`, repeated:

| Spec | Means |
|---|---|
| `8080=127.0.0.1:3000` | TCP on overlay port 8080 → `127.0.0.1:3000` |
| `53/udp=127.0.0.1:53` | UDP on overlay port 53 → `127.0.0.1:53` |
| `5432=[::1]:5432` | an IPv6 backend, bracketed |

The network defaults to `tcp`. The backend is dialled per connection and is not
resolved in advance, so a name that does not resolve yet is fine. To change the set
on an anchor that is already running, without a restart, that one is `anchorctl`'s:

```console
$ conflux anchorctl proxy                            # what it is serving
$ conflux anchorctl proxy -add 9000=127.0.0.1:9000   # one more, now
```

Those two are not the same command as `conflux proxy`, which decides the mode this
machine boots into. Both are listed under [Commands](#commands).

### Joining over a cable: the generic uplink

An anchor normally binds a UDP socket, so it needs a host IP network under it. An
uplink replaces that: a file descriptor becomes the medium, and no socket is bound at
all. Give each end of the cable the device, and the machines are in one realm with no
IP network anywhere between them:

```console
$ sudo conflux up --uplink /dev/ttyUSB0:115200 --taint brhk-2mq9-tzva-6pjs --no-ipv4
  anchor       anchor6btpa3gn6w4stipba4hekzho7caw6srfyy5puvbz7mfanaiept5a
  uplink       /dev/ttyUSB0:115200 — no socket bound, no address advertised
  interface    anchor0
  taint        brhk-2mq9-tzva-6pjs
  service      active (systemd: conflux.service, enabled at boot)
```

`--uplink` decides the *medium*, and the command it is written on decides what this
machine gets out of it — so it goes on either verb, and the two are independent
questions:

```console
$ sudo conflux up --uplink /dev/ttyUSB0:115200               # a cable, and an interface
$ sudo conflux proxy 8080=127.0.0.1:3000 --uplink /dev/ttyS1  # a cable, and no interface
$ sudo conflux up --no-uplink                                 # back to the host's network
```

Two things to know before the cable is the only thing plugged in:

**Enrol while the machine still has the internet.** Enrolment is an HTTPS call to the
realm's API and the link cannot carry it — the credential is what admits this machine
to the realm, so it has to exist before the realm is reachable. Run the command once
where there is a network, then move the machine; a second `conflux up` re-uses the
identity and enrols nothing. Renewal has the same requirement, which is what makes a
permanently offline uplink machine a seven-day deployment rather than an indefinite
one.

**The line has to be fast enough for a realm handshake.** That is a full TLS 1.3
exchange with ML-DSA certificates in both directions, twenty to thirty kilobytes:
comfortable at 115200 baud, usable at 19200, and marginal at 9600 against a
sixty-second idle timeout. conflux says so when the speed you give is under 19200.
The floor is the identity model's rather than the link's, which is why LoRa and the
other duty-cycled radios are out of reach rather than merely slow.

See [uplink.md](docs/uplink.md) for the device forms, what an uplink refuses beside
it, and the two limits it still has.

### Three things worth knowing

**The prompt appears once.** conflux asks for an overlay IPv4 because thirty-two bits
is too small to derive collision-free; the IPv6 address comes from this machine's
identity and needs no answer. Blank is a valid answer and a common one. A second
`conflux up` reads the configuration and prompts for nothing — changing a machine's
address because somebody re-ran a command is not something conflux will do.

**The taint is the whole of who can reach you.** conflux generates one because the
alternative is not "no restriction": an anchor with no taints carries the realm's
default compartment, which every other unconfigured anchor in the realm also carries.
Machines that share a taint can exchange data; machines that do not are not merely
unreachable, they have no address for each other. See
[concepts.md](docs/concepts.md).

**`up` and `proxy` are exclusive.** One daemon holds one anchor, and an anchor with a
host interface cannot also serve a reverse proxy — the kernel owns the overlay address
in that mode, so a service binds it directly and needs nothing from conflux. Running
either replaces the other, and says so.

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

**The mode and the medium are different questions.** The mode is what this machine
gets out of the realm, and the two are exclusive. The medium is what the anchor
reaches the realm over — the host's IP network, or a link named by `--uplink` — and
either mode runs on either one. See [modes.md](docs/modes.md) and
[uplink.md](docs/uplink.md).

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

**Eight names are conflux's and the rest are anchorctl's.** Two of them shadow a
command anchorctl has, and each collision is resolved rather than guessed: bare
`conflux status` is conflux's and prints anchorctl's underneath, while
`conflux status -watch 5s` forwards; `conflux proxy 8080=127.0.0.1:3000` starts
userspace mode, while `conflux anchorctl proxy -add 8080=127.0.0.1:3000` adds one to an
anchor already running. `start`, `stop` and `restart` are refused rather than passed
through, because running them directly would leave conflux's configuration describing
an anchor that is not the one running.

## Where things live

| | Linux | macOS | Windows |
|---|---|---|---|
| configuration | `/etc/conflux/` | `/Library/Application Support/conflux/` | `%ProgramData%\conflux\` |
| identity and state | `/var/lib/conflux/` | `/Library/Application Support/conflux/` | `%ProgramData%\conflux\` |
| socket and token | `/run/conflux/` | `/var/run/conflux/` | `%ProgramData%\conflux\run\` |

One directory per machine, root-owned, with no home directory anywhere in it — the
boot service runs as root, and a path under `$HOME` is a path it cannot read. See
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

It is not a second implementation of anything. Every packet decision, every credential
check and every route belongs to [anchor](https://github.com/veil-net/anchor); conflux
chooses the arguments and keeps the files. When something goes wrong on the wire,
anchor's documentation is what describes it.

It does not change anchor's credential format or its protocol, and it does not
reimplement a single thing `anchorctl` already does.

## License

TBD.
