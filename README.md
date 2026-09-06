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

## Quickstart

The first machine:

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

The second:

```console
$ sudo conflux up --taint brhk-2mq9-tzva-6pjs --ipv4 10.128.0.2/24
$ ping 10.128.0.1
```

Or, on a machine where you cannot get `CAP_NET_ADMIN`, publish a service instead of
taking an interface:

```console
$ sudo conflux proxy 8080=127.0.0.1:3000 53/udp=127.0.0.1:53
```

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
| Boot service | yes | yes |

## Commands

| Command | What it does |
|---|---|
| `conflux up [--taint T] [--ipv4 PREFIX \| --no-ipv4] [--subnet CIDR]...` | enrol if needed, start in TUN mode, register the boot service |
| `conflux proxy PORT[/NETWORK]=BACKEND ...` | enrol if needed, start in userspace mode serving those backends |
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
