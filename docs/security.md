# Security

This page is about what conflux adds to [anchor's threat
model](https://github.com/veil-net/anchor/blob/main/docs/security.md), which is where
the protocol, the handshake and the credential chain are analysed. conflux adds
exactly two things anchor does not have: **an executable written to disk**, and **a
private key in a file**.

## A stolen `manifest.b64` is permanent

The manifest holds the 32-byte identity seed. Anyone who has it *is* that anchor. A
guardian-issued one holds a renewal bearer as well, so whoever has it can also keep
that identity's credential current indefinitely — the same statement, one step
stronger.

And there is no revocation, and there cannot be. Cutting somebody off would mean
refusing to renew, and refusing requires knowing who to refuse — but enrolment stores
nothing and renewal is unauthenticated, so a thief renews the stolen credential
themselves, indefinitely. The thirty-day window bounds nothing in that case.

Stated plainly: **if the file leaves the machine, the only remedy is to stop using
that identity.** `conflux uninstall --yes` and `conflux up --taint` draw a new one, and
every peer that knew the old address has to be told the new one. The stolen credential
is still granted the old taint, and renews in it, so if the thief must not reach the
other machines either, they move too: each draws a new identity in a new taint, since
a credential's taints never change.

This is the cost of an anonymous, accountless design, and it is a real one.

**On a self-hosted guardian the last paragraph is different, and only the last one.**
There the machine was commissioned by an operator who recorded it, so there is somebody
to tell and something they can do: revocation is that guardian refusing to renew, and
the credential lapses on its own schedule with nothing pushed and no list distributed.
Everything above still holds — the file is still the identity, a thief is still that
anchor, and they remain one until the credential lapses. What changes is that the
lapse now happens, and that the window is the operator's to choose.

## The file, and the directory around it

- `0600`, with the mode set on the descriptor before any content is written. Writing
  and then chmod'ing leaves a window at the umask's mode.
- `0700` on the directory, or `0710` where `anchord`'s own account is let through it —
  which lets that account pass and list nothing, read nothing of root's and create
  nothing. A `0600` file in a directory others may write is one `rename` away from being
  replaced. A directory that already exists is held to the same: one of conflux's own left
  wider is narrowed to `0700`, and one another account owns is refused rather than used,
  since whatever that account put in it is not conflux's.
- On Windows, mode bits mean nothing and `%ProgramData%` lets `Users` read and create
  beneath it, so conflux gives its root to SYSTEM and Administrators — owner, and a
  protected DACL everything beneath inherits — and refuses a root another account made.
  See [windows.md](windows.md#file-permissions).
- Never in an argv. It travels on stdin to `anchorctl start -manifest -`, becomes an
  inline secret on the wire, and is never named as a path in the request — so it never
  appears in `ps` or `/proc/*/cmdline`.
- Never in a log. The types that carry it have `String` and `GoString` methods that
  return `<anchor manifest, redacted>`, so no `%v` or `%#v` anywhere can print it.

## A backup of the state directory is the machine

`/var/lib/conflux` in a backup, a VM snapshot, or a container image **is** the
identity. Restoring that backup onto a second machine while the first is still running
makes the anchor exist twice, which anchor reports as an address conflict.

Treat it the way you would treat an SSH host key.

## The extracted binaries

conflux writes `anchord` and `anchorctl` to disk and executes them. That is a dropper
shape, and it is worth being honest about how it is bounded:

- The path is content-addressed under the state directory — root-owned, and writable by
  nobody else, on a filesystem the administrator chose. Not `/tmp`, which is world-writable and, under
  `PrivateTmp=`, is not even the same directory the service sees. On Windows, where the
  name of a set directory is computable and `%ProgramData%` would let anybody create it,
  a set is run only if Administrators, SYSTEM or the account running conflux owns it,
  and extracted again otherwise.
- The bytes come from inside the conflux binary. There is no download and no network
  path into them; verifying conflux verifies them.
- `conflux version` prints both SHA-256s, so what is on disk can be checked against a
  release note.

The boot service is held to the same rule. It runs as root (SYSTEM on Windows) and
starts whatever file it names at every boot, so it names a copy of conflux in the same
state directory, which `up`, `proxy`, `install` and `start` refresh, and never the file
conflux was run from — a home directory or a download that another account could swap
for a program of its own, to be run as root at the next start. On Windows the root's
DACL is set by the first conflux command that creates it, extraction included, and a
root that holds anything another account made before then is refused rather than
repaired around it.

`CONFLUX_DIR` can point the extraction somewhere else, which is a knob worth knowing
about: it lets a caller choose the directory a root daemon executes from. It exists
for tests and for hosts where the default filesystem is `noexec`. The directory it names
must belong to the account running conflux — on every platform, a root another account
owns is refused — and it is used as an absolute path, so the service registered under it
runs from where it was installed whatever the working directory was.

## What anchord runs as

`anchord` is the process that parses what the network sends, so it is the one worth
confining. The rule: **it runs as root, or with a capability, only where the host or the
configuration needs that** — and wherever giving something up would cost an operation or a
function, it keeps it, and `conflux status` says why:

```
  anchord      conflux, with no privilege
  anchord      conflux, with CAP_NET_ADMIN for its interface
  anchord      root — firewalld takes changes only from root, and anchord lets its port in through it
```

The supervisor, `conflux serve`, stays root (SYSTEM on Windows). It has no listener, it
owns the root-only state — the identity, and the binaries root executes — and it is the
part that hands `anchord` exactly what its mode needs.

| | `conflux proxy` (userspace) | `conflux up` (TUN) |
|---|---|---|
| Linux | the account `conflux`, no capabilities, `no_new_privs` | `conflux` with `CAP_NET_ADMIN` |
| macOS | the account `_conflux` | root: only root gets a utun |
| FreeBSD, OpenBSD | the account (`conflux`, `_conflux`) | root: only root gets a tun |
| Windows | `LOCAL SERVICE`, every privilege but `SeChangeNotify` removed, `NT SERVICE\conflux` added | SYSTEM: wintun |

What changes that, and why:

- **Linux, TUN, and the host's firewall.** anchor opens its UDP port through the host's
  firewall whenever it has an interface, and with `--subnet` or `--serve-exit` sets the host
  up to forward. With `nft`, or `iptables` on nf_tables, `CAP_NET_ADMIN` is all of that.
  Where `nft` is missing, anchor's router falls back to `iptables -m set`, whose set match
  opens a raw socket, so `CAP_NET_RAW` is added. Where firewalld runs (it takes changes only
  from root, over D-Bus) or an installed `iptables` is on the legacy backend (its lock is in
  `/run`, and it needs raw sockets), `anchord` stays root.
- **Linux, userspace, and the UDP buffers.** quic-go sizes its socket buffers to 7 MiB,
  past `net.core.rmem_max`/`wmem_max` with `SO_RCVBUFFORCE`, which is `CAP_NET_ADMIN`'s.
  Where those limits are under 3670016 the account is given `CAP_NET_ADMIN` for it; raise
  them (`sysctl -w net.core.rmem_max=7340032 net.core.wmem_max=7340032`) and it is not.
- **A port below 1024** — conflux.json's, or the credential's `listenPort` — adds
  `CAP_NET_BIND_SERVICE` on Linux (unless `ip_unprivileged_port_start` already allows it),
  and keeps `anchord` root on OpenBSD and on FreeBSD below `reservedhigh`.
- **An uplink's device** is opened through its group (`dialout`, `uucp`), which the account
  is given; one only root may open keeps `anchord` root. That group opens every device it
  owns, not only the uplink.
- **`/dev/net/tun`** that only root may open keeps a TUN's `anchord` root.
- **Where the supervisor cannot drop** — it is not root, a container gave it only some
  capabilities (dropping needs `CAP_SETUID`, `CAP_SETGID`, `CAP_CHOWN`, `CAP_FOWNER`,
  `CAP_DAC_OVERRIDE` and `CAP_KILL`), the account cannot be made (no `useradd` or `adduser`),
  an account of that name exists that conflux did not make, the account cannot run `anchord`
  here (a `CONFLUX_DIR` it cannot pass through, `noexec`, a user namespace with no uid for
  it), or Windows will not log `LOCAL SERVICE` on for it — `anchord` runs as the supervisor
  does, which is never more than it had before, and says why.

### What the account can reach

| Path (Linux) | Owner | Mode |
|---|---|---|
| `/var/lib/conflux`, `bin/`, `bin/<set>/` | root, group `conflux` | `0710` — pass through, list nothing |
| `bin/<set>/anchord` | root, group `conflux` | `0750` (`anchorctl` stays root's alone) |
| `anchord.json` | whoever `anchord` runs as | `0600` |
| `anchor/` — the account's `-dir` | `conflux` | `0700` |
| `anchor.root/` — a root anchord's `-dir` | root | `0700` |
| `/run/conflux` | root, group `conflux` | `0710` |
| `/run/conflux/anchord/` — the socket and its lock | whoever `anchord` runs as | `0700`, made afresh at every start |
| the configuration, the manifest, the state, the token, the pid record, the service's copy | root | unchanged |

Three rules hold it together:

- **Nothing is re-owned in a directory the account can write.** The account can hard-link
  into its own directory any file it can name, a binary root runs included, so a `chown -R`
  there could hand it that file. When `anchord` changes identity — `proxy` and `up` on macOS,
  a host that gains firewalld — what the anchor kept is *copied* to the other directory:
  regular files with one link, read through a root nothing leads out of, written fresh.
- **A root anchord never works in the account's directories.** anchor follows a symlink in
  its directory; one the account planted would lead root's writes wherever it pointed. So
  root's has its own `-dir`, and `run/anchord/` is made afresh, for the right owner, before
  every start, after everything that runs as the account has been ended.
- **Root reads what the account wrote as untrusted.** The socket's lock, which the reaper asks
  about, is opened to read, never created, and never through a symlink; a Subnets order's
  `subnets.json`, which `conflux status` prints, is read only as a regular file of one link
  and bounded size, with control characters taken out of who set it.

The token reaches `anchord` in its environment (`ANCHORD_TOKEN`), so the file the CLI reads it
from stays root's.

**One thing works differently, by design:** a path a pass-through command makes `anchord`
open itself — `keygen -out` and `priv -out`, which write "on the daemon's filesystem", and
export certificates set at run time by path — is opened with `anchord`'s rights. One the
account cannot reach is refused by `anchord`, naming it; leave out `-out` and the key comes
back to your terminal instead. Paths in `conflux.json`'s export block are not affected:
conflux reads them and hands their content over.

### What a compromised anchord still has

The account's own directories, its socket, the identity it already holds in memory, and
the network. With a TUN on Linux, also `CAP_NET_ADMIN` in the host's network namespace —
interfaces, routes, nf_tables — and, there, no `no_new_privs`, because `nft` and `iptables`
are run under it and SELinux would refuse their transitions. On Windows, the logon session
it shares with the other services that run as `LOCAL SERVICE`. Wherever it runs as root, all
of it, as before.

## What conflux does not defend against

- **A root-equivalent local attacker.** They can read the manifest, and that is the
  end of it.
- **A compromised release channel**, beyond what the digests in `conflux version` and
  the release attestation give you.
- **Traffic analysis**, which is anchor's problem and is discussed in anchor's own
  security documentation.
- **Anything a taint appears to promise.** Taints are a blast-radius control inside a
  realm that has already decided everyone in it is a member — not a tenant boundary.
  Taint names are not secret: anybody may ask the alpha API for a credential in any
  name, and the tag derives from a public root id, so any member can compute the tag for
  a name it can guess. A taint is as private as it is hard to guess: a *generated* one,
  about 128 bits, is unguessable and that is the whole of its protection. `prod` is not.
  And a member whose credential grants the `taint` capability can move a machine to
  other compartments while it runs; an alpha credential grants that to nobody, a
  guardian may. See [concepts.md](concepts.md).

## Reporting

Security issues in conflux belong here; issues in the protocol, the handshake or the
credential format belong to [anchor](https://github.com/veil-net/anchor).
