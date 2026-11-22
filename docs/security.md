# Security

This page is about what conflux adds to [anchor's threat
model](https://github.com/veil-net/anchor/blob/main/docs/security.md), which is where
the protocol, the handshake and the credential chain are analysed. conflux adds
exactly two things anchor does not have: **an executable written to disk**, and **a
private key in a file**.

## A stolen `manifest.b64` is permanent

The manifest holds the 64-byte identity seed. Anyone who has it *is* that anchor. A
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

**Or there is no file.** An ephemeral run (`--ephemeral`, [ephemeral.md](ephemeral.md))
holds the identity in memory alone, from the enrolment response or the manifest handed in
straight through to anchord, and writes it nowhere; core dumps are off for it and its
anchord. What is left to steal is the memory of a running process, which only root on that
host can read, and when the run stops there is nothing at all.

## The file, and the directory around it

- `0600`, with the mode set on the descriptor before any content is written. Writing
  and then chmod'ing leaves a window at the umask's mode.
- `0700` on the directory, or `0710` where `anchord`'s own account is let through it —
  which lets that account pass and list nothing, read nothing of root's and create
  nothing. A `0600` file in a directory others may write is one `rename` away from being
  replaced. On Windows, mode bits mean nothing and `%ProgramData%` lets `Users` read and create
  beneath it, so conflux makes its root the Administrators' under a protected DACL granting SYSTEM
  and the Administrators alone, set as the root is made, which everything beneath inherits. See
  [windows.md](windows.md#file-permissions).
- Conflux's folders are conflux's by their names: the platform's roots (`/etc/conflux`,
  `/var/lib/conflux` and `/run/conflux` on Linux, their counterparts on macOS and the BSDs,
  `%ProgramData%\conflux` on Windows), an ephemeral run's, and under `CONFLUX_DIR=<dir>` the folder
  `<dir>/.conflux`, which conflux makes inside `<dir>` and keeps everything of its own in. Conflux
  makes each as above, and whatever is at one of those names and is not as conflux makes a root — a
  link, a file, a directory another account owns, or whose mode or ACL lets another account write it,
  or on Windows whose DACL grants another account anything — is removed as itself from the folder it
  is in, through a handle held on that folder, never followed, and the root made afresh, with
  nothing of what it held: a root widened by hand loses the identity in it. The folders conflux
  keeps in a root — `run/` and `logs/` where they are in it, `bin/` and `anchor.root/` — are held to
  the same, and each that is not as conflux makes it is removed whole and made afresh; `anchor/`,
  which `anchord`'s own account is given, is that account's. So is each file conflux keeps in a root —
  `conflux.json`, `state.json`, `manifest.b64`, `anchord.priv`, `way`, the two lock files and the
  boot service's copy of conflux — and one that is not as conflux makes it (a link, a folder, another
  account's, or one another account may change; on Windows one an administrator's process left that
  administrator's, as an earlier conflux left the service's copy on a Windows client) is removed as
  itself, for what writes it to make afresh: such a `manifest.b64` takes the identity with it. The
  supervisor alone leaves the copy as it makes the roots, since it runs from it — Windows will not
  remove a running image, and one removed on Unix would leave the service nothing to start — and then
  places one not there, or not as conflux makes it, afresh from its own image, written beside it and
  renamed over it, the running one moved aside first on Windows, before it reads anything, so none
  survives a start; the next `up`, `proxy`, `observe`, `install`, `enrol`, `start` or `update` places one
  afresh too, and the boot service is never started again on one that is not, nor in roots the
  readers' check refuses.
  `anchord.json` is `anchord`'s own account's. Nothing in a root is
  kept or protected for anybody: what is in conflux's folders is conflux's to overwrite, empty or
  remove, and `uninstall` removes them whole, whatever anybody put in them.
- Every folder conflux did not make — a `CONFLUX_DIR` itself, and every folder above a root — is
  never changed and never judged. A `CONFLUX_DIR` is the user's choice, and choosing it is the
  user's responsibility: whoever can change it, or a folder above it, can put a root of their own
  where conflux's was. conflux owns `.conflux` inside it, and remakes it as it makes it: another
  account's `.conflux` there is none of conflux's, removed as above where it may be.
- Every command that reads a root without making it — `status`, a pass-through, `renew`, `down`,
  `uninstall`, `update` asking whether the anchor runs, and every reader of an ephemeral run's root —
  holds it to the same judgement first, the readers' check, before it reads, runs or signals anything
  in it by its name: the directory at the root's own name, looked up in the folder held and never
  followed, as conflux makes a root — owned by root or the account running conflux, and
  written by nobody else; on Windows owned by SYSTEM, the Administrators or TrustedInstaller, and
  granting nobody else anything. What conflux picks itself — the platform's roots, an ephemeral run's,
  an elevated reader's temporary copy of anchorctl — an elevated conflux never trusts its own account
  with by its SID: its processes that are not elevated could have made and filled what that account
  owns or is granted. Nothing above a root is judged. A root that fails is refused, saying why, with nothing in it read, run or stopped; with none there the command
  says nothing is installed, reading nothing, since what is at a name that was not there a moment ago
  is whoever made it first's. Nothing in a root that passes is judged: nobody else can have put anything there. The
  one place conflux reads what another account may write is `anchord`'s own: its anchor directory,
  `anchord.json` and the run directory's `anchord/`, read as untrusted, never through a link nor
  blocking on a FIFO. `help`'s `anchorctl`, and that of `status`, `renew` and a pass-through, is
  this build's extraction in a root that passes the readers' check, taken as it is found; where it
  is not extracted yet it is extracted into `bin/`, where that is there and as conflux makes it,
  adding a set and removing none, and otherwise it runs from a private copy in a temporary
  directory, removed once it has run: a reader makes neither a root nor `bin/`, and removes nothing
  from one a service may be running from. A pass-through to a socket the user named takes it the
  same way.
- Never in an argv. It travels on stdin to `anchorctl start -manifest -`, and to
  `anchorctl observe -start -manifest -` for the observer, which runs under it too, becomes an
  inline secret on the wire, and is never named as a path in the request — so it never
  appears in `ps` or `/proc/*/cmdline`. A renewed chain goes the same way, to `renew -cred -`
  and `observe -cred -`.
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
  `PrivateTmp=`, is not even the same directory the service sees. A set is run, and on Windows
  `wintun.dll` beside it loaded, only from a root conflux has just made as it makes one, or held to
  the readers' check, in the same process: nobody else can have put anything there, so who wrote a
  set is not asked again, and one not whole at its sizes is extracted again.
- The bytes come from inside the conflux binary. There is no download and no network
  path into them; verifying conflux verifies them.
- `conflux version` prints both SHA-256s, so what is on disk can be checked against a
  release note.

The boot service is held to the same rule. It runs as root (SYSTEM on Windows) and starts
whatever file it names at every boot, so it names a copy of conflux in the same state directory,
which `up`, `proxy`, `observe`, `enrol`, `install`, `start` and `update` refresh, and never the file
conflux was run from — a
home directory or a download that another account could swap for a program of its own, to be run
as root at the next start. Its log, where conflux writes it (`serve --log`, on macOS and FreeBSD), is
opened by its name, as root, only once `EnsureAll` has made the root as conflux makes one, and the
service is registered only by a command that has made it so first (`EnsureAll`: `up`, `proxy`,
`observe`, `install`, `register` and `start`), so the name launchd's `StandardErrorPath` and FreeBSD's
`daemon(8)` open as root is in a directory only root can change. On Windows a root is made with its
DACL set as it is created, so it never carries `%ProgramData%`'s grant to `Users`, not even for an
instant, and everything an elevated conflux makes is the Administrators' from the moment it exists
(`ElevatedDefaultOwner`), never the administrator's own, whose unelevated processes could change it.
A root found there that is not as conflux makes one — another account's, as `%ProgramData%` lets any
account make `conflux` first, one granting another account anything, or a junction — is removed as
itself, through handles, with backup intent so that a DACL granting the Administrators nothing does
not keep it, and made afresh: never adopted, restricted or followed. A root on a network volume,
however it is reached, is refused, by the readers' check too, as the volume conflux holds it open on
says; a link naming a share on the way to a `CONFLUX_DIR` is refused before conflux follows it, by
where the link itself says it leads, by every command that makes a root and by the readers' check,
before anything is looked up there.

On Windows one gap is left, a class: a handle keeps every right it was opened with, and conflux
judges a DACL as it finds it, so where an administrator tightened a DACL after another account had
opened what it guards under a looser one, the handle that account kept outlives the tightening, and
conflux cannot see it. So a root an administrator tightened by hand to SYSTEM's and the
Administrators' alone, which conflux takes as its own, can still be changed through a handle opened
on it before. What conflux makes, it makes with its DACL set as it is created, and the
Administrators' from that moment, which nobody can have opened before; what an administrator
tightens by hand is safe from such a handle once nobody else can hold one: after a restart, or made
again rather than tightened. A link at a root's own name is never followed ([windows.md](windows.md#file-permissions)).

`CONFLUX_DIR` can point the extraction somewhere else, which is a knob worth knowing
about: it lets a caller choose the directory a root daemon executes from. It exists
for tests and for hosts where the default filesystem is `noexec`. A `CONFLUX_DIR` is never
judged: choosing it is the user's responsibility, as choosing where root runs any program from is.
conflux owns `.conflux` inside it, and remakes it as it makes it; the directory itself, and every
folder above it, is never changed and never judged, so a `CONFLUX_DIR` another account can change,
or one inside such a directory, lets that account put a root of its own where conflux's was, with a
conflux in it for the boot service to run as root. The way to a root is walked from the top of its
volume, a name at a time, each directory held open and the next name looked up in it and nowhere
else, never followed (`openat` with `O_NOFOLLOW` on Unix, `NtCreateFile` relative to a handle on
Windows): a link is read where it is and gone on from where it leads, as the system's own lookup
goes, and the root's own name is looked up in the last directory held. On macOS and the BSDs
conflux holds a directory by opening it to read, so one this account may only search, not read, is
held instead by its name in the directory held before it, and the names after it are looked up
through that name; Linux holds every directory open as a path (`O_PATH`), which needs only the
right to search. A root not made yet is made in the last directory held, and each directory
missing on the way is made in the one held before it and held open in turn, never by its name,
conflux's own or one somebody else made at the name meanwhile — a sticky directory such as `/tmp`,
and `C:\`, let anybody make a name not taken yet — and a link there is refused. An installation
keeps a record of the directories it made on the way to a `CONFLUX_DIR`'s root, in its state root
(`way`), a `CONFLUX_DIR` conflux made among them, and an ephemeral run under a `CONFLUX_DIR` one in
its own root, with the `.conflux` it made there; a directory conflux had to make on the way to a
platform's root or an ephemeral run's elsewhere — a user's cache or runtime directory, a home — is
the system's, which other programs fill too, and is not recorded. Uninstall, or the run as it ends,
reads the record before it removes the roots — only from a root as conflux makes one, as a file
another account may have put there, never through a link, and through the root held open first, as
`update` asks after the serve lock — taking only directories above its roots, none the top of a
volume; and then removes each, deepest first, from the directory it is in as a walk of the way
holds it, never through a link and never by its name, leaving any that a link took the place of:
each whole, whatever it holds, but for one that is, or holds, the installation's root while that
holds anything — a root uninstall could not remove, or, as an ephemeral run ends, the `.conflux` it
made on its way, which is the installation's root by its name and may hold an installation made
since, whose identity only `uninstall` removes. A way that ends in where a link leads, at a name
not there, is refused, with nothing made there, and so is one that cannot be walked: `uninstall`
walks every root's way before it acts, and stops there, nothing removed, where one cannot be.

What a root, and each folder and file conflux keeps in it, is held to is its own owner, mode and
ACL: owned by root or the account running conflux, and written by nobody else. On Unix that is its
mode's bits; a group that lets in no account but the one running conflux, as the group database
answers (its members, and every account it is the primary group of), writes for that account
alone. conflux is built without cgo, so on Linux and the BSDs it names the group and the account it
runs as from `/etc/group` and `/etc/passwd` alone, and macOS asks its directory service. On Linux the
root's POSIX ACL counts as well as its mode: an entry that lets a named user other than root and the
one running conflux write it, or a named group that lets in anybody else, once the mask has had its
say, is refused like its mode's bits; once a directory has an ACL its mode's group bits are the
mask rather than what its group may do, so its group is then judged by the ACL's entry for it.
FreeBSD's POSIX.1e ACLs (UFS) are read the same way. An extended ACL — macOS's, or FreeBSD's NFSv4
ACL (ZFS) — is read too, without cgo: an entry allowing anybody but the owner a right to write the
root (to add a file or a directory to it, to delete what is in it or the root itself, or to change
its ACL or owner) is refused, and on macOS, whose ACLs name accounts by a UUID conflux cannot map to
one without cgo, that is every such entry, one naming the account conflux runs as included. An
entry counts whatever it says of inheritance, and one the `CONFLUX_DIR` passes on lands on the
`.conflux` conflux makes inside it, which is then not as conflux makes a root. A deny entry takes
nothing away from what is counted, so it is not read. On Windows a root is held to its owner and
DACL (above). A `CONFLUX_DIR` on a network volume — a share, a drive mapped to one, or a link
leading to either — is refused, before anything is made there, since the owner and DACL of the root
conflux would make there name accounts of the machine serving it, which this one cannot judge. The
root is used as an absolute path, so the service registered under it runs from where it was
installed whatever the working directory was.

## What anchord runs as

`anchord` is the process that parses what the network sends, so it is the one worth
confining. The rule: **it runs as root, or with a capability, only where the host or the
configuration needs that** — and wherever giving something up would cost an operation or a
function, it keeps it, and `conflux status` says why:

An ephemeral run started as root holds its anchord to the same rule under an account of
its own, `conflux-ephemeral`, which the installed supervisor never touches; started as an
ordinary user, anchord runs as that user. See [ephemeral.md](ephemeral.md#who-runs-it-and-as-what).

```
  anchord      conflux, with no privilege
  anchord      conflux, with CAP_NET_ADMIN for its interface
  anchord      conflux, with CAP_NET_RAW to copy what the host's interfaces carry, for the observer
  anchord      root — firewalld takes changes only from root, and anchord lets its port in through it
```

The supervisor, `conflux serve`, stays root (SYSTEM on Windows). It has no listener, it
owns the root-only state — the identity, and the binaries root executes — and it is the
part that hands `anchord` exactly what its mode needs.

| | `conflux proxy` (userspace) | `conflux up` (TUN) | `conflux observe` |
|---|---|---|---|
| Linux | the account `conflux`, no capabilities, `no_new_privs` | `conflux` with `CAP_NET_ADMIN` | `conflux` with `CAP_NET_RAW`, `no_new_privs` |
| macOS | the account `_conflux` | root: only root gets a utun | `_conflux`, its group given read access to `/dev/bpf*` |
| FreeBSD, OpenBSD | the account (`conflux`, `_conflux`) | root: only root gets a tun | refused: no capture |
| Windows | `LOCAL SERVICE`, every privilege but `SeChangeNotify` removed, `NT SERVICE\conflux` added | SYSTEM: wintun | `LOCAL SERVICE`, as userspace |

The observer beside an anchor, `--observe`, adds its column's capture to the anchor's: `CAP_NET_RAW`
beside a TUN's `CAP_NET_ADMIN` on Linux, read access to `/dev/bpf*` beside userspace on macOS,
and nothing where the anchor's `anchord` is root or SYSTEM already.

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
- **The observer** is given its capture and nothing more. Observing alone, the anchor's kept
  settings grant nothing: no port is bound and no uplink opened, so a `port` below 1024 or a
  root-only uplink in `conflux.json` waits for the next `up` or `proxy`. On Linux a kernel with
  no ambient set keeps an observing `anchord` root, and one that cannot be given `CAP_NET_RAW`
  at all — a container that holds it back — has its observer refused, for good. On macOS the
  BPF devices are only root's until the supervisor gives the account's group read access to
  them, which it does at every start ([observe.md](observe.md#what-it-is-given)); where it cannot,
  `anchord` stays root and says why, and devices another group of the host's may read already
  are left alone, the account given that group, as are devices every account may read.
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
  about, a Subnets order's `subnets.json`, which `conflux status` prints, and what is copied
  between anchor directories are all opened one way: to read, never created, never through
  a symlink (on Windows, any reparse point) and never blocking on a FIFO, and used only as a
  regular file of one link (Windows links nothing without the right to write it); the order
  and the copies within a bounded size, and the order with control characters taken out of
  who set it.

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

Where it observes, also a copy of everything the host's interfaces carry — the start of every
flow whole, every other packet's headers and its first bytes — which is the observer's whole
privilege and the reason it is off unless asked for. On Linux that is `CAP_NET_RAW`, which can
also send a packet of its own making, on any interface; on macOS read access to the BPF
devices, which can send nothing.

## FIPS 140-3 and CMVP

**The requirement.** Every cryptographic service conflux's own code uses is an approved
service of the Go Cryptographic Module, used the way the module's Security Policy approves it.
conflux is built against the module (`GOFIPS140` in the Makefile, see
[build.md](build.md#fips-140-3)) and runs in FIPS 140-3 mode, and its tests run with the
module refusing what it does not approve. anchord is its own program, built and claimed by
anchor, whose `docs/security.md` says what it runs and claims; conflux carries it unchanged.

**What may be claimed, exactly.** Every service conflux's code uses is one that the Security
Policy of module v1.0.0 (CMVP certificate #5247) approves, with ML-DSA the one exception:
v1.0.0 has no ML-DSA, and `conflux cert` makes and checks ML-DSA keys and signatures
([cert.md](cert.md)). The binaries run module v1.26.0, which is in CMVP review, has ML-DSA,
and is the module anchord runs, since anchor signs with nothing else; one program carries one
module. So nothing conflux ships runs in a *validated* module yet:

- v1.0.0 is validated, and every service named below but ML-DSA is approved in it.
- v1.26.0 is what the builds run, ML-DSA included, and it is not validated until its
  certificate is issued.

A certificate covers the operating environments it lists, and nothing else. #5247's include
Linux on amd64 and arm64, Windows on amd64 and arm64, macOS on arm64 and FreeBSD on amd64,
which is every target conflux ships but OpenBSD's.

**The services, and how each is used.**

| Service | Standard | Used for | How it is kept approved |
|---|---|---|---|
| SHA-256 | FIPS 180-4 | the digests of the embedded anchor binaries, of a release `conflux update` installs, of anchor's release files and of wintun's archive; a `CONFLUX_DIR` installation's scope | — |
| CTR_DRBG | SP 800-90A | every random byte, through `crypto/rand`: the bearer token anchord is started with, a minted taint | — |
| TLS 1.3 and 1.2, as a client and a server | SP 800-52r2, with the module's KDFs (SP 800-135 for 1.2, HKDF for 1.3), and ML-KEM (FIPS 203) in the hybrid groups | HTTPS to the enrolment API, to GitHub for `conflux update` and for anchor's release files, and to wintun.net; `conflux cert probe` and `serve` | `crypto/tls` in FIPS 140-3 mode offers and accepts only approved parameters: AES-GCM suites (and AES-CBC with SHA-256 on 1.2); P-256, P-384, P-521, the ML-KEM hybrids and ML-KEM-1024; ML-DSA, ECDSA, RSA and Ed25519 signatures; the Extended Master Secret on 1.2 |
| ECDSA, RSA and EdDSA verification | FIPS 186-5 | the server certificate chains of those connections, on Linux and the BSDs; `conflux cert`'s checks of certificates, requests and revocation lists | — |
| ML-DSA key generation, signing and verification | FIPS 204 | `conflux cert`'s keys, and everything it signs and checks with them. **The exception:** not in v1.0.0 | pure ML-DSA alone, no pre-hash; a key is kept as its seed |
| ECDSA, RSA and EdDSA key generation and signing | FIPS 186-5 | `conflux cert`'s classical keys, and what it signs with them | P-256, P-384 and P-521; RSA of 2048 bits or more, PKCS #1 v1.5 or PSS, SHA-2; pure Ed25519, never Ed25519ctx or Ed25519ph |
| SHA-384, SHA-512, SHA3-256, SHA3-384, SHA3-512 | FIPS 180-4, FIPS 202 | the hashes of ECDSA and RSA signatures; `conflux cert fingerprint` | no SHA-1 or MD5 fingerprint is offered |
| SHAKE256 | FIPS 202 | checking an ML-DSA key's expanded half against its seed, as it is read | — |
| PBKDF2, with HMAC-SHA-2 | SP 800-132, FIPS 198-1 | the key that encrypts a private key `conflux cert` writes or reads, and a PKCS#12 bundle's bags and MAC key | a salt of 16 bytes or more; 600,000 iterations written |
| HMAC-SHA-2 | FIPS 198-1 | a PKCS#12 bundle's PBMAC1 MAC (RFC 9579) | PKCS#12's own KDF is never used: a bundle made with it is refused |
| AES-CBC | SP 800-38A | encrypting a private key, or a PKCS#12 bundle's bags, under PBES2 | `internal/pki/pbes2.go` alone builds it; nothing else in conflux holds an AES block |

**What is outside the module.**

- **The chain check on macOS and Windows.** There `crypto/x509` hands a chain verified
  against the system roots to the operating system's verifier, so the certificate signatures
  of conflux's HTTPS are checked by the OS, not by the module. The handshake and the session
  are still the module's.
- **OpenBSD.** The module refuses to run there (`-fexecute-only`), so OpenBSD's conflux is
  built without it, reports `fips140 off`, and claims nothing.
- **SHA-1.** The one SHA-1 an installation involves is the Windows service SID, `S-1-5-80`
  and the SHA-1 of the service's name. Windows computes it (`RtlCreateServiceSid`); conflux
  computes no SHA-1 itself.

**Seeing it.** `conflux version` and `conflux status` say `fips140 on, Go Cryptographic Module
v1.26.0`, and `GODEBUG=fips140=debug conflux version` prints the module's self-tests and its
integrity check (`fips140: verified`). A build against the module that is run with
`GODEBUG=fips140=off` refuses every command, with exit 70, as anchord refuses to start: running
anyway would make all of the above untrue while nothing on the machine said so. A build without
the module (OpenBSD's) runs, claiming nothing, but its `conflux cert` refuses every command
with exit 70: keys and certificates are artifacts other people rely on.

**Held to it.** The tests run with the module refusing what it does not approve
(`GODEBUG=fips140=only`). `internal/pki/approved_test.go` reads every non-test Go file for
what that refusal does not catch: golang.org/x/crypto, MD5, SHA-1, DES, RC4, DSA, crypto/ecdh,
AES in CTR, CFB, OFB or ECB, AES-CBC outside `pbes2.go`, GCM under a caller's nonce, RSA PKCS
#1 v1.5 encryption, legacy PEM encryption, Ed25519ctx and Ed25519ph, and the module's
enforcement switched off.

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
