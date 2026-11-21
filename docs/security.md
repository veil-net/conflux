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
- No root is a directory others keep what is theirs in, however it is reached — at its name or
  through a link there — and whoever owns it: such a one is refused, never narrowed, filled or
  emptied, by every command that makes a root, by `update` and `start` before they remove anything
  from one (Windows), and by `uninstall`, which refuses it before it removes
  anything, the boot service included, or, where the root's name is a link to it, removes the link
  alone, unless it holds what conflux never makes there (below). On Unix that is a sticky directory (`/tmp`,
  `/var/tmp`, `/dev/shm`), `/`, every directory directly under `/` (`/home`, `/opt`, `/srv`, `/usr`
  …), which only root makes there, but one conflux may have made a root of — its owner's, at `0700` or
  `0710`, and holding anything, an empty one, as `/lost+found` may be, refused; what it holds is held
  to conflux's names (below), so `/root` is refused for its own files — the system's log directory, a directory above where a platform
  root is kept by default (`/etc`, `/var`, `/var/lib` …), and the directory the running conflux is in
  or one above it, but for the boot service's own root where the running conflux is the copy the
  service runs from it, one file with the copy at its name there, and the root already holds this
  installation's own state, a name conflux makes there besides the copy and the lock files: then whatever the root's mode,
  and directly under `/` too, a state root found widened is narrowed by the service, as by any command
  that secures it, rather than refused at every start; a folder holding the running conflux and nothing
  of an installation's, as `/usr/local/bin` does, is refused, and a sticky one whatever it holds. On Windows it is a volume's root (`C:\`, `\\?\C:\`, or the volume by its
  GUID), the top of any volume a drive letter reaches, a `SUBST` letter's folder among them, which no
  folder holds for it to be removed from, a folder directly under a volume's root that
  Windows made, which TrustedInstaller or SYSTEM owns (`Program Files`, `ProgramData`, `PerfLogs` …)
  where what conflux or an administrator makes there is the Administrators' or the administrator's,
  `%ProgramData%`, `%SystemRoot%`, `C:\Users` and `C:\Users\Public`, the folder the running conflux
  is in or one above it — `%ProgramFiles%\conflux`, where `install.ps1` puts it — but for the boot
  service's own root, as on Unix, unless its DACL makes it a space other accounts share, and any folder whose own DACL makes it a space other accounts
  share, as `%ProgramData%`'s does: Users let add to it and to the folders made in it, and `CREATOR
  OWNER` passed on, so each owns what it adds. A folder that only inherits such entries, as one made
  in `%ProgramData%` does, is a root like any other, judged and restricted.
- No root holds what conflux never makes there, but a working one. A root whose top level — at its
  name, or where a link there that conflux follows leads — holds any name but conflux's own is
  somebody else's, a `CONFLUX_DIR` at a folder of homes, at `/root` or a home kept at `0700`, or a link
  at a root's name pointed at a program's folder, and is refused and left as it is, never adopted,
  narrowed, filled or emptied: by every command that makes a
  root, by `update` and `start` before they remove anything from one (Windows), and by `uninstall`,
  which refuses it before it removes anything, the boot service and a link at its name included. The
  refusal names the first stray entry. Conflux's names are one list (`paths.Dirs.own`): the
  configuration, the identity and the state, the privilege record, the way record, the locks, the
  extraction and the service's copy of conflux, with the image an update moved aside, `anchord`'s
  `-config` and anchor directories, with the names the supervisor makes and sets them aside under,
  the run and log directories and what they hold where those are the root, an ephemeral run's root
  inside a `CONFLUX_DIR`, and what an atomic write, the service's copy or an update leaves before
  its rename (`.tmp-`, `.conflux-`). An empty directory, and a root conflux made, hold nothing else.
  The one exception is a working installation's or run's root: one conflux has secured — root's or the
  account running conflux's at `0700` or `0710` with no ACL letting another account write it, or on
  Windows SYSTEM's or the Administrators' under a protected DACL granting nobody else anything — that
  already holds this installation's own state, a name of conflux's there besides the service's copy,
  the image an update moved aside and the lock files. Nothing in it is a stray, since only an account
  conflux trusts could have put it there: an editor's backup beside a hand-edited `conflux.json`
  (`conflux.json.bak`, `conflux.json~`, `.conflux.json.swp`) in a working install is fine. The same
  root widened by hand, and a secured directory holding nothing of an installation's, are held to
  conflux's names, as any directory conflux would adopt is.
  Nor is a file at a root's name conflux's, nor anything else that is neither a directory nor a link:
  conflux makes only a directory there, and `uninstall` refuses one, as it refuses such a root,
  rather than remove it.
- `0700` on the directory, or `0710` where `anchord`'s own account is let through it —
  which lets that account pass and list nothing, read nothing of root's and create
  nothing. A `0600` file in a directory others may write is one `rename` away from being
  replaced. A directory that already exists is held to the same: one of conflux's own left
  wider is narrowed to `0700`, and one another account owns, or whose own extended ACL (macOS,
  NFSv4) lets another account write or move it past what the narrowing rewrites, is refused
  rather than used, since whatever that account put in it is not conflux's. Narrowing takes
  nothing out of a root that was wider, so what it holds is judged as well, before the narrowing
  and again after, as on Windows: everything in it, each directory gone into, read from the root
  held open by `fstatat` and `openat` and never by a name, an entry's ACL through its own
  descriptor. A link is refused, wherever it leads: conflux makes none in a root, and one at
  `logs/conflux.log` would have the service write its log through it as root. So is anything but a
  file, a directory or a socket, an entry another account owns, and anything another account may
  write by its mode, the sticky bit letting nothing through, or its ACL; and a file with a second
  name, which would lead root's writes wherever that name is, in a root found wider than conflux
  leaves one, which another account may have been able to write, before the narrowing and after it,
  and in a root at `0700`, which only root and the account running conflux can search, and conflux
  makes no file of two names. In a `0710` root a second name may be `anchord`'s account's, which may
  link what it can name, and refusing it would send an operator to remove a file conflux keeps, the
  manifest among them, so it is taken there; the refusal elsewhere names the file and asks for its
  other name to be found first. That leaves a wide root narrowed by hand to `0710`, rather than by
  conflux, holding whatever second name another account made in it while it was wide, so the
  readers' refusal of a wide root asks for conflux to narrow it — `sudo conflux start` or
  `install`, and for a `CONFLUX_DIR`'s `sudo env CONFLUX_DIR=<dir> conflux start`, or `up` where it
  has no service registered, since `sudo` keeps no `CONFLUX_DIR` of its own — and not for a `chmod`. `anchord`'s own account is conflux's: what the supervisor gives it — `anchor/`,
  `anchord.json` and the run directory's `anchord/` — it may own, and its directories are not gone
  into, since conflux reads what `anchord` writes there as untrusted; anything else it owns is
  refused, as it can make nothing elsewhere in a root. Every reader of an ephemeral run's root
  judges what the root holds the same way.
- On Windows, mode bits mean nothing and `%ProgramData%` lets `Users` read and create
  beneath it, so conflux gives its root to SYSTEM and Administrators — owner, and a
  protected DACL everything beneath inherits, set as the root is made — and refuses a root
  another account made. See [windows.md](windows.md#file-permissions).
- Every command that reads a root, or acts on what it holds, without making it — `status`, a
  pass-through, `renew`, `down`, `uninstall`, `update` asking whether the anchor runs,
  and every reader of an ephemeral run's root — holds it to one check
  first, the readers' check, on every platform, before it reads anything in it by its name
  (`uninstall` then removes a root that fails it all the same, reading and signalling nothing in
  it, through handles held from the top of its volume down, following no link but one at the root's
  own name that this check would follow, and on Windows the SYSTEM service too, to a directory conflux
  has secured as a root, and with a `CONFLUX_DIR`'s way held to the same rule; the
  roots it refuses, before it removes anything, are a `CONFLUX_DIR` whose way another account
  controls, since that account could have put a directory of its own where the root is, a root
  that is a shared or system directory, one holding what conflux never makes there (above), and one
  whose name it cannot look up at all, which nothing has judged; see
  [commands.md](commands.md#conflux-uninstall)):
  whoever could have put a configuration, a pid record, a token or a binary there would otherwise
  have conflux read, signal or run theirs. The root's owner must be root (SYSTEM or the
  Administrators on Windows) or the account running conflux, a link at its name included, and
  nobody else may write it or point it elsewhere: by its mode and ACL as found on Unix, the sticky
  bit letting nothing through, and on Windows by the DACL a root conflux secured keeps, which grants
  nobody else any right, to read it included, a link at its name that leads off the machine refused.
  A `CONFLUX_DIR`'s way is held to the rule it is made by, for the account reading it, and on Windows
  a link anywhere on it that leads off the machine is refused.
  Nothing is narrowed: a root that fails is refused, saying why, with nothing in it read, run or
  stopped, and with none there the command says nothing is installed, reading nothing,
  since what is at a name that was not there a moment ago is whoever made it first's; a link at a
  root's name, or on a `CONFLUX_DIR`'s way, that leads nowhere is refused, not taken for none. Every root
  conflux makes passes it. `help`'s `anchorctl` runs from the extraction in a root only where the
  root passes it, and otherwise from a private copy in a temporary directory: a root that fails is
  not refused for help, and nothing in it is read. A reader of an ephemeral root, which another
  process keeps, then judges what the root holds too, each thing by its own owner and its mode and
  ACL, or DACL, as above and in [windows.md](windows.md#file-permissions).
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
  `PrivateTmp=`, is not even the same directory the service sees. On Windows, where the
  name of a set directory is computable and `%ProgramData%` would let anybody create it,
  a set is run only if Administrators, SYSTEM or the account running conflux owns it,
  and extracted again otherwise.
- The bytes come from inside the conflux binary. There is no download and no network
  path into them; verifying conflux verifies them.
- `conflux version` prints both SHA-256s, so what is on disk can be checked against a
  release note.

The boot service is held to the same rule. It runs as root (SYSTEM on Windows) and starts
whatever file it names at every boot, so it names a copy of conflux in the same state directory,
which `up`, `proxy`, `install` and `start` refresh, and never the file conflux was run from — a
home directory or a download that another account could swap for a program of its own, to be run
as root at the next start. Its log, where conflux writes it (`serve --log`, on macOS and FreeBSD), is
opened by its name, as root, only once `EnsureAll` has made the root conflux's alone, and the service
is registered only by a command that has made it so first (`EnsureAll`: `up`, `proxy`, `observe`,
`install`, `register` and `start`), so the name launchd's `StandardErrorPath` and FreeBSD's `daemon(8)` open as root is
in a directory only root can change. On Windows the root's DACL is set as the first conflux command that creates it makes it, extraction
included, so it never carries `%ProgramData%`'s grant to `Users`, not even for an instant. A root
found already there is judged and restricted through one handle on the directory itself, never by
its name again, refused where its DACL lets another account move what is in it, made to hold its
`run\` directory through that handle before anything in it is judged, so that no handle opened on it
earlier can make a junction of it whatever conflux then decides, a refusal included, and refused if
it became one meanwhile; a root already secured is made to hold it too. One that holds anything
another account may change — that it owns, or that it may write, move or point elsewhere,
`anchord`'s own account aside, judged as found, again once the root is restricted, and on every run
after, and in an installation's root for SYSTEM, as the service judges it, so the administrator
running conflux counts as another account there — is refused rather than repaired around, by every reader of an ephemeral root too, after the
readers' check, as is a junction in it, and a root that is itself a junction another account may
point elsewhere; one nobody else may is replaced with a junction conflux makes, through its own
handle, leading to the directory it judged (see [windows.md](windows.md#file-permissions)). What
the account running conflux owns in an installation's root — an administrator's own, as a Windows
client's default-owner policy leaves what an elevated administrator's tools make, or as an earlier
conflux left it — is refused there like any other account's, not given to the Administrators: a
handle opened while the administrator owned it keeps its rights whoever owns it after. Every
elevated conflux makes the Administrators the owner of what it makes as it starts, so nothing it
makes is ever the administrator's; what an earlier conflux left so, `update`, and a plain `start`
where no supervisor serves the root, remove and make again — the lock files, `logs\`, `run\`, `bin\`, the service's copy and its moved-aside image,
`anchord.json` — through handles, never by a name and never through a junction, the log the service
would take kept through handles and moved back into the `logs\` made again, and anything else
wrong, the identity, configuration and state among it, it refuses, naming it. On Unix there is
nothing to remake: what root or the account running conflux owns passes already, and the service
runs as root, as every command that makes an installation's root does. A root
on a network volume, however it is reached, is refused, by the readers' check too, as the volume
conflux holds it open on says; a link naming a share, at a root's name or on the way to a
`CONFLUX_DIR`, is refused before conflux follows it, by where the link itself says it leads, by
every command that makes a root and by the readers' check, before anything is looked up there.

On Windows two gaps are left. The first is a class: a handle keeps every right it was opened with,
and conflux judges a DACL as it finds it, so where an administrator tightened a DACL after another
account had opened what it guards under a looser one, the handle that account kept outlives the
tightening, and conflux cannot see it. So a handle on a root, opened with `DELETE`, can still move
it aside; one on a directory above a `CONFLUX_DIR`, opened to rename what is in it, can move the
root aside and put another in its place; one on an empty folder in the root, opened to write its
attributes, can make a junction of it; and one on a junction root, opened to write its attributes,
can point it elsewhere once the junction is tightened to SYSTEM's or the Administrators' under a
protected DACL granting nobody else the right to write it, add to it, move it or change who may, as
conflux leaves the one it makes, since conflux then takes it as its own and does not replace it.
An owner always holds the right to read and change a DACL, so the same goes for a root the
administrator running conflux owns, which conflux never makes but repairs rather than refuses,
since it holds the identity and cannot be made again: a handle the administrator's own processes,
elevated or not, opened on it while they owned it keeps those rights once conflux has given it to
the Administrators and restricted it, and can change its DACL after. What conflux makes, it makes
with its DACL set as it is created, and the Administrators' from that moment, which nobody can have
opened before; what an administrator tightens or owns by hand is safe from such a handle once
nobody else can hold one: after a restart, or made again rather than tightened. The second is a way to a root that
conflux does not judge whole: a drive letter that stands for a folder rather than a volume — one
`SUBST` or `DefineDosDevice` defined. conflux judges a `CONFLUX_DIR`'s way from the top of its
drive, `X:\`, so the folders above the one the letter stands for are not judged, and whoever may
move one of them could put another root in its place. Only an administrator can define a letter the
service's account or an elevated conflux sees, and conflux does not refuse one: a `CONFLUX_DIR` on
such a letter is held only as far as its folder's own parents are kept to SYSTEM and the
Administrators by whoever defined it. A link on a `CONFLUX_DIR`'s way that leads to such a letter is
followed the same way, and judged from the top of what the letter stands for; so is one leading to a
local volume the mount manager names by no GUID, which only a letter defined the same way, outside
the mount manager, can reach, since a link conflux follows names a drive letter or a volume's GUID.
A root that is itself such a link is refused, as no junction of conflux's could lead there
([windows.md](windows.md#file-permissions)).

`CONFLUX_DIR` can point the extraction somewhere else, which is a knob worth knowing
about: it lets a caller choose the directory a root daemon executes from. It exists
for tests and for hosts where the default filesystem is `noexec`. The directory it names
must belong to the account running conflux — on every platform, a root another account
owns is refused — and so must the way to it: a `CONFLUX_DIR` inside a directory another
account can change is refused too, naming that directory and who can change it, since
whoever can move the root aside can put a directory of their own in its place, with a
conflux in it for the boot service to run as root. The way is walked from the top of its volume,
a name at a time, each directory held open and judged before the next name is looked up in it, and
that name looked up in the directory held and nowhere else, never followed (`openat` with
`O_NOFOLLOW` on Unix, `NtCreateFile` relative to a handle on Windows): a link is read where it is,
judged, and gone on from where it leads, so nothing on the way is looked up afresh after it was
judged, the one case below aside, or used before. On macOS and the BSDs conflux holds a directory
by opening it to read, so one this account may only search, not read, is held instead by its name in
the directory held before it, and the names after it are looked up through that name. That opens no
way in: the directory the name is in was judged before the name was looked up, so only root and the
account running conflux may change where the name leads — or, in a sticky directory, the name's own
owner, whom the judgement of the directory itself, before anything is looked up in it, holds to root
and that account as well — and those two could change the way anyway. The way to a root of the
platform's own is not judged at all, on any platform: the directories above `/etc/conflux`,
`/var/lib/conflux` and `/run/conflux` on Linux and their counterparts on macOS and the BSDs, and
`%ProgramData%` and `C:\` above `%ProgramData%\conflux` on Windows — and, for an ephemeral run of an
ordinary user, that user's own runtime and cache directories, or the sticky `/tmp`. Only root or an administrator can change those directories, or
the user their own, and whoever can could change conflux, or anything it runs, anyway; so a link or a
junction an administrator put there is followed, as any program follows it, and a lookup through
the name is the lookup by name any program makes there. Only a `CONFLUX_DIR`, which whoever set it
chose, has its way judged. Linux holds every directory open as a path (`O_PATH`), which needs
only the right to search. A root not made yet is held to this before anything is made, as far as the
way is there, and each directory missing is made in the last one held and held open in turn, never
by its name, and held to the same rule before anything is made in it, conflux's own or one somebody
else made at the name meanwhile — a sticky directory such as `/tmp`, and `C:\`, let anybody make a
name not taken yet — and a link there is refused. An installation keeps a record of the directories
it made on the way, in its state root (`way`), which uninstall reads before it removes the roots —
where the readers' check refuses what that root holds too, as a file another account may have put
there, never through a link, and through the root held open first, as `update` asks after the serve
lock: for a `CONFLUX_DIR`, once its way passes parents' rule, the root's owner root, SYSTEM, the
Administrators or the account running conflux, and a link at the root's name followed only where its
owner is one of those, nobody else may point it elsewhere, and it leads to a directory one of those
owns — taking only directories above its roots, since all a record somebody else wrote
could lead to is removing; and then
removes each that is empty, deepest first, from the directory it is in as a walk of the way holds
it, never through a link and never by its name, leaving any that holds something or that a link
took the place of. Each step of the way is judged once, as the root
is made or found: what conflux then does with the root itself does not walk its way again. One made at the root's own name is the root, held to the rules a
root found there is (a directory of this account's that is too wide is narrowed, on Unix), though a
link there is still refused; and a way that ends in where a link leads, at a name not there, is
refused, with nothing made there. The way to it is every directory the
lookup of the root passes through: those above it as it is spelled and, for each link on the
way — a junction among them on Windows, which the lookup follows as it does a link — the
directory the link is in and those above where it leads, however many links are chained, with
each link held to its owner too, who may point it elsewhere. On Unix that is any directory on
the way owned by an account other than root and the one running conflux, or one its group or
anybody may write, unless it is sticky, as `/tmp` is, where nobody may rename what is not
theirs. A group that lets in no account but the one running conflux, as the group database
answers (its members, and every account it is the primary group of) — the group of one user
that Ubuntu gives each, whose directories its umask of 002 leaves group-writable — writes for
that account alone, so its write is not refused; a group with anybody else in it, or one the
database cannot answer for, is. conflux is built without cgo, so on Linux and the BSDs it
names the directory's group and the account it runs as from `/etc/group` and `/etc/passwd`
alone: one that is only in a network directory (LDAP, SSSD) is not found there, and the group
is refused. macOS asks its directory service either way. On Linux the directory's POSIX ACL
counts as well as its mode: an entry that lets a named user other than root and the one running
conflux write it, or a named group that lets in anybody else, once the mask has had its say, is
refused like its mode's bits. Once a directory has an ACL its mode's group bits are the mask
rather than what its group may do, so its group is then judged by the ACL's entry for it.
FreeBSD's POSIX.1e ACLs (UFS) are read the same way. An extended ACL — macOS's, or FreeBSD's NFSv4 ACL
(ZFS) — is read too, without cgo: an entry allowing anybody but the owner a right to write the
directory (to add a file or a directory to it, to delete what is in it or the directory itself,
or to change its ACL or owner) is refused, and on macOS, whose ACLs name accounts by a UUID
conflux cannot map to one without cgo, that is every such entry, one naming the account conflux
runs as included. An entry counts whatever it says of inheritance: one the directory only passes
on is inherited by the root conflux makes inside it. A deny entry takes nothing away from what is
counted, so it is not read: the `everyone deny delete` on a macOS home directory passes. A sticky
directory lets through an entry that only lets somebody write it, as it does its mode's bits —
ZFS's own ACL for a `1777` `/tmp` among them — but not one that lets them delete what is in it,
delete the directory, or change its ACL or owner, which the sticky bit does not hold back. The
root's own ACL is read by the same rules, every root's and not only a `CONFLUX_DIR`'s, as the
root will be once narrowed, with no sticky bit to let anything through: an entry a directory
above passed on lands there, though that directory was let through itself, and an extended ACL
sits beside the mode and keeps its entries through the narrowing, so one that lets another
account write the root or move it is refused. A POSIX ACL's mask is the mode's group bits, so
narrowing the root to `0700` sets the mask to nothing and takes the write from every entry: a
root's POSIX ACL, one passed on by a default ACL above it among them, is left to the narrowing.
So is the part of an NFSv4 ACL that is the mode itself — the trivial `owner@`, `group@` and
`everyone@` entries ZFS, and UFS with `nfsv4acls`, keep it in, which `chmod` rewrites with the
mode — where it grants the write the mode shows and nothing past it, passing nothing on: a root
of conflux's found at `0775` or `0777` on ZFS is narrowed, not refused. A root's NFSv4 ACL is
read, and only those entries are left to the narrowing: every other one is judged — a named
user's or group's, one passed on or passing on, and one granting more than the mode's write. On
Linux, where conflux reads POSIX ACLs alone, the root's own is not read at all.
On Windows it is any directory on the way owned by an account other than SYSTEM, the
Administrators, TrustedInstaller and the one running conflux, or one whose DACL grants another
account — by any entry that allows, a conditional one included — the right to delete or rename
what is in it, to delete or rename the directory itself, or to change its DACL or owner; the
right to create folders in it, which `C:\` gives every user, is not one of them. For an
installation's root, the one the boot service runs from, the account running conflux is not among
those trusted: the service runs as SYSTEM, which trusts no other account, and holds the way to its
root to that at every start, so a way an administrator's own grant lets through — the folders of
their profile grant them full control — would be refused there, every time, once the service was
registered; `up`, `proxy`, `observe`, `enrol`, `install`, `register` and `start` hold it to the
service's rule instead, and refuse it up front, naming the folder. An ephemeral run's root, which no service
serves, is held for the account running it. conflux tells the two apart by the directories it was
handed: an ephemeral run's are its own (`paths.EphemeralDirs`), and every other set is an
installation's. On Unix the service runs as root, as every command that makes an installation's
root must, so the two rules are one. A link or
junction on the way is held as well to whoever may point it elsewhere or write it: the right to
write its data or its attributes is enough to rewrite where a junction leads. A compound entry
counts as one that allows, for its client, and a DACL holding an entry of a type Windows does
not document is refused rather than read as granting nobody. A `CONFLUX_DIR` on a network
volume — a share, a drive mapped to one, or a link leading to either — is refused, before anything
is made there, whatever the directories above it allow, since their owners and DACLs, and its own,
name accounts of the machine serving it, which this one cannot judge. The root is used as an
absolute path, so the service registered under it runs from where it was installed whatever the
working directory was.

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
