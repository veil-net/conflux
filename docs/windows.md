# Windows

## Which Windows

Windows 10 version 1803 (build 17134) or later, Windows 11, or Windows Server 2019 or later.
`anchord`'s control socket is an AF_UNIX socket, which Windows has from build 17063, first
released as 1803. conflux refuses to run on an older build: every command stops before it does
anything, naming the build, rather than start an `anchord` that cannot listen.

## `wintun.dll` is downloaded, never embedded

A TUN interface on Windows needs Wintun, and conflux does not ship it. Two reasons,
either of which would be enough, and both are anchor's:

**It is GPLv2.** Embedding a copy would be redistribution and would bring those terms
with it.

**A driver extracted at runtime from a program's own resources is the shape of a DLL
hijack.** It is exactly what a dropper does, and building it into a program that runs
as LocalSystem is a bad habit to normalise even when the bytes are the right ones.

So conflux fetches it when a TUN machine needs it — on `conflux up`, and again at any
start that finds it missing — verifies it, and places it beside the extracted
`anchord.exe`, which is the first path anchor's loader searches, before the
*safe* system search (`LOAD_LIBRARY_SEARCH_SYSTEM32` and friends, never the legacy
order that includes the working directory).

`conflux proxy` needs none of this. Userspace mode has no interface, so there is no
driver to load.

## The pinned version and what is checked

The version and the archive's SHA-256 are constants in `internal/wintun/pinned.go`, and
they are the only thing standing between a user and an arbitrary DLL loaded next to a
LocalSystem process. conflux:

1. checks whether the DLL is already in place, and does nothing if it is;
2. downloads over HTTPS with a 90-second timeout and a 10 MiB cap, refusing any
   redirect that leaves HTTPS or changes host, and stopping after 10 requests;
3. verifies the **archive** digest against the pin, and aborts printing both digests if
   it disagrees;
4. extracts `wintun/bin/<arch>/wintun.dll` and only then writes it, atomically, into
   the set directory, which only SYSTEM and Administrators may write.

The same constant is read by CI, rather than typed a second time — a workflow that
pinned a different version from the product code would be a test of nothing.

Because the DLL lands in the content-addressed set directory, upgrading conflux to a
build with a different anchor pair needs it again in the new directory, and the
supervisor fetches it there before it starts the anchor — a reboot after an upgrade
needs nothing typed. That is correct: the driver belongs beside the executable that
loads it. A start that cannot fetch it is retried with the supervisor's backoff.

## If it cannot be downloaded

conflux says exactly what to do:

```
conflux: a network interface on Windows needs wintun.dll, and it could not be fetched: …

  Download wintun-0.14.1.zip from https://www.wintun.net and put
  bin\amd64\wintun.dll at:
    C:\ProgramData\conflux\bin\998ece52739a7c74\wintun.dll

  Or run "conflux proxy PORT=BACKEND", which needs no interface at all
```

That last line is the real fallback. On a machine where the driver cannot be installed
at all, userspace mode is a complete way to use the overlay.

## Defender and SmartScreen

A 50 MB binary that writes a 30 MB executable to disk and immediately runs it with
elevated privileges is, structurally, a textbook dropper. Expect the first releases to
be flagged, and know the mitigations:

- Released binaries are not Authenticode-signed, so SmartScreen has no publisher
  reputation to go on; each release carries a build-provenance attestation instead.
- Extraction goes to a stable path under `%ProgramData%\conflux\bin`, not a random
  temporary one — reputation attaches to paths and publishers.
- `conflux version` prints both anchor digests, so what was written can be checked
  against the release notes.
- If you need an exclusion, `%ProgramData%\conflux\bin` is the directory.

If the extracted binaries will not run at all, conflux says so and names endpoint
protection as the likely cause rather than reporting a bare permission error.

## File permissions

Mode bits do not exist on Windows in the sense Go's `Chmod` implies — a call to
`Chmod(0600)` sets the read-only attribute and nothing else — and `%ProgramData%` lets
`Users` read everything below it and create files and folders in it. So conflux makes
`%ProgramData%\conflux` belong to SYSTEM and Administrators instead: Administrators own
it, and a protected DACL grants the two of them full control and nobody else anything,
inherited by everything beneath. Both are set as the directory is created, so it never
carries `%ProgramData%`'s grant to `Users` — enough to turn an empty directory into a
junction — not even for an instant. Every secret file gets the same, explicitly, before
anything is written into it.

A root on a network volume — a share reached by its UNC path, a drive mapped to one, or a link
leading to either, as the volume conflux holds it open on says, not as it is spelled — is refused
before anything is made or put there, one not made yet by the volume the walk of its way (below)
reaches, and refused by the readers' check (below): who owns what is there, and whom its
DACL grants, are accounts of the machine serving it, which this one cannot judge. A link naming
anything but a drive letter or a volume of this machine's — a share by its UNC path, or a WebDAV
server's — or a relative link that names a volume itself, which a lookup starts from rather than
from the link's folder, is refused before anything follows it, by where the link itself says it
leads, so that conflux never signs this machine in to whoever serves it: at a root's name, and for a
`CONFLUX_DIR` at every step of the way to it, by every command that makes a root and by the
readers' check (below), before anything is looked up there. So is a link that leads nowhere, with nothing made where it leads.
A root not made yet is made through a handle on the folder it goes in, so a junction or a link
somebody plants at its name meanwhile is found there and refused, rather than followed. The way to
it is walked from the top of its volume, each folder held open through a handle on the one before,
never followed, and a junction or a link read off itself and gone on from where it leads; for a
`CONFLUX_DIR`, each folder there is held, before a name is looked up in it, to the rule the way to
one is held to ([security.md](security.md#the-extracted-binaries)): nobody else may move what is in
it. For an installation's root that is the rule the service, running as SYSTEM, holds the way to at
every start, which trusts no account but SYSTEM, the Administrators and TrustedInstaller: the folders
of an administrator's profile, which grant them full control, pass that administrator's own rule
and not the service's, so a `CONFLUX_DIR` there is refused by the commands that make an
installation's root, before the service is registered to refuse it at every start; an ephemeral
run's root is held for the account running it. The folders missing are made from the last one held, each through a handle on the one before,
never by their names, since `C:\` lets every user make a folder where the next is to go, and the
owner of a folder on the way may make anything in it. Each is made exactly as the root is, the
Administrators' from the moment it exists, under a protected DACL granting SYSTEM and the
Administrators full control and nobody else anything, rather than with what the folder above passes
on — in `C:\` `Authenticated Users`' right to delete it — and owned by the administrator who ran
conflux, whom the service, running as SYSTEM, would not trust: the way conflux makes is its own, as
the `0700` directories it makes on Unix are, passes the rule for the service as for the account that
made it, and a folder of it later taken as a root is one conflux finds secured already. Each folder
conflux goes into on the way, one it made or one somebody else made at the name meanwhile, opened as
itself, is held to the same rule before anything is made in it, and a junction or a link there is
refused.

Every command that reads a root, or acts on what it holds, rather than making it — `status`, a
pass-through, `renew`, `start`, `down`, `uninstall`, `update` asking whether the anchor runs, and
every reader of an ephemeral run's root — holds it to one check first,
the readers' check, before it reads anything in it by its name: through one handle, a junction or a
link judged as itself as above, it must be SYSTEM's, the Administrators' or the account running
conflux's, and its DACL must grant nobody else any right, to read it included, nor pass one on to
what is made in it, which is what a root conflux secured keeps: a root is conflux's alone, and one
granting more is one conflux would restrict — so one that only inherits `%ProgramData%`'s grant to
`Users` is refused too, and so is one that lets them read it; a `CONFLUX_DIR`'s way is held as it is when the root is made. A `CREATOR OWNER` entry passed
on, as an administrator tightening a root by hand may keep `%ProgramData%`'s, is no such grant here,
nor when conflux secures a root: it grants whoever made what it is passed to, and only SYSTEM, the
Administrators and the account running conflux may make anything in the root. Nothing is changed: a root that
fails is refused, saying why, with nothing in it read, run, stopped or removed, and one not there is
a machine with nothing installed, of which nothing is read either, since whoever made the name
first would answer for what is at it. A reader of an ephemeral root, which another process keeps,
then judges what it holds as below. `help`'s `anchorctl` runs from the extraction in a root only
where the root passes this check, and otherwise from a private copy, reading nothing in the root.

A root found already there is judged and restricted through one handle, opened on the directory
itself and never looked up by its name again. Before anything in it is judged, it is made to hold
its `run\` directory, created through that handle, SYSTEM's and the Administrators' from the moment
it exists, since a reparse point cannot be set on a directory that is not empty: a handle somebody
opened on the root while its old DACL let them write it, which keeps that right, can no longer make
a junction of it, whatever conflux then decides, a refusal included. That holds only while nobody
else may take `run\` out again, so a root whose DACL, as found, lets another account delete or
rename what is in it, or change who may, is refused before `run\` is made; `%ProgramData%`'s own
grant to `Users`, to add to a folder and write its attributes, is not that, though the readers'
check, which restricts nothing, refuses it. Then it is read once more through the handle: one that became a
junction meanwhile is refused, and one whose DACL, as found, does not let conflux create `run\` in
it is refused, saying so. A root already secured — the Administrators' or SYSTEM's, under a
protected DACL that grants nobody else any right, to read it included, nor passes one on to what is
made in it — is not restricted again, but it is made to hold `run\` and read
again the same way, since one an administrator restricted while it was empty is as open to a handle
opened before, and what it holds is judged again, so that a folder refused once stays refused; a
protected one that grants more, or passes more on — to `logs\`, which conflux then makes in it by
its name, and to `serve.lock` and `conflux.lock`, which an account let read them could hold against
the supervisor — is judged and restricted as any other, and one with no DACL at all, which grants anybody
everything, is refused. A root some other account created is refused rather than taken over: whoever made it
could have filled it first. So is one conflux may not open or read, by the readers' check too,
rather than taken for one that is not there: whoever made it can deny conflux that as
easily. So is one that holds anything another account may change, each thing in
it judged by its own owner and DACL rather than by what it leads to, before the root is restricted,
what it inherits from the root included, and again once it is, so that a folder another account
added in between is judged too: anything another account owns, whatever its name, or that its DACL
lets another account write, move or point elsewhere — a folder they may add to, or write the
attributes or extended attributes of, among them, the attributes enough to make a junction of it
while it is empty — or, for a folder, passes such a right on to what is made in it. `anchord`'s own account, `NT SERVICE\conflux`, is conflux's: what a DACL grants
it is not held against the thing granted, though what it owns is, and a folder whose DACL lets it
write — `anchor\` and `run\anchord\` — is not looked inside, since only SYSTEM, the Administrators
and `anchord` may write there and conflux reads what `anchord` writes as untrusted. A reader of
an ephemeral root holds what it holds to the same, after the readers' check, so nothing is run from
one whose contents another account could have planted. So is a root that is a junction another account may point
elsewhere: `%ProgramData%` lets any user make one where `%ProgramData%\conflux` or
`%ProgramData%\conflux-ephemeral` is not yet, leading into a directory of SYSTEM's, and point it at
a directory of their own once conflux has filled it. A junction root is held as a symlinked root is
on Unix: used only when it belongs to SYSTEM, the Administrators, TrustedInstaller or the account
running conflux, and its DACL grants nobody else the right to write its data, attributes or
extended attributes, add to it, delete it, or change its DACL or owner, as the readers' check
holds one too. Then, since a handle somebody opened on it while its
DACL let them write it could still repoint it in place, conflux replaces it: the junction is
removed, and one made in its place through conflux's own handle, with the root's ownership and DACL
from the moment it exists, and pointed through that handle at the directory conflux judged. A
junction can lead only to a directory named by its volume's GUID, so a link root leading to a local
volume that has no such name is refused, whether conflux would replace it or finds it its own
already, and by the readers' check. Something made at that name in
between is refused, naming where the junction led and the commands that make it again (below),
which come before conflux is run again: with nothing at the name, conflux would make a new root
there, and the machine a new identity. A failure to make or point its own junction says the same.
Between removing the junction and pointing its own, the name holds nothing and then an empty
directory of conflux's, so a conflux killed then leaves either, which the next run takes as a new
root: remove whatever is at the name and make the junction again before the next `up`. A junction
or a link inside a root, anywhere conflux looks, is refused whoever may change it, since conflux
makes none there; `anchor\` and `run\anchord\`, which `anchord` writes, are not looked inside. And
the two binaries the service runs as SYSTEM, and `wintun.dll` beside them, are run only if
Administrators, SYSTEM or the account running conflux owns them — a set directory is named for
content anybody can compute, so one made by somebody else is extracted again rather than trusted.

A junction root is made again in a folder only SYSTEM and the Administrators may write, on the
root's volume — `%ProgramFiles%` on the system drive — and moved into place, not made at its name
with `mklink /J`: there it would carry what the folder it is in passes on, in `%ProgramData%`
`Users`' right to write its attributes, enough to point it elsewhere, and conflux would refuse it.
A move on one volume keeps the DACL the junction was made with, which is not protected, so the next
run replaces it with one of conflux's own. In `cmd` — `mklink` is one of its commands, and its
`rmdir` removes a junction without going into where it leads — as Administrator, for
`%ProgramData%\conflux` leading to `D:\conflux`, the refusal says:

```
rmdir "C:\ProgramData\conflux"
mklink /J "%ProgramFiles%\conflux.junction" "D:\conflux"
move "%ProgramFiles%\conflux.junction" "C:\ProgramData\conflux"
```

For a root on a volume `%ProgramFiles%` is not on, where `move` cannot take a junction from there,
the refusal gives no commands: it names the volume, and says to make the junction in a folder on
it that only SYSTEM and the Administrators can write, then move it into place the same way.

A root, its `run\`, the folders missing on the way to a `CONFLUX_DIR`, and the junction conflux puts
in place of a junction root, are made through a handle on the folder each goes in: the name is looked up there and nowhere else, and not followed. The create
also carries a flag that keeps it from being reparsed anywhere a junction leads (`OBJ_DONT_REPARSE`):
defence in depth, guarding a case not shown to happen, since a create relative to a folder conflux
holds is not known to be taken through a junction that folder became without it. The other folders
conflux keeps in a root — `logs\`, `bin\` and what extraction makes in it, `anchor\`,
`anchor.root\` and `run\anchord\` — it makes by their names.

Where `anchord` runs as `LOCAL SERVICE` (below), the service's own SID,
`NT SERVICE\conflux`, is added to exactly what it needs: read and execute on its set
directory and `anchord.exe`, and read on `anchord.json`. `anchor\` and `run\anchord\`
are made with their security set as they are created — full control for that SID on what
is inside them, no `WRITE_DAC`, `WRITE_OWNER` or `DELETE` on the directories themselves,
and an `OWNER RIGHTS` entry so that owning a file grants nothing — and are never
propagated over afterwards. A SYSTEM `anchord` has `anchor.root\` and a `run\anchord\` of
SYSTEM's and Administrators' instead, made the same way, with that security as they are created.

## An ephemeral run

`conflux up --ephemeral` and `conflux proxy --ephemeral` need Administrator on Windows,
whatever the mode: every directory conflux keeps there, the ephemeral run's
`%ProgramData%\conflux-ephemeral` included, is SYSTEM's and Administrators'. anchord runs
as that Administrator, in conflux's job object, so it ends however conflux does. See
[ephemeral.md](ephemeral.md).

## The service

Registered as `conflux`, displayed as `VeilNet Conflux`, running as `LocalSystem`. See
[service.md](service.md).

`anchord` itself runs as SYSTEM only for a TUN, which wintun needs. In userspace mode the
supervisor logs `LOCAL SERVICE` on for it with `LogonUserExExW`, the service's SID and a
logon SID of its own added as groups, as the SCM gives a service, and takes every
privilege but `SeChangeNotify` out of the token — `LOCAL SERVICE` holds `SeImpersonate`,
which is the well-known way back to SYSTEM, and a privilege merely disabled can be
enabled again. The token's default DACL names only SYSTEM and the service's SID, and the
process's and its thread's own add Administrators, so nothing else that runs as
`LOCAL SERVICE` can open it or what it creates; it does still share that account's
logon session with them. Before it is relied on, `anchord -h` is started under the token
once: a host that will not start it so runs it as SYSTEM, as before, and `conflux status`
says why. See [security.md](security.md#what-anchord-runs-as).

Each `anchord` runs in a job object of its own, which ends it — and anything it started —
when it has gone, and when the supervisor's process ends, however that ends: the SCM
terminating a service that overran its stop, or a crash, takes the daemon with it rather
than leaving one holding the control socket.
