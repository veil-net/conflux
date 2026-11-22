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

A reader — help, `status`, `renew`, a pass-through, one to a socket you named among them — that
finds no extraction it may use runs a temporary copy of `anchorctl` instead. Elevated, the
copy goes in a folder of its own in `%ProgramData%`, `conflux-usage-<n>`, which with the copy is
SYSTEM's and the Administrators' from the moment it exists, never your own `%TEMP%`, which your
processes that are not elevated could change between the write and the run; not elevated, it goes
in your `%TEMP%`, granted to you. The folder goes once the copy has run, and one a reader killed
before then left goes at the next `uninstall`, or the next command that removes what earlier
conflux left ([commands.md](commands.md#conflux-uninstall)), which, run elevated, look in
`%ProgramData%` and in that account's own `%TEMP%`; one whose copy is running is passed over.

## File permissions

`%ProgramData%` is the system's: `\ProgramData` on the volume Windows is installed on, read from the
system, never the `ProgramData` variable. An elevated process's environment is built from the user's
registry, which that user's processes that are not elevated may write, and a `ProgramData` of theirs
would otherwise lead the roots an elevated conflux makes, and the anchorctl it runs, into a folder
they own.

Mode bits do not exist on Windows in the sense Go's `Chmod` implies — a call to
`Chmod(0600)` sets the read-only attribute and nothing else — and `%ProgramData%` lets
`Users` read everything below it and create files and folders in it. So conflux makes
`%ProgramData%\conflux` belong to SYSTEM and Administrators instead: Administrators own
it, and a protected DACL grants the two of them full control and nobody else anything,
inherited by everything beneath. Both are set as the directory is created, so it never
carries `%ProgramData%`'s grant to `Users` — enough to turn an empty directory into a
junction — not even for an instant. Every secret file gets the same, explicitly, before
anything is written into it. A `CONFLUX_DIR`'s root, `.conflux` inside the folder it names, an
ephemeral run's root, and the folders conflux makes on the way to a `CONFLUX_DIR` are made the same.

Everything else conflux makes in a root or on the way to one — `logs\`, the lock files,
`bin\` and its lock, the service's copy of conflux, the log — is the Administrators' as well,
with its DACL what it inherits: every conflux process running elevated makes them the owner its
token gives what it makes, as the first thing it does, rather than leaving that to the machine's
default-owner policy, so each is theirs from the moment it exists. On Windows Server what an
elevated administrator makes is the Administrators'; on a Windows client it is that
administrator's own, which their unelevated processes could change for the SYSTEM service to read
or run. A token that is not elevated, which no command making a root runs with, keeps its own.
Where the owner cannot be set, every command but `version` and `cert` is refused, exit 70: each of
the rest can make something in a root, help, `status`, `renew` and a pass-through among them, which
extract the anchor pair into `bin\` where it is not there yet.

A root conflux finds already there is its own only where it is as conflux makes one: a folder, not a
junction or a link, owned by SYSTEM, the Administrators or TrustedInstaller, whose DACL grants nobody
else any right, to read it included, on it or on what is made in it. An ephemeral run's root, which
only an elevated conflux makes or can open, is judged for the Administrators, never for the account
running conflux by its SID, whose processes that are not elevated could have made one first in
`%ProgramData%` and filled it. An installation's root, which the boot service runs from as SYSTEM, trusting no other
account, is judged for SYSTEM, so one the administrator running conflux owns, or that grants them a
right, is not conflux's either. Anything else at the name — a folder another account made, as
`%ProgramData%` lets any account make `conflux` or `conflux-ephemeral` first, one that inherits
`%ProgramData%`'s grants, a junction, a file — is removed as itself by every command that makes a
root, through a handle on the folder it is in, never followed, opened to delete it and read its
attributes alone, a folder to list it too, with the backup intent the privileges an Administrator
holds give, so that a DACL granting the Administrators nothing does not keep it; and the root is
made afresh, with nothing of what was there. `run\`, `logs\`, `bin\` and `anchor.root\` are judged as
the root is, and each that is not as conflux makes it, such as one an earlier conflux left the
administrator's own, is removed whole and made afresh. A root that is a junction to another disk is therefore
not followed, and a fresh root is made at its name: to keep conflux's files on another disk, use a
`CONFLUX_DIR` there. Each file conflux keeps in a root — `conflux.json`, `state.json`,
`manifest.b64`, `anchord.priv`, `way`, the lock files and the service's copy of conflux — is judged
as the root is, and one that is not as conflux makes it, such as a copy an earlier conflux left the
administrator's own, is removed for what writes it to make afresh; the supervisor, which runs from the
service's copy, leaves it as it makes the roots, and places one not there, or not as conflux makes it,
afresh from its own image, the running one moved aside. Nothing else in a root is judged: nobody else can have
put anything there. A root on a network volume, however it is reached, is refused, as the volume
conflux holds it open on says; a link naming a share on the way to a `CONFLUX_DIR` is refused before
anything follows it, by where the link itself says it leads.

A `CONFLUX_DIR` itself, and every folder above a root, is never changed and never judged: choosing
a `CONFLUX_DIR` is the user's responsibility, and one another account can change, or a folder above it,
lets that account put a root of its own where conflux's was. conflux owns `.conflux` inside it, and
remakes it as it makes it. The way to a root is walked from the top of its volume, each folder held
open through a handle on the one before, never followed, and a junction or a link read off itself and
gone on from where it leads. What conflux picks itself — the platform's roots, an ephemeral run's
root, an elevated reader's temporary copy of anchorctl — is judged for SYSTEM or the Administrators,
never the account running conflux by its SID, so that account's processes that are not elevated
cannot have made or changed it.

Every command that reads a root without making it holds it to the same judgement first, the readers'
check: a root that fails is refused, naming it and why, and nothing in it is read or run; one this
account may not open or read is refused too, since whoever made it can deny conflux the right to read
its owner and DACL as easily as they can make it. Nothing is changed.

A root, and the folders missing on the way to a `CONFLUX_DIR`, are made through a handle on the
folder each goes in: the name is looked up there and nowhere else, and not followed. The create
also carries a flag that keeps it from being reparsed anywhere a junction leads (`OBJ_DONT_REPARSE`):
defence in depth, guarding a case not shown to happen, since a create relative to a folder conflux
holds is not known to be taken through a junction that folder became without it. The other folders
conflux keeps in a root — `run\`, `logs\`, `bin\` and what extraction makes in it, `anchor\`,
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

The SCM keeps the service's command line as one to expand, and replaces each `%NAME%` in it from
the system's environment at every start, so every command that registers the service — `install`,
`up`, `proxy`, `observe`, `enrol`, `start`, and the `register` an update runs — refuses, before it
makes anything, a `CONFLUX_DIR` holding a `%`, or a copy's path holding one: with `C:\%OS%`, SYSTEM
would run `C:\Windows_NT\.conflux\conflux.exe`, in a folder any account may make. Choose a
`CONFLUX_DIR` without one.

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
