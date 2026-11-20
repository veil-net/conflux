# Windows

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

A root found already there is judged and restricted through one handle, opened on the
directory itself and never looked up by its name again. Once restricted, it is made to hold
its `run\` directory, created through that handle with the same ownership and DACL, since a
reparse point cannot be set on a directory that is not empty: a handle somebody opened on the
root while its old DACL let them write it, which keeps that right, can no longer make a junction
of it. That holds only while nobody else may take `run\` out again, so a root whose DACL, as
found, lets another account delete or rename what is in it, or change who may, is refused before
it is restricted, and passed over by every reader of an ephemeral root; `%ProgramData%`'s own grant to `Users`, to add to a folder and write its
attributes, is not that. Then it is read once more through the handle: one that became a junction meanwhile is
refused. A root already secured — the Administrators' or SYSTEM's, under a protected DACL that
lets nobody else write it, add to it, move it or change who may — is not restricted again, but
what it holds is judged again, so that a folder refused once stays refused; a protected
one that grants more is judged and restricted as any other, and one with no DACL at all, which
grants anybody everything, is refused. A root some other account created is refused rather than
taken over: whoever made it could have filled it first. So is one that holds anything another account may change, each
thing in it judged by its own owner and DACL rather than by what it leads to, before the root is
restricted, what it inherits from the root included, and again once it is, before `run\` is made,
so that a folder another account added in between is judged too: anything another
account owns, whatever its name, or that its DACL lets another account write, move or point
elsewhere — a folder they may add to, or write the attributes or extended attributes of, among
them, the attributes enough to make a junction of it while it is empty. `anchord`'s own account, `NT SERVICE\conflux`, is conflux's: what
a DACL grants it is not held against the thing granted, though what it owns is, and a folder
whose DACL lets it write — `anchor\` and `run\anchord\` — is not looked inside, since only
SYSTEM, the Administrators and `anchord` may write there and conflux reads what `anchord` writes
as untrusted. Every reader of an ephemeral root holds what it holds to the same, so nothing is run
from one whose contents another account could have planted. So is a root that is a junction
another account may point elsewhere: `%ProgramData%` lets any user make one where `%ProgramData%\conflux` or
`%ProgramData%\conflux-ephemeral` is not yet, leading into a directory of SYSTEM's, and point
it at a directory of their own once conflux has filled it. A junction, the root or one in it,
is used only when it belongs to SYSTEM, the Administrators, TrustedInstaller or the account
running conflux, and its DACL grants nobody else the right to write its data, attributes or
extended attributes, add to it, delete it, or change its DACL or owner; an ephemeral root that fails this is passed over by
every reader too. And the two binaries the service runs as SYSTEM, and
`wintun.dll` beside them, are run only if Administrators, SYSTEM or the account running
conflux owns them — a set directory is named for content anybody can compute, so one
made by somebody else is extracted again rather than trusted.

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
