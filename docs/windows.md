# Windows

## `wintun.dll` is downloaded, never embedded

A TUN interface on Windows needs Wintun, and conflux does not ship it. Two reasons,
either of which would be enough, and both are anchor's:

**It is GPLv2.** Embedding a copy would be redistribution and would bring those terms
with it.

**A driver extracted at runtime from a program's own resources is the shape of a DLL
hijack.** It is exactly what a dropper does, and building it into a program that runs
as LocalSystem is a bad habit to normalise even when the bytes are the right ones.

So conflux fetches it on the first `conflux up`, verifies it, and places it beside the
extracted `anchord.exe` — which is the first path anchor's loader searches, before the
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
   redirect that changes host;
3. verifies the **archive** digest against the pin, and aborts printing both digests if
   it disagrees;
4. extracts `wintun/bin/<arch>/wintun.dll` and only then writes it, atomically, into
   the `0700` set directory.

The same constant is read by CI, rather than typed a second time — a workflow that
pinned a different version from the product code would be a test of nothing.

Because the DLL lands in the content-addressed set directory, upgrading conflux to a
build with a different anchor pair fetches it again into the new directory. That is
correct: the driver belongs beside the executable that loads it.

## If it cannot be downloaded

conflux says exactly what to do:

```
conflux: a network interface on Windows needs wintun.dll, and it could not be fetched: …

  Download wintun-0.14.1.zip from https://www.wintun.net and put
  bin\amd64\wintun.dll at:
    C:\ProgramData\conflux\bin\998ece52739a7c74\wintun.dll

  Or run "conflux proxy PORT=BACKEND", which needs no interface at all.
```

That last line is the real fallback. On a machine where the driver cannot be installed
at all, userspace mode is a complete way to use the overlay.

## Defender and SmartScreen

A 48 MB binary that writes a 30 MB executable to disk and immediately runs it with
elevated privileges is, structurally, a textbook dropper. Expect the first releases to
be flagged, and know the mitigations:

- Released binaries are Authenticode-signed where signing secrets are configured.
- Extraction goes to a stable path under `%ProgramData%\conflux\bin`, not a random
  temporary one — reputation attaches to paths and publishers.
- `conflux version` prints both anchor digests, so what was written can be checked
  against the release notes.
- If you need an exclusion, `%ProgramData%\conflux\bin` is the directory.

If the extracted binaries will not run at all, conflux says so and names endpoint
protection as the likely cause rather than reporting a bare permission error.

## File permissions

Mode bits do not exist on Windows in the sense Go's `Chmod` implies — a call to
`Chmod(0600)` sets the read-only attribute and nothing else — and `%ProgramData%`
grants `Users` read by default. conflux therefore replaces the DACL outright on the
identity file: SYSTEM and Administrators, full control, inheritance off, so the
parent's grant cannot come back.

## The service

Registered as `conflux`, displayed as `VeilNet Conflux`, running as `LocalSystem`. See
[service.md](service.md).
