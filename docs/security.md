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
- `0700` on the directory. A `0600` file in a traversable directory is one `rename`
  away from being replaced.
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

- The path is content-addressed under the state directory — `0700`, root-owned, on a
  filesystem the administrator chose. Not `/tmp`, which is world-writable and, under
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
for tests and for hosts where the default filesystem is `noexec`.

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
