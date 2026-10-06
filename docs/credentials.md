# Credentials

## Two issuers, and everything below depends on which

conflux runs against either of two things, and they are opposite products rather than
the same one configured differently. Almost every page of this documentation was
written about the first; the differences are collected here, and each section below
says which it is about.

| | **the public alpha realm** | **a self-hosted guardian** |
|---|---|---|
| getting a credential | `conflux up` enrols itself | an operator commissions the machine and hands you a file; `conflux enrol` installs it |
| who is recorded | nobody. There is no account and no record | the machine, by the operator who commissioned it |
| renewal | unauthenticated; the route is gated on nothing | a bearer minted for that one machine, carried in the manifest |
| revocation | **none, and none is possible** | the guardian refusing to renew |
| the window | thirty days | whatever the operator chose; anchor sets no ceiling |
| addresses | derived from the identity | derived, plus an IPv4 the operator may allocate |

The rest of this page is the alpha realm unless it says otherwise. The section on
guardian-issued credentials is near the end, followed by the one on credentials that
do not renew at all, which is what VeilNet's own ghost realm nodes carry.

## Enrolment is one unauthenticated POST

`POST https://api.veilnet.com.au/ghosts/alpha` takes the taints to put the anchor in,
`{"taints": ["brhk-2mq9-tzva-6pjs-k4xe-nw7d-qf"]}`, needs no account, and returns a
base64 anchor manifest. The API mints an identity inline, signs a credential for it in
those taints, puts both in the document, and forgets them. The manifest's `taints` field
echoes the set, and the credential commits to it. At most 32 names, none containing a
space, a character that does not print, an `@` or a `+`; conflux checks the same before
it asks, and never asks for none.

There is no sign-up, no session and no record. That is the product rather than an
omission — the free tier is free *of* us, not merely free of charge.

## The response is the only copy

Nothing is stored server-side, so there is no second download and no recovery. Drop
the response and the identity is gone; a second call draws a different one, with a
different AnchorID and a different overlay address.

This is why conflux writes `manifest.b64` **before** it does anything else with the
response — before decoding it, before starting anything. An enrolment that succeeds
and then loses the bytes to a crash costs the machine its identity permanently, and
that is a bad enough outcome to be worth ordering the code around.

It is also why `conflux uninstall` asks before it runs.

## Enrolment happens exactly once

conflux enrols only when `manifest.b64` does not exist. In particular:

- **A failed renewal never falls back to enrolling.** That fallback is the obvious
  "resilient" thing to write, and it would silently change the machine's overlay
  address and orphan every peer that had it.
- **Re-running `conflux up` does not enrol.** It reads the identity that is there.
- **Switching modes does not enrol.** `up` after `proxy` keeps the identity.

## Taints are the credential's

An anchor does not claim its taints; its issuer grants them. The credential commits to a
digest of the set, `anchorctl start` refuses any other, and the names are written beside
it in the manifest, which is where anchorctl takes them from — conflux passes no
`-taints`. So:

- **They are requested at enrolment.** The first machine of a network asks for the one
  conflux mints, and every machine joining it passes that one with `--taint` and asks for
  the same. conflux never asks the alpha realm for none, which is its shared compartment.
- **They are fixed for the life of the identity.** A renewal restates them — the API
  keeps no record to read them back from — and cannot change them. On a machine that
  already holds a credential, `conflux up --taint` with the same set is accepted, and
  any other is refused.
- **Changing them is a new identity**, with a new AnchorID and a new overlay address:
  `conflux uninstall --yes`, then `conflux up --taint NEW`.
- **`conflux.json` mirrors them.** After enrolment its `taints` are the grant, and every
  start checks them against the manifest, refusing for good when the two disagree — a
  hand-edited file, say — rather than retrying something no retry changes.
- **A machine enrolled before the alpha realm granted taints is refused.** Its credential
  grants none, which puts it in the shared compartment whatever `conflux.json` names, so
  every start refuses it with the same advice, and `conflux status` shows a `refused`
  line saying why. Nothing re-enrols it automatically: that would be a new identity
  drawn behind the operator's back.
- **An imported credential takes what its issuer granted.** `conflux enrol` has no
  `--taint`; it writes the manifest's set into `conflux.json`. A guardian's or a ghost
  realm node's credential granting none puts the machine in its issuer realm's default
  compartment. An alpha one granting none is refused at import. See
  [commands.md](commands.md#conflux-enrol).

The realm can still move a running machine: a member whose credential grants the `taint`
capability can send it a Taints order, and anchor keeps that grant in its directory and
reapplies it over the credential's set at every start. An alpha credential grants that
capability to nobody. See [commands.md](commands.md#realm-control).

## The thirty-day window, and renewal

*(The alpha realm. A guardian chooses its own window; the arithmetic below is the
same either way, because it is computed from the document's own `issuedAt` and
`notAfter` rather than from a constant.)*

A credential is issued for thirty days. conflux renews at **two thirds of the window** —
day twenty — which is what the API's own documentation specifies, and which leaves ten
days of retry budget for a machine that is having a bad week.

Renewal happens in two places, and both go through the same arithmetic:

- **On every start**, before the anchor is built, so that `start` always receives a
  current chain. This is why the boot path needs no separate renewal step.
- **On a timer** while running. The sleep is clamped to at most six hours and
  recomputed against the wall clock each time, so a laptop that was suspended for six
  months renews within six hours of waking rather than sleeping on a timer armed in
  another era.

Renewal is hot. `anchorctl renew` calls `SetRealmCred` on the running anchor: the
identity does not change and not one session is lost. A restart would cost every
connection the anchor is holding, for a swap that needs none of that.

**The renewed chain is written to disk as well as installed**, before it is installed,
along with its expiry and the moment it arrived. If it were only installed, the next
reboot would start from the stale chain — and if the machine had been off longer than
the original window, from an expired one, at a moment when nothing is watching. The
arrival time is the start of the window the next two-thirds is taken of, so a machine
that renews and reboots renews on the renewed credential's schedule, not the first
one's.

**So is the issuer's bootstrap list**, when the answer carries a usable, non-empty one:
conflux writes it into the stored manifest in place of the old. `anchorctl renew`
installs the chain and nothing else, so the running anchor keeps the list it started
with and the next start uses the fresh one. An answer with no list, or one anchor would
not dial, leaves the manifest's own. The taints are never rewritten: the renewal
restated them.

A renewed chain the running anchor will not take is a failed renewal, even though it
is on disk: the next start runs on it, and until then the timer keeps to the schedule
of the chain the anchor holds, so a renewal that was due is retried every minute, and
`conflux status` names the install as what failed.

## Being offline past the expiry costs nothing but a call

The renewal route is checked against nothing and gated on nothing:
`POST /ghosts/alpha/renew` takes an AnchorID, which is the public half, and the taints
the manifest names, `{"anchorId": "anchor…", "taints": ["…"]}` — the API keeps no record
of them — and signs a fresh chain for it in those taints, answering
`{"chain": "…", "notAfter": "…", "bootstrap": ["…"]}`. It works after expiry.

So a machine that was switched off for a month renews on its next launch and **keeps
its AnchorID and its overlay address**. There is no window to miss. The address is
lost only if something re-enrols, which is why conflux will not.

That safety is also, seen from the other side, the thing to understand about this
model: see [security.md](security.md).

## What renewal failure looks like

Three states, three behaviours:

| State | What conflux does |
|---|---|
| credential valid, renewal failed | warns with the time remaining, starts normally, retries every minute |
| credential expired, renewal failed | a running anchor stays up, with every handshake refused, and the timer retries every minute; a start is refused by anchor, which will not build an anchor on an expired credential, so the supervisor retries with a backoff up to thirty seconds, renewing first each time. Either way `conflux status` says `EXPIRED` and names the last error, because reporting "running" would be describing the wrong thing |
| credential expired, renewal succeeded | nothing special; this is the ordinary long-offline case |

## Renewing by hand

`conflux renew` forces one now: it fetches a fresh chain and installs it on the
running anchor with `anchorctl renew`, the same hot swap the timer uses. Nothing is
restarted and no session is dropped.

It is not part of normal operation — the two automatic paths above cover every machine
that is working. It is for the one that is not, where `renewal: failing since ...` has
been showing in `conflux status` and the only other lever was restarting the service.

It refuses, with exit 69, on a machine that has never enrolled (there is nothing to
renew, and drawing an identity would replace the one a reboot expects) and on one
where nothing is running (a credential is installed into a running anchor, and the
next start renews on its own). It takes no arguments; `anchorctl renew -cred FILE`,
which installs a credential you already hold, is reached through the escape hatch.

## Clock skew

Three separate things break on a bad clock and only one of them says so.

A credential starts at the moment the issuer signs it, and anchor refuses one that
starts more than ten minutes after its own clock says now. So a machine ten minutes
slow cannot start on a credential it has just been issued, enrolled or renewed, and the
refusal names the credential rather than the clock. Further out, anchor's handshake
tag rotates hourly and a peer accepts one epoch either side, so two machines two hours
apart **cannot connect at all** — and the symptom is a TLS alert that looks exactly
like a wrong realm. And a clock weeks fast makes a current credential look expired,
while one a year slow makes an expired one look fine.

conflux compares the API's `Date` header to the local clock on every call, records the
skew in `state.json`, and refuses to bring a machine up when it exceeds ten minutes —
anchor's own allowance, and the tightest of the three — naming NTP, because the failure
is otherwise unrecognisable. Better to stop than to start an anchor that reports itself
healthy and reaches nobody.

The measurement comes from talking to the API, so it is taken on the paths that do:
enrolling, and renewing. A start whose credential is current makes no call — unless the
last measurement was over the limit, in which case it renews to measure again rather
than trusting a figure from before the clock was fixed. `conflux status` prints the
skew the last call measured, when it is more than a second.

## Moving a machine

There is no account, so there is nothing to transfer and no supported migration. The
identity is `manifest.b64` and nothing else; copying it moves the machine, and copying
it *without deleting the original* makes the anchor exist twice, which is an address
conflict rather than redundancy.

If you do not need the address preserved, `conflux uninstall` and `conflux up` on the
new machine is the whole procedure.

## A guardian-issued credential

> **The contract is written down once, in the other repository.**
> [`guardian/docs/contracts/guardian-node.md`](https://github.com/veil-net/guardian/blob/main/docs/contracts/guardian-node.md)
> defines the `renewalAuth` value, the name and shape of the secret beside it, the
> renewal request and response bodies, the `export` block and the ship order. Two
> repositories implement it and neither owns it; this page is conflux's side, and
> anything here that disagrees with that document is a bug here.

A self-hosted guardian is an operator running their own control plane and their own
subtree of the realm tree. It serves **no enrolment route at all**, which is the whole
shape of the difference: machines are commissioned in advance, in the operator's own
interface, and each gets one file.

```console
$ sudo conflux enrol --manifest node-14.b64
credential installed
  from          node-14.b64
  api           https://guardian.example.gov
  renewal       https://guardian.example.gov/nodes/e3b0c442-…/credential
  expires       2026-10-13 04:12 UTC
  ipv4          10.20.0.7/24
  taint         site-alpha
  bootstrap     genesis-1.example.gov:4700, genesis-2.example.gov:4700

Next: sudo conflux up
```

The document is the same format — anchor's, `formatVersion: 1`, `kind: "anchor"` — and
the fields an issuer adds carry the difference.

### `renewalAuth: "node-secret"`

There are exactly three answers:

- **absent, or `"anchor-id"`** — no header. The alpha realm sends `"anchor-id"`, and
  anchor's own format has no renewal fields at all.
- **`"node-secret"`** — `Authorization: Bearer <renewalSecret>`, where `renewalSecret`
  is a value in the same document, minted for this one machine.
- **anything else** — refused, naming the value.

The refusal is deliberate and is worth stating, because the tempting alternative is to
send nothing and hope. There is no case where that succeeds: the far end is expecting
proof, so what you get is a 401 and a failure message about a status code instead of
one that says which scheme this build does not implement. A node that quietly
downgrades is worse than one that stops.

`conflux enrol` refuses an unknown scheme at import, when a person is present to read
it. The running renewal path warns and carries on instead — an anchor that cannot yet
renew is strictly better than one that will not start.

### `renewalSecret` is the machine, a second time

Everything [the section on a stolen manifest](security.md#a-stolen-manifestb64-is-permanent) says
applies to this field as well, and it is the reason that section did not get any
gentler on this path. Whoever holds the document holds the identity seed **and** the
bearer that keeps its credential current, so they are that anchor and can stay that
anchor.

What is different is that there is now somewhere to report it to. Revocation on a
guardian is the guardian refusing to renew, which is the entire mechanism — nothing is
pushed, no list is distributed, and the credential simply lapses on its own schedule.
On the alpha realm there is nobody to tell and nothing that could be done.

The secret never reaches an argv, never gets its own file, and is covered by the same
redaction that keeps the rest of the document out of logs.

### `ipv4` and `export`, copied once

A guardian allocates overlay IPv4 addresses out of a range it keeps, and may say where
telemetry should go. Both travel in the document, and `conflux enrol` copies them into
`conflux.json` **once** — after that they are ordinary configuration, visible in
`conflux status` and editable.

Read once rather than obeyed on every start, and that is the same distinction that
makes conflux refuse to inherit the two exit flags at all. An exit flag would go on
deciding, at every boot, whether this machine is a route to the public internet for
other people. These are a suggestion made at commissioning time by the operator who is
about to run the collector anyway, recorded where they can see it and change it, and
never consulted again.

### Renewal, and what a lapse costs

Renewal is the same exchange with a header on it: `POST` the renewal URL with the same
body, `{"anchorId": "anchor…", "taints": [...]}` — the taints the manifest names, `[]`
for a credential granting none — and `Authorization: Bearer <renewalSecret>`, and get
back the same shape, `{"chain": "…", "notAfter": "…", "bootstrap": [...]}`. That URL is
where the configured API base came from in the first place — enrol reads it out of the
document — so the two agree unless `--api` was passed to say otherwise, in which case
they are checked against each other. See [commands.md](commands.md#conflux-enrol).

A guardian signs from its own realm root, which it holds. So its ability to renew your
machine does not depend on it being able to reach anything upstream — if its own
delegation lapses, its realm is cut off from the tree above and **keeps running within
itself**, and it goes on renewing the machines beneath it indefinitely. That is the
point of a self-hosted deployment, and it is why a guardian node's renewal URL names
the guardian and never us.

## A credential that does not renew

A document carrying no renewal fields at all, no `renewalUrl` and no `renewalAuth`, is
**fixed-term**. It runs to its `notAfter` and is then replaced, not renewed.

That is not a third issuer so much as a third answer to "who renews this", and the one
case that produces it today is VeilNet's own fleet. traveller commissions the nodes it
runs in its two ghost realms (beta exits, alpha bootstraps) from its admin routes under
`/ghosts/realms/:realm/nodes`. It mints their credentials for **a century**, as long as
the realm's delegation above them, and serves **no node renewal route**. Taking one of
those nodes out of its realm means going to the host, which is the trade traveller makes
so that an outage in a renewal path cannot take the fleet down. anchor's own manifest
format has no renewal fields either, so a document anchorctl wrote reads the same way.

```console
$ sudo conflux enrol --manifest node-au.b64
credential installed
  from          node-au.b64
  renewal       none: it runs to its expiry and is then replaced
  expires       2126-10-03 11:25 UTC
  taint         au
  bootstrap     anchor…@203.0.113.10:4701, genesis.veilnet.com.au:4700
  exit          commissioned as one; conflux serves an exit only when told to

Next: sudo conflux up --serve-exit
```

What conflux does differently:

- **`conflux enrol` installs it with no `--api`.** There is no renewal URL to read a base
  out of. `--api` is taken as given if passed, and nothing is checked against it.
- **An expired one is refused at enrol.** A credential that renews comes back from
  expiry on its first renewal. One that does not renew never comes back, and installing
  it would also make it the identity `enrol` refuses to replace. Past its expiry on a
  machine already running, the next start is refused for good — anchor will not build an
  anchor on it — and the unit shows as failed until it is replaced.
- **Nothing asks to renew it.** A start does not call the API, the timer stops instead
  of retrying every minute, and `conflux renew` exits 69 naming the reason. None of this
  is recorded as a failing renewal, because nothing failed.
- **`exit: true` is reported, not obeyed.** A beta node is commissioned as an exit.
  conflux passes `-serve-exit` itself on every start, so the machine serves one only
  after `conflux up --serve-exit` (or `conflux proxy --serve-exit`, which serves it from
  the anchor's own process with nothing on the host). With an interface on Linux, anchor
  sets the host up to forward as it starts; see [modes.md](modes.md).
- **`listenPort` applies** unless `--port` says otherwise. traveller lists the node in
  every bootstrap list at that port, so leave it alone.

A document that names a `renewalAuth` and no `renewalUrl` is **not** fixed-term. It says
how to authenticate a renewal but not where to send one, so it is refused at enrol as a
mistake by its issuer.
