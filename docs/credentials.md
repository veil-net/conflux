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
| the window | seven days | whatever the operator chose, inside anchor's ninety-day cap |
| addresses | derived from the identity | derived, plus an IPv4 the operator may allocate |

The rest of this page is the alpha realm unless it says otherwise, and the section on
guardian-issued credentials is at the end.

## Enrolment is one unauthenticated POST

`POST https://api.veilnet.com.au/ghosts/alpha` takes no body, needs no account, and
returns a base64 anchor manifest. The API mints an identity inline, signs a credential
for it, puts both in the document, and forgets them.

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

## The seven-day window, and renewal

*(The alpha realm. A guardian chooses its own window; the arithmetic below is the
same either way, because it is computed from the document's own `issuedAt` and
`notAfter` rather than from a constant.)*

A credential is issued for seven days. conflux renews at **two thirds of the window** —
day 4.67 — which is what the API's own documentation specifies, and which leaves
fifty-six hours of retry budget for a machine that is having a bad week.

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

**The renewed chain is written to disk as well as installed.** If it were only
installed, the next reboot would start from the stale chain — and if the machine had
been off longer than the original window, from an expired one, at a moment when
nothing is watching.

## Being offline past the expiry costs nothing but a call

The renewal route is checked against nothing and gated on nothing: it takes an
AnchorID, which is the public half, and signs a fresh chain for it. It works after
expiry.

So a machine that was switched off for a month renews on its next launch and **keeps
its AnchorID and its overlay address**. There is no window to miss. The address is
lost only if something re-enrols, which is why conflux will not.

That safety is also, seen from the other side, the thing to understand about this
model: see [security.md](security.md).

## What renewal failure looks like

Three states, three behaviours:

| State | What conflux does |
|---|---|
| credential valid, renewal failed | warns with the time remaining, starts normally, retries on a backoff |
| credential expired, renewal failed | starts, retries forever, and `conflux status` says `EXPIRED` and names the last error — the anchor is up but every handshake is refused, and reporting "running" would be describing the wrong thing |
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

anchor's handshake tag rotates hourly and a peer accepts one epoch either side, so two
machines two hours apart **cannot connect at all** — and the symptom is a TLS alert
that looks exactly like a wrong realm. Separately, a clock an hour fast makes a fresh
credential look nearly expired, and one a year slow makes an expired one look fine.

conflux compares the API's `Date` header to the local clock on every call, records the
skew, and refuses to bring a machine up when it exceeds an hour — naming NTP, because
the failure is otherwise unrecognisable. Better to stop than to start an anchor that
reports itself healthy and reaches nobody.

The measurement comes from talking to the API, so it exists on the two paths that do:
enrolling, and renewing. A start that needs neither makes no call and measures
nothing, which is why `conflux status` prints the clock line only when there is a
figure to print — silence there means "not measured", not "measured and fine".

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
$ sudo conflux enrol --manifest node-14.b64 --api https://guardian.example.gov
credential installed
  from          node-14.b64
  api           https://guardian.example.gov
  renewal       https://guardian.example.gov/nodes/e3b0c442-…/credential
  expires       2026-10-13 04:12 UTC
  ipv4          10.20.0.7/24
  bootstrap     genesis-1.example.gov:4700, genesis-2.example.gov:4700

Next: sudo conflux up
```

The document is the same format — `formatVersion: 1`, `kind: "anchor"` — and three
fields that the alpha realm does not use carry the difference.

### `renewalAuth: "node-secret"`

The field has always been in the document and conflux never read it, because with one
issuer whose route was gated on nothing there was nothing to read it for. It is read
now, and there are exactly three answers:

- **absent, or `"anchor-id"`** — no header. The alpha realm, byte for byte as before.
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

Everything [the section on a stolen manifest](#a-stolen-manifestb64-is-permanent) says
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
`conflux config` and editable.

Read once rather than obeyed on every start, and that is the same distinction that
makes conflux refuse to inherit the two exit flags at all. An exit flag would go on
deciding, at every boot, whether this machine is a route to the public internet for
other people. These are a suggestion made at commissioning time by the operator who is
about to run the collector anyway, recorded where they can see it and change it, and
never consulted again.

### Renewal, and what a lapse costs

Renewal is the same exchange with a header on it: `POST` the renewal URL with
`{"anchorId": "anchor…"}`, get back `{"chain": "…", "notAfter": "…"}`. The URL must
name the same host as `--api`, for the reason [commands.md](commands.md#conflux-enrol)
gives.

A guardian signs from its own realm root, which it holds. So its ability to renew your
machine does not depend on it being able to reach anything upstream — if its own
delegation lapses, its realm is cut off from the tree above and **keeps running within
itself**, and it goes on renewing the machines beneath it indefinitely. That is the
point of a self-hosted deployment, and it is why a guardian node's renewal URL names
the guardian and never us.
