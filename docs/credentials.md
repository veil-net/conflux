# Credentials

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
