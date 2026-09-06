# Concepts

Five words appear in conflux's output. This page defines them once and then links out
to [anchor's documentation](https://github.com/veil-net/anchor/tree/main/docs), which
describes the mechanism rather than the wrapper.

## An anchor is an identity

An anchor's name *is* its public key. The AnchorID conflux prints —
`anchor6btpa3gn6w4stipba4hekzho7…` — is derived from a 32-byte seed, and so is the
overlay IPv6 address beside it. Nothing assigns either; they fall out of the key.

Two consequences run through everything else. The address is stable for as long as the
seed survives, which is why conflux enrols exactly once. And the address cannot be
changed, which is why losing the seed loses the machine's place on the network rather
than merely inconveniencing it. See [credentials.md](credentials.md).

## A realm is admission control

A realm is a root key and a credential per member. An anchor presents a chain proving
it descends from the root, and the chain is checked during the TLS handshake — before
any data. Membership is not a list on a server; it is a signature.

conflux enrols into VeilNet's public realm. The credential is issued for seven days
and renewed automatically. See [credentials.md](credentials.md).

## Overlay addresses are derived, not assigned

Every anchor has an IPv6 address computed from its identity and its realm. It needs no
coordination and cannot collide.

IPv4 is different, and that is why `conflux up` asks. Thirty-two bits is too small to
derive collision-free, so an overlay IPv4 is *operator-assigned*: you pick it, and
nothing checks that two machines did not pick the same one. It is written as a prefix
(`10.128.0.7/24`) rather than a bare address, because the prefix length is what tells
the stack which addresses are on-link.

Blank is a valid answer. The realm works without IPv4 at all.

## Taints

A taint is a compartment label, and it is the whole of who can reach a machine.

**The rule is containment, not overlap.** Two anchors in one realm may exchange data
only if one of them carries every taint the other does. This is worth reading twice,
because "they share a taint" is not the rule and the difference matters:

| A carries | B carries | Can they exchange data? | Why |
|---|---|---|---|
| `{x}` | `{x}` | yes | each set contains the other |
| `{x}` | `{x, y}` | yes | A's set is contained in B's |
| `{x, y}` | `{x, z}` | **no** | neither contains the other, despite sharing `x` |
| `{x}` | `{y}` | no | neither contains the other |
| `{}` | anything | yes | the empty set is contained in every set |

Everything else still works across a taint boundary: two separated anchors still
connect, still bootstrap from each other, still relay for each other. What they cannot
do is exchange data. It is a blast-radius control inside a realm that has already
decided everyone in it is a member — not a tenant boundary. The hard boundary is the
realm.

Three practical corollaries:

- **Three machines with three generated taints are three disconnected machines.** The
  taint has to be shared deliberately; nothing propagates it.
- **A hub with `{a}` and spokes with `{a,b}` and `{a,c}` works as a hub.** The hub
  reaches both spokes and the spokes cannot reach each other. That is the arrangement
  containment exists to express, and it is a feature.
- **Two machines with `{office,laptop}` and `{office,desktop}` cannot talk**, which
  surprises people. If you want both reachable from each other, give them the same
  set.

`conflux status` prints the taint, and `conflux peers` has a `DATA` column that says
`yes` or `no` per peer. That column is the only signal you will get, and it is the
first thing to look at when two machines are up and cannot see each other.

### Why conflux generates one

An anchor with no configured taints is not exempt from the rule. It carries the
realm's **default compartment**, a real derived tag that every other unconfigured
anchor in the realm also carries. So "no taint" does not mean "no restriction"; it
means "in the commons, with every stranger who also left it blank".

That is the right default for the realm conflux enrols into, which exists to let any
device reach any other, and the wrong default for somebody joining two of their own
machines. So `conflux up` mints `brhk-2mq9-tzva-6pjs` — sixteen characters from an
alphabet with no `i`, `l`, `o`, `0` or `1`, because it gets read off one screen and
typed into another — and prints it.

Taint names are not secret from the realm: the tag is derived from a public root id,
so any member can compute the tag for a name it can guess. A generated one is
unguessable, which is the whole of the protection it provides. `prod` is not.

`conflux up --no-taint` opts back into the commons. It is a deliberate choice, and
conflux says so when you make it.

## What conflux decides, and what anchor decides

conflux decides: which mode, which taints, which overlay IPv4, which subnets, which
proxies, where the files live, and when to renew. That is the whole list, and it is
what the configuration file holds.

anchor decides everything else — every packet, every route, every credential check,
every peer. When something goes wrong on the wire it is anchor's documentation that
describes it.

| Read | For |
|---|---|
| [anchor: realm.md](https://github.com/veil-net/anchor/blob/main/docs/realm.md) | taints, compartments, and the derivation |
| [anchor: identity.md](https://github.com/veil-net/anchor/blob/main/docs/identity.md) | what an identity is and how it is stored |
| [anchor: overlay.md](https://github.com/veil-net/anchor/blob/main/docs/overlay.md) | how addresses are derived |
| [anchor: architecture.md](https://github.com/veil-net/anchor/blob/main/docs/architecture.md) | the whole design |
| [anchor: operations.md](https://github.com/veil-net/anchor/blob/main/docs/operations.md) | the operator's manual for anchorctl itself |
