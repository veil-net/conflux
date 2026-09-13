#!/usr/bin/env bash
# Three conflux nodes, one taint, reaching each other over the overlay.
#
# This enrols three times against the live API. That is deliberate and cheap: the
# route is anonymous, stores nothing, and the taint below is random -- so the nodes
# sit in a compartment of their own and can exchange data with nobody else in the
# realm.
#
# The third node is the LAN-discovery control and joins late; everything before it is
# the two-node test this file has always been.
set -euo pipefail

IMAGE=${IMAGE:-conflux-systemd-test}
TAINT="cfx-ci-$(head -c6 /dev/urandom | od -An -tx1 | tr -d ' \n')"

say() { printf '\n== %s\n' "$*"; }

boot() {
  local name=$1
  docker rm -f "$name" >/dev/null 2>&1 || true
  docker run -d --name "$name" --privileged --cgroupns=host \
    -v /sys/fs/cgroup:/sys/fs/cgroup:rw --device /dev/net/tun "$IMAGE" >/dev/null
  for _ in $(seq 40); do
    [ "$(docker exec "$name" systemctl is-system-running 2>/dev/null)" = running ] && return 0
    sleep 1
  done
  echo "$name: systemd did not come up" >&2
  return 1
}

anchor_id() { docker exec "$1" sh -c "sed -n 's/.*\"anchorId\": \"\([^\"]*\)\".*/\1/p' /var/lib/conflux/state.json"; }

# lan_found sums anchor_lan_peers_found_total across whatever labels it carries -- the
# counter is per-interface, and a container with two bridges would otherwise be read
# as only the first of them. `conflux metrics` is the anchorctl pass-through, and its
# format is "name<two spaces>value"; see internal/anchorctl.ParseMetrics.
lan_found() {
  docker exec "$1" conflux metrics 2>/dev/null |
    awk '$1 ~ /^anchor_lan_peers_found_total/ { s += $2 } END { print s + 0 }'
}

# Reaped before as well as after. The trap does not fire when a CI run is cancelled
# -- the runner's SIGTERM ends bash without it, and SIGKILL is not catchable at all --
# and the runner is no longer a machine that is thrown away afterwards, so a cancelled
# run leaves three fixed names for the next run to collide with. `docker rm -f` shrugs
# at a name that is not there, so this is a no-op on a clean machine.
before=$(docker ps -aq | wc -l)
docker rm -f cfx-a cfx-b cfx-c >/dev/null 2>&1 || true
echo "containers on this machine: $before before this run"

trap 'docker rm -f cfx-a cfx-b cfx-c >/dev/null 2>&1 || true' EXIT

say "taint for this run: $TAINT"

say "node A joins"
boot cfx-a
docker exec cfx-a conflux up --taint "$TAINT" --ipv4 10.128.0.1/24
A_ID=$(anchor_id cfx-a)
[ -n "$A_ID" ] || { echo "node A recorded no AnchorID" >&2; exit 1; }

say "the identity is 0600 and the state directory 0700"
[ "$(docker exec cfx-a stat -c%a /var/lib/conflux/manifest.b64)" = 600 ] \
  || { echo "manifest.b64 is not 0600" >&2; exit 1; }
[ "$(docker exec cfx-a stat -c%a /run/conflux)" = 700 ] \
  || { echo "the run directory is not 0700" >&2; exit 1; }

say "a second up must not enrol again"
docker exec cfx-a conflux up >/dev/null
[ "$(anchor_id cfx-a)" = "$A_ID" ] \
  || { echo "the identity changed on a second up -- conflux re-enrolled" >&2; exit 1; }

say "node B joins with the same taint"
boot cfx-b
docker exec cfx-b conflux up --taint "$TAINT" --ipv4 10.128.0.2/24

say "waiting for the two to find each other"
for i in $(seq 12); do
  if docker exec cfx-a ping -c1 -W2 10.128.0.2 >/dev/null 2>&1; then
    echo "reachable after ~$((i * 10))s"
    break
  fi
  sleep 10
done

say "reachable both ways, v4 and v6"
docker exec cfx-a ping -c3 -W3 10.128.0.2
docker exec cfx-b ping -c3 -W3 10.128.0.1
B6=$(docker exec cfx-b sh -c "ip -o -6 addr show anchor0 scope global | awk '{print \$4}' | cut -d/ -f1")
docker exec cfx-a ping -c2 -W3 "$B6"

# Both containers sit on one Docker bridge, which is a real link with a real
# multicast-capable kernel -- the one thing no Go test in this tree can arrange. So
# the probe is live here whether or not anything was configured to use it.
#
# Non-zero rather than present, and that is the whole assertion. The series is created
# the first time it is written, delta included, so the name appears at zero as soon as
# an anchor polls -- a grep for the name alone passes on an anchor that never found a
# thing. anchor's own suite records being caught by exactly that.
say "the realm was found on the link, not only through the bootstrap list"
for i in $(seq 12); do
  [ "$(lan_found cfx-a)" -gt 0 ] && { echo "discovery counter moved after ~$((i * 5))s"; break; }
  sleep 5
done
[ "$(lan_found cfx-a)" -gt 0 ] \
  || { echo "anchor_lan_peers_found_total never moved on A, so nothing was found on the link" >&2; exit 1; }

# The control, and the reason it is worth a third enrolment: A's counter moved, so if C's
# stays at zero on the same link then --lan-discovery no reached anchor rather than being
# accepted by conflux and dropped on the floor. That is conflux's contribution and the only
# thing here this repository can be held to.
#
# Two claims used to be made together, and only one of them was ever conflux's. The other
# was that C, naming no --peers, still reaches the realm from the manifest's own bootstrap
# list -- which would prove discovery is a third source rather than a load-bearing one.
#
# That one cannot hold in this topology, and the reason is not a firewall. C can only be
# told about a node the bootstrap list already knows, so it needs at least one of A or B to
# have reached the realm's bootstrap nodes and been announced there. Here none of the three
# ever does: they meet on the Docker bridge and nowhere else. So the bootstrap list has
# nothing to tell C, and C finding nothing is the correct outcome rather than a failure.
#
# Still worth reporting. The day one of them does reach the realm, C finding it is exactly
# the proof that discovery is additive -- so the run says which happened.
say "node C joins with --lan-discovery no and no bootstrap list of its own"
boot cfx-c
docker exec cfx-c conflux up --taint "$TAINT" --ipv4 10.128.0.3/24 --lan-discovery no

# Zero is only worth asserting from an anchor that is up and answering. lan_found sends
# stderr to /dev/null and awk prints 0 for no input at all, so a C that had died would pass
# the check below by saying nothing -- which is the shape of gate this repository has been
# caught by before. Prove there are metrics first; the zero means something after that.
metrics=0
for _ in $(seq 12); do
  metrics=$(docker exec cfx-c conflux metrics 2>/dev/null | grep -c '^anchor_' || true)
  [ "$metrics" -gt 0 ] && break
  sleep 5
done

[ "$metrics" -gt 0 ] \
  || { echo "C served no anchor_ metrics, so a zero discovery counter would prove nothing" >&2; exit 1; }

[ "$(lan_found cfx-c)" -eq 0 ] \
  || { echo "C probed the link despite --lan-discovery no: the flag did not reach anchor" >&2; exit 1; }
echo "C is answering with $metrics anchor_ metrics and has probed the link 0 times:"
echo "  --lan-discovery no reached anchor, while A on the same link probed and found peers"

# Reported, not asserted. See the note above.
if docker exec cfx-a ping -c3 -W3 10.128.0.3 >/dev/null 2>&1; then
  echo "  and C reached the realm anyway, so something the bootstrap list knows carried it:"
  echo "  discovery is additive here rather than load-bearing"
else
  echo "  C did not reach the realm, which is the correct outcome in this topology: neither"
  echo "  A nor B was ever announced to the realm's bootstrap nodes, so there is nothing"
  echo "  there for C to be told about once it stops probing the link"
fi

say "reboot A: it must come back by itself, same identity"
docker restart cfx-a >/dev/null
for _ in $(seq 40); do
  [ "$(docker exec cfx-a systemctl is-active conflux.service 2>/dev/null)" = active ] && break
  sleep 1
done
docker exec cfx-a conflux status
[ "$(anchor_id cfx-a)" = "$A_ID" ] \
  || { echo "the identity changed across a reboot" >&2; exit 1; }

say "down leaves the registration and the configuration"
docker exec cfx-b conflux down
[ "$(docker exec cfx-b systemctl is-enabled conflux.service)" = enabled ] \
  || { echo "down disabled the boot service" >&2; exit 1; }
docker exec cfx-b sh -c 'test -f /etc/conflux/conflux.json' \
  || { echo "down removed the configuration" >&2; exit 1; }
docker exec cfx-b sh -c 'test -f /var/lib/conflux/manifest.b64' \
  || { echo "down removed the identity" >&2; exit 1; }
docker exec cfx-b sh -c '! ip link show anchor0' >/dev/null 2>&1 \
  || { echo "down left the interface up" >&2; exit 1; }

say "start brings B back without a reboot, and without retyping anything"
B_BEFORE=$(anchor_id cfx-b)
docker exec cfx-b conflux start
for _ in $(seq 40); do
  docker exec cfx-b sh -c 'ip link show anchor0' >/dev/null 2>&1 && break
  sleep 1
done
docker exec cfx-b sh -c 'ip link show anchor0' >/dev/null 2>&1 \
  || { echo "start did not bring the interface back" >&2; exit 1; }
[ "$(anchor_id cfx-b)" = "$B_BEFORE" ] \
  || { echo "B's identity changed across down and start" >&2; exit 1; }

say "down again, and a reboot brings B back"
docker exec cfx-b conflux down
B_ID=$(anchor_id cfx-b)
docker restart cfx-b >/dev/null
for _ in $(seq 40); do
  [ "$(docker exec cfx-b systemctl is-active conflux.service 2>/dev/null)" = active ] && break
  sleep 1
done
[ "$(anchor_id cfx-b)" = "$B_ID" ] \
  || { echo "B's identity changed across down and a reboot" >&2; exit 1; }

say "uninstall removes everything"
docker exec cfx-b conflux uninstall --yes
docker exec cfx-b sh -c 'test ! -f /etc/systemd/system/conflux.service' \
  || { echo "the unit survived uninstall" >&2; exit 1; }
docker exec cfx-b sh -c 'test ! -d /var/lib/conflux' \
  || { echo "the state directory survived uninstall" >&2; exit 1; }

say "all assertions passed"
