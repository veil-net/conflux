#!/usr/bin/env bash
# Three conflux nodes, one taint, reaching each other over the overlay.
#
# This enrols three times against the live API, and renews once. That is deliberate
# and cheap: the routes are anonymous, store nothing, and the taint below is random --
# every credential is issued in it, so the nodes sit in a compartment of their own and
# can exchange data with nobody else in the realm.
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

# wait_active waits for the service to say the anchor is up -- Type=notify, so active is
# that and not merely a started process -- and fails the run if it never does.
wait_active() {
  for _ in $(seq 40); do
    [ "$(docker exec "$1" systemctl is-active conflux.service 2>/dev/null)" = active ] && return 0
    sleep 1
  done
  echo "$1: the service did not come back after the reboot" >&2
  docker exec "$1" journalctl -u conflux --no-pager -n 30 >&2 || true
  return 1
}

anchor_id() { docker exec "$1" sh -c "sed -n 's/.*\"anchorId\": \"\([^\"]*\)\".*/\1/p' /var/lib/conflux/state.json"; }

# grants is 1 when a node's credential grants exactly [$2], and 0 otherwise: the
# manifest is compact JSON on one line, from the API and as conflux rewrites it.
grants() {
  docker exec "$1" sh -c 'base64 -d /var/lib/conflux/manifest.b64' | grep -c "\"taints\":\[\"$2\"\]" || true
}

# lan_found sums anchor_lan_peers_found_total across whatever labels it carries -- the
# counter is per-interface, and a container with two bridges would otherwise be read
# as only the first of them. connections is the anchor_connections gauge. `conflux
# metrics` is the anchorctl pass-through, "name<padding>value" per line.
#
# Every reader of a pipe in this file reads to the end. One that stops early -- awk's
# exit, grep -q -- leaves the writer to die of SIGPIPE whenever it has more to say, and
# under pipefail that is a 141 which fails an assignment and falsifies an if.
lan_found() {
  docker exec "$1" conflux metrics 2>/dev/null |
    awk '$1 ~ /^anchor_lan_peers_found_total/ { s += $2 } END { print s + 0 }'
}

connections() {
  docker exec "$1" conflux metrics 2>/dev/null | awk '$1 == "anchor_connections" { v = $2 } END { print v + 0 }'
}

# A and B are given a bootstrap entry that cannot answer -- 192.0.2.1 is RFC 5737's
# documentation range -- in place of the realm's own. anchor probes the local link only
# until its first connection, so with the live realm answering, both would be introduced
# through it within a second and the link would prove nothing. Without it, the only way
# the two can meet is LAN discovery on the Docker bridge, which is the one thing no Go
# test in this tree can arrange: a real kernel, real multicast, a real answer.
NOWHERE=192.0.2.1:4700

# Reaped before as well as after. The trap does not fire when a run is cancelled -- a
# SIGTERM ends bash without it, and SIGKILL is not catchable at all -- and on a machine
# that is not thrown away afterwards a cancelled run leaves three fixed names for the
# next run to collide with. `docker rm -f` shrugs at a name that is not there, so this
# is a no-op on a clean machine.
before=$(docker ps -aq | wc -l)
docker rm -f cfx-a cfx-b cfx-c >/dev/null 2>&1 || true
echo "containers on this machine: $before before this run"

trap 'docker rm -f cfx-a cfx-b cfx-c >/dev/null 2>&1 || true' EXIT

say "taint for this run: $TAINT"

say "node A joins"
boot cfx-a
docker exec cfx-a conflux up --taint "$TAINT" --ipv4 10.128.0.1/24 --peers "$NOWHERE"
A_ID=$(anchor_id cfx-a)
[ -n "$A_ID" ] || { echo "node A recorded no AnchorID" >&2; exit 1; }

say "the identity is 0600 and the state directory 0700"
[ "$(docker exec cfx-a stat -c%a /var/lib/conflux/manifest.b64)" = 600 ] \
  || { echo "manifest.b64 is not 0600" >&2; exit 1; }
[ "$(docker exec cfx-a stat -c%a /run/conflux)" = 700 ] \
  || { echo "the run directory is not 0700" >&2; exit 1; }

say "the credential grants the taint A asked for"
[ "$(grants cfx-a "$TAINT")" = 1 ] || { echo "A's credential does not grant $TAINT" >&2; exit 1; }

say "a second up must not enrol again"
docker exec cfx-a conflux up >/dev/null
[ "$(anchor_id cfx-a)" = "$A_ID" ] \
  || { echo "the identity changed on a second up -- conflux re-enrolled" >&2; exit 1; }

# A credential's taints never change, so another one is a new identity, which conflux
# will not draw behind a re-run: it refuses, naming the way out, and nothing is replaced.
say "an up asking for another taint is refused, and the identity stays"
if refusal=$(docker exec cfx-a conflux up --taint cfx-ci-elsewhere 2>&1); then
  echo "A accepted a taint its credential does not grant" >&2
  exit 1
fi
case $refusal in
  *"conflux uninstall"*) ;;
  *) printf 'the refusal did not name the way out:\n%s\n' "$refusal" >&2; exit 1 ;;
esac
[ "$(anchor_id cfx-a)" = "$A_ID" ] && [ "$(grants cfx-a "$TAINT")" = 1 ] \
  || { echo "the refused up replaced A's identity or credential" >&2; exit 1; }

# The renewal restates the taint, and the running anchor refuses a chain granting any
# other set: a hot install that succeeds is the proof the two agree.
say "A renews against the live API and installs the chain hot"
docker exec cfx-a conflux renew
[ "$(anchor_id cfx-a)" = "$A_ID" ] || { echo "a renewal changed A's identity" >&2; exit 1; }

say "node B joins with the same taint"
boot cfx-b
docker exec cfx-b conflux up --taint "$TAINT" --ipv4 10.128.0.2/24 --peers "$NOWHERE"

# The realm's control over its members is anchorctl's, reached through conflux unchanged.
# Listing blocks needs no power; an order does, and an alpha credential grants none, so
# A asking B how it is must be refused for that -- on A's side, before anything is sent.
say "realm control passes through: blocks lists, and an order is refused for want of the power"
docker exec cfx-a conflux blocks | awk 'NR == 1 && $1 == "ANCHOR" { ok = 1 } END { exit !ok }' \
  || { echo "conflux blocks did not print anchorctl's table" >&2; exit 1; }
if refusal=$(docker exec cfx-a conflux telemetry -from "$(anchor_id cfx-b)" -timeout 10s 2>&1); then
  echo "an alpha credential ordered telemetry from another member" >&2
  exit 1
fi
case $refusal in
  *capability*) echo "refused: ${refusal%%$'\n'*}" ;;
  *) printf 'the order was refused for another reason:\n%s\n' "$refusal" >&2; exit 1 ;;
esac

# Both directions, because each learns the other's IPv4 from a signed advertisement and
# the two need not arrive together. Polled every second, so the figure printed is how
# long it took rather than the next multiple of a sleep.
say "waiting for the two to find each other"
SECONDS=0
while [ "$SECONDS" -lt 120 ]; do
  if docker exec cfx-a ping -c1 -W1 10.128.0.2 >/dev/null 2>&1 &&
    docker exec cfx-b ping -c1 -W1 10.128.0.1 >/dev/null 2>&1; then
    echo "reachable both ways after ${SECONDS}s"
    break
  fi
  sleep 1
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
# Non-zero rather than present, and that is the whole assertion: anchor writes the
# counter only when a probe finds a peer, so a sum above zero is a find, where a grep
# for the name would hold only as long as nothing else ever wrote it.
# They met, and nothing but the link could have introduced them; the counter says the
# probe is what found them. Either end may be the one that counts: whichever probe the
# other answers first, the connection it makes stops the other's.
say "the two found each other on the link"
SECONDS=0
while [ "$SECONDS" -lt 60 ]; do
  found=$(( $(lan_found cfx-a) + $(lan_found cfx-b) ))
  [ "$found" -gt 0 ] && { echo "discovery counter moved after ${SECONDS}s"; break; }
  sleep 1
done
[ "$found" -gt 0 ] \
  || { echo "anchor_lan_peers_found_total never moved on A or B, so they did not meet on the link" >&2; exit 1; }

# C is enrolled the other way: from an alpha manifest fetched here, in the run's taint,
# and handed to `conflux enrol` on stdin, which is the path a commissioned machine takes
# and the one that would otherwise only ever see hand-written fixtures. The taint comes
# from the credential; `up` restating it is accepted, and must start from the manifest
# without enrolling again.
say "node C is enrolled from a live alpha manifest, then joins with --lan-discovery no and no bootstrap list of its own"
boot cfx-c
manifest=$(curl -fsS -X POST -H 'Accept: application/json' -H 'Content-Type: application/json' \
  -d "{\"taints\":[\"$TAINT\"]}" --max-time 30 https://api.veilnet.com.au/ghosts/alpha |
  sed -n 's/^{"credentials":"\([A-Za-z0-9+/=]*\)"}$/\1/p')
[ -n "$manifest" ] || { echo "POST /ghosts/alpha did not answer with {\"credentials\": ...}" >&2; exit 1; }
printf '%s' "$manifest" | docker exec -i cfx-c conflux enrol --manifest -
unset manifest
[ "$(grants cfx-c "$TAINT")" = 1 ] || { echo "C's credential does not grant $TAINT" >&2; exit 1; }
docker exec cfx-c conflux up --taint "$TAINT" --ipv4 10.128.0.3/24 --lan-discovery no
if docker exec cfx-c journalctl -u conflux --no-pager | awk '/enrolling/ { n++ } END { exit n == 0 }'; then
  echo "C enrolled again instead of starting from the manifest it was given" >&2
  exit 1
fi
[ -n "$(anchor_id cfx-c)" ] || { echo "node C recorded no AnchorID" >&2; exit 1; }

# The no-flag path: with discovery off and no --peers, the only way C reaches anything is
# the bootstrap list in the manifest it was given -- A and B cannot carry it, since they
# reach no realm node themselves. A connection proves the issuer's list works as shipped.
say "C reaches the realm through the manifest's own bootstrap list"
SECONDS=0
conns=0
while [ "$SECONDS" -lt 60 ]; do
  conns=$(connections cfx-c)
  [ "${conns:-0}" -gt 0 ] && { echo "C holds $conns connection(s) after ${SECONDS}s"; break; }
  sleep 1
done
# On failure, what C resolved and what anchord said while trying: the containers are
# reaped on exit, so this is the only record of why.
if [ "${conns:-0}" -eq 0 ]; then
  echo "C reached nothing through the manifest's bootstrap list" >&2
  docker exec cfx-c getent ahosts genesis.veilnet.com.au >&2 || echo "C cannot resolve genesis.veilnet.com.au" >&2
  docker exec cfx-c conflux status >&2 || true
  docker exec cfx-c journalctl -u conflux --no-pager -n 60 >&2 || true
  exit 1
fi

# The control, and the reason it is worth a third enrolment: C is up and answering on the
# same link where A and B found each other, so if its counter stays at zero then
# --lan-discovery no reached anchor rather than being accepted by conflux and dropped on
# the floor.
[ "$(lan_found cfx-c)" -eq 0 ] \
  || { echo "C probed the link despite --lan-discovery no: the flag did not reach anchor" >&2; exit 1; }
echo "C has probed the link 0 times: --lan-discovery no reached anchor"

say "reboot A: it must come back by itself, same identity"
docker restart cfx-a >/dev/null
wait_active cfx-a
docker exec cfx-a conflux status
[ "$(anchor_id cfx-a)" = "$A_ID" ] \
  || { echo "the identity changed across a reboot" >&2; exit 1; }

# A daemon that dies is the supervisor's to restart, with no reboot and nothing typed.
# The Go tests hold shutdown to returning once anchord has gone; this is the whole path,
# a real anchord killed under a real systemd, until the anchor is back on the overlay.
# The readiness marker is withdrawn on the way down and written once the anchor is up,
# so a new pid with a marker beside it is the new anchor, not the old one's leftovers.
say "anchord dies on A: the supervisor brings it back, same identity, without a reboot"
A_PID=$(docker exec cfx-a pidof anchord)
docker exec cfx-a sh -c "kill -9 $A_PID"
SECONDS=0
while [ "$SECONDS" -lt 60 ]; do
  pid=$(docker exec cfx-a pidof anchord || true)
  if [ -n "$pid" ] && [ "$pid" != "$A_PID" ] && docker exec cfx-a test -f /run/conflux/ready; then
    echo "anchord $pid replaced $A_PID after ${SECONDS}s"
    break
  fi
  sleep 1
done
if [ -z "${pid:-}" ] || [ "$pid" = "$A_PID" ] || ! docker exec cfx-a test -f /run/conflux/ready; then
  echo "the supervisor did not bring anchord back after it died" >&2
  docker exec cfx-a journalctl -u conflux --no-pager -n 30 >&2 || true
  exit 1
fi
[ "$(anchor_id cfx-a)" = "$A_ID" ] \
  || { echo "the identity changed across a restart of anchord" >&2; exit 1; }
# Over B's IPv6, which is derived from its identity: back on the overlay is what this
# stage asks, and that address needs nothing from B but its record.
SECONDS=0
until docker exec cfx-a ping -c1 -W1 "$B6" >/dev/null 2>&1; do
  [ "$SECONDS" -lt 60 ] || { echo "A did not reach B again after anchord came back" >&2; exit 1; }
  sleep 1
done
echo "A reaches B again after ${SECONDS}s"

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
wait_active cfx-b
[ "$(anchor_id cfx-b)" = "$B_ID" ] \
  || { echo "B's identity changed across down and a reboot" >&2; exit 1; }

say "uninstall removes everything"
docker exec cfx-b conflux uninstall --yes
docker exec cfx-b sh -c 'test ! -f /etc/systemd/system/conflux.service' \
  || { echo "the unit survived uninstall" >&2; exit 1; }
for dir in /etc/conflux /var/lib/conflux /run/conflux; do
  docker exec cfx-b test ! -e "$dir" || { echo "$dir survived uninstall" >&2; exit 1; }
done
docker exec cfx-b sh -c '! ip link show anchor0' >/dev/null 2>&1 \
  || { echo "uninstall left the interface up" >&2; exit 1; }

say "all assertions passed"
