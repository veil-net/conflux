#!/usr/bin/env bash
# Two conflux nodes, one taint, reaching each other over the overlay.
#
# This enrols twice against the live API. That is deliberate and cheap: the route is
# anonymous, stores nothing, and the taint below is random -- so the two nodes sit in
# a compartment of their own and can exchange data with nobody else in the realm.
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

trap 'docker rm -f cfx-a cfx-b >/dev/null 2>&1 || true' EXIT

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
