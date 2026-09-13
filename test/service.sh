#!/usr/bin/env bash
# The boot service, in a container that actually boots systemd.
#
# install registers the unit and does not start it; uninstall leaves nothing behind.
# Neither assertion enrols, so this runs without touching the API -- which is what
# makes it the cheap one to run when the question is only about the unit.
#
# Restarting the container is the reboot, and that half lives in integration.sh
# because proving a machine comes back needs a machine that was up.
set -euo pipefail

IMAGE=${IMAGE:-conflux-systemd-test}
NAME=${NAME:-cfx}

say() { printf '\n== %s\n' "$*"; }

# Before as well as after. The trap below does not fire when a CI run is cancelled --
# the runner's SIGTERM ends bash without it, and SIGKILL is not catchable at all --
# and on a machine that is not thrown away afterwards that leaves a name the next run
# collides with, for a reason that has nothing to do with the commit under test.
docker rm -f "$NAME" >/dev/null 2>&1 || true
trap 'docker rm -f "$NAME" >/dev/null 2>&1 || true' EXIT

say "a container that boots systemd"
docker run -d --name "$NAME" --privileged --cgroupns=host \
  -v /sys/fs/cgroup:/sys/fs/cgroup:rw --device /dev/net/tun "$IMAGE" >/dev/null

for _ in $(seq 40); do
  [ "$(docker exec "$NAME" systemctl is-system-running 2>/dev/null)" = running ] && break
  sleep 1
done
[ "$(docker exec "$NAME" systemctl is-system-running 2>/dev/null)" = running ] \
  || { echo "systemd did not come up" >&2; exit 1; }

say "install registers without inventing a configuration"
docker exec "$NAME" conflux install
[ "$(docker exec "$NAME" systemctl is-enabled conflux.service)" = enabled ] \
  || { echo "install did not enable the unit" >&2; exit 1; }

# The half that is easy to regress: install must register and not start. A machine
# with no configuration has nothing to start, and an install that started anyway
# would spend the unit's ninety seconds failing before saying so.
[ "$(docker exec "$NAME" systemctl is-active conflux.service)" = inactive ] \
  || { echo "install started the service; it must only register" >&2; exit 1; }

say "uninstall leaves nothing"
docker exec "$NAME" conflux uninstall --yes
docker exec "$NAME" sh -c 'test ! -f /etc/systemd/system/conflux.service' \
  || { echo "the unit file survived uninstall" >&2; exit 1; }
docker exec "$NAME" sh -c 'test ! -d /var/lib/conflux' \
  || { echo "the state directory survived uninstall" >&2; exit 1; }

say "all assertions passed"
