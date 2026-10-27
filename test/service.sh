#!/usr/bin/env bash
# The boot service, in a container that actually boots systemd.
#
# install registers the unit and does not start it; anchord runs with only the privilege
# its mode needs; uninstall leaves nothing behind. Nothing enrols -- the configuration
# names an API that answers nothing -- so this runs without touching the
# API, which is what makes it the cheap one to run when the question is only about the
# unit.
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

# The unit runs the copy in the state directory, which only root can change, and never
# the file conflux was run from -- here /usr/local/bin, elsewhere a download anybody
# might be able to swap.
say "the unit runs the root-only copy of conflux"
docker exec "$NAME" systemctl show -p ExecStart --value conflux.service | grep 'path=/var/lib/conflux/conflux ' >/dev/null \
  || { echo "the unit does not run /var/lib/conflux/conflux:" >&2
       docker exec "$NAME" systemctl show -p ExecStart --value conflux.service >&2; exit 1; }
[ "$(docker exec "$NAME" stat -c '%a %U' /var/lib/conflux/conflux)" = "700 root" ] \
  || { echo "the service's copy is not root's alone:" >&2
       docker exec "$NAME" stat -c '%a %U' /var/lib/conflux/conflux >&2; exit 1; }

# An API that answers nothing: systemd accepts each connection and hands it to a sleep, so
# an enrolment waits out its timeout, and anchord stays up while it does. An address that
# refuses would end each try in milliseconds.
docker exec -i "$NAME" sh -c 'cat > /etc/systemd/system/silent.socket' <<'UNIT'
[Socket]
ListenStream=127.0.0.1:9443
Accept=yes
UNIT
docker exec -i "$NAME" sh -c 'cat > /etc/systemd/system/silent@.service' <<'UNIT'
[Service]
ExecStart=/bin/sleep infinity
StandardInput=socket
UNIT
docker exec "$NAME" sh -c 'systemctl daemon-reload && systemctl start silent.socket'

# A configuration conflux could have written, pointed at that API.
configure() { # MODE
  local extra='"proxies":["8080=127.0.0.1:3000"],'
  [ "$1" = tun ] && extra=''
  docker exec -i "$NAME" sh -c "umask 077; cat > /etc/conflux/conflux.json" <<JSON
{"version":1,"mode":"$1",$extra"taints":["cfx-service-test"],"apiBaseUrl":"https://127.0.0.1:9443","createdAt":"2026-01-01T00:00:00Z","updatedAt":"2026-01-01T00:00:00Z"}
JSON
}

# creds prints the Uid and CapEff of the running anchord, once there is one: the
# supervisor restarts one that its enrolment gave up on, so it is looked for a while.
creds() {
  for _ in $(seq 300); do
    out=$(docker exec "$NAME" sh -c 'for p in /proc/[0-9]*; do
        case "$(readlink $p/exe 2>/dev/null)" in /var/lib/conflux/bin/*/anchord)
          awk "/^(Uid|CapEff|NoNewPrivs):/ { printf \"%s %s \", \$1, \$2 }" $p/status; exit;; esac
      done' 2>/dev/null || true)
    [ -n "$out" ] && { echo "$out"; return 0; }
    sleep 0.2
  done
  echo "no anchord started" >&2
  return 1
}

say "in userspace anchord runs as its own account, with no capability"
configure proxy
docker exec "$NAME" systemctl start --no-block conflux.service
got=$(creds)
uid=$(docker exec "$NAME" id -u conflux) \
  || { echo "no conflux account was made" >&2; exit 1; }
# The buffers quic-go wants are past net.core.rmem_max on a default kernel, and sizing
# them past it is CAP_NET_ADMIN's; with the limit raised, nothing at all.
rmem=$(docker exec "$NAME" cat /proc/sys/net/core/rmem_max)
wmem=$(docker exec "$NAME" cat /proc/sys/net/core/wmem_max)
want="Uid: $uid CapEff: 0000000000000000 NoNewPrivs: 1 "
if [ "$rmem" -lt 3670016 ] || [ "$wmem" -lt 3670016 ]; then
  want="Uid: $uid CapEff: 0000000000001000 NoNewPrivs: 1 "
fi
echo "  anchord: $got"
[ "$got" = "$want" ] || { echo "anchord runs as: $got; want $want" >&2; exit 1; }
[ "$(docker exec "$NAME" stat -c '%a %U %G' /var/lib/conflux)" = "710 root conflux" ] \
  || { echo "the state directory is not root's with conflux let through:" >&2
       docker exec "$NAME" stat -c '%a %U %G' /var/lib/conflux >&2; exit 1; }
[ "$(docker exec "$NAME" stat -c '%a %U' /var/lib/conflux/anchor /run/conflux/token)" = "$(printf '700 conflux\n600 root')" ] \
  || { echo "anchord's directory is not its own, or the token is not root's" >&2; exit 1; }

# systemd re-owns a directory it was told to make, at every start, once its group is not
# the unit's: the state directory is not one of those, and stays as the supervisor left it.
say "a restart leaves anchord's directory its own"
docker exec "$NAME" systemctl stop conflux.service
docker exec "$NAME" systemctl start --no-block conflux.service
creds >/dev/null
[ "$(docker exec "$NAME" stat -c '%U' /var/lib/conflux/anchor)" = conflux ] \
  || { echo "a restart gave anchord's directory back to root" >&2; exit 1; }

# A TUN needs CAP_NET_ADMIN on Linux and nothing more -- as long as the account may open
# /dev/net/tun. A host that keeps the device root's keeps anchord root, and says why.
say "with a TUN anchord has CAP_NET_ADMIN, and only that"
docker exec "$NAME" systemctl stop conflux.service
configure tun
docker exec "$NAME" systemctl start --no-block conflux.service
got=$(creds)
echo "  anchord: $got"
if docker exec "$NAME" sh -c '[ "$(stat -c %a /dev/net/tun | cut -c3)" -ge 6 ]'; then
  want="Uid: $uid CapEff: 0000000000001000 NoNewPrivs: 0 "
  [ "$got" = "$want" ] || { echo "anchord runs as: $got; want $want" >&2; exit 1; }
else
  case $got in
    "Uid: 0 "*) ;;
    *) echo "anchord runs as: $got, where only root may open /dev/net/tun" >&2; exit 1 ;;
  esac
fi
docker exec "$NAME" systemctl stop conflux.service

# install made all three directories, so all three have to go -- and the account.
say "uninstall leaves nothing"
docker exec "$NAME" conflux uninstall --yes
docker exec "$NAME" sh -c 'test ! -f /etc/systemd/system/conflux.service' \
  || { echo "the unit file survived uninstall" >&2; exit 1; }
docker exec "$NAME" sh -c 'test ! -L /etc/systemd/system/multi-user.target.wants/conflux.service' \
  || { echo "the unit's wants link survived uninstall" >&2; exit 1; }
for dir in /etc/conflux /var/lib/conflux /run/conflux; do
  docker exec "$NAME" test ! -e "$dir" || { echo "$dir survived uninstall" >&2; exit 1; }
done
if docker exec "$NAME" id conflux >/dev/null 2>&1; then
  echo "the conflux account survived uninstall" >&2
  exit 1
fi

say "all assertions passed"
