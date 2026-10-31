#!/usr/bin/env bash
# The boot service, in a container that actually boots systemd.
#
# install registers the unit and does not start it; anchord runs as conflux's own account
# with exactly what each mode and host needs, and as root only where the host demands it;
# uninstall leaves nothing behind. Nothing enrols -- the configuration names an API that
# answers nothing, so anchord stays up while the enrolment waits -- so this runs without
# touching the API, which is what makes it the cheap one to run when the question is only
# about the unit and what it starts. The observer needs no API at all: it is run alone, its
# records read back from the inventory and from a collector, and beside each anchor.
#
# The hosts it needs are made inside the container, so every branch is taken on every
# runner: /dev/net/tun opened up or kept root's, and firewalld and iptables stood in for by
# scripts that answer the one question conflux asks them.
#
# Restarting the container is the reboot, and that half lives in integration.sh
# because proving a machine comes back needs a machine that was up.
set -euo pipefail

IMAGE=${IMAGE:-conflux-systemd-test}
NAME=${NAME:-cfx}
OTEL=${OTEL:-$NAME-otel}

# The collector the observer's records are exported to: anchor's own suite runs this one.
OTEL_IMAGE=${OTEL_IMAGE:-otel/opentelemetry-collector:0.162.0}

say() { printf '\n== %s\n' "$*"; }

# Before as well as after. The trap below does not fire when a CI run is cancelled --
# the runner's SIGTERM ends bash without it, and SIGKILL is not catchable at all --
# and on a machine that is not thrown away afterwards that leaves a name the next run
# collides with, for a reason that has nothing to do with the commit under test.
docker rm -f "$NAME" "$OTEL" >/dev/null 2>&1 || true
otelconf=$(mktemp)
trap 'docker rm -f "$NAME" "$OTEL" >/dev/null 2>&1 || true; rm -f "$otelconf"' EXIT

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
put() { docker exec -i "$NAME" sh -c "cat > $1 && chmod ${2:-644} $1"; }
put /etc/systemd/system/silent.socket <<'UNIT'
[Socket]
ListenStream=127.0.0.1:9443
Accept=yes
UNIT
put /etc/systemd/system/silent@.service <<'UNIT'
[Service]
ExecStart=/bin/sleep infinity
StandardInput=socket
UNIT
docker exec "$NAME" sh -c 'systemctl daemon-reload && systemctl start silent.socket'

# creds is the running anchord's uid, effective capabilities, no_new_privs and
# supplementary groups, on one line.
put /usr/local/bin/creds 755 <<'SH'
#!/bin/sh
for p in /proc/[0-9]*; do
  case "$(readlink "$p/exe" 2>/dev/null)" in
    /var/lib/conflux/bin/*/anchord)
      awk '/^Uid:/ { u = $2 } /^CapEff:/ { c = $2 } /^NoNewPrivs:/ { n = $2 }
           /^Groups:/ { for (i = 2; i <= NF; i++) g = g (g ? "," : "") $i }
           END { printf "uid=%s caps=%s nnp=%s groups=%s\n", u, c, n, g }' "$p/status"
      exit 0 ;;
  esac
done
exit 1
SH

# configure writes a configuration conflux could have written, in MODE, with any more
# fields after it, pointed at that API.
configure() { # MODE [FIELDS]
  local extra=''
  [ "$1" = proxy ] && extra='"proxies":["8080=127.0.0.1:3000"],'
  docker exec -i "$NAME" sh -c "umask 077; cat > /etc/conflux/conflux.json" <<JSON
{"version":1,"mode":"$1",$extra${2:+$2,}"taints":["cfx-service-test"],"apiBaseUrl":"https://127.0.0.1:9443","createdAt":"2026-01-01T00:00:00Z","updatedAt":"2026-01-01T00:00:00Z"}
JSON
}

# start stops the service, which waits for anchord to go, and starts it without waiting
# for an anchor that will never come up -- clearing the failure systemd records for a unit
# started five times in ten seconds first, as conflux's own start does.
start() {
  docker exec "$NAME" systemctl stop conflux.service
  docker exec "$NAME" systemctl reset-failed conflux.service
  docker exec "$NAME" systemctl start --no-block conflux.service
}

# expect waits for the anchord just started and holds it to WANT, a creds line -- a
# pattern, so a root anchord's capabilities, which are whatever this runner gives root, can
# be left open -- and to a status row that says ROW.
expect() { # WHAT WANT ROW
  local got="" row=""
  for _ in $(seq 150); do
    got=$(docker exec "$NAME" creds 2>/dev/null) && break
    sleep 0.2
  done
  for _ in $(seq 50); do
    row=$(docker exec "$NAME" conflux status 2>/dev/null | sed -n 's/^  anchord *//p')
    [ -n "$row" ] && break
    sleep 0.2
  done
  printf '  anchord: %s\n           %s\n' "$got" "$row"
  # shellcheck disable=SC2254 # WANT is a pattern on purpose
  case $got in
    $2) ;;
    *) echo "$1: anchord runs with ${got:-nothing}; want $2" >&2; journal; exit 1 ;;
  esac
  case $row in
    *"$3"*) ;;
    *) echo "$1: status says \"$row\"; want it to say \"$3\"" >&2; journal; exit 1 ;;
  esac
}

# journal is what the service said, for a failure to be read by.
journal() { docker exec "$NAME" journalctl -u conflux.service -n 40 --no-pager >&2 || true; }

caps() { printf '%016x' "$(( $1 ))"; }

# quic-go sizes its UDP buffers to 7 MiB, past net.core's limits with CAP_NET_ADMIN where
# they are lower; that sysctl is the host's, not the container's, so it is read, not set.
bufcap=0
[ "$(docker exec "$NAME" cat /proc/sys/net/core/rmem_max)" -lt 3670016 ] && bufcap=0x1000
[ "$(docker exec "$NAME" cat /proc/sys/net/core/wmem_max)" -lt 3670016 ] && bufcap=0x1000
bufrow="with no privilege"
[ "$bufcap" = 0x1000 ] && bufrow="CAP_NET_ADMIN to size its UDP buffers"

# conflux 1.0.0 gave a root anchord the account's name for its directory: the first start
# after the upgrade moves that state to root's own, and the account starts from a copy.
docker exec "$NAME" sh -c 'umask 077 && mkdir -p /var/lib/conflux/anchor && echo 1.0.0 > /var/lib/conflux/anchor/legacy'

say "in userspace anchord runs as its own account, with no capability"
configure proxy
start
# The supervisor makes the account the first time it is needed.
for _ in $(seq 150); do
  uid=$(docker exec "$NAME" id -u conflux 2>/dev/null) && break
  sleep 0.2
done
[ -n "${uid:-}" ] || { echo "no conflux account was made" >&2; exit 1; }
expect "userspace" "uid=$uid caps=$(caps "$bufcap") nnp=1 groups=" "$bufrow"
check_mode() { # PATH WANT
  [ "$(docker exec "$NAME" stat -c '%a %U %G' "$1")" = "$2" ] \
    || { echo "$1 is $(docker exec "$NAME" stat -c '%a %U %G' "$1"), want $2" >&2; exit 1; }
}
check_mode /var/lib/conflux "710 root conflux"
check_mode /run/conflux "710 root conflux"
check_mode /var/lib/conflux/anchor "700 conflux conflux"
check_mode /run/conflux/anchord "700 conflux conflux"
check_mode /var/lib/conflux/anchord.json "600 conflux conflux"
check_mode /run/conflux/token "600 root root"
check_mode /var/lib/conflux/conflux "700 root root"

say "the 1.0.0 anchor directory became root's, and the account's started from a copy"
check_mode /var/lib/conflux/anchor.root/legacy "600 root root"
check_mode /var/lib/conflux/anchor/legacy "600 conflux conflux"

# systemd re-owns a directory it was told to make, at every start, once its group is not
# the unit's: the state directory is not one of those, and stays as the supervisor left it.
say "a restart leaves anchord's directory its own"
start
expect "restarted" "uid=$uid caps=$(caps "$bufcap") nnp=1 groups=" "$bufrow"
check_mode /var/lib/conflux/anchor "700 conflux conflux"

say "a port below 1024 is given CAP_NET_BIND_SERVICE, and nothing more"
# Docker lets a container bind any port; a host keeps the first 1024 for root.
docker exec "$NAME" sh -c 'echo 1024 > /proc/sys/net/ipv4/ip_unprivileged_port_start'
configure proxy '"port":443'
start
expect "port 443" "uid=$uid caps=$(caps "0x400 | $bufcap") nnp=1 groups=" "CAP_NET_BIND_SERVICE for port 443"

say "an uplink's device is opened through its group, and one only root opens keeps root"
docker exec "$NAME" sh -c 'mknod -m 660 /dev/ttyCFX c 1 3 && chgrp dialout /dev/ttyCFX'
dialout=$(docker exec "$NAME" getent group dialout | cut -d: -f3)
configure proxy '"uplink":"/dev/ttyCFX:115200"'
start
expect "uplink" "uid=$uid caps=$(caps 0) nnp=1 groups=$dialout" "with no privilege"
docker exec "$NAME" chmod 600 /dev/ttyCFX
start
expect "a root-only uplink" "uid=0 caps=* nnp=0 groups=*" "/dev/ttyCFX opens only for root"
docker exec "$NAME" rm -f /dev/ttyCFX

# A TUN needs CAP_NET_ADMIN and nothing more, wherever the account may open /dev/net/tun:
# opened up here, as a stock host has it, whatever the runner's own is.
say "with a TUN anchord has CAP_NET_ADMIN, and only that"
docker exec "$NAME" chmod 666 /dev/net/tun
configure tun
start
expect "tun" "uid=$uid caps=$(caps 0x1000) nnp=0 groups=" "CAP_NET_ADMIN for its interface"

# What the account leaves in its directory for root to carry: a file of its own, and a
# symlink and a hard link to a file of root's, which a copy must not follow, take or touch.
docker exec "$NAME" sh -c 'cd /var/lib/conflux &&
  umask 077 && echo secret > secret &&
  su -s /bin/sh conflux -c "echo carried > anchor/carried" &&
  ln -s /var/lib/conflux/secret anchor/link && ln secret anchor/hard'

say "a host that keeps /dev/net/tun root's keeps anchord root, in a directory of its own"
docker exec "$NAME" chmod 600 /dev/net/tun
start
expect "root-only tun" "uid=0 caps=* nnp=0 groups=*" "/dev/net/tun opens only for root"
check_mode /var/lib/conflux/anchor.root "700 root root"
check_mode /var/lib/conflux/anchor.root/carried "600 root root"
for name in link hard; do
  docker exec "$NAME" test ! -e "/var/lib/conflux/anchor.root/$name" \
    || { echo "the copy to root's directory took the account's $name" >&2; exit 1; }
done
check_mode /var/lib/conflux/secret "600 root root"

# anchor runs the host's firewall commands with a TUN, and some answer only root. They are
# stood in for by scripts that answer the question conflux asks: whether firewalld runs,
# and which backend iptables is.
tool() { # NAME VERSION-LINE
  put "/usr/local/sbin/$1" 755 <<SH
#!/bin/sh
[ "\$1" = --version ] && echo "$2"
exit 0
SH
}
docker exec "$NAME" chmod 666 /dev/net/tun

say "firewalld, which takes changes only from root, keeps anchord root"
tool firewall-cmd "running"
start
expect "firewalld" "uid=0 caps=* nnp=0 groups=*" "firewalld takes changes only from root"
docker exec "$NAME" rm /usr/local/sbin/firewall-cmd

say "iptables on the legacy backend keeps anchord root"
tool iptables "iptables v1.8.10 (legacy)"
start
expect "legacy iptables" "uid=0 caps=* nnp=0 groups=*" "iptables is on the legacy backend"

say "iptables on nf_tables with no nft adds CAP_NET_RAW, for its set match"
tool iptables "iptables v1.8.10 (nf_tables)"
start
expect "iptables without nft" "uid=$uid caps=$(caps 0x3000) nnp=0 groups=" "CAP_NET_RAW for iptables' set match"
docker exec "$NAME" rm /usr/local/sbin/iptables

say "back in userspace, the account starts from root's state, as its own"
configure proxy
start
expect "userspace again" "uid=$uid caps=$(caps "$bufcap") nnp=1 groups=" "$bufrow"
check_mode /var/lib/conflux/anchor/carried "600 conflux conflux"

# The observer, alone: no anchor, so nothing enrols, and anchord is given the capture and
# nothing else -- CAP_NET_RAW, under no_new_privs, and no buffer capability, since no socket
# is bound.
say "observing alone, anchord has CAP_NET_RAW and nothing else, and enrols nothing"
configure observe '"observer":{}'
start
expect "observing" "uid=$uid caps=$(caps 0x2000) nnp=1 groups=" "CAP_NET_RAW to copy what the host's interfaces carry"

# observing waits until status shows the observer capturing.
observing() {
  for _ in $(seq 100); do
    docker exec "$NAME" conflux status 2>/dev/null | grep -q '^  observer *af_packet' && return 0
    sleep 0.2
  done
  echo "the observer is not capturing:" >&2
  docker exec "$NAME" conflux status >&2 || true
  journal
  exit 1
}

# traffic makes a TLS connection out of the container and ends it: conflux asking GitHub for
# its latest release, which is one HTTPS exchange and then the process is gone.
traffic() { docker exec "$NAME" sh -c 'conflux update --check >/dev/null 2>&1 || true'; }

observing
traffic
for _ in $(seq 60); do
  docker exec "$NAME" conflux inventory 2>/dev/null | grep -q ' 443/tcp ' && break
  sleep 2
done
docker exec "$NAME" conflux inventory | grep ' 443/tcp ' \
  || { echo "the inventory holds no connection to port 443:" >&2
       docker exec "$NAME" conflux inventory >&2 || true; journal; exit 1; }
docker exec "$NAME" conflux status | grep -q '^  records *kept here' \
  || { echo "status does not say the records are kept here" >&2; exit 1; }
docker exec "$NAME" test ! -e /var/lib/conflux/manifest.b64 \
  || { echo "observing alone enrolled" >&2; exit 1; }

# Each record leaves as it is made, with no anchor: a collector that logs every record it is
# sent, in detail, is the dashboard's side of it.
say "observing alone, each record reaches the collector the export names"
cat > "$otelconf" <<'YAML'
receivers:
  otlp:
    protocols:
      grpc:
        endpoint: 0.0.0.0:4317
exporters:
  debug:
    verbosity: detailed
service:
  pipelines:
    logs: {receivers: [otlp], exporters: [debug]}
YAML
chmod 644 "$otelconf"
docker run -d --name "$OTEL" -v "$otelconf:/etc/otel.yaml:ro" "$OTEL_IMAGE" --config /etc/otel.yaml >/dev/null
collector=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$OTEL")
[ -n "$collector" ] || { echo "the collector has no address" >&2; docker logs "$OTEL" >&2; exit 1; }
configure observe "\"observer\":{},\"export\":{\"enabled\":true,\"endpoint\":\"$collector:4317\",\"insecure\":true,\"flows\":true}"
start
expect "observing, exporting" "uid=$uid caps=$(caps 0x2000) nnp=1 groups=" "CAP_NET_RAW to copy what the host's interfaces carry"
observing
traffic
for _ in $(seq 60); do
  docker logs "$OTEL" 2>&1 | grep -q 'anchor.observed_flow.key_exchange' && break
  sleep 2
done
docker logs "$OTEL" 2>&1 | grep -q 'anchor.observed_flow.key_exchange' \
  || { echo "no anchor.observed_flow record reached the collector:" >&2
       docker logs "$OTEL" 2>&1 | tail -20 >&2; journal; exit 1; }
docker rm -f "$OTEL" >/dev/null

# Beside an anchor, the capture is added to what the anchor's mode is given.
say "the observer beside an anchor adds CAP_NET_RAW to what its mode has"
configure proxy '"observer":{}'
start
expect "userspace and observing" "uid=$uid caps=$(caps "0x2000|$bufcap") nnp=1 groups=" "CAP_NET_RAW to copy"
observing
configure tun '"observer":{}'
start
expect "tun and observing" "uid=$uid caps=$(caps 0x3000) nnp=0 groups=" "CAP_NET_RAW to copy"
observing

# An upgraded conflux brings its own unit, and start is how an upgrade reaches the
# service: a 1.0.0 unit, with its capability line, is replaced.
say "start registers the unit this conflux writes"
docker exec "$NAME" sh -c 'sed -i "s/^User=root$/User=root\nAmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW/" /etc/systemd/system/conflux.service && systemctl daemon-reload'
docker exec "$NAME" systemctl stop conflux.service
docker exec "$NAME" timeout 10 conflux start >/dev/null 2>&1 || true
if docker exec "$NAME" grep -q AmbientCapabilities /etc/systemd/system/conflux.service; then
  echo "start left the old unit in place" >&2
  exit 1
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

# An account of that name conflux did not make is somebody else's: anchord does not run
# as it, and uninstall leaves it where it was.
say "an account conflux did not make is neither used nor removed"
docker exec "$NAME" useradd --system --no-create-home conflux
docker exec "$NAME" conflux install >/dev/null
configure proxy
start
expect "a foreign account" "uid=0 caps=* nnp=0 groups=*" "conflux did not make it"
docker exec "$NAME" conflux uninstall --yes >/dev/null
docker exec "$NAME" id conflux >/dev/null || { echo "uninstall removed an account conflux did not make" >&2; exit 1; }

say "all assertions passed"
