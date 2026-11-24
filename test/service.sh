#!/usr/bin/env bash
# The boot service, in a container that actually boots systemd.
#
# install registers the unit and does not start it; anchord runs as conflux's own account
# with exactly what each mode and host needs, and as root only where the host demands it;
# uninstall leaves nothing behind. Until the observer's legs nothing enrols -- the
# configuration names an API that answers nothing, so anchord stays up while the enrolment
# waits -- which is what makes this the cheap one to run when the question is only about the
# unit and what it starts. The observer runs only under a credential, so its legs enrol one
# anonymous alpha credential at $VEILNET_API, in a random taint, as service-host.sh does, and
# run under it: alone, its records read back from the inventory and from a collector, and
# beside each anchor.
#
# The hosts it needs are made inside the container, so every branch is taken on every
# runner: /dev/net/tun opened up or kept root's, and firewalld and iptables stood in for by
# scripts that answer the one question conflux asks them.
#
# Restarting the container is the reboot, and that half lives in integration.sh
# because proving a machine comes back needs a machine that was up.
set -euo pipefail

# Nothing here pipes a command into grep -q: grep stops at its first match, the command still
# writing is then ended by SIGPIPE, and under pipefail that fails the line however right its
# output was. Each answer is read whole, then searched (grep -q PATTERN <<<"$(COMMAND)").

IMAGE=${IMAGE:-conflux-systemd-test}
NAME=${NAME:-cfx}
OTEL=${OTEL:-$NAME-otel}

# The collector the observer's records are exported to: anchor's own suite runs this one.
OTEL_IMAGE=${OTEL_IMAGE:-otel/opentelemetry-collector:0.162.0}

# Where the observer's legs enrol their one credential, production's API when unset: it has to
# be the tree the embedded anchord is pinned to, which CI names by the pull request's base. The
# taint is random, so the credential reaches nobody else in the realm.
API=${VEILNET_API:-https://api.veilnet.com.au}
TAINT="cfx-svc-$(head -c6 /dev/urandom | od -An -tx1 | tr -d ' \n')"

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
docker exec "$NAME" systemctl show -p ExecStart --value conflux.service | grep 'path=/var/lib/.conflux/conflux ' >/dev/null \
  || { echo "the unit does not run /var/lib/.conflux/conflux:" >&2
       docker exec "$NAME" systemctl show -p ExecStart --value conflux.service >&2; exit 1; }
[ "$(docker exec "$NAME" stat -c '%a %U' /var/lib/.conflux/conflux)" = "700 root" ] \
  || { echo "the service's copy is not root's alone:" >&2
       docker exec "$NAME" stat -c '%a %U' /var/lib/.conflux/conflux >&2; exit 1; }

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
    /var/lib/.conflux/bin/*/anchord)
      awk '/^Uid:/ { u = $2 } /^CapEff:/ { c = $2 } /^NoNewPrivs:/ { n = $2 }
           /^Groups:/ { for (i = 2; i <= NF; i++) g = g (g ? "," : "") $i }
           END { printf "uid=%s caps=%s nnp=%s groups=%s\n", u, c, n, g }' "$p/status"
      exit 0 ;;
  esac
done
exit 1
SH

# configure writes a configuration conflux could have written, in MODE, with any more
# fields after it, in TAINT at API: by default pointed at that silent API.
configure() { # MODE [FIELDS [TAINT API]]
  local extra=''
  [ "$1" = proxy ] && extra='"proxies":["8080=127.0.0.1:3000"],'
  docker exec -i "$NAME" sh -c "umask 077; cat > /var/lib/.conflux/conflux.json" <<JSON
{"version":1,"mode":"$1",$extra${2:+$2,}"taints":["${3:-cfx-service-test}"],"apiBaseUrl":"${4:-https://127.0.0.1:9443}","createdAt":"2026-01-01T00:00:00Z","updatedAt":"2026-01-01T00:00:00Z"}
JSON
}

# start stops the service, which waits for anchord to go, and starts it without waiting
# for an anchor that will never come up -- clearing the failure systemd records for a unit
# started five times in ten seconds first, as conflux's own start does. It notes which
# anchord.priv, the record of what the last anchord was started as, is there before: by its
# inode, since every start writes a new one atomically. The record stays, unlike
# service-bsd.sh's: the supervisor reads which anchor directory the last anchor kept its
# state in from it, and the legs that flip between anchor/ and anchor.root/ test that.
start() {
  docker exec "$NAME" systemctl stop conflux.service
  docker exec "$NAME" systemctl reset-failed conflux.service
  last_record=$(docker exec "$NAME" stat -c %i /var/lib/.conflux/anchord.priv 2>/dev/null || true)
  docker exec "$NAME" systemctl start --no-block conflux.service
}

# expect waits for the anchord just started and holds it to WANT, a creds line -- a
# pattern, so a root anchord's capabilities, which are whatever this runner gives root, can
# be left open -- and to a status row that says ROW. It waits first for the start's own
# record, written once anchord runs: until then status reads the last leg's, and creds can
# find the `anchord -h` the supervisor tries a drop with before it starts the real one.
expect() { # WHAT WANT ROW
  local got="" row="" now=""
  for _ in $(seq 150); do
    now=$(docker exec "$NAME" stat -c %i /var/lib/.conflux/anchord.priv 2>/dev/null || true)
    [ -n "$now" ] && [ "$now" != "$last_record" ] && break
    sleep 0.2
  done
  [ -n "$now" ] && [ "$now" != "$last_record" ] \
    || { echo "$1: the supervisor recorded no anchord it started" >&2; journal; exit 1; }
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
check_mode /var/lib/.conflux "710 root conflux"
check_mode /var/lib/.conflux/run "710 root conflux"
check_mode /var/lib/.conflux/anchor "700 conflux conflux"
check_mode /var/lib/.conflux/run/anchord "700 conflux conflux"
check_mode /var/lib/.conflux/anchord.json "600 conflux conflux"
check_mode /var/lib/.conflux/run/token "600 root root"
check_mode /var/lib/.conflux/conflux "700 root root"

say "the unit runs with a system service's protections"
for want in UMask=0077 PrivateTmp=yes ProtectHome=read-only ProtectHostname=yes \
  ProtectControlGroups=yes LockPersonality=yes RestrictRealtime=yes RestrictSUIDSGID=yes \
  ProtectClock=no DevicePolicy=auto DeviceAllow=; do
  key=${want%%=*}
  got=$(docker exec "$NAME" systemctl show -p "$key" --value conflux.service)
  [ "$key=$got" = "$want" ] || { echo "the unit's $key is $got, want ${want#*=}" >&2; exit 1; }
done

# systemd re-owns a directory it was told to make, at every start, once its group is not
# the unit's: the root is not one of those, and stays as the supervisor left it.
say "a restart leaves anchord's directory its own"
start
expect "restarted" "uid=$uid caps=$(caps "$bufcap") nnp=1 groups=" "$bufrow"
check_mode /var/lib/.conflux/anchor "700 conflux conflux"

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
docker exec "$NAME" sh -c 'cd /var/lib/.conflux &&
  umask 077 && echo secret > secret &&
  su -s /bin/sh conflux -c "echo carried > anchor/carried" &&
  ln -s /var/lib/.conflux/secret anchor/link && ln secret anchor/hard'

say "a host that keeps /dev/net/tun root's keeps anchord root, in a directory of its own"
docker exec "$NAME" chmod 600 /dev/net/tun
start
expect "root-only tun" "uid=0 caps=* nnp=0 groups=*" "/dev/net/tun opens only for root"
check_mode /var/lib/.conflux/anchor.root "700 root root"
check_mode /var/lib/.conflux/anchor.root/carried "600 root root"
for name in link hard; do
  docker exec "$NAME" test ! -e "/var/lib/.conflux/anchor.root/$name" \
    || { echo "the copy to root's directory took the account's $name" >&2; exit 1; }
done
check_mode /var/lib/.conflux/secret "600 root root"

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
check_mode /var/lib/.conflux/anchor/carried "600 conflux conflux"

# The observer runs only under a credential, checked as an anchor's start is, so its legs run
# under one: anonymous, alpha, in this run's taint, enrolled at $API by the first of them, which
# finds none, as `conflux observe` enrols one. Alone, there is no anchor, and anchord is given
# the capture and nothing else -- CAP_NET_RAW, under no_new_privs, and no buffer capability,
# since no socket is bound.
say "observing alone, under a credential enrolled at $API in $TAINT, anchord has CAP_NET_RAW and nothing else"
configure observe '"observer":{}' "$TAINT" "$API"
start
expect "observing" "uid=$uid caps=$(caps 0x2000) nnp=1 groups=" "CAP_NET_RAW to copy what the host's interfaces carry"

# observing waits until status shows the observer capturing: the first time, once the enrolment
# it starts after has answered.
observing() {
  for _ in $(seq 300); do
    grep -q '^  observer *af_packet' <<<"$(docker exec "$NAME" conflux status 2>/dev/null)" && return 0
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
docker exec "$NAME" test -s /var/lib/.conflux/manifest.b64 \
  || { echo "the observer is capturing, and there is no credential it runs under" >&2; exit 1; }

# identity is the credential the observer's legs run under, on one line: manifest.b64's SHA-256
# and the AnchorID state.json records for it.
identity() {
  local sum id
  sum=$(docker exec "$NAME" sha256sum /var/lib/.conflux/manifest.b64) || return 1
  id=$(docker exec "$NAME" sed -n 's/.*"anchorId": "\([^"]*\)".*/\1/p' /var/lib/.conflux/state.json) || return 1
  printf '%s %s\n' "${sum%% *}" "$id"
}

# The observer's legs enrol once: the first, above, found no credential and enrolled one, and
# every leg after it runs under that one, enrolling nothing. What it enrolled is the manifest's
# bytes, and the AnchorID state.json records for it as the start that began the observer ends.
enrolled=""
for _ in $(seq 50); do
  enrolled=$(identity) || enrolled=""
  case $enrolled in *" anchor"?*) break ;; esac
  sleep 0.2
done
case $enrolled in
  *" anchor"?*) ;;
  *) echo "state.json records no AnchorID for the credential the observer runs under: ${enrolled:-no credential}" >&2
     journal; exit 1 ;;
esac

# enrolled_once holds the credential to the one the first observer leg enrolled.
enrolled_once() { # AFTER
  local now
  now=$(identity) || now=""
  [ "$now" = "$enrolled" ] \
    || { echo "after $1 the credential is ${now:-gone}, not the $enrolled the first observer leg enrolled" >&2
         journal; exit 1; }
}

traffic
for _ in $(seq 60); do
  grep -q ' 443/tcp ' <<<"$(docker exec "$NAME" conflux inventory 2>/dev/null)" && break
  sleep 2
done
docker exec "$NAME" conflux inventory | grep ' 443/tcp ' \
  || { echo "the inventory holds no connection to port 443:" >&2
       docker exec "$NAME" conflux inventory >&2 || true; journal; exit 1; }
grep -q '^  records *kept here' <<<"$(docker exec "$NAME" conflux status)" \
  || { echo "status does not say the records are kept here" >&2; exit 1; }

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
configure observe "\"observer\":{},\"export\":{\"enabled\":true,\"endpoint\":\"$collector:4317\",\"insecure\":true,\"flows\":true}" "$TAINT" "$API"
start
expect "observing, exporting" "uid=$uid caps=$(caps 0x2000) nnp=1 groups=" "CAP_NET_RAW to copy what the host's interfaces carry"
observing
traffic
for _ in $(seq 60); do
  grep -q 'anchor.observed_flow.key_exchange' <<<"$(docker logs "$OTEL" 2>&1)" && break
  sleep 2
done
grep -q 'anchor.observed_flow.key_exchange' <<<"$(docker logs "$OTEL" 2>&1)" \
  || { echo "no anchor.observed_flow record reached the collector:" >&2
       docker logs "$OTEL" 2>&1 | tail -20 >&2; journal; exit 1; }
docker rm -f "$OTEL" >/dev/null
enrolled_once "the export leg"

# Beside an anchor, under the same credential, the capture is added to what the anchor's mode
# is given.
say "the observer beside an anchor adds CAP_NET_RAW to what its mode has"
configure proxy '"observer":{}' "$TAINT" "$API"
start
expect "userspace and observing" "uid=$uid caps=$(caps "0x2000|$bufcap") nnp=1 groups=" "CAP_NET_RAW to copy"
observing
configure tun '"observer":{}' "$TAINT" "$API"
start
expect "tun and observing" "uid=$uid caps=$(caps 0x3000) nnp=0 groups=" "CAP_NET_RAW to copy"
observing
enrolled_once "the legs beside an anchor"

# start registers the unit this conflux writes: one changed by hand, here with a capability
# line, is replaced.
say "start registers the unit this conflux writes"
docker exec "$NAME" sh -c 'sed -i "s/^User=root$/User=root\nAmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW/" /etc/systemd/system/conflux.service && systemctl daemon-reload'
docker exec "$NAME" systemctl stop conflux.service
docker exec "$NAME" timeout 10 conflux start >/dev/null 2>&1 || true
if docker exec "$NAME" grep -q AmbientCapabilities /etc/systemd/system/conflux.service; then
  echo "start left the old unit in place" >&2
  exit 1
fi
docker exec "$NAME" systemctl stop conflux.service

# The service is the supervisor's to keep: started by systemd itself, with nothing typed, it
# puts back a unit changed by hand and removes the unit's four drop-in directories, in /etc and
# /run, which would change it -- written by hand, or by systemctl set-property, each persistent in
# /etc or for the boot in /run.
say "a start by systemd puts the unit back and removes its drop-ins"
dropins=(/etc/systemd/system/conflux.service.d /etc/systemd/system.control/conflux.service.d
  /run/systemd/system/conflux.service.d /run/systemd/system.control/conflux.service.d)
anydropin() { docker exec "$NAME" sh -c 'for d; do [ -e "$d" ] && exit 0; done; exit 1' sh "${dropins[@]}"; }
docker exec "$NAME" sh -c 'sed -i "s/^User=root$/User=root\nAmbientCapabilities=CAP_NET_ADMIN/" /etc/systemd/system/conflux.service &&
  for d in /etc/systemd/system /run/systemd/system; do
    mkdir -p $d/conflux.service.d && printf "[Service]\nEnvironment=HAND=1\n" > $d/conflux.service.d/hand.conf
  done &&
  systemctl set-property conflux.service CPUWeight=50 &&
  systemctl set-property --runtime conflux.service CPUWeight=60 && systemctl daemon-reload'
for d in "${dropins[@]}"; do
  docker exec "$NAME" test -d "$d" || { echo "there is no drop-in at $d for a start to remove" >&2; exit 1; }
done
docker exec "$NAME" timeout 20 systemctl start conflux.service >/dev/null 2>&1 || true
for _ in $(seq 50); do
  docker exec "$NAME" grep -q AmbientCapabilities /etc/systemd/system/conflux.service || anydropin || break
  sleep 0.2
done
if docker exec "$NAME" grep -q AmbientCapabilities /etc/systemd/system/conflux.service; then
  echo "a start left the hand-changed unit in place" >&2
  exit 1
fi
for d in "${dropins[@]}"; do
  docker exec "$NAME" test ! -e "$d" || { echo "a start left the unit's drop-in directory $d" >&2; exit 1; }
done
docker exec "$NAME" systemctl stop conflux.service
enrolled_once "the starts that put the unit back"

# uninstall stops the unit itself, and only then disables it: a disable fails for a unit whose
# file is gone, which systemd may still be running. Here the file is deleted under the running
# unit, with no daemon-reload, under the configuration the legs above left -- a TUN and the
# observer, under the run's credential.
say "uninstall stops a running unit whose file was deleted"
# serving is whether a supervisor runs: a process whose command line is the unit's ExecStart.
serving() {
  docker exec "$NAME" sh -c 'for c in /proc/[0-9]*/cmdline; do
    [ "$(tr "\0" " " 2>/dev/null < "$c")" = "/var/lib/.conflux/conflux serve " ] && exit 0
  done
  exit 1'
}
start
expect "a running unit" "uid=$uid caps=$(caps 0x3000) nnp=0 groups=" "CAP_NET_RAW to copy"
serving || { echo "no conflux serve is running for uninstall to stop" >&2; journal; exit 1; }
docker exec "$NAME" rm /etc/systemd/system/conflux.service
docker exec "$NAME" conflux uninstall --yes
if serving; then
  echo "uninstall left conflux serve running from a unit whose file was gone" >&2
  exit 1
fi
docker exec "$NAME" test ! -L /etc/systemd/system/multi-user.target.wants/conflux.service \
  || { echo "uninstall left the wants link of a unit whose file was gone" >&2; exit 1; }

# Installed again, with the executable copied back where the image put it, and started once in
# userspace, which makes the account again: the uninstall below has all of it to remove.
docker cp "$(dirname "$0")/systemd/conflux" "$NAME":/usr/local/bin/conflux
docker exec "$NAME" conflux install >/dev/null
configure proxy
start
uid=""
for _ in $(seq 150); do
  uid=$(docker exec "$NAME" id -u conflux 2>/dev/null) && break
  sleep 0.2
done
[ -n "$uid" ] || { echo "no conflux account was made again" >&2; exit 1; }
expect "installed again" "uid=$uid caps=$(caps "$bufcap") nnp=1 groups=" "$bufrow"

# A drop-in of systemctl set-property's, in system.control, made after the supervisor started
# and so not removed by it: uninstall removes it with the unit.
docker exec "$NAME" systemctl set-property conflux.service CPUQuota=50%
docker exec "$NAME" test -d /etc/systemd/system.control/conflux.service.d \
  || { echo "systemctl set-property made no drop-in for uninstall to remove" >&2; exit 1; }
docker exec "$NAME" systemctl stop conflux.service

# install made the root, so it has to go -- and the account, the drop-in, and the executable
# the image put where the installer puts it.
say "uninstall leaves nothing"
docker exec "$NAME" conflux uninstall --yes
docker exec "$NAME" test ! -e /usr/local/bin/conflux \
  || { echo "the installed executable survived uninstall" >&2; exit 1; }
docker exec "$NAME" sh -c 'test ! -f /etc/systemd/system/conflux.service' \
  || { echo "the unit file survived uninstall" >&2; exit 1; }
docker exec "$NAME" sh -c 'test ! -L /etc/systemd/system/multi-user.target.wants/conflux.service' \
  || { echo "the unit's wants link survived uninstall" >&2; exit 1; }
if anydropin; then
  echo "a drop-in directory of the unit's survived uninstall" >&2
  exit 1
fi
docker exec "$NAME" test ! -e /var/lib/.conflux || { echo "/var/lib/.conflux survived uninstall" >&2; exit 1; }
if docker exec "$NAME" id conflux >/dev/null 2>&1; then
  echo "the conflux account survived uninstall" >&2
  exit 1
fi

# An account of that name conflux did not make is somebody else's: anchord does not run
# as it, and uninstall leaves it where it was.
say "an account conflux did not make is neither used nor removed"
docker cp "$(dirname "$0")/systemd/conflux" "$NAME":/usr/local/bin/conflux
docker exec "$NAME" useradd --system --no-create-home conflux
docker exec "$NAME" conflux install >/dev/null
configure proxy
start
expect "a foreign account" "uid=0 caps=* nnp=0 groups=*" "conflux did not make it"
docker exec "$NAME" conflux uninstall --yes >/dev/null
docker exec "$NAME" id conflux >/dev/null || { echo "uninstall removed an account conflux did not make" >&2; exit 1; }

say "all assertions passed"
