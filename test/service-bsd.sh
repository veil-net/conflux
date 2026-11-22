#!/bin/sh
# The boot service on FreeBSD and OpenBSD, against rc, as root in a VM CI boots for it.
#
#   test/service-bsd.sh CONFLUX
#
# What test/service.sh is for systemd and test/service-host.sh for launchd and the SCM:
# install registers and starts nothing; in userspace anchord runs as conflux's own account
# -- conflux on FreeBSD, _conflux on OpenBSD -- made the first time it is needed; a TUN and
# a port only root may bind keep it root, saying why; and uninstall leaves nothing behind,
# the account included. Nothing is enrolled: the configuration names an API that accepts
# and answers nothing, so anchord stays up while the enrolment waits. POSIX sh, which is
# what both have.
set -eu

CONFLUX=${1:?usage: test/service-bsd.sh CONFLUX}

say() { printf '\n== %s\n' "$*"; }
fail() { echo "$*" >&2; exit 1; }

state=/var/db/.conflux
priv=$state/anchord.priv

case "$(uname -s)" in
  FreeBSD) os=freebsd account=conflux script=/usr/local/etc/rc.d/conflux log=$state/logs/conflux.log
    fips='fips140 on, Go Cryptographic Module v1.26.0' ;;
  OpenBSD) os=openbsd account=_conflux script=/etc/rc.d/conflux log=/var/log/daemon
    fips='fips140 off, this build carries no frozen Go Cryptographic Module' ;;
  *) fail "service-bsd.sh is for FreeBSD and OpenBSD" ;;
esac

rc() { # VERB
  if [ "$os" = freebsd ]; then service conflux "$1"; else rcctl "$1" conflux; fi
}

# FreeBSD's conflux runs the Go Cryptographic Module in FIPS 140-3 mode, here on the kernel it
# ships for; OpenBSD's is built without it, which the module refuses to run on.
say "conflux reports the FIPS 140-3 mode its build carries"
"$CONFLUX" version | grep -qx "$fips" || fail "conflux version does not say: $fips"

# The certificate toolkit makes artifacts other people rely on, so it runs only where the
# module does: FreeBSD makes and checks an ML-DSA certificate, OpenBSD refuses with 70.
say "conflux cert runs where the module does, and refuses where it does not"
certs=$(mktemp -d)
if [ "$os" = freebsd ]; then
  "$CONFLUX" cert genkey --out "$certs/k.pem" || fail "cert genkey failed"
  "$CONFLUX" cert selfsign --key "$certs/k.pem" --subject CN=bsd.test --profile server --out "$certs/c.pem" ||
    fail "cert selfsign failed"
  "$CONFLUX" cert verify "$certs/c.pem" --ca "$certs/c.pem" --name bsd.test --require-pq >/dev/null ||
    fail "a self-signed ML-DSA certificate does not verify"
else
  code=0
  "$CONFLUX" cert genkey --out "$certs/k.pem" 2>/dev/null || code=$?
  [ "$code" = 70 ] || fail "cert genkey on a build without the module exited $code, not 70"
  [ ! -e "$certs/k.pem" ] || fail "cert genkey wrote a key on a build without the module"
fi
rm -rf "$certs"

# A root conflux keeps is refused where an ACL lets another account write it, which its mode does
# not show; a CONFLUX_DIR, and every folder above a root, is never judged. FreeBSD keeps two kinds,
# POSIX.1e (UFS mounted with acls) and NFSv4 (ZFS, and UFS mounted with nfsv4acls), and conflux asks
# the kernel for each, so each is given here on a memory disk of its own, whatever the VM booted on.
# enrol makes the roots and, with no manifest to read, goes no further, under a directory whose ACL
# lets another account write it as anywhere; status, the readers' check, then refuses the root once
# it carries such an entry, naming the ACL, and takes it once the ACL is taken off.
acl_leg() { # MOUNT-OPTION SETFACL-ENTRY
  mnt=$(mktemp -d /tmp/cfx-acl.XXXXXX)
  md=$(mdconfig -a -t swap -s 16m)
  newfs "/dev/$md" >/dev/null
  mount -o "$1" "/dev/$md" "$mnt"
  mkdir "$mnt/open"
  setfacl -m "$2" "$mnt/open"

  out=$(CONFLUX_DIR="$mnt/open/conflux" "$CONFLUX" enrol --manifest "$mnt/none" 2>&1) &&
    fail "enrol with no manifest succeeded"
  case $out in
    *"read the manifest"*) ;;
    *) printf '%s\n' "$out" >&2; fail "under a directory whose $1 ACL lets nobody write, enrol did not make its root" ;;
  esac

  root="$mnt/open/conflux/.conflux"
  setfacl -m "$2" "$root"
  out=$(CONFLUX_DIR="$mnt/open/conflux" "$CONFLUX" status 2>&1) &&
    fail "status of a root whose $1 ACL lets nobody write succeeded"
  case $out in
    *"$root is not as conflux makes"*"its ACL lets uid "*) ;;
    *) printf '%s\n' "$out" >&2; fail "a root whose $1 ACL lets nobody write was not refused for it" ;;
  esac

  setfacl -b "$root"
  out=$(CONFLUX_DIR="$mnt/open/conflux" "$CONFLUX" status 2>&1) || true
  case $out in
    *"its ACL"*) printf '%s\n' "$out" >&2; fail "the $1 ACL taken off, the root is still refused for it" ;;
  esac

  umount "$mnt"
  mdconfig -d -u "$md"
  rmdir "$mnt"
}

if [ "$os" = freebsd ]; then
  say "a root whose POSIX.1e ACL lets another account write is refused, and nothing above it is judged"
  acl_leg acls u:nobody:w
  say "a root whose NFSv4 ACL lets another account write is refused, and nothing above it is judged"
  acl_leg nfsv4acls user:nobody:write_data::allow
fi

# A run cut short leaves its registration behind; a fresh VM has none to remove.
"$CONFLUX" uninstall --yes >/dev/null 2>&1 || true

# An API that accepts and never answers: the base system's nc holds each connection, so an
# enrolment waits out its timeout and anchord stays up while it does.
nc -k -l 127.0.0.1 9443 </dev/null >/dev/null 2>&1 &
silent=$!
trap 'kill "$silent" 2>/dev/null || true' EXIT

say "install registers and starts nothing"
"$CONFLUX" install
[ -x "$script" ] || fail "install wrote no rc script at $script"
if [ "$os" = freebsd ]; then
  [ "$(sysrc -n conflux_enable)" = YES ] || fail "install did not enable the service"
else
  rcctl ls on | grep -qx conflux || fail "install did not enable the service"
  # Where rcctl recorded it, which uninstall's check below reads.
  grep -q conflux /etc/rc.conf.local || fail "rcctl enable wrote nothing of conflux to rc.conf.local"
fi
if pgrep -f 'conflux serve' >/dev/null; then
  fail "install started the service; it must only register"
fi

say "status: registered, nothing to start"
code=0
"$CONFLUX" status || code=$?
[ "$code" = 78 ] || fail "status exited $code with no configuration, want 78"

# configure writes a configuration conflux could have written, with any more fields.
configure() { # MODE [FIELDS]
  extra='"proxies":["8080=127.0.0.1:3000"],'
  [ "$1" = tun ] && extra=''
  (umask 077; printf '%s\n' "{\"version\":1,\"mode\":\"$1\",$extra${2:+$2,}\"taints\":[\"cfx-service-bsd\"],\"apiBaseUrl\":\"https://127.0.0.1:9443\",\"createdAt\":\"2026-01-01T00:00:00Z\",\"updatedAt\":\"2026-01-01T00:00:00Z\"}" \
    > "$state/conflux.json")
}

# started starts the service afresh and waits for the record of what the supervisor
# started anchord as, which it writes once anchord is running.
started() {
  rc stop >/dev/null 2>&1 || true
  rm -f "$priv"
  rc start >/dev/null
  i=0
  while [ "$i" -lt 120 ]; do
    [ -s "$priv" ] && { cat "$priv"; return 0; }
    sleep 0.5
    i=$((i + 1))
  done
  tail -n 30 "$log" >&2 || true
  fail "the supervisor recorded no anchord"
}

say "in userspace anchord runs as $account, with no privilege"
configure proxy
got=$(started)
echo "  anchord: $got"
case $got in
  *'"account":true'*"\"as\":\"$account\""*) ;;
  *) fail "anchord did not run as $account" ;;
esac
id "$account" >/dev/null || fail "no $account account was made"

# The process itself, while the enrolment it waits on holds it up.
i=0
user=""
while [ "$i" -lt 60 ]; do
  # One -o for each column: FreeBSD's ps, as POSIX has it, takes everything after the
  # first = as that column's header, the rest of the list included.
  user=$(ps -ax -o user= -o command= | awk '$2 ~ /\/anchord$/ && $3 == "-socket" { print $1; exit }')
  [ -n "$user" ] && break
  sleep 0.5
  i=$((i + 1))
done
[ "$user" = "$account" ] || fail "the running anchord is ${user:-not there}'s, want $account's"

[ "$(stat -f '%Sp %Su %Sg' "$state")" = "drwx--x--- root $account" ] \
  || fail "the state directory is $(stat -f '%Sp %Su %Sg' "$state"), want root's with $account let through"
[ "$(stat -f '%Su' "$state/anchor")" = "$account" ] || fail "anchord's directory is not $account's"
[ "$(stat -f '%Sp %Su' "$state/run/token")" = "-rw------- root" ] || fail "the token is not root's alone"

# A port below 1024 is root's on both, and a TUN is root's: anchord stays root for each,
# and says why.
say "a port only root may bind keeps anchord root"
configure proxy '"port":80'
got=$(started)
echo "  anchord: $got"
case $got in
  *'"account":false'*'reserved for root'*) ;;
  *) fail "anchord with port 80 is not root, or does not say why" ;;
esac

say "a TUN keeps anchord root"
configure tun
got=$(started)
echo "  anchord: $got"
case $got in
  *'"account":false'*'only root can open a tun'*) ;;
  *) fail "anchord with a TUN is not root, or does not say why" ;;
esac
rc stop >/dev/null 2>&1 || true

# anchor has nothing to capture with here, so conflux refuses the observer before it asks
# for anything, and a configuration asking for one is refused by the supervisor too.
say "observing is refused: there is no capture here"
code=0
out=$("$CONFLUX" observe 2>&1) || code=$?
echo "  $out"
[ "$code" = 2 ] || fail "conflux observe exited $code here, want 2"
case $out in
  *"no capture"*) ;;
  *) fail "conflux observe does not say there is no capture here" ;;
esac
code=0
out=$("$CONFLUX" up --observe --no-ipv4 2>&1) || code=$?
case $out in
  *"no capture"*) ;;
  *) fail "conflux up --observe does not say there is no capture here (exit $code)" ;;
esac

# An ephemeral run killed outright leaves its anchord on the BSDs, where nothing can ask at the
# start for it to end with conflux, and the next ephemeral run stops it. The API answers
# nothing, so anchord is up and the run waits on its enrolment when it is killed.
say "an ephemeral run killed outright: the next one stops the anchord it left"
eroot=$state/ephemeral
eph_start() {
  "$CONFLUX" proxy --ephemeral --api https://127.0.0.1:9443 --no-ipv4 --taint cfx-bsd 8080=127.0.0.1:1 \
    >/tmp/ephemeral.log 2>&1 &
  eph=$!
}
eph_pid() {
  for _ in $(seq 60); do
    if [ -s "$eroot/run/anchord.pid" ]; then head -1 "$eroot/run/anchord.pid"; return 0; fi
    sleep 1
  done
  return 1
}
eph_start
first=$(eph_pid) || { cat /tmp/ephemeral.log >&2; fail "the ephemeral run never recorded its anchord"; }
kill -9 "$eph"
sleep 2
kill -0 "$first" 2>/dev/null || fail "anchord went with the killed run, which nothing on $os arranges"
eph_start
for _ in $(seq 60); do kill -0 "$first" 2>/dev/null || break; sleep 1; done
if kill -0 "$first" 2>/dev/null; then
  cat /tmp/ephemeral.log >&2
  fail "the next ephemeral run did not stop the anchord a killed one left"
fi
kill -INT "$eph"
wait "$eph" 2>/dev/null || true
for _ in $(seq 20); do [ ! -e "$eroot" ] && break; sleep 1; done
[ ! -e "$eroot" ] || fail "the ephemeral run left $eroot behind"
eaccount=$(printf '%s' "$account" | sed 's/conflux$/conflux-ephemeral/')
id "$eaccount" >/dev/null 2>&1 || fail "no $eaccount account was made for the ephemeral run"

say "uninstall leaves nothing"
"$CONFLUX" uninstall --yes
[ ! -e "$script" ] || fail "the rc script survived uninstall"
[ ! -e "$state" ] || fail "$state survived uninstall"
if id "$eaccount" >/dev/null 2>&1; then
  fail "the $eaccount account survived uninstall"
fi
if id "$account" >/dev/null 2>&1; then
  fail "the $account account survived uninstall"
fi
# Uninstall disables the service, and on FreeBSD removes the log conflux writes itself, with its root,
# ignoring what either says, so their outcome is read here. OpenBSD's rcctl lists only services
# whose script is in /etc/rc.d, which uninstall has removed, so a disable that failed shows in
# rc.conf.local alone.
if [ "$os" = freebsd ]; then
  if sysrc -n conflux_enable >/dev/null 2>&1; then
    fail "conflux_enable survived uninstall in rc.conf"
  fi
  [ ! -e "$log" ] || fail "$log survived uninstall"
else
  if [ -e /etc/rc.conf.local ] && grep -q conflux /etc/rc.conf.local; then
    fail "rc.conf.local still enables conflux after uninstall: $(grep conflux /etc/rc.conf.local)"
  fi
fi

say "all assertions passed"
