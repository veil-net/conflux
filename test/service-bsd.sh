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

case "$(uname -s)" in
  FreeBSD) os=freebsd account=conflux script=/usr/local/etc/rc.d/conflux log=/var/log/conflux.log ;;
  OpenBSD) os=openbsd account=_conflux script=/etc/rc.d/conflux log=/var/log/daemon ;;
  *) fail "service-bsd.sh is for FreeBSD and OpenBSD" ;;
esac

state=/var/db/conflux
priv=$state/anchord.priv

rc() { # VERB
  if [ "$os" = freebsd ]; then service conflux "$1"; else rcctl "$1" conflux; fi
}

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
    > /usr/local/etc/conflux/conflux.json)
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
  user=$(ps -axo user=,command= | awk '$2 ~ /\/anchord$/ && $3 == "-socket" { print $1; exit }')
  [ -n "$user" ] && break
  sleep 0.5
  i=$((i + 1))
done
[ "$user" = "$account" ] || fail "the running anchord is ${user:-not there}'s, want $account's"

[ "$(stat -f '%Sp %Su %Sg' "$state")" = "drwx--x--- root $account" ] \
  || fail "the state directory is $(stat -f '%Sp %Su %Sg' "$state"), want root's with $account let through"
[ "$(stat -f '%Su' "$state/anchor")" = "$account" ] || fail "anchord's directory is not $account's"
[ "$(stat -f '%Sp %Su' /var/run/conflux/token)" = "-rw------- root" ] || fail "the token is not root's alone"

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

say "uninstall leaves nothing"
"$CONFLUX" uninstall --yes
[ ! -e "$script" ] || fail "the rc script survived uninstall"
for path in /usr/local/etc/conflux "$state" /var/run/conflux; do
  [ ! -e "$path" ] || fail "$path survived uninstall"
done
if id "$account" >/dev/null 2>&1; then
  fail "the $account account survived uninstall"
fi

say "all assertions passed"
