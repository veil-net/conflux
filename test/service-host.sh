#!/usr/bin/env bash
# The boot service on macOS and Windows, against the real service manager.
#
#   test/service-host.sh CONFLUX     (as root on macOS; as Administrator on Windows)
#
# What test/service.sh is for systemd: install registers and starts nothing, status and
# down answer for a registered service with nothing to run, and uninstall leaves nothing
# behind -- launchd's disabled database and the SCM's entry included. Nothing is enrolled
# and nothing is started, so it needs no API and no anchor, and takes seconds. It runs on
# the machine itself, which is why it is for a CI runner that is thrown away afterwards.
#
# bash 3.2, which is what a Mac has, and Git Bash on Windows.
set -euo pipefail

CONFLUX=${1:?usage: test/service-host.sh CONFLUX}

say() { printf '\n== %s\n' "$*"; }
fail() { echo "$*" >&2; exit 1; }

case "$(uname -s)" in
  Darwin) os=darwin ;;
  MINGW* | MSYS* | CYGWIN*) os=windows ;;
  *) fail "service-host.sh is for macOS and Windows; systemd has test/service.sh" ;;
esac

LABEL=org.veilnet.conflux

# A run cut short leaves its registration behind; a fresh runner has none to remove.
"$CONFLUX" uninstall --yes >/dev/null 2>&1 || true

say "install registers and starts nothing"
"$CONFLUX" install

if [ "$os" = darwin ]; then
  [ -f "/Library/LaunchDaemons/$LABEL.plist" ] || fail "install wrote no plist"
  if launchctl print "system/$LABEL" >/dev/null 2>&1; then
    fail "install loaded the job, which starts it"
  fi
else
  sc.exe query conflux | grep STOPPED >/dev/null || { sc.exe query conflux >&2; fail "the service is not registered and stopped"; }
  # Restarted when it stops with an error as well as when it dies: the supervisor's exit 1.
  sc.exe qfailureflag conflux | grep 'NONCRASH_FAILURES *: *TRUE' >/dev/null \
    || { sc.exe qfailureflag conflux >&2; fail "recovery does not cover a service that stops with an error"; }
  [ "$(sc.exe qfailure conflux | grep -c RESTART)" -ge 3 ] \
    || { sc.exe qfailure conflux >&2; fail "the recovery actions are not the three restarts"; }
fi

say "status: registered, nothing to start"
code=0
out=$("$CONFLUX" status 2>&1) || code=$?
printf '%s\n' "$out"
[ "$code" = 78 ] || fail "status exited $code with no configuration, want 78"
case "$out" in
  *"installed, not running"*) ;;
  *) fail "status does not say the service is installed and not running" ;;
esac

say "down on a service that is not running"
"$CONFLUX" down || fail "down failed on a service that was not running"

say "uninstall leaves nothing"
"$CONFLUX" uninstall --yes

if [ "$os" = darwin ]; then
  [ ! -e "/Library/LaunchDaemons/$LABEL.plist" ] || fail "the plist survived uninstall"
  if launchctl print-disabled system | grep -F "\"$LABEL\"" >/dev/null; then
    launchctl print-disabled system | grep -F "\"$LABEL\"" >&2
    fail "uninstall left the label in launchd's disabled database"
  fi
  for path in "/Library/Application Support/conflux" /var/run/conflux /var/log/conflux.log; do
    [ ! -e "$path" ] || fail "$path survived uninstall"
  done
else
  if sc.exe query conflux >/dev/null 2>&1; then
    fail "the service survived uninstall"
  fi
  root="$(cygpath -u "$PROGRAMDATA")/conflux"
  [ ! -e "$root" ] || fail "$root survived uninstall"
fi

say "all assertions passed"
