#!/usr/bin/env bash
# The boot service on macOS and Windows, against the real service manager.
#
#   test/service-host.sh CONFLUX     (as root on macOS; as Administrator on Windows)
#
# What test/service.sh is for systemd: install registers and starts nothing, status and
# down answer for a registered service with nothing to run, a userspace anchord runs as
# an account of its own -- _conflux on macOS, LOCAL SERVICE on Windows -- an observing one
# captures as that account, given only what the capture needs, and uninstall leaves nothing
# behind: launchd's disabled database, the SCM's entry, the account and the BPF devices'
# access included. Nothing is enrolled -- the configuration names an API that answers nothing --
# so it needs no API and no anchor, and takes seconds. It runs on the machine itself,
# which is why it is for a CI runner that is thrown away afterwards.
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

if [ "$os" = darwin ]; then
  root="/Library/Application Support/conflux"
else
  # Git Bash imports Windows's variables upper-cased; the fallback is Windows's default.
  root="$(cygpath -u "${PROGRAMDATA:-C:\\ProgramData}")/conflux"
fi

# A configuration conflux could have written, with an API that answers nothing: the
# supervisor starts anchord, records what it started it as, and retries the enrolment.
# The record is read rather than the process, which lives only as long as a try.
say "in userspace anchord runs as an account of its own"
(umask 077; printf '%s\n' '{"version":1,"mode":"proxy","proxies":["8080=127.0.0.1:3000"],"taints":["cfx-service-host"],"apiBaseUrl":"https://192.0.2.1:9","createdAt":"2026-01-01T00:00:00Z","updatedAt":"2026-01-01T00:00:00Z"}' > "$root/conflux.json")
if [ "$os" = darwin ]; then
  launchctl bootstrap system "/Library/LaunchDaemons/$LABEL.plist"
  account='"as":"_conflux"'
  who='starting anchord as _conflux, with no privilege'
  log=/var/log/conflux.log
else
  sc.exe start conflux >/dev/null
  account='LOCAL SERVICE'
  who='starting anchord as NT AUTHORITY\LOCAL SERVICE, with no privilege'
  log="$root/logs/conflux.log"
fi
priv=""
for _ in $(seq 120); do
  priv=$(cat "$root/anchord.priv" 2>/dev/null || true)
  [ -n "$priv" ] && break
  sleep 0.5
done
echo "  anchord: $priv"
case $priv in
  *'"account":true'*"$account"*) ;;
  *) fail "anchord did not run as its own account: ${priv:-nothing was recorded}" ;;
esac

# The record says what anchord was started as. The supervisor enrols only once anchord has
# answered an authenticated call on the socket it made, so "enrolling" after that start is
# anchord serving as its own account, not merely started as it.
for _ in $(seq 120); do
  grep -q 'enrolling' "$log" 2>/dev/null && break
  sleep 0.5
done
grep -F "$who" "$log" >/dev/null || { cat "$log" >&2; fail "the log does not say anchord started as its own account"; }
grep -q 'enrolling' "$log" || { cat "$log" >&2; fail "anchord never answered on its socket as its own account"; }
"$CONFLUX" down || fail "down failed on a running service"

# Observing alone needs no API, so this one comes all the way up: start waits for the
# observer as it waits for an anchor. As its own account, with the capture and nothing else:
# on macOS the BPF devices given to its group by the supervisor, on Windows LOCAL SERVICE's
# own leave to start the trace session.
say "observing alone, anchord captures as its own account"
(umask 077; printf '%s\n' '{"version":1,"mode":"observe","observer":{},"createdAt":"2026-01-01T00:00:00Z","updatedAt":"2026-01-01T00:00:00Z"}' > "$root/conflux.json")
if [ "$os" = darwin ]; then
  capture=bpf
  who='_conflux, with read access to /dev/bpf*, for the observer'
else
  capture=etw
  who='NT AUTHORITY\LOCAL SERVICE, with no privilege'
fi
"$CONFLUX" start || { cat "$log" >&2; fail "the observer did not come up"; }
out=$("$CONFLUX" status)
printf '%s\n' "$out"
case $out in
  *"observer     $capture,"*) ;;
  *) cat "$log" >&2; fail "status does not show the observer capturing with $capture" ;;
esac
case $out in
  *"anchord      $who"*) ;;
  *) fail "anchord does not observe as its own account with only the capture" ;;
esac
[ ! -e "$root/manifest.b64" ] || fail "observing alone enrolled"
if [ "$os" = darwin ]; then
  bpf=$(stat -f '%Sg %Sp' /dev/bpf0)
  [ "$bpf" = "_conflux crw-r-----" ] || fail "/dev/bpf0 is $bpf while _conflux observes, want _conflux crw-r-----"
fi
"$CONFLUX" down || fail "down failed on an observing service"

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
  if dscl . -read /Users/_conflux >/dev/null 2>&1; then
    fail "the _conflux account survived uninstall"
  fi
  bpf=$(stat -f '%Sg %Sp' /dev/bpf0)
  [ "$bpf" = "wheel crw-------" ] || fail "/dev/bpf0 is $bpf after uninstall, want root's alone: wheel crw-------"
  for d in /dev/bpf*; do
    [ "$(stat -f '%Sg' "$d")" = wheel ] || fail "$d is still $(stat -f '%Sg' "$d")'s after uninstall"
  done
else
  if sc.exe query conflux >/dev/null 2>&1; then
    fail "the service survived uninstall"
  fi
  [ ! -e "$root" ] || fail "$root survived uninstall"
fi

say "all assertions passed"
