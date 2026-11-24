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
# access included. The configurations name an API that answers nothing, but for the observing
# leg's: the observer runs only under a credential, so that leg enrols one anonymous alpha
# credential at $VEILNET_API, in a random taint, and nothing else is enrolled. It needs no
# anchor, and takes seconds. It runs on the machine itself, which is why it is for a CI runner
# that is thrown away afterwards.
#
# bash 3.2, which is what a Mac has, and Git Bash on Windows.
set -euo pipefail

# Nothing here pipes a command into grep -q: grep stops at its first match, the command still
# writing is then ended by SIGPIPE, and under pipefail that fails the line however right its
# output was. Each answer is read whole, then searched (grep -q PATTERN <<<"$(COMMAND)").

CONFLUX=${1:?usage: test/service-host.sh CONFLUX}

say() { printf '\n== %s\n' "$*"; }
fail() { echo "$*" >&2; exit 1; }

case "$(uname -s)" in
  Darwin) os=darwin ;;
  MINGW* | MSYS* | CYGWIN*) os=windows ;;
  *) fail "service-host.sh is for macOS and Windows; systemd has test/service.sh" ;;
esac

LABEL=org.veilnet.conflux

# The API the observing leg enrols its one anonymous alpha credential at: the tree the embedded
# anchord is pinned to, which CI names by the pull request's base.
API=${VEILNET_API:-https://api.veilnet.com.au}

# logs prints what the service wrote to the system's log: the unified log, which a logger(1)
# the supervisor started fills on macOS, and the Application event log, under conflux's own
# source, on Windows.
logs() {
  if [ "$os" = darwin ]; then
    log show --last 15m --style compact --predicate 'process == "logger"' 2>/dev/null
  else
    powershell.exe -NoProfile -Command "Get-WinEvent -FilterHashtable @{LogName='Application'; ProviderName='conflux'} -MaxEvents 500 -ErrorAction SilentlyContinue | Sort-Object TimeCreated | ForEach-Object { \$_.Message }" 2>/dev/null
  fi
}

# A run cut short leaves its registration behind; a fresh runner has none to remove.
"$CONFLUX" uninstall --yes >/dev/null 2>&1 || true

# Run from where the installer puts it, and on Windows on the machine's Path as install.ps1
# puts it, so that uninstall's removal of both is seen below.
if [ "$os" = darwin ]; then
  installed=/usr/local/bin/conflux
else
  installed="$(cygpath -u "${PROGRAMFILES:-C:\\Program Files}")/conflux/conflux.exe"
fi
mkdir -p "$(dirname "$installed")"
cp "$CONFLUX" "$installed"
CONFLUX=$installed
if [ "$os" = windows ]; then
  # shellcheck disable=SC2016 # PowerShell's variables, for PowerShell to expand
  powershell.exe -NoProfile -Command '$d = Join-Path $env:ProgramFiles conflux; $p = [Environment]::GetEnvironmentVariable("Path", "Machine"); if (($p -split ";") -notcontains $d) { [Environment]::SetEnvironmentVariable("Path", "$p;$d", "Machine") }'
fi

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
  # Its own SID, and nobody but SYSTEM and the Administrators allowed to start, stop or change it.
  grep -q 'UNRESTRICTED' <<<"$(sc.exe qsidtype conflux)" || { sc.exe qsidtype conflux >&2; fail "the service has no SID of its own"; }
  # The DACL alone: sdshow prints the SACL after it, the SCM's default audit entry, which
  # conflux sets no part of.
  sd=$(sc.exe sdshow conflux | tr -d '\r\n ')
  dacl=${sd%%S:*}
  [ "$dacl" = 'D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)' ] \
    || fail "the service's DACL is $dacl (of $sd)"
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
  root="/Library/Application Support/.conflux"
else
  # Git Bash imports Windows's variables upper-cased; the fallback is Windows's default.
  root="$(cygpath -u "${PROGRAMDATA:-C:\\ProgramData}")/.conflux"
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
else
  sc.exe start conflux >/dev/null
  account='LOCAL SERVICE'
  who='starting anchord as NT AUTHORITY\LOCAL SERVICE, with no privilege'
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
  grep -q 'enrolling' <<<"$(logs)" && break
  sleep 0.5
done
grep -qF "$who" <<<"$(logs)" || { logs >&2; fail "the system log does not say anchord started as its own account"; }
grep -q 'enrolling' <<<"$(logs)" || { logs >&2; fail "anchord never answered on its socket as its own account"; }
"$CONFLUX" down || fail "down failed on a running service"

# Observing alone comes all the way up, under the credential the observer runs as: one
# anonymous alpha enrolment in a random taint at the API the embedded anchord is pinned to,
# and start waits for the observer as it waits for an anchor. As its own account, with the
# capture and nothing else: on macOS the BPF devices given to its group by the supervisor, on
# Windows LOCAL SERVICE's own leave to start the trace session.
say "observing alone, anchord captures as its own account"
taint=cfx-host-$(head -c6 /dev/urandom | od -An -tx1 | tr -d ' \n')
(umask 077; printf '{"version":1,"mode":"observe","observer":{},"taints":["%s"],"apiBaseUrl":"%s","createdAt":"2026-01-01T00:00:00Z","updatedAt":"2026-01-01T00:00:00Z"}\n' "$taint" "$API" > "$root/conflux.json")
if [ "$os" = darwin ]; then
  capture=bpf
  who='_conflux, with read access to /dev/bpf*, for the observer'
else
  capture=etw
  who='NT AUTHORITY\LOCAL SERVICE, with no privilege'
fi
"$CONFLUX" start || { logs >&2; fail "the observer did not come up"; }
out=$("$CONFLUX" status)
printf '%s\n' "$out"
case $out in
  *"observer     $capture,"*) ;;
  *) logs >&2; fail "status does not show the observer capturing with $capture" ;;
esac
case $out in
  *"anchord      $who"*) ;;
  *) fail "anchord does not observe as its own account with only the capture" ;;
esac
[ -s "$root/manifest.b64" ] || fail "the observer is capturing, and there is no credential it runs under"
if [ "$os" = darwin ]; then
  bpf=$(stat -f '%Sg %Sp' /dev/bpf0)
  [ "$bpf" = "_conflux crw-r-----" ] || fail "/dev/bpf0 is $bpf while _conflux observes, want _conflux crw-r-----"
fi
"$CONFLUX" down || fail "down failed on an observing service"

# An ephemeral run killed outright: on Windows its anchord goes with it, in its job; on macOS
# nothing can ask at the start, so it is left, and the next ephemeral run stops it. The API
# answers nothing, so anchord is up and the run waits on its enrolment when it is killed.
say "an ephemeral run killed outright, and what becomes of its anchord"
if [ "$os" = darwin ]; then
  eroot=/var/run/conflux-ephemeral
else
  # The running account's temporary directory, as Windows gives it to conflux.
  eroot="$(cygpath -u "$(powershell.exe -NoProfile -Command '[IO.Path]::GetTempPath()' | tr -d '\r')")/conflux-ephemeral"
fi
eph_start() { # LOG
  "$CONFLUX" proxy --ephemeral --api https://192.0.2.1:9 --no-ipv4 --taint cfx-host 8080=127.0.0.1:1 >"$1" 2>&1 &
}
eph_pid() { # waits for the run's anchord to be recorded, and prints its pid
  for _ in $(seq 60); do
    if [ -s "$eroot/run/anchord.pid" ]; then head -1 "$eroot/run/anchord.pid" | tr -d '\r'; return 0; fi
    sleep 1
  done
  return 1
}
alive() { # PID
  if [ "$os" = darwin ]; then kill -0 "$1" 2>/dev/null; else grep -qi anchord <<<"$(tasklist //FI "PID eq $1" 2>/dev/null)"; fi
}
elog=$(mktemp)
eph_start "$elog"
first=$(eph_pid) || { cat "$elog" >&2; fail "the ephemeral run never recorded its anchord"; }
if [ "$os" = darwin ]; then
  kill -9 $!
  sleep 2
  alive "$first" || fail "anchord went with the killed run on macOS, which nothing there arranges"
  eph_start "$elog"
  for _ in $(seq 60); do alive "$first" || break; sleep 1; done
  alive "$first" && { cat "$elog" >&2; fail "the next ephemeral run did not stop the anchord a killed one left"; }
  second=$(eph_pid) || { cat "$elog" >&2; fail "the next ephemeral run never recorded its anchord"; }
  [ "$second" != "$first" ] || fail "the next run reports the killed one's anchord as its own"
  kill -INT $!
  wait $! 2>/dev/null || true
else
  taskkill //F //IM conflux.exe >/dev/null
  for _ in $(seq 20); do alive "$first" || break; sleep 1; done
  alive "$first" && fail "anchord outlived the ephemeral run that was killed; its job should have ended it"
  wait 2>/dev/null || true
fi
rm -f "$elog"
# A run stopped with Ctrl-C removes its root; a killed one leaves it to the next run, or to
# uninstall, which must remove it below.
if [ "$os" = darwin ]; then
  [ ! -e "$eroot" ] || fail "the ephemeral run stopped with Ctrl-C left $eroot behind"
else
  [ -e "$eroot" ] || fail "the killed ephemeral run left no root, so uninstall's removal of one goes untested"
fi

say "uninstall leaves nothing"
"$CONFLUX" uninstall --yes

if [ "$os" = darwin ]; then
  [ ! -e "/Library/LaunchDaemons/$LABEL.plist" ] || fail "the plist survived uninstall"
  if launchctl print-disabled system | grep -F "\"$LABEL\"" >/dev/null; then
    launchctl print-disabled system | grep -F "\"$LABEL\"" >&2
    fail "uninstall left the label in launchd's disabled database"
  fi
  [ ! -e "$root" ] || fail "$root survived uninstall"
  if dscl . -read /Users/_conflux >/dev/null 2>&1; then
    fail "the _conflux account survived uninstall"
  fi
  if dscl . -read /Users/_conflux-ephemeral >/dev/null 2>&1; then
    fail "the _conflux-ephemeral account survived uninstall"
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
  if reg.exe query 'HKLM\SYSTEM\CurrentControlSet\Services\EventLog\Application\conflux' >/dev/null 2>&1; then
    fail "the service's event source survived uninstall"
  fi
  [ ! -e "$root" ] || fail "$root survived uninstall"
  # A running executable cannot delete itself, so its directory goes a few seconds after
  # uninstall has exited.
  dir=$(dirname "$CONFLUX")
  for _ in $(seq 30); do [ -e "$dir" ] || break; sleep 1; done
  [ ! -e "$dir" ] || fail "$dir, where conflux was installed, survived uninstall"
  # shellcheck disable=SC2016 # PowerShell's variables, for PowerShell to expand
  powershell.exe -NoProfile -Command '$d = Join-Path $env:ProgramFiles conflux; if (([Environment]::GetEnvironmentVariable("Path", "Machine") -split ";") -contains $d) { exit 1 }' \
    || fail "uninstall left conflux's directory on the machine's Path"
fi
[ ! -e "$CONFLUX" ] || fail "$CONFLUX, the installed executable, survived uninstall"
[ ! -e "$eroot" ] || fail "$eroot, a killed ephemeral run's root, survived uninstall"

say "all assertions passed"
