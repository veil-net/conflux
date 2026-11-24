#!/bin/sh
# Say whether a conflux build runs in FIPS 140-3 mode against the Go Cryptographic Module it is
# built with, asking nothing but the build itself: no Go.
#
#   scripts/fips-check.sh EXE
#
# Three answers, each read whole before it is searched: `version` names the module, the module's
# integrity check passes as it starts (GODEBUG=fips140=debug says so), and with the mode switched
# off it refuses, exit 70, rather than run without it. The module is $GOFIPS140, which make
# exports, else the Makefile's own line, the one place it is named: a VM handed the tree runs
# this with no make. Run by make buildcheck, after its digest check, on the build make made for
# this machine, and by test/service-bsd.sh on FreeBSD's, in a VM with no Go. Not for OpenBSD's
# build, which carries no module. POSIX sh.
set -eu

exe=${1:?usage: scripts/fips-check.sh EXE}
module=${GOFIPS140:-$(sed -n 's/^GOFIPS140 ?= *\([^[:space:]]*\).*/\1/p' "$(dirname "$0")/../Makefile")}

fail() { echo "  FAIL $*"; exit 1; }

case $module in
  '' | off) fail "there is no Go Cryptographic Module to hold $exe to (GOFIPS140 is ${module:-unset})" ;;
esac

v=$("$exe" version 2>&1) || fail "$exe version failed:
$v"
printf '%s\n' "$v" | grep -qxF "fips140 on, Go Cryptographic Module $module" ||
  fail "$exe does not say it runs in FIPS 140-3 mode against Go Cryptographic Module $module:
$v"

d=$(GODEBUG=fips140=debug "$exe" version 2>&1) || fail "$exe version failed under GODEBUG=fips140=debug:
$d"
printf '%s\n' "$d" | grep -q '^fips140: verified' || fail "the module's integrity check did not say it verified:
$d"

rc=0
GODEBUG=fips140=off "$exe" version >/dev/null 2>&1 || rc=$?
[ "$rc" = 70 ] || fail "with GODEBUG=fips140=off $exe exited $rc, not 70"

echo "  ok   $exe runs in FIPS 140-3 mode against Go Cryptographic Module $module, its integrity check verified, and exits 70 with the mode off"
