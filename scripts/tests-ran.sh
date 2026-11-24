#!/usr/bin/env bash
#
# Say whether every test the source declares for this platform ran, by name, in a go test -v log.
#
#   ./scripts/tests-ran.sh LOG OUTCOME...      e.g. test.log PASS, or test.log PASS SKIP
#
# Run by CI after the suite, from the module's root, on the platform the log is from: a test that
# never runs is green, and so is a package whose tests stop running, a TestMain that returns before
# m.Run among them. So the tests that ran are held to the tests there are, read from the source:
# every top-level `func TestXxx(... *testing.T)` in the test files go list says each package's
# tests are built from here. Not from `go test -list`, which asks the same test binaries, and which
# the same TestMain hides them from. A file its build constraints leave out of this platform is
# not expected here (`make cross` vets it on each platform); benchmarks, examples and fuzz targets
# are outside it.
#
# Each must have ended once with one of the OUTCOMEs, found wherever a line holds it, since a
# test's own output may end without a newline; a subtest's name holds a slash, and is not counted.
# A mismatch prints the diff of the two lists. Bash 3.2, as macOS has it.
set -euo pipefail

usage='usage: scripts/tests-ran.sh LOG OUTCOME...'
log=${1:?$usage}
shift
[ $# -gt 0 ] || { echo "$usage" >&2; exit 2; }
outcomes=$(IFS='|'; echo "$*")
said=$(IFS=/; echo "$*")

die() { echo "::error::tests-ran: $*" >&2; exit 1; }

[ -r "$log" ] || die "there is no test log at $log"

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

# Each package's test files, one path a line. go list writes a directory with this platform's
# separator, a backslash on Windows, where Git Bash's tools read the path written with slashes.
# shellcheck disable=SC1003 # tr's escaped backslash, not a quote
go list -f '{{range .TestGoFiles}}{{$.Dir}}/{{.}}{{"\n"}}{{end}}{{range .XTestGoFiles}}{{$.Dir}}/{{.}}{{"\n"}}{{end}}' ./... |
  tr '\\' / > "$work/files"
[ -s "$work/files" ] || die "go list names no test files here"

# Read by awk, a file at a time, so no argument list is too long for Windows. A test is Test alone,
# or Test and a name whose first letter is not lower case, taking one *testing.T: what go test runs.
# A line may end in a carriage return, from a checkout that wrote CRLF, so its end is not anchored.
awk '{
  file = $0
  while ((r = (getline line < file)) > 0) {
    if (line ~ /^func Test[^(]*\(([A-Za-z_][A-Za-z0-9_]* +)?\*testing\.T\)/) {
      name = substr(line, 6)
      sub(/\(.*/, "", name)
      if (name == "Test" || substr(name, 5, 1) !~ /[a-z]/) print name
    }
  }
  if (r < 0) { print "tests-ran: cannot read " file > "/dev/stderr"; exit 1 }
  close(file)
}' "$work/files" | LC_ALL=C sort > "$work/declared"
[ -s "$work/declared" ] || die "the test files go list names declare no test"

{ grep -oE -- "--- ($outcomes): Test[^ /]* \(" "$log" || true; } |
  sed -E "s/^--- ($outcomes): //; s/ \($//" | LC_ALL=C sort > "$work/ran"

declared=$(($(wc -l < "$work/declared")))
ran=$(($(wc -l < "$work/ran")))
if ! diff "$work/declared" "$work/ran" >&2; then
  die "$ran tests ended $said of the $declared the source declares here (< declared, not $said; > $said, not declared)"
fi
echo "$ran tests ended $said: every one the source declares here"
