//go:build !windows

package service

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// onPath puts commands of the test's own, each a name and its script, in a directory that is
// all of PATH, so the machine's own are never asked: the BSDs' sysrc and rcctl here, and
// systemd's systemctl in service_linux_test.go.
func onPath(t *testing.T, commands map[string]string) {
	t.Helper()

	bin := t.TempDir()

	for name, script := range commands {
		if err := os.WriteFile(filepath.Join(bin, name), []byte(script), 0o755); err != nil {
			t.Fatal(err)
		}
	}

	t.Setenv("PATH", bin)
}

// rcCommands are a sysrc and an rcctl of the tests' own, which keep the line in the file $RC_LINE
// names, a line being a file that is not empty. $RC_REFUSE makes the command refuse, saying it,
// and $RC_KEEP makes it succeed with the line kept, as one set somewhere it does not look would
// be. rcctl answers a get for a service whose script, $RC_SCRIPT, is not there as rcctl(8) does,
// "does not exist" and exit 2, and disables one whatever its script. Shell builtins alone, so
// PATH needs nothing else.
var rcCommands = map[string]string{
	"sysrc": `#!/bin/sh
[ "$2" = conflux_enable ] || { echo "unexpected: sysrc $*" >&2; exit 2; }
case "$1" in
-x)
  [ -s "$RC_LINE" ] || { echo "sysrc: unknown variable '$2'" >&2; exit 1; }
  [ -z "$RC_REFUSE" ] || { echo "sysrc: $RC_REFUSE" >&2; exit 1; }
  [ -n "$RC_KEEP" ] || : > "$RC_LINE" ;;
-n)
  [ -s "$RC_LINE" ] || { echo "sysrc: unknown variable '$2'" >&2; exit 1; }
  read -r v < "$RC_LINE"; echo "$v" ;;
*) echo "unexpected: sysrc $*" >&2; exit 2 ;;
esac
`,
	"rcctl": `#!/bin/sh
case "$*" in
"disable conflux")
  [ -z "$RC_REFUSE" ] || { echo "rcctl: $RC_REFUSE" >&2; exit 1; }
  [ -n "$RC_KEEP" ] || : > "$RC_LINE" ;;
"get conflux status")
  [ -x "$RC_SCRIPT" ] || { echo "rcctl: service conflux does not exist" >&2; exit 2; }
  [ -s "$RC_LINE" ] ;;
*) echo "unexpected: rcctl $*" >&2; exit 2 ;;
esac
`,
}

// rcRefusal is what the stand-ins say when $RC_REFUSE makes them refuse.
const rcRefusal = "/etc/rc.conf: Read-only file system"

// bsds are FreeBSD's and OpenBSD's way of enabling conflux at boot, with what an error about a
// line left must say.
var bsds = []struct {
	name  string
	e     rcEnabled
	names []string
}{
	{"FreeBSD", freebsdEnabled, []string{"rc.conf", "conflux_enable"}},
	{"OpenBSD", openbsdEnabled, []string{"rc.conf.local", "enables conflux"}},
}

// rcMachine is a machine for the stand-ins: the line set or not, the script there or not, and
// $RC_REFUSE and $RC_KEEP as given. It returns the line's file and the script's path.
func rcMachine(t *testing.T, set, script bool, refuse, keep string) (string, string) {
	t.Helper()

	dir := t.TempDir()
	line, path := filepath.Join(dir, "line"), filepath.Join(dir, rcName)

	var held []byte
	if set {
		held = []byte("YES\n")
	}

	if err := os.WriteFile(line, held, 0o644); err != nil {
		t.Fatal(err)
	}

	if script {
		if err := os.WriteFile(path, []byte("#!/bin/ksh\n"), 0o555); err != nil {
			t.Fatal(err)
		}
	}

	t.Setenv("RC_LINE", line)
	t.Setenv("RC_SCRIPT", path)
	t.Setenv("RC_REFUSE", refuse)
	t.Setenv("RC_KEEP", keep)

	return line, path
}

// present reports whether a file is at path, failing the test where that cannot be told.
func present(t *testing.T, path string) bool {
	t.Helper()

	ok, err := exists(path)
	if err != nil {
		t.Fatal(err)
	}

	return ok
}

// saysTheLine fails the test unless err says the line left, naming it, and, where refused, what
// the command said.
func saysTheLine(t *testing.T, err error, names []string, refused bool) {
	t.Helper()

	if err == nil {
		t.Fatal("remove = nil; want the line left said")
	}

	for _, want := range names {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("remove = %v; want it to name %q", err, want)
		}
	}

	if refused && !strings.Contains(err.Error(), rcRefusal) {
		t.Errorf("remove = %v; want what the command said, %q, said with it", err, rcRefusal)
	}

	if strings.Contains(err.Error(), "%!") {
		t.Errorf("remove = %v; a nil error was formatted into it", err)
	}
}

// TestRCRemoveSaysALineLeft: FreeBSD's and OpenBSD's Remove take conflux's line out of the
// administrator's rc configuration (sysrc -x, rcctl disable), and a line still there after is
// said, whatever the command answered, as systemd's Remove says a file it could not remove: it is
// conflux, left on the machine. What the command said is forgiven once the line is gone, sysrc's
// refusal of a variable that was never set among it. The script goes only with the line. Where
// the question cannot be answered -- rcctl knows no service whose script is gone -- the command's
// own answer stands: a refusal is said, and a line it took out, or none there, is gone.
func TestRCRemoveSaysALineLeft(t *testing.T) {
	onPath(t, rcCommands)

	for _, bsd := range bsds {
		for _, c := range []struct {
			name           string
			set, script    bool   // the line is there before, and the script
			refuse, keep   string // $RC_REFUSE and $RC_KEEP
			left           bool   // an error is wanted, naming the line
			saysTheRefusal bool   // and saying what the command said
		}{
			{"taken out", true, true, "", "", false, false},
			{"never there", false, true, "", "", false, false},
			{"refused and left", true, true, rcRefusal, "", true, true},
			{"left without a word", true, true, "", "yes", true, false},
			{"nothing installed", false, false, "", "", false, false},
			{"refused, the script gone", true, false, rcRefusal, "", true, true},
		} {
			t.Run(bsd.name+", "+c.name, func(t *testing.T) {
				line, script := rcMachine(t, c.set, c.script, c.refuse, c.keep)

				err := bsd.e.remove(script)

				if !c.left {
					if err != nil {
						t.Errorf("remove = %v; want nil, the line gone", err)
					}

					if fileSize(t, line) != 0 {
						t.Error("the line is still there")
					}

					if present(t, script) {
						t.Error("the script is still there, with the line gone")
					}

					return
				}

				saysTheLine(t, err, bsd.names, c.saysTheRefusal)

				if c.script && !present(t, script) {
					t.Error("the script went, with the line left")
				}
			})
		}
	}
}

// TestRCRemoveKeepsTheScriptWhileTheLineIsLeft: a line left keeps the script, so the next
// uninstall can ask again whether the line is there -- rcctl answers nothing for a service whose
// script is gone, and once it was taken for a no, that uninstall said nothing was left while the
// line was -- and the script goes once a remove has taken the line out.
func TestRCRemoveKeepsTheScriptWhileTheLineIsLeft(t *testing.T) {
	onPath(t, rcCommands)

	for _, bsd := range bsds {
		t.Run(bsd.name, func(t *testing.T) {
			line, script := rcMachine(t, true, true, rcRefusal, "")

			for _, try := range []string{"the first remove", "a second, still refused"} {
				saysTheLine(t, bsd.e.remove(script), bsd.names, true)

				if !present(t, script) {
					t.Errorf("%s took the script, with the line left", try)
				}
			}

			t.Setenv("RC_REFUSE", "")

			if err := bsd.e.remove(script); err != nil {
				t.Errorf("a remove that takes the line out = %v; want nil", err)
			}

			if fileSize(t, line) != 0 {
				t.Error("the line is still there")
			}

			if present(t, script) {
				t.Error("the script is still there, with the line gone")
			}
		})
	}
}

// fileSize is the size of the file at path.
func fileSize(t *testing.T, path string) int64 {
	t.Helper()

	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}

	return fi.Size()
}
