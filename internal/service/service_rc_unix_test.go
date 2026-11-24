//go:build !windows

package service

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestRCRemoveSaysALineLeft: FreeBSD's and OpenBSD's Remove take conflux's line out of the
// administrator's rc configuration (sysrc -x, rcctl disable), and a line still there after is
// said, whatever the command answered, as systemd's Remove says a file it could not remove: it is
// conflux, left on the machine. What the command said is forgiven once the line is gone, sysrc's
// refusal of a variable that was never set among it.
func TestRCRemoveSaysALineLeft(t *testing.T) {
	// A sysrc and an rcctl of the test's own, found first on PATH, which keep the line in the file
	// $RC_LINE names, a line being a file that is not empty. $RC_REFUSE makes the command refuse,
	// saying it, and $RC_KEEP makes it succeed with the line kept, as one set somewhere it does
	// not look would be. Shell builtins alone, so PATH holds nothing else and the machine's are
	// never asked.
	stubs := map[string]string{
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
"get conflux status") [ -s "$RC_LINE" ] ;;
*) echo "unexpected: rcctl $*" >&2; exit 2 ;;
esac
`,
	}

	bin := t.TempDir()

	for name, stub := range stubs {
		if err := os.WriteFile(filepath.Join(bin, name), []byte(stub), 0o755); err != nil {
			t.Fatal(err)
		}
	}

	t.Setenv("PATH", bin)

	const refusal = "/etc/rc.conf: Read-only file system"

	for _, bsd := range []struct {
		name  string
		e     rcEnabled
		names []string // what an error about a line left must say
	}{
		{"FreeBSD", freebsdEnabled, []string{"rc.conf", "conflux_enable"}},
		{"OpenBSD", openbsdEnabled, []string{"rc.conf.local", "enables conflux"}},
	} {
		for _, c := range []struct {
			name           string
			set            bool   // the line is there before
			refuse, keep   string // $RC_REFUSE and $RC_KEEP
			left           bool   // an error is wanted, naming the line
			saysTheRefusal bool   // and saying what the command said
		}{
			{"taken out", true, "", "", false, false},
			{"never there", false, "", "", false, false},
			{"refused and left", true, refusal, "", true, true},
			{"left without a word", true, "", "yes", true, false},
		} {
			t.Run(bsd.name+", "+c.name, func(t *testing.T) {
				line := filepath.Join(t.TempDir(), "line")

				var held []byte
				if c.set {
					held = []byte("YES\n")
				}

				if err := os.WriteFile(line, held, 0o644); err != nil {
					t.Fatal(err)
				}

				t.Setenv("RC_LINE", line)
				t.Setenv("RC_REFUSE", c.refuse)
				t.Setenv("RC_KEEP", c.keep)

				err := bsd.e.remove()

				if !c.left {
					if err != nil {
						t.Errorf("remove = %v; want nil, the line gone", err)
					}

					if fi, statErr := os.Stat(line); statErr != nil || fi.Size() != 0 {
						t.Errorf("the line is still there (%v)", statErr)
					}

					return
				}

				if err == nil {
					t.Fatal("remove = nil; want the line left said")
				}

				for _, want := range bsd.names {
					if !strings.Contains(err.Error(), want) {
						t.Errorf("remove = %v; want it to name %q", err, want)
					}
				}

				if c.saysTheRefusal && !strings.Contains(err.Error(), refusal) {
					t.Errorf("remove = %v; want what the command said, %q, said with it", err, refusal)
				}

				if strings.Contains(err.Error(), "%!") {
					t.Errorf("remove = %v; a nil error was formatted into it", err)
				}
			})
		}
	}
}
