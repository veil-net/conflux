package service

import (
	"strings"
	"testing"
)

// TestSystemdUnit: an ordinary install is the unit it always was, word for word.
func TestSystemdUnit(t *testing.T) {
	unit := systemdUnit("/usr/local/bin/conflux", []string{"serve"}, false)

	for _, want := range []string{
		"\nExecStart=/usr/local/bin/conflux serve\n",
		"\nType=notify\n",
		"\nRestartPreventExitStatus=78 70\n",
		"\nRuntimeDirectory=conflux\nRuntimeDirectoryMode=0700\n",
		"\nLimitNOFILE=1048576\n",
	} {
		if !strings.Contains(unit, want) {
			t.Errorf("the unit has no %q:\n%s", strings.TrimSpace(want), unit)
		}
	}

	// A CONFLUX_DIR install's unit claims none of the machine's directories: systemd
	// empties a RuntimeDirectory when its unit stops, whichever unit that is.
	scoped := systemdUnit("/usr/local/bin/conflux", []string{"serve", "--dir", "/srv/x"}, true)
	if strings.Contains(scoped, "Directory=") || !strings.Contains(scoped, "\nLimitNOFILE=1048576\n") {
		t.Errorf("a scoped unit claims the machine's directories:\n%s", scoped)
	}
}

// TestSystemdUnitQuotesAnything: a CONFLUX_DIR run registers its root, a path may hold
// any character, and systemd splits an ExecStart= on whitespace and expands a % and a $
// wherever they are.
func TestSystemdUnitQuotesAnything(t *testing.T) {
	unit := systemdUnit("/opt/my tools/conflux", []string{"serve", "--dir", `/srv/it's "odd" $HOME 100%\x`}, true)

	want := `ExecStart="/opt/my tools/conflux" serve --dir "/srv/it's \"odd\" $$HOME 100%%\\x"` + "\n"
	if !strings.Contains(unit, want) {
		t.Errorf("the unit has no\n  %s\n%s", want, unit)
	}
}
