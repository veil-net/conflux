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
		"\nUser=root\n",
		"\nLimitNOFILE=1048576\n",
	} {
		if !strings.Contains(unit, want) {
			t.Errorf("the unit has no %q:\n%s", strings.TrimSpace(want), unit)
		}
	}

	// The supervisor gives anchord its capabilities, and systemd must not take anchord's
	// directory back: a StateDirectory= is re-owned at every start once its group is
	// anchord's account.
	for _, absent := range []string{"Capabilities=", "StateDirectory", "NoNewPrivileges"} {
		if strings.Contains(unit, absent) {
			t.Errorf("the unit has %q:\n%s", absent, unit)
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

	// A line break would end the line, and systemd reads the rest as a setting of its own;
	// every control character goes in as its C escape, which systemd reads back inside quotes.
	unit = systemdUnit("/opt/conflux", []string{"serve", "--dir", "/srv/a\nRestart=no\tb\x01\x7f"}, true)

	want = `ExecStart=/opt/conflux serve --dir "/srv/a\nRestart=no\tb\x01\x7f"` + "\n"
	if !strings.Contains(unit, want) || strings.Contains(unit, "\nRestart=no") {
		t.Errorf("the unit has no\n  %s\n%s", want, unit)
	}
}

// TestMainPIDIsWhetherTheUnitRuns: systemctl show's MainPID names the unit's main process, which a
// unit starting, running or stopping has -- the supervisor tidy stops for an update -- and one
// waiting to be restarted has not, MainPID=0. An answer naming no number, empty or with no value, is
// none systemd gives, and an error naming it, never a "no".
func TestMainPIDIsWhetherTheUnitRuns(t *testing.T) {
	for _, c := range []struct {
		out      string
		running  bool
		refusing bool
	}{
		{out: "MainPID=0"},
		{out: "MainPID=42", running: true},
		{out: "", refusing: true},
		{out: "MainPID=", refusing: true},
	} {
		running, err := mainPID(c.out)
		if running != c.running || (err != nil) != c.refusing || err != nil && !strings.Contains(err.Error(), `"`+c.out+`"`) {
			t.Errorf("mainPID(%q) = %v, %v, want %v, refused %v naming the answer", c.out, running, err, c.running,
				c.refusing)
		}
	}
}
