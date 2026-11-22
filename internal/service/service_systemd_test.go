package service

import (
	"strings"
	"testing"
)

// TestSystemdUnit: an ordinary install is the unit it always was, word for word.
func TestSystemdUnit(t *testing.T) {
	unit := systemdUnit("/usr/local/bin/conflux", []string{"serve"})

	for _, want := range []string{
		"\nExecStart=/usr/local/bin/conflux serve\n",
		"\nType=notify\n",
		"\nRestartPreventExitStatus=78 70\n",
		"\nUser=root\n",
		"\nLimitNOFILE=1048576\n",
	} {
		if !strings.Contains(unit, want) {
			t.Errorf("the unit has no %q:\n%s", strings.TrimSpace(want), unit)
		}
	}

	// The supervisor gives anchord its capabilities, and conflux makes every directory it keeps
	// itself: systemd claims none -- a StateDirectory= is re-owned at every start once its group
	// is anchord's account.
	for _, absent := range []string{"Capabilities=", "Directory", "NoNewPrivileges"} {
		if strings.Contains(unit, absent) {
			t.Errorf("the unit has %q:\n%s", absent, unit)
		}
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
