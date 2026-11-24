package service

import (
	"strings"
	"testing"
)

// TestSystemdUnit: the unit conflux registers, its supervisor run from the root.
func TestSystemdUnit(t *testing.T) {
	unit := systemdUnit("/var/lib/.conflux/conflux", []string{"serve"})

	for _, want := range []string{
		"\nExecStart=/var/lib/.conflux/conflux serve\n",
		"\nType=notify\n",
		"\nRestartPreventExitStatus=78 70\n",
		"\nUser=root\n",
		"\nLimitNOFILE=1048576\n",
	} {
		if !strings.Contains(unit, want) {
			t.Errorf("the unit has no %q:\n%s", strings.TrimSpace(want), unit)
		}
	}

	// The supervisor gives anchord its capabilities, and systemd must not take anchord's
	// directory back: a StateDirectory= is re-owned at every start once its group is
	// anchord's account. Nor does the unit claim a directory of its own: everything is in
	// the root, which the supervisor keeps.
	for _, absent := range []string{"Capabilities=", "StateDirectory", "NoNewPrivileges", "RuntimeDirectory", "ConfigurationDirectory"} {
		if strings.Contains(unit, absent) {
			t.Errorf("the unit has %q:\n%s", absent, unit)
		}
	}
}

// TestSystemdUnitQuotesAnything: a path may hold any character, and systemd splits an
// ExecStart= on whitespace and expands a % and a $ wherever they are.
func TestSystemdUnitQuotesAnything(t *testing.T) {
	unit := systemdUnit("/opt/my tools/conflux", []string{"serve", `/srv/it's "odd" $HOME 100%\x`})

	want := `ExecStart="/opt/my tools/conflux" serve "/srv/it's \"odd\" $$HOME 100%%\\x"` + "\n"
	if !strings.Contains(unit, want) {
		t.Errorf("the unit has no\n  %s\n%s", want, unit)
	}
}
