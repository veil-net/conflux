//go:build linux

package service

import (
	"bytes"
	"fmt"
	"os"
	"strings"
)

// unitName is used everywhere, suffix included: systemd appends .service to a bare
// name, and relying on that breaks the day a conflux.socket appears beside it.
//
// A function and not a constant because a run rooted in a CONFLUX_DIR is a separate
// installation and must not be registered over the machine's own; see scope.
func unitName() string { return "conflux" + scope() + ".service" }

func unitPath() string { return "/etc/systemd/system/" + unitName() }

// wantsPath is the link `systemctl enable` makes for the unit's WantedBy=, and what
// enabled means on disk.
func wantsPath() string { return "/etc/systemd/system/multi-user.target.wants/" + unitName() }

type systemd struct{}

func newManager() (Manager, error) { return systemd{}, nil }

func (s systemd) Install(exe string, args ...string) error {
	unit := []byte(systemdUnit(exe, args, scope() != ""))

	// Registered exactly so already, which is every re-run of up and proxy: a read and a
	// stat, rather than a daemon-reload and an enable that would change nothing and cost
	// most of what the restart that follows does.
	if cur, err := os.ReadFile(unitPath()); err == nil && bytes.Equal(cur, unit) {
		if _, err := os.Lstat(wantsPath()); err == nil {
			return nil
		}
	}

	if err := os.WriteFile(unitPath(), unit, 0o644); err != nil { //nolint:gosec // a unit file is world-readable by design
		return fmt.Errorf("write %s: %w", unitPath(), err)
	}

	if err := run("systemctl", "daemon-reload"); err != nil {
		return err
	}

	// Enable, and deliberately not start. Starting is the caller's decision, and
	// `conflux install` on a machine with no configuration must register without
	// starting anything.
	return run("systemctl", "enable", unitName())
}

func (s systemd) Remove() error {
	// Every step tolerates its own failure, so a unit file already deleted does not
	// stop the rest from being undone.
	var first error

	note := func(err error) {
		if err != nil && first == nil {
			first = err
		}
	}

	note(run("systemctl", "disable", "--now", unitName()))

	if err := os.Remove(unitPath()); err != nil && !os.IsNotExist(err) {
		note(err)
	}

	note(run("systemctl", "daemon-reload"))
	_ = run("systemctl", "reset-failed", unitName())

	if installed, _ := s.Installed(); installed {
		return first
	}

	// It is gone, which is what was asked for, whatever complained on the way.
	return nil
}

func (systemd) Stop() error    { return run("systemctl", "stop", unitName()) }
func (systemd) Restart() error { return run("systemctl", "restart", unitName()) }

// Installed is a stat rather than `systemctl list-unit-files`: cheaper, and it
// answers correctly on a machine where systemd is not currently running.
func (systemd) Installed() (bool, error) { return exists(unitPath()) }

// Describe asks systemd once for both answers it gives.
func (s systemd) Describe() string {
	installed, _ := s.Installed()
	if !installed {
		return "not installed"
	}

	out, _ := query("systemctl", "show", unitName(), "--property=ActiveState,UnitFileState")

	state, enabled := "unknown", "unknown"

	for line := range strings.Lines(out) {
		key, value, _ := strings.Cut(strings.TrimSpace(line), "=")

		switch {
		case value == "":
		case key == "ActiveState":
			state = value
		case key == "UnitFileState":
			enabled = value
		}
	}

	return fmt.Sprintf("%s (systemd: %s, %s at boot)", state, unitName(), enabled)
}

func (systemd) LogHint() string { return "journalctl -u " + unitName() + " -n 50" }
