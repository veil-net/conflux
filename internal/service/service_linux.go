//go:build linux

package service

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/veil-net/conflux/internal/config"
	"github.com/veil-net/conflux/internal/paths"
)

// unitName is used everywhere, suffix included: systemd appends .service to a bare
// name, and relying on that breaks the day a conflux.socket appears beside it.
//
// A function and not a constant because a run rooted in a CONFLUX_DIR is a separate
// installation and must not be registered over the machine's own; see scope.
func unitName() string { return "conflux" + paths.Scope() + ".service" }

func unitPath() string { return "/etc/systemd/system/" + unitName() }

// wantsPath is the link `systemctl enable` makes for the unit's WantedBy=, and what
// enabled means on disk.
func wantsPath() string { return "/etc/systemd/system/multi-user.target.wants/" + unitName() }

type systemd struct{}

func newManager() Manager { return systemd{} }

// running reports whether systemd is this machine's init, as sd_booted(3) decides it.
func running() bool {
	fi, err := os.Stat("/run/systemd/system")

	return err == nil && fi.IsDir()
}

func (s systemd) Install(exe string, args ...string) error {
	// Before anything is written: without systemd the unit would be written and then
	// refused at daemon-reload, leaving a registration nothing will ever run.
	if !running() {
		return errors.New("this machine is not running systemd, which is the only service manager " +
			"conflux registers with on Linux")
	}

	unit := []byte(systemdUnit(exe, args, paths.Scope() != ""))

	// Registered exactly so already, which is every re-run of up and proxy: a read and a
	// stat, rather than a daemon-reload and an enable that would change nothing and cost
	// most of what the restart that follows does.
	if cur, err := os.ReadFile(unitPath()); err == nil && bytes.Equal(cur, unit) {
		if _, err := os.Lstat(wantsPath()); err == nil {
			return nil
		}
	}

	// Readable by all, as systemd expects a unit to be; written whole or not at all.
	if err := config.WriteFileAtomic(unitPath(), unit, 0o644); err != nil {
		return err
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
	errs := []error{run("systemctl", "disable", "--now", unitName())}

	// Gone with a disable that worked, and left dangling by one that did not.
	for _, path := range []string{wantsPath(), unitPath()} {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			errs = append(errs, err)
		}
	}

	errs = append(errs, run("systemctl", "daemon-reload"))
	_ = run("systemctl", "reset-failed", unitName())

	if installed, _ := s.Installed(); installed {
		return errors.Join(errs...)
	}

	// It is gone, which is what was asked for, whatever complained on the way.
	return nil
}

func (systemd) Stop() error { return run("systemctl", "stop", unitName()) }

// Restart clears a failed unit first: one started too often in a row refuses every
// start until its interval has passed, and an operator's start is not one of a loop.
func (systemd) Restart() error {
	_ = run("systemctl", "reset-failed", unitName())

	return run("systemctl", "restart", unitName())
}

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
