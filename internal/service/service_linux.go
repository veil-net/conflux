//go:build linux

package service

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/veil-net/conflux/internal/config"
)

// unitName is used everywhere, suffix included: systemd appends .service to a bare
// name, and relying on that breaks the day a conflux.socket appears beside it.
const unitName = "conflux.service"

const unitPath = "/etc/systemd/system/" + unitName

// wantsPath is the link `systemctl enable` makes for the unit's WantedBy=, and what
// enabled means on disk.
const wantsPath = "/etc/systemd/system/multi-user.target.wants/" + unitName

// dropinDirs are the unit's four drop-in directories in /etc and /run: an administrator's, and
// systemctl set-property's (system.control), each persistent in /etc and for the boot in /run.
// None of them conflux's, so the unit that runs is the one conflux writes. systemd reads others
// -- a package's under /usr/lib and /usr/local/lib, and those for every service -- which nothing
// of conflux's writes and nothing here removes.
var dropinDirs = []string{
	"/etc/systemd/system/" + unitName + ".d",
	"/etc/systemd/system.control/" + unitName + ".d",
	"/run/systemd/system/" + unitName + ".d",
	"/run/systemd/system.control/" + unitName + ".d",
}

// removeDropins removes the unit's four drop-in directories under root, "/" but in a test, and
// reports whether there was one.
func removeDropins(root string) (bool, error) {
	var (
		found bool
		errs  []error
	)

	for _, dir := range dropinDirs {
		path := filepath.Join(root, dir)
		if _, err := os.Lstat(path); err != nil {
			continue
		}

		found = true

		errs = append(errs, os.RemoveAll(path))
	}

	return found, errors.Join(errs...)
}

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

	// A drop-in in /etc or /run would make the unit that runs something other than this one.
	dropins, err := removeDropins("/")
	if err != nil {
		return err
	}

	// Readable by all, as systemd expects a unit to be; written whole or not at all, and only
	// where it differs.
	wrote, err := config.WriteFileIfChanged(unitPath, []byte(systemdUnit(exe, args)), 0o644)
	if err != nil {
		return err
	}

	// Registered exactly so already, which is every re-run of up and proxy: a read and a
	// stat, rather than a daemon-reload and an enable that would change nothing and cost
	// most of what the restart that follows does.
	if !wrote && !dropins {
		if _, err := os.Lstat(wantsPath); err == nil {
			return nil
		}
	}

	if err := run("systemctl", "daemon-reload"); err != nil {
		return err
	}

	// Enable, and deliberately not start. Starting is the caller's decision, and
	// `conflux install` on a machine with no configuration must register without
	// starting anything.
	return run("systemctl", "enable", unitName)
}

func (systemd) Remove() error { return remove("/") }

// remove is Remove for the unit's files under root, "/" but in a test.
func remove(root string) error {
	// Every step tolerates its own failure, so a unit file already deleted does not
	// stop the rest from being undone. The stop is its own step for the same reason: disable
	// --now stops nothing once the disable has failed, which it does for a unit whose file is
	// gone, and such a unit may still be running. It answers no for a unit not loaded at all.
	_ = run("systemctl", "stop", unitName)

	disable := run("systemctl", "disable", unitName)

	// The wants link, gone with a disable that worked and left dangling by one that did not, the
	// unit file, and the drop-ins. One that could not be removed is said whatever became of the
	// rest: it is conflux, left on the machine.
	var files []error

	for _, path := range []string{wantsPath, unitPath} {
		if err := os.Remove(filepath.Join(root, path)); err != nil && !os.IsNotExist(err) {
			files = append(files, err)
		}
	}

	_, err := removeDropins(root)
	files = append(files, err)

	reload := run("systemctl", "daemon-reload")
	_ = run("systemctl", "reset-failed", unitName)

	// systemctl's answers are forgiven once the unit file is gone, which is what was asked for:
	// a disable fails for a unit whose file went first.
	if installed, _ := exists(filepath.Join(root, unitPath)); installed {
		return errors.Join(disable, errors.Join(files...), reload)
	}

	return errors.Join(files...)
}

func (systemd) Stop() error { return run("systemctl", "stop", unitName) }

// Restart clears a failed unit first: one started too often in a row refuses every
// start until its interval has passed, and an operator's start is not one of a loop.
func (systemd) Restart() error {
	_ = run("systemctl", "reset-failed", unitName)

	return run("systemctl", "restart", unitName)
}

// Installed is a stat rather than `systemctl list-unit-files`: cheaper, and it
// answers correctly on a machine where systemd is not currently running.
func (systemd) Installed() (bool, error) { return exists(unitPath) }

// Describe asks systemd once for both answers it gives.
func (s systemd) Describe() string {
	installed, _ := s.Installed()
	if !installed {
		return "not installed"
	}

	out, _ := query("systemctl", "show", unitName, "--property=ActiveState,UnitFileState")

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

	return fmt.Sprintf("%s (systemd: %s, %s at boot)", state, unitName, enabled)
}

func (systemd) LogHint() string { return "journalctl -u " + unitName + " -n 50" }

// Reconcile is Install, which rewrites the unit only where it differs, removes the unit's four
// drop-in directories, and starts nothing, so the running service may call it.
func (systemd) Reconcile(exe string, args ...string) error { return systemd{}.Install(exe, args...) }
