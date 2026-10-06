//go:build openbsd

package service

import (
	"fmt"
	"os"
)

// openbsd is rc.d(8): a script in /etc/rc.d, enabled and driven with rcctl.
type openbsd struct{}

func newManager() (Manager, error) { return openbsd{}, nil }

func scriptPath() string { return "/etc/rc.d/" + rcName() }

// Install writes the script and enables it, and starts nothing.
func (openbsd) Install(exe string, args ...string) error {
	script, err := openbsdScript(exe, args)
	if err != nil {
		return err
	}

	if err := os.WriteFile(scriptPath(), []byte(script), 0o555); err != nil { //nolint:gosec // an rc script is executable by design
		return fmt.Errorf("write %s: %w", scriptPath(), err)
	}

	// WriteFile keeps the mode of a file that already exists.
	if err := os.Chmod(scriptPath(), 0o555); err != nil {
		return fmt.Errorf("chmod %s: %w", scriptPath(), err)
	}

	return run("rcctl", "enable", rcName())
}

// Remove stops and disables the service and deletes the script. Its output went to
// syslog, which conflux does not own.
func (openbsd) Remove() error {
	_ = run("rcctl", "stop", rcName())
	_ = run("rcctl", "disable", rcName())

	if err := os.Remove(scriptPath()); err != nil && !os.IsNotExist(err) {
		return err
	}

	return nil
}

func (openbsd) Stop() error    { return run("rcctl", "stop", rcName()) }
func (openbsd) Restart() error { return run("rcctl", "restart", rcName()) }

func (openbsd) Installed() (bool, error) { return exists(scriptPath()) }

func (o openbsd) Describe() string {
	if installed, _ := o.Installed(); !installed {
		return "not installed"
	}

	if _, running := query("rcctl", "check", rcName()); running {
		return fmt.Sprintf("running (rc.d: %s, enabled at boot)", rcName())
	}

	return fmt.Sprintf("installed, not running (rc.d: %s, enabled at boot)", rcName())
}

func (openbsd) LogHint() string { return "grep " + rcName() + " /var/log/daemon | tail -n 50" }
