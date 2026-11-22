//go:build openbsd

package service

import (
	"fmt"
	"os"

	"github.com/veil-net/conflux/internal/paths"
	"github.com/veil-net/conflux/internal/privcheck"
)

// openbsd is rc.d(8): a script in /etc/rc.d, enabled and driven with rcctl.
type openbsd struct{}

func newManager() Manager { return openbsd{} }

const scriptPath = "/etc/rc.d/" + rcName

// Install writes the script and enables it, and starts nothing.
func (openbsd) Install(exe string, args ...string) error {
	script := openbsdScript(exe, args)

	// The mode base's own rc.d scripts have, whatever was there before; written whole or
	// not at all.
	if err := paths.WriteAtomic(scriptPath, 0o555, -1, -1, []byte(script)); err != nil {
		return err
	}

	return run("rcctl", "enable", rcName)
}

// Remove stops and disables the service and deletes the script. Its output went to
// syslog, which conflux does not own.
func (openbsd) Remove() error {
	_ = run("rcctl", "stop", rcName)
	_ = run("rcctl", "disable", rcName)

	if err := os.Remove(scriptPath); err != nil && !os.IsNotExist(err) {
		return err
	}

	return nil
}

func (openbsd) Stop() error    { return run("rcctl", "stop", rcName) }
func (openbsd) Restart() error { return run("rcctl", "restart", rcName) }

// Running is rcctl's answer, which check gives a service that is not running by its exit.
func (openbsd) Running() (bool, error) { return running(), nil }

func running() bool {
	_, ok := query("rcctl", "check", rcName)

	return ok
}

func (openbsd) Installed() (bool, error) { return exists(scriptPath) }

func (o openbsd) Describe() string {
	if installed, _ := o.Installed(); !installed {
		return "not installed"
	}

	if running() {
		return fmt.Sprintf("running (rc.d: %s, enabled at boot)", rcName)
	}

	return fmt.Sprintf("installed, not running (rc.d: %s, enabled at boot)", rcName)
}

func (openbsd) LogHint() string {
	return privcheck.Command("grep", rcName, "/var/log/daemon") + " | tail -n 50"
}
