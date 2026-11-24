//go:build openbsd

package service

import (
	"fmt"
	"os"

	"github.com/veil-net/conflux/internal/config"
)

// openbsd is rc.d(8): a script in /etc/rc.d, enabled and driven with rcctl.
type openbsd struct{}

func newManager() Manager { return openbsd{} }

func scriptPath() string { return "/etc/rc.d/" + rcName }

// Install writes the script and enables it, and starts nothing. Each only where it is not so
// already, which is every start of the service: rc.conf.local is the administrator's, which
// rcctl rewrites.
func (openbsd) Install(exe string, args ...string) error {
	script, err := openbsdScript(exe, args)
	if err != nil {
		return err
	}

	// The mode base's own rc.d scripts have; written whole or not at all.
	if _, err := config.WriteFileIfChanged(scriptPath(), []byte(script), 0o555); err != nil {
		return err
	}

	// rcctl(8): get ... status exits 0 for a service that is enabled.
	if _, enabled := query("rcctl", "get", rcName, "status"); enabled {
		return nil
	}

	return run("rcctl", "enable", rcName)
}

// Remove stops and disables the service and deletes the script. Its output went to
// syslog, which conflux does not own.
func (openbsd) Remove() error {
	_ = run("rcctl", "stop", rcName)
	_ = run("rcctl", "disable", rcName)

	if err := os.Remove(scriptPath()); err != nil && !os.IsNotExist(err) {
		return err
	}

	return nil
}

func (openbsd) Stop() error    { return run("rcctl", "stop", rcName) }
func (openbsd) Restart() error { return run("rcctl", "restart", rcName) }

func (openbsd) Installed() (bool, error) { return exists(scriptPath()) }

func (o openbsd) Describe() string {
	if installed, _ := o.Installed(); !installed {
		return "not installed"
	}

	if _, running := query("rcctl", "check", rcName); running {
		return fmt.Sprintf("running (rc.d: %s, enabled at boot)", rcName)
	}

	return fmt.Sprintf("installed, not running (rc.d: %s, enabled at boot)", rcName)
}

func (openbsd) LogHint() string { return "grep " + rcName + " /var/log/daemon | tail -n 50" }

// Reconcile is Install, which writes the script and enables it where either is not so, and
// starts nothing, so the running service may call it.
func (openbsd) Reconcile(exe string, args ...string) error { return openbsd{}.Install(exe, args...) }
