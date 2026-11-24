//go:build freebsd

package service

import (
	"fmt"

	"github.com/veil-net/conflux/internal/paths"

	"github.com/veil-net/conflux/internal/config"
)

// freebsd is rc(8): a script in /usr/local/etc/rc.d, enabled in rc.conf with sysrc.
type freebsd struct{}

func newManager() Manager { return freebsd{} }

func scriptPath() string { return "/usr/local/etc/rc.d/" + rcName }

// Install writes the script and enables it, and starts nothing. Each only where it is not so
// already, which is every start of the service: rc.conf is the administrator's, which sysrc
// rewrites.
func (freebsd) Install(exe string, args ...string) error {
	script, err := freebsdScript(rcName, exe, args, paths.Default().RCPidFile())
	if err != nil {
		return err
	}

	// Executable; written whole or not at all.
	if _, err := config.WriteFileIfChanged(scriptPath(), []byte(script), 0o755); err != nil {
		return err
	}

	// rc.subr's own answer, which reads a YES in any of the spellings it accepts.
	if _, enabled := query("service", rcName, "enabled"); enabled {
		return nil
	}

	return run("sysrc", rcName+"_enable=YES")
}

// Remove stops the service, disables it, and deletes the script once the rc.conf line is gone
// (rcEnabled.remove), saying a line or a script it left.
func (f freebsd) Remove() error {
	_ = run("service", rcName, "onestop")

	return freebsdEnabled.remove(scriptPath())
}

// Stop succeeds on a service that is not running, which rc.subr answers "not running?"
// and exit 1: `conflux down` twice is a stopped service, not a failure.
func (freebsd) Stop() error {
	if !running() {
		return nil
	}

	return run("service", rcName, "stop")
}

func (freebsd) Restart() error { return run("service", rcName, "restart") }

func (freebsd) Installed() (bool, error) { return exists(scriptPath()) }

func running() bool {
	_, ok := query("service", rcName, "status")

	return ok
}

func (f freebsd) Describe() string {
	if installed, _ := f.Installed(); !installed {
		return "not installed"
	}

	if running() {
		return fmt.Sprintf("running (rc: %s, enabled at boot)", rcName)
	}

	return fmt.Sprintf("installed, not running (rc: %s, enabled at boot)", rcName)
}

func (freebsd) LogHint() string { return "grep conflux /var/log/messages | tail -n 50" }

// Reconcile is Install, which writes the script and enables it where either is not so, and
// starts nothing, so the running service may call it.
func (freebsd) Reconcile(exe string, args ...string) error { return freebsd{}.Install(exe, args...) }
