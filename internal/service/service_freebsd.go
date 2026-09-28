//go:build freebsd

package service

import (
	"fmt"
	"os"

	"github.com/veil-net/conflux/internal/paths"
)

// freebsd is rc(8): a script in /usr/local/etc/rc.d, enabled in rc.conf with sysrc.
type freebsd struct{}

func newManager() (Manager, error) { return freebsd{}, nil }

func scriptPath() string { return "/usr/local/etc/rc.d/" + rcName() }

func logFile() string { return paths.Default().LogFile() }

// Install writes the script and enables it, and starts nothing.
func (freebsd) Install(exe string, args ...string) error {
	script := freebsdScript(rcName(), exe, args, logFile())

	if err := os.WriteFile(scriptPath(), []byte(script), 0o755); err != nil { //nolint:gosec // an rc script is executable by design
		return fmt.Errorf("write %s: %w", scriptPath(), err)
	}

	// WriteFile keeps the mode of a file that already exists.
	if err := os.Chmod(scriptPath(), 0o755); err != nil {
		return fmt.Errorf("chmod %s: %w", scriptPath(), err)
	}

	return run("sysrc", rcName()+"_enable=YES")
}

// Remove stops the service, disables it, and deletes the script and the log.
func (f freebsd) Remove() error {
	var first error

	note := func(err error) {
		if err != nil && first == nil {
			first = err
		}
	}

	_ = run("service", rcName(), "onestop")
	_ = run("sysrc", "-x", rcName()+"_enable")

	if err := os.Remove(scriptPath()); err != nil && !os.IsNotExist(err) {
		note(err)
	}

	note(removeLog(logFile()))

	return first
}

func (freebsd) Stop() error    { return run("service", rcName(), "stop") }
func (freebsd) Restart() error { return run("service", rcName(), "restart") }

func (freebsd) Installed() (bool, error) { return exists(scriptPath()) }

func (f freebsd) Describe() string {
	if installed, _ := f.Installed(); !installed {
		return "not installed"
	}

	if _, running := query("service", rcName(), "status"); running {
		return fmt.Sprintf("running (rc: %s, enabled at boot)", rcName())
	}

	return fmt.Sprintf("installed, not running (rc: %s, enabled at boot)", rcName())
}

func (freebsd) LogHint() string { return "tail -n 50 " + logFile() }
