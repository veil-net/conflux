//go:build freebsd

package service

import (
	"errors"
	"fmt"
	"os"

	"github.com/veil-net/conflux/internal/logfile"
	"github.com/veil-net/conflux/internal/paths"
	"github.com/veil-net/conflux/internal/privcheck"
)

// freebsd is rc(8): a script in /usr/local/etc/rc.d, enabled in rc.conf with sysrc.
type freebsd struct{}

func newManager() Manager { return freebsd{} }

func scriptPath() string { return "/usr/local/etc/rc.d/" + rcName() }

// Install writes the script and enables it, and starts nothing.
func (freebsd) Install(exe string, args ...string) error {
	script, err := freebsdScript(rcName(), exe, withLog(args), logFile())
	if err != nil {
		return err
	}

	// Executable, whatever was there before; written whole or not at all.
	if err := paths.WriteAtomic(scriptPath(), 0o755, -1, -1, []byte(script)); err != nil {
		return err
	}

	return run("sysrc", rcName()+"_enable=YES")
}

// Remove stops the service, disables it, and deletes the script and the log.
func (f freebsd) Remove() error {
	_ = run("service", rcName(), "onestop")
	_ = run("sysrc", "-x", rcName()+"_enable")

	var errs []error

	if err := os.Remove(scriptPath()); err != nil && !os.IsNotExist(err) {
		errs = append(errs, err)
	}

	return errors.Join(append(errs, logfile.Remove(logFile()))...)
}

// Stop succeeds on a service that is not running, which rc.subr answers "not running?"
// and exit 1: `conflux down` twice is a stopped service, not a failure.
func (freebsd) Stop() error {
	if !running() {
		return nil
	}

	return run("service", rcName(), "stop")
}

func (freebsd) Restart() error { return run("service", rcName(), "restart") }

func (freebsd) Installed() (bool, error) { return exists(scriptPath()) }

// Running is rc.subr's answer, which status gives a service that is not running by its exit.
func (freebsd) Running() (bool, error) { return running(), nil }

func running() bool {
	_, ok := query("service", rcName(), "status")

	return ok
}

func (f freebsd) Describe() string {
	if installed, _ := f.Installed(); !installed {
		return "not installed"
	}

	if running() {
		return fmt.Sprintf("running (rc: %s, enabled at boot)", rcName())
	}

	return fmt.Sprintf("installed, not running (rc: %s, enabled at boot)", rcName())
}

func (freebsd) LogHint() string { return privcheck.Command("tail", "-n", "50", logFile()) }
