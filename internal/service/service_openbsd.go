//go:build openbsd

package service

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/veil-net/conflux/internal/config"
)

// openbsd is rc.d(8): a script in /etc/rc.d, enabled and driven with rcctl.
type openbsd struct{}

func newManager() Manager { return openbsd{} }

func scriptPath() string { return "/etc/rc.d/" + rcName }

// classPath is the login class rc.subr runs the service under, found by its name.
// login.conf(5): a class in /etc/login.conf.d/<class> takes precedence over one of that name in
// /etc/login.conf.
const classPath = "/etc/login.conf.d/" + rcName

// Install writes the login class and the script and enables the service, and starts nothing.
// Each only where it is not so already, which is every start of the service: rc.conf.local is
// the administrator's, which rcctl rewrites.
func (openbsd) Install(exe string, args ...string) error {
	script, err := openbsdScript(exe, args)
	if err != nil {
		return err
	}

	if err := os.MkdirAll(filepath.Dir(classPath), 0o755); err != nil {
		return err
	}

	// Readable by all, as login.conf is.
	if _, err := config.WriteFileIfChanged(classPath, []byte(openbsdClass()), 0o644); err != nil {
		return err
	}

	// cgetent(3) reads a cap_mkdb(1) database in place of the file beside it, so one there
	// would be the class, whatever conflux wrote; conflux writes none.
	if err := os.Remove(classPath + ".db"); err != nil && !os.IsNotExist(err) {
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

// Remove stops and disables the service, deletes the login class, and the script once the
// rc.conf.local line is gone (rcEnabled.remove), saying a line or a file it left. Its output went
// to syslog, which conflux does not own.
func (openbsd) Remove() error {
	_ = run("rcctl", "stop", rcName)

	errs := []error{openbsdEnabled.remove(scriptPath())}

	for _, path := range []string{classPath, classPath + ".db"} {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			errs = append(errs, err)
		}
	}

	return errors.Join(errs...)
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

// Reconcile is Install, which writes the login class and the script and enables the service
// where any is not so, and starts nothing, so the running service may call it.
func (openbsd) Reconcile(exe string, args ...string) error { return openbsd{}.Install(exe, args...) }
