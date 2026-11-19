//go:build darwin

package service

import (
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/veil-net/conflux/internal/paths"
)

// Functions and not constants because a run rooted in a CONFLUX_DIR is a separate
// installation and must not be registered over the machine's own; see scope.
func label() string { return "org.veilnet.conflux" + paths.Scope() }

// Label is the launchd job's label, which launchd hands what it starts as XPC_SERVICE_NAME.
func Label() string { return label() }

func plistPath() string { return "/Library/LaunchDaemons/" + label() + ".plist" }

// job is this installation's job, driven by the real launchctl.
func job() launchdJob {
	return launchdJob{label: label(), plistPath: plistPath(), ctl: launchctl{
		run:   func(args ...string) error { return run("launchctl", args...) },
		query: func(args ...string) (string, bool) { return query("launchctl", args...) },
	}}
}

type launchd struct{}

func newManager() Manager { return launchd{} }

// Install writes the job and loads nothing; see launchdJob.install.
func (launchd) Install(exe string, args ...string) error {
	return job().install([]byte(launchdPlist(label(), append([]string{exe}, withLog(args)...), logFile())))
}

// Remove deregisters the job and deletes its plist and its log, and deliberately
// leaves nothing in launchd's disabled database: a disabled label outlives the plist and
// stops the next install from loading, which is persistent state for a thing that no
// longer exists.
//
// Each step tolerates its own failure, so a half-removed service can always be finished off.
func (l launchd) Remove() error {
	j := job()
	errs := []error{j.ctl.run("bootout", j.target())}

	if err := os.Remove(plistPath()); err != nil && !os.IsNotExist(err) {
		errs = append(errs, err)
	}

	errs = append(errs, removeLog(logFile()))

	if installed, _ := l.Installed(); installed {
		return errors.Join(errs...)
	}

	return nil
}

// Restart asks first whether the job is loaded, and that is the question that keeps a
// Mac from starting twice.
//
// A job that is not loaded is started by loading it: bootstrap plus RunAtLoad is a start,
// and a kickstart on top of it would kill the instance launchd had just made. A job that
// is already loaded cannot be bootstrapped again -- that fails with "37: Operation already
// in progress" -- so it is kickstarted with -k, which starts a stopped job and restarts a
// running one.
func (l launchd) Restart() error {
	j := job()
	if _, loaded := j.print(); !loaded {
		return j.load()
	}

	return j.ctl.run("kickstart", "-k", j.target())
}

// Stop kills the process and leaves the job loaded, which is exactly the semantics
// `conflux down` needs: stopped now, back at the next boot.
//
// A job that is not running -- not loaded at all, or loaded and stopped already -- is in
// the state Stop is asked for, and saying so beats the refusal launchctl would give: "Could
// not find service" for one, and no process to signal for the other. Both are real:
// `conflux install` registers without loading, and `conflux down` twice is a stopped job.
//
// launchctl kill returns at once, so Stop waits for the job to go, as systemctl stop does,
// within the plist's ExitTimeOut and a little more.
func (l launchd) Stop() error {
	j := job()
	if !j.running() {
		return nil
	}

	if err := j.ctl.run("kill", "SIGTERM", j.target()); err != nil {
		return err
	}

	for deadline := time.Now().Add(35 * time.Second); j.running(); time.Sleep(200 * time.Millisecond) {
		if time.Now().After(deadline) {
			return errors.New("the job did not stop within 35s")
		}
	}

	return nil
}

func (launchd) Installed() (bool, error) { return exists(plistPath()) }

func (launchd) LogHint() string { return "tail -n 50 " + logFile() }

func (l launchd) Describe() string {
	installed, _ := l.Installed()
	if !installed {
		return "not installed"
	}

	if job().running() {
		return fmt.Sprintf("running (launchd: %s, at boot)", label())
	}

	return fmt.Sprintf("installed, not running (launchd: %s, at boot)", label())
}
