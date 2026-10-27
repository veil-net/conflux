//go:build darwin

package service

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/veil-net/conflux/internal/config"
	"github.com/veil-net/conflux/internal/paths"
)

// Functions and not constants because a run rooted in a CONFLUX_DIR is a separate
// installation and must not be registered over the machine's own; see scope.
func label() string     { return "org.veilnet.conflux" + paths.Scope() }
func plistPath() string { return "/Library/LaunchDaemons/" + label() + ".plist" }
func target() string    { return "system/" + label() }

type launchd struct{}

func newManager() Manager { return launchd{} }

// Install writes the job and loads nothing, which is the whole of what registration
// means here. Loading it would start it -- bootstrap honours RunAtLoad -- and Install
// starts nothing, so the caller's Restart is the one start.
//
// Nothing about a reboot depends on loading it here. launchd bootstraps everything in
// /Library/LaunchDaemons at boot, so the plist on disk *is* the registration, and
// Start and Restart load it when there is something to run.
func (l launchd) Install(exe string, args ...string) error {
	plist := launchdPlist(label(), append([]string{exe}, args...), logFile())

	// 0644 whatever was there before: launchd refuses a job whose plist is group- or
	// world-writable, for a reason nothing in its error names.
	if err := config.WriteFileAtomic(plistPath(), []byte(plist), 0o644); err != nil {
		return err
	}

	// A job already loaded is loaded from the plist it was bootstrapped with, not from
	// the one just written, so an upgrade that moved the executable would keep running
	// the old path until something unloaded it. Unloading here is also what makes the
	// next Restart take the bootstrap branch, which is the single start.
	_ = run("launchctl", "bootout", target())

	enableIfDisabled()

	return nil
}

// enableIfDisabled lifts a disable on the label, and does nothing to one that has none.
//
// launchctl(1): "Once a service is disabled, it cannot be loaded in the specified domain
// until it is once again enabled. This state persists across boots of the device." A
// disabled label makes bootstrap fail with "Bootstrap failed: 5: Input/output error",
// which names nothing. But an enable is itself an entry in that database, which outlives
// the plist and which uninstall cannot remove, so it is written only where a disable is
// there to lift.
func enableIfDisabled() {
	out, _ := query("launchctl", "print-disabled", "system")

	for line := range strings.Lines(out) {
		key, value, _ := strings.Cut(strings.TrimSpace(line), "=>")
		if strings.TrimSpace(key) != `"`+label()+`"` {
			continue
		}

		if v := strings.TrimSpace(value); v == "disabled" || v == "true" {
			_ = run("launchctl", "enable", target())
		}

		return
	}
}

// printJob is launchd's view of the job, and whether there is one in the domain at all.
// One spelling of the command, because loaded and Running ask it the same question and
// read different halves of the answer.
func printJob() (string, bool) { return query("launchctl", "print", target()) }

// loaded reports whether the job is bootstrapped into the system domain.
//
// Not "is it running": a job that has been stopped by `conflux down` is still loaded,
// and the two need different starts.
func (l launchd) loaded() bool {
	_, ok := printJob()

	return ok
}

// load bootstraps the job, which also starts it.
//
// Loading is a start and cannot be anything else here. RunAtLoad asks for it, and
// launchd.plist(5) says KeepAlive asks for it too -- "this key implies that RunAtLoad is
// set to true, since the job needs to run at least once before an exit status can be
// determined" -- so a job carrying KeepAlive{SuccessfulExit:false} launches when it is
// loaded whatever the RunAtLoad key says. Start and Restart are built on that rather than
// trying to work around it.
//
// A disabled label is enabled first; see enableIfDisabled.
func (l launchd) load() error {
	enableIfDisabled()

	if err := run("launchctl", "bootstrap", "system", plistPath()); err != nil {
		return fmt.Errorf("%w\n%s", err, bootstrapHint())
	}

	return nil
}

// bootstrapHint names what launchd will not say for itself.
//
// Error 5 is "Input/output error" and covers every refusal launchd has no code for, so the
// message an operator gets names none of the four things that actually cause it.
func bootstrapHint() string {
	return "  launchd reports most refusals as error 5, which names nothing. The usual causes:\n" +
		"    - the label is disabled:  sudo launchctl enable " + target() + "\n" +
		"    - " + plistPath() + " is not root-owned, or is group- or world-writable\n" +
		"    - the job is already loaded:  sudo launchctl bootout " + target() + "\n" +
		"    - the executable it names is gone, or is on a volume that is not mounted yet"
}

// Remove deregisters the job and deletes its plist and its log, and deliberately
// leaves nothing in launchd's disabled database: a disabled label outlives the plist and
// stops the next install from loading, which is persistent state for a thing that no
// longer exists.
//
// Each step tolerates its own failure, so a half-removed service can always be finished off.
func (l launchd) Remove() error {
	errs := []error{run("launchctl", "bootout", target())}

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
	if !l.loaded() {
		return l.load()
	}

	return run("launchctl", "kickstart", "-k", target())
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
	if !running() {
		return nil
	}

	if err := run("launchctl", "kill", "SIGTERM", target()); err != nil {
		return err
	}

	for deadline := time.Now().Add(35 * time.Second); running(); time.Sleep(200 * time.Millisecond) {
		if time.Now().After(deadline) {
			return errors.New("the job did not stop within 35s")
		}
	}

	return nil
}

func (launchd) Installed() (bool, error) { return exists(plistPath()) }

// running asks launchd rather than inferring it from Installed. A job that is not
// loaded -- registered but never started in this boot -- prints nothing and is not
// running, which is the honest answer and the one Describe needs.
func running() bool {
	out, ok := printJob()

	return ok && strings.Contains(out, "state = running")
}

func (launchd) LogHint() string { return "tail -n 50 " + logFile() }

func (l launchd) Describe() string {
	installed, _ := l.Installed()
	if !installed {
		return "not installed"
	}

	if running() {
		return fmt.Sprintf("running (launchd: %s, at boot)", label())
	}

	return fmt.Sprintf("installed, not running (launchd: %s, at boot)", label())
}
