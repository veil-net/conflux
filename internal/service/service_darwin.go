//go:build darwin

package service

import (
	"fmt"
	"os"
	"strings"
)

// Functions and not constants because a run rooted in a CONFLUX_DIR is a separate
// installation and must not be registered over the machine's own; see scope.
func label() string     { return "org.veilnet.conflux" + scope() }
func plistPath() string { return "/Library/LaunchDaemons/" + label() + ".plist" }
func target() string    { return "system/" + label() }

// plistTemplate is the job conflux writes.
//
// KeepAlive is {SuccessfulExit: false} rather than true. The previous conflux used
// true, which restarts the job even after a deliberate clean exit -- the launchd
// analogue of restarting forever on the no-configuration case.
//
// ProcessType is Interactive rather than the Background that daemons default to,
// because Background imposes a low-priority I/O class and App Nap eligibility, and a
// networking daemon the scheduler throttles is a support ticket nobody can diagnose.
const plistTemplate = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>            <string>%s</string>
  <key>ProgramArguments</key>
  <array>
%s  </array>
  <key>RunAtLoad</key>        <true/>
  <key>KeepAlive</key>
  <dict><key>SuccessfulExit</key> <false/></dict>
  <key>ThrottleInterval</key>  <integer>5</integer>
  <key>ProcessType</key>       <string>Interactive</string>
  <key>StandardOutPath</key>   <string>/var/log/conflux.log</string>
  <key>StandardErrorPath</key> <string>/var/log/conflux.log</string>
  <key>ExitTimeOut</key>       <integer>30</integer>
</dict>
</plist>
`

type launchd struct{}

func newManager() (Manager, error) { return launchd{}, nil }

func (launchd) Name() string { return label() }

// Install writes the job and loads nothing, which is the whole of what registration
// means here.
//
// It used to bootstrap and then SIGTERM what bootstrapping started, because bootstrap
// honours RunAtLoad and Install is not meant to start anything. The kill was correct and
// the cost was not: the supervisor launchd started got as far as enrolling, opening a
// utun, assigning addresses and dialling the realm before the signal reached it, and
// then the caller started a second one for real. Every `conflux up` on a Mac brought an
// anchor up twice and threw the first away, with a ThrottleInterval wait between them --
// which is most of why a Mac took so much longer to come up than a Linux box, where
// Install writes a unit, reloads and enables, and deliberately starts nothing.
//
// Nothing about a reboot depends on loading it here. launchd bootstraps everything in
// /Library/LaunchDaemons at boot, so the plist on disk *is* the registration, and
// Start and Restart load it when there is something to run.
func (l launchd) Install(exe string, args ...string) error {
	var argv strings.Builder

	for _, a := range append([]string{exe}, args...) {
		fmt.Fprintf(&argv, "    <string>%s</string>\n", escapeXML(a))
	}

	plist := fmt.Sprintf(plistTemplate, label(), argv.String())

	if err := os.WriteFile(plistPath(), []byte(plist), 0o644); err != nil { //nolint:gosec // a plist is world-readable by design
		return fmt.Errorf("write %s: %w", plistPath(), err)
	}

	// WriteFile does not change the mode of a file that already exists, and launchd
	// refuses a job whose plist is group- or world-writable. A conflux upgraded over one
	// that wrote it differently would otherwise fail to bootstrap for a reason nothing
	// in the error names.
	if err := os.Chmod(plistPath(), 0o644); err != nil {
		return fmt.Errorf("chmod %s: %w", plistPath(), err)
	}

	// A job already loaded is loaded from the plist it was bootstrapped with, not from
	// the one just written, so an upgrade that moved the executable would keep running
	// the old path until something unloaded it. Unloading here is also what makes the
	// next Restart take the bootstrap branch, which is the single start.
	_ = run("launchctl", "bootout", target())

	// Best effort here and asked again in load(), which is where it has to succeed.
	_ = run("launchctl", "enable", target())

	return nil
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
// **enable comes first, and that ordering is a bug fix.** launchctl(1): "Once a service is
// disabled, it cannot be loaded in the specified domain until it is once again enabled.
// This state persists across boots of the device." A disabled label makes bootstrap fail
// with "Bootstrap failed: 5: Input/output error", which names nothing and is the error an
// uninstall-then-up cycle produced every time: Remove disabled the label, Install
// bootstrapped before enabling, and returned the failure before the enable on the line
// below it could ever run. Remove no longer disables anything, and this is what clears the
// landmine on a machine that already has one.
func (l launchd) load() error {
	// Not checked: a label that was never disabled has nothing to enable, and the
	// bootstrap below is the call whose answer matters either way.
	_ = run("launchctl", "enable", target())

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

// Remove deregisters the job, and deliberately leaves nothing in the disabled database.
//
// It used to `launchctl disable` on the way out, which is persistent state outliving the
// thing it refers to: launchctl(1) says a disabled label "cannot be loaded in the specified
// domain until it is once again enabled. This state persists across boots of the device."
// The plist is deleted here, so nothing could load the job anyway and the disable bought
// nothing -- but it stayed on the machine, and the next `conflux up` hit "Bootstrap failed:
// 5: Input/output error" with no way to tell why. An uninstall must not leave a machine
// unable to install again.
//
// Each step tolerates its own failure, so a half-removed service can always be finished off.
func (l launchd) Remove() error {
	var first error

	if err := run("launchctl", "bootout", target()); err != nil && first == nil {
		first = err
	}

	if err := os.Remove(plistPath()); err != nil && !os.IsNotExist(err) && first == nil {
		first = err
	}

	if installed, _ := l.Installed(); installed {
		return first
	}

	return nil
}

// Start and Restart both ask the same question first, and it is the question that keeps
// a Mac from starting twice.
//
// A job that is not loaded is started by loading it: bootstrap plus RunAtLoad is a start,
// and a kickstart on top of it would kill the instance launchd had just made. A job that
// is already loaded cannot be bootstrapped again -- that fails with "37: Operation already
// in progress", which is what the previous conflux did -- so it is kickstarted, which
// starts a stopped job and restarts a running one.
func (l launchd) Start() error {
	if !l.loaded() {
		return l.load()
	}

	return run("launchctl", "kickstart", target())
}

func (l launchd) Restart() error {
	if !l.loaded() {
		return l.load()
	}

	return run("launchctl", "kickstart", "-k", target())
}

// Stop kills the process and leaves the job loaded, which is exactly the semantics
// `conflux down` needs: stopped now, back at the next boot.
//
// A job that is not loaded at all is already in the state Stop is asked for, and saying
// so beats "Could not find service" from a launchctl that is right and unhelpful. The
// case is real: `conflux install` now registers without loading, so a machine can have a
// service it has never started in this boot.
func (l launchd) Stop() error {
	if !l.loaded() {
		return nil
	}

	return run("launchctl", "kill", "SIGTERM", target())
}

func (launchd) Installed() (bool, error) {
	_, err := os.Stat(plistPath())
	if err == nil {
		return true, nil
	}

	if os.IsNotExist(err) {
		return false, nil
	}

	return false, err
}

// Running asks launchd rather than inferring it from Installed. A job that is not loaded
// -- registered but never started in this boot -- prints nothing and is not running,
// which is the honest answer and the one Describe needs.
func (launchd) Running() (bool, error) {
	out, ok := printJob()
	if !ok {
		return false, nil
	}

	return strings.Contains(out, "state = running"), nil
}

func (l launchd) Describe() string {
	installed, _ := l.Installed()
	if !installed {
		return "not installed"
	}

	running, _ := l.Running()
	if running {
		return fmt.Sprintf("running (launchd: %s, at boot)", label())
	}

	return fmt.Sprintf("installed, not running (launchd: %s, at boot)", label())
}

func escapeXML(s string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;").Replace(s)
}
