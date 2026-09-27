//go:build darwin

package service

import (
	"fmt"
	"os"
	"strings"

	"github.com/veil-net/conflux/internal/paths"
)

// Functions and not constants because a run rooted in a CONFLUX_DIR is a separate
// installation and must not be registered over the machine's own; see scope.
func label() string     { return "org.veilnet.conflux" + scope() }
func plistPath() string { return "/Library/LaunchDaemons/" + label() + ".plist" }
func target() string    { return "system/" + label() }

// plistTemplate is the job conflux writes.
//
// KeepAlive is {SuccessfulExit: false} rather than true, so a deliberate clean exit
// stays exited. launchd has no way to name the exit codes that should not restart,
// so unlike the systemd unit a supervisor that exits 78 or 70 is started again after
// ThrottleInterval.
//
// ProcessType is Interactive rather than the Background that daemons default to,
// because Background imposes a low-priority I/O class and App Nap eligibility, and a
// networking daemon the scheduler throttles is a support ticket nobody can diagnose.
const plistTemplate = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>            <string>%[1]s</string>
  <key>ProgramArguments</key>
  <array>
%[2]s  </array>
  <key>RunAtLoad</key>        <true/>
  <key>KeepAlive</key>
  <dict><key>SuccessfulExit</key> <false/></dict>
  <key>ThrottleInterval</key>  <integer>5</integer>
  <key>ProcessType</key>       <string>Interactive</string>
  <key>StandardOutPath</key>   <string>%[3]s</string>
  <key>StandardErrorPath</key> <string>%[3]s</string>
  <key>ExitTimeOut</key>       <integer>30</integer>
</dict>
</plist>
`

type launchd struct{}

func newManager() (Manager, error) { return launchd{}, nil }

// logFile is where the job's output goes.
func logFile() string { return paths.Default().LogFile() }

// Install writes the job and loads nothing, which is the whole of what registration
// means here. Loading it would start it -- bootstrap honours RunAtLoad -- and Install
// starts nothing, so the caller's Restart is the one start.
//
// Nothing about a reboot depends on loading it here. launchd bootstraps everything in
// /Library/LaunchDaemons at boot, so the plist on disk *is* the registration, and
// Start and Restart load it when there is something to run.
func (l launchd) Install(exe string, args ...string) error {
	var argv strings.Builder

	for _, a := range append([]string{exe}, args...) {
		fmt.Fprintf(&argv, "    <string>%s</string>\n", escapeXML(a))
	}

	plist := fmt.Sprintf(plistTemplate, label(), argv.String(), escapeXML(logFile()))

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
// enable comes first. launchctl(1): "Once a service is disabled, it cannot be loaded in
// the specified domain until it is once again enabled. This state persists across boots
// of the device." A disabled label makes bootstrap fail with "Bootstrap failed: 5:
// Input/output error", which names nothing, so the label is enabled before every load.
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

// Remove deregisters the job and deletes its plist and its log, and deliberately
// leaves nothing in launchd's disabled database: a disabled label outlives the plist and
// stops the next install from loading, which is persistent state for a thing that no
// longer exists.
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

	if err := removeLog(logFile()); err != nil && first == nil {
		first = err
	}

	if installed, _ := l.Installed(); installed {
		return first
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

func escapeXML(s string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;").Replace(s)
}
