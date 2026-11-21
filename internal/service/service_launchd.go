package service

import (
	"bytes"
	"fmt"
	"os"
	"strings"
	"sync/atomic"

	"github.com/veil-net/conflux/internal/paths"
)

// The launchd job, rendered and driven here without a build tag so both are tested on the
// machines that build conflux rather than only on the Macs that run it.

// plistTemplate is the job conflux writes.
//
// KeepAlive is {SuccessfulExit: false} rather than true, so a deliberate clean exit
// stays exited. launchd has no way to name the exit codes that should not restart, so
// the supervisor it starts exits 0 where it would exit 78 or 70 (cli.launchdExit), and is
// left stopped as the systemd unit leaves it.
//
// StandardOutPath and StandardErrorPath name the log for what conflux cannot write itself;
// the rest it writes there with serve --log, stamped and moved aside when full.
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

// launchdPlist is the job for argv, its output going to logFile.
func launchdPlist(label string, argv []string, logFile string) string {
	var args strings.Builder

	for _, a := range argv {
		fmt.Fprintf(&args, "    <string>%s</string>\n", escapeXML(a))
	}

	return fmt.Sprintf(plistTemplate, escapeXML(label), args.String(), escapeXML(logFile))
}

func escapeXML(s string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;").Replace(s)
}

// launchctl drives launchd: run for a change, with launchctl's own explanation in the
// error, and query for an answer, false where launchctl exits non-zero. On a Mac they run
// launchctl itself.
type launchctl struct {
	run   func(args ...string) error
	query func(args ...string) (string, bool)
}

// launchdJob is the job an installation registers: its label, its plist, and the
// launchctl that drives it.
type launchdJob struct {
	label, plistPath string
	ctl              launchctl
}

func (j launchdJob) target() string { return "system/" + j.label }

// install writes plist as the job, which is the whole of what registration means here, and
// never loads a job that was not loaded: loading starts it -- bootstrap honours RunAtLoad --
// and Install starts nothing that is not running, so the caller's Restart is the one start.
// Nor does it leave stopped what was running: a running job whose plist changed is loaded
// again, which starts it again on the new one, and the Restart after it starts nothing.
//
// Nothing about a reboot depends on loading it here. launchd bootstraps everything in
// /Library/LaunchDaemons at boot, so the plist on disk *is* the registration -- with its
// label enabled -- and Start and Restart load it when there is something to run.
//
// started is whether it bootstrapped the job, which is a start.
func (j launchdJob) install(plist []byte) (started bool, err error) {
	j.enableIfDisabled()

	// Registered exactly so already, which is every re-run of up and proxy: a read, and
	// the job left as it is, loaded from this same plist or not loaded at all.
	if cur, err := os.ReadFile(j.plistPath); err == nil && bytes.Equal(cur, plist) {
		return false, nil
	}

	// 0644 whatever was there before: launchd refuses a job whose plist is group- or
	// world-writable, for a reason nothing in its error names.
	if err := paths.WriteAtomic(j.plistPath, 0o644, -1, -1, plist); err != nil {
		return false, err
	}

	// A job already loaded is loaded from the plist it was bootstrapped with, not from the
	// one just written, so an upgrade that moved the executable would keep running the old
	// path, and the next Restart's kickstart would start it again there. So a loaded job is
	// unloaded, and the next start bootstraps the new plist; one that was running is
	// bootstrapped now, which starts it again on the new plist rather than leaving it
	// stopped until somebody starts it.
	out, loaded := j.print()
	if !loaded {
		return false, nil
	}

	if err := j.ctl.run("bootout", j.target()); err != nil {
		return false, err
	}

	if !jobRunning(out, loaded) {
		return false, nil
	}

	if err := j.load(); err != nil {
		return false, err
	}

	return true, nil
}

// launchdManager is what one launchd manager keeps between its calls: whether its
// Install has just started the job.
type launchdManager struct {
	// started is set by an install that bootstrapped the job -- a running job whose plist
	// changed, loaded again so it keeps running -- and taken by the restart that follows from
	// the same caller, which then starts nothing: a kickstart -k there would kill the
	// instance launchd had just made, and start it a second time.
	started atomic.Bool
}

func (m *launchdManager) install(j launchdJob, plist []byte) error {
	started, err := j.install(plist)
	if started {
		m.started.Store(true)
	}

	return err
}

func (m *launchdManager) restart(j launchdJob) error {
	if m.started.Swap(false) {
		return nil
	}

	return j.restart()
}

// restart asks first whether the job is loaded, and that is the question that keeps a Mac
// from starting twice.
//
// A job that is not loaded is started by loading it: bootstrap plus RunAtLoad is a start,
// and a kickstart on top of it would kill the instance launchd had just made. A job that
// is already loaded cannot be bootstrapped again -- that fails with "37: Operation already
// in progress" -- so it is kickstarted with -k, which starts a stopped job and restarts a
// running one.
func (j launchdJob) restart() error {
	if _, loaded := j.print(); !loaded {
		return j.load()
	}

	return j.ctl.run("kickstart", "-k", j.target())
}

// enableIfDisabled lifts a disable on the label, and does nothing to one that has none.
//
// launchctl(1): "Once a service is disabled, it cannot be loaded in the specified domain
// until it is once again enabled. This state persists across boots of the device." A
// disabled label makes bootstrap fail with "Bootstrap failed: 5: Input/output error",
// which names nothing. But an enable is itself an entry in that database, which outlives
// the plist and which uninstall cannot remove, so it is written only where a disable is
// there to lift.
func (j launchdJob) enableIfDisabled() {
	out, _ := j.ctl.query("print-disabled", "system")

	for line := range strings.Lines(out) {
		key, value, _ := strings.Cut(strings.TrimSpace(line), "=>")
		if strings.TrimSpace(key) != `"`+j.label+`"` {
			continue
		}

		if v := strings.TrimSpace(value); v == "disabled" || v == "true" {
			_ = j.ctl.run("enable", j.target())
		}

		return
	}
}

// print is launchd's view of the job, and whether it is loaded -- bootstrapped into the
// system domain -- at all. Loaded is not running: a job `conflux down` stopped is still
// loaded, and the two need different starts.
func (j launchdJob) print() (string, bool) { return j.ctl.query("print", j.target()) }

// jobRunning reads print's answer: a job that is not loaded -- registered but never
// started in this boot -- prints nothing and is not running.
func jobRunning(out string, loaded bool) bool {
	return loaded && strings.Contains(out, "state = running")
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
// A disabled label would refuse it, and install has lifted any already: every start --
// Install's own, and the Restart up, proxy, install and start make -- follows an install.
func (j launchdJob) load() error {
	if err := j.ctl.run("bootstrap", "system", j.plistPath); err != nil {
		return fmt.Errorf("%w\n%s", err, j.bootstrapHint())
	}

	return nil
}

// bootstrapHint names what launchd will not say for itself.
//
// Error 5 is "Input/output error" and covers every refusal launchd has no code for, so the
// message an operator gets names none of the four things that actually cause it.
func (j launchdJob) bootstrapHint() string {
	return "  launchd reports most refusals as error 5, which names nothing. The usual causes:\n" +
		"    - the label is disabled:  sudo launchctl enable " + j.target() + "\n" +
		"    - " + j.plistPath + " is not root-owned, or is group- or world-writable\n" +
		"    - the job is already loaded:  sudo launchctl bootout " + j.target() + "\n" +
		"    - the executable it names is gone, or is on a volume that is not mounted yet"
}
