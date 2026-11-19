package service

import (
	"bytes"
	"fmt"
	"os"
	"strings"

	"github.com/veil-net/conflux/internal/config"
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

// install writes plist as the job and loads nothing new, which is the whole of what
// registration means here. Loading a job that was not loaded would start it -- bootstrap
// honours RunAtLoad -- and Install starts nothing, so the caller's Restart is the one
// start. Nor does it stop anything: a job that was running is running when it returns.
//
// Nothing about a reboot depends on loading it here. launchd bootstraps everything in
// /Library/LaunchDaemons at boot, so the plist on disk *is* the registration -- with its
// label enabled -- and Start and Restart load it when there is something to run.
func (j launchdJob) install(plist []byte) error {
	j.enableIfDisabled()

	// Registered exactly so already, which is every re-run of up and proxy: a read, and
	// the job left as it is, loaded from this same plist or not loaded at all.
	if cur, err := os.ReadFile(j.plistPath); err == nil && bytes.Equal(cur, plist) {
		return nil
	}

	// 0644 whatever was there before: launchd refuses a job whose plist is group- or
	// world-writable, for a reason nothing in its error names.
	if err := config.WriteFileAtomic(j.plistPath, plist, 0o644); err != nil {
		return err
	}

	// A job already loaded is loaded from the plist it was bootstrapped with, not from the
	// one just written, so an upgrade that moved the executable would keep running the old
	// path, and the next Restart's kickstart would start it again there. So a loaded job is
	// unloaded, and the next start bootstraps the new plist; one that was running is
	// bootstrapped now, which starts it again on the new plist rather than leaving it
	// stopped until somebody starts it.
	out, loaded := j.print()
	if !loaded {
		return nil
	}

	if err := j.ctl.run("bootout", j.target()); err != nil {
		return err
	}

	if !jobRunning(out, loaded) {
		return nil
	}

	return j.load()
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

// running asks launchd rather than inferring it from Installed. A job that is not
// loaded -- registered but never started in this boot -- prints nothing and is not
// running, which is the honest answer and the one Describe needs.
func (j launchdJob) running() bool { return jobRunning(j.print()) }

// jobRunning reads print's answer.
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
