//go:build darwin

package service

import (
	"fmt"
	"os"
	"strings"
)

const (
	label     = "org.veilnet.conflux"
	plistPath = "/Library/LaunchDaemons/" + label + ".plist"
	target    = "system/" + label
)

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

func (launchd) Name() string { return label }

func (l launchd) Install(exe string, args ...string) error {
	var argv strings.Builder

	for _, a := range append([]string{exe}, args...) {
		fmt.Fprintf(&argv, "    <string>%s</string>\n", escapeXML(a))
	}

	plist := fmt.Sprintf(plistTemplate, label, argv.String())

	if err := os.WriteFile(plistPath, []byte(plist), 0o644); err != nil { //nolint:gosec // a plist is world-readable by design
		return fmt.Errorf("write %s: %w", plistPath, err)
	}

	// Bootstrapping a job that is already loaded fails with "Operation already in
	// progress", so unload first and ignore whatever that says.
	_ = run("launchctl", "bootout", target)

	if err := run("launchctl", "bootstrap", "system", plistPath); err != nil {
		return err
	}

	// Bootstrapping loads it and RunAtLoad starts it, which Install is not meant to
	// do. Stop it again, so that a machine with no configuration gets registration
	// and nothing else -- the caller starts it when there is something to start.
	_ = run("launchctl", "kill", "SIGTERM", target)

	return run("launchctl", "enable", target)
}

func (l launchd) Remove() error {
	var first error

	if err := run("launchctl", "bootout", target); err != nil && first == nil {
		first = err
	}

	_ = run("launchctl", "disable", target)

	if err := os.Remove(plistPath); err != nil && !os.IsNotExist(err) && first == nil {
		first = err
	}

	if installed, _ := l.Installed(); installed {
		return first
	}

	return nil
}

// Start uses kickstart, which starts or restarts. The previous conflux re-ran
// bootstrap, which fails with "37: Operation already in progress" on a loaded job.
func (launchd) Start() error   { return run("launchctl", "kickstart", target) }
func (launchd) Restart() error { return run("launchctl", "kickstart", "-k", target) }

// Stop kills the process and leaves the job loaded, which is exactly the semantics
// `conflux down` needs: stopped now, back at the next boot.
func (launchd) Stop() error { return run("launchctl", "kill", "SIGTERM", target) }

func (launchd) Installed() (bool, error) {
	_, err := os.Stat(plistPath)
	if err == nil {
		return true, nil
	}

	if os.IsNotExist(err) {
		return false, nil
	}

	return false, err
}

func (launchd) Running() (bool, error) {
	out, ok := query("launchctl", "print", target)
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
		return fmt.Sprintf("running (launchd: %s, at boot)", label)
	}

	return fmt.Sprintf("installed, not running (launchd: %s, at boot)", label)
}

func escapeXML(s string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;").Replace(s)
}
