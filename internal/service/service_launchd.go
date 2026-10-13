package service

import (
	"fmt"
	"strings"
)

// The launchd job, rendered here without a build tag so the rendering is tested on the
// machines that build conflux rather than only on the Macs that run it.

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
