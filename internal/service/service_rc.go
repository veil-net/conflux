package service

import (
	"fmt"
	"strings"
)

// The BSDs' rc scripts, rendered here without a build tag so the rendering is tested
// on the machines that build conflux rather than only on the two that run it.

// rcName is the service name an rc system knows conflux by, which both rc.subr implementations build
// variable names from: conflux_enable, conflux_flags.
const rcName = "conflux"

// freebsdScript is /usr/local/etc/rc.d/<name>.
//
// daemon(8) backgrounds conflux and appends its output to the log, and -p records
// conflux's pid rather than its own, so `service conflux stop` signals conflux itself:
// it closes the anchor and then anchord, and daemon(8) exits behind it. No -r: like
// the systemd unit, a supervisor that exits with nothing to start (78) or having given
// up (70) is left stopped rather than restarted into the same answer, and conflux
// restarts anchord itself. Nothing restarts a supervisor that exits 1, either.
func freebsdScript(exe string, args []string, logFile string) string {
	argv := append([]string{exe}, args...)

	return fmt.Sprintf(`#!/bin/sh
#
# PROVIDE: %[1]s
# REQUIRE: NETWORKING
# KEYWORD: shutdown
#
# Written by conflux install; conflux uninstall removes it.

. /etc/rc.subr

name=%[1]s
rcvar=%[1]s_enable
desc="Conflux, a VeilNet anchor"

pidfile=/var/run/%[1]s.pid
procname=%[2]s
command=/usr/sbin/daemon
command_args="-f -o %[3]s -p ${pidfile} %[4]s"

load_rc_config "$name"
: "${%[1]s_enable:=NO}"

run_rc_command "$1"
`, rcName, exe, logFile, strings.Join(argv, " "))
}

// openbsdScript is /etc/rc.d/<name>. rc.subr backgrounds it and sends its output to
// syslog, and rcctl matches the running process by its command line.
func openbsdScript(exe string, args []string) string {
	return fmt.Sprintf(`#!/bin/ksh
#
# Written by conflux install; conflux uninstall removes it.

daemon=%s
daemon_flags=%q
daemon_logger=daemon.info

. /etc/rc.d/rc.subr

rc_bg=YES
rc_reload=NO

rc_cmd $1
`, exe, strings.Join(args, " "))
}
