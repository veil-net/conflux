package service

import (
	"fmt"
	"strings"
)

// The BSDs' rc scripts, rendered here without a build tag so the rendering is tested
// on the machines that build conflux rather than only on the two that run it.

// rcName is the service name an rc system knows conflux by. An underscore rather than
// scope's hyphen: both rc.subr implementations build variable names from it --
// conflux_enable, conflux_flags -- and a hyphen is not legal in one.
func rcName() string { return "conflux" + strings.ReplaceAll(scope(), "-", "_") }

// shQuote makes s one word to a POSIX shell, whatever it holds.
func shQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

func shWords(words []string) string {
	quoted := make([]string, len(words))
	for i, w := range words {
		quoted[i] = shQuote(w)
	}

	return strings.Join(quoted, " ")
}

// freebsdScript is /usr/local/etc/rc.d/<name>.
//
// daemon(8) backgrounds conflux and appends its output to the log, and -p records
// conflux's pid rather than its own, so `service conflux stop` signals conflux itself:
// it closes the anchor and then anchord, and daemon(8) exits behind it. No -r: like
// the systemd unit, a supervisor that exits with nothing to start (78) or having given
// up (70) is left stopped rather than restarted into the same answer, and conflux
// restarts anchord itself.
func freebsdScript(name, exe string, args []string, logFile string) string {
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
`, name, shQuote(exe), inDoubleQuotes(shQuote(logFile)), inDoubleQuotes(shWords(append([]string{exe}, args...))))
}

// inDoubleQuotes escapes what a shell still interprets between double quotes.
func inDoubleQuotes(s string) string {
	return strings.NewReplacer(`\`, `\\`, `"`, `\"`, "$", `\$`, "`", "\\`").Replace(s)
}

// openbsdScript is /etc/rc.d/<name>. rc.subr backgrounds it and sends its output to
// syslog, and rcctl matches the running process by its command line.
func openbsdScript(exe string, args []string) string {
	return fmt.Sprintf(`#!/bin/ksh
#
# Written by conflux install; conflux uninstall removes it.

daemon=%s
daemon_flags=%s
daemon_logger=daemon.info

. /etc/rc.d/rc.subr

rc_bg=YES
rc_reload=NO

rc_cmd $1
`, shQuote(exe), shQuote(strings.Join(args, " ")))
}
