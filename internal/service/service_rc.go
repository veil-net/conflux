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

// plainWords refuses any word an rc script cannot carry as it is.
//
// Both rc.subr implementations find the running conflux again by matching its command
// line -- FreeBSD's procname against the first word ps prints, OpenBSD's rcctl against
// the whole of it as a pattern -- and OpenBSD's also runs the command through a shell. No
// quoting survives that, so a word with a space or a shell or pattern character in it --
// a CONFLUX_DIR root, say -- is refused rather than registered as a service that starts
// and can then be neither stopped nor asked about.
func plainWords(words ...string) error {
	for _, w := range words {
		if w == "" || strings.Trim(w, plainWord) != "" {
			return fmt.Errorf(
				"%q cannot be carried by an rc script, which finds the running service by matching its "+
					"command line unquoted; use a path of letters, digits and . _ - / only", w)
		}
	}

	return nil
}

// freebsdScript is /usr/local/etc/rc.d/<name>.
//
// daemon(8) backgrounds conflux and appends its output to the log, and -p records
// conflux's pid rather than its own, so `service conflux stop` signals conflux itself:
// it closes the anchor and then anchord, and daemon(8) exits behind it. No -r: like
// the systemd unit, a supervisor that exits with nothing to start (78) or having given
// up (70) is left stopped rather than restarted into the same answer, and conflux
// restarts anchord itself. Nothing restarts a supervisor that exits 1, either.
func freebsdScript(name, exe string, args []string, logFile string) (string, error) {
	argv := append([]string{exe}, args...)

	if err := plainWords(append(argv, logFile)...); err != nil {
		return "", err
	}

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
`, name, exe, logFile, strings.Join(argv, " ")), nil
}

// openbsdScript is /etc/rc.d/<name>. rc.subr backgrounds it and sends its output to
// syslog, and rcctl matches the running process by its command line.
func openbsdScript(exe string, args []string) (string, error) {
	if err := plainWords(append([]string{exe}, args...)...); err != nil {
		return "", err
	}

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
`, exe, strings.Join(args, " ")), nil
}

// plainWord is every character a word may hold and mean the same to a shell and to a
// pattern match.
const plainWord = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-/"
