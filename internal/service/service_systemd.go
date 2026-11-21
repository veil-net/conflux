package service

import (
	"fmt"
	"strconv"
	"strings"
)

// The systemd unit, rendered here without a build tag -- as the rc scripts are -- so
// its quoting is tested on every machine that builds conflux rather than only on Linux;
// and the one answer of systemd's that Running reads (mainPID), for the same reason.

// unitTemplate is the unit conflux writes.
//
// Type=notify, with sd_notify from the supervisor, is what makes `systemctl start`
// return only once the anchor is actually up rather than once fork succeeded.
//
// RestartPreventExitStatus names the two answers a restart would only repeat, 78 and 70:
// `conflux serve` exits ExitNoConfig when there is nothing to start, and ExitChildFailed
// when it has given up on a configuration or a host that no retry changes; without this
// the unit would restart into the same answer every five seconds forever, instead of
// showing failed.
//
// Restart=on-failure rather than always, so a deliberate clean exit stays exited.
//
// RuntimeDirectory and ConfigurationDirectory make systemd create and mode two of the
// directories, and clean /run/conflux on stop. conflux still creates them itself, so
// running in the foreground and on non-systemd hosts works. They name the machine's own
// directories, so a unit for a CONFLUX_DIR install leaves them out: stopping it would
// otherwise empty the real installation's /run/conflux.
//
// User=root, and no capability line: the supervisor is root, and it is the supervisor
// that gives anchord, as its own account, exactly the capabilities its mode needs and no
// others (internal/daemon/privilege.go). An AmbientCapabilities= here would be granted
// to the supervisor, which has them all as root anyway, and to nothing else.
//
// Deliberately absent: StateDirectory, because systemd gives a directory it claims to
// User= and Group= again, recursively, at every start once its top belongs to anybody
// else -- and the state directory's group is anchord's account, so every start would
// hand anchord's own directory back to root. PrivateTmp, because nothing conflux does
// touches /tmp and it would only confuse the extraction path. ProtectSystem=strict, which
// would need a ReadWritePaths list. And NoNewPrivileges, which would hold for a root
// anchord too, where a host's firewall answers only root, and stop its firewall commands'
// SELinux transitions; the supervisor sets no_new_privs on the anchord it can, itself.
const unitTemplate = `[Unit]
Description=Conflux — VeilNet anchor
Documentation=https://github.com/veil-net/conflux
After=network-online.target
Wants=network-online.target

[Service]
Type=notify
NotifyAccess=main
ExecStart=%[1]s
Restart=on-failure
RestartSec=5
RestartPreventExitStatus=%[2]d %[3]d
TimeoutStartSec=90
TimeoutStopSec=30
KillMode=mixed
KillSignal=SIGTERM
User=root
Group=root
%[4]sLimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
`

// machineDirectories are the unit's claim on the machine's own directories.
const machineDirectories = `RuntimeDirectory=conflux
RuntimeDirectoryMode=0700
ConfigurationDirectory=conflux
ConfigurationDirectoryMode=0700
`

// systemdUnit is the unit for exe run with args; scoped for a CONFLUX_DIR install, which
// does not claim the machine's directories.
func systemdUnit(exe string, args []string, scoped bool) string {
	dirs := machineDirectories
	if scoped {
		dirs = ""
	}

	return fmt.Sprintf(unitTemplate, execLine(append([]string{exe}, args...)), ExitNoConfig, ExitChildFailed, dirs)
}

// execLine renders an ExecStart= command line, each word quoted where systemd would
// otherwise split it or read it: whitespace, quotes, backslashes and control characters
// are quoted and escaped, and a % or a $ -- a specifier or a variable to systemd, quoted
// or not -- is doubled. A CONFLUX_DIR run registers its root here, and a path may hold any
// of them.
func execLine(words []string) string {
	literal := strings.NewReplacer("%", "%%", "$", "$$")

	out := make([]string, len(words))

	for i, w := range words {
		w = literal.Replace(w)
		if w == "" || strings.ContainsAny(w, " \"'\\;") || strings.ContainsFunc(w, control) {
			w = quoteExec(w)
		}

		out[i] = w
	}

	return strings.Join(out, " ")
}

// control is an ASCII control character, which a unit file cannot hold as itself: a line
// break would end the setting, and systemd read what follows it as one of its own.
func control(r rune) bool { return r < 0x20 || r == 0x7f }

// quoteExec is w in double quotes, a quote and a backslash escaped and every control
// character written as the C escape systemd reads back.
func quoteExec(w string) string {
	var b strings.Builder

	b.WriteByte('"')

	for i := range len(w) {
		switch c := w[i]; {
		case c == '"' || c == '\\':
			b.WriteByte('\\')
			b.WriteByte(c)
		case c == '\n':
			b.WriteString(`\n`)
		case c == '\t':
			b.WriteString(`\t`)
		case control(rune(c)):
			fmt.Fprintf(&b, `\x%02x`, c)
		default:
			b.WriteByte(c)
		}
	}

	b.WriteByte('"')

	return b.String()
}

// mainPID reads out, systemctl show's answer for a unit's MainPID property, and says whether it
// names a main process: one a unit starting, running or stopping has, and one waiting to be
// restarted has not (MainPID=0). An answer naming no number is none systemd gives, and an error.
func mainPID(out string) (bool, error) {
	value, _ := strings.CutPrefix(out, "MainPID=")

	pid, err := strconv.Atoi(value)
	if err != nil {
		return false, fmt.Errorf("answered %q, naming no main process", out)
	}

	return pid != 0, nil
}
