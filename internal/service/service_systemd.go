package service

import (
	"fmt"
	"strings"
)

// The systemd unit, rendered here without a build tag -- as the rc scripts are -- so
// its quoting is tested on every machine that builds conflux rather than only on Linux.

// unitTemplate is the unit conflux writes.
//
// Type=notify, with sd_notify from the supervisor, is what makes `systemctl start`
// return only once the anchor is actually up rather than once fork succeeded.
//
// RestartPreventExitStatus=78 70 is the two answers a restart would only repeat.
// `conflux serve` exits 78 when there is nothing to start, and 70 when it has given up
// on a configuration or a host that no retry changes; without this the unit would
// restart into the same answer every five seconds forever, instead of showing failed.
//
// Restart=on-failure rather than always, so a deliberate clean exit stays exited.
//
// No RuntimeDirectory or ConfigurationDirectory: everything conflux keeps is in its one
// root, which the supervisor makes and holds to its modes itself, run directory included,
// which it empties as it starts.
//
// User=root, and no capability line: the supervisor is root, and it is the supervisor
// that gives anchord, as its own account, exactly the capabilities its mode needs and no
// others (internal/daemon/privilege.go). An AmbientCapabilities= here would be granted
// to the supervisor, which has them all as root anyway, and to nothing else.
//
// The protections a system service is given where they take nothing it needs: UMask=0077,
// so nothing the supervisor or anchord creates is anybody else's to read; a /tmp of its own
// (PrivateTmp), which nothing here uses; home directories read-only; and the clock, the
// hostname, the cgroup tree, the execution domain, realtime scheduling, set-user-ID files
// and foreign system-call ABIs out of reach. They hold for anchord and what it runs too,
// none of which needs any of them.
//
// Deliberately absent: StateDirectory, because systemd gives a directory it claims to
// User= and Group= again, recursively, at every start once its top belongs to anybody
// else -- and the root's group is anchord's account, so every start would hand anchord's
// own directory back to root. ProtectSystem, because the supervisor writes /etc -- the
// account anchord runs as, and its own unit when it puts it back. ProtectKernelTunables and
// ProtectKernelModules, because anchor's router sets sysctls and its firewall commands load
// modules. And NoNewPrivileges, which would hold for a root anchord too, where a host's
// firewall answers only root, and stop its firewall commands' SELinux transitions; the
// supervisor sets no_new_privs on the anchord it can, itself.
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
RestartPreventExitStatus=78 70
TimeoutStartSec=90
TimeoutStopSec=30
KillMode=mixed
KillSignal=SIGTERM
User=root
Group=root
LimitNOFILE=%[2]d
UMask=0077
PrivateTmp=yes
ProtectHome=read-only
ProtectClock=yes
ProtectHostname=yes
ProtectControlGroups=yes
LockPersonality=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
SystemCallArchitectures=native

[Install]
WantedBy=multi-user.target
`

// systemdUnit is the unit for exe run with args.
func systemdUnit(exe string, args []string) string {
	return fmt.Sprintf(unitTemplate, execLine(append([]string{exe}, args...)), openFiles)
}

// execLine renders an ExecStart= command line, each word quoted where systemd would
// otherwise split it or read it: whitespace, quotes and backslashes are quoted and
// escaped, and a % or a $ -- a specifier or a variable to systemd, quoted or not -- is
// doubled. The root conflux runs from is fixed, but a path may hold any of them, and macOS's
// holds a space.
func execLine(words []string) string {
	literal := strings.NewReplacer("%", "%%", "$", "$$")
	quoted := strings.NewReplacer(`\`, `\\`, `"`, `\"`)

	out := make([]string, len(words))

	for i, w := range words {
		w = literal.Replace(w)
		if w == "" || strings.ContainsAny(w, " \t\n\"'\\;") {
			w = `"` + quoted.Replace(w) + `"`
		}

		out[i] = w
	}

	return strings.Join(out, " ")
}
