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
// User=root, and no capability line: the supervisor is root, and it is the supervisor
// that gives anchord, as its own account, exactly the capabilities its mode needs and no
// others (internal/daemon/privilege.go). An AmbientCapabilities= here would be granted
// to the supervisor, which has them all as root anyway, and to nothing else.
//
// Deliberately absent: any directory setting -- conflux makes everything it keeps in its one root,
// .conflux, itself, as it does under every service manager and in the foreground -- and
// StateDirectory above all, because systemd gives a directory it claims to
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
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
`

// systemdUnit is the unit for exe run with args.
func systemdUnit(exe string, args []string) string {
	return fmt.Sprintf(unitTemplate, strings.Join(append([]string{exe}, args...), " "), ExitNoConfig, ExitChildFailed)
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
